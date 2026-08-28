// Package fileenc implements ZeroVault's standalone file encryption tool:
// encrypt/decrypt any file on disk with the same AES-256-GCM + PBKDF2
// pipeline the vault itself uses, but streamed in bounded-memory chunks so
// files far larger than available RAM can be processed.
//
// crypto/cipher's AEAD interface only exposes a single-shot Seal/Open call,
// which would force the entire file into memory for one GCM operation. To
// stream in fixed-size chunks while still getting AEAD's tamper-detection
// guarantee, each chunk is sealed independently under its own nonce, built
// from a random per-file prefix plus a monotonically increasing counter
// (the "STREAM" construction used by tools like age/rage and Tink's
// streaming AEAD). The final chunk's counter has its top bit set, which
// binds "this is the last chunk" into the authenticated nonce itself — an
// attacker who truncates the ciphertext can't make an earlier chunk pass
// as the last one, because it was never sealed with that bit set.
package fileenc

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	vcrypto "zerovault/internal/crypto"
)

// magicHeader identifies a ZeroVault-encrypted file. It is checked before
// any decryption is attempted so a wrong-format file fails fast with a
// clear message instead of a confusing crypto error.
var magicHeader = []byte("ZEROVAULT_ENC\n")

const (
	noncePrefixLen  = 8
	chunkPlaintext  = 64 * 1024 // stream in 64KB pieces, per the spec
	lastChunkFlag   = uint32(1) << 31
	maxChunkCipher  = chunkPlaintext + 16 + 4096 // plaintext + GCM tag + slack for the metadata chunk
	lengthPrefixLen = 4
)

// metadata is sealed as chunk 0, before any file content, so the original
// filename and size travel inside the encrypted envelope rather than as
// plaintext next to it.
type metadata struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// OverwriteFunc is asked for permission before an existing output file is
// replaced. A nil OverwriteFunc always allows the overwrite (used by
// callers, such as the web dashboard, that already write to a fresh
// temp file and have nothing meaningful to ask about).
type OverwriteFunc func(path string) (bool, error)

// ProgressFunc is called after each chunk is processed with the number of
// plaintext bytes handled so far and the total (known up front for encrypt,
// known after the metadata chunk for decrypt).
type ProgressFunc func(written, total int64)

// ErrNotZeroVaultFile is returned by DecryptFile when the input doesn't
// start with the expected magic header.
var ErrNotZeroVaultFile = fmt.Errorf("fileenc: not a ZeroVault encrypted file")

// ErrOverwriteDeclined is returned when confirm rejects replacing an
// existing output file.
var ErrOverwriteDeclined = fmt.Errorf("fileenc: output file already exists")

// streamCipher bundles the derived key material needed to seal/open chunks
// under the STREAM nonce construction described in the package doc.
type streamCipher struct {
	gcm         gcmAEAD
	noncePrefix []byte
}

// gcmAEAD is the minimal surface fileenc needs from crypto/cipher.AEAD;
// declared narrowly so this file only depends on the shape it actually
// uses from internal/crypto's construction helper below.
type gcmAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

func (c *streamCipher) nonce(index uint32, last bool) []byte {
	n := make([]byte, 12)
	copy(n, c.noncePrefix)
	ctr := index
	if last {
		ctr |= lastChunkFlag
	}
	binary.BigEndian.PutUint32(n[noncePrefixLen:], ctr)
	return n
}

func (c *streamCipher) seal(index uint32, last bool, plaintext []byte) []byte {
	return c.gcm.Seal(nil, c.nonce(index, last), plaintext, nil)
}

func (c *streamCipher) open(index uint32, last bool, ciphertext []byte) ([]byte, error) {
	return c.gcm.Open(nil, c.nonce(index, last), ciphertext, nil)
}

// newStreamCipher derives the AES-256 key with the same PBKDF2 pipeline the
// vault uses (vcrypto.DeriveKey) and builds the AES-GCM AEAD each chunk is
// sealed/opened under.
func newStreamCipher(password string, salt, noncePrefix []byte) (*streamCipher, error) {
	key := vcrypto.DeriveKey([]byte(password), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("fileenc: failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("fileenc: failed to create GCM mode: %w", err)
	}
	return &streamCipher{gcm: gcm, noncePrefix: noncePrefix}, nil
}

// EncryptFile encrypts inPath and writes the result to outPath, prompting
// via confirm if outPath already exists. progress (may be nil) is invoked
// after every chunk with cumulative plaintext bytes written and the total
// file size.
func EncryptFile(inPath, outPath, password string, confirm OverwriteFunc, progress ProgressFunc) error {
	in, err := os.Open(inPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("fileenc: file %q does not exist", inPath)
		}
		return fmt.Errorf("fileenc: failed to open %q: %w", inPath, err)
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("fileenc: failed to stat %q: %w", inPath, err)
	}
	total := info.Size()

	if err := checkOverwrite(outPath, confirm); err != nil {
		return err
	}

	salt, err := vcrypto.RandomSalt()
	if err != nil {
		return err
	}
	noncePrefix, err := vcrypto.RandomBytes(noncePrefixLen)
	if err != nil {
		return err
	}
	sc, err := newStreamCipher(password, salt, noncePrefix)
	if err != nil {
		return err
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("fileenc: failed to create %q: %w", outPath, err)
	}
	defer out.Close()

	bw := bufio.NewWriter(out)
	if _, err := bw.Write(magicHeader); err != nil {
		return err
	}
	if _, err := bw.Write(salt); err != nil {
		return err
	}
	if _, err := bw.Write(noncePrefix); err != nil {
		return err
	}

	meta, err := json.Marshal(metadata{Name: filepath.Base(inPath), Size: total})
	if err != nil {
		return fmt.Errorf("fileenc: failed to serialize metadata: %w", err)
	}
	if err := writeChunk(bw, sc.seal(0, false, meta)); err != nil {
		return err
	}

	br := bufio.NewReaderSize(in, chunkPlaintext)
	var index uint32 = 1
	var written int64
	buf := make([]byte, chunkPlaintext)
	for {
		n, readErr := io.ReadFull(br, buf)
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return fmt.Errorf("fileenc: failed to read %q: %w", inPath, readErr)
		}

		_, peekErr := br.Peek(1)
		isLast := peekErr != nil

		if err := writeChunk(bw, sc.seal(index, isLast, buf[:n])); err != nil {
			return err
		}
		written += int64(n)
		if progress != nil {
			progress(written, total)
		}
		if isLast {
			break
		}
		index++
	}

	return bw.Flush()
}

// DecryptFile decrypts inPath (which must have been produced by
// EncryptFile) and writes the recovered plaintext to outPath, or, if
// outPath is empty, to the original filename recorded inside the encrypted
// metadata (in the same directory as inPath). It returns the path actually
// written to.
func DecryptFile(inPath, outPath, password string, confirm OverwriteFunc, progress ProgressFunc) (string, error) {
	in, err := os.Open(inPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("fileenc: file %q does not exist", inPath)
		}
		return "", fmt.Errorf("fileenc: failed to open %q: %w", inPath, err)
	}
	defer in.Close()

	br := bufio.NewReaderSize(in, chunkPlaintext+maxChunkCipher)

	header := make([]byte, len(magicHeader))
	if _, err := io.ReadFull(br, header); err != nil || !bytes.Equal(header, magicHeader) {
		return "", ErrNotZeroVaultFile
	}

	salt := make([]byte, vcrypto.SaltLen)
	if _, err := io.ReadFull(br, salt); err != nil {
		return "", ErrNotZeroVaultFile
	}
	noncePrefix := make([]byte, noncePrefixLen)
	if _, err := io.ReadFull(br, noncePrefix); err != nil {
		return "", ErrNotZeroVaultFile
	}

	sc, err := newStreamCipher(password, salt, noncePrefix)
	if err != nil {
		return "", err
	}

	metaCipher, last, err := readChunk(br)
	if err != nil {
		return "", fmt.Errorf("fileenc: truncated or corrupted file")
	}
	if last {
		return "", fmt.Errorf("fileenc: truncated or corrupted file")
	}
	metaPlain, err := sc.open(0, false, metaCipher)
	if err != nil {
		return "", fmt.Errorf("fileenc: decryption failed (wrong password or tampered file)")
	}
	var meta metadata
	if err := json.Unmarshal(metaPlain, &meta); err != nil {
		return "", fmt.Errorf("fileenc: corrupted metadata: %w", err)
	}

	if outPath == "" {
		name := filepath.Base(meta.Name) // never trust a path from inside the file
		if name == "" || name == "." || name == string(filepath.Separator) {
			name = "decrypted-output"
		}
		outPath = filepath.Join(filepath.Dir(inPath), name)
	}
	if err := checkOverwrite(outPath, confirm); err != nil {
		return "", err
	}

	out, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("fileenc: failed to create %q: %w", outPath, err)
	}
	defer out.Close()
	bw := bufio.NewWriter(out)

	var index uint32 = 1
	var written int64
	sawLast := false
	for {
		cipherChunk, isLast, err := readChunk(br)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("fileenc: truncated or corrupted file")
		}

		plain, err := sc.open(index, isLast, cipherChunk)
		if err != nil {
			return "", fmt.Errorf("fileenc: decryption failed (wrong password or tampered file)")
		}
		if _, err := bw.Write(plain); err != nil {
			return "", err
		}
		written += int64(len(plain))
		if progress != nil {
			progress(written, meta.Size)
		}
		if isLast {
			sawLast = true
			break
		}
		index++
	}
	if !sawLast {
		return "", fmt.Errorf("fileenc: file is truncated — final chunk marker never seen")
	}

	if err := bw.Flush(); err != nil {
		return "", err
	}
	return outPath, nil
}

// IsZeroVaultFile reports whether path starts with the ZeroVault magic
// header, without attempting decryption.
func IsZeroVaultFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	header := make([]byte, len(magicHeader))
	_, err = io.ReadFull(f, header)
	return err == nil && bytes.Equal(header, magicHeader)
}

func checkOverwrite(path string, confirm OverwriteFunc) error {
	if _, err := os.Stat(path); err != nil {
		return nil // doesn't exist — nothing to confirm
	}
	if confirm == nil {
		return nil
	}
	ok, err := confirm(path)
	if err != nil {
		return err
	}
	if !ok {
		return ErrOverwriteDeclined
	}
	return nil
}

// writeChunk writes a length-prefixed ciphertext chunk: a 4-byte
// big-endian length followed by that many bytes.
func writeChunk(w io.Writer, ciphertext []byte) error {
	var lenBuf [lengthPrefixLen]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ciphertext)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(ciphertext)
	return err
}

// readChunk reads one length-prefixed ciphertext chunk and reports whether
// no further chunk follows in the stream (checked via Peek before this
// chunk is returned, mirroring how the encoder decided isLast) — that
// wire-position fact is what gets fed into the nonce on decrypt.
func readChunk(br *bufio.Reader) (ciphertext []byte, isLast bool, err error) {
	var lenBuf [lengthPrefixLen]byte
	if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
		if err == io.EOF {
			return nil, false, io.EOF
		}
		return nil, false, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxChunkCipher {
		return nil, false, fmt.Errorf("fileenc: implausible chunk length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, false, err
	}
	_, peekErr := br.Peek(1)
	return buf, peekErr != nil, nil
}
