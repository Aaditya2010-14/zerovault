// Package qrcode implements QR code generation (ISO/IEC 18004) entirely
// from the specification: byte-mode data encoding, Reed-Solomon error
// correction over GF(256) (gf256.go), the standard function-pattern
// layout (finder/timing/alignment patterns), the zigzag data placement
// algorithm, and best-of-8 data masking selected by the spec's penalty
// scoring rules. No QR library, no image library — the output is either
// a block-character terminal rendering or a hand-built SVG of plain
// rectangles.
//
// Scope is deliberately narrow: byte mode only, error-correction level L
// (the lowest — maximizes data capacity, keeping the QR code small), and
// versions 1-5 (21x21 to 37x37 modules) — every version that still uses a
// single Reed-Solomon block at level L, avoiding the added complexity of
// interleaving multiple codeword blocks. That range comfortably fits a
// ZeroVault otpauth:// URI even with a long entry name. Larger inputs
// return an error rather than silently growing past what this package
// supports — see Encode's doc comment.
package qrcode

import "fmt"

// Matrix is a generated QR code's module grid. Modules[row][col] is true
// for a dark (black) module.
type Matrix struct {
	Size    int
	Modules [][]bool
}

// version capacity/ECC tables for error-correction level L, versions 1-5.
// All five versions use a single Reed-Solomon block at level L, so no
// block interleaving is needed (real reference: ISO/IEC 18004 Table 9) —
// version 6 onward starts splitting into multiple blocks, which is out
// of scope here.
var versionInfo = []struct {
	dataCodewords int // total data codewords (mode+count+payload+padding)
	eccCodewords  int
}{
	{},        // index 0 unused, versions are 1-based
	{19, 7},   // v1: 21x21
	{34, 10},  // v2: 25x25
	{55, 15},  // v3: 29x29
	{80, 20},  // v4: 33x33
	{108, 26}, // v5: 37x37
}

func moduleSize(version int) int { return 17 + 4*version }

// Encode builds a QR code (byte mode, ECC level L) for data, automatically
// picking the smallest version (1-4) that fits. otpauth:// URIs for
// ZeroVault's TOTP entries (a name plus a 32-character Base32 secret) fit
// comfortably within version 1-2; version 4's 80-byte capacity covers
// long entry names too. Longer input returns an error rather than
// silently exceeding this package's supported version range.
func Encode(data []byte) (*Matrix, error) {
	version, err := pickVersion(len(data))
	if err != nil {
		return nil, err
	}

	codewords, err := buildCodewords(data, version)
	if err != nil {
		return nil, err
	}

	size := moduleSize(version)
	modules := make([][]bool, size)
	reserved := make([][]bool, size)
	for i := range modules {
		modules[i] = make([]bool, size)
		reserved[i] = make([]bool, size)
	}

	drawFunctionPatterns(modules, reserved, size, version)
	placeData(modules, reserved, size, codewords)

	maskPattern := chooseBestMask(modules, reserved, size)
	applyMask(modules, reserved, size, maskPattern)
	drawFormatBits(modules, reserved, size, maskPattern)

	return &Matrix{Size: size, Modules: modules}, nil
}

func pickVersion(dataLen int) (int, error) {
	for v := 1; v < len(versionInfo); v++ {
		// Byte mode capacity in bytes: data codewords minus 1 byte for the
		// 4-bit mode indicator + 8-bit character count (they share a
		// byte-and-a-half but always cost at most 2 bytes of overhead
		// once the terminator/padding is accounted for — see
		// buildCodewords for the exact bit-level accounting).
		capacity := versionInfo[v].dataCodewords - 2
		if dataLen <= capacity {
			return v, nil
		}
	}
	return 0, fmt.Errorf("qrcode: data too long (%d bytes) for the supported version range (max ~%d bytes)",
		dataLen, versionInfo[len(versionInfo)-1].dataCodewords-2)
}

// buildCodewords encodes data as a byte-mode QR data segment, pads it out
// to the version's full data codeword capacity, and appends Reed-Solomon
// error correction codewords.
func buildCodewords(data []byte, version int) ([]byte, error) {
	info := versionInfo[version]
	capacityBits := info.dataCodewords * 8

	bits := newBitWriter(capacityBits)
	bits.write(0b0100, 4) // byte mode indicator
	bits.write(uint32(len(data)), 8)
	for _, b := range data {
		bits.write(uint32(b), 8)
	}

	// Terminator: up to 4 zero bits, only as many as fit.
	if room := capacityBits - bits.len(); room > 0 {
		bits.write(0, min(4, room))
	}
	// Pad to a byte boundary.
	if rem := bits.len() % 8; rem != 0 {
		bits.write(0, 8-rem)
	}
	// Pad codewords: alternate 0xEC, 0x11 until the version's data
	// codeword capacity is filled (ISO/IEC 18004 §7.4.10).
	pad := [2]byte{0xEC, 0x11}
	for i := 0; bits.len() < capacityBits; i++ {
		bits.write(uint32(pad[i%2]), 8)
	}
	if bits.len() != capacityBits {
		return nil, fmt.Errorf("qrcode: internal error: built %d bits, wanted exactly %d", bits.len(), capacityBits)
	}

	dataCodewords := bits.bytes()
	ecc := rsEncode(dataCodewords, info.eccCodewords)

	all := make([]byte, 0, len(dataCodewords)+len(ecc))
	all = append(all, dataCodewords...)
	all = append(all, ecc...)
	return all, nil
}

// --- bit writer ---

type bitWriter struct {
	bits []bool
}

func newBitWriter(capacityHint int) *bitWriter {
	return &bitWriter{bits: make([]bool, 0, capacityHint)}
}

func (w *bitWriter) write(value uint32, n int) {
	for i := n - 1; i >= 0; i-- {
		w.bits = append(w.bits, (value>>uint(i))&1 != 0)
	}
}

func (w *bitWriter) len() int { return len(w.bits) }

func (w *bitWriter) bytes() []byte {
	out := make([]byte, len(w.bits)/8)
	for i := range out {
		var b byte
		for j := 0; j < 8; j++ {
			b <<= 1
			if w.bits[i*8+j] {
				b |= 1
			}
		}
		out[i] = b
	}
	return out
}
