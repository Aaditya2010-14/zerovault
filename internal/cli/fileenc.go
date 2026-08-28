package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"zerovault/internal/fileenc"
)

// cmdEncrypt implements `zerovault encrypt <file> [-o out.enc]`.
func cmdEncrypt(args []string) int {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	out := fs.String("o", "", "output file name (default: <file>.enc)")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) != 1 {
		printError("usage: zerovault encrypt <file> [-o out.enc]")
		return 1
	}
	inPath := rest[0]
	outPath := *out
	if outPath == "" {
		outPath = inPath + ".enc"
	}

	pw1, err := ReadPassword("Encryption password: ")
	if err != nil {
		printError("%v", err)
		return 1
	}
	pw2, err := ReadPassword("Confirm password: ")
	if err != nil {
		printError("%v", err)
		return 1
	}
	if pw1 != pw2 {
		printError("passwords do not match")
		return 1
	}
	if pw1 == "" {
		printError("password cannot be empty")
		return 1
	}

	info, statErr := os.Stat(inPath)
	showProgress := statErr == nil && info.Size() > 1024*1024

	err = fileenc.EncryptFile(inPath, outPath, pw1, promptOverwrite, progressPrinter("Encrypting", showProgress))
	if showProgress {
		fmt.Println()
	}
	if err != nil {
		if err == fileenc.ErrOverwriteDeclined {
			printWarning("cancelled — output file already exists")
			return 1
		}
		printError("%v", err)
		return 1
	}

	printSuccess("encrypted %q -> %q", inPath, outPath)
	return 0
}

// cmdDecrypt implements `zerovault decrypt <file.enc> [-o out]`.
func cmdDecrypt(args []string) int {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	out := fs.String("o", "", "output file name (default: original filename stored in the encrypted file)")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) != 1 {
		printError("usage: zerovault decrypt <file.enc> [-o out]")
		return 1
	}
	inPath := rest[0]

	if !fileenc.IsZeroVaultFile(inPath) {
		printError("%q is not a ZeroVault encrypted file", inPath)
		return 1
	}

	pw, err := ReadPassword("Decryption password: ")
	if err != nil {
		printError("%v", err)
		return 1
	}

	info, statErr := os.Stat(inPath)
	showProgress := statErr == nil && info.Size() > 1024*1024

	usedPath, err := fileenc.DecryptFile(inPath, *out, pw, promptOverwrite, progressPrinter("Decrypting", showProgress))
	if showProgress {
		fmt.Println()
	}
	if err != nil {
		if err == fileenc.ErrOverwriteDeclined {
			printWarning("cancelled — output file already exists")
			return 1
		}
		printError("%v", err)
		return 1
	}

	printSuccess("decrypted %q -> %q", inPath, usedPath)
	return 0
}

// promptOverwrite asks the user on stdin before an existing output file is
// replaced.
func promptOverwrite(path string) (bool, error) {
	fmt.Printf("%q already exists. Overwrite? (y/N): ", path)
	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return false, nil
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// progressPrinter returns a fileenc.ProgressFunc that prints a live
// "Encrypting... 45% (2.3MB / 5.1MB)" line for files over 1MB, and does
// nothing for smaller files (per the spec: only show progress above 1MB).
func progressPrinter(verb string, enabled bool) func(written, total int64) {
	if !enabled {
		return nil
	}
	return func(written, total int64) {
		pct := 0
		if total > 0 {
			pct = int(written * 100 / total)
		}
		fmt.Printf("\r%s... %d%% (%s / %s)   ", verb, pct, formatBytes(written), formatBytes(total))
	}
}

func formatBytes(n int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case n >= gb:
		return fmt.Sprintf("%.1fGB", float64(n)/gb)
	case n >= mb:
		return fmt.Sprintf("%.1fMB", float64(n)/mb)
	case n >= kb:
		return fmt.Sprintf("%.1fKB", float64(n)/kb)
	default:
		return fmt.Sprintf("%dB", n)
	}
}
