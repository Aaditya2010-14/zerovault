//go:build windows

package cli

import (
	"syscall"
	"unsafe"
)

// Windows console mode flags, per the Win32 Console API.
const (
	enableEchoInput = 0x0004
	enableLineInput = 0x0002
)

// stdInputHandle is STD_INPUT_HANDLE (-10), expressed as its 32-bit two's
// complement value since GetStdHandle takes a DWORD.
const stdInputHandle = uintptr(0xFFFFFFF6)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetStdHandle   = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// readPasswordRaw disables console echo (keeping line input so backspace
// still works) for the duration of the read, then restores the original
// mode. Uses only syscall against kernel32.dll — no golang.org/x/sys.
func readPasswordRaw() (string, error) {
	handle, _, _ := procGetStdHandle.Call(stdInputHandle)
	if handle == 0 || handle == ^uintptr(0) {
		return readPasswordFallback()
	}

	var originalMode uint32
	ret, _, _ := procGetConsoleMode.Call(handle, uintptr(unsafe.Pointer(&originalMode)))
	if ret == 0 {
		// Not a console (e.g. piped input in tests) — fall back to plain read.
		return readPasswordFallback()
	}

	noEchoMode := (originalMode &^ enableEchoInput) | enableLineInput
	procSetConsoleMode.Call(handle, uintptr(noEchoMode))
	defer procSetConsoleMode.Call(handle, uintptr(originalMode))

	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return line, nil
}
