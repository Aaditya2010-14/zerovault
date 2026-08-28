//go:build !windows

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

// termios flag bits used to disable echo, per POSIX termios(3).
const (
	echoFlag   = 0x00000008 // ECHO
	icanonFlag = 0x00000002 // ICANON (kept enabled so backspace still works)
	tcgets     = 0x5401
	tcsets     = 0x5402
)

type termios struct {
	Iflag, Oflag, Cflag, Lflag uint32
	Line                       byte
	Cc                         [32]byte
	Ispeed, Ospeed             uint32
}

// readPasswordRaw disables terminal echo for the duration of the read via
// a direct TCGETS/TCSETS ioctl, then restores the original terminal state.
// Uses only the stdlib syscall package — no golang.org/x/term.
func readPasswordRaw() (string, error) {
	fd := os.Stdin.Fd()

	var oldState termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, tcgets, uintptr(unsafe.Pointer(&oldState))); errno != 0 {
		// Not a TTY (e.g. piped input) — fall back to plain read.
		return readPasswordFallback()
	}

	newState := oldState
	newState.Lflag &^= echoFlag
	newState.Lflag |= icanonFlag
	syscall.Syscall(syscall.SYS_IOCTL, fd, tcsets, uintptr(unsafe.Pointer(&newState)))
	defer syscall.Syscall(syscall.SYS_IOCTL, fd, tcsets, uintptr(unsafe.Pointer(&oldState)))

	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return line, nil
}
