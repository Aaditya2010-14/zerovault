package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// stdinReader is a single shared buffered reader over os.Stdin. Password
// reads must all go through it (rather than each allocating their own
// bufio.Reader) — a fresh bufio.Reader greedily buffers ahead on its first
// read, which would silently swallow bytes meant for a later prompt when
// stdin is piped (e.g. multiple prompts fed by one echo/heredoc).
var stdinReader = bufio.NewReader(os.Stdin)

// ReadPassword prompts and reads a password from stdin without echoing it
// to the terminal (platform-specific implementation in password_windows.go
// / password_unix.go). Falls back to visible input if stdin isn't an
// interactive terminal (e.g. piped input in scripts/tests).
func ReadPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	pw, err := readPasswordRaw()
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("cli: failed to read password: %w", err)
	}
	return strings.TrimRight(pw, "\r\n"), nil
}

// readPasswordFallback reads a line from stdin with normal echo. Used when
// the terminal-raw-mode syscalls aren't applicable (non-TTY stdin).
func readPasswordFallback() (string, error) {
	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return line, nil
}
