package vault

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

// ClipboardClearDelay is how long a copied secret stays in the clipboard
// before it is automatically overwritten with an empty string.
const ClipboardClearDelay = 10 * time.Second

// CopyToClipboard copies text to the OS clipboard by shelling out to the
// platform's native clipboard utility (no clipboard package exists in the
// Go standard library). Callers that want the auto-clear-after-delay
// behavior must call ClearClipboard themselves after ClipboardClearDelay —
// deliberately not a background goroutine here, since a short-lived CLI
// process would exit (killing the goroutine mid-flight) before a delayed
// clear could ever run; see cli.printClipboardCountdown for the caller
// that waits out the delay in the foreground before clearing.
func CopyToClipboard(text string) error {
	return setClipboard(text)
}

// ClearClipboard overwrites the clipboard with an empty string.
func ClearClipboard() error {
	return setClipboard("")
}

func setClipboard(text string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("clip")
	case "darwin":
		cmd = exec.Command("pbcopy")
	default:
		cmd = exec.Command("xclip", "-selection", "clipboard")
	}

	cmd.Stdin = bytes.NewBufferString(text)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("vault: failed to copy to clipboard: %w", err)
	}
	return nil
}
