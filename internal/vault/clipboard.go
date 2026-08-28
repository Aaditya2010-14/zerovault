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
const ClipboardClearDelay = 20 * time.Second

// CopyToClipboard copies text to the OS clipboard by shelling out to the
// platform's native clipboard utility (no clipboard package exists in the
// Go standard library). It then schedules an automatic clear after
// ClipboardClearDelay so a copied password doesn't linger indefinitely.
func CopyToClipboard(text string) error {
	if err := setClipboard(text); err != nil {
		return err
	}

	go func() {
		time.Sleep(ClipboardClearDelay)
		// Best-effort: only clear if nothing else has changed since it's
		// simplest to just overwrite unconditionally. A stale clear
		// wiping a newer copy is an acceptable tradeoff for guaranteeing
		// secrets don't linger.
		_ = setClipboard("")
	}()

	return nil
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
