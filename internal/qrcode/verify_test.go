package qrcode

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// This file cross-checks the from-scratch encoder against a real,
// independent QR decoder (OpenCV's QRCodeDetector, via a small Python
// script) — not just internal structural assertions. Rendering to PNG
// uses only image/png (Go stdlib); the Python/OpenCV step is test-only
// verification infrastructure, exactly like gitscan's tests shelling out
// to the real `git` binary to build fixtures. If Python/OpenCV isn't
// available, the test is skipped rather than failed.

func toPNG(m *Matrix, path string) error {
	const scale = 8
	total := (m.Size + 2*quietZone) * scale
	img := image.NewGray(image.Rect(0, 0, total, total))
	for y := 0; y < total; y++ {
		for x := 0; x < total; x++ {
			img.SetGray(x, y, color.Gray{Y: 255})
		}
	}
	for r := 0; r < m.Size; r++ {
		for c := 0; c < m.Size; c++ {
			if !m.Modules[r][c] {
				continue
			}
			x0 := (c + quietZone) * scale
			y0 := (r + quietZone) * scale
			for dy := 0; dy < scale; dy++ {
				for dx := 0; dx < scale; dx++ {
					img.SetGray(x0+dx, y0+dy, color.Gray{Y: 0})
				}
			}
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

func findPython(t *testing.T) string {
	t.Helper()
	candidates := []string{
		`C:\Users\Gayatri\AppData\Local\Programs\Python\Python313\python.exe`,
		"python3",
		"python",
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skip("no Python interpreter found — skipping OpenCV cross-check")
	return ""
}

func decodeWithOpenCV(t *testing.T, py, pngPath string) string {
	t.Helper()
	script := `
import sys, cv2
img = cv2.imread(sys.argv[1])
detector = cv2.QRCodeDetector()
data, points, _ = detector.detectAndDecode(img)
sys.stdout.write(data)
`
	scriptPath := filepath.Join(t.TempDir(), "decode.py")
	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(py, scriptPath, pngPath)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Skipf("OpenCV decode script failed (cv2 likely not installed): %v\n%s", err, stderr.String())
	}
	return out.String()
}

func TestEncodeIsRealDecodable(t *testing.T) {
	py := findPython(t)

	cases := []string{
		"HELLO",
		"otpauth://totp/ZeroVault:github-2fa?secret=JBSWY3DPEHPK3PXP&issuer=ZeroVault",
		"otpauth://totp/ZeroVault:work-email?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ZeroVault",
	}

	for _, text := range cases {
		m, err := Encode([]byte(text))
		if err != nil {
			t.Fatalf("Encode(%q): %v", text, err)
		}

		pngPath := filepath.Join(t.TempDir(), "code.png")
		if err := toPNG(m, pngPath); err != nil {
			t.Fatalf("toPNG: %v", err)
		}

		got := decodeWithOpenCV(t, py, pngPath)
		if got != text {
			t.Errorf("OpenCV decoded %q, want %q (version-size=%d)", got, text, m.Size)
		}
	}
}
