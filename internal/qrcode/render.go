package qrcode

import (
	"fmt"
	"strings"
)

// quietZone is the minimum light-module border ISO/IEC 18004 requires
// around a QR code so a scanner can reliably find the finder patterns.
const quietZone = 4

// ToASCII renders m as block characters for a terminal. Each module is
// drawn as two "█" (or two spaces) side by side, since terminal character
// cells are roughly twice as tall as they are wide — without doubling,
// the code renders visibly squashed and scans poorly from a phone camera
// pointed at a terminal.
func ToASCII(m *Matrix) string {
	var b strings.Builder
	total := m.Size + 2*quietZone

	writeRow := func(dark func(c int) bool) {
		for c := 0; c < total; c++ {
			if dark(c) {
				b.WriteString("██")
			} else {
				b.WriteString("  ")
			}
		}
		b.WriteByte('\n')
	}

	for r := 0; r < quietZone; r++ {
		writeRow(func(c int) bool { return false })
	}
	for r := 0; r < m.Size; r++ {
		row := r
		writeRow(func(c int) bool {
			mc := c - quietZone
			if mc < 0 || mc >= m.Size {
				return false
			}
			return m.Modules[row][mc]
		})
	}
	for r := 0; r < quietZone; r++ {
		writeRow(func(c int) bool { return false })
	}
	return b.String()
}

// ToSVG renders m as a minimal SVG: a white background rect plus one
// black rect per dark module, at moduleSize pixels per module.
func ToSVG(m *Matrix) string {
	const moduleSize = 8
	total := (m.Size + 2*quietZone) * moduleSize

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d">`,
		total, total, total, total)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#ffffff"/>`, total, total)

	for r := 0; r < m.Size; r++ {
		for c := 0; c < m.Size; c++ {
			if !m.Modules[r][c] {
				continue
			}
			x := (c + quietZone) * moduleSize
			y := (r + quietZone) * moduleSize
			fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" fill="#000000"/>`, x, y, moduleSize, moduleSize)
		}
	}
	b.WriteString(`</svg>`)
	b.WriteByte('\n')
	return b.String()
}
