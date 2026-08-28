package qrcode

// drawFunctionPatterns places every fixed structural element of the QR
// code — finder patterns + separators, timing patterns, the single
// alignment pattern (versions 2-4 have exactly one, since the alignment
// coordinate list's other combinations all collide with a finder
// pattern), and the always-dark module — marking each as reserved so the
// data placement pass in placeData skips them.
func drawFunctionPatterns(m, reserved [][]bool, size, version int) {
	drawFinder(m, reserved, size, 0, 0)
	drawFinder(m, reserved, size, 0, size-7)
	drawFinder(m, reserved, size, size-7, 0)

	// Timing patterns: alternating dark/light along row 6 and column 6,
	// between the finder patterns.
	for i := 8; i < size-8; i++ {
		dark := i%2 == 0
		m[6][i] = dark
		reserved[6][i] = true
		m[i][6] = dark
		reserved[i][6] = true
	}

	if version >= 2 {
		pos := 4*version + 10 // the single alignment pattern's center, versions 2-6
		drawAlignment(m, reserved, pos, pos)
	}

	// The dark module: always present, position fixed by the version.
	m[size-8][8] = true
	reserved[size-8][8] = true

	reserveFormatAreas(reserved, size)
}

// drawFinder draws a 7x7 finder pattern (concentric squares) with its
// 1-module light separator, top-left corner at (r0, c0).
func drawFinder(m, reserved [][]bool, size, r0, c0 int) {
	for dr := -1; dr <= 7; dr++ {
		for dc := -1; dc <= 7; dc++ {
			r, c := r0+dr, c0+dc
			if r < 0 || r >= size || c < 0 || c >= size {
				continue
			}
			reserved[r][c] = true
			if dr < 0 || dr > 6 || dc < 0 || dc > 6 {
				continue // separator: stays light (false)
			}
			dark := dr == 0 || dr == 6 || dc == 0 || dc == 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4)
			m[r][c] = dark
		}
	}
}

// drawAlignment draws a 5x5 alignment pattern centered at (r0, c0).
func drawAlignment(m, reserved [][]bool, r0, c0 int) {
	for dr := -2; dr <= 2; dr++ {
		for dc := -2; dc <= 2; dc++ {
			r, c := r0+dr, c0+dc
			reserved[r][c] = true
			dark := dr == -2 || dr == 2 || dc == -2 || dc == 2 || (dr == 0 && dc == 0)
			m[r][c] = dark
		}
	}
}

// reserveFormatAreas marks the two format-information strips (around the
// top-left finder pattern, and split across the top-right/bottom-left
// finder patterns) so data placement skips them; drawFormatBits fills in
// their actual values after masking is chosen.
func reserveFormatAreas(reserved [][]bool, size int) {
	for i := 0; i <= 8; i++ {
		reserved[8][i] = true
		reserved[i][8] = true
	}
	for i := size - 8; i < size; i++ {
		reserved[8][i] = true
		reserved[i][8] = true
	}
}

// placeData writes codewords (data + ECC bytes, MSB-first per byte) into
// every non-reserved module using the standard QR zigzag: two-module-wide
// vertical columns, alternating upward and downward, moving right to
// left, skipping the vertical timing column entirely.
func placeData(m, reserved [][]bool, size int, codewords []byte) {
	bitIndex := 0
	totalBits := len(codewords) * 8
	nextBit := func() bool {
		if bitIndex >= totalBits {
			return false // remainder bits (a few unused trailing modules on some versions): always light
		}
		b := codewords[bitIndex/8]
		bit := (b>>uint(7-bitIndex%8))&1 != 0
		bitIndex++
		return bit
	}

	col := size - 1
	upward := true
	for col > 0 {
		if col == 6 {
			col-- // the vertical timing column carries no data
		}
		for i := 0; i < size; i++ {
			row := i
			if upward {
				row = size - 1 - i
			}
			for _, c := range [2]int{col, col - 1} {
				if !reserved[row][c] {
					m[row][c] = nextBit()
				}
			}
		}
		upward = !upward
		col -= 2
	}
}
