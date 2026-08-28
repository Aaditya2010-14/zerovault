package qrcode

// maskFuncs are the eight standard QR data-masking patterns (ISO/IEC
// 18004 Table 10), each a predicate over module coordinates: true means
// "flip this module." Masking exists so the finished code doesn't have
// large uniform runs or accidental finder-pattern lookalikes that would
// confuse a scanner's image processing.
var maskFuncs = [8]func(r, c int) bool{
	func(r, c int) bool { return (r+c)%2 == 0 },
	func(r, c int) bool { return r%2 == 0 },
	func(r, c int) bool { return c%3 == 0 },
	func(r, c int) bool { return (r+c)%3 == 0 },
	func(r, c int) bool { return (r/2+c/3)%2 == 0 },
	func(r, c int) bool { return (r*c)%2+(r*c)%3 == 0 },
	func(r, c int) bool { return ((r*c)%2+(r*c)%3)%2 == 0 },
	func(r, c int) bool { return ((r+c)%2+(r*c)%3)%2 == 0 },
}

// applyMask flips every non-reserved (data) module for which maskFuncs[p]
// is true. Function patterns (finders, timing, alignment, format-info
// area) are never masked.
func applyMask(m, reserved [][]bool, size, pattern int) {
	f := maskFuncs[pattern]
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			if !reserved[r][c] && f(r, c) {
				m[r][c] = !m[r][c]
			}
		}
	}
}

// chooseBestMask tries all 8 masks against a scratch copy of the matrix
// and returns the one with the lowest ISO/IEC 18004 §7.8.3 penalty score
// — the standard way a QR encoder picks a mask that avoids patterns real
// scanners struggle with (long runs, 2x2 blocks, finder-pattern
// lookalikes, imbalanced dark/light ratio).
func chooseBestMask(m, reserved [][]bool, size int) int {
	best, bestScore := 0, -1
	for p := 0; p < 8; p++ {
		scratch := cloneMatrix(m, size)
		applyMask(scratch, reserved, size, p)
		score := penaltyScore(scratch, size)
		if bestScore == -1 || score < bestScore {
			best, bestScore = p, score
		}
	}
	return best
}

func cloneMatrix(m [][]bool, size int) [][]bool {
	out := make([][]bool, size)
	for r := range m {
		out[r] = append([]bool(nil), m[r]...)
	}
	return out
}

func penaltyScore(m [][]bool, size int) int {
	return penaltyRuns(m, size) + penaltyBlocks(m, size) + penaltyPatterns(m, size) + penaltyBalance(m, size)
}

// penaltyRuns: rule 1 — 5+ same-color modules in a row/column.
func penaltyRuns(m [][]bool, size int) int {
	score := 0
	scoreLine := func(get func(i int) bool) {
		run := 1
		for i := 1; i < size; i++ {
			if get(i) == get(i-1) {
				run++
				continue
			}
			if run >= 5 {
				score += 3 + (run - 5)
			}
			run = 1
		}
		if run >= 5 {
			score += 3 + (run - 5)
		}
	}
	for r := 0; r < size; r++ {
		scoreLine(func(i int) bool { return m[r][i] })
	}
	for c := 0; c < size; c++ {
		scoreLine(func(i int) bool { return m[i][c] })
	}
	return score
}

// penaltyBlocks: rule 2 — each 2x2 block of same-color modules.
func penaltyBlocks(m [][]bool, size int) int {
	score := 0
	for r := 0; r < size-1; r++ {
		for c := 0; c < size-1; c++ {
			v := m[r][c]
			if m[r][c+1] == v && m[r+1][c] == v && m[r+1][c+1] == v {
				score += 3
			}
		}
	}
	return score
}

// penaltyPatterns: rule 3 — a 1:1:3:1:1 dark:light:dark:dark:dark:light:dark
// finder-like run (padded by 4 light modules on either side), searched
// for in every row and column.
func penaltyPatterns(m [][]bool, size int) int {
	patternA := []bool{true, false, true, true, true, false, true, false, false, false, false}
	patternB := []bool{false, false, false, false, true, false, true, true, true, false, true}
	matchAt := func(get func(i int) bool, start int) bool {
		for _, want := range [2][]bool{patternA, patternB} {
			ok := true
			for i, v := range want {
				if get(start+i) != v {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
		return false
	}

	score := 0
	for r := 0; r < size; r++ {
		for c := 0; c <= size-11; c++ {
			if matchAt(func(i int) bool { return m[r][i] }, c) {
				score += 40
			}
		}
	}
	for c := 0; c < size; c++ {
		for r := 0; r <= size-11; r++ {
			if matchAt(func(i int) bool { return m[i][c] }, r) {
				score += 40
			}
		}
	}
	return score
}

// penaltyBalance: rule 4 — deviation of the dark-module percentage from
// 50%, in steps of 5%.
func penaltyBalance(m [][]bool, size int) int {
	dark := 0
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			if m[r][c] {
				dark++
			}
		}
	}
	percent := dark * 100 / (size * size)
	diff := percent - 50
	if diff < 0 {
		diff = -diff
	}
	return (diff / 5) * 10
}

// drawFormatBits computes the 15-bit format information (2-bit EC level +
// 3-bit mask pattern, protected by a (15,5) BCH code and XORed with the
// fixed mask 0x5412 per ISO/IEC 18004 §7.9) and writes both standard
// copies into the matrix, plus the always-dark module.
func drawFormatBits(m, reserved [][]bool, size, maskPattern int) {
	const eccLevelL = 0b01 // ISO/IEC 18004 Table 25: L=01, M=00, Q=11, H=10
	data := (eccLevelL << 3) | maskPattern

	rem := data
	for i := 0; i < 10; i++ {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	bits := ((data << 10) | (rem & 0x3FF)) ^ 0x5412

	get := func(i int) bool { return (bits>>uint(i))&1 != 0 }
	set := func(r, c int, v bool) {
		m[r][c] = v
		reserved[r][c] = true
	}

	// Column 8 (vertical strip): bits 0-5 go in rows 0-5, bits 6-7 jump
	// past the timing-pattern row to rows 7-8, and bits 8-14 continue
	// below the bottom-left finder pattern at rows (size-7)..(size-1).
	for i := 0; i < 15; i++ {
		v := get(i)
		switch {
		case i < 6:
			set(i, 8, v)
		case i < 8:
			set(i+1, 8, v)
		default:
			set(size-15+i, 8, v)
		}
	}

	// Row 8 (horizontal strip): bits 0-7 go in columns (size-1)..(size-8)
	// descending, bit 8 jumps past the timing-pattern column to column 7,
	// and bits 9-14 continue at columns 5..0.
	for i := 0; i < 15; i++ {
		v := get(i)
		switch {
		case i < 8:
			set(8, size-i-1, v)
		case i < 9:
			set(8, 7, v)
		default:
			set(8, 14-i, v)
		}
	}

	set(size-8, 8, true) // dark module, always on
}
