package scanner

import "math"

// MinEntropy is the default Shannon entropy threshold (bits per character)
// above which a quoted string assigned to a suspiciously named identifier
// is flagged as a likely secret. Random Base64/hex secrets typically land
// well above 4.0; natural-language strings and short identifiers land
// well below it.
const MinEntropy = 3.5

// ShannonEntropy computes the Shannon entropy of s in bits per character:
// -sum(p(c) * log2(p(c))) over the character frequency distribution of s.
// Higher values indicate more randomness (closer to a uniform distribution
// over the alphabet used), which is characteristic of generated secrets
// as opposed to natural language or short identifiers.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	counts := make(map[rune]int)
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}

	var entropy float64
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}
