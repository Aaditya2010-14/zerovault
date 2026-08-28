package scanner

import (
	"math"
	"testing"
)

func TestShannonEntropy_Empty(t *testing.T) {
	if got := ShannonEntropy(""); got != 0 {
		t.Fatalf("ShannonEntropy(\"\") = %v, want 0", got)
	}
}

func TestShannonEntropy_AllSameCharacterIsZero(t *testing.T) {
	if got := ShannonEntropy("aaaaaaaaaa"); got != 0 {
		t.Fatalf("ShannonEntropy(all-same) = %v, want 0", got)
	}
}

func TestShannonEntropy_UniformBinaryIsOne(t *testing.T) {
	// "ab" repeated: exactly 2 symbols, 50/50 split -> entropy = 1 bit.
	got := ShannonEntropy("abababab")
	if math.Abs(got-1.0) > 1e-9 {
		t.Fatalf("ShannonEntropy(ababab...) = %v, want 1.0", got)
	}
}

func TestShannonEntropy_RandomLooking_HigherThanWord(t *testing.T) {
	word := ShannonEntropy("password")
	random := ShannonEntropy("xK9$mQ2#pL7@vR4!")
	if random <= word {
		t.Fatalf("expected random-looking string entropy (%v) > natural word entropy (%v)", random, word)
	}
}
