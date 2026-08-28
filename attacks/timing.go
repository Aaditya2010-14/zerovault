package attacks

import (
	"fmt"
	"io"
	"strings"
	"time"

	vcrypto "zerovault/internal/crypto"
)

// --- ATTACK LOGIC ---

// timingSample is one real, measured PBKDF2 derivation.
type timingSample struct {
	label    string
	password string
	elapsed  time.Duration
}

// measureDerivation runs the actual DeriveKey ZeroVault uses for every
// unlock and times it. If PBKDF2 leaked information through timing (e.g.
// short-circuiting on password length), longer passwords would visibly
// take longer — they should not, since PBKDF2 always runs the same fixed
// iteration count regardless of input length.
func measureDerivation(password string) time.Duration {
	salt := make([]byte, vcrypto.SaltLen) // fixed salt: isolate password-length effects only
	start := time.Now()
	vcrypto.DeriveKey([]byte(password), salt)
	return time.Since(start)
}

// runTimingAnalysis measures derivation time for passwords of very
// different lengths and checks that the variance between them is small.
func runTimingAnalysis(h *Harness, w io.Writer) Result {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[TIMING] Measuring PBKDF2 key derivation timing...")

	cases := []struct {
		label, password string
	}{
		{`"a" (1 char)`, "a"},
		{`"password" (8 chars)`, "password"},
		{`50-char password`, strings.Repeat("a]v3ry.l0ng-p@ssw0rd", 3)[:50]},
	}

	var samples []timingSample
	for _, c := range cases {
		elapsed := measureDerivation(c.password)
		samples = append(samples, timingSample{c.label, c.password, elapsed})
	}
	reportTimingSamples(w, samples)

	variance := timingVariancePct(samples)
	reportVariance(w, variance)

	total := time.Duration(0)
	for _, s := range samples {
		total += s.elapsed
	}

	// A generous threshold: real side-channel leaks show up as order-of-
	// magnitude differences, not a few percent of OS scheduling jitter.
	if variance > 25.0 {
		return Result{StatusVulnerable, fmt.Sprintf("timing variance %.1f%% is high enough to suggest a side channel", variance), total}
	}
	return Result{StatusSecure, "no timing side-channel detected", total}
}

func timingVariancePct(samples []timingSample) float64 {
	if len(samples) == 0 {
		return 0
	}
	min, max := samples[0].elapsed, samples[0].elapsed
	for _, s := range samples {
		if s.elapsed < min {
			min = s.elapsed
		}
		if s.elapsed > max {
			max = s.elapsed
		}
	}
	if max == 0 {
		return 0
	}
	return float64(max-min) / float64(max) * 100
}

// --- REPORTING ---

func reportTimingSamples(w io.Writer, samples []timingSample) {
	for _, s := range samples {
		fmt.Fprintf(w, "[TIMING] Password %-24s %s\n", s.label+":", formatDuration(s.elapsed))
	}
}

func reportVariance(w io.Writer, pct float64) {
	fmt.Fprintf(w, "[TIMING] Variance: %.1f%% — ", pct)
	if pct <= 25.0 {
		fmt.Fprintln(w, "timing is consistent regardless of password length")
	} else {
		fmt.Fprintln(w, "timing varies more than expected")
	}
}
