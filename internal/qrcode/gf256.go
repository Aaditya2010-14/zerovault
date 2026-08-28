package qrcode

// GF(256) arithmetic for QR code Reed-Solomon error correction, built on
// the field QR codes are defined over: primitive polynomial x^8 + x^4 +
// x^3 + x^2 + 1 (0x11D), generator element 2. exp/log tables are built
// once at package init rather than computed per encode.
var gfExp [512]byte // extended to 512 so gfExp[i] for i in [255,510) avoids a modulo on every multiply
var gfLog [256]byte

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// rsGeneratorDivisor returns the degree-n generator polynomial for
// Reed-Solomon encoding with n error correction codewords — the product
// of (x - 2^i) for i in [0, n) — as the n coefficients *excluding* the
// implicit leading x^n term (which is always 1, since the generator is
// monic), ordered from the x^(n-1) coefficient down to the constant term.
// This is the layout rsEncode's polynomial-division loop expects.
func rsGeneratorDivisor(n int) []byte {
	result := make([]byte, n)
	result[n-1] = 1
	root := byte(1)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			result[j] = gfMul(result[j], root)
			if j+1 < n {
				result[j] ^= result[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return result
}

// rsEncode computes the Reed-Solomon error correction codewords for data
// via polynomial long division (implemented as an LFSR-style running
// remainder, the standard way to compute this without ever materializing
// the full data*x^n polynomial) by the generator polynomial — the
// standard QR code ECC algorithm.
func rsEncode(data []byte, eccLen int) []byte {
	divisor := rsGeneratorDivisor(eccLen)
	remainder := make([]byte, eccLen)

	for _, d := range data {
		factor := d ^ remainder[0]
		copy(remainder, remainder[1:])
		remainder[eccLen-1] = 0
		if factor != 0 {
			for i := range remainder {
				remainder[i] ^= gfMul(divisor[i], factor)
			}
		}
	}
	return remainder
}
