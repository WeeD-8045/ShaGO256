package sha256

import "math/bits"

// Add32 adds two 32-bit words with modulo 2^32 overflow.
func Add32(a, b uint32) uint32 {
	return a + b
}

// RightRotate32 rotates x right by n bits.
func RightRotate32(x uint32, n uint32) uint32 {
	return bits.RotateLeft32(x, -int(n%32))
}

// LittleSigma0 is the message schedule sigma0 function:
// rotr(7) ^ rotr(18) ^ (x >> 3)
func LittleSigma0(x uint32) uint32 {
	return RightRotate32(x, 7) ^ RightRotate32(x, 18) ^ (x >> 3)
}

// LittleSigma1 is the message schedule sigma1 function:
// rotr(17) ^ rotr(19) ^ (x >> 10)
func LittleSigma1(x uint32) uint32 {
	return RightRotate32(x, 17) ^ RightRotate32(x, 19) ^ (x >> 10)
}

// BigSigma0 is the round Sigma0 function:
// rotr(2) ^ rotr(13) ^ rotr(22)
func BigSigma0(x uint32) uint32 {
	return RightRotate32(x, 2) ^ RightRotate32(x, 13) ^ RightRotate32(x, 22)
}

// BigSigma1 is the round Sigma1 function:
// rotr(6) ^ rotr(11) ^ rotr(25)
func BigSigma1(x uint32) uint32 {
	return RightRotate32(x, 6) ^ RightRotate32(x, 11) ^ RightRotate32(x, 25)
}

// Choice returns (x & y) ^ (~x & z), choosing bits from y or z based on x.
func Choice(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

// Majority returns the bitwise majority of x, y, and z.
func Majority(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

// Shorthand helpers for internal use
func rotr(x uint32, n uint) uint32 { return RightRotate32(x, uint32(n)) }
func ch(x, y, z uint32) uint32     { return Choice(x, y, z) }
func maj(x, y, z uint32) uint32    { return Majority(x, y, z) }
func sigma0(x uint32) uint32       { return LittleSigma0(x) }
func sigma1(x uint32) uint32       { return LittleSigma1(x) }
func Sigma0(x uint32) uint32       { return BigSigma0(x) }
func Sigma1(x uint32) uint32       { return BigSigma1(x) }

