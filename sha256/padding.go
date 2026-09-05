package sha256

import "encoding/binary"

// Padding computes the standard SHA-256 padding bytes for a given input length.
// Appends 0x80, zeros to align to 56 mod 64, and the 64-bit big-endian bit length.
func Padding(inputLength uint64) []byte {
	remainderBytes := (inputLength + 8) % 64
	fillerBytes := 64 - remainderBytes
	zeroBytes := fillerBytes - 1

	totalPaddingLen := 1 + zeroBytes + 8
	pad := make([]byte, totalPaddingLen)
	pad[0] = 0x80

	bitLength := inputLength * 8
	binary.BigEndian.PutUint64(pad[totalPaddingLen-8:], bitLength)

	return pad
}

// PadMessage appends SHA-256 padding to msg.
func PadMessage(msg []byte) []byte {
	p := Padding(uint64(len(msg)))
	result := make([]byte, len(msg)+len(p))
	copy(result, msg)
	copy(result[len(msg):], p)
	return result
}

func pad(msg []byte) []byte {
	return PadMessage(msg)
}

