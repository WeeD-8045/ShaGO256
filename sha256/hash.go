package sha256

import "encoding/binary"

// HashFromState serializes the 8 32-bit state words into a 32-byte big-endian digest.
func HashFromState(state [8]uint32) [32]byte {
	var digest [32]byte
	for i, v := range state {
		binary.BigEndian.PutUint32(digest[i*4:], v)
	}
	return digest
}

// Sum computes the SHA-256 checksum of data.
func Sum(data []byte) [32]byte {
	padded := PadMessage(data)
	state := IV
	for i := 0; i < len(padded); i += 64 {
		state = CompressBlock(state, padded[i:i+64])
	}
	return HashFromState(state)
}

