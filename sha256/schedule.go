package sha256

// MessageSchedule expands a 64-byte block into 64 32-bit words (W).
func MessageSchedule(block []byte) [64]uint32 {
	if len(block) != 64 {
		panic("block must be exactly 64 bytes")
	}

	var W [64]uint32

	// First 16 words are read directly from the block (big-endian).
	for i := 0; i < 16; i++ {
		j := i * 4
		W[i] = uint32(block[j])<<24 |
			uint32(block[j+1])<<16 |
			uint32(block[j+2])<<8 |
			uint32(block[j+3])
	}

	// Expand words 16 through 63 using little sigma functions.
	for i := 16; i < 64; i++ {
		s0 := LittleSigma0(W[i-15])
		s1 := LittleSigma1(W[i-2])
		W[i] = W[i-16] + s0 + W[i-7] + s1
	}

	return W
}

func buildSchedule(block []byte) [64]uint32 {
	return MessageSchedule(block)
}

