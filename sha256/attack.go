package sha256

import "encoding/binary"

// ExtendedInput builds the concatenated message:
// originalInput + padding(len(originalInput)) + chosenSuffix.
func ExtendedInput(originalInput, chosenSuffix []byte) []byte {
	pad := Padding(uint64(len(originalInput)))
	result := make([]byte, 0, len(originalInput)+len(pad)+len(chosenSuffix))
	result = append(result, originalInput...)
	result = append(result, pad...)
	result = append(result, chosenSuffix...)
	return result
}

// ReconstituteState unpacks a 32-byte hash back into the 8 internal state words.
func ReconstituteState(hash [32]byte) [8]uint32 {
	var state [8]uint32
	for i := 0; i < 8; i++ {
		state[i] = binary.BigEndian.Uint32(hash[i*4 : i*4+4])
	}
	return state
}

// LengthExtend computes SHA256(original || padding || chosenSuffix) using only
// originalHash and originalLen, without knowing what original was.
func LengthExtend(originalHash [32]byte, originalLen uint64, chosenSuffix []byte) [32]byte {
	state := ReconstituteState(originalHash)
	syntheticLen := originalLen + uint64(len(Padding(originalLen))) + uint64(len(chosenSuffix))
	finalPadding := Padding(syntheticLen)

	newBlocks := make([]byte, 0, len(chosenSuffix)+len(finalPadding))
	newBlocks = append(newBlocks, chosenSuffix...)
	newBlocks = append(newBlocks, finalPadding...)

	for i := 0; i < len(newBlocks); i += 64 {
		state = CompressBlock(state, newBlocks[i:i+64])
	}

	return HashFromState(state)
}

