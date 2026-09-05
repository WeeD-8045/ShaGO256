package sha256

// Round performs a single round of SHA-256 compression on the 8-word state.
func Round(state [8]uint32, roundConstant uint32, scheduleWord uint32) [8]uint32 {
	s1 := BigSigma1(state[4])
	ch := Choice(state[4], state[5], state[6])
	temp1 := state[7] + s1 + ch + roundConstant + scheduleWord

	s0 := BigSigma0(state[0])
	maj := Majority(state[0], state[1], state[2])
	temp2 := s0 + maj

	return [8]uint32{
		temp1 + temp2,
		state[0],
		state[1],
		state[2],
		state[3] + temp1,
		state[4],
		state[5],
		state[6],
	}
}

// CompressBlock runs all 64 rounds on a 64-byte block and adds the result back into inputState.
func CompressBlock(inputState [8]uint32, block []byte) [8]uint32 {
	w := MessageSchedule(block)
	state := inputState
	for i := 0; i < 64; i++ {
		state = Round(state, RoundConstants[i], w[i])
	}
	return [8]uint32{
		inputState[0] + state[0],
		inputState[1] + state[1],
		inputState[2] + state[2],
		inputState[3] + state[3],
		inputState[4] + state[4],
		inputState[5] + state[5],
		inputState[6] + state[6],
		inputState[7] + state[7],
	}
}

func compress(state *[8]uint32, W [64]uint32) {
	curr := *state
	for i := 0; i < 64; i++ {
		curr = Round(curr, RoundConstants[i], W[i])
	}
	for i := 0; i < 8; i++ {
		state[i] += curr[i]
	}
}

