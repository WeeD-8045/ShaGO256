package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"ShaGo/sha256"
)

type Problem10Input struct {
	State         [8]uint32 `json:"state"`
	RoundConstant uint32    `json:"round_constant"`
	ScheduleWord  uint32    `json:"schedule_word"`
}

type Problem11Input struct {
	State [8]uint32 `json:"state"`
	Block string    `json:"block"`
}

type Problem14Input struct {
	OriginalInput string `json:"original_input"`
	ChosenSuffix  string `json:"chosen_suffix"`
}

type Problem16Input struct {
	OriginalHash string `json:"original_hash"`
	OriginalLen  uint64 `json:"original_len"`
	ChosenSuffix string `json:"chosen_suffix"`
}

type Input struct {
	Problem1  [][2]uint32    `json:"problem1"`
	Problem2  [][2]uint32    `json:"problem2"`
	Problem3  uint32         `json:"problem3"`
	Problem4  uint32         `json:"problem4"`
	Problem5  string         `json:"problem5"`
	Problem6  uint32         `json:"problem6"`
	Problem7  uint32         `json:"problem7"`
	Problem8  [3]uint32      `json:"problem8"`
	Problem9  [3]uint32      `json:"problem9"`
	Problem10 Problem10Input `json:"problem10"`
	Problem11 Problem11Input `json:"problem11"`
	Problem12 []uint64       `json:"problem12"`
	Problem13 []string       `json:"problem13"`
	Problem14 Problem14Input `json:"problem14"`
	Problem15 string         `json:"problem15"`
	Problem16 Problem16Input `json:"problem16"`
}

type Output struct {
	Problem1  []uint32  `json:"problem1"`
	Problem2  []uint32  `json:"problem2"`
	Problem3  uint32    `json:"problem3"`
	Problem4  uint32    `json:"problem4"`
	Problem5  []uint32  `json:"problem5"`
	Problem6  uint32    `json:"problem6"`
	Problem7  uint32    `json:"problem7"`
	Problem8  uint32    `json:"problem8"`
	Problem9  uint32    `json:"problem9"`
	Problem10 [8]uint32 `json:"problem10"`
	Problem11 [8]uint32 `json:"problem11"`
	Problem12 []string  `json:"problem12"`
	Problem13 []string  `json:"problem13"`
	Problem14 string    `json:"problem14"`
	Problem15 [8]uint32 `json:"problem15"`
	Problem16 string    `json:"problem16"`
}

func main() {
	inputBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
		os.Exit(1)
	}

	var in Input
	if err := json.Unmarshal(inputBytes, &in); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding JSON: %v\n", err)
		os.Exit(1)
	}

	var out Output

	// Problem 1: add32
	out.Problem1 = make([]uint32, len(in.Problem1))
	for i, pair := range in.Problem1 {
		out.Problem1[i] = sha256.Add32(pair[0], pair[1])
	}

	// Problem 2: rightrotate32
	out.Problem2 = make([]uint32, len(in.Problem2))
	for i, pair := range in.Problem2 {
		out.Problem2[i] = sha256.RightRotate32(pair[0], pair[1])
	}

	// Problem 3: little_sigma0
	out.Problem3 = sha256.LittleSigma0(in.Problem3)

	// Problem 4: little_sigma1
	out.Problem4 = sha256.LittleSigma1(in.Problem4)

	// Problem 5: message schedule
	schedule := sha256.MessageSchedule([]byte(in.Problem5))
	out.Problem5 = schedule[:]

	// Problem 6: big_sigma0
	out.Problem6 = sha256.BigSigma0(in.Problem6)

	// Problem 7: big_sigma1
	out.Problem7 = sha256.BigSigma1(in.Problem7)

	// Problem 8: choice
	out.Problem8 = sha256.Choice(in.Problem8[0], in.Problem8[1], in.Problem8[2])

	// Problem 9: majority
	out.Problem9 = sha256.Majority(in.Problem9[0], in.Problem9[1], in.Problem9[2])

	// Problem 10: round
	out.Problem10 = sha256.Round(in.Problem10.State, in.Problem10.RoundConstant, in.Problem10.ScheduleWord)

	// Problem 11: compress_block
	out.Problem11 = sha256.CompressBlock(in.Problem11.State, []byte(in.Problem11.Block))

	// Problem 12: padding
	out.Problem12 = make([]string, len(in.Problem12))
	for i, length := range in.Problem12 {
		out.Problem12[i] = hex.EncodeToString(sha256.Padding(length))
	}

	// Problem 13: sha256
	out.Problem13 = make([]string, len(in.Problem13))
	for i, msg := range in.Problem13 {
		digest := sha256.Sum([]byte(msg))
		out.Problem13[i] = hex.EncodeToString(digest[:])
	}

	// Problem 14: extended input
	extended := sha256.ExtendedInput([]byte(in.Problem14.OriginalInput), []byte(in.Problem14.ChosenSuffix))
	out.Problem14 = hex.EncodeToString(extended)

	// Problem 15: reconstitute state
	h15Bytes, err := hex.DecodeString(in.Problem15)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding problem15 hex: %v\n", err)
		os.Exit(1)
	}
	var h15 [32]byte
	copy(h15[:], h15Bytes)
	out.Problem15 = sha256.ReconstituteState(h15)

	// Problem 16: length extension attack
	h16Bytes, err := hex.DecodeString(in.Problem16.OriginalHash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding problem16 hex: %v\n", err)
		os.Exit(1)
	}
	var h16 [32]byte
	copy(h16[:], h16Bytes)
	attackDigest := sha256.LengthExtend(h16, in.Problem16.OriginalLen, []byte(in.Problem16.ChosenSuffix))
	out.Problem16 = hex.EncodeToString(attackDigest[:])

	// Marshal and output JSON
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&out); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON output: %v\n", err)
		os.Exit(1)
	}
}
