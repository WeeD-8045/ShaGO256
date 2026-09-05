package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"ShaGo/sha256"
)


func printUsage() {
	fmt.Println("ShaGo - SHA-256 and Length Extension Attack Tool in Go")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  shago [options] [file...]")
	fmt.Println("  shago extend -hash <hex> -len <num> -suffix <text>")
	fmt.Println("  shago --solve < input.json > output.json")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -s <string>     Hash the provided string argument directly")
	fmt.Println("  -c <hash>       Verify input against expected hex hash")
	fmt.Println("  --solve         Solve all 16 JSON assignment problems from stdin")
	fmt.Println("  -h, --help      Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  shago myfile.txt")
	fmt.Println("  shago -s \"hello world\"")
	fmt.Println("  shago -c b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 -s \"hello world\"")
	fmt.Println("  shago extend -hash 27b82abe... -len 41 -suffix \"extra data\"")
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "extend") {
		runExtend(os.Args[2:])
		return
	}

	stringFlag := flag.String("s", "", "String to hash directly")
	checkFlag := flag.String("c", "", "Expected hex hash to verify against")
	solveFlag := flag.Bool("solve", false, "Solve JSON problems from stdin (grade.py mode)")
	flag.Usage = printUsage
	flag.Parse()

	if *solveFlag {
		runSolve()
		return
	}

	var data []byte
	var label string

	if *stringFlag != "" {
		data = []byte(*stringFlag)
		label = fmt.Sprintf("\"%s\"", *stringFlag)
	} else if flag.NArg() > 0 {
		filePath := flag.Arg(0)
		if filePath == "-" {
			var err error
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
				os.Exit(1)
			}
			label = "stdin"
		} else {
			var err error
			data, err = os.ReadFile(filePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", filePath, err)
				os.Exit(1)
			}
			label = filePath
		}
	} else {
		// Check if standard input has data
		stat, err := os.Stdin.Stat()
		if err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
				os.Exit(1)
			}
			label = "stdin"
		} else {
			printUsage()
			return
		}
	}

	digest := sha256.Sum(data)
	computedHex := hex.EncodeToString(digest[:])

	if *checkFlag != "" {
		expected := strings.ToLower(strings.TrimSpace(*checkFlag))
		if computedHex == expected {
			fmt.Printf("OK: %s matches %s\n", label, expected)
		} else {
			fmt.Printf("FAILED: %s does not match\n  got:  %s\n  want: %s\n", label, computedHex, expected)
			os.Exit(1)
		}
		return
	}

	if label == "stdin" || *stringFlag != "" {
		fmt.Println(computedHex)
	} else {
		fmt.Printf("%s  %s\n", computedHex, label)
	}
}

func runExtend(args []string) {
	fs := flag.NewFlagSet("extend", flag.ExitOnError)
	hashHex := fs.String("hash", "", "Original SHA-256 hash in hex (64 chars)")
	origLen := fs.Uint64("len", 0, "Length of original message in bytes")
	suffix := fs.String("suffix", "", "Suffix string to append")
	fs.Parse(args)

	if *hashHex == "" || *origLen == 0 || *suffix == "" {
		fmt.Println("Usage: shago extend -hash <hex> -len <original_length> -suffix <text>")
		os.Exit(1)
	}

	decodedHash, err := hex.DecodeString(strings.TrimSpace(*hashHex))
	if err != nil || len(decodedHash) != 32 {
		fmt.Fprintf(os.Stderr, "Error: hash must be 64 hexadecimal characters (32 bytes)\n")
		os.Exit(1)
	}

	var origHash [32]byte
	copy(origHash[:], decodedHash)

	suffixBytes := []byte(*suffix)
	extendedHash := sha256.LengthExtend(origHash, *origLen, suffixBytes)
	extendedHashHex := hex.EncodeToString(extendedHash[:])

	pad := sha256.Padding(*origLen)
	syntheticLen := *origLen + uint64(len(pad)) + uint64(len(suffixBytes))

	fmt.Println("=== SHA-256 Length Extension Attack ===")
	fmt.Printf("Original Hash:      %s\n", *hashHex)
	fmt.Printf("Original Length:    %d bytes\n", *origLen)
	fmt.Printf("Padding Added:      %d bytes (hex: %s)\n", len(pad), hex.EncodeToString(pad))
	fmt.Printf("Appended Suffix:    %q (%d bytes)\n", *suffix, len(suffixBytes))
	fmt.Printf("Synthetic Length:   %d bytes\n", syntheticLen)
	fmt.Printf("New Extended Hash:  %s\n", extendedHashHex)
}

func runSolve() {
	inputBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
		os.Exit(1)
	}

	// Unmarshal input json
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(inputBytes, &rawMap); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding JSON: %v\n", err)
		os.Exit(1)
	}

	outputs := make(map[string]any)

	// Problem 1
	if raw, ok := rawMap["problem1"]; ok {
		var pairs [][2]uint32
		if err := json.Unmarshal(raw, &pairs); err == nil {
			res := make([]uint32, len(pairs))
			for i, p := range pairs {
				res[i] = sha256.Add32(p[0], p[1])
			}
			outputs["problem1"] = res
		}
	}

	// Problem 2
	if raw, ok := rawMap["problem2"]; ok {
		var pairs [][2]uint32
		if err := json.Unmarshal(raw, &pairs); err == nil {
			res := make([]uint32, len(pairs))
			for i, p := range pairs {
				res[i] = sha256.RightRotate32(p[0], p[1])
			}
			outputs["problem2"] = res
		}
	}

	// Problem 3
	if raw, ok := rawMap["problem3"]; ok {
		var val uint32
		if err := json.Unmarshal(raw, &val); err == nil {
			outputs["problem3"] = sha256.LittleSigma0(val)
		}
	}

	// Problem 4
	if raw, ok := rawMap["problem4"]; ok {
		var val uint32
		if err := json.Unmarshal(raw, &val); err == nil {
			outputs["problem4"] = sha256.LittleSigma1(val)
		}
	}

	// Problem 5
	if raw, ok := rawMap["problem5"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			sched := sha256.MessageSchedule([]byte(s))
			outputs["problem5"] = sched[:]
		}
	}

	// Problem 6
	if raw, ok := rawMap["problem6"]; ok {
		var val uint32
		if err := json.Unmarshal(raw, &val); err == nil {
			outputs["problem6"] = sha256.BigSigma0(val)
		}
	}

	// Problem 7
	if raw, ok := rawMap["problem7"]; ok {
		var val uint32
		if err := json.Unmarshal(raw, &val); err == nil {
			outputs["problem7"] = sha256.BigSigma1(val)
		}
	}

	// Problem 8
	if raw, ok := rawMap["problem8"]; ok {
		var triple [3]uint32
		if err := json.Unmarshal(raw, &triple); err == nil {
			outputs["problem8"] = sha256.Choice(triple[0], triple[1], triple[2])
		}
	}

	// Problem 9
	if raw, ok := rawMap["problem9"]; ok {
		var triple [3]uint32
		if err := json.Unmarshal(raw, &triple); err == nil {
			outputs["problem9"] = sha256.Majority(triple[0], triple[1], triple[2])
		}
	}

	// Problem 10
	if raw, ok := rawMap["problem10"]; ok {
		var obj struct {
			State         [8]uint32 `json:"state"`
			RoundConstant uint32    `json:"round_constant"`
			ScheduleWord  uint32    `json:"schedule_word"`
		}
		if err := json.Unmarshal(raw, &obj); err == nil {
			outputs["problem10"] = sha256.Round(obj.State, obj.RoundConstant, obj.ScheduleWord)
		}
	}

	// Problem 11
	if raw, ok := rawMap["problem11"]; ok {
		var obj struct {
			State [8]uint32 `json:"state"`
			Block string    `json:"block"`
		}
		if err := json.Unmarshal(raw, &obj); err == nil {
			outputs["problem11"] = sha256.CompressBlock(obj.State, []byte(obj.Block))
		}
	}

	// Problem 12
	if raw, ok := rawMap["problem12"]; ok {
		var lengths []uint64
		if err := json.Unmarshal(raw, &lengths); err == nil {
			res := make([]string, len(lengths))
			for i, l := range lengths {
				res[i] = hex.EncodeToString(sha256.Padding(l))
			}
			outputs["problem12"] = res
		}
	}

	// Problem 13
	if raw, ok := rawMap["problem13"]; ok {
		var msgs []string
		if err := json.Unmarshal(raw, &msgs); err == nil {
			res := make([]string, len(msgs))
			for i, m := range msgs {
				d := sha256.Sum([]byte(m))
				res[i] = hex.EncodeToString(d[:])
			}
			outputs["problem13"] = res
		}
	}

	// Problem 14
	if raw, ok := rawMap["problem14"]; ok {
		var obj struct {
			OriginalInput string `json:"original_input"`
			ChosenSuffix  string `json:"chosen_suffix"`
		}
		if err := json.Unmarshal(raw, &obj); err == nil {
			ext := sha256.ExtendedInput([]byte(obj.OriginalInput), []byte(obj.ChosenSuffix))
			outputs["problem14"] = hex.EncodeToString(ext)
		}
	}

	// Problem 15
	if raw, ok := rawMap["problem15"]; ok {
		var hexStr string
		if err := json.Unmarshal(raw, &hexStr); err == nil {
			b, _ := hex.DecodeString(hexStr)
			var h [32]byte
			copy(h[:], b)
			outputs["problem15"] = sha256.ReconstituteState(h)
		}
	}

	// Problem 16
	if raw, ok := rawMap["problem16"]; ok {
		var obj struct {
			OriginalHash string `json:"original_hash"`
			OriginalLen  uint64 `json:"original_len"`
			ChosenSuffix string `json:"chosen_suffix"`
		}
		if err := json.Unmarshal(raw, &obj); err == nil {
			b, _ := hex.DecodeString(obj.OriginalHash)
			var h [32]byte
			copy(h[:], b)
			attack := sha256.LengthExtend(h, obj.OriginalLen, []byte(obj.ChosenSuffix))
			outputs["problem16"] = hex.EncodeToString(attack[:])
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(outputs)
}

