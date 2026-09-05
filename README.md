# ShaGo: SHA-256 and Length Extension Attack in Go

A complete, educational, and production-clean implementation of **SHA-256** and the **SHA-256 Length Extension Attack** in Go, based on [oconnor663/sha256_project](https://github.com/oconnor663/sha256_project) (developed for NYU Tandon's CS-GY 6903 Applied Cryptography course).

---

## Features

- **Pure Go from scratch**: Zero third-party runtime dependencies. Implements modular addition, bitwise rotations, message schedule expansion, round functions, block compression, padding, and state extraction.
- **Passes All 16 Assignment Problems**: Fully autograded via `grade.py` against randomized vectors.
- **Length Extension Attack**: Full implementation demonstrating how Merkle–Damgård hash functions without a MAC construct can be compromised without knowing secret keys.
- **Standard Library Verified**: Tested against Go's standard `crypto/sha256` across arbitrary message lengths (0–1000+ bytes).
- **Dual Entrypoints**:
  - `cmd/main` (`shago`): Interactive CLI for file hashing, string hashing, verification, and length extension attack demonstrations.
  - `cmd/solution`: Fast JSON input/output solver for the assignment autograder.

---

## Project Structure

```
ShaGo/
├── cmd/
│   ├── main/main.go       # Interactive CLI tool (file/string hashing, attack demo, --solve)
│   └── solution/main.go   # Autograder JSON stdin/stdout runner
├── sha256/
│   ├── attack.go          # Problems 14-16: Length extension attack & state reconstitution
│   ├── compress.go        # Problems 10-11: 64-round compression and round function
│   ├── constants.go       # Initial hash values (IV/H0) and 64 round constants (K)
│   ├── file.go            # File hashing utilities
│   ├── hash.go            # Problem 13: Full SHA-256 Sum and state formatting
│   ├── helpers.go         # Problems 1-4, 6-9: Add32, RightRotate32, Sigmas, Choice, Majority
│   ├── padding.go         # Problem 12: Big-endian bit-length encoded padding
│   ├── schedule.go        # Problem 5: 64-word message schedule expansion
│   └── sha256_test.go     # Comprehensive unit tests, compatibility tests & benchmarks
├── example_input.json     # Example assignment test vectors
├── example_output.json    # Expected outputs for example vectors
├── generate_input.py      # Random vector generator for grading
├── grade.py               # Official autograding script
└── go.mod                 # Go module definition
```

---

## 16 Assignment Problems

| Problem | Description | Function |
|---------|-------------|----------|
| **1** | Addition modulo $2^{32}$ | `sha256.Add32(a, b)` |
| **2** | Bitwise right rotation | `sha256.RightRotate32(x, n)` |
| **3** | Little sigma 0 ($\sigma_0$) | `sha256.LittleSigma0(x)` |
| **4** | Little sigma 1 ($\sigma_1$) | `sha256.LittleSigma1(x)` |
| **5** | Message schedule expansion | `sha256.MessageSchedule(block)` |
| **6** | Big sigma 0 ($\Sigma_0$) | `sha256.BigSigma0(x)` |
| **7** | Big sigma 1 ($\Sigma_1$) | `sha256.BigSigma1(x)` |
| **8** | Choice function $Ch(x, y, z)$ | `sha256.Choice(x, y, z)` |
| **9** | Majority function $Maj(x, y, z)$ | `sha256.Majority(x, y, z)` |
| **10** | Single SHA-256 round | `sha256.Round(state, roundConst, schedWord)` |
| **11** | Block compression function | `sha256.CompressBlock(state, block)` |
| **12** | SHA-256 padding bytes | `sha256.Padding(inputLen)` |
| **13** | Full SHA-256 hash | `sha256.Sum(data)` |
| **14** | Synthetic extended input | `sha256.ExtendedInput(orig, suffix)` |
| **15** | State recovery from hash | `sha256.ReconstituteState(hash)` |
| **16** | Length extension attack | `sha256.LengthExtend(hash, origLen, suffix)` |

---

## Quick Start

### 1. Run Unit Tests
```bash
go test -v ./sha256/...
```

### 2. Run Benchmarks
```bash
go test -bench="." ./sha256
```

### 3. Run Autograder
```bash
python grade.py go run ./cmd/solution
# Or using compiled binary:
go build -o solution.exe ./cmd/solution
python grade.py .\solution.exe
```

Expected output:
```
problem1 correct
problem2 correct
...
problem16 correct
Well done!
```

---

## CLI Usage

Build the CLI tool:
```bash
go build -o shago.exe ./cmd/main
```

### Hash a string:
```bash
./shago -s "hello world"
# b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

### Hash a file:
```bash
./shago myfile.txt
```

### Verify against an expected digest:
```bash
./shago -c b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9 -s "hello world"
# OK: "hello world" matches b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

### Demonstrate Length Extension Attack:
```bash
./shago extend \
  -hash 27b82abe296f3ecd5174b6e6168ea683cd8ef94306d9abd9f81807f2fa587d2a \
  -len 41 \
  -suffix "manatee jaguar zebra zebra dog"
```
