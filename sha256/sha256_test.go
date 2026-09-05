package sha256

import (
	"bytes"
	cryptoSha256 "crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestStandardCompatibility(t *testing.T) {
	// Test empty message
	empty := []byte("")
	ourEmpty := Sum(empty)
	stdEmpty := cryptoSha256.Sum256(empty)
	if ourEmpty != stdEmpty {
		t.Fatalf("Empty mismatch: %x != %x", ourEmpty, stdEmpty)
	}

	// Test lengths 0 through 1000 with varying patterns
	for length := 0; length <= 1000; length++ {
		data := make([]byte, length)
		for i := 0; i < length; i++ {
			data[i] = byte((i * 31 + 7) % 251)
		}
		ourSum := Sum(data)
		stdSum := cryptoSha256.Sum256(data)
		if ourSum != stdSum {
			t.Fatalf("Mismatch at length %d: our=%x, std=%x", length, ourSum, stdSum)
		}
	}
}

func TestKnownVectors(t *testing.T) {
	vectors := []struct {
		input    string
		expected string
	}{
		{
			"",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			"hello world",
			"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
		{
			"The quick brown fox jumps over the lazy dog",
			"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
		},
	}

	for _, tc := range vectors {
		got := Sum([]byte(tc.input))
		gotHex := hex.EncodeToString(got[:])
		if gotHex != tc.expected {
			t.Errorf("For %q: got %s, expected %s", tc.input, gotHex, tc.expected)
		}
	}
}

func TestBuildingBlocks(t *testing.T) {
	// Add32
	if Add32(4294967295, 1) != 0 {
		t.Errorf("Add32 overflow failed")
	}
	if Add32(1, 2) != 3 {
		t.Errorf("Add32 basic addition failed")
	}

	// RightRotate32
	if RightRotate32(2, 1) != 1 {
		t.Errorf("RightRotate32(2, 1) failed")
	}
	if RightRotate32(1, 1) != 2147483648 {
		t.Errorf("RightRotate32(1, 1) failed")
	}
	if RightRotate32(2919882184, 31) != 1544797073 {
		t.Errorf("RightRotate32(2919882184, 31) failed")
	}

	// Sigma functions
	if LittleSigma0(1114723206) != 1345017931 {
		t.Errorf("LittleSigma0 failed")
	}
	if LittleSigma1(1232674167) != 2902922196 {
		t.Errorf("LittleSigma1 failed")
	}
	if BigSigma0(3536071395) != 3003388882 {
		t.Errorf("BigSigma0 failed")
	}
	if BigSigma1(651015076) != 2194029931 {
		t.Errorf("BigSigma1 failed")
	}

	// Boolean functions
	if Choice(2749825547, 776049372, 1213590135) != 1783753340 {
		t.Errorf("Choice failed")
	}
	if Majority(3758166654, 2821345890, 1850678816) != 3893039714 {
		t.Errorf("Majority failed")
	}
}

func TestPadding(t *testing.T) {
	p0 := Padding(0)
	if len(p0) != 64 {
		t.Errorf("Padding(0) length = %d, expected 64", len(p0))
	}
	if p0[0] != 0x80 {
		t.Errorf("Padding(0)[0] != 0x80")
	}

	// 55 bytes message + 9 bytes padding = 64 bytes (1 block)
	p55 := Padding(55)
	if len(p55) != 9 {
		t.Errorf("Padding(55) length = %d, expected 9", len(p55))
	}

	// 56 bytes message needs a second block: 56 + 72 = 128 bytes
	p56 := Padding(56)
	if len(p56) != 72 {
		t.Errorf("Padding(56) length = %d, expected 72", len(p56))
	}
}

func TestLengthExtensionAttack(t *testing.T) {
	for originalLen := 0; originalLen < 200; originalLen++ {
		originalInput := make([]byte, originalLen)
		for i := 0; i < originalLen; i++ {
			originalInput[i] = byte((i * 17) % 256)
		}
		chosenSuffix := []byte(fmt.Sprintf("extended_payload_step_%d", originalLen))

		origHash := Sum(originalInput)

		// Attacker extends the hash without knowing originalInput
		extendedHash := LengthExtend(origHash, uint64(originalLen), chosenSuffix)

		// Verify against directly hashing the synthesized message
		fullInput := ExtendedInput(originalInput, chosenSuffix)
		expectedHash := Sum(fullInput)

		if !bytes.Equal(extendedHash[:], expectedHash[:]) {
			t.Fatalf("Length extension attack mismatch at len %d:\n  got: %x\n want: %x",
				originalLen, extendedHash, expectedHash)
		}
	}
}

func BenchmarkSum1KB(b *testing.B) {
	data := make([]byte, 1024)
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(data)
	}
}

func BenchmarkCryptoSha256_1KB(b *testing.B) {
	data := make([]byte, 1024)
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cryptoSha256.Sum256(data)
	}
}
