package sha256

import (
	"encoding/hex"
	"os"
)

// HashFile reads a file from disk and returns its SHA-256 checksum as a hex string.
func HashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	sum := Sum(data)
	return hex.EncodeToString(sum[:]), nil
}

