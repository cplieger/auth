package auth

import (
	"encoding/hex"
	"strings"
)

// parseAAGUID parses a UUID string into 16 bytes. Used only by tests.
func parseAAGUID(s string) []byte {
	clean := strings.ReplaceAll(s, "-", "")
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != 16 {
		return nil
	}
	return b
}
