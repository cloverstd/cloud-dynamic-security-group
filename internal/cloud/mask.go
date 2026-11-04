package cloud

import (
	"crypto/sha256"
	"encoding/hex"
)

func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:6])
}
