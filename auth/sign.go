package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// Sign returns an HMAC of msg keyed with the JWT secret, for links Scarf
// hands out and must later trust (the download proxy).
func Sign(msg string) string {
	mac := hmac.New(sha256.New, jwtKey)
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature made by Sign.
func Verify(msg, sig string) bool {
	return len(jwtKey) > 0 && hmac.Equal([]byte(Sign(msg)), []byte(sig))
}
