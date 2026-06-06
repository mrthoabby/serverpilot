package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	totpIssuer   = "ServerPilot"
	totpDigits   = 6
	totpPeriod   = 30
	totpKeyBytes = 20
)

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a base32-encoded secret suitable for authenticator
// apps. The secret is persisted only after the operator proves possession by
// submitting a valid code.
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, totpKeyBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("failed to generate MFA secret")
	}
	return base32NoPadding.EncodeToString(raw), nil
}

// TOTPAuthURL returns the otpauth URI consumed by authenticator apps.
func TOTPAuthURL(username, secret string) string {
	label := url.PathEscape(totpIssuer + ":" + username)
	q := url.Values{}
	q.Set("secret", strings.ToUpper(strings.TrimSpace(secret)))
	q.Set("issuer", totpIssuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(totpDigits))
	q.Set("period", strconv.Itoa(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// ValidateTOTPCode verifies a 6-digit TOTP code with a one-step clock skew
// window. The accepted window is current, previous, or next 30-second step.
func ValidateTOTPCode(secret, code string, now time.Time) bool {
	cleanCode := strings.TrimSpace(code)
	if len(cleanCode) != totpDigits {
		return false
	}
	for _, c := range cleanCode {
		if c < '0' || c > '9' {
			return false
		}
	}

	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return false
	}
	counter := now.Unix() / totpPeriod
	for offset := int64(-1); offset <= 1; offset++ {
		expected := totpCode(key, uint64(counter+offset))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(cleanCode)) == 1 {
			return true
		}
	}
	return false
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	clean := strings.ToUpper(strings.TrimSpace(secret))
	clean = strings.ReplaceAll(clean, " ", "")
	if clean == "" || len(clean) > 128 {
		return nil, fmt.Errorf("invalid MFA secret")
	}
	return base32NoPadding.DecodeString(clean)
}

func totpCode(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	code := binCode % 1000000
	return fmt.Sprintf("%06d", code)
}
