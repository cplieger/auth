package auth

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 required by HIBP k-anonymity API (not for security)
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// PasswordMinLengthMultiFactor is the minimum password length when password
// login is not the sole sufficient factor.
const PasswordMinLengthMultiFactor = 8

// PasswordMinLengthSolo is the minimum password length when password login is
// enabled and thus a sole sufficient factor.
const PasswordMinLengthSolo = 15

// PasswordMaxLength is the maximum password length to prevent DoS via
// extremely long inputs to Argon2id (OWASP recommendation).
const PasswordMaxLength = 128

// hibpRequestTimeout is the HTTP request timeout for the Have I Been Pwned
// k-anonymity API.
const hibpRequestTimeout = 5 * time.Second

// ValidatePasswordLength enforces minimum and maximum password length.
// Maximum length (128 chars) prevents DoS via Argon2id processing of
// extremely long inputs.
func ValidatePasswordLength(password string, passwordOnly bool) error {
	runeLen := len([]rune(password))
	if runeLen > PasswordMaxLength {
		return fmt.Errorf("password must be at most %d characters", PasswordMaxLength)
	}
	minLen := PasswordMinLengthMultiFactor
	if passwordOnly {
		minLen = PasswordMinLengthSolo
	}
	if runeLen < minLen {
		return fmt.Errorf("password must be at least %d characters", minLen)
	}
	return nil
}

// ValidatePasswordContext rejects passwords that trivially embed the username
// or any of the provided forbidden words.
func ValidatePasswordContext(password, username string, forbiddenWords []string) error {
	lower := strings.ToLower(password)
	for _, word := range forbiddenWords {
		if word != "" && strings.Contains(lower, strings.ToLower(word)) {
			return errors.New("password must not contain a forbidden word")
		}
	}
	if len(username) >= 4 && strings.Contains(lower, strings.ToLower(username)) {
		return errors.New("password must not contain your username")
	}
	return nil
}

// CheckBreachedPassword checks a password against the Have I Been Pwned
// Passwords API using k-anonymity. Returns true if the password has been
// found in a breach.
func CheckBreachedPassword(ctx context.Context, client *http.Client, password string) (bool, error) {
	hash := sha1.Sum([]byte(password)) //nolint:gosec // SHA-1 required by HIBP k-anonymity API
	hexHash := fmt.Sprintf("%X", hash)
	prefix := hexHash[:5]
	suffix := hexHash[5:]

	reqCtx, cancel := context.WithTimeout(ctx, hibpRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
		"https://api.pwnedpasswords.com/range/"+prefix, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("auth: create HIBP request: %w", err)
	}
	req.Header.Set("User-Agent", "Auth-Library")
	req.Header.Set("Add-Padding", "true")

	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("auth: breached password check failed, allowing password", "error", err)
		return false, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("auth: breached password check: unexpected status, allowing password",
			"status", resp.StatusCode)
		return false, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MB cap
	if err != nil {
		slog.Warn("auth: breached password check: read response failed, allowing password", "error", err)
		return false, nil
	}

	for line := range strings.SplitSeq(strings.TrimSpace(string(body)), "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], suffix) {
			continue
		}
		count, convErr := strconv.Atoi(strings.TrimSpace(parts[1]))
		if convErr != nil || count == 0 {
			continue
		}
		return true, nil
	}

	return false, nil
}
