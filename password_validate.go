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

// validatePasswordLength enforces the shared maximum (128 chars, preventing
// DoS via Argon2id processing of extremely long inputs) and the given minimum,
// both counted in runes.
func validatePasswordLength(password string, minLen int) error {
	runeLen := len([]rune(password))
	if runeLen > PasswordMaxLength {
		return fmt.Errorf("password must be at most %d characters", PasswordMaxLength)
	}
	if runeLen < minLen {
		return fmt.Errorf("password must be at least %d characters", minLen)
	}
	return nil
}

// ValidateMultiFactorPasswordLength enforces minimum and maximum password
// length for an account where the password is NOT the sole sufficient factor
// (minimum [PasswordMinLengthMultiFactor]). Use [ValidateSoloPasswordLength]
// when password login alone grants access. Neither arm kept the pre-v4 name,
// so a migrating caller must choose an arm explicitly instead of silently
// inheriting the weaker minimum.
func ValidateMultiFactorPasswordLength(password string) error {
	return validatePasswordLength(password, PasswordMinLengthMultiFactor)
}

// ValidateSoloPasswordLength enforces minimum and maximum password length for
// an account where password login is enabled and thus a sole sufficient
// factor (minimum [PasswordMinLengthSolo]).
func ValidateSoloPasswordLength(password string) error {
	return validatePasswordLength(password, PasswordMinLengthSolo)
}

// PasswordContext carries the user-specific values a candidate password must
// not trivially embed. Passing it as a field-named struct keeps the password
// and the username from sitting as adjacent same-typed parameters, where a
// silent swap would validate the username against itself.
//
// WARNING: the zero value FAILS OPEN — it turns every context check off.
// An empty Username disables the username-substring check and an empty
// ForbiddenWords disables the forbidden-word check, so a partial literal
// silently validates less, not more. Populate every field the account has.
type PasswordContext struct {
	// Username is rejected as a password substring when it is at least four
	// characters long (shorter names over-reject common words).
	Username string
	// ForbiddenWords are app-specific words (site name, product name) the
	// password must not contain; empty entries are ignored.
	ForbiddenWords []string
}

// ValidatePasswordContext rejects passwords that trivially embed the username
// or any of the forbidden words in pctx.
func ValidatePasswordContext(password string, pctx PasswordContext) error {
	lower := strings.ToLower(password)
	for _, word := range pctx.ForbiddenWords {
		if word != "" && strings.Contains(lower, strings.ToLower(word)) {
			return errors.New("password must not contain a forbidden word")
		}
	}
	if len(pctx.Username) >= 4 && strings.Contains(lower, strings.ToLower(pctx.Username)) {
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
