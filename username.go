package auth

import (
	"errors"
	"fmt"

	"golang.org/x/text/secure/precis"
)

// Sentinel errors returned by [NormalizeUsername].
var (
	// ErrUsernameEmpty reports that the username is empty, or normalized to
	// empty. RFC 8265 §3.1 requires a non-empty result; see [NormalizeUsername]
	// for why this library enforces that itself.
	ErrUsernameEmpty = errors.New("username must not be empty")

	// ErrUsernameInvalid reports that the username contains a code point the
	// PRECIS IdentifierClass disallows. The wrapped error carries the detail
	// from golang.org/x/text and is not part of this library's contract.
	ErrUsernameInvalid = errors.New("username contains a disallowed character")
)

// NormalizeUsername returns the canonical form of a username: two names that
// normalize to the same string identify the same account, and two that do not
// are different accounts. A consumer's storage layer applies it to build the
// unique-username index key, and applies it again to the login input before the
// lookup, so the comparison happens on canonical forms at both ends.
//
// The rule is the UsernameCaseMapped profile of the PRECIS IdentifierClass
// (RFC 8265 §3.3), which case-folds and applies Unicode normalization. Two
// consequences a caller should know, because neither matches a naive
// ASCII-lowercasing rule:
//
//   - Case folding covers the whole of Unicode, so "Müller" and "MÜLLER" are one
//     account. It is not a transliteration: "straße" does not fold to "strasse",
//     so those remain two accounts.
//   - The IdentifierClass disallows spaces, so "alex muller" is rejected rather
//     than normalized. Dots, hyphens and underscores are allowed.
//
// It returns ErrUsernameEmpty for an empty result and ErrUsernameInvalid,
// wrapping the underlying cause, for anything the profile refuses. The
// empty check is this library's own: RFC 8265 §3.1 requires a non-empty
// result, but precis.UsernameCaseMapped accepts the empty string (see
// https://github.com/golang/go/issues/64531), so the standard does not arrive
// complete from golang.org/x/text. Checking the result rather than the input
// covers both that case and any input the profile's mapping steps reduce to
// nothing.
func NormalizeUsername(username string) (string, error) {
	normalized, err := precis.UsernameCaseMapped.String(username)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUsernameInvalid, err)
	}
	if normalized == "" {
		return "", ErrUsernameEmpty
	}
	return normalized, nil
}
