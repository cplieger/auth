package auth_test

import (
	"context"
	"fmt"
	"time"

	"github.com/cplieger/auth"
	"github.com/cplieger/auth/authtest"
)

func ExampleHashPassword() {
	hash, err := auth.HashPassword("my-secure-password")
	if err != nil {
		panic(err)
	}
	ok, err := auth.VerifyPassword("my-secure-password", hash)
	if err != nil {
		panic(err)
	}
	fmt.Println(ok)
	// Output: true
}

func ExampleValidatePasswordLength() {
	err := auth.ValidatePasswordLength("short", true)
	fmt.Println(err != nil)
	// Output: true
}

func ExampleGenerateSessionToken() {
	plaintext, hash, err := auth.GenerateSessionToken()
	if err != nil {
		panic(err)
	}
	fmt.Println(len(plaintext) == 64, len(hash) == 64, plaintext != hash)
	// Output: true true true
}

func ExampleGenerateAPIKey() {
	plaintext, hash, prefix, suffix, err := auth.GenerateAPIKey("ak_")
	if err != nil {
		panic(err)
	}
	fmt.Println(plaintext[:3], len(hash) == 64, len(prefix) == 8, len(suffix) == 4)
	// Output: ak_ true true true
}

func ExampleAuthenticator_RequireAuth() {
	store := authtest.NewMemStore()
	store.AddUser(&auth.User{
		Username: "alice",
		Role:     auth.RoleAdmin,
		Enabled:  true,
	})

	authn, err := auth.NewAuthenticator(
		store,
		auth.WithIdleTimeout(1*time.Hour),
		auth.WithAbsTimeout(24*time.Hour),
	)
	if err != nil {
		panic(err)
	}
	_ = authn
	fmt.Println("authenticator configured")
	// Output: authenticator configured
}

func ExampleVerifyAPIKey() {
	store := authtest.NewMemStore()
	store.AddUser(&auth.User{
		Username: "bot",
		Role:     auth.RoleUser,
		Enabled:  true,
	})

	plaintext, hash, prefix, suffix, _ := auth.GenerateAPIKey("ak_")
	store.AddAPIKey(&auth.Key{
		UserID:    1,
		KeyHash:   hash,
		KeyPrefix: prefix,
		KeySuffix: suffix,
		Label:     "ci",
	})

	key, err := auth.VerifyAPIKey(context.Background(), store, plaintext)
	fmt.Println(key != nil, err == nil)
	// Output: true true
}

func ExampleHasRole() {
	admin := &auth.User{Role: auth.RoleAdmin}
	user := &auth.User{Role: auth.RoleUser}
	fmt.Println(auth.HasRole(admin, auth.RoleUser))
	fmt.Println(auth.HasRole(user, auth.RoleAdmin))
	// Output:
	// true
	// false
}

func ExampleValidateRedirectURI() {
	fmt.Println(auth.ValidateRedirectURI("/dashboard"))
	fmt.Println(auth.ValidateRedirectURI("https://evil.com"))
	// Output:
	// /dashboard
	// /
}
