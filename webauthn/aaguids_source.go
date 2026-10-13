package webauthn

//go:generate go run ../internal/cmd/genaaguids

// aaguidListCommit is the commit of the community AAGUID list that
// aaguids_gen.go was generated from; go generate fetches the list at it.
// renovate: datasource=git-refs depName=passkey-authenticator-aaguids packageName=https://github.com/passkeydeveloper/passkey-authenticator-aaguids branch=main
const aaguidListCommit = "ec5aef699a9f11fe6ce96888d0e289a156271f8d"
