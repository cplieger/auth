package webauthn

//go:generate go run ../internal/cmd/genaaguids

// aaguidListCommit is the commit of the community AAGUID list that
// aaguids_gen.go was generated from; go generate fetches the list at it.
// renovate: datasource=git-refs depName=passkey-authenticator-aaguids packageName=https://github.com/passkeydeveloper/passkey-authenticator-aaguids branch=main
const aaguidListCommit = "12285f5642ba7f470d4964dfdbe007994db059dc"
