package webauthn

//go:generate go run ../internal/cmd/genaaguids

// aaguidListCommit is the commit of the community AAGUID list that
// aaguids_gen.go was generated from; go generate fetches the list at it.
// renovate: datasource=git-refs depName=passkey-authenticator-aaguids packageName=https://github.com/passkeydeveloper/passkey-authenticator-aaguids branch=main
const aaguidListCommit = "eb87f8f5e9a69ad36f2c5bd73e5883e68cb71bd2"
