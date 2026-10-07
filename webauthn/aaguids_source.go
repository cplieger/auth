package webauthn

//go:generate go run gen_aaguids.go

// aaguidListCommit is the commit of the community AAGUID list that
// aaguids_gen.go was generated from; go generate fetches the list at it.
// renovate: datasource=git-refs depName=passkey-authenticator-aaguids packageName=https://github.com/passkeydeveloper/passkey-authenticator-aaguids branch=main
const aaguidListCommit = "33084641e49c2f15ea124e1e5f713f8dac131257"
