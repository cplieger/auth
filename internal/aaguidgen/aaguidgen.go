// Package aaguidgen builds the webauthn package's authenticator name table
// from the community passkey AAGUID list at
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids.
package aaguidgen

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const commitConst = "aaguidListCommit"

const (
	rawBaseURL    = "https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/"
	maxInputBytes = 4 << 20
	maxNameRunes  = 64
)

var (
	keyPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// SourceURL returns the raw aaguid.json at one commit of the community list.
func SourceURL(commit string) string {
	return rawBaseURL + commit + "/aaguid.json"
}

// ReadCommit returns the value of the aaguidListCommit string constant
// declared in the Go file at path, refusing anything but a full lowercase
// commit hash.
func ReadCommit(path string) (string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return "", fmt.Errorf("aaguidgen: %w", err)
	}
	value := commitValue(f)
	if value == nil {
		return "", fmt.Errorf("aaguidgen: %s declares no %s constant", path, commitConst)
	}
	lit, ok := value.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", fmt.Errorf("aaguidgen: %s in %s is not a string literal", commitConst, path)
	}
	commit, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", fmt.Errorf("aaguidgen: %s in %s: %w", commitConst, path, err)
	}
	if err := checkCommit(commit); err != nil {
		return "", err
	}
	return commit, nil
}

func commitValue(f *ast.File) ast.Expr {
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if ok && len(vs.Names) == 1 && vs.Names[0].Name == commitConst && len(vs.Values) == 1 {
				return vs.Values[0]
			}
		}
	}
	return nil
}

func checkCommit(commit string) error {
	if !commitPattern.MatchString(commit) {
		return fmt.Errorf("aaguidgen: commit %q is not a 40-character lowercase hash", commit)
	}
	return nil
}

// Fetch requests url and returns the response body for Run to read. The
// caller closes it. Any status but 200 is an error.
func Fetch(ctx context.Context, client *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("aaguidgen: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aaguidgen: fetch: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("aaguidgen: fetch %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

// Entry is one authenticator: its AAGUID in 8-4-4-4-12 form and its display name.
type Entry struct{ UUID, Name string }

// extraEntries names authenticators the community list lacks. Add one only
// for an AAGUID the list does not carry. The list wins when it gains one of
// these AAGUIDs, and Run then reports the entry as covered so it can go.
var extraEntries = []Entry{
	{"2fc0579f-8113-47ea-b116-bb5a8db9202a", "YubiKey 5"},
	{"b5397723-31d4-4c13-b037-37be46e30e9e", "1Password"},
	{"fa2b99dc-9e39-4257-8f92-4a30d23c4118", "YubiKey 5 NFC"},
}

// Output is everything one generation produces.
type Output struct {
	Table    []Entry // the merged table, sorted by AAGUID
	Source   []byte  // gofmt'd webauthn/aaguids_gen.go
	Snapshot []byte  // name-only copy of the list, itself valid Generate input
	Kept     []Entry // extra entries the list lacks, sorted by AAGUID
	Covered  []Entry // extra entries the list now has, sorted by AAGUID
}

// Generate validates an aaguid.json document taken from commit of the
// community list and renders the table. It refuses a commit that is not a
// full lowercase hash, an empty or invalid-UTF-8 document, a key that is not
// a lowercase UUID, and an entry whose name is missing, empty, padded,
// unprintable or longer than 64 runes. Only the names are kept; every other
// field is dropped.
func Generate(data []byte, commit string) (*Output, error) {
	if err := checkCommit(commit); err != nil {
		return nil, err
	}
	list, err := decode(data)
	if err != nil {
		return nil, err
	}

	merged := slices.Clone(list)
	out := &Output{}
	have := make(map[string]bool, len(list))
	for _, e := range list {
		have[e.UUID] = true
	}
	for _, e := range extraEntries {
		if have[e.UUID] {
			out.Covered = append(out.Covered, e)
			continue
		}
		out.Kept = append(out.Kept, e)
		merged = append(merged, e)
	}
	byUUID := func(a, b Entry) int { return strings.Compare(a.UUID, b.UUID) }
	slices.SortFunc(merged, byUUID)
	slices.SortFunc(out.Kept, byUUID)
	slices.SortFunc(out.Covered, byUUID)

	out.Table = merged
	if out.Source, err = renderSource(merged, commit); err != nil {
		return nil, err
	}
	if out.Snapshot, err = renderSnapshot(list); err != nil {
		return nil, err
	}
	return out, nil
}

// Reject invalid UTF-8 before json.Unmarshal, which replaces it with U+FFFD
// that checkName accepts as printable. See https://pkg.go.dev/encoding/json#Unmarshal.
func decode(data []byte) ([]Entry, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("aaguidgen: the list is not valid UTF-8")
	}
	var doc map[string]struct {
		Name *string `json:"name"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("aaguidgen: decode: %w", err)
	}
	if len(doc) == 0 {
		return nil, errors.New("aaguidgen: the list has no entries")
	}
	entries := make([]Entry, 0, len(doc))
	for key, v := range doc {
		if !keyPattern.MatchString(key) {
			return nil, fmt.Errorf("aaguidgen: key %q is not a lowercase UUID", key)
		}
		if v.Name == nil || *v.Name == "" {
			return nil, fmt.Errorf("aaguidgen: entry %q has no name", key)
		}
		if err := checkName(*v.Name); err != nil {
			return nil, fmt.Errorf("aaguidgen: entry %q: name %q %w", key, *v.Name, err)
		}
		entries = append(entries, Entry{UUID: key, Name: *v.Name})
	}
	return entries, nil
}

func checkName(name string) error {
	if strings.TrimSpace(name) != name {
		return errors.New("has leading or trailing white space")
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("contains unprintable rune %U", r)
		}
	}
	if utf8.RuneCountInString(name) > maxNameRunes {
		return fmt.Errorf("is longer than %d runes", maxNameRunes)
	}
	return nil
}

func renderSource(entries []Entry, commit string) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("// Code generated by \"go run gen_aaguids.go\"; DO NOT EDIT.\n")
	b.WriteString("// Source: " + SourceURL(commit) + "\n\n")
	b.WriteString("package webauthn\n\nvar knownAAGUIDTable = []AAGUIDEntry{\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "\t{UUID: %s, Name: %s},\n", strconv.Quote(e.UUID), strconv.Quote(e.Name))
	}
	b.WriteString("}\n")
	src, err := format.Source(b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("aaguidgen: format: %w", err)
	}
	return src, nil
}

func renderSnapshot(entries []Entry) ([]byte, error) {
	type named struct {
		Name string `json:"name"`
	}
	doc := make(map[string]named, len(entries))
	for _, e := range entries {
		doc[e.UUID] = named{Name: e.Name}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("aaguidgen: snapshot: %w", err)
	}
	return b.Bytes(), nil
}

// Paths names Run's two outputs.
type Paths struct{ Out, Snapshot string }

// Run reads the list taken from commit from in, generates, and replaces
// p.Snapshot and then p.Out, each by rename so a reader never sees a partial
// file. Any input or validation error writes nothing. It prints the kept and
// covered extra entries to report.
func Run(in io.Reader, commit string, p Paths, report io.Writer) error {
	data, err := readCapped(in)
	if err != nil {
		return err
	}
	out, err := Generate(data, commit)
	if err != nil {
		return err
	}
	if err := replaceFile(p.Snapshot, out.Snapshot); err != nil {
		return err
	}
	if err := replaceFile(p.Out, out.Source); err != nil {
		return err
	}
	for _, e := range out.Kept {
		fmt.Fprintf(report, "kept extra %s %s\n", e.UUID, e.Name)
	}
	for _, e := range out.Covered {
		fmt.Fprintf(report, "covered by the list, delete from extraEntries: %s %s\n", e.UUID, e.Name)
	}
	fmt.Fprintf(report, "%d entries\n", len(out.Table))
	return nil
}

func readCapped(in io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(in, maxInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("aaguidgen: read: %w", err)
	}
	if len(data) > maxInputBytes {
		return nil, fmt.Errorf("aaguidgen: the list is larger than %d bytes", maxInputBytes)
	}
	return data, nil
}

func replaceFile(dst string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".aaguidgen-*")
	if err != nil {
		return fmt.Errorf("aaguidgen: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("aaguidgen: write %s: %w", dst, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("aaguidgen: write %s: %w", dst, err)
	}
	if err = os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("aaguidgen: %w", err)
	}
	if err = os.Rename(tmp.Name(), dst); err != nil {
		return fmt.Errorf("aaguidgen: %w", err)
	}
	return nil
}
