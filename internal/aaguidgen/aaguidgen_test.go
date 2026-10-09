package aaguidgen

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const validKey = "00000000-1111-2222-3333-444444444444"

var testCommit = strings.Repeat("ab", 20)

func TestGenerate_refuses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		input     string
		noEntries bool
	}{
		{name: "null", input: `null`, noEntries: true},
		{name: "empty_object", input: `{}`, noEntries: true},
		{name: "array", input: `[]`},
		{name: "string", input: `"x"`},
		{name: "missing_name", input: `{"` + validKey + `":{}}`},
		{name: "null_name", input: `{"` + validKey + `":{"name":null}}`},
		{name: "empty_name", input: `{"` + validKey + `":{"name":""}}`},
		{name: "whitespace_name", input: `{"` + validKey + `":{"name":"  "}}`},
		{name: "padded_name", input: `{"` + validKey + `":{"name":" Vault"}}`},
		{name: "bidi_override", input: `{"` + validKey + `":{"name":"Vault\u202e"}}`},
		{name: "newline", input: `{"` + validKey + `":{"name":"Va\nult"}}`},
		{name: "too_long", input: `{"` + validKey + `":{"name":"` + strings.Repeat("a", maxNameRunes+1) + `"}}`},
		{name: "uppercase_key", input: `{"ABCDEF00-1111-2222-3333-444444444444":{"name":"Vault"}}`},
		{name: "not_a_uuid", input: `{"not-a-uuid":{"name":"Vault"}}`},
		{name: "braced_key", input: `{"{` + validKey + `}":{"name":"Vault"}}`},
		{name: "numeric_name", input: `{"` + validKey + `":{"name":7}}`},
		{name: "invalid_utf8_name", input: `{"` + validKey + `":{"name":"Vault` + "\xff" + `"}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := Generate([]byte(tc.input), testCommit)
			if err == nil {
				t.Fatalf("Generate(%q) = %v, nil, want an error", tc.input, out)
			}
			if tc.noEntries && !strings.Contains(err.Error(), "no entries") {
				t.Errorf("Generate(%q) error = %q, want it to say %q", tc.input, err, "no entries")
			}
		})
	}
}

func TestGenerate_accepts_longest_name(t *testing.T) {
	t.Parallel()
	name := strings.Repeat("é", maxNameRunes)
	in := `{"` + validKey + `":{"name":"` + name + `"}}`
	if _, err := Generate([]byte(in), testCommit); err != nil {
		t.Errorf("Generate(%d-rune name) error = %v, want nil", maxNameRunes, err)
	}
}

func TestGenerate_merges_extras(t *testing.T) {
	t.Parallel()
	covered := extraEntries[0]
	in := `{"` + validKey + `":{"name":"Vault"},"` + covered.UUID + `":{"name":"Listed name"}}`
	out, err := Generate([]byte(in), testCommit)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want := strings.Contains(string(out.Source), `{UUID: "`+covered.UUID+`", Name: "Listed name"}`)
	if !want || strings.Contains(string(out.Source), covered.Name+`"`) {
		t.Errorf("Generate source does not give %s the list's name:\n%s", covered.UUID, out.Source)
	}
	if !slices.Equal(out.Covered, []entry{covered}) {
		t.Errorf("Generate Covered = %v, want %v", out.Covered, []entry{covered})
	}
	if !slices.Equal(out.Kept, extraEntries[1:]) {
		t.Errorf("Generate Kept = %v, want %v", out.Kept, extraEntries[1:])
	}
	if len(out.Table) != 4 {
		t.Errorf("Generate table has %d entries, want 4", len(out.Table))
	}
	if !slices.IsSortedFunc(out.Table, func(a, b entry) int { return strings.Compare(a.UUID, b.UUID) }) {
		t.Errorf("Generate table is not sorted by AAGUID: %v", out.Table)
	}
	var rows []string
	for line := range strings.Lines(string(out.Source)) {
		if uuid, ok := strings.CutPrefix(strings.TrimSpace(line), `{UUID: "`); ok {
			rows = append(rows, uuid[:36])
		}
	}
	if !slices.IsSorted(rows) || len(rows) != len(out.Table) {
		t.Errorf("Generate source rows = %v, want %d rows sorted by AAGUID", rows, len(out.Table))
	}
}

func TestGenerate_strips_icons(t *testing.T) {
	t.Parallel()
	in := `{"` + validKey + `":{"name":"Vault","icon_light":"data:image/svg+xml;base64,AA==","icon_dark":"data:image/svg+xml;base64,AA=="}}`
	out, err := Generate([]byte(in), testCommit)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{"Source", out.Source}, {"Snapshot", out.Snapshot}} {
		if bytes.Contains(f.data, []byte("icon")) || bytes.Contains(f.data, []byte("data:image")) {
			t.Errorf("Generate %s carries icon data:\n%s", f.name, f.data)
		}
	}
}

func TestGenerate_snapshot_is_a_fixed_point(t *testing.T) {
	t.Parallel()
	in := `{"` + validKey + `":{"name":"Sésame <&>","icon_dark":"x"},"ffffffff-1111-2222-3333-444444444444":{"name":"Vault"}}`
	first, err := Generate([]byte(in), testCommit)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	second, err := Generate(first.Snapshot, testCommit)
	if err != nil {
		t.Fatalf("Generate(snapshot): %v", err)
	}
	if !bytes.Equal(second.Source, first.Source) {
		t.Errorf("Generate(snapshot) source differs:\ngot:\n%s\nwant:\n%s", second.Source, first.Source)
	}
	if !bytes.Equal(second.Snapshot, first.Snapshot) {
		t.Errorf("Generate(snapshot) snapshot differs:\ngot:\n%s\nwant:\n%s", second.Snapshot, first.Snapshot)
	}
}

func TestGenerate_source_header(t *testing.T) {
	t.Parallel()
	out, err := Generate([]byte(`{"`+validKey+`":{"name":"Vault"}}`), testCommit)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	first, _, _ := strings.Cut(string(out.Source), "\n")
	if !strings.HasPrefix(first, "// Code generated ") || !strings.HasSuffix(first, " DO NOT EDIT.") {
		t.Errorf("Generate source first line = %q, want a Go generated-code header", first)
	}
	want := "// Source: https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/" + testCommit + "/aaguid.json\n"
	if !strings.Contains(string(out.Source), want) {
		t.Errorf("Generate source does not contain %q:\n%s", want, out.Source)
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("Setup: %v", err)
	}
}

func outputPaths(t *testing.T) (dir string, p Paths) {
	t.Helper()
	dir = t.TempDir()
	return dir, Paths{Out: filepath.Join(dir, "out.go"), Snapshot: filepath.Join(dir, "snap.json")}
}

func TestRun_refusal_leaves_files_untouched(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		input  string
		commit string
	}{
		{name: "empty_list", input: `{}`, commit: testCommit},
		{name: "bad_commit", input: `{"` + validKey + `":{"name":"Vault"}}`, commit: "main"},
		{name: "invalid_utf8", input: `{"` + validKey + `":{"name":"Vault` + "\xff" + `"}}`, commit: testCommit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir, p := outputPaths(t)
			writeFile(t, p.Out, "sentinel out")
			writeFile(t, p.Snapshot, "sentinel snapshot")

			if err := Run(strings.NewReader(tc.input), tc.commit, p, &bytes.Buffer{}); err == nil {
				t.Fatalf("Run(%q, %q) = nil, want an error", tc.input, tc.commit)
			}
			for path, want := range map[string]string{p.Out: "sentinel out", p.Snapshot: "sentinel snapshot"} {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != want {
					t.Errorf("after Run(%q, %q), %s = %q, %v, want %q", tc.input, tc.commit, filepath.Base(path), got, err, want)
				}
			}
			leftovers, err := filepath.Glob(filepath.Join(dir, ".aaguidgen-*"))
			if err != nil || len(leftovers) != 0 {
				t.Errorf("after Run(%q, %q), temp files = %v, %v, want none", tc.input, tc.commit, leftovers, err)
			}
		})
	}
}

func TestRun_refuses_oversized_input(t *testing.T) {
	t.Parallel()
	_, p := outputPaths(t)
	in := `{"` + validKey + `":{"name":"Vault"}}` + strings.Repeat(" ", maxInputBytes)
	if err := Run(strings.NewReader(in), testCommit, p, &bytes.Buffer{}); err == nil {
		t.Fatalf("Run(%d-byte input) = nil, want an error", len(in))
	}
	if _, err := os.Stat(p.Out); !os.IsNotExist(err) {
		t.Errorf("after Run(oversized input), Stat(out) error = %v, want not-exist", err)
	}
}

func TestRun_writes_both_outputs(t *testing.T) {
	t.Parallel()
	_, p := outputPaths(t)
	in := `{"` + validKey + `":{"name":"Vault"},"ffffffff-1111-2222-3333-444444444444":{"name":"Other"}}`

	var report bytes.Buffer
	if err := Run(strings.NewReader(in), testCommit, p, &report); err != nil {
		t.Fatalf("Run: %v", err)
	}
	src, err := os.ReadFile(p.Out)
	if err != nil || !bytes.HasPrefix(src, []byte("// Code generated")) || !bytes.Contains(src, []byte(testCommit)) {
		t.Errorf("Run wrote out = %q, %v, want a generated Go file naming commit %s", src, err, testCommit)
	}
	snap, err := os.ReadFile(p.Snapshot)
	if err != nil || !bytes.Contains(snap, []byte(`"name": "Vault"`)) {
		t.Errorf("Run wrote snapshot = %q, %v, want the listed names", snap, err)
	}
	for _, e := range extraEntries {
		if line := "kept extra " + e.UUID + " " + e.Name + "\n"; !strings.Contains(report.String(), line) {
			t.Errorf("Run report = %q, want it to contain %q", report.String(), line)
		}
	}
	if want := "5 entries\n"; !strings.HasSuffix(report.String(), want) {
		t.Errorf("Run report = %q, want it to end with %q", report.String(), want)
	}
}

func TestGenerate_refuses_bad_commit(t *testing.T) {
	t.Parallel()
	in := []byte(`{"` + validKey + `":{"name":"Vault"}}`)
	for _, commit := range []string{"", "main", testCommit[:39], testCommit + "a", strings.ToUpper(testCommit), "../" + testCommit[3:]} {
		if out, err := Generate(in, commit); err == nil {
			t.Errorf("Generate(list, %q) = %v, nil, want an error", commit, out)
		}
	}
}

func TestReadCommit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		src     string
		want    string
		wantErr bool
	}{
		{name: "const", src: "package p\n\n// renovate: marker\nconst aaguidListCommit = \"" + testCommit + "\"\n", want: testCommit},
		{name: "grouped", src: "package p\n\nconst (\n\tother = 1\n\taaguidListCommit = `" + testCommit + "`\n)\n", want: testCommit},
		{name: "missing", src: "package p\n\nconst other = \"" + testCommit + "\"\n", wantErr: true},
		{name: "var", src: "package p\n\nvar aaguidListCommit = \"" + testCommit + "\"\n", wantErr: true},
		{name: "not_a_string", src: "package p\n\nconst aaguidListCommit = 7\n", wantErr: true},
		{name: "branch_name", src: "package p\n\nconst aaguidListCommit = \"main\"\n", wantErr: true},
		{name: "not_go", src: "aaguidListCommit = " + testCommit, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "source.go")
			writeFile(t, path, tc.src)
			got, err := ReadCommit(path)
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Errorf("ReadCommit(%q) = %q, %v, want %q, error %v", tc.src, got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestFetch(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "list")
	}))
	t.Cleanup(srv.Close)

	body, err := Fetch(t.Context(), srv.Client(), srv.URL+"/ok")
	if err != nil {
		t.Fatalf("Fetch(/ok) error = %v, want nil", err)
	}
	got, err := io.ReadAll(body)
	_ = body.Close()
	if err != nil || string(got) != "list" {
		t.Errorf("Fetch(/ok) body = %q, %v, want %q", got, err, "list")
	}
	if body, err := Fetch(t.Context(), srv.Client(), srv.URL+"/missing"); err == nil {
		_ = body.Close()
		t.Errorf("Fetch(/missing) = nil error, want one for a 404")
	}
}

func TestExtraEntries_are_valid(t *testing.T) {
	t.Parallel()
	for _, e := range extraEntries {
		if !keyPattern.MatchString(e.UUID) {
			t.Errorf("extraEntries key %q is not a lowercase UUID", e.UUID)
		}
		if err := checkName(e.Name); err != nil || e.Name == "" {
			t.Errorf("extraEntries name %q for %s: %v", e.Name, e.UUID, err)
		}
	}
	if !slices.IsSortedFunc(extraEntries, func(a, b entry) int { return strings.Compare(a.UUID, b.UUID) }) {
		t.Errorf("extraEntries is not sorted by AAGUID")
	}
}
