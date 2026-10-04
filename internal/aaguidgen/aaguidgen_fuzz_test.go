package aaguidgen

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"testing"
)

func FuzzGenerate_output_is_a_fixed_point(f *testing.F) {
	f.Add([]byte(`{"` + validKey + `":{"name":"Vault"}}`))
	f.Add([]byte(`{"` + validKey + `":{"name":"Sésame \"<&>\" \\t ` + "`" + `x` + "`" + `","icon_dark":"x"}}`))
	f.Add([]byte(`{"` + validKey + `":{"name":"Back\\tslash"}}`))
	f.Add([]byte(`{"` + validKey + `":{"name":"Vault"},"` + extraEntries[0].UUID + `":{"name":"Listed"}}`))
	f.Add([]byte(`{"` + validKey + `":{"name":"Vault"`))
	f.Add([]byte(`{"` + validKey + `":{"name":"Vault` + "\xff" + `"}}`))
	f.Add([]byte(`{"` + validKey + `":{"name":"Vault\u2028"}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		first, err := Generate(data, testCommit)
		if err != nil {
			return
		}
		table, err := sourceTable(first.Source)
		if err != nil {
			t.Fatalf("Generate(%q) source does not parse as Go: %v\n%s", data, err, first.Source)
		}
		if !slices.Equal(table, first.Table) {
			t.Errorf("Generate(%q) source table = %q, want %q", data, table, first.Table)
		}
		second, err := Generate(first.Snapshot, testCommit)
		if err != nil {
			t.Fatalf("Generate(snapshot of %q) = %v, want the snapshot accepted", data, err)
		}
		if !bytes.Equal(second.Source, first.Source) {
			t.Errorf("Generate(snapshot of %q) source differs:\ngot:\n%s\nwant:\n%s", data, second.Source, first.Source)
		}
		if !bytes.Equal(second.Snapshot, first.Snapshot) {
			t.Errorf("Generate(snapshot of %q) snapshot differs:\ngot:\n%s\nwant:\n%s", data, second.Snapshot, first.Snapshot)
		}
	})
}

// sourceTable reads the entries back out of a generated file, so the test
// checks what the Go compiler will see rather than the bytes renderSource wrote.
func sourceTable(src []byte) ([]Entry, error) {
	f, err := parser.ParseFile(token.NewFileSet(), "aaguids_gen.go", src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || len(lit.Elts) != 2 {
			return true
		}
		var e Entry
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			key, _ := kv.Key.(*ast.Ident)
			val, _ := kv.Value.(*ast.BasicLit)
			if key == nil || val == nil {
				return true
			}
			s, err := strconv.Unquote(val.Value)
			if err != nil {
				return true
			}
			switch key.Name {
			case "UUID":
				e.UUID = s
			case "Name":
				e.Name = s
			}
		}
		entries = append(entries, e)
		return false
	})
	return entries, nil
}
