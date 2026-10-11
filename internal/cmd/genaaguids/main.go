// Command genaaguids regenerates webauthn/aaguids_gen.go from the community
// list at the commit webauthn/aaguids_source.go pins; see internal/aaguidgen.
// go generate runs it from the webauthn directory, which the default paths
// are relative to.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cplieger/auth/v6/internal/aaguidgen"
)

func main() {
	source := flag.String("source", "aaguids_source.go", "Go file declaring aaguidListCommit")
	out := flag.String("out", "aaguids_gen.go", "generated Go file to replace")
	snapshot := flag.String("snapshot", "testdata/aaguid.json", "name-only snapshot to replace")
	flag.Parse()
	if err := run(*source, aaguidgen.Paths{Out: *out, Snapshot: *snapshot}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(source string, p aaguidgen.Paths) error {
	commit, err := aaguidgen.ReadCommit(source)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 90 * time.Second}
	body, err := aaguidgen.Fetch(ctx, client, aaguidgen.SourceURL(commit))
	if err != nil {
		return err
	}
	defer body.Close()
	return aaguidgen.Run(body, commit, p, os.Stderr)
}
