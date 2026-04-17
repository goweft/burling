package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/goweft/burling/internal/chained"
	"github.com/goweft/burling/internal/compact"
	"github.com/goweft/burling/internal/identity"
	"github.com/goweft/burling/internal/report"
)

// commonFlags holds the two flags shared by every subcommand. The
// defaultFormat argument lets each command pick its own default
// (text for human-facing, json for lint/CI).
type commonFlags struct {
	format string
	strict bool
}

func registerCommonFlags(fs *flag.FlagSet, defaultFormat string) *commonFlags {
	cf := &commonFlags{}
	fs.StringVar(&cf.format, "format", defaultFormat, "output format: text or json")
	fs.BoolVar(&cf.strict, "strict", false, "promote WARNING to failing exit code")
	return cf
}

// cmdValidate handles `burling validate <token-file>`.
func cmdValidate(ctx context.Context, args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cf := registerCommonFlags(fs, "text")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(stderr, "usage: burling validate [--format text|json] [--strict] <token-file>")
		return 2
	}
	raw, err := readTokenFile(rest[0])
	if err != nil {
		fmt.Fprintf(stderr, "burling validate: %v\n", err)
		return 2
	}
	tok, err := compact.Parse(raw)
	if err != nil {
		fmt.Fprintf(stderr, "burling validate: parse token: %v\n", err)
		return 2
	}
	r := compact.Validate(ctx, tok, compact.Options{
		Resolver: identity.NewHTTPResolver(),
	})
	r.Target = rest[0]
	r.BurlingVersion = Version
	r.SpecVersion = "draft-prakash-aip-00"
	return render(stdout, stderr, r, cf)
}

// cmdValidateIdentity handles `burling validate-identity <url|file>`.
//
// Argument routing: a leading "http://" or "https://" is treated as a
// URL and fetched via HTTPResolver; anything else is a file path.
// The URL path doubles as self-check for ID-08 because the fetched
// document's id should resolve back to the same URL.
func cmdValidateIdentity(ctx context.Context, args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("validate-identity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cf := registerCommonFlags(fs, "text")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(stderr, "usage: burling validate-identity [--format text|json] [--strict] <url|file>")
		return 2
	}
	arg := rest[0]
	var (
		docBytes []byte
		err      error
	)
	if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
		docBytes, err = fetchURL(ctx, arg)
	} else {
		docBytes, err = os.ReadFile(arg)
	}
	if err != nil {
		fmt.Fprintf(stderr, "burling validate-identity: %v\n", err)
		return 2
	}
	doc, err := identity.ParseDocument(docBytes)
	if err != nil {
		fmt.Fprintf(stderr, "burling validate-identity: parse: %v\n", err)
		return 2
	}
	r := identity.Validate(ctx, doc, identity.Options{
		Resolver: identity.NewHTTPResolver(),
	})
	r.Target = arg
	r.BurlingVersion = Version
	r.SpecVersion = "draft-prakash-aip-00"
	return render(stdout, stderr, r, cf)
}

// cmdLint handles `burling lint <token-file>`. Like `validate` but
// with JSON default output and aggregated findings from every live
// module (identity reachable via the issuer, compact, plus the six
// stubbed modules so CI sees the full conformance picture).
//
// Identity is not run here in v0.1 — the token's issuer is resolved
// by compact.Validate for CM-03/04 and that's sufficient for the
// conformance picture of the token itself. A dedicated
// validate-identity run is the right call for document-level checks.
func cmdLint(ctx context.Context, args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cf := registerCommonFlags(fs, "json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(stderr, "usage: burling lint [--format text|json] [--strict] <token-file>")
		return 2
	}
	raw, err := readTokenFile(rest[0])
	if err != nil {
		fmt.Fprintf(stderr, "burling lint: %v\n", err)
		return 2
	}
	tok, err := compact.Parse(raw)
	if err != nil {
		fmt.Fprintf(stderr, "burling lint: parse token: %v\n", err)
		return 2
	}
	r := compact.Validate(ctx, tok, compact.Options{
		Resolver: identity.NewHTTPResolver(),
	})
	// Append stub-module findings so CI sees every ID advertised by
	// the matrix even if most are INFO. Importing each stub package
	// here is the only place in the codebase that does so.
	appendStubFindings(ctx, r)
	r.Target = rest[0]
	r.BurlingVersion = Version
	r.SpecVersion = "draft-prakash-aip-00"
	return render(stdout, stderr, r, cf)
}

// cmdAuditChain handles `burling audit-chain <token-file>`. v0.1:
// stub. Dispatches to internal/chained which emits a single INFO.
// The file argument is accepted but not parsed (chained tokens are
// Biscuit, not JWT — parsing is v0.2).
func cmdAuditChain(ctx context.Context, args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("audit-chain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cf := registerCommonFlags(fs, "text")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(stderr, "usage: burling audit-chain [--format text|json] [--strict] <token-file>")
		return 2
	}
	// File is not read in v0.1 — audit-chain dispatches to the stub
	// module regardless of content. Keep the positional-arg contract
	// so v0.2 can drop in a real implementation without changing CLI
	// invocation for users.
	r := chained.Validate(ctx)
	r.Target = rest[0]
	r.BurlingVersion = Version
	r.SpecVersion = "draft-prakash-aip-00"
	return render(stdout, stderr, r, cf)
}

// readTokenFile reads a compact-token file and trims surrounding
// whitespace/newlines. Most editors add a trailing newline; compact
// tokens are ASCII dot-separated, so a trim is always safe.
func readTokenFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// fetchURL is a thin wrapper around http.Get used only by
// validate-identity when given a URL argument. HTTPResolver does its
// own fetching during ID-08, but we still need to pull the document
// once up front to have something to pass to ParseDocument.
func fetchURL(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return b, nil
}

// appendStubFindings runs the six deferred-module stubs and appends
// their findings to r. Kept here (not in the compact package) so
// internal/compact stays single-purpose.
func appendStubFindings(ctx context.Context, r *report.Report) {
	for _, v := range stubValidators() {
		sr := v(ctx)
		r.Findings = append(r.Findings, sr.Findings...)
	}
}

// stubValidators returns the deferred modules as a slice of
// Validate functions. Ordered to match the conformance matrix so
// lint output reads top-to-bottom.
func stubValidators() []func(context.Context) *report.Report {
	// Imported via init-style loose coupling would be nicer but
	// creates import cycles; direct imports are fine.
	return deferredValidators
}
