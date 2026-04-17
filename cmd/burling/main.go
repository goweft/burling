// Command burling validates AIP (Agent Identity Protocol) identity
// documents and Invocation-Bound Capability Tokens against the
// conformance matrix in docs/conformance-matrix.md.
//
// Usage:
//
//	burling validate          <token-file>   # validate compact IBCT
//	burling validate-identity <url|file>     # validate identity doc
//	burling lint              <token-file>   # all checks, JSON default
//	burling audit-chain       <token-file>   # chained mode (v0.1 stub)
//
// Shared flags apply to every subcommand:
//
//	--format text|json   output format (default: text for validate /
//	                     validate-identity / audit-chain; json for lint)
//	--strict             promote WARNING to failing exit code
//
// Exit codes: 0 on success, 1 on any ERROR finding (or WARNING if
// --strict), 2 on CLI usage / I/O error.
package main

import (
	"context"
	"fmt"
	"os"
)

// Version is stamped at build time via -ldflags; defaults to "dev"
// for local go-run invocations.
var Version = "dev"

// main is intentionally thin: it dispatches to runCommand and exits
// with whatever code that returns. Tests call runCommand directly so
// they can capture stdout/stderr without process isolation.
func main() {
	code := runCommand(context.Background(), os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}

// runCommand is the testable entry point. args is os.Args[1:], stdout
// and stderr are injectable writers.
//
// Subcommand dispatch is deliberately flat: the subcommand name is
// args[0], and each command function parses the rest of args itself.
// This keeps per-command flag parsing local and avoids a framework.
func runCommand(ctx context.Context, args []string, stdout, stderr *os.File) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case "validate":
		return cmdValidate(ctx, args[1:], stdout, stderr)
	case "validate-identity":
		return cmdValidateIdentity(ctx, args[1:], stdout, stderr)
	case "lint":
		return cmdLint(ctx, args[1:], stdout, stderr)
	case "audit-chain":
		return cmdAuditChain(ctx, args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "burling %s\n", Version)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "burling: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w *os.File) {
	fmt.Fprintf(w, `burling — AIP conformance validator

Usage:
  burling validate          <token-file>   Validate a compact IBCT
  burling validate-identity <url|file>     Validate an identity document
  burling lint              <token-file>   All checks, JSON output
  burling audit-chain       <token-file>   Chained-mode audit (v0.1 stub)

Shared flags:
  --format text|json   Output format (default: text for validate /
                       validate-identity / audit-chain; json for lint)
  --strict             Promote WARNING to failing exit code

Exit codes:
  0   all checks passed (no ERROR, and no WARNING under --strict)
  1   at least one ERROR (or WARNING under --strict)
  2   CLI usage or I/O error

See https://github.com/goweft/burling for details.
`)
}
