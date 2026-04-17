# burling

**AIP conformance validator and IBCT chain auditor.**

burling is an open-source conformance validator for the Agent Identity Protocol (`draft-prakash-aip-00`). It validates Invocation-Bound Capability Tokens (IBCTs) and identity documents against every mechanically-checkable normative requirement in the AIP draft.

The name follows the [goweft](https://github.com/goweft) textile convention: *burling* is the process of inspecting finished cloth for defects and removing them. burling inspects finished IBCTs for protocol defects.

## Status

**v0.1 — internal milestone.** 18 of 43 conformance checks are fully implemented; the remaining 25 are stubbed and return an INFO finding noting deferral to v0.2. This is the first end-to-end conformance run against synthetic fixtures — not a public release. See `docs/MILESTONE-v0.1.md` for scope, and `docs/CONFORMANCE.md` for per-check status.

| Module | Spec | Checks | Status |
|--------|------|-------:|--------|
| Identity Document | §2.3 | 9 | **LIVE** |
| Compact Mode (JWT/Ed25519) | §3.1 | 9 | **LIVE** |
| Chained Mode (Biscuit) | §3.2 | 5 | stub (v0.2) |
| Scope Attenuation | §3.3 | 6 | stub (v0.2) |
| Bounded Delegation Depth | §3.4 | 3 | stub (v0.2) |
| Delegation Context | §3.5 | 4 | stub (v0.2) |
| Completion Blocks | §3.6 | 4 | stub (v0.2) |
| MCP Binding | §4.1 | 3 | stub (v0.2) |

## Install

```
go install github.com/goweft/burling/cmd/burling@latest
```

Or from source:

```
git clone https://github.com/goweft/burling
cd burling
go build -o burling ./cmd/burling
```

Requires Go 1.22+. No third-party dependencies on the standard path; the Biscuit decision for chained mode is deferred to v0.2.

## CLI

```
burling validate          <token-file>   Validate a compact IBCT
burling validate-identity <url|file>     Validate an identity document
burling lint              <token-file>   All checks, JSON output for CI
burling audit-chain       <token-file>   Chained-mode audit (v0.1 stub)
```

Shared flags: `--format text|json`, `--strict` (promotes WARNING to failing exit code). ERROR findings always fail the exit code.

Exit codes:
- `0` — all checks passed (no ERROR, and no WARNING under `--strict`)
- `1` — at least one ERROR (or WARNING under `--strict`)
- `2` — CLI usage or I/O error

## Worked example

The repository includes committed fixtures under `testdata/example/` for experimenting with the CLI. They can be regenerated at any time with `go run ./testdata/gen -outdir testdata/example`.

**Validating a well-formed identity document:**

```
$ burling validate-identity testdata/example/identity.json
Target:  testdata/example/identity.json
Spec:    draft-prakash-aip-00
burling: dev

ERROR   [ID-08] §2.3  failed to resolve aip:web:example.com/issuer-alpha: identity document not found

Summary: 1 ERROR — FAIL
```

The identity document itself is structurally valid and its signature verifies. The single ERROR is ID-08: the document claims issuer `aip:web:example.com/issuer-alpha`, but there is no live HTTP endpoint at `https://example.com/.well-known/aip/issuer-alpha.json`. That's expected — the example.com domain has no AIP well-known location.

**Detecting a tampered signature:**

```
$ burling validate-identity testdata/example/identity-tampered.json
Target:  testdata/example/identity-tampered.json
Spec:    draft-prakash-aip-00
burling: dev

ERROR   [ID-06] §2.3  document_signature did not verify against any listed ed25519 public key
ERROR   [ID-08] §2.3  failed to resolve aip:web:example.com/issuer-alpha: identity document not found

Summary: 2 ERROR — FAIL
```

The tampered fixture has one byte flipped in the signature. burling catches it at ID-06 via the JCS canonicalization + Ed25519 verification path.

**Machine-readable output for CI:**

```
$ burling lint --format json testdata/example/token.jwt | jq '.findings[] | {check_id, severity, message}'
{
  "check_id": "CM-03",
  "severity": "ERROR",
  "message": "failed to resolve issuer \"aip:web:example.com/issuer-alpha\": ..."
}
{
  "check_id": "SA-00",
  "severity": "INFO",
  "message": "scope-attenuation validation deferred to v0.2 (depends on chained mode)"
}
...
```

## Architecture

- `internal/report` — stable JSON finding schema consumed by all modules
- `internal/identity` — §2.3 identity-document validator (ID-01..ID-09) + zero-dep JCS canonicalizer
- `internal/compact` — §3.1 JWT/Ed25519 validator (CM-01..CM-09), reuses `identity.Resolver` for `kid` lookup
- `internal/{chained,scope,depth,delegation,completion,mcpbind}` — v0.1 stubs; each emits one INFO finding
- `cmd/burling` — CLI front-end
- `testdata/gen` — fixture generator for the `testdata/example/` directory

## Design principles

- **Zero third-party dependencies** on the standard path. Biscuit for chained mode is the single deferred exception.
- **Table-driven tests** with programmatically generated crypto fixtures. No static signed-document fixtures committed (rationale in `testdata/identity/README.md`).
- **CI green from day one**: `go test ./... -race -cover`, `go vet`, and `golangci-lint`.
- **Small verified steps**: review gates between modules, matrix-ordered implementation.

## Documentation

- [`docs/conformance-matrix.md`](docs/conformance-matrix.md) — the full 43-check test matrix, with severities and spec references
- [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) — per-check implementation status for the current version
- [`docs/spec-ambiguities.md`](docs/spec-ambiguities.md) — open questions flagged to the spec author
- [`docs/MILESTONE-v0.1.md`](docs/MILESTONE-v0.1.md) — v0.1 scope and done criteria

## Relationship to AIP

burling tracks `draft-prakash-aip-00`. The draft is expected to evolve; burling will update its matrix and add new ambiguity entries as the spec moves.

The project exists as a wedge into the AIP ecosystem: an independent conformance harness is concrete value to protocol implementers regardless of which runtimes adopt AIP, and its careful line-by-line reading of the draft surfaces ambiguities worth resolving upstream.

## Status of outreach

The spec author has been notified that this project exists and that the five initial ambiguities documented in `docs/spec-ambiguities.md` have been flagged for upstream discussion.

## License

Apache 2.0. Matches the rest of the [goweft](https://github.com/goweft) stack (`cas`, `heddle`, `ratine`, `crocking`).
