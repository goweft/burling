# burling v0.1 — "first conformance run shipped"

**Status:** active milestone, scope frozen
**Framing:** internal milestone (not a public release)
**Goal:** prove the architecture works end-to-end against synthetic fixtures, ship when CI is green

---

## Why this milestone exists

burling's value as a wedge depends on shipping *something* that runs the
conformance loop end-to-end before the matrix gets bigger. The four-project
sprawl risk identified in strategy review is real: without a declared
finish line, v0.1 quietly becomes v0.9 forever.

This document defines what "shipped" means concretely. Anything outside this
scope is v0.2 or later, no exceptions.

## Scope

### In v0.1 (live, fully implemented + tested)

| Module | Checks | Count |
|--------|--------|-------|
| Identity Document Validation (`internal/identity`) | ID-01 through ID-09 | 9 |
| Compact Mode JWT/Ed25519 (`internal/compact`) | CM-01 through CM-09 | 9 |
| **Total live** | | **18 of 43** |

### Stubbed in v0.1

Every other module returns a single INFO finding `"module deferred to v0.2"`
and exits cleanly. Stubs exist so the CLI can dispatch to them without
panicking; no validation logic.

| Module | Reason |
|--------|--------|
| Scope attenuation (SA-01–06) | Operates on chains; meaningful only with chained mode |
| Chained mode (CH-01–05) | Already declared v0.1 stub in conformance matrix |
| Bounded delegation depth (BD-01–03) | Chain-dependent |
| Delegation context (DC-01–04) | Chain-dependent |
| Completion blocks (CB-01–04) | Chain-dependent |
| MCP binding (MB-01–03) | Transport-level; gated on real MCP test target |

### CLI surface

| Command | Status in v0.1 |
|---------|----------------|
| `burling validate <token-file>` | Works for compact tokens |
| `burling validate-identity <url\|file>` | Fully works |
| `burling lint <token-file>` | JSON output, all live findings |
| `burling audit-chain <token-file>` | Stub: "chained mode deferred to v0.2" |

Shared flags `--format json|text` and `--strict` work across all commands.
ERROR always fails exit code; `--strict` promotes WARNING to failing.

### Fixtures

- Synthetic, generated programmatically (Ed25519 keypairs created per test
  run; no static crypto fixtures committed)
- Each live check has at least one passing and one failing fixture
- Minimum: 18 checks × 2 = **36 fixture cases**
- Generators committed under `testdata/<module>/` and reusable for v0.2

### CI gates

- `go test ./... -race -cover` passes
- `golangci-lint run` passes
- Coverage ≥80% on every live module package, with one exception:
  - `internal/identity/jcs.go` allowed ≥70% if uncovered lines are
    exclusively in the `TODO(jcs-numbers)` exponent path
- One end-to-end CLI test per command, exercising real fixture files

### Documentation

- README updated: "v0.1 implements 18 of 43 checks. Six modules stubbed,
  will land in v0.2."
- New file `docs/CONFORMANCE.md`: status table for all 43 check IDs
  (live / stubbed / deferred), updated as work lands
- One worked example in README: sample token + command + JSON output

## Explicitly NOT in v0.1

These are deliberate exclusions, not oversights:

- Any external AIP implementation tested against (no others exist yet;
  v0.2 milestone will be tied to first external reference)
- Public announcement, blog post, social outreach
- Performance benchmarks
- Any check beyond the 18 above
- Any module beyond identity and compact
- Biscuit dependency decision (deferred to v0.2 per house style)
- Model-integrity scanning, general-purpose policy framework, or any
  scope expansion that conceptually rhymes with IBCTs but isn't AIP

## Baseline (as of milestone declaration)

- `internal/report`: implemented, 94.7% coverage, passing
- `internal/identity`: empty directory
- `internal/compact`: empty directory
- All other `internal/*`: empty directories
- `cmd/burling`: empty directory
- `pkg/burling`: empty directory
- Git history: 1 commit (initial scaffolding)

**Distance to v0.1:** 0 of 18 live checks. Identity package and compact
package both built from scratch.

## Implementation order to v0.1

Follows `docs/conformance-matrix.md` order, narrowed to v0.1 scope:

1. `internal/identity` — JCS canonicalizer + Ed25519 verify + 9 checks
2. `internal/compact` — JWT parse + Ed25519 verify + 9 checks
3. Stub packages for the six deferred modules (each returns one INFO)
4. `cmd/burling` — wire all four CLI commands
5. Fixtures, CI hardening, README + CONFORMANCE.md

## Done criteria checklist

- [x] `internal/identity` implemented, 9 checks tested, ≥80% coverage
      (jcs.go ≥70% with documented exemption)
- [x] `internal/compact` implemented, 9 checks tested, ≥80% coverage
- [x] Six stub packages return INFO findings without panicking
- [x] All four CLI commands dispatch correctly
- [x] `--format json|text` and `--strict` honored across CLI
- [x] 36+ fixture cases passing
- [x] `go test ./... -race -cover` green
- [x] `golangci-lint run` green
- [x] `docs/CONFORMANCE.md` exists and accurate
- [x] README declares 18 of 43 status
- [x] Worked example in README runs against committed fixture

When every box is checked, v0.1 is shipped. Tag `v0.1.0`. Move to v0.2
planning.
