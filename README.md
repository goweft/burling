# burling

**AIP conformance validator and IBCT chain auditor.**

burling is an open-source conformance validator for the Agent Identity Protocol (`draft-prakash-aip-00`). It validates Invocation-Bound Capability Tokens (IBCTs) and identity documents against every mechanically-checkable normative requirement in the AIP draft.

The name follows the [goweft](https://github.com/goweft) textile convention: *burling* is the process of inspecting finished cloth for defects and removing them. burling inspects finished IBCTs for protocol defects.

## Status

**Pre-alpha (v0.0.1).** Scaffolding phase.

See `docs/conformance-matrix.md` for the full 45-check test matrix.
See `docs/spec-ambiguities.md` for open questions flagged to the spec author.

## CLI (v0.1, frozen)

```
burling validate <token-file>          # Validate compact or chained IBCT
burling validate-identity <url|file>   # Validate an identity document
burling audit-chain <token-file>       # Full chain audit, human-readable
burling lint <token-file>              # All checks, JSON output for CI
```

Shared flags: `--format json|text`, `--strict` (promotes WARNING to failing exit code). ERROR always fails the exit code.

## Build

```
go build ./cmd/burling
go test ./... -race -cover
```

## License

Apache 2.0. See [LICENSE](LICENSE).
