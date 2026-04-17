# burling Conformance Status

This table tracks every check in the AIP conformance matrix and its
status in the burling validator. Updated as work lands.

**Status legend:**

- **LIVE** — fully implemented, tested, and reported by the CLI.
- **STUB** — module returns a single INFO finding noting deferral;
  check IDs listed here are not yet validated.
- **DEFERRED** — planned for a future version (v0.2+).

**Spec tracked:** `draft-prakash-aip-00`
**burling version covered by this document:** v0.1

---

## §2.3 — Identity Document Validation (`internal/identity`)

| ID | Check | Severity | Status |
|----|-------|----------|--------|
| ID-01 | `aip` field equals `"1.0"` | ERROR | LIVE |
| ID-02 | `id` is a valid AIP identifier (`aip:web:` or `aip:key:ed25519:`) | ERROR | LIVE |
| ID-03 | `public_keys` array is non-empty | ERROR | LIVE |
| ID-04 | Each key has `valid_from` and `valid_until` timestamps | ERROR | LIVE |
| ID-05 | At least one key is currently valid | ERROR | LIVE |
| ID-06 | `document_signature` verifies (JCS RFC 8785 + Ed25519) | ERROR | LIVE |
| ID-07 | `expires` timestamp is in the future | WARNING | LIVE |
| ID-08 | DNS-based ID resolves at `https://<domain>/.well-known/aip/<path>.json` | ERROR | LIVE |
| ID-09 | Key validity windows overlap during rotation | WARNING | LIVE |

## §3.1 — Compact Mode — JWT/Ed25519 (`internal/compact`)

| ID | Check | Severity | Status |
|----|-------|----------|--------|
| CM-01 | JWS header `alg` is `EdDSA` | ERROR | LIVE |
| CM-02 | JWS header `typ` is `aip-ibct+jwt` | ERROR | LIVE |
| CM-03 | JWS header `kid` references a key in issuer's identity document | ERROR | LIVE |
| CM-04 | Signature verifies against resolved public key | ERROR | LIVE |
| CM-05 | Required claims present: `iss`, `sub`, `aud`, `exp`, `nbf`, `jti`, `scope`, `invocation` | ERROR | LIVE |
| CM-06 | `exp` is in the future | ERROR | LIVE |
| CM-07 | `nbf` is in the past | ERROR | LIVE |
| CM-08 | `exp - nbf` does not exceed max TTL (1h standard, 15m sensitive) | WARNING | LIVE |
| CM-09 | `jti` is a valid UUIDv4 or ULID | WARNING | LIVE |

## §3.2 — Chained Mode — Biscuit (`internal/chained`)

| ID | Check | Severity | Status |
|----|-------|----------|--------|
| CH-01 | Token parses as a valid Biscuit v2 structure | ERROR | STUB (v0.2) |
| CH-02 | Root signature verifies against issuer identity document | ERROR | STUB (v0.2) |
| CH-03 | Each block signature verifies against preceding block's next-key | ERROR | STUB (v0.2) |
| CH-04 | Datalog evaluates without contradiction | ERROR | STUB (v0.2) |
| CH-05 | Authority block present and structurally valid | ERROR | STUB (v0.2) |

Chained mode is stubbed because the Biscuit vendor-vs-implement
decision is deferred to v0.2. See `docs/MILESTONE-v0.1.md`.

## §3.3 — Scope Attenuation (`internal/scope`)

| ID | Check | Severity | Status |
|----|-------|----------|--------|
| SA-01 | Child tool scope ⊆ parent tool scope | ERROR | STUB (v0.2) |
| SA-02 | Child resource scope ⊆ parent resource scope | ERROR | STUB (v0.2) |
| SA-03 | Child action scope ⊆ parent action scope | ERROR | STUB (v0.2) |
| SA-04 | Child temporal scope ⊆ parent temporal scope | ERROR | STUB (v0.2) |
| SA-05 | Scope attenuation holds transitively across all hops | ERROR | STUB (v0.2) |
| SA-06 | No scope field introduces capabilities absent from parent | ERROR | STUB (v0.2) |

Scope attenuation is the highest-priority security property of the
protocol. It's stubbed in v0.1 because it operates on chains of
blocks, which are meaningful only once chained mode is supported.

## §3.4 — Bounded Delegation Depth (`internal/depth`)

| ID | Check | Severity | Status |
|----|-------|----------|--------|
| BD-01 | Chain depth does not exceed profile ceiling | ERROR | STUB (v0.2) |
| BD-02 | Each block declares its depth consistently | ERROR | STUB (v0.2) |
| BD-03 | Depth is monotonic (each child = parent + 1) | ERROR | STUB (v0.2) |

## §3.5 — Delegation Context (`internal/delegation`)

| ID | Check | Severity | Status |
|----|-------|----------|--------|
| DC-01 | `delegation_reason` field present on every non-root block | ERROR | STUB (v0.2) |
| DC-02 | `delegation_reason` is a known enum value or free-form string under length limit | WARNING | STUB (v0.2) |
| DC-03 | `on_behalf_of` field present and resolves to a valid identity | ERROR | STUB (v0.2) |
| DC-04 | Budget ceilings declared when present are numerically coherent | ERROR | STUB (v0.2) |

## §3.6 — Completion Blocks (`internal/completion`)

| ID | Check | Severity | Status |
|----|-------|----------|--------|
| CB-01 | Completion block, if present, is the final block in the chain | ERROR | STUB (v0.2) |
| CB-02 | Completion block contains required fields | ERROR | STUB (v0.2) |
| CB-03 | Completion signature verifies against the terminal agent's identity | ERROR | STUB (v0.2) |
| CB-04 | No blocks follow a completion block | ERROR | STUB (v0.2) |

## §4.1 — MCP Binding (`internal/mcpbind`)

| ID | Check | Severity | Status |
|----|-------|----------|--------|
| MB-01 | Token is presented in `Authorization: AIP <token>` header format | ERROR | STUB (v0.2) |
| MB-02 | MCP tool invocation matches a tool in the token's scope | ERROR | STUB (v0.2) |
| MB-03 | MCP session ID, if present, matches `invocation.session_id` | WARNING | STUB (v0.2) |

---

## Summary

| Module | Section | Live | Stubbed | Total |
|--------|---------|-----:|--------:|------:|
| Identity | §2.3 | 9 | 0 | 9 |
| Compact | §3.1 | 9 | 0 | 9 |
| Chained | §3.2 | 0 | 5 | 5 |
| Scope | §3.3 | 0 | 6 | 6 |
| Depth | §3.4 | 0 | 3 | 3 |
| Delegation | §3.5 | 0 | 4 | 4 |
| Completion | §3.6 | 0 | 4 | 4 |
| MCP Binding | §4.1 | 0 | 3 | 3 |
| **Total** | | **18** | **25** | **43** |

Note: matrix row count is 43, not 45. The original kickoff framing
cited 45 checks; the current matrix has 43 after refinement. This
document tracks the matrix as it actually stands.

## How to update this document

When a check moves from STUB to LIVE:

1. Change its Status column entry from `STUB (v0.2)` to `LIVE`.
2. Update the summary table counts.
3. Bump `burling version covered` at the top if the change ships
   in a new release.
