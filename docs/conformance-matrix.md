# burling — AIP Conformance Test Matrix

**Target spec:** `draft-prakash-aip-00` (Agent Identity Protocol)
**Repo:** `goweft/burling`
**Purpose:** Validate IBCTs (Invocation-Bound Capability Tokens) and identity documents against every mechanically-checkable invariant in the AIP draft.

This document is the living source of truth for what burling validates. Every check here maps to a specific spec section. Do not implement checks that are not in this matrix; do not skip checks that are.

Severity rules:
- **ERROR** — MUST/MUST NOT violation. Always fails exit code.
- **WARNING** — SHOULD/SHOULD NOT violation. Fails exit code only with `--strict`.
- **INFO** — Descriptive observation. Never fatal.

---

## 1. Identity Document Validation (§2.3)

| ID | Check | Severity |
|----|-------|----------|
| ID-01 | `aip` field equals `"1.0"` | ERROR |
| ID-02 | `id` is a valid AIP identifier (`aip:web:` or `aip:key:ed25519:`) | ERROR |
| ID-03 | `public_keys` array is non-empty | ERROR |
| ID-04 | Each key has `valid_from` and `valid_until` timestamps | ERROR |
| ID-05 | At least one key is currently valid (now ∈ [valid_from, valid_until]) | ERROR |
| ID-06 | `document_signature` verifies (JCS RFC 8785 + Ed25519) | ERROR |
| ID-07 | `expires` timestamp is in the future | WARNING |
| ID-08 | DNS-based ID resolves at `https://<domain>/.well-known/aip/<path>.json` | ERROR |
| ID-09 | Key validity windows overlap during rotation (no gap) | WARNING |

## 2. Compact Mode — JWT/Ed25519 (§3.1)

| ID | Check | Severity |
|----|-------|----------|
| CM-01 | JWS header `alg` is `EdDSA` | ERROR |
| CM-02 | JWS header `typ` is `aip-ibct+jwt` | ERROR |
| CM-03 | JWS header `kid` references a key in issuer's identity document | ERROR |
| CM-04 | Signature verifies against resolved public key | ERROR |
| CM-05 | Required claims present: `iss`, `sub`, `aud`, `exp`, `nbf`, `jti`, `scope`, `invocation` | ERROR |
| CM-06 | `exp` is in the future | ERROR |
| CM-07 | `nbf` is in the past | ERROR |
| CM-08 | `exp - nbf` does not exceed max TTL (1h standard, 15m sensitive) | WARNING |
| CM-09 | `jti` is a valid UUIDv4 or ULID | WARNING |

## 3. Chained Mode — Biscuit (§3.2)

**v0.1: STUB ONLY.** Returns `ErrChainedModeUnsupported`. Biscuit vendor-vs-implement decision deferred to v0.2.

| ID | Check | Severity |
|----|-------|----------|
| CH-01 | Token parses as a valid Biscuit v2 structure | ERROR |
| CH-02 | Root signature verifies against issuer identity document | ERROR |
| CH-03 | Each block signature verifies against preceding block's next-key | ERROR |
| CH-04 | Datalog evaluates without contradiction | ERROR |
| CH-05 | Authority block present and structurally valid | ERROR |

## 4. Scope Attenuation (§3.3) — HIGHEST PRIORITY

This is the core security property of the whole protocol. If burling does nothing else well, it must do this well.

| ID | Check | Severity |
|----|-------|----------|
| SA-01 | Child tool scope ⊆ parent tool scope | ERROR |
| SA-02 | Child resource scope ⊆ parent resource scope | ERROR |
| SA-03 | Child action scope ⊆ parent action scope | ERROR |
| SA-04 | Child temporal scope ⊆ parent temporal scope (`exp` never extends) | ERROR |
| SA-05 | Scope attenuation holds transitively across all hops | ERROR |
| SA-06 | No scope field introduces capabilities absent from parent | ERROR |

## 5. Bounded Delegation Depth (§3.4)

| ID | Check | Severity |
|----|-------|----------|
| BD-01 | Chain depth does not exceed profile ceiling (Simple=1, Standard=3, Advanced=7) | ERROR |
| BD-02 | Each block declares its depth consistently | ERROR |
| BD-03 | Depth is monotonic (each child = parent + 1) | ERROR |

## 6. Delegation Context (§3.5)

| ID | Check | Severity |
|----|-------|----------|
| DC-01 | `delegation_reason` field present on every non-root block | ERROR |
| DC-02 | `delegation_reason` is a known enum value or free-form string under length limit | WARNING |
| DC-03 | `on_behalf_of` field present and resolves to a valid identity | ERROR |
| DC-04 | Budget ceilings declared when present are numerically coherent (child ≤ parent) | ERROR |

## 7. Completion Blocks (§3.6)

| ID | Check | Severity |
|----|-------|----------|
| CB-01 | Completion block, if present, is the final block in the chain | ERROR |
| CB-02 | Completion block contains required fields: `completed_at`, `result_hash`, `signature` | ERROR |
| CB-03 | Completion signature verifies against the terminal agent's identity | ERROR |
| CB-04 | No blocks follow a completion block | ERROR |

## 8. MCP Binding (§4.1)

| ID | Check | Severity |
|----|-------|----------|
| MB-01 | Token is presented in the `Authorization: AIP <token>` header format | ERROR |
| MB-02 | MCP tool invocation matches a tool in the token's scope | ERROR |
| MB-03 | MCP session ID, if present, matches `invocation.session_id` | WARNING |

---

## Implementation order

1. `internal/report` — Finding type and JSON schema. ✅ (v0.0.1)
2. `internal/identity` — JCS + Ed25519. Smallest self-contained module.
3. `internal/compact` — JWT parse + Ed25519 verify + claim extraction.
4. `internal/scope` — Attenuation across all four dimensions. **Spend time here.**
5. `internal/depth`, `internal/context`, `internal/completion` — Structural checks.
6. `internal/mcpbind` — Transport-level, lighter weight.
7. `internal/chained` — STUB ONLY for v0.1.

When implementing a check that hits one of the open spec ambiguities, stub it with a `// TODO(ambiguity-NN)` comment and keep moving. See `spec-ambiguities.md`.
