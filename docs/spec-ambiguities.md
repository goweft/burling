# burling — Spec Ambiguities

Open questions in `draft-prakash-aip-00` flagged for discussion with the spec author (Sunil Prakash). When implementing a check that bumps into one of these, stub it with a `// TODO(ambiguity-NN)` comment and keep moving — the goal is to surface these upstream rather than work around them silently.

These five were identified during the initial spec read for the conformance matrix. As implementation proceeds, more may be added; new entries should follow the same numbered pattern and reference the spec section they touch.

---

## ambiguity-01 — Budget enforcement boundary (§3.5)

The spec states that aggregate budget enforcement is the responsibility of the orchestration platform, not the token verifier. burling can validate that per-token ceilings are numerically coherent (child ≤ parent, check DC-04), but cumulative enforcement across a chain is out of scope for any standalone validator.

**Question for Prakash:** Should a future spec version define a budget-reporting sidecar protocol, so orchestrators have a standard interface for emitting and aggregating consumption telemetry? Without this, every implementation invents its own and they will not interoperate.

**burling impact:** DC-04 implements the per-block check. No cumulative check; documented as platform responsibility in the README.

---

## ambiguity-02 — Revocation gap for long-running chains (§5.5)

Short TTLs are listed as the only v1 mitigation against compromised tokens. For chained tokens with three or more hops where the full chain may take minutes to execute, even a one-hour TTL leaves a meaningful exposure window. There is no defined mechanism to revoke a token mid-chain.

**Question for Prakash:** Is there an intended pattern for "revoke mid-chain" — for example, a verifier-side revocation list checked at each hop, or a sidecar OCSP-equivalent for IBCTs? If short TTLs are the entire answer, what is the recommended TTL for chained mode specifically?

**burling impact:** burling will warn (not error) when chained-mode TTL exceeds 15 minutes, with a comment referencing this ambiguity. Cannot validate revocation status because no mechanism exists.

---

## ambiguity-03 — Policy profile detection (§3.4)

The spec defines three policy profiles (Simple, Standard, Advanced) with different delegation depth ceilings (1, 3, 7) and Datalog complexity allowances. However, no explicit field in the token declares which profile it conforms to. A verifier must infer the profile from the token's structure.

**Question for Prakash:** Should there be an explicit `profile` field in the IBCT, or in the issuer's identity document? Inference works for unambiguous cases but breaks down at the boundaries (e.g., a Standard-profile token that happens to have depth 1 is indistinguishable from Simple).

**burling impact:** v0.1 will infer profile from delegation depth and presence/absence of Datalog blocks. Will accept a `--profile` CLI flag to override inference. BD-01 implementation should reference this ambiguity.

---

## ambiguity-04 — Completion block ordering (§3.6)

The spec says a completion block, if present, is "the final block" in a chain. CB-01 enforces this. But the spec does not explicitly state what should happen if an agent appends a delegation block after a completion block — is this an explicitly invalid token, or implementation-defined?

**Question for Prakash:** Should burling treat a post-completion block as an ERROR (token is malformed and MUST be rejected), or as a WARNING (unusual but possibly intentional)? A clarifying sentence in §3.6 would resolve this for all implementers.

**burling impact:** CB-04 will treat post-completion blocks as ERROR until clarified. Conservative default — easier to relax than tighten later.

---

## ambiguity-05 — Identity document caching headers (§2.3, §5.4)

§5.4 states that identity document cache TTL MUST NOT exceed 5 minutes. However, no `Cache-Control` or `max-age` guidance is given for the HTTP response that serves the identity document. Implementations are left to invent their own caching policy on top of whatever the origin happens to return.

**Question for Prakash:** Should there be normative guidance for `Cache-Control: max-age=300, must-revalidate` (or similar) on identity document responses? Without this, well-behaved verifiers may still cache for hours if the origin says so, defeating the §5.4 ceiling.

**burling impact:** When fetching identity documents (ID-08), burling will respect the §5.4 ceiling regardless of `Cache-Control` headers. Will emit an INFO finding if the origin returns a `max-age` greater than 300.

---

## How to add new ambiguities

When implementing a module reveals a new ambiguity:

1. Add an entry here with the next sequential ID (`ambiguity-06`, etc.).
2. Reference the spec section it touches.
3. State the question for the spec author plainly.
4. Document burling's chosen behavior and which check it affects.
5. Add a `// TODO(ambiguity-NN)` comment in the relevant Go file.
6. Mention it in the next outreach email or follow-up to Prakash.
