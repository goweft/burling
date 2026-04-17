# identity testdata

This directory is intentionally empty for v0.1.

Identity tests in `internal/identity/validate_test.go` generate their
fixtures programmatically at test time rather than loading static JSON.
Rationale:

1. Signatures are keyed to a specific Ed25519 private key. A static
   fixture either has to include the private key (defeats the point
   of fixtures — the private key *is* the signing authority) or be
   re-generated any time the test wants a `tampered-but-signed`
   variant, which is most of them.

2. Table-driven tests that mutate tree fields (drop `valid_from`,
   change the id, corrupt the signature) are clearer when the
   mutation is adjacent to the assertion than when it's encoded as
   a filename lookup.

3. The JCS canonicalization path is exercised on every test run
   because every signature involves canonicalizing. Static fixtures
   would let a canonicalizer regression pass undetected.

The helpers live in `validate_test.go`:

- `mintDoc(t, id)` — fresh keypair, minimal valid document, signed.
- `resign(t, raw, priv, fn)` — mutate tree, re-sign with same key.
- `mutateRaw(t, raw, fn)` — mutate tree, do NOT re-sign (for
  tampered-signature tests).

Static fixtures may land here later if burling grows a round-trip
corpus of known-good documents from real AIP implementers. For now,
programmatic generation is the contract.
