// Package compact implements AIP §3.1 compact-mode IBCT validation.
//
// Compact mode tokens are JWTs signed with Ed25519 (alg=EdDSA) carrying
// the AIP-specific typ "aip+jwt" and a fixed claim set. The nine checks
// CM-01..CM-09 from docs/conformance-matrix.md are dispatched by
// Validate.
//
// CM-03 and CM-04 resolve the issuer's identity document to locate the
// signing key. The Resolver is the same interface used by the identity
// package — a single MapResolver can feed both modules in tests, and a
// single HTTPResolver in production.
package compact

import (
	"encoding/json"
)

// Token is the parsed form of a compact IBCT.
//
// Raw is the original three-part string "<header>.<payload>.<signature>"
// in base64url form. HeaderRaw and PayloadRaw are the base64url-decoded
// JSON bytes for their respective segments; SignatureRaw is the decoded
// signature bytes (64 bytes for Ed25519). These are held separately
// because CM-04 signature verification operates on the
// "<header>.<payload>" ASCII bytes, not on a re-marshaled form.
type Token struct {
	Raw          string
	HeaderRaw    []byte
	PayloadRaw   []byte
	SignatureRaw []byte

	Header  Header
	Payload Payload
}

// Header is the JWS protected header per §3.1.
//
// Only the fields burling checks are modeled; unknown header fields
// are tolerated at parse time but have no effect on validation.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	KID string `json:"kid"`
}

// Payload is the IBCT claim set per §3.1. The seven REQUIRED claims are
// iss, sub, scope, budget_usd, max_depth, iat, and exp.
//
// Time claims (iat, exp) are unix seconds per RFC 7519. Scope is kept
// as raw JSON so the compact package doesn't need to know its internal
// shape — that's scope-attenuation's job in v0.2. Claims whose presence
// CM-05 checks but whose value burling doesn't inspect (e.g. max_depth)
// live only in Raw.
type Payload struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Scope     json.RawMessage `json:"scope"`
	BudgetUSD float64         `json:"budget_usd"`
	IssuedAt  int64           `json:"iat"`
	Expiry    int64           `json:"exp"`

	// Raw holds every top-level field as raw JSON, including fields
	// not modeled above. CM-05 iterates Raw to check required-claim
	// presence so adding a new required claim is a one-line change.
	Raw map[string]json.RawMessage `json:"-"`
}
