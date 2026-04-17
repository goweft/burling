// Package compact implements AIP §3.1 compact-mode IBCT validation.
//
// Compact mode tokens are JWTs signed with Ed25519 (alg=EdDSA) carrying
// the AIP-specific typ "aip-ibct+jwt" and a fixed claim set. The nine
// checks CM-01..CM-09 from docs/conformance-matrix.md are dispatched
// by Validate.
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

// Payload is the IBCT claim set per §3.1.
//
// Time claims (exp, nbf) are unix seconds per RFC 7519. Scope and
// Invocation are kept as raw JSON so the compact package doesn't
// need to know their internal shape — that's scope-attenuation's job
// in v0.2. Claims whose presence CM-05 checks but whose content
// burling doesn't inspect live in Raw.
type Payload struct {
	Issuer     string          `json:"iss"`
	Subject    string          `json:"sub"`
	Audience   json.RawMessage `json:"aud"`
	Expiry     int64           `json:"exp"`
	NotBefore  int64           `json:"nbf"`
	JTI        string          `json:"jti"`
	Scope      json.RawMessage `json:"scope"`
	Invocation json.RawMessage `json:"invocation"`

	// Raw holds every top-level field as raw JSON, including fields
	// not modeled above. CM-05 iterates Raw to check required-claim
	// presence so adding a new required claim is a one-line change.
	Raw map[string]json.RawMessage `json:"-"`
}
