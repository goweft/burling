// Package identity implements AIP §2.3 identity document validation.
//
// The nine checks ID-01..ID-09 from docs/conformance-matrix.md are all
// dispatched by Validate. Validate is pure: all network side effects
// (ID-08, well-known resolution) go through the Resolver interface so
// tests can inject MapResolver and production code injects HTTPResolver.
package identity

import "time"

// Document is the parsed form of an AIP identity document per §2.3.
//
// Unknown fields are tolerated on parse because the spec allows
// extensions. ID-06 signature verification uses the raw bytes, not the
// re-serialized form of this struct, so field order and extension
// fields are preserved.
type Document struct {
	AIP                string      `json:"aip"`
	ID                 string      `json:"id"`
	PublicKeys         []PublicKey `json:"public_keys"`
	Expires            *time.Time  `json:"expires,omitempty"`
	DocumentSignature  string      `json:"document_signature"`
	DocumentSigningKID string      `json:"document_signing_kid,omitempty"`

	// Raw holds the exact bytes the document was parsed from. Required
	// for ID-06: JCS canonicalization + Ed25519 verification operate on
	// the canonicalized form of the document with document_signature
	// removed, not on a re-marshaled Document value (which would lose
	// field ordering and any extension fields).
	Raw []byte `json:"-"`
}

// PublicKey is a single entry in public_keys per §2.3.
//
// Only Ed25519 is supported in v0.1. Key is the raw public key bytes
// (32 bytes for Ed25519), decoded from KeyBase64 at parse time so the
// crypto path doesn't have to handle encoding errors inline.
type PublicKey struct {
	KID        string    `json:"kid"`
	Alg        string    `json:"alg"`
	Key        []byte    `json:"-"`
	KeyBase64  string    `json:"key"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
}

// IsValidAt reports whether this key's validity window covers t.
// Boundaries are inclusive on both ends, matching the draft's language
// that a key is valid "from valid_from through valid_until."
func (k PublicKey) IsValidAt(t time.Time) bool {
	return !t.Before(k.ValidFrom) && !t.After(k.ValidUntil)
}
