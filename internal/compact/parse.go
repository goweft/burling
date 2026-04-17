package compact

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Parse decodes a compact IBCT string into a Token.
//
// The input must have exactly three segments separated by dots; each
// segment must be valid base64url (unpadded preferred, padded
// tolerated). Header and payload must be valid JSON.
//
// Parse does NOT verify the signature — that's CM-04's job, called
// through Validate.
func Parse(raw string) (*Token, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("compact: expected 3 segments, got %d", len(parts))
	}
	headerB, err := decodeB64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("compact: decode header: %w", err)
	}
	payloadB, err := decodeB64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("compact: decode payload: %w", err)
	}
	sigB, err := decodeB64URL(parts[2])
	if err != nil {
		return nil, fmt.Errorf("compact: decode signature: %w", err)
	}

	var hdr Header
	if err := json.Unmarshal(headerB, &hdr); err != nil {
		return nil, fmt.Errorf("compact: parse header: %w", err)
	}

	// Parse payload twice: once into the typed struct, once into the
	// raw map so CM-05 can enumerate actual field presence.
	var pl Payload
	if err := json.Unmarshal(payloadB, &pl); err != nil {
		return nil, fmt.Errorf("compact: parse payload: %w", err)
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(payloadB, &rawMap); err != nil {
		return nil, fmt.Errorf("compact: parse payload (raw): %w", err)
	}
	pl.Raw = rawMap

	return &Token{
		Raw:          raw,
		HeaderRaw:    headerB,
		PayloadRaw:   payloadB,
		SignatureRaw: sigB,
		Header:       hdr,
		Payload:      pl,
	}, nil
}

// SigningInput returns the bytes the signature was computed over:
// "<header-b64url>.<payload-b64url>" in ASCII.
//
// This is the second-to-last dot-join of Raw. Using the original
// segments (not re-encoding HeaderRaw/PayloadRaw) is deliberate — any
// canonical-form mismatch in the encoder would break verification.
func (t *Token) SigningInput() []byte {
	i := strings.LastIndex(t.Raw, ".")
	if i < 0 {
		return nil
	}
	return []byte(t.Raw[:i])
}

// decodeB64URL accepts unpadded (raw) or padded base64url.
func decodeB64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
