package identity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
)

// Canonicalize produces the RFC 8785 JSON Canonicalization Scheme (JCS)
// form of the given JSON bytes. The output is the canonical byte
// sequence that ID-06 Ed25519 verification signs/verifies against.
//
// Scope and limitations for v0.1:
//   - UTF-16 code-unit key sorting (RFC 8785 §3.2.3): implemented.
//   - Minimal string escaping (§3.2.2.2): implemented.
//   - ES6-style number serialization (§3.2.2.3): implemented for the
//     common integer path. Exponent-form edge cases rely on
//     strconv.FormatFloat and may diverge from ES6 for very large or
//     very small magnitudes.
//     TODO(jcs-numbers): replace with a port of ECMAScript's
//     ToString(Number) when identity documents begin to use exponent
//     notation in practice. v0.1 identity documents avoid that path
//     entirely (all numeric fields are integers or
//     timestamps-as-strings).
//
// Canonicalize first decodes to json.RawMessage tree with UseNumber so
// we preserve the exact lexical form of numbers from the input and
// don't lose precision through float64 round-tripping before format.
func Canonicalize(in []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("jcs: parse input: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("jcs: trailing data after top-level value")
	}

	var out bytes.Buffer
	if err := canonicalWrite(&out, v); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func canonicalWrite(w *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		w.WriteString("null")
		return nil
	case bool:
		if t {
			w.WriteString("true")
		} else {
			w.WriteString("false")
		}
		return nil
	case json.Number:
		return writeNumber(w, string(t))
	case string:
		return writeString(w, t)
	case []any:
		w.WriteByte('[')
		for i, elem := range t {
			if i > 0 {
				w.WriteByte(',')
			}
			if err := canonicalWrite(w, elem); err != nil {
				return err
			}
		}
		w.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortKeysUTF16(keys)

		w.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				w.WriteByte(',')
			}
			if err := writeString(w, k); err != nil {
				return err
			}
			w.WriteByte(':')
			if err := canonicalWrite(w, t[k]); err != nil {
				return err
			}
		}
		w.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("jcs: unsupported type %T", v)
	}
}

// sortKeysUTF16 sorts keys by UTF-16 code-unit sequence per RFC 8785
// §3.2.3. Go's default string comparison is UTF-8 byte order, which
// diverges from UTF-16 order for supplementary-plane characters
// (> U+FFFF). We encode once to UTF-16 and sort on the paired slice
// so the encoding stays aligned with its key through every swap.
func sortKeysUTF16(keys []string) {
	u16 := make([][]uint16, len(keys))
	for i, k := range keys {
		u16[i] = utf16.Encode([]rune(k))
	}
	type pair struct {
		key string
		u16 []uint16
	}
	pairs := make([]pair, len(keys))
	for i := range keys {
		pairs[i] = pair{keys[i], u16[i]}
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		a, b := pairs[i].u16, pairs[j].u16
		n := len(a)
		if len(b) < n {
			n = len(b)
		}
		for k := 0; k < n; k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return len(a) < len(b)
	})
	for i := range pairs {
		keys[i] = pairs[i].key
	}
}

// writeNumber emits a JSON number in ES6-compatible form.
func writeNumber(w *bytes.Buffer, s string) error {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		w.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("jcs: invalid number %q: %w", s, err)
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return fmt.Errorf("jcs: non-finite number %q not representable", s)
	}
	// RFC 8785 §3.2.2.3: -0 serializes as "0".
	if f == 0 {
		w.WriteString("0")
		return nil
	}
	w.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	return nil
}

// writeString emits a JSON string with JCS-minimal escaping per
// §3.2.2.2. Only the seven required characters and the
// U+0000..U+001F range are escaped; all other code points pass
// through as their UTF-8 bytes.
func writeString(w *bytes.Buffer, s string) error {
	w.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			w.WriteString(`\"`)
		case '\\':
			w.WriteString(`\\`)
		case '\b':
			w.WriteString(`\b`)
		case '\f':
			w.WriteString(`\f`)
		case '\n':
			w.WriteString(`\n`)
		case '\r':
			w.WriteString(`\r`)
		case '\t':
			w.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(w, `\u%04x`, r)
			} else {
				w.WriteRune(r)
			}
		}
	}
	w.WriteByte('"')
	return nil
}
