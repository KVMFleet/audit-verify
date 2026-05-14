package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
)

// canonical emits a deterministic JSON byte sequence that matches what
// Python produces with:
//
//	json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
//
// — i.e. sorted map keys, no whitespace, and `ensure_ascii=True` style
// `\uXXXX` escapes for any rune ≥ 0x80. The platform's audit chain hashes
// over exactly this byte sequence, so the verifier must reproduce it to
// recompute row hashes.
//
// Inputs are expected to come from `json.Decoder` with `UseNumber()` set,
// so numeric values arrive as json.Number (a string) and we emit them
// verbatim — preserving the int-vs-float distinction the platform hashed.
func canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		encodeString(buf, x)
	case json.Number:
		// Emit verbatim; the original JSON source's representation is
		// what was hashed.
		buf.WriteString(string(x))
	case float64:
		// Should not occur when the decoder has UseNumber() set, but
		// handle defensively. Match Python's repr of float — finite
		// only.
		buf.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
	case int:
		buf.WriteString(strconv.Itoa(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeValue(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeString(buf, k)
			buf.WriteByte(':')
			if err := encodeValue(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported type %T", v)
	}
	return nil
}

// encodeString writes a JSON string with Python's `ensure_ascii=True`
// escape rules:
//   - control chars (< 0x20): short escapes for \b \f \n \r \t, \u00XX
//     for the rest;
//   - 0x22 (") and 0x5C (\) escaped;
//   - 0x7F: not escaped (Python's `ensure_ascii` only escapes ≥ 0x80);
//   - any rune ≥ 0x80: \uXXXX, with UTF-16 surrogate pair for > 0xFFFF;
//   - forward slash NOT escaped (matches Python default).
//
// HTML-unsafe chars (<, >, &) are NOT escaped — Python doesn't escape
// them, and we mustn't either.
func encodeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(buf, `\u%04x`, r)
		case r < 0x80:
			buf.WriteRune(r)
		case r <= 0xFFFF:
			fmt.Fprintf(buf, `\u%04x`, r)
		default:
			// Emit as UTF-16 surrogate pair (matches Python's
			// ensure_ascii output for code points above the BMP).
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(buf, `\u%04x\u%04x`, hi, lo)
		}
	}
	buf.WriteByte('"')
}
