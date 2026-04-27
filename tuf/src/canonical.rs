//! Canonical JSON encoder for TUF metadata.
//!
//! TUF specifies that signatures cover the **canonical JSON** form
//! of the `signed` object. Real TUF clients re-canonicalise on every
//! verify; live Sigstore TUF metadata is NOT pre-canonicalised on
//! the wire, so a working verifier MUST be able to compute the
//! canonical form itself.
//!
//! # Spec references
//!
//! - TUF spec §4.2.1 "Canonical JSON":
//!   <https://theupdateframework.io/specification/latest/#canonical-json>
//! - The TUF spec defers the precise encoder to securesystemslib's
//!   `encode_canonical`, which is the de-facto canonical form
//!   emitted by every shipping TUF producer (tuf-on-ci, python-tuf,
//!   go-tuf). The OLPC canonical-JSON wiki page is a strict
//!   superset that does NOT match what TUF producers actually
//!   sign over -- empirically, the bundled Sigstore production
//!   root v14 fails to verify against an OLPC-style re-emit but
//!   passes against the securesystemslib form below.
//!
//! # Encoding rules (the contract this module implements)
//!
//! 1. **No insignificant whitespace.** No spaces, tabs, or newlines
//!    appear outside string values.
//! 2. **Object keys sorted by UTF-16 code units.** The comparison
//!    is over each key's UTF-16 encoding (the units
//!    `&str::encode_utf16()` produces), NOT over its raw UTF-8
//!    byte order. The two differ for any non-ASCII key.
//! 3. **Strings: minimal escapes only — backslash and double-quote.**
//!    - `\\` for U+005C (REVERSE SOLIDUS).
//!    - `\"` for U+0022 (QUOTATION MARK).
//!    - **Every other byte passes through verbatim**, including the
//!      RFC 8259 control bytes U+0000..U+001F (LF, TAB, etc.) and
//!      multibyte UTF-8 sequences. This produces **technically
//!      invalid JSON** for strings containing control bytes, but it
//!      matches what securesystemslib's `encode_canonical` emits
//!      and what every shipping TUF producer signs over. Sigstore's
//!      v14 root, for instance, has PEM-encoded public keys whose
//!      JSON-decoded value contains literal LF (0x0A) bytes; if we
//!      escaped those to `\n`, the canonical bytes would diverge
//!      from what Sigstore's signers hashed and every signature
//!      would fail to verify.
//!    - Supplementary-plane characters (U+10000..U+10FFFF) pass
//!      through as their 4-byte UTF-8 sequence.
//! 4. **Numbers: integers only.** TUF metadata's schema has no
//!    floating-point fields; emitting one would force us to pick an
//!    IEEE-754-to-decimal rendering that two implementations are
//!    unlikely to agree on. We refuse with [`CanonicalizationError::FloatNotSupported`]
//!    rather than silently allow two non-equivalent canonical forms
//!    to coexist. Booleans and `null` pass through verbatim.
//! 5. **Arrays: comma-separated, no spaces.** Empty arrays are `[]`.
//! 6. **Recursive.** The rules apply to every nested value; the
//!    top-level value can be any JSON type.
//!
//! # Why approach (a) — re-canonicalisation — for v0
//!
//! There are two ways to feed signature verification the right
//! bytes:
//!
//! - (a) Parse the document into [`serde_json::Value`], then re-emit
//!   the `signed` field through this canonicaliser.
//! - (b) Use a streaming parser that preserves source spans, and
//!   hand the original `signed` byte slice straight to the
//!   verifier. (b) is the long-term correct answer — we then trust
//!   the source-of-truth bytes rather than our own re-emit. But it
//!   requires a custom span-preserving JSON parser (~500 LOC of
//!   careful work) and is overkill for v0 if (a) is correct.
//!
//! For v0 we do (a). A follow-up issue tracks the (b) migration.
//!
//! # Non-goals
//!
//! - Not a general-purpose JSON formatter. Use `serde_json::to_*`
//!   for human output. `serde_json::to_string` is NOT canonical: it
//!   permits multiple legal forms (key order, escape choice for
//!   non-ASCII), so signatures over its output verify on the
//!   signer's box and fail on the verifier's after a serde
//!   round-trip.
//! - Not a parser. Input is `serde_json::Value` (already parsed).

use std::io::Write as _;

use serde_json::Value;

/// Errors from canonicalising a [`serde_json::Value`] to OLPC
/// canonical JSON.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalizationError {
    /// A floating-point number was encountered. TUF metadata's
    /// schema has no floats, and emitting one would force a
    /// decimal rendering that two implementations are unlikely to
    /// agree on bit-for-bit. Reject loudly rather than silently
    /// allow two non-equivalent canonical forms.
    ///
    /// `path` is a JSON-Pointer-style location of the offending
    /// value (e.g. `/signed/version`) for diagnostics.
    #[error("float numbers are not supported in canonical JSON (at {path})")]
    FloatNotSupported {
        /// JSON Pointer (RFC 6901) location of the float.
        path: String,
    },

    /// A number could not be represented as either a signed or
    /// unsigned 64-bit integer. In practice serde_json only hits
    /// this if the number is outside `[i64::MIN, u64::MAX]`; very
    /// large integers in TUF metadata would be a schema violation.
    #[error("number out of supported integer range (at {path})")]
    NumberOutOfRange {
        /// JSON Pointer (RFC 6901) location of the offending number.
        path: String,
    },
}

/// Encode `value` to OLPC canonical JSON bytes.
///
/// See the module-level docs for the full rule set. The output is
/// deterministic: two calls with the same logical value produce
/// byte-identical output, regardless of the input's source
/// (hand-built `Value`, `serde_json::from_slice`, or a round-trip
/// through this function).
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, CanonicalizationError> {
    let mut out = Vec::with_capacity(64);
    write_value(&mut out, value, "")?;
    Ok(out)
}

fn write_value(out: &mut Vec<u8>, value: &Value, path: &str) -> Result<(), CanonicalizationError> {
    match value {
        Value::Null => {
            out.extend_from_slice(b"null");
            Ok(())
        }
        Value::Bool(true) => {
            out.extend_from_slice(b"true");
            Ok(())
        }
        Value::Bool(false) => {
            out.extend_from_slice(b"false");
            Ok(())
        }
        Value::Number(n) => write_number(out, n, path),
        Value::String(s) => {
            write_string(out, s);
            Ok(())
        }
        Value::Array(arr) => write_array(out, arr, path),
        Value::Object(map) => write_object(out, map, path),
    }
}

fn write_number(
    out: &mut Vec<u8>,
    n: &serde_json::Number,
    path: &str,
) -> Result<(), CanonicalizationError> {
    // serde_json::Number tags the underlying type. A float lit like
    // `1.0` deserialises to is_f64()==true even though it has an
    // integer value; we treat that as a schema violation and refuse.
    if n.is_f64() {
        return Err(CanonicalizationError::FloatNotSupported {
            path: path.to_string(),
        });
    }
    if let Some(i) = n.as_i64() {
        // i64 covers all of [i64::MIN, i64::MAX]; positive values
        // up to i64::MAX go through this branch in serde_json.
        write!(out, "{i}").expect("write to Vec<u8> never fails");
        return Ok(());
    }
    if let Some(u) = n.as_u64() {
        // u64 in (i64::MAX, u64::MAX] — serde_json keeps these
        // separately so we don't lose precision converting through
        // i64.
        write!(out, "{u}").expect("write to Vec<u8> never fails");
        return Ok(());
    }
    // Not f64, not i64, not u64 — out of representable range.
    Err(CanonicalizationError::NumberOutOfRange {
        path: path.to_string(),
    })
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            // securesystemslib's `encode_canonical` escapes ONLY
            // backslash and double-quote. Every other byte passes
            // through verbatim, including U+0000..U+001F control
            // bytes. The result is technically invalid JSON when a
            // control byte appears in a string value, but it
            // matches what TUF producers (tuf-on-ci, python-tuf,
            // go-tuf via securesystemslib) actually sign over --
            // any wider escape rule would diverge from the bytes
            // those producers hashed and every signature would
            // fail to verify. See module docs for the specific
            // load-bearing case (PEM-encoded public keys whose
            // JSON-decoded value carries literal LF bytes).
            '\\' => out.extend_from_slice(b"\\\\"),
            '"' => out.extend_from_slice(b"\\\""),
            c => {
                let mut buf = [0u8; 4];
                let encoded = c.encode_utf8(&mut buf);
                out.extend_from_slice(encoded.as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn write_array(out: &mut Vec<u8>, arr: &[Value], path: &str) -> Result<(), CanonicalizationError> {
    out.push(b'[');
    for (i, item) in arr.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        // Build the child path lazily — only allocate a new String
        // when we descend.
        let child_path = format!("{path}/{i}");
        write_value(out, item, &child_path)?;
    }
    out.push(b']');
    Ok(())
}

fn write_object(
    out: &mut Vec<u8>,
    map: &serde_json::Map<String, Value>,
    path: &str,
) -> Result<(), CanonicalizationError> {
    // OLPC canonical JSON sorts object keys by UTF-16 code units —
    // NOT by &str byte order. The two diverge for any non-ASCII
    // key. Example: 'a' (U+0061) vs 'é' (U+00E9): UTF-16-cmp
    // orders 'a' < 'é' (because 0x0061 < 0x00E9), and so does
    // byte-cmp here, but for keys differing only above U+007F the
    // UTF-8 byte order can disagree with the code-point order
    // (UTF-8 multi-byte prefix bytes are >= 0xC2). Sorting by
    // encode_utf16 gives the same answer as the code-point order
    // for everything outside the supplementary plane, and for the
    // supplementary plane it gives the surrogate-pair order which
    // is what OLPC specifies.
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));

    out.push(b'{');
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        write_string(out, key);
        out.push(b':');
        // Build a JSON-Pointer child path. Per RFC 6901, '~' and
        // '/' inside a key need escaping (~0 and ~1). We do that
        // here so error paths are unambiguous; it's diagnostic
        // text, not part of the canonical output.
        let escaped_key = key.replace('~', "~0").replace('/', "~1");
        let child_path = format!("{path}/{escaped_key}");
        let value = map
            .get(key.as_str())
            .expect("key was just iterated from map");
        write_value(out, value, &child_path)?;
    }
    out.push(b'}');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Smoke: object keys are emitted in sorted order, not insertion
    /// order.
    ///
    /// Bug it catches: a non-canonicalising encoder that preserves
    /// insertion order. Two signers building the same logical
    /// metadata would emit different bytes; the verifier's
    /// re-canonicalisation must produce the canonical form
    /// regardless of input order.
    #[test]
    fn test_canonicalize_object_with_unsorted_keys_emits_sorted_keys() {
        let v = json!({"b": 1, "a": 2});
        let bytes = canonicalize(&v).unwrap();
        assert_eq!(bytes, br#"{"a":2,"b":1}"#);
    }

    /// Nested object keys are also sorted, not just the top level.
    ///
    /// Bug it catches: a shallow sort that only reorders the
    /// outermost map. TUF metadata is deeply nested
    /// (`signed.roles.root.keyids` is 3 levels in); a shallow
    /// canonicaliser would silently produce different bytes for the
    /// same logical document.
    #[test]
    fn test_canonicalize_nested_object_with_unsorted_keys_sorts_recursively() {
        let v = json!({"a": {"b": 1, "a": 2}});
        let bytes = canonicalize(&v).unwrap();
        assert_eq!(bytes, br#"{"a":{"a":2,"b":1}}"#);
    }

    /// Empty objects render as `{}` with no whitespace.
    ///
    /// Bug it catches: an encoder that always emits a trailing
    /// space or newline would break canonical-JSON byte equality
    /// even on empty containers.
    #[test]
    fn test_canonicalize_empty_object_emits_two_braces() {
        let v = json!({});
        let bytes = canonicalize(&v).unwrap();
        assert_eq!(bytes, b"{}");
    }

    /// Empty arrays render as `[]`.
    ///
    /// Bug it catches: an encoder that emits a leading/trailing
    /// comma in the empty case (off-by-one in the comma loop).
    #[test]
    fn test_canonicalize_empty_array_emits_two_brackets() {
        let v = json!([]);
        let bytes = canonicalize(&v).unwrap();
        assert_eq!(bytes, b"[]");
    }

    /// The empty string is `""`.
    ///
    /// Bug it catches: an encoder that omits both quote marks for
    /// the empty case, breaking JSON validity.
    #[test]
    fn test_canonicalize_empty_string_emits_two_quotes() {
        let v = json!("");
        let bytes = canonicalize(&v).unwrap();
        assert_eq!(bytes, b"\"\"");
    }

    /// A string containing a literal newline byte (0x0A) passes
    /// through verbatim — NOT escaped to `\n`. This matches
    /// securesystemslib's `encode_canonical` and is what every
    /// shipping TUF producer signs over.
    ///
    /// Bug it catches: a regression to RFC-8259 / OLPC-style
    /// escaping would diverge from what Sigstore's tuf-on-ci
    /// actually emits. The bundled v14 production root carries
    /// PEM-encoded public keys whose JSON-decoded value contains
    /// literal LF bytes; escaping those to `\n` makes every ECDSA
    /// signature fail to verify (see
    /// `crate::root::tests::test_verify_role_against_bundled_sigstore_v14_self_signature`).
    #[test]
    fn test_canonicalize_string_with_newline_passes_through_verbatim() {
        let v = json!("a\nb");
        let bytes = canonicalize(&v).unwrap();
        // Output is the 5 bytes: " a 0x0A b "
        assert_eq!(bytes, b"\"a\nb\"");
    }

    /// Backslash and double-quote ARE escaped (the only two
    /// characters securesystemslib's canonical encoder escapes);
    /// every other byte that RFC 8259 would conventionally write
    /// as a shorthand escape passes through verbatim.
    ///
    /// Bug it catches: a partial revert that re-introduced any
    /// of the RFC-8259 shorthands (`\b`, `\t`, `\n`, `\f`, `\r`)
    /// would diverge from securesystemslib and break signature
    /// verification on every TUF root that contains those bytes
    /// in a string value.
    #[test]
    fn test_canonicalize_string_only_backslash_and_quote_escaped() {
        let v = json!("\u{0008}\u{0009}\u{000A}\u{000C}\u{000D}\"\\");
        let bytes = canonicalize(&v).unwrap();
        // Five raw control bytes, then \", then \\.
        assert_eq!(bytes, b"\"\x08\x09\x0A\x0C\x0D\\\"\\\\\"");
    }

    /// Non-ASCII characters in a string pass through as their UTF-8
    /// bytes, NOT as `\uXXXX` escapes.
    ///
    /// Bug it catches: an over-eager escaper that quotes printable
    /// BMP characters would produce canonically-different bytes
    /// from another conformant impl. RFC 8259 only *requires*
    /// escapes for U+0000..U+001F, `\`, and `"`.
    #[test]
    fn test_canonicalize_string_with_non_ascii_passes_through_as_utf8() {
        let v = json!("héllo");
        let bytes = canonicalize(&v).unwrap();
        // 'é' is U+00E9; its UTF-8 encoding is 0xC3 0xA9.
        let expected: &[u8] = b"\"h\xC3\xA9llo\"";
        assert_eq!(bytes, expected);
    }

    /// A character above the BMP (here U+1F600, the grinning face)
    /// is emitted as its 4-byte UTF-8 encoding, NOT as a JSON
    /// surrogate pair.
    ///
    /// Bug it catches: emitting `\uD83D\uDE00` (the surrogate-pair
    /// JSON escape) would canonically differ from a conformant impl
    /// that uses the literal UTF-8 bytes. RFC 8259 permits both
    /// forms; OLPC canonical JSON requires the literal form.
    #[test]
    fn test_canonicalize_string_with_supplementary_plane_char_emits_utf8_bytes() {
        // Build the string explicitly so the test source is ASCII-clean.
        let s = String::from('\u{1F600}');
        let v = Value::String(s);
        let bytes = canonicalize(&v).unwrap();
        // U+1F600 in UTF-8 is the 4-byte sequence F0 9F 98 80.
        let expected: &[u8] = b"\"\xF0\x9F\x98\x80\"";
        assert_eq!(bytes, expected);
    }

    /// U+007F (DEL) is NOT in RFC 8259's required-escape set
    /// (U+0000..U+001F); it passes through as the literal 0x7F
    /// byte.
    ///
    /// Bug it catches: an off-by-one where the escape range is
    /// `< 0x21` or `<= 0x20` instead of `< 0x20` would over-escape
    /// DEL and produce canonically-different output.
    #[test]
    fn test_canonicalize_string_with_del_byte_passes_through_unescaped() {
        let v = Value::String(String::from('\u{007F}'));
        let bytes = canonicalize(&v).unwrap();
        // Three bytes: opening quote, raw 0x7F, closing quote.
        assert_eq!(bytes, b"\"\x7F\"");
    }

    /// Plain integers render as decimal with no decoration.
    ///
    /// Bug it catches: a number formatter that adds a `.0` suffix
    /// (Python-style) or scientific notation for small ints would
    /// produce canonically-different output from a conformant impl.
    #[test]
    fn test_canonicalize_small_integers_emit_plain_decimal() {
        assert_eq!(canonicalize(&json!(42)).unwrap(), b"42");
        assert_eq!(canonicalize(&json!(0)).unwrap(), b"0");
        assert_eq!(canonicalize(&json!(-1)).unwrap(), b"-1");
    }

    /// `i64::MAX` and `i64::MIN` round-trip through the
    /// canonicaliser as plain decimal — no scientific notation, no
    /// truncation.
    ///
    /// Bug it catches: a formatter that flips to `1e19` for
    /// 9.2e18-ish values would canonically differ from
    /// `9223372036854775807`. TUF version numbers are u32 in
    /// practice, but defensive coverage for the full i64 range
    /// catches a class of formatter regressions.
    #[test]
    fn test_canonicalize_i64_extremes_emit_full_decimal_no_scientific() {
        let max = canonicalize(&json!(i64::MAX)).unwrap();
        assert_eq!(max, b"9223372036854775807");
        let min = canonicalize(&json!(i64::MIN)).unwrap();
        assert_eq!(min, b"-9223372036854775808");
    }

    /// Floating-point numbers trigger a typed error, not a silent
    /// formatting choice.
    ///
    /// Bug it catches: silently rendering 1.0 as "1.0" or "1" would
    /// let two equivalent-by-value canonical forms coexist. TUF
    /// metadata schemas have no floats; refusing forces the caller
    /// to handle it explicitly.
    #[test]
    fn test_canonicalize_float_value_returns_float_not_supported_error() {
        let v = json!({"signed": {"version": 1.5}});
        let err = canonicalize(&v).unwrap_err();
        match err {
            CanonicalizationError::FloatNotSupported { path } => {
                assert_eq!(path, "/signed/version");
            }
            other => panic!("expected FloatNotSupported, got {other:?}"),
        }
    }

    /// `true`, `false`, and `null` pass through as the literal
    /// 4/5/4-byte tokens.
    ///
    /// Bug it catches: a serde-derived encoder that quotes booleans
    /// (Python-style "True") would canonically differ from any
    /// conformant impl.
    #[test]
    fn test_canonicalize_bool_and_null_emit_literal_tokens() {
        assert_eq!(canonicalize(&json!(true)).unwrap(), b"true");
        assert_eq!(canonicalize(&json!(false)).unwrap(), b"false");
        assert_eq!(canonicalize(&Value::Null).unwrap(), b"null");
    }

    /// Object keys differing only in non-ASCII characters sort by
    /// UTF-16 code units, not by raw byte order.
    ///
    /// `'é'` is U+00E9 (UTF-16 unit 0x00E9, UTF-8 bytes 0xC3 0xA9);
    /// `'a'` is U+0061 (UTF-16 unit 0x0061, UTF-8 byte 0x61).
    /// UTF-16-cmp orders `'a' (0x0061) < 'é' (0x00E9)`, so the
    /// canonical output places key `"a"` before key `"é"`.
    ///
    /// (Sanity: byte-cmp would order them the same way *here*
    /// because 0x61 < 0xC3, but for keys differing only above
    /// U+0080 the byte-cmp and code-point-cmp can disagree because
    /// UTF-8 multi-byte prefixes are >= 0xC2. The right test is
    /// that we compare on `encode_utf16` output.)
    ///
    /// Bug it catches: sorting by raw bytes (`String::cmp`) instead
    /// of by UTF-16 units. The two impls disagree on, for example,
    /// keys `"\u{007F}"` vs `"\u{0080}"` — but more importantly
    /// they disagree systematically for any pair of keys whose
    /// first differing character is above U+007F.
    #[test]
    fn test_canonicalize_object_with_non_ascii_keys_sorts_by_utf16_code_units() {
        // Build the map explicitly so we can assert the exact byte
        // form including the UTF-8 encoding of the e-acute key.
        let mut map = serde_json::Map::new();
        map.insert("é".to_string(), json!(1));
        map.insert("a".to_string(), json!(2));
        let v = Value::Object(map);
        let bytes = canonicalize(&v).unwrap();
        // {"a":2,"é":1} with é as raw UTF-8 0xC3 0xA9.
        let expected: &[u8] = b"{\"a\":2,\"\xC3\xA9\":1}";
        assert_eq!(bytes, expected);
    }

    /// A representative mixed structure round-trips to the exact
    /// expected canonical bytes.
    ///
    /// Bug it catches: composition errors between the per-type
    /// writers — e.g. a stray space between the `:` and the value,
    /// or between `,` and the next item.
    #[test]
    fn test_canonicalize_mixed_top_level_array_emits_exact_canonical_bytes() {
        let v = json!([
            {"z": 1, "a": 2},
            {"x": [true, false, null], "k": "v"},
            42
        ]);
        let bytes = canonicalize(&v).unwrap();
        assert_eq!(
            bytes,
            br#"[{"a":2,"z":1},{"k":"v","x":[true,false,null]},42]"#
        );
    }

    /// Canonicalising the same `Value` twice produces byte-identical
    /// output.
    ///
    /// Bug it catches: any non-determinism (e.g. iterating a
    /// HashMap instead of a sorted Vec, or relying on
    /// `String::hash`-derived order). This is a smoke-test for the
    /// invariant the rest of the suite assumes.
    #[test]
    fn test_canonicalize_called_twice_on_same_value_produces_identical_bytes() {
        let v = json!({"b": [1, 2, {"d": 4, "c": 3}], "a": "x"});
        let first = canonicalize(&v).unwrap();
        let second = canonicalize(&v).unwrap();
        assert_eq!(first, second);
    }

    /// Round-trip: `canonicalize(parse(canonicalize(v))) ==
    /// canonicalize(v)`. A canonicaliser that's lossy through
    /// parse → re-canonicalise can't be used as the basis for
    /// signature verification.
    ///
    /// Bug it catches: an encoder that drops information the
    /// parser can't recover (e.g. relying on insertion order that
    /// parse-then-emit doesn't preserve).
    #[test]
    fn test_canonicalize_parse_recanonicalize_round_trip_is_stable() {
        let v = json!({
            "_type": "root",
            "version": 7,
            "expires": "2030-01-01T00:00:00Z",
            "consistent_snapshot": true,
            "roles": {
                "root":      {"keyids": ["abc"], "threshold": 1},
                "snapshot":  {"keyids": ["abc"], "threshold": 1},
                "targets":   {"keyids": ["abc"], "threshold": 1},
                "timestamp": {"keyids": ["abc"], "threshold": 1}
            }
        });
        let first = canonicalize(&v).unwrap();
        let parsed: Value = serde_json::from_slice(&first).unwrap();
        let second = canonicalize(&parsed).unwrap();
        assert_eq!(first, second);
    }

    /// Float diagnostics: the JSON-Pointer path inside an array
    /// element is rendered with the index, not the key.
    ///
    /// Bug it catches: a path-builder that always uses keys would
    /// produce a malformed pointer like `/0/x` becoming `//x` for
    /// arrays, making the error message useless to a TUF metadata
    /// author trying to fix an offending field.
    #[test]
    fn test_canonicalize_float_inside_array_reports_indexed_path() {
        let v = json!([{"a": 1.5}]);
        let err = canonicalize(&v).unwrap_err();
        match err {
            CanonicalizationError::FloatNotSupported { path } => {
                assert_eq!(path, "/0/a");
            }
            other => panic!("expected FloatNotSupported, got {other:?}"),
        }
    }
}
