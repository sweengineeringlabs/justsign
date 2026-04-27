//! Span-preserving TUF envelope parser — approach (b) from the
//! [`crate::canonical`] module's trade-off discussion.
//!
//! # The problem
//!
//! TUF metadata files are `{ "signed": <object>, "signatures": [...] }`.
//! Signatures cover the **canonical-JSON form of the `signed` value**.
//! Sigstore's wire metadata is NOT pre-canonicalised on the wire, so a
//! verifier cannot just hash the raw `signed` bytes — except in the
//! degenerate case where a producer already emitted canonical JSON.
//!
//! [`crate::canonical`] picks approach (a): parse the document into a
//! [`serde_json::Value`], then re-emit `signed` through the
//! canonicaliser and feed the resulting bytes to the verifier. That
//! works, but it means signature verification trusts our re-emit, not
//! the source-of-truth wire bytes — any drift between the
//! canonicaliser's output and what the producer hashed shows up as a
//! signature mismatch. The drift surface is the entire canonicaliser.
//!
//! This module implements approach (b): scan the document with byte
//! offsets, record the [`Range<usize>`] that brackets the `signed`
//! value's source bytes, and let the caller hand `&doc[range]`
//! straight to the verifier (or, when the wire form is already
//! canonical, hash those bytes directly). The drift surface shrinks
//! to "did we extract the right span?" — a property the tests below
//! pin down byte-for-byte.
//!
//! # Trade-off
//!
//! - (a) is shorter (~250 LOC of canonicaliser, no parser). Drift
//!   surface: the canonicaliser's correctness across every escape /
//!   number / key-order edge case.
//! - (b) is longer (this module: hand-rolled scanner + tests). Drift
//!   surface: the scanner's correctness on JSON syntax (strings,
//!   escapes, nesting). Once the scanner is right, every byte the
//!   verifier sees is identical to a byte the producer signed.
//!
//! Both ship. (a) remains the path callers use until the TUF fetcher
//! migrates to (b); a follow-up issue tracks that migration.
//!
//! # Why hand-rolled instead of `serde_json::de::Deserializer`
//!
//! `serde_json`'s public API exposes parsed values, not source spans.
//! Pulling spans out of its internals would be brittle. A 200-LOC
//! hand-rolled JSON scanner that knows just enough to find the
//! `signed` value's bracketing offsets is simpler than reaching into
//! serde internals — and the test matrix below pins down every edge
//! case (nested objects, escaped quotes, control-char escapes,
//! multi-byte UTF-8, key-order independence).
//!
//! # Inputs we accept
//!
//! - Optional UTF-8 BOM (`\xEF\xBB\xBF`) at byte 0.
//! - Leading + trailing whitespace at the top level.
//! - Standard JSON whitespace (` `, `\t`, `\n`, `\r`) inside the
//!   document.
//! - Multi-byte UTF-8 inside string values (RFC 8259 requires UTF-8;
//!   we reject invalid UTF-8 cleanly via the typed deserialiser).
//! - `signatures` and `signed` in either order at the top level.
//!
//! # Inputs we reject
//!
//! - Top-level value that is not a JSON object.
//! - Document missing `signed`.
//! - Document missing `signatures`.
//! - Anything that fails typed `serde_json` deserialisation of the
//!   role body or the signatures vector.

use std::ops::Range;

use crate::root::Signature;

/// Parsed TUF envelope plus the source-byte range that brackets the
/// `signed` value.
///
/// `signed_bytes` is a half-open `[start, end)` byte range into the
/// input document. `&doc[signed_bytes.clone()]` is bit-for-bit
/// identical to the source bytes the producer signed (modulo
/// canonicalisation, when the wire form is not already canonical).
#[derive(Debug, Clone)]
pub struct SpannedSignedEnvelope<T> {
    /// Typed role body deserialised from the `signed` field.
    pub signed: T,

    /// Source-byte range of the `signed` field's value. Half-open
    /// `[start, end)`.
    pub signed_bytes: Range<usize>,

    /// Signatures sibling of `signed`.
    pub signatures: Vec<Signature>,
}

/// Errors produced by [`parse_with_signed_span`].
#[derive(Debug, thiserror::Error)]
pub enum SpanParseError {
    /// Top-level shape did not match the TUF envelope grammar
    /// (e.g. document was not a JSON object, was truncated, or
    /// contained an unbalanced bracket inside `signed`).
    #[error("invalid JSON envelope: {0}")]
    InvalidJson(String),

    /// The envelope was a valid object but did not carry the named
    /// field. TUF envelopes require both `signed` and `signatures`.
    #[error("envelope missing required field: {0}")]
    MissingField(&'static str),

    /// Typed deserialisation of `signed` (into `T`) or `signatures`
    /// (into `Vec<Signature>`) failed. The scanner got the shape
    /// right but the typed schema rejected the contents.
    #[error("typed deserialization failed: {0}")]
    Json(#[from] serde_json::Error),

    /// Input bytes were not valid UTF-8. RFC 8259 requires JSON
    /// documents to be UTF-8; we surface this as a typed error rather
    /// than letting it surface as a generic `serde_json` parse error
    /// so callers can route on it.
    #[error("input was not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

/// Parse a TUF envelope document and return the typed body together
/// with the source-byte range of the `signed` value.
///
/// The byte range obeys the load-bearing identity:
///
/// ```text
/// &doc[result.signed_bytes.clone()] == "the source bytes of the `signed` value"
/// ```
///
/// "Source bytes" means the bytes between the opening `{` (or `[` /
/// `"` / digit / `t` / `f` / `n`) of the `signed` value and the byte
/// immediately after its terminator, inclusive of any internal
/// whitespace the producer chose to emit. No trimming, no
/// re-encoding — these are the bytes a verifier should hand to the
/// canonicaliser-or-hasher.
pub fn parse_with_signed_span<T>(doc: &[u8]) -> Result<SpannedSignedEnvelope<T>, SpanParseError>
where
    T: serde::de::DeserializeOwned,
{
    // RFC 8259 says JSON is UTF-8; reject invalid UTF-8 up front so
    // every offset we record is a valid char boundary in the source.
    std::str::from_utf8(doc)?;

    let mut scanner = Scanner::new(doc);
    scanner.skip_bom_and_whitespace();
    scanner.expect_byte(b'{')?;

    let mut signed_span: Option<Range<usize>> = None;
    let mut signatures_span: Option<Range<usize>> = None;

    scanner.skip_whitespace();
    // Empty object: `{}`. Both required fields are absent, but report
    // `signed` first since it is the load-bearing one.
    if scanner.peek() == Some(b'}') {
        return Err(SpanParseError::MissingField("signed"));
    }

    loop {
        scanner.skip_whitespace();
        let key = scanner.read_string()?;
        scanner.skip_whitespace();
        scanner.expect_byte(b':')?;
        scanner.skip_whitespace();

        let value_start = scanner.pos();
        scanner.skip_value()?;
        let value_end = scanner.pos();
        let value_range = value_start..value_end;

        match key.as_str() {
            "signed" => {
                if signed_span.is_some() {
                    return Err(SpanParseError::InvalidJson(
                        "duplicate `signed` field".into(),
                    ));
                }
                signed_span = Some(value_range);
            }
            "signatures" => {
                if signatures_span.is_some() {
                    return Err(SpanParseError::InvalidJson(
                        "duplicate `signatures` field".into(),
                    ));
                }
                signatures_span = Some(value_range);
            }
            // Unknown top-level keys are tolerated for forward-compat
            // (TUF envelopes are conventionally exactly these two
            // fields, but the spec does not forbid extensions).
            _ => {}
        }

        scanner.skip_whitespace();
        match scanner.peek() {
            Some(b',') => {
                scanner.advance();
                continue;
            }
            Some(b'}') => {
                scanner.advance();
                break;
            }
            Some(b) => {
                return Err(SpanParseError::InvalidJson(format!(
                    "expected ',' or '}}' at byte {}, found {:?}",
                    scanner.pos() - 1,
                    b as char
                )));
            }
            None => {
                return Err(SpanParseError::InvalidJson(
                    "unexpected end of document inside top-level object".into(),
                ));
            }
        }
    }

    // Trailing tokens after the envelope object are forbidden — TUF
    // documents are a single JSON value.
    scanner.skip_whitespace();
    if scanner.peek().is_some() {
        return Err(SpanParseError::InvalidJson(format!(
            "trailing bytes after envelope at byte {}",
            scanner.pos()
        )));
    }

    let signed_span = signed_span.ok_or(SpanParseError::MissingField("signed"))?;
    let signatures_span = signatures_span.ok_or(SpanParseError::MissingField("signatures"))?;

    // Typed deserialise from the recovered spans. Doing it from the
    // span (not the whole doc + a key lookup) is the load-bearing
    // claim: the bytes the verifier sees and the bytes serde sees
    // are the same bytes.
    let signed: T = serde_json::from_slice(&doc[signed_span.clone()])?;
    let signatures: Vec<Signature> = serde_json::from_slice(&doc[signatures_span])?;

    // Debug-only sanity check: the recovered span must reparse to
    // *some* JSON value. Catches scanner off-by-one bugs in
    // development without paying the cost in release.
    debug_assert!(
        serde_json::from_slice::<serde_json::Value>(&doc[signed_span.clone()]).is_ok(),
        "recovered signed span did not reparse as JSON",
    );

    Ok(SpannedSignedEnvelope {
        signed,
        signed_bytes: signed_span,
        signatures,
    })
}

/// Minimal byte-offset-tracking JSON scanner.
///
/// Knows just enough of RFC 8259 to find the bracketing offsets of a
/// JSON value: matched `{}`, matched `[]`, strings (with backslash
/// escapes), and the four primitive scalar shapes (numbers, `true`,
/// `false`, `null`). Does NOT validate every JSON-grammar nuance —
/// `serde_json::from_slice` re-validates the recovered span.
struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn advance(&mut self) {
        self.pos += 1;
    }

    fn skip_bom_and_whitespace(&mut self) {
        // UTF-8 BOM: 0xEF 0xBB 0xBF.
        if self.bytes.len() >= 3 && &self.bytes[..3] == b"\xEF\xBB\xBF" {
            self.pos = 3;
        }
        self.skip_whitespace();
    }

    fn skip_whitespace(&mut self) {
        while let Some(b) = self.peek() {
            // RFC 8259 §2 whitespace: space, tab, LF, CR.
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect_byte(&mut self, want: u8) -> Result<(), SpanParseError> {
        match self.peek() {
            Some(got) if got == want => {
                self.pos += 1;
                Ok(())
            }
            Some(got) => Err(SpanParseError::InvalidJson(format!(
                "expected {:?} at byte {}, found {:?}",
                want as char, self.pos, got as char
            ))),
            None => Err(SpanParseError::InvalidJson(format!(
                "expected {:?} at byte {}, found end of input",
                want as char, self.pos
            ))),
        }
    }

    /// Read a JSON string starting at the current `"`, advancing past
    /// the closing `"`. Returns the decoded contents (we use this
    /// only for top-level keys, which are short and must be
    /// `"signed"` / `"signatures"`; using a real decode keeps the
    /// match against those literals honest, e.g. a key written as
    /// `"\u0073igned"` would still be recognised).
    fn read_string(&mut self) -> Result<String, SpanParseError> {
        self.expect_byte(b'"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => {
                    return Err(SpanParseError::InvalidJson(
                        "unterminated string in object key".into(),
                    ));
                }
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'"') => {
                            out.push('"');
                            self.pos += 1;
                        }
                        Some(b'\\') => {
                            out.push('\\');
                            self.pos += 1;
                        }
                        Some(b'/') => {
                            out.push('/');
                            self.pos += 1;
                        }
                        Some(b'b') => {
                            out.push('\u{0008}');
                            self.pos += 1;
                        }
                        Some(b'f') => {
                            out.push('\u{000C}');
                            self.pos += 1;
                        }
                        Some(b'n') => {
                            out.push('\n');
                            self.pos += 1;
                        }
                        Some(b'r') => {
                            out.push('\r');
                            self.pos += 1;
                        }
                        Some(b't') => {
                            out.push('\t');
                            self.pos += 1;
                        }
                        Some(b'u') => {
                            // For top-level keys we only need to NOT
                            // crash on `\uXXXX`; we do not decode
                            // surrogate pairs since the only keys we
                            // care about (`"signed"`, `"signatures"`)
                            // are pure ASCII. Non-ASCII keys fall
                            // through the `_ => {}` arm in the main
                            // loop and are tolerated as-is.
                            self.pos += 1;
                            let hex_start = self.pos;
                            for _ in 0..4 {
                                match self.peek() {
                                    Some(b) if b.is_ascii_hexdigit() => self.pos += 1,
                                    _ => {
                                        return Err(SpanParseError::InvalidJson(format!(
                                            "bad \\u escape at byte {}",
                                            hex_start
                                        )));
                                    }
                                }
                            }
                            let hex = std::str::from_utf8(&self.bytes[hex_start..self.pos])
                                .map_err(|e| {
                                    SpanParseError::InvalidJson(format!(
                                        "non-UTF8 hex in \\u escape: {e}"
                                    ))
                                })?;
                            let code = u32::from_str_radix(hex, 16).map_err(|e| {
                                SpanParseError::InvalidJson(format!(
                                    "invalid hex in \\u escape: {e}"
                                ))
                            })?;
                            if let Some(c) = char::from_u32(code) {
                                out.push(c);
                            } else {
                                // Lone surrogate; tolerate by dropping
                                // it from the decoded key. The only
                                // top-level keys we route on are
                                // pure ASCII, so this never matters
                                // for matching.
                            }
                        }
                        Some(b) => {
                            return Err(SpanParseError::InvalidJson(format!(
                                "bad escape \\{} at byte {}",
                                b as char,
                                self.pos - 1
                            )));
                        }
                        None => {
                            return Err(SpanParseError::InvalidJson(
                                "unterminated escape in string".into(),
                            ));
                        }
                    }
                }
                Some(_) => {
                    // Pass through one UTF-8 codepoint at a time.
                    // We already validated the whole input is UTF-8
                    // up front; using `str::from_utf8` on the tail
                    // and walking chars keeps us on codepoint
                    // boundaries even for multi-byte keys.
                    let tail = std::str::from_utf8(&self.bytes[self.pos..]).map_err(|e| {
                        SpanParseError::InvalidJson(format!(
                            "non-UTF8 inside string at byte {}: {e}",
                            self.pos
                        ))
                    })?;
                    let c = tail.chars().next().ok_or_else(|| {
                        SpanParseError::InvalidJson("string truncated mid-codepoint".into())
                    })?;
                    out.push(c);
                    self.pos += c.len_utf8();
                }
            }
        }
    }

    /// Skip past a single JSON value, leaving `pos` immediately after
    /// its last byte. Tracks nesting and string-escape semantics.
    fn skip_value(&mut self) -> Result<(), SpanParseError> {
        match self.peek() {
            Some(b'{') => self.skip_object_or_array(b'{', b'}'),
            Some(b'[') => self.skip_object_or_array(b'[', b']'),
            Some(b'"') => self.skip_string(),
            Some(b't') => self.skip_literal(b"true"),
            Some(b'f') => self.skip_literal(b"false"),
            Some(b'n') => self.skip_literal(b"null"),
            Some(b) if b == b'-' || b.is_ascii_digit() => self.skip_number(),
            Some(b) => Err(SpanParseError::InvalidJson(format!(
                "unexpected byte {:?} at start of value (offset {})",
                b as char, self.pos
            ))),
            None => Err(SpanParseError::InvalidJson(
                "unexpected end of document at start of value".into(),
            )),
        }
    }

    /// Skip past the matched bracket pair. Maintains a stack of
    /// pending closers so that nested heterogeneous structures
    /// (`{ "a": [1, {"b": 2}] }`) are tracked correctly: an array
    /// closer `]` does not satisfy a pending object closer `}`.
    /// Strings are skipped via [`Self::skip_string`] so internal
    /// quotes/brackets are not mistaken for structure.
    fn skip_object_or_array(&mut self, open: u8, close: u8) -> Result<(), SpanParseError> {
        debug_assert_eq!(self.peek(), Some(open));
        self.pos += 1;
        let mut stack: Vec<u8> = Vec::with_capacity(8);
        stack.push(close);
        while let Some(&top_close) = stack.last() {
            match self.peek() {
                None => {
                    return Err(SpanParseError::InvalidJson(format!(
                        "unbalanced {:?} ... {:?}",
                        open as char, close as char
                    )));
                }
                Some(b'"') => self.skip_string()?,
                Some(b'{') => {
                    self.pos += 1;
                    stack.push(b'}');
                }
                Some(b'[') => {
                    self.pos += 1;
                    stack.push(b']');
                }
                Some(b) if b == b'}' || b == b']' => {
                    if b != top_close {
                        return Err(SpanParseError::InvalidJson(format!(
                            "mismatched closer {:?} at byte {} (expected {:?})",
                            b as char, self.pos, top_close as char
                        )));
                    }
                    self.pos += 1;
                    stack.pop();
                }
                Some(_) => {
                    self.pos += 1;
                }
            }
        }
        Ok(())
    }

    /// Skip past a JSON string starting at `"`, including the closing
    /// `"`. Handles `\\`, `\"`, and other backslash escapes by
    /// stepping over the escape sequence so the closer of the escape
    /// is not mistaken for the string's end.
    fn skip_string(&mut self) -> Result<(), SpanParseError> {
        debug_assert_eq!(self.peek(), Some(b'"'));
        self.pos += 1;
        loop {
            match self.peek() {
                None => {
                    return Err(SpanParseError::InvalidJson(
                        "unterminated string literal".into(),
                    ));
                }
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some(b'\\') => {
                    // Step over the backslash AND the next byte. For
                    // `\u`, the four hex digits that follow are
                    // syntactically just bytes — we are not decoding
                    // here, only finding the matching `"`, so the
                    // generic "escape consumes two bytes" rule is
                    // enough to keep us from mistaking a `\"` for
                    // the closer.
                    self.pos += 1;
                    if self.pos >= self.bytes.len() {
                        return Err(SpanParseError::InvalidJson(
                            "unterminated escape in string".into(),
                        ));
                    }
                    self.pos += 1;
                }
                Some(_) => {
                    // Multi-byte UTF-8 inside a string passes through
                    // byte-by-byte; no special handling needed for
                    // span purposes.
                    self.pos += 1;
                }
            }
        }
    }

    fn skip_literal(&mut self, literal: &[u8]) -> Result<(), SpanParseError> {
        if self.pos + literal.len() > self.bytes.len()
            || &self.bytes[self.pos..self.pos + literal.len()] != literal
        {
            return Err(SpanParseError::InvalidJson(format!(
                "expected literal {:?} at byte {}",
                std::str::from_utf8(literal).unwrap_or("?"),
                self.pos
            )));
        }
        self.pos += literal.len();
        Ok(())
    }

    /// Skip past a JSON number: optional `-`, digits, optional
    /// fractional part, optional exponent. We do not validate the
    /// shape rigorously — `serde_json` re-validates when the
    /// recovered span deserialises.
    fn skip_number(&mut self) -> Result<(), SpanParseError> {
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-') {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(SpanParseError::InvalidJson(format!(
                "expected digit at byte {}",
                start
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Bug it catches: a producer who wraps the document in leading
    /// whitespace would trip a scanner that expects `{` at byte 0.
    /// Tolerating leading + trailing whitespace matches RFC 8259's
    /// "whitespace MAY surround any value" rule.
    #[test]
    fn test_parse_with_signed_span_top_level_whitespace_tolerated() {
        let doc = b"   \n\t  {\"signed\": {\"v\": 1}, \"signatures\": []}  \n";
        let env: SpannedSignedEnvelope<Value> =
            parse_with_signed_span(doc).expect("whitespace-tolerant parse");
        assert_eq!(&doc[env.signed_bytes.clone()], b"{\"v\": 1}");
    }

    /// Bug it catches: many editors (and some HTTP transcoders) emit
    /// a UTF-8 BOM. A scanner that expects `{` at byte 0 would
    /// reject. RFC 8259 §8.1 says BOM MAY appear; we eat it.
    #[test]
    fn test_parse_with_signed_span_utf8_bom_tolerated() {
        let mut doc = Vec::new();
        doc.extend_from_slice(b"\xEF\xBB\xBF");
        doc.extend_from_slice(b"{\"signed\": {\"v\": 1}, \"signatures\": []}");
        let env: SpannedSignedEnvelope<Value> =
            parse_with_signed_span(&doc).expect("BOM-tolerant parse");
        assert_eq!(&doc[env.signed_bytes.clone()], b"{\"v\": 1}");
    }

    /// Bug it catches: a depth-counting scanner that does not handle
    /// nested objects would close on the inner `}` and record the
    /// wrong end offset. The span MUST cover the outermost matched
    /// pair.
    #[test]
    fn test_parse_with_signed_span_nested_objects_in_signed_extract_outermost() {
        let doc = br#"{"signed": {"a": {"b": {"c": 1}}}, "signatures": []}"#;
        let env: SpannedSignedEnvelope<Value> = parse_with_signed_span(doc).expect("nested parse");
        assert_eq!(&doc[env.signed_bytes.clone()], br#"{"a": {"b": {"c": 1}}}"#);
    }

    /// Bug it catches: `]` inside an array nested inside `signed`
    /// must not be mistaken for the outer object's closer.
    #[test]
    fn test_parse_with_signed_span_nested_arrays_in_signed_extract_outermost() {
        let doc = br#"{"signed": {"x": [[1,2],[3,[4,5]]]}, "signatures": []}"#;
        let env: SpannedSignedEnvelope<Value> = parse_with_signed_span(doc).expect("array parse");
        assert_eq!(
            &doc[env.signed_bytes.clone()],
            br#"{"x": [[1,2],[3,[4,5]]]}"#
        );
    }

    /// Bug it catches: a naive scanner that searches for the next `}`
    /// after `signed`'s `{` would close the value at the inner `\"`
    /// inside `with \"quotes\"` — wrong by ~10 bytes. This is the
    /// classic spot where hand-rolled JSON scanners fail.
    #[test]
    fn test_parse_with_signed_span_escaped_quotes_in_string_extract_full_value() {
        let doc = br#"{"signed": {"k": "with \"quotes\""}, "signatures": []}"#;
        let env: SpannedSignedEnvelope<Value> =
            parse_with_signed_span(doc).expect("escaped-quote parse");
        assert_eq!(
            &doc[env.signed_bytes.clone()],
            br#"{"k": "with \"quotes\""}"#
        );
    }

    /// Bug it catches: a scanner that treats `\` and the next byte as
    /// independent characters might mis-handle `\\` (escape of
    /// escape) and end up "in escape mode" when it should be back to
    /// scanning. The byte sequence `"\\""` should close the string
    /// at the third `"`, not the second.
    #[test]
    fn test_parse_with_signed_span_escaped_backslash_does_not_consume_closing_quote() {
        let doc = br#"{"signed": {"k": "ends with backslash: \\"}, "signatures": []}"#;
        let env: SpannedSignedEnvelope<Value> =
            parse_with_signed_span(doc).expect("escaped-backslash parse");
        assert_eq!(
            &doc[env.signed_bytes.clone()],
            br#"{"k": "ends with backslash: \\"}"#
        );
    }

    /// Bug it catches: control-character escape sequences (`\n`,
    /// `\t`, `\u00xx`) inside a string are bytes the scanner must
    /// pass through without incident. A scanner that confused
    /// `\u00xx` for "open a brace four bytes from now" would record
    /// the wrong span.
    #[test]
    fn test_parse_with_signed_span_control_char_escapes_in_signed_string_round_trip() {
        let doc = br#"{"signed": {"k": "tab\tnl\nu\u0001"}, "signatures": []}"#;
        let env: SpannedSignedEnvelope<Value> =
            parse_with_signed_span(doc).expect("control-escape parse");
        assert_eq!(
            &doc[env.signed_bytes.clone()],
            br#"{"k": "tab\tnl\nu\u0001"}"#
        );
    }

    /// Bug it catches: multi-byte UTF-8 inside a string. Asian
    /// characters and emoji are >1 byte each in UTF-8; a scanner
    /// that walks codepoints rather than bytes would mis-count
    /// offsets, while one that treats every byte uniformly should
    /// be fine — this test pins the latter.
    #[test]
    fn test_parse_with_signed_span_multibyte_utf8_in_signed_preserves_exact_bytes() {
        let doc = "{\"signed\": {\"hello\": \"\u{4f60}\u{597d}\u{1f600}\"}, \"signatures\": []}"
            .as_bytes();
        let env: SpannedSignedEnvelope<Value> =
            parse_with_signed_span(doc).expect("multi-byte parse");
        let expected = "{\"hello\": \"\u{4f60}\u{597d}\u{1f600}\"}".as_bytes();
        assert_eq!(&doc[env.signed_bytes.clone()], expected);
    }

    /// Bug it catches: producers may emit `signatures` before
    /// `signed`. An order-dependent scanner would record the wrong
    /// span. JSON object members are unordered (RFC 8259 §4) so
    /// either order is legal on the wire.
    #[test]
    fn test_parse_with_signed_span_signatures_before_signed_extracts_correct_signed_span() {
        let doc = br#"{"signatures": [], "signed": {"v": 7}}"#;
        let env: SpannedSignedEnvelope<Value> =
            parse_with_signed_span(doc).expect("reverse-order parse");
        assert_eq!(&doc[env.signed_bytes.clone()], br#"{"v": 7}"#);
    }

    /// Bug it catches: silently treating a missing `signed` field as
    /// an empty object would let a malformed document past the
    /// verifier. A typed `MissingField("signed")` error forces the
    /// caller to handle it.
    #[test]
    fn test_parse_with_signed_span_missing_signed_field_returns_missing_field_error() {
        let doc = br#"{"signatures": []}"#;
        let err = parse_with_signed_span::<Value>(doc).expect_err("must error");
        match err {
            SpanParseError::MissingField("signed") => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    /// Bug it catches: same as above but for `signatures`. A
    /// document with no signatures is not the same as a document
    /// with the field omitted — the caller MUST distinguish.
    #[test]
    fn test_parse_with_signed_span_missing_signatures_field_returns_missing_field_error() {
        let doc = br#"{"signed": {"v": 1}}"#;
        let err = parse_with_signed_span::<Value>(doc).expect_err("must error");
        match err {
            SpanParseError::MissingField("signatures") => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    /// Bug it catches: a top-level array, string, or scalar is not a
    /// TUF envelope. Reject with a typed error rather than panicking
    /// or trying to deserialise into `T`.
    #[test]
    fn test_parse_with_signed_span_top_level_not_object_returns_invalid_json() {
        let docs: &[&[u8]] = &[b"[]", b"\"hi\"", b"42", b"null"];
        for doc in docs {
            let err = parse_with_signed_span::<Value>(doc).expect_err("must error");
            assert!(
                matches!(err, SpanParseError::InvalidJson(_)),
                "wanted InvalidJson, got {err:?} for {:?}",
                std::str::from_utf8(doc).unwrap_or("?")
            );
        }
    }

    /// Bug it catches: this is THE load-bearing safety claim of the
    /// (b) approach. The bytes the verifier hashes MUST be
    /// bit-for-bit identical to a contiguous slice of the source
    /// document. If this test fails, every signature verifying off
    /// the recovered span is dishonest.
    #[test]
    fn test_parse_with_signed_span_recovered_bytes_are_subslice_of_source_byte_for_byte() {
        let doc = br#"{"signed": {"k": "v", "n": 42, "nested": {"a": [1, 2, 3]}}, "signatures": [{"keyid": "x", "sig": "y"}]}"#;
        let env: SpannedSignedEnvelope<Value> = parse_with_signed_span(doc).expect("parse");
        // Identity: doc[start..end] is the exact substring at those
        // offsets.
        let recovered = &doc[env.signed_bytes.clone()];
        let expected = br#"{"k": "v", "n": 42, "nested": {"a": [1, 2, 3]}}"#;
        assert_eq!(recovered, expected);
        // And the offsets really are inside the doc (defensive
        // check — guards against future refactors that build a
        // synthetic span outside the input).
        assert!(env.signed_bytes.start < env.signed_bytes.end);
        assert!(env.signed_bytes.end <= doc.len());
    }

    /// Bug it catches: regression for the typed-deserialisation
    /// path. Having the span is necessary but not sufficient — the
    /// envelope must still produce a typed body. This is the full
    /// happy path a production caller hits.
    #[test]
    fn test_parse_with_signed_span_typed_root_happy_path_produces_signed_and_span() {
        let doc = br#"{
            "signed": {
                "_type": "root",
                "spec_version": "1.0.31",
                "version": 9,
                "expires": "2099-01-01T00:00:00Z",
                "keys": {},
                "roles": {
                    "root":      {"keyids": [], "threshold": 1},
                    "timestamp": {"keyids": [], "threshold": 1},
                    "snapshot":  {"keyids": [], "threshold": 1},
                    "targets":   {"keyids": [], "threshold": 1}
                },
                "consistent_snapshot": true
            },
            "signatures": [
                {"keyid": "abc", "sig": "deadbeef"}
            ]
        }"#;
        let env: SpannedSignedEnvelope<crate::root::Root> =
            parse_with_signed_span(doc).expect("typed parse");
        assert_eq!(env.signed.version, 9);
        assert_eq!(env.signatures.len(), 1);
        assert_eq!(env.signatures[0].keyid, "abc");
        // Span lies within the doc, and re-parsing it as Value
        // succeeds (it really is a valid JSON value, not a chunk
        // that happens to contain the right bytes plus garbage).
        let _: Value = serde_json::from_slice(&doc[env.signed_bytes.clone()]).expect("reparse");
    }

    /// Bug it catches: invalid UTF-8 should surface as a typed
    /// `Utf8` error, NOT a panic and NOT a confusing `serde_json`
    /// "unexpected character" error far from the actual cause.
    #[test]
    fn test_parse_with_signed_span_invalid_utf8_returns_utf8_error() {
        // 0xFF is never a valid leading byte in UTF-8.
        let doc: &[u8] = &[
            b'{', b'"', b's', b'i', b'g', b'n', b'e', b'd', b'"', b':', b'{', b'}', b',', b'"',
            b's', b'i', b'g', b'n', b'a', b't', b'u', b'r', b'e', b's', b'"', b':', b'[', b']',
            b'}', // garbage trailing byte
            0xFF,
        ];
        let err = parse_with_signed_span::<Value>(doc).expect_err("must error");
        assert!(matches!(err, SpanParseError::Utf8(_)), "got: {err:?}");
    }

    /// Bug it catches: a duplicate `signed` field is ambiguous —
    /// which one did the producer sign? Reject loudly rather than
    /// silently taking the first or the last and risking a
    /// signature mismatch.
    #[test]
    fn test_parse_with_signed_span_duplicate_signed_field_returns_invalid_json() {
        let doc = br#"{"signed": {"v": 1}, "signed": {"v": 2}, "signatures": []}"#;
        let err = parse_with_signed_span::<Value>(doc).expect_err("must error");
        match err {
            SpanParseError::InvalidJson(msg) => assert!(msg.contains("duplicate")),
            other => panic!("wrong error: {other:?}"),
        }
    }
}
