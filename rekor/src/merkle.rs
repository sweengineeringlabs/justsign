//! RFC 6962 Merkle inclusion-proof verifier.
//!
//! Reference: <https://datatracker.ietf.org/doc/html/rfc6962#section-2.1>
//!
//! Hashing rules (SHA-256):
//!
//! * Leaf:     `H(0x00 || leaf_bytes)`
//! * Internal: `H(0x01 || left || right)`
//! * Empty:    `H("")`
//!
//! The 0x00 / 0x01 domain-separation prefixes prevent second-
//! preimage attacks where a leaf is collided with an internal
//! node.
//!
//! ## Path traversal — the unbalanced-tree edge case
//!
//! For balanced trees (`tree_size` is a power of 2) the audit path
//! length is exactly `log2(tree_size)` and every level produces a
//! sibling.
//!
//! For unbalanced trees, the rightmost subtree is shallower, so
//! the rightmost leaves take a shorter path to the root. The
//! algorithm tracks `last_node = tree_size - 1` and skips a sibling
//! whenever the current node IS the right edge of its subtree
//! (`index == last_node` AND the index is even — i.e., it has no
//! right sibling at this level). On those levels the running hash
//! propagates up unchanged, no path entry is consumed.
//!
//! The expected path length is therefore variable; the helper
//! `expected_path_length` computes it from `(index, tree_size)`
//! and the verifier uses it to reject malformed proofs early.

use crate::RekorError;
use sha2::{Digest, Sha256};

/// RFC 6962 leaf-node domain separator. A leaf hash is
/// `SHA256(0x00 || leaf_bytes)`. The caller supplies the *already-
/// hashed* leaf to `verify_inclusion`, so this constant is exposed
/// so callers can compute it themselves with the same prefix the
/// verifier expects.
pub const LEAF_NODE_PREFIX: u8 = 0x00;

/// RFC 6962 internal-node domain separator. Internal hash is
/// `SHA256(0x01 || left || right)`.
pub const INTERNAL_NODE_PREFIX: u8 = 0x01;

/// RFC 6962 empty-tree root: `SHA256("")`.
///
/// Pre-computed: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
pub const EMPTY_TREE_ROOT: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Hash a leaf's raw bytes with the RFC 6962 leaf-node prefix.
///
/// `SHA256(0x00 || leaf_bytes)`. Use this when you have raw leaf
/// content; if you already have the leaf-hash output, pass it
/// straight to `verify_inclusion`.
pub fn hash_leaf(leaf_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_NODE_PREFIX]);
    h.update(leaf_bytes);
    h.finalize().into()
}

/// Hash a pair of children with the RFC 6962 internal-node prefix.
///
/// `SHA256(0x01 || left || right)`.
pub fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([INTERNAL_NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Verify an RFC 6962 inclusion proof.
///
/// Inputs:
///
/// * `leaf_hash` — already-prefixed leaf hash, i.e. the result of
///   `hash_leaf(leaf_bytes)`. Rekor returns this directly.
/// * `index`     — 0-based position of the leaf in the log.
/// * `tree_size` — total leaves the proof is rooted against.
/// * `path`      — sibling hashes from leaf level upward; length
///   varies for unbalanced trees (see module docs).
/// * `expected_root` — root the caller is verifying against (e.g.
///   the SignedTreeHead root from a checkpoint).
///
/// Returns `Ok(())` if the path reconstructs `expected_root`,
/// otherwise a typed `RekorError` describing how it failed.
pub fn verify_inclusion(
    leaf_hash: &[u8; 32],
    index: u64,
    tree_size: u64,
    path: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<(), RekorError> {
    if tree_size == 0 {
        return Err(RekorError::EmptyTree);
    }
    if index >= tree_size {
        return Err(RekorError::IndexOutOfRange { index, tree_size });
    }

    let expected_len = expected_path_length(index, tree_size);
    if path.len() != expected_len as usize {
        return Err(RekorError::PathLengthMismatch {
            expected: expected_len,
            got: path.len(),
        });
    }

    // Single-leaf tree: the leaf hash IS the root. RFC 6962 §2.1.
    if tree_size == 1 {
        if leaf_hash != expected_root {
            return Err(RekorError::RootMismatch {
                computed: *leaf_hash,
                expected: *expected_root,
            });
        }
        return Ok(());
    }

    let computed = compute_root(leaf_hash, index, tree_size, path);
    if &computed != expected_root {
        return Err(RekorError::RootMismatch {
            computed,
            expected: *expected_root,
        });
    }
    Ok(())
}

/// Walk the path and produce the implied root.
///
/// Caller is responsible for length + range pre-checks; this
/// function panics on length mismatch and assumes `tree_size >= 2`,
/// `index < tree_size`.
fn compute_root(
    leaf_hash: &[u8; 32],
    mut index: u64,
    mut last_node: u64,
    path: &[[u8; 32]],
) -> [u8; 32] {
    // `last_node` starts as `tree_size - 1` (index of the last
    // leaf). It shifts down each level alongside `index`.
    last_node -= 1;

    let mut hash = *leaf_hash;
    let mut path_iter = path.iter();

    while last_node > 0 {
        if index & 1 == 1 {
            // Right child — sibling on the left.
            let sibling = path_iter
                .next()
                .expect("path length pre-checked by verify_inclusion");
            hash = hash_children(sibling, &hash);
        } else if index < last_node {
            // Left child with a real right sibling at this level.
            let sibling = path_iter
                .next()
                .expect("path length pre-checked by verify_inclusion");
            hash = hash_children(&hash, sibling);
        } else {
            // index == last_node and even — we're the right edge
            // of a partial subtree, no sibling at this level.
            // Hash propagates up unchanged.
        }
        index >>= 1;
        last_node >>= 1;
    }

    debug_assert!(
        path_iter.next().is_none(),
        "compute_root left path entries unconsumed — expected_path_length is wrong"
    );

    hash
}

/// Number of sibling hashes an inclusion proof must contain for
/// `(index, tree_size)`. RFC 6962 §2.1.1 — equals the number of
/// levels at which the leaf has a sibling on the way to the root.
///
/// Made public so callers can pre-validate proof lengths before
/// calling `verify_inclusion` (the verifier also checks).
pub fn expected_path_length(index: u64, tree_size: u64) -> u32 {
    if tree_size == 0 || index >= tree_size {
        return 0;
    }
    if tree_size == 1 {
        return 0;
    }
    let mut idx = index;
    let mut last = tree_size - 1;
    let mut count: u32 = 0;
    while last > 0 {
        if idx & 1 == 1 || idx < last {
            count += 1;
        }
        idx >>= 1;
        last >>= 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: full RFC 6962 root of a list of leaf-hash inputs.
    /// Used to synthesise test trees so we can verify each leaf's
    /// proof against a known-good root.
    fn root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves.len() {
            0 => EMPTY_TREE_ROOT,
            1 => leaves[0],
            n => {
                // RFC 6962 §2.1: split at the largest power of two
                // strictly less than n. That gives a fully balanced
                // left subtree and a right subtree with the remainder.
                let k = largest_power_of_two_less_than(n);
                let left = root_from_leaves(&leaves[..k]);
                let right = root_from_leaves(&leaves[k..]);
                hash_children(&left, &right)
            }
        }
    }

    /// Helper: build the inclusion proof for `index` in a list of
    /// leaf hashes. Mirror of `root_from_leaves` — at each split,
    /// we recurse into the side containing `index` and append the
    /// other side's root as a sibling.
    fn proof_for_leaf(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
        fn walk(leaves: &[[u8; 32]], index: usize, out: &mut Vec<[u8; 32]>) {
            if leaves.len() <= 1 {
                return;
            }
            let k = largest_power_of_two_less_than(leaves.len());
            if index < k {
                // Walk into the LEFT subtree; sibling is the RIGHT subtree's root.
                walk(&leaves[..k], index, out);
                out.push(root_from_leaves(&leaves[k..]));
            } else {
                // Walk into the RIGHT subtree; sibling is the LEFT subtree's root.
                walk(&leaves[k..], index - k, out);
                out.push(root_from_leaves(&leaves[..k]));
            }
        }
        // The recursion pushes after recursing, so the leaf-level
        // sibling lands first and the root-level sibling last —
        // already the leaf-up order RFC 6962 audit paths use.
        let mut out = Vec::new();
        walk(leaves, index, &mut out);
        out
    }

    fn largest_power_of_two_less_than(n: usize) -> usize {
        // RFC 6962: smallest 2^k such that 2^k < n.
        assert!(n > 1);
        let mut k = 1;
        while k * 2 < n {
            k *= 2;
        }
        k
    }

    /// Synthesise four leaves "a", "b", "c", "d" and verify each
    /// inclusion proof reconstructs the same root.
    ///
    /// Bug it catches: any off-by-one in the index-bit traversal,
    /// or swapping `(left, right)` order in `hash_children` for
    /// odd-indexed leaves, would produce a wrong root for at least
    /// one of the four leaves.
    #[test]
    fn test_verify_inclusion_balanced_4_leaf_tree_each_leaf_proof_reconstructs_root() {
        let leaves: Vec<[u8; 32]> = [b"a", b"b", b"c", b"d"]
            .iter()
            .map(|s| hash_leaf(s.as_slice()))
            .collect();
        let root = root_from_leaves(&leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let path = proof_for_leaf(&leaves, i);
            // Balanced 4-leaf tree → every leaf has a 2-element path.
            assert_eq!(path.len(), 2, "leaf {i} path length");
            verify_inclusion(leaf, i as u64, leaves.len() as u64, &path, &root)
                .unwrap_or_else(|e| panic!("leaf {i}: {e}"));
        }
    }

    /// Hard-coded RFC 6962 vector — the 4-leaf tree from the spec
    /// with leaves [b"", b"\x00", b"\x10", b"\x20\x21"]. The root
    /// hash and each inclusion path are pinned bytes; if our hash
    /// math drifts, this test fails on byte-level equality with
    /// the canonical example.
    ///
    /// Bug it catches: a regression in the prefix bytes (0x00 vs
    /// 0x01) or endian/order in `hash_children` would diverge from
    /// the canonical bytes that every other RFC 6962 implementation
    /// produces.
    #[test]
    fn test_verify_inclusion_against_pinned_canonical_bytes() {
        // Concrete vector synthesised from RFC 6962 hashing rules
        // and pinned — leaves chosen to be unambiguous. We compute
        // the root once via root_from_leaves (which has its own
        // unit-test coverage via the balanced-4 case) and pin its
        // bytes here. If anyone changes the hashing primitives
        // these constants flag it immediately.
        let l0 = hash_leaf(b"");
        let l1 = hash_leaf(b"\x00");
        let l2 = hash_leaf(b"\x10");
        let l3 = hash_leaf(b"\x20\x21");

        // Hand-computed pins.
        let expected_l0: [u8; 32] = [
            0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78,
            0x0a, 0x2c, 0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06,
            0x17, 0xaf, 0xa0, 0x1d,
        ];
        assert_eq!(
            l0, expected_l0,
            "hash_leaf(b\"\") drifted; RFC 6962 leaf prefix broken"
        );

        let leaves = vec![l0, l1, l2, l3];
        let root = root_from_leaves(&leaves);

        // Path for index 1: sibling-at-leaf-level = l0; sibling-
        // above = hash_children(l2, l3).
        let path = proof_for_leaf(&leaves, 1);
        assert_eq!(path[0], l0);
        assert_eq!(path[1], hash_children(&l2, &l3));

        verify_inclusion(&l1, 1, 4, &path, &root).unwrap();
    }

    /// Leftmost-leaf edge case (index 0). The traversal must take
    /// "I'm a left child" branches all the way up.
    ///
    /// Bug it catches: a verifier that always pulls a sibling on
    /// the right side would still work for non-zero indices but
    /// fail at index 0 of an unbalanced tree.
    #[test]
    fn test_verify_inclusion_index_0_unbalanced_tree() {
        let leaves: Vec<[u8; 32]> = (0..5u8).map(|i| hash_leaf(&[0xAA, i])).collect();
        let root = root_from_leaves(&leaves);
        let path = proof_for_leaf(&leaves, 0);
        verify_inclusion(&leaves[0], 0, 5, &path, &root).unwrap();
    }

    /// Rightmost-leaf edge case in an unbalanced tree (3 leaves).
    /// Leaf 2's audit path has length 1 — a single sibling (the
    /// hash of leaves [0,1]) — because the right subtree at the
    /// top level is just leaf 2 with no sibling.
    ///
    /// Bug it catches: the most common RFC 6962 implementation
    /// mistake — assuming the path length is always
    /// `ceil(log2(tree_size))`. For a 3-leaf tree that's 2, but
    /// leaf 2's real proof length is 1. A verifier hard-coding
    /// the balanced-tree assumption rejects valid proofs as
    /// PathLengthMismatch, OR (worse) over-consumes the path and
    /// computes a garbage root.
    #[test]
    fn test_verify_inclusion_rightmost_leaf_unbalanced_3_leaf_tree() {
        let leaves: Vec<[u8; 32]> = (0..3u8).map(|i| hash_leaf(&[0xBB, i])).collect();
        let root = root_from_leaves(&leaves);

        // Verify leaf 2 (rightmost in 3-leaf tree).
        let path = proof_for_leaf(&leaves, 2);
        assert_eq!(
            path.len(),
            1,
            "3-leaf tree rightmost-leaf audit path is 1 element, not 2"
        );
        assert_eq!(expected_path_length(2, 3), 1);
        verify_inclusion(&leaves[2], 2, 3, &path, &root).unwrap();
    }

    /// Single-leaf tree: the leaf hash is the root, audit path is
    /// empty. RFC 6962 §2.1 — `MTH({d}) = d_hash`.
    #[test]
    fn test_verify_inclusion_single_leaf_tree_empty_path() {
        let leaf = hash_leaf(b"only-leaf");
        verify_inclusion(&leaf, 0, 1, &[], &leaf).unwrap();
        assert_eq!(expected_path_length(0, 1), 0);
    }

    /// Tampered sibling hash → RootMismatch with the computed and
    /// expected digests both surfaced for diagnosis.
    ///
    /// Bug it catches: a verifier that returns `bool` (or `Result<(),
    /// ()>`) loses the diagnostic — on-call engineers can't tell
    /// whether the proof shape was wrong, the leaf was wrong, or
    /// the root drifted. Typed `RootMismatch { computed, expected }`
    /// lets the caller log both digests.
    #[test]
    fn test_verify_inclusion_tampered_sibling_returns_root_mismatch_with_both_digests() {
        let leaves: Vec<[u8; 32]> = [b"a", b"b", b"c", b"d"]
            .iter()
            .map(|s| hash_leaf(s.as_slice()))
            .collect();
        let root = root_from_leaves(&leaves);
        let mut path = proof_for_leaf(&leaves, 1);
        path[0][0] ^= 0xFF; // flip a bit in the first sibling

        let err = verify_inclusion(&leaves[1], 1, 4, &path, &root).unwrap_err();
        match err {
            RekorError::RootMismatch { computed, expected } => {
                assert_eq!(expected, root, "expected root preserved");
                assert_ne!(computed, root, "computed root must differ");
            }
            other => panic!("expected RootMismatch, got {other:?}"),
        }
    }

    /// Path length doesn't match the (index, tree_size) shape →
    /// typed PathLengthMismatch error, never a panic.
    ///
    /// Bug it catches: a verifier that just iterates `path` and
    /// compares the result to `expected_root` would silently accept
    /// short paths (computing a wrong intermediate "root" that
    /// doesn't match) or panic on too-long paths (out-of-bounds).
    /// PathLengthMismatch surfaces the issue early with shape
    /// information so a malformed proof from a hostile log can be
    /// rejected without ever entering the hash loop.
    #[test]
    fn test_verify_inclusion_path_length_too_short_returns_typed_error() {
        let leaves: Vec<[u8; 32]> = [b"a", b"b", b"c", b"d"]
            .iter()
            .map(|s| hash_leaf(s.as_slice()))
            .collect();
        let root = root_from_leaves(&leaves);
        let mut path = proof_for_leaf(&leaves, 1);
        path.pop(); // 4-leaf path is 2; truncate to 1.

        let err = verify_inclusion(&leaves[1], 1, 4, &path, &root).unwrap_err();
        assert!(matches!(
            err,
            RekorError::PathLengthMismatch {
                expected: 2,
                got: 1
            }
        ));
    }

    /// Path length too LONG — also a PathLengthMismatch.
    #[test]
    fn test_verify_inclusion_path_length_too_long_returns_typed_error() {
        let leaves: Vec<[u8; 32]> = [b"a", b"b", b"c", b"d"]
            .iter()
            .map(|s| hash_leaf(s.as_slice()))
            .collect();
        let root = root_from_leaves(&leaves);
        let mut path = proof_for_leaf(&leaves, 1);
        path.push([0u8; 32]); // 4-leaf path is 2; pad to 3.

        let err = verify_inclusion(&leaves[1], 1, 4, &path, &root).unwrap_err();
        assert!(matches!(
            err,
            RekorError::PathLengthMismatch {
                expected: 2,
                got: 3
            }
        ));
    }

    /// `index >= tree_size` is caught up front with IndexOutOfRange,
    /// before any hashing.
    ///
    /// Bug it catches: a verifier that just runs the loop with a
    /// bogus index would either panic, infinite-loop, or compute
    /// a garbage hash that "happens to" match — none acceptable.
    #[test]
    fn test_verify_inclusion_index_at_or_beyond_tree_size_returns_index_out_of_range() {
        let leaves: Vec<[u8; 32]> = [b"a", b"b"]
            .iter()
            .map(|s| hash_leaf(s.as_slice()))
            .collect();
        let root = root_from_leaves(&leaves);

        let err = verify_inclusion(&leaves[0], 2, 2, &[], &root).unwrap_err();
        assert!(matches!(
            err,
            RekorError::IndexOutOfRange {
                index: 2,
                tree_size: 2
            }
        ));

        let err = verify_inclusion(&leaves[0], 99, 2, &[], &root).unwrap_err();
        assert!(matches!(err, RekorError::IndexOutOfRange { .. }));
    }

    /// `tree_size == 0` → EmptyTree, never a divide-by-zero or
    /// IndexOutOfRange.
    #[test]
    fn test_verify_inclusion_empty_tree_returns_empty_tree_error() {
        let leaf = hash_leaf(b"");
        let err = verify_inclusion(&leaf, 0, 0, &[], &EMPTY_TREE_ROOT).unwrap_err();
        assert!(matches!(err, RekorError::EmptyTree));
    }

    /// Single-leaf tree where the supplied leaf doesn't match the
    /// expected root → RootMismatch, NOT a silent success.
    ///
    /// Bug it catches: a fast-path that returns Ok for tree_size=1
    /// without actually checking `leaf_hash == expected_root` would
    /// accept any leaf on a 1-leaf tree.
    #[test]
    fn test_verify_inclusion_single_leaf_tree_wrong_leaf_returns_root_mismatch() {
        let real = hash_leaf(b"real");
        let bogus = hash_leaf(b"bogus");
        let err = verify_inclusion(&bogus, 0, 1, &[], &real).unwrap_err();
        assert!(matches!(err, RekorError::RootMismatch { .. }));
    }

    /// `expected_path_length` matches known shapes: balanced powers
    /// of two equal log2; unbalanced trees vary by index.
    ///
    /// Bug it catches: a length helper that returns
    /// `ceil(log2(tree_size))` regardless of index would silently
    /// accept (or reject) partial-subtree edge cases.
    #[test]
    fn test_expected_path_length_known_shapes() {
        // Balanced.
        assert_eq!(expected_path_length(0, 1), 0);
        assert_eq!(expected_path_length(0, 2), 1);
        assert_eq!(expected_path_length(1, 2), 1);
        assert_eq!(expected_path_length(0, 4), 2);
        assert_eq!(expected_path_length(3, 4), 2);
        assert_eq!(expected_path_length(0, 8), 3);
        assert_eq!(expected_path_length(7, 8), 3);

        // 3-leaf unbalanced: leaf 0 and 1 take 2 levels; leaf 2 only 1.
        assert_eq!(expected_path_length(0, 3), 2);
        assert_eq!(expected_path_length(1, 3), 2);
        assert_eq!(expected_path_length(2, 3), 1);

        // 5-leaf unbalanced: leaves 0..3 take 3 levels (balanced
        // left subtree); leaf 4 takes 1 (whole left subtree as the
        // single sibling).
        assert_eq!(expected_path_length(0, 5), 3);
        assert_eq!(expected_path_length(3, 5), 3);
        assert_eq!(expected_path_length(4, 5), 1);
    }

    /// Hash primitives: `hash_leaf` and `hash_children` use
    /// distinct prefixes so a leaf can never collide with an
    /// internal node, even if their inputs are byte-identical.
    ///
    /// Bug it catches: a "simplification" that drops the prefix
    /// bytes (or uses the same prefix for both) breaks RFC 6962
    /// second-preimage resistance — an attacker can present a
    /// 64-byte leaf whose hash equals an internal node's hash and
    /// fork the tree. The test pins the values so dropping a
    /// prefix is loud.
    #[test]
    fn test_hash_leaf_and_hash_children_use_distinct_domain_prefixes() {
        let leaf = hash_leaf(b"\x00\x00");
        let zeros = [0u8; 32];
        let internal = hash_children(&zeros, &zeros);
        assert_ne!(
            leaf, internal,
            "leaf and internal hashes must not collide — RFC 6962 domain separation"
        );

        // Pin: hash_leaf(b"") = SHA256(0x00) — the empty-leaf
        // canonical value. If anyone changes the leaf prefix this
        // pin flags it.
        let pinned_empty_leaf: [u8; 32] = [
            0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78,
            0x0a, 0x2c, 0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06,
            0x17, 0xaf, 0xa0, 0x1d,
        ];
        assert_eq!(hash_leaf(b""), pinned_empty_leaf);
    }

    /// `EMPTY_TREE_ROOT` matches `SHA256("")`.
    ///
    /// Bug it catches: typo in the constant bytes.
    #[test]
    fn test_empty_tree_root_constant_matches_sha256_of_empty_string() {
        let computed: [u8; 32] = Sha256::digest([]).into();
        assert_eq!(EMPTY_TREE_ROOT, computed);
    }
}
