"""Tests for sigstore_root_refresh.py (issue #33). Run: python -m unittest discover scripts

Standard library only. Network is replaced by an in-memory fetcher; the
repo's real asset and embedded.rs are copied into a temp dir, so the
rewrite is exercised against the real file layout.
"""

import datetime as dt
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sigstore_root_refresh as r  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
NOW = dt.datetime(2026, 11, 7, tzinfo=dt.timezone.utc)


def a_root(version: int, expires: str = "2099-01-01T00:00:00Z") -> bytes:
    """A shape-valid root envelope (signatures are not this script's concern)."""
    return json.dumps(
        {"signatures": [], "signed": {"_type": "root", "version": version, "expires": expires}}
    ).encode()


class FakeMirror:
    """In-memory CDN + GitHub. Records the URLs requested."""

    def __init__(self, cdn: dict, github: dict):
        self.cdn, self.github, self.requested = cdn, github, []

    def __call__(self, url: str):
        self.requested.append(url)
        for n, body in self.cdn.items():
            if url == r.CDN_URL.format(n=n):
                return body
        for n, body in self.github.items():
            if url == r.GITHUB_URL.format(n=n):
                return body
        return None  # clean 404


class Workspace(unittest.TestCase):
    """A temp repo root holding copies of the real asset and embedded.rs."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for rel in (r.ASSET_RELPATH, r.EMBEDDED_RS_RELPATH):
            (self.tmp / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(REPO / rel, self.tmp / rel)
        self.asset = self.tmp / r.ASSET_RELPATH
        self.embedded = self.tmp / r.EMBEDDED_RS_RELPATH
        self.old_bytes = self.asset.read_bytes()
        self.old_version = int(json.loads(self.old_bytes)["signed"]["version"])

    def snapshot(self):
        return self.asset.read_bytes(), self.embedded.read_bytes()


class TestDiscoverLatest(unittest.TestCase):
    def test_discover_latest_walks_to_last_version_before_404(self):
        mirror = FakeMirror({5: b"five", 6: b"six", 7: b"seven"}, {})
        n, body = r.discover_latest(5, mirror)
        self.assertEqual((n, body), (7, b"seven"))
        # It must have probed 8 (the 404), not stopped early.
        self.assertIn(r.CDN_URL.format(n=8), mirror.requested)

    def test_discover_latest_start_version_missing_raises(self):
        with self.assertRaises(r.CrossCheckError):
            r.discover_latest(5, FakeMirror({}, {}))

    def test_discover_latest_never_404_is_bounded(self):
        calls = []

        def endless(url):
            calls.append(url)
            return b"x"

        with self.assertRaises(r.CrossCheckError):
            r.discover_latest(1, endless)
        self.assertLessEqual(len(calls), r.MAX_WALK + 1)


class TestCrossCheck(unittest.TestCase):
    def test_cross_check_identical_bytes_returns_sha256(self):
        b = a_root(3)
        self.assertEqual(r.cross_check(3, b, FakeMirror({}, {3: b})), r.sha256_hex(b))

    def test_cross_check_different_bytes_raises_naming_both_hashes(self):
        a, b = a_root(3), a_root(3, "2098-01-01T00:00:00Z")
        with self.assertRaises(r.CrossCheckError) as cm:
            r.cross_check(3, a, FakeMirror({}, {3: b}))
        msg = str(cm.exception)
        self.assertIn(r.sha256_hex(a), msg)
        self.assertIn(r.sha256_hex(b), msg)

    def test_cross_check_github_missing_raises(self):
        with self.assertRaises(r.CrossCheckError):
            r.cross_check(3, a_root(3), FakeMirror({}, {}))


class TestParseRoot(unittest.TestCase):
    def test_parse_root_real_embedded_asset_is_valid(self):
        signed = r.parse_root((REPO / r.ASSET_RELPATH).read_bytes(), "asset")
        self.assertEqual(signed["_type"], "root")

    def test_parse_root_rejects_non_root_type(self):
        bad = json.dumps({"signed": {"_type": "targets", "version": 1, "expires": "2099-01-01T00:00:00Z"}})
        with self.assertRaises(r.CrossCheckError):
            r.parse_root(bad.encode(), "x")

    def test_parse_root_rejects_non_utc_z_expiry(self):
        bad = json.dumps({"signed": {"_type": "root", "version": 1, "expires": "2099-01-01T00:00:00+00:00"}})
        with self.assertRaises(r.CrossCheckError):
            r.parse_root(bad.encode(), "x")

    def test_parse_root_rejects_garbage(self):
        with self.assertRaises(r.CrossCheckError):
            r.parse_root(b"not json", "x")


class TestRewriteEmbeddedRs(unittest.TestCase):
    def setUp(self):
        self.text = (REPO / r.EMBEDDED_RS_RELPATH).read_bytes().decode().replace("\r\n", "\n")

    def test_rewrite_updates_every_constant_and_both_doc_urls(self):
        sha = "ab" * 32
        out = r.rewrite_embedded_rs(self.text, version=99, sha256=sha, fetched_at="2030-01-02T03:04:05Z")
        self.assertIn(f'"{sha}"', out)
        self.assertIn('"https://tuf-repo-cdn.sigstore.dev/99.root.json"', out)
        self.assertIn("SIGSTORE_PRODUCTION_ROOT_VERSION: u32 = 99;", out)
        self.assertIn('FETCHED_AT: &str = "2030-01-02T03:04:05Z"', out)
        self.assertIn("<https://tuf-repo-cdn.sigstore.dev/99.root.json>", out)
        self.assertIn("metadata/root_history/99.root.json>", out)

    def test_rewrite_leaves_everything_else_untouched(self):
        sha = "cd" * 32
        out = r.rewrite_embedded_rs(self.text, version=99, sha256=sha, fetched_at="2030-01-02T03:04:05Z")
        # Only the lines carrying the five values may differ.
        changed = [
            (a, b) for a, b in zip(self.text.splitlines(), out.splitlines()) if a != b
        ]
        self.assertEqual(len(self.text.splitlines()), len(out.splitlines()))
        self.assertLessEqual(len(changed), 6, f"unexpected extra changes: {changed}")

    def test_rewrite_refuses_when_a_constant_is_missing(self):
        broken = self.text.replace("SIGSTORE_PRODUCTION_ROOT_VERSION", "SIGSTORE_PRODUCTION_ROOT_RENAMED")
        with self.assertRaises(r.CrossCheckError):
            r.rewrite_embedded_rs(broken, version=99, sha256="ab" * 32, fetched_at="2030-01-02T03:04:05Z")


class TestRun(Workspace):
    def mirror_at(self, latest: int, latest_bytes: bytes = None) -> FakeMirror:
        """CDN/GitHub serving the embedded version up to `latest`."""
        cdn = {self.old_version: self.old_bytes}
        gh = {self.old_version: self.old_bytes}
        for n in range(self.old_version + 1, latest + 1):
            body = latest_bytes if (n == latest and latest_bytes) else a_root(n)
            cdn[n], gh[n] = body, body
        return FakeMirror(cdn, gh)

    def run_it(self, mirror, **kw):
        kw.setdefault("apply", True)
        kw.setdefault("warn_days", 60)
        return r.run(self.tmp, fetch=mirror, now=NOW, **kw)

    def test_run_up_to_date_changes_nothing(self):
        before = self.snapshot()
        res = self.run_it(self.mirror_at(self.old_version))
        self.assertFalse(res["update_available"])
        self.assertFalse(res["applied"])
        self.assertEqual(self.snapshot(), before, "idempotent: a no-op month must not touch files")

    def test_run_newer_without_apply_reports_but_changes_nothing(self):
        before = self.snapshot()
        res = self.run_it(self.mirror_at(self.old_version + 1), apply=False)
        self.assertTrue(res["update_available"])
        self.assertFalse(res["applied"])
        self.assertEqual(self.snapshot(), before)

    def test_run_newer_with_apply_replaces_asset_and_constants(self):
        new = a_root(self.old_version + 1)
        saved = self.tmp / "old.json"
        res = self.run_it(self.mirror_at(self.old_version + 1, new), old_root_out=saved)
        self.assertTrue(res["applied"])
        self.assertEqual(self.asset.read_bytes(), new)
        self.assertEqual(saved.read_bytes(), self.old_bytes, "previous root must be kept for the chain check")
        rs = self.embedded.read_bytes().decode()
        self.assertIn(f'"{r.sha256_hex(new)}"', rs)
        self.assertIn(f"SIGSTORE_PRODUCTION_ROOT_VERSION: u32 = {self.old_version + 1};", rs)

    def test_run_applied_constants_match_the_new_asset(self):
        """The invariant tuf's own test enforces: the SHA constant is the asset's hash."""
        new = a_root(self.old_version + 1)
        self.run_it(self.mirror_at(self.old_version + 1, new))
        rs = self.embedded.read_bytes().decode()
        self.assertIn(r.sha256_hex(self.asset.read_bytes()), rs)

    def test_run_cdn_github_mismatch_aborts_without_touching_files(self):
        before = self.snapshot()
        n = self.old_version + 1
        m = self.mirror_at(n)
        m.github[n] = a_root(n, "2098-01-01T00:00:00Z")  # same version, different bytes
        with self.assertRaises(r.CrossCheckError):
            self.run_it(m)
        self.assertEqual(self.snapshot(), before)

    def test_run_same_version_but_different_bytes_is_refused(self):
        n = self.old_version
        different = a_root(n, "2098-01-01T00:00:00Z")
        m = FakeMirror({n: different}, {n: different})
        before = self.snapshot()
        with self.assertRaises(r.CrossCheckError):
            self.run_it(m)
        self.assertEqual(self.snapshot(), before)

    def test_run_flags_expiring_soon_when_embedded_expires_inside_window(self):
        soon = (NOW + dt.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Rebuild the embedded asset with a near expiry (shape only).
        near = a_root(self.old_version, soon)
        self.asset.write_bytes(near)
        res = self.run_it(FakeMirror({self.old_version: near}, {self.old_version: near}))
        self.assertTrue(res["expiring_soon"])
        self.assertEqual(res["embedded_days_left"], 10)

    def test_run_not_expiring_soon_when_far_in_future(self):
        res = self.run_it(self.mirror_at(self.old_version))
        self.assertFalse(res["expiring_soon"])

    def test_run_preserves_crlf_line_endings_of_embedded_rs(self):
        text = self.embedded.read_bytes().decode().replace("\r\n", "\n").replace("\n", "\r\n")
        self.embedded.write_bytes(text.encode())
        self.run_it(self.mirror_at(self.old_version + 1))
        out = self.embedded.read_bytes()
        self.assertIn(b"\r\n", out)
        self.assertNotIn(b"\n", out.replace(b"\r\n", b""), "mixed line endings introduced")


class TestPrBody(unittest.TestCase):
    def test_pr_body_carries_both_hashes_and_versions(self):
        res = {
            "embedded_version": 16, "embedded_expires": "2027-04-22T19:27:31Z",
            "latest_version": 17, "latest_sha256": "ab" * 32,
        }
        body = r.render_pr_body(res, "cd" * 32)
        for needle in ("v16", "v17", "ab" * 32, "cd" * 32, "CDN", "root-signing"):
            self.assertIn(needle, body)


if __name__ == "__main__":
    unittest.main()
