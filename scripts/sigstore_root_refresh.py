#!/usr/bin/env python3
"""Detect, cross-check and (optionally) apply a Sigstore production TUF root rotation.

Used by `.github/workflows/sigstore_root_watch.yml` (issue #33). Standard
library only, so a stock runner needs nothing installed.

What it does
------------
1. Reads the embedded root (`tuf/assets/sigstore_prod.root.json`) and finds
   the newest root on the Sigstore CDN by walking `<N>.root.json` upward from
   the embedded version until a 404.
2. Cross-checks the newest root's bytes against the `sigstore/root-signing`
   GitHub repository (`metadata/root_history/<N>.root.json`). The two MUST be
   byte-identical; a mismatch is a hard failure (exit 2), never a refresh.
3. If nothing newer exists: does nothing (idempotent) and reports how long
   the embedded root has left.
4. With `--apply` and a newer root: replaces the asset and updates the
   constants in `tuf/src/embedded.rs`.

What it deliberately does NOT do
--------------------------------
It does not verify the TUF signature chain itself. The workflow does that by
running the real client (`live_sigstore` test) with the OLD embedded root as
bootstrap, which walks old -> new through `TufClient::fetch_root`. Keeping the
signature logic in one place (the Rust client) avoids a second, drifting
implementation.

Exit codes: 0 ok (up to date, or refreshed), 2 cross-check failed,
3 network/IO failure, 4 invalid input.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Optional

CDN_URL = "https://tuf-repo-cdn.sigstore.dev/{n}.root.json"
GITHUB_URL = (
    "https://raw.githubusercontent.com/sigstore/root-signing/main/"
    "metadata/root_history/{n}.root.json"
)

ASSET_RELPATH = Path("tuf/assets/sigstore_prod.root.json")
EMBEDDED_RS_RELPATH = Path("tuf/src/embedded.rs")

# Upper bound on the upward walk. Sigstore is at v16 after years; 1000 is far
# beyond any plausible rotation count and keeps a misbehaving mirror (one that
# never 404s) from looping forever.
MAX_WALK = 1000
HTTP_TIMEOUT_SECS = 30
HTTP_ATTEMPTS = 3  # bounded retries for transient failures

EXIT_OK = 0
EXIT_CROSSCHECK = 2
EXIT_NETWORK = 3
EXIT_INPUT = 4


class CrossCheckError(Exception):
    """CDN and GitHub disagree about a root, or a root is malformed."""


class NetworkError(Exception):
    """A fetch failed for a reason other than a clean 404."""


Fetcher = Callable[[str], Optional[bytes]]
"""Returns the body, or None for a clean 404. Raises NetworkError otherwise."""


def http_fetch(url: str) -> Optional[bytes]:
    """GET `url`. None on 404; NetworkError on anything else that fails."""
    last: Optional[Exception] = None
    for attempt in range(HTTP_ATTEMPTS):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "justsign-root-watch"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECS) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            last = e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
        time.sleep(2 * (attempt + 1))
    raise NetworkError(f"GET {url} failed after {HTTP_ATTEMPTS} attempts: {last}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_root(data: bytes, what: str) -> dict:
    """Parse a root envelope and return its `signed` object, validating shape."""
    try:
        doc = json.loads(data)
        signed = doc["signed"]
        if signed["_type"] != "root":
            raise ValueError(f"_type is {signed['_type']!r}, not 'root'")
        int(signed["version"])
        parse_expires(signed["expires"])
    except (ValueError, KeyError, TypeError) as e:
        raise CrossCheckError(f"{what} is not a well-formed TUF root: {e}") from e
    return signed


def parse_expires(value: str) -> dt.datetime:
    """Parse an RFC 3339 UTC-Z timestamp (TUF's only form)."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ValueError(f"expires {value!r} is not RFC 3339 UTC-Z")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def discover_latest(start_version: int, fetch: Fetcher) -> tuple[int, bytes]:
    """Walk `<N>.root.json` upward from `start_version`; return (latest N, bytes).

    `start_version` must exist on the CDN (it is the embedded root); a 404
    there means the mirror and our asset disagree and is an error.
    """
    latest_n = start_version
    latest_bytes = fetch(CDN_URL.format(n=start_version))
    if latest_bytes is None:
        raise CrossCheckError(
            f"CDN has no {start_version}.root.json although it is the embedded version"
        )
    for n in range(start_version + 1, start_version + 1 + MAX_WALK):
        body = fetch(CDN_URL.format(n=n))
        if body is None:
            return latest_n, latest_bytes
        latest_n, latest_bytes = n, body
    raise CrossCheckError(f"walked {MAX_WALK} versions without a 404; refusing to continue")


def cross_check(n: int, cdn_bytes: bytes, fetch: Fetcher) -> str:
    """Require the GitHub copy of root `n` to be byte-identical; return the SHA-256."""
    gh_bytes = fetch(GITHUB_URL.format(n=n))
    if gh_bytes is None:
        raise CrossCheckError(f"GitHub root-signing repo has no root_history/{n}.root.json")
    cdn_sha, gh_sha = sha256_hex(cdn_bytes), sha256_hex(gh_bytes)
    if cdn_sha != gh_sha:
        raise CrossCheckError(
            f"root v{n} differs between sources: CDN sha256={cdn_sha} GitHub sha256={gh_sha}"
        )
    return cdn_sha


def rewrite_embedded_rs(
    text: str, *, version: int, sha256: str, fetched_at: str
) -> str:
    """Update the provenance doc URLs and the four constants in embedded.rs.

    Each substitution must match exactly once (docs: the CDN URL appears in
    one doc comment, the history URL in one), or the file has drifted from
    what this script understands and we refuse rather than half-update.
    """

    def sub_once(pattern: str, repl: str, s: str, label: str) -> str:
        new, count = re.subn(pattern, repl, s)
        if count != 1:
            raise CrossCheckError(
                f"embedded.rs: expected exactly 1 match for {label}, found {count}; "
                "the file layout changed -- update this script"
            )
        return new

    text = sub_once(
        r"(https://tuf-repo-cdn\.sigstore\.dev/)\d+(\.root\.json>)",
        rf"\g<1>{version}\g<2>",
        text,
        "provenance CDN URL (doc comment)",
    )
    text = sub_once(
        r"(metadata/root_history/)\d+(\.root\.json>)",
        rf"\g<1>{version}\g<2>",
        text,
        "provenance history URL (doc comment)",
    )
    text = sub_once(
        r'(pub const SIGSTORE_PRODUCTION_ROOT_SHA256: &str =\s*")[0-9a-f]{64}(")',
        rf"\g<1>{sha256}\g<2>",
        text,
        "SIGSTORE_PRODUCTION_ROOT_SHA256",
    )
    text = sub_once(
        r'(pub const SIGSTORE_PRODUCTION_ROOT_SOURCE: &str =\s*"https://tuf-repo-cdn\.sigstore\.dev/)\d+(\.root\.json")',
        rf"\g<1>{version}\g<2>",
        text,
        "SIGSTORE_PRODUCTION_ROOT_SOURCE",
    )
    text = sub_once(
        r'(pub const SIGSTORE_PRODUCTION_ROOT_FETCHED_AT: &str = ")[^"]*(")',
        rf"\g<1>{fetched_at}\g<2>",
        text,
        "SIGSTORE_PRODUCTION_ROOT_FETCHED_AT",
    )
    text = sub_once(
        r"(pub const SIGSTORE_PRODUCTION_ROOT_VERSION: u32 = )\d+(;)",
        rf"\g<1>{version}\g<2>",
        text,
        "SIGSTORE_PRODUCTION_ROOT_VERSION",
    )
    return text


def utc_now_iso(now: Optional[dt.datetime] = None) -> str:
    now = now or dt.datetime.now(dt.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def read_text_preserving_newlines(path: Path) -> tuple[str, str]:
    """Read UTF-8 text, returning (LF-normalised text, original newline style)."""
    raw = path.read_bytes().decode("utf-8")
    newline = "\r\n" if "\r\n" in raw else "\n"
    return raw.replace("\r\n", "\n"), newline


def write_text_with_newlines(path: Path, text: str, newline: str) -> None:
    path.write_bytes(text.replace("\n", newline).encode("utf-8"))


def run(
    repo_root: Path,
    *,
    apply: bool,
    warn_days: int,
    fetch: Fetcher,
    now: Optional[dt.datetime] = None,
    old_root_out: Optional[Path] = None,
) -> dict:
    """Core logic. Returns a result dict; raises CrossCheckError / NetworkError."""
    now = now or dt.datetime.now(dt.timezone.utc)
    asset_path = repo_root / ASSET_RELPATH
    embedded_rs_path = repo_root / EMBEDDED_RS_RELPATH

    old_bytes = asset_path.read_bytes()
    old_signed = parse_root(old_bytes, str(ASSET_RELPATH))
    old_version = int(old_signed["version"])
    old_expires = parse_expires(old_signed["expires"])
    days_left = (old_expires - now).days

    latest_n, latest_bytes = discover_latest(old_version, fetch)
    cdn_sha = cross_check(latest_n, latest_bytes, fetch)
    parse_root(latest_bytes, f"CDN {latest_n}.root.json")

    result = {
        "embedded_version": old_version,
        "embedded_expires": old_signed["expires"],
        "embedded_days_left": days_left,
        "latest_version": latest_n,
        "latest_sha256": cdn_sha,
        "update_available": latest_n > old_version,
        "expiring_soon": days_left < warn_days,
        "applied": False,
    }

    # discover_latest starts at the embedded version (and errors if the CDN
    # lacks it), so latest_n >= old_version always holds here.
    if latest_n == old_version:
        if sha256_hex(old_bytes) != cdn_sha:
            raise CrossCheckError(
                f"embedded v{old_version} differs from upstream v{old_version} "
                f"(embedded sha256={sha256_hex(old_bytes)}, upstream sha256={cdn_sha})"
            )
        return result

    if apply:
        if old_root_out is not None:
            old_root_out.write_bytes(old_bytes)
        asset_path.write_bytes(latest_bytes)
        text, newline = read_text_preserving_newlines(embedded_rs_path)
        new_text = rewrite_embedded_rs(
            text, version=latest_n, sha256=cdn_sha, fetched_at=utc_now_iso(now)
        )
        write_text_with_newlines(embedded_rs_path, new_text, newline)
        result["applied"] = True
    return result


def render_pr_body(result: dict, old_sha: str) -> str:
    """Markdown PR body carrying the evidence a reviewer needs (issue #33 AC)."""
    return f"""\
## Refresh bundled Sigstore production TUF root: v{result['embedded_version']} -> v{result['latest_version']}

Opened by the `sigstore_root_watch` workflow. Review the evidence below, then merge.

### Cross-check (CDN vs GitHub)

| Source | URL | SHA-256 |
|---|---|---|
| Sigstore CDN | `https://tuf-repo-cdn.sigstore.dev/{result['latest_version']}.root.json` | `{result['latest_sha256']}` |
| sigstore/root-signing | `.../metadata/root_history/{result['latest_version']}.root.json` | `{result['latest_sha256']}` |

The two copies are byte-identical (the workflow aborts otherwise).

### Versions

- Previously embedded: v{result['embedded_version']} (expires `{result['embedded_expires']}`, sha256 `{old_sha}`)
- New: v{result['latest_version']}

### Verification run by the workflow before opening this PR

- `cargo build --workspace` (build-time integrity + expiry gate in `tuf/build.rs`)
- `cargo test -p swe_justsign_tuf` (embedded sha / version / self-signature tests)
- `live_sigstore` with the **previous embedded root as bootstrap**, i.e. the real
  client walked the signature chain v{result['embedded_version']} -> v{result['latest_version']}
  against the live Sigstore mirror

### Note

PRs opened with the default `GITHUB_TOKEN` do not trigger other workflows. Push an empty
commit or re-run CI on this branch so the normal checks run before merging.
"""


def write_github_output(path: Path, result: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        for key, value in result.items():
            f.write(f"{key}={str(value).lower() if isinstance(value, bool) else value}\n")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--repo-root", type=Path, default=Path("."))
    ap.add_argument("--apply", action="store_true", help="rewrite the asset and embedded.rs when newer")
    ap.add_argument("--warn-days", type=int, default=60, help="flag expiry within this many days")
    ap.add_argument("--github-output", type=Path, help="append key=value results (GITHUB_OUTPUT)")
    ap.add_argument("--body-file", type=Path, help="write the PR body here when an update is applied")
    ap.add_argument("--old-root-out", type=Path, help="save the previous asset here before replacing it")
    args = ap.parse_args(argv)

    try:
        old_sha = sha256_hex((args.repo_root / ASSET_RELPATH).read_bytes())
        result = run(
            args.repo_root,
            apply=args.apply,
            warn_days=args.warn_days,
            fetch=http_fetch,
            old_root_out=args.old_root_out,
        )
    except CrossCheckError as e:
        print(f"::error::cross-check failed: {e}", file=sys.stderr)
        return EXIT_CROSSCHECK
    except NetworkError as e:
        print(f"::error::network failure: {e}", file=sys.stderr)
        return EXIT_NETWORK
    except (OSError, ValueError) as e:
        print(f"::error::invalid input: {e}", file=sys.stderr)
        return EXIT_INPUT

    print(json.dumps(result, indent=2))
    if args.github_output:
        write_github_output(args.github_output, result)
    if result["applied"] and args.body_file:
        args.body_file.write_text(render_pr_body(result, old_sha), encoding="utf-8")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
