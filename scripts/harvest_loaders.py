#!/usr/bin/env python3
"""
Firehose loader harvester for bulk community sources.

Complements download_temblast_loaders.py. Temblast (https://www.temblast.com/ref/loaders.htm)
is a curated catalog with per-file signer/hash metadata, and only indexes six upstream repos.
This script harvests whole sources instead of a catalog, in four flavours:

  --repo / --org   git repos, cloned shallow (thantoeaungat/firehose, programmer-collection/*)
  --archive        zip/tar dumps that live outside git
  --page           plain HTML indexes that link loaders directly

Temblast itself is folded in as a metadata overlay rather than a second download pipeline:
its catalog supplies the upstream repo list (discovered from the row URLs, not hardcoded),
a signer per known file, and the 12 known-bad loaders to drop. Rows are matched on the
first 16 hex chars of the MD5, because that is all Temblast publishes.

Sources that Temblast does not cover ship no manifest at all, so those rows carry an empty
signer and `go-unbrick library import-loaders` falls back to the image's own OEM_ID.
"""

import argparse
import collections
import csv
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.parse
import zipfile
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path

DEFAULT_REPOS = [
    "thantoeaungat/firehose",
    # Temblast indexes this one (site O), so the cross-dedupe reduces it to the delta its
    # crawl missed.
    "OneLabsTools/Programmers",
    "zenlty/Qualcomm-Firehose",
    "zenlty/firehose_generalmobile",
    # Temblast site A; kept so its post-crawl additions land.
    "Alephgsm/SAMSUNG-EDL-Loaders",
    # Found via `gh search repos`; none are forks, so the overlap is real duplication
    # rather than a shared history, and the MD5 dedupe sorts it out.
    "CE1CECL/EDL-Loaders",
    "aaronstarstaff/edl-loaders",
    "se7enf98/Xperia-Loaders",
    # Found by code-searching text sidecars (.mbn.der.info, rawprogram0.xml) -- GitHub does
    # not index the binaries themselves, so `--match path` is what surfaces these.
    "openpst/assets",
    "ele7enxxh/msm8909w-law-2-0_amss_standard_oem",
]

# HTML indexes that link loader files. Walked recursively, so an autoindex root is enough.
DEFAULT_PAGES = [
    "https://edl.bananahackers.net/",
    # h5ai autoindex; the only non-GitHub source in the Temblast catalog.
    "https://archive.diablosat.cc/firmwares/amt-dumps/FirehoseLoaders/",
]

# Bounds on an index walk: be polite, and never wander into an unbounded tree.
MAX_INDEX_DIRS = 64
INDEX_DELAY = 0.3

TEMBLAST_URL = "https://www.temblast.com/ref/loaders.htm"

# Expanded at runtime so new vendor repos are picked up without editing this list.
DEFAULT_ORGS = ["programmer-collection"]

# Community dumps that live outside git. Disroot shares 303 to a DAV endpoint, so the
# fetcher has to follow redirects.
DEFAULT_ARCHIVES = [
    # loaders-8909-2019-07-18.zip -- MSM8909 collection
    "https://cloud.disroot.org/s/HzxB6YM2wRFPpWT/download",
]

LOADER_EXTS = {".elf", ".mbn", ".bin", ".melf", ".hex"}

ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz"}
MAX_NEST_DEPTH = 3

# Drop archives here and they are harvested without any flag.
FOUND_DIR = "found"

# Extension alone is unreliable: these repos ship loaders with no extension and READMEs
# named .bin.
ELF_MAGIC = b"\x7fELF"

# Qualcomm SBL/MBN header codeword pair. Files carrying it have the 80-byte header
# (image_id, image_src, image_dest_ptr, image_size, code_size, sig_ptr, cert_ptr).
MBN_MAGIC = b"\xd1\xdc\x4b\x84\x34\x10\xd7\x73"

# A signed loader lands around 5.5 bits/byte. Anything at ~8.0 is encrypted or compressed,
# not an image any parser can read -- these repos carry a lot of it under loader filenames.
OPAQUE_ENTROPY = 7.9


def sanitize(name):
    return re.sub(r'[\\/:*?"<>|]', "_", name).strip() or "unknown"


def expand_org(org):
    """Every non-empty repo in a GitHub org, via gh. Empty on failure -- a missing token
    should cost us that org's repos, not the whole run."""
    cmd = ["gh", "api", f"orgs/{org}/repos?per_page=100", "--paginate",
           "--jq", ".[] | select(.size > 0) | .full_name"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"  [warning] could not enumerate org {org}: {res.stderr.strip()}", file=sys.stderr)
        return []
    return [line.strip() for line in res.stdout.splitlines() if line.strip()]


def clone_repo(repo, cache_dir, dry_run=False, refresh=False):
    target = cache_dir / repo.replace("/", "__")
    if target.exists() and (target / ".git").exists():
        if not refresh:
            print(f"  [cache] {repo} -> {target}")
            return target
        print(f"  [refresh] {repo}")
        if not dry_run:
            subprocess.run(["git", "-C", str(target), "fetch", "--depth", "1", "origin"], check=False)
            subprocess.run(["git", "-C", str(target), "reset", "--hard", "FETCH_HEAD"], check=False)
        return target

    cmd = ["gh", "repo", "clone", repo, str(target), "--", "--depth", "1"]
    print(f"  [gh clone] {repo}")
    if dry_run:
        return target
    cache_dir.mkdir(parents=True, exist_ok=True)
    if subprocess.run(cmd).returncode != 0:
        print("  [warning] gh repo clone failed, falling back to git clone", file=sys.stderr)
        git_cmd = ["git", "clone", "--depth", "1", f"https://github.com/{repo}.git", str(target)]
        if subprocess.run(git_cmd).returncode != 0:
            print(f"  [error] failed to clone {repo}", file=sys.stderr)
            return None
    return target


def looks_like_loader(path, min_size, max_size):
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size < min_size or size > max_size:
        return False
    if path.suffix.lower() in LOADER_EXTS:
        return True
    # Extensionless blobs: accept only on ELF magic.
    if path.suffix == "":
        try:
            with open(path, "rb") as f:
                return f.read(4) == ELF_MAGIC
        except OSError:
            return False
    return False


def hash_file(path):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def shannon_entropy(data):
    if not data:
        return 0.0
    freq = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def repair_magic(head):
    """Sellers neuter loaders by flipping one byte of the magic: \\x7fELE for \\x7fELF,
    d1dc4b87 for the MBN codeword. Everything after the magic still validates, so the file
    is a working loader one byte away. Returns the corrected first byte(s), or None."""
    if head[:3] == b"\x7fEL" and head[3] != 0x46:
        # Only when the rest of e_ident is a sane ELF: class 1/2, data 1/2, version 1.
        if head[4] in (1, 2) and head[5] in (1, 2) and head[6] == 1:
            return 3, 0x46
    if head[:3] == b"\xd1\xdcK" and head[3] != 0x84 and head[4:8] == b"\x34\x10\xd7\x73":
        return 3, 0x84
    return None


def classify_image(path):
    """ELF32/ELF64, MBN, OPAQUE (encrypted or compressed), or UNKNOWN.

    Classifying by 'not ELF' is what produced a manifest full of mislabelled MBNs: in
    thantoeaungat/firehose only 3 of 113 such files were real MBNs and the other 110 were
    opaque blobs, which no amount of MBN parsing would have recovered.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(8)
            fix = repair_magic(head)
            if fix:
                head = head[:fix[0]] + bytes([fix[1]]) + head[fix[0] + 1:]
            if head[:4] == ELF_MAGIC:
                return "ELF64" if head[4] == 2 else "ELF32"
            if head == MBN_MAGIC:
                return "MBN"
            f.seek(0)
            body = f.read(1 << 20)
    except OSError:
        return ""
    return "OPAQUE" if shannon_entropy(body) > OPAQUE_ENTROPY else "UNKNOWN"


def fetch_archive(spec, cache_dir, dry_run=False, refresh=False, password=None):
    """Download (if a URL) and extract a loader archive; returns its extraction root."""
    archives = cache_dir / "archives"
    if spec.startswith("http://") or spec.startswith("https://"):
        local = archives / (re.sub(r"[^A-Za-z0-9._-]", "_", spec.rsplit("/", 2)[-2]) + ".archive")
        if not local.exists() or refresh:
            print(f"  [curl] {spec}")
            if not dry_run:
                archives.mkdir(parents=True, exist_ok=True)
                # -J alone would let the server name the file; keep our own stable cache name
                # but follow redirects, since these shares 303 to a DAV endpoint.
                if subprocess.run(["curl", "-fsSL", spec, "-o", str(local)]).returncode != 0:
                    print(f"  [error] failed to download {spec}", file=sys.stderr)
                    return None
        else:
            print(f"  [cache] {spec}")
    else:
        local = Path(spec).resolve()
        if not local.exists():
            print(f"  [error] no such archive: {spec}", file=sys.stderr)
            return None

    target = archives / (local.stem + ".d")
    if target.exists() and not refresh:
        print(f"  [cache] extracted at {target}")
        return target
    if dry_run:
        return target

    # Extract into a staging dir and promote it to the final .d only on success,
    # so a .d's existence guarantees a complete extraction. A crashed or partial
    # run leaves .d.partial (ignored by the cache check above), never a
    # half-populated .d that the next run would silently reuse.
    staging = archives / (local.stem + ".d.partial")
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    if not extract_any(local, staging, password):
        shutil.rmtree(staging, ignore_errors=True)
        return None
    # These dumps nest: gadgetsdr.com.rar is 237 files, 100 of which are themselves zips.
    for depth in range(MAX_NEST_DEPTH):
        nested = [q for q in staging.rglob("*")
                  if q.is_file() and q.suffix.lower() in ARCHIVE_EXTS]
        if not nested:
            break
        print(f"  [nested] depth {depth + 1}: {len(nested)} archive(s)")
        for q in nested:
            sub = q.with_suffix(q.suffix + ".d")
            sub.mkdir(parents=True, exist_ok=True)
            if extract_any(q, sub, password):
                q.unlink(missing_ok=True)  # drop the inner archive only once its contents are out
            else:
                # Keep the archive rather than losing it; a later run or manual
                # step can recover it. The loader scan ignores .zip/.rar anyway.
                print(f"  [warning] kept {q.name}: nested extraction failed", file=sys.stderr)
                shutil.rmtree(sub, ignore_errors=True)
    if refresh:
        shutil.rmtree(target, ignore_errors=True)
    os.replace(staging, target)
    return target


def extract_any(local, target, password=None):
    """Extract one archive into target. zip/tar natively, everything else via unar.

    Dispatch on the leading magic bytes, not zipfile.is_zipfile / tarfile.is_tarfile:
    those scan the whole file and false-positive on a container that embeds a zip or tar
    (e.g. a RAR full of .zip loaders reads as a zip and extracts one stray entry).
    """
    try:
        with open(local, "rb") as f:
            head = f.read(8)
    except OSError as e:
        print(f"  [error] reading {local.name}: {e}", file=sys.stderr)
        return False

    zip_magic = head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    # unar owns the container formats libarchive/zipfile mishandle; check these before tar
    # so a rar/7z is never mistaken for a tar by content scanning.
    unar_magic = head[:6] in (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01") or head[:6] == b"7z\xbc\xaf\x27\x1c"
    tar_magic = head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00"

    try:
        if zip_magic:
            with zipfile.ZipFile(local) as z:
                for member in z.infolist():
                    # Reject absolute paths and traversal before extracting.
                    name = member.filename
                    if name.startswith("/") or ".." in Path(name).parts:
                        print(f"  [skip] unsafe archive member: {name}", file=sys.stderr)
                        continue
                    z.extract(member, target, pwd=password.encode() if password else None)
            return True
        if not unar_magic and (tar_magic or tarfile.is_tarfile(local)):
            with tarfile.open(local) as t:
                t.extractall(target, filter="data")
            return True
    except Exception as e:
        print(f"  [error] extracting {local.name}: {e}", file=sys.stderr)
        return False

    # RAR5 and friends: 7-Zip cannot decode method v6, libarchive rejects the block
    # headers, so unar is the one that works.
    if shutil.which("unar") is None:
        print(f"  [error] {local.name} needs 'unar' (brew install unar)", file=sys.stderr)
        return False
    cmd = ["unar", "-q", "-D", "-o", str(target)]
    if password:
        cmd += ["-p", password]
    cmd.append(str(local))
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0 or "wrong password" in (res.stdout + res.stderr):
        print(f"  [error] unar failed on {local.name}: {res.stdout.strip()[:120]}", file=sys.stderr)
        return False
    return True


def fetch_page(url, cache_dir, dry_run=False, refresh=False):
    """Download every loader-looking file linked from an HTML index, recursing into
    subdirectory links that stay under `url`.

    Autoindexes (diablosat runs h5ai) nest, and walking them beats a hardcoded file list:
    the walk found Oplus/ and Oplus_Exploit/, which Temblast's own crawl had missed.
    """
    root = cache_dir / "pages" / re.sub(r"[^A-Za-z0-9._-]", "_", url)
    if root.exists() and not refresh:
        print(f"  [cache] {url}")
        return root
    if dry_run:
        return root
    root.mkdir(parents=True, exist_ok=True)

    seen, queue, found = set(), [url], 0
    while queue and len(seen) < MAX_INDEX_DIRS:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        res = subprocess.run(["curl", "-fsSL", "--max-time", "60", current], capture_output=True)
        if res.returncode != 0:
            print(f"  [warning] failed index {current}", file=sys.stderr)
            continue
        for raw in re.findall(rb'href="([^"]+)"', res.stdout):
            href = raw.decode("utf-8", "ignore")
            if href in ("..", ".") or href.startswith("//"):
                continue
            full = urllib.parse.urljoin(current, href)
            if not full.startswith(url):
                continue
            if full.endswith("/"):
                if full not in seen:
                    queue.append(full)
                continue
            if Path(urllib.parse.urlparse(full).path).suffix.lower() not in LOADER_EXTS:
                continue
            # Mirror the remote layout so same-named files in sibling dirs don't collide.
            rel = urllib.parse.unquote(full[len(url):]).lstrip("/")
            target = root / rel
            if target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if subprocess.run(["curl", "-fsSL", full, "-o", str(target)]).returncode != 0:
                print(f"  [warning] failed {full}", file=sys.stderr)
                target.unlink(missing_ok=True)
            else:
                found += 1
        time.sleep(INDEX_DELAY)
    print(f"  [page] {url}: walked {len(seen)} dir(s), fetched {found} loader(s)")
    return root


class TemblastHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_table = False
        self.in_tr = False
        self.in_cell = False
        self.is_header = False
        self.cell_data = []
        self.cell_attrs = {}
        self.cell_links = []
        self.rows = []
        self.current_row_cells = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "table":
            self.in_table = True
        elif tag == "tr" and self.in_table:
            self.in_tr = True
            self.current_row_cells = []
        elif tag in ("td", "th") and self.in_tr:
            self.in_cell = True
            self.is_header = (tag == "th")
            self.cell_data = []
            self.cell_attrs = attrs_dict
            self.cell_links = []
        elif tag == "a" and self.in_cell:
            if "href" in attrs_dict:
                self.cell_links.append(attrs_dict["href"])

    def handle_data(self, data):
        if self.in_cell:
            self.cell_data.append(data)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.in_cell:
            text = "".join(self.cell_data).strip()
            rowspan = int(self.cell_attrs.get("rowspan", 1))
            colspan = int(self.cell_attrs.get("colspan", 1))
            css_class = self.cell_attrs.get("class", "")
            self.current_row_cells.append({
                "text": text,
                "rowspan": rowspan,
                "colspan": colspan,
                "class": css_class,
                "links": list(self.cell_links),
                "is_header": self.is_header
            })
            self.in_cell = False
        elif tag == "tr" and self.in_tr:
            if self.current_row_cells:
                self.rows.append(self.current_row_cells)
            self.in_tr = False
        elif tag == "table" and self.in_table:
            self.in_table = False

def parse_html_content(html_text):
    html_start = html_text.find("<?xml")
    if html_start == -1:
        html_start = html_text.find("<html")
    if html_start != -1:
        html_text = html_text[html_start:]

    parser = TemblastHTMLParser()
    parser.feed(html_text)

    if not parser.rows:
        return []

    # Map onto 2D matrix resolving rowspan & colspan
    occupied = {}
    for r_idx, row_cells in enumerate(parser.rows[1:]): # skip header row
        c_idx = 0
        while (r_idx, c_idx) in occupied:
            c_idx += 1
        for cell in row_cells:
            while (r_idx, c_idx) in occupied:
                c_idx += 1
            rs = cell["rowspan"]
            cs = cell["colspan"]
            for dr in range(rs):
                for dc in range(cs):
                    occupied[(r_idx + dr, c_idx + dc)] = cell
            c_idx += cs

    num_data_rows = len(parser.rows) - 1
    entries = []
    for r in range(num_data_rows):
        row_data = [occupied.get((r, c), None) for c in range(8)]
        signer = row_data[0]["text"] if row_data[0] else ""
        sha256 = row_data[1]["text"] if row_data[1] else ""
        sha384 = row_data[2]["text"] if row_data[2] else ""
        file_md5 = row_data[3]["text"] if row_data[3] else ""
        loader_type = row_data[4]["text"] if row_data[4] else ""
        ver = row_data[5]["text"] if row_data[5] else ""
        site = row_data[6]["text"] if row_data[6] else ""
        path_cell = row_data[7]
        path = path_cell["text"] if path_cell else ""
        url = path_cell["links"][0] if (path_cell and path_cell["links"]) else ""
        is_bad = any("bad" in (row_data[c].get("class", "") if row_data[c] else "") for c in range(8))

        repo_owner_name = ""
        repo_file_path = ""
        if "github.com/" in url:
            sub = url.split("github.com/")[1]
            parts = sub.split("/")
            if len(parts) >= 5 and parts[2] == "blob":
                repo_owner_name = f"{parts[0]}/{parts[1]}"
                repo_file_path = urllib.parse.unquote("/".join(parts[4:]))

        entries.append({
            "row": r + 1,
            "signer": signer,
            "sha256": sha256,
            "sha384": sha384,
            "file_md5": file_md5,
            "type": loader_type,
            "ver": ver,
            "site": site,
            "path": path,
            "url": url,
            "is_bad": is_bad,
            "repo": repo_owner_name,
            "repo_path": repo_file_path
        })

    return entries


def refresh_catalog(catalog_path):
    """Re-scrape the Temblast table into catalog_path. Nothing else regenerates it."""
    print(f"Fetching {TEMBLAST_URL} ...")
    res = subprocess.run(["curl", "-fsSL", "--max-time", "60", TEMBLAST_URL], capture_output=True)
    if res.returncode != 0:
        print("  [error] could not fetch the Temblast page", file=sys.stderr)
        return False
    entries = parse_html_content(res.stdout.decode("iso-8859-1", errors="ignore"))
    if len(entries) < 1000:
        # The live table has thousands of rows; a short parse means the markup moved.
        print(f"  [error] parsed only {len(entries)} rows, refusing to overwrite the catalog",
              file=sys.stderr)
        return False
    Path(catalog_path).write_text(json.dumps(entries, indent=2), encoding="utf-8")
    print(f"  wrote {len(entries)} entries to {catalog_path}")
    return True


def load_temblast(catalog_path):
    """Temblast as metadata, not as a download list.

    Returns (meta, repos). `meta` maps a 16-hex MD5 prefix -- Temblast truncates its hashes
    -- to the row's signer/type/bad flag. `repos` is the set of GitHub repos its rows point
    at, so the upstream list is discovered rather than hardcoded.

    The signer is the point: 2639 of 2723 rows name one, and without it import-loaders falls
    back to OEM_ID, which has no mapping for e.g. 0073 and files every Vivo loader under
    "qualcomm".
    """
    meta, repos = {}, set()
    if not catalog_path or not Path(catalog_path).exists():
        return meta, repos
    with open(catalog_path, "r", encoding="utf-8") as f:
        entries = json.load(f)
    for e in entries:
        md5 = (e.get("file_md5") or "").lower()
        if md5:
            # First row wins; duplicates across sites carry the same signer.
            meta.setdefault(md5, {
                "signer": e.get("signer", ""),
                "type": e.get("type", ""),
                "is_bad": bool(e.get("is_bad")),
            })
        url = e.get("url", "")
        if "github.com/" in url:
            parts = url.split("github.com/")[1].split("/")
            if len(parts) >= 2:
                repos.add(f"{parts[0]}/{parts[1]}")
    return meta, repos


def main():
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent

    p = argparse.ArgumentParser(description="Harvest Firehose loaders from GitHub repos not indexed by Temblast")
    p.add_argument("--repo", action="append", default=None,
                   help=f"owner/name to harvest; repeatable (default: {', '.join(DEFAULT_REPOS)})")
    p.add_argument("--org", action="append", default=None,
                   help=f"harvest every repo in a GitHub org; repeatable (default: {', '.join(DEFAULT_ORGS)})")
    p.add_argument("--page", action="append", default=None,
                   help=f"HTML index linking loader files; repeatable (default: {', '.join(DEFAULT_PAGES)})")
    p.add_argument("--archive", action="append", default=None,
                   help="zip/tar of loaders (URL or local path); repeatable. Defaults to the "
                        "known community dumps; pass --no-default-archives to harvest only repos")
    p.add_argument("--no-default-archives", action="store_true",
                   help="skip the built-in archive list")
    p.add_argument("--archive-password", default=None,
                   help=f"password for encrypted archives (also applied to anything in {FOUND_DIR}/)")
    p.add_argument("--out", default="harvested_loaders", help="target output directory")
    p.add_argument("--cache-dir", default=".gh_loader_repos", help="clone cache (shared with the Temblast script)")
    p.add_argument("--temblast-catalog", default=str(project_root / "catalog" / "temblast_loaders.json"),
                   help="Temblast catalog JSON used to skip already-known loaders")
    p.add_argument("--delta-only", action="store_true",
                   help="emit only loaders Temblast does not already list (the old default)")
    p.add_argument("--include-bad", action="store_true",
                   help="keep the loaders Temblast flags as broken")
    p.add_argument("--refresh-catalog", action="store_true",
                   help=f"re-scrape {TEMBLAST_URL} into the catalog before harvesting")
    p.add_argument("--no-temblast-repos", action="store_true",
                   help="do not harvest the upstream repos discovered from the catalog")
    p.add_argument("--skip-opaque", action="store_true",
                   help="drop encrypted/compressed blobs (entropy > %.1f) instead of copying them" % OPAQUE_ENTROPY)
    p.add_argument("--structure", choices=["flat", "by-repo", "by-type"], default="flat",
                   help="folder layout for harvested loaders")
    p.add_argument("--min-size", type=int, default=16 * 1024, help="skip files smaller than this")
    p.add_argument("--max-size", type=int, default=8 * 1024 * 1024, help="skip files larger than this")
    p.add_argument("--refresh", action="store_true", help="re-fetch repos already in the clone cache")
    p.add_argument("--limit", type=int, default=0, help="max files to copy")
    p.add_argument("--dry-run", action="store_true", help="report what would be harvested")
    args = p.parse_args()

    repos = list(args.repo or DEFAULT_REPOS)
    archives = args.archive or ([] if args.no_default_archives else DEFAULT_ARCHIVES)
    pages = args.page if args.page is not None else ([] if args.repo else DEFAULT_PAGES)

    # Anything dropped in found/ is harvested with no flag: archives (at any depth) get
    # extracted, and loose loaders (e.g. found/misc/prog_firehose_spacewar_sm7325.elf) are
    # scanned in place by adding found/ itself as a source root below.
    found_dir = Path(project_root / FOUND_DIR)
    found_loose = None
    if found_dir.is_dir() and not args.archive:
        dropped = sorted(str(q) for q in found_dir.rglob("*")
                         if q.is_file() and q.suffix.lower() in ARCHIVE_EXTS)
        if dropped:
            print(f"{FOUND_DIR}/: {len(dropped)} archive(s)")
            archives = list(archives) + dropped
        loose = [q for q in found_dir.rglob("*")
                 if q.is_file() and looks_like_loader(q, args.min_size, args.max_size)]
        if loose:
            print(f"{FOUND_DIR}/: {len(loose)} loose loader file(s)")
            found_loose = found_dir

    orgs = args.org if args.org is not None else ([] if args.repo else DEFAULT_ORGS)
    for org in orgs:
        org_repos = expand_org(org)
        print(f"Org {org}: {len(org_repos)} repo(s)")
        repos.extend(r for r in org_repos if r not in repos)

    if shutil.which("gh") is None and shutil.which("git") is None:
        print("Error: neither 'gh' nor 'git' is in PATH.", file=sys.stderr)
        sys.exit(1)

    if args.refresh_catalog:
        refresh_catalog(args.temblast_catalog)

    temblast, temblast_repos = load_temblast(args.temblast_catalog)
    if temblast:
        named = sum(1 for m in temblast.values() if m["signer"])
        print(f"Temblast: {len(temblast)} known loaders ({named} with a signer), "
              f"{len(temblast_repos)} upstream repo(s).")
    if temblast_repos and not args.no_temblast_repos and not args.repo:
        repos.extend(r for r in sorted(temblast_repos) if r not in repos)

    cache_dir = Path(args.cache_dir).resolve()
    # (label, root, site, url_for) per source; site 'G' = git repo, 'Z' = archive.
    sources = []

    print(f"\nCloning {len(repos)} repo(s)...")
    for repo in repos:
        root = clone_repo(repo, cache_dir, dry_run=args.dry_run, refresh=args.refresh)
        if root:
            sources.append((repo, root, "G", lambda rel, r=repo: f"https://github.com/{r}/blob/HEAD/{rel}"))

    if archives:
        print(f"\nFetching {len(archives)} archive(s)...")
        for spec in archives:
            root = fetch_archive(spec, cache_dir, dry_run=args.dry_run, refresh=args.refresh,
                                 password=args.archive_password)
            if root:
                sources.append((spec, root, "Z", lambda rel, s=spec: s))

    if pages:
        print(f"\nScraping {len(pages)} index page(s)...")
        for url in pages:
            root = fetch_page(url, cache_dir, dry_run=args.dry_run, refresh=args.refresh)
            if root:
                sources.append((url, root, "W", lambda rel, u=url: urllib.parse.urljoin(u, rel)))

    if found_loose is not None:
        sources.append((FOUND_DIR, found_loose, "F", lambda rel: f"{FOUND_DIR}/{rel}"))

    out_dir = Path(args.out).resolve()
    seen_md5 = {}
    records = []
    scanned = skipped_known = skipped_dup = skipped_opaque = repaired = 0
    skipped_bad = annotated = 0

    for repo, root, site, url_for in sources:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or ".git" in path.parts:
                continue
            if not looks_like_loader(path, args.min_size, args.max_size):
                continue
            scanned += 1
            md5, sha256 = hash_file(path)
            row = temblast.get(md5[:16])
            if row and row["is_bad"] and not args.include_bad:
                skipped_bad += 1
                continue
            if row and args.delta_only:
                skipped_known += 1
                continue
            if md5 in seen_md5:
                skipped_dup += 1
                continue

            ltype = classify_image(path)
            if args.skip_opaque and ltype == "OPAQUE":
                skipped_opaque += 1
                continue
            seen_md5[md5] = path

            rel = path.relative_to(root).as_posix()
            dest_name = f"{sha256[:16]}_{md5[:16]}_{sanitize(path.name)}"
            if args.structure == "by-repo":
                dest = out_dir / sanitize(repo.replace("/", "__")) / dest_name
            elif args.structure == "by-type":
                dest = out_dir / sanitize(ltype) / dest_name
            else:
                dest = out_dir / dest_name

            with open(path, "rb") as f:
                fix = repair_magic(f.read(8))
            if fix:
                repaired += 1
            if row and row["signer"]:
                annotated += 1
            print(f"  [{len(records) + 1}] {repo}:{rel} -> {dest.name}" + ("  [magic repaired]" if fix else ""))
            if not args.dry_run:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dest)
                if fix:
                    with open(dest, "r+b") as f:
                        f.seek(fix[0]); f.write(bytes([fix[1]]))

            records.append({
                # Empty: these sources carry no signer metadata, so import-loaders falls back
                # to the OEM_ID baked into the image.
                "signer": row["signer"] if row else "",
                "sha256": sha256[:16],
                "sha384": "",
                "file_md5": md5[:16],
                "type": ltype,
                "ver": "",
                "site": site,
                "path": rel,
                "url": url_for(rel),
                "is_bad": bool(row and row["is_bad"]),
                "known": bool(row),
                "repaired": bool(fix),
                "repo": repo,
                "repo_path": rel,
                "saved_file": str(dest.relative_to(out_dir)),
            })

            if args.limit and len(records) >= args.limit:
                break
        if args.limit and len(records) >= args.limit:
            break

    if records and not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        with open(out_dir / "manifest.json", "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        with open(out_dir / "manifest.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=records[0].keys())
            w.writeheader()
            w.writerows(records)
        print(f"\nWrote {out_dir / 'manifest.json'} and {out_dir / 'manifest.csv'}")

    by_type = defaultdict(int)
    for r in records:
        by_type[r["type"]] += 1
    print(f"\nScanned {scanned} candidate file(s) across {len(sources)} source(s).")
    print(f"  {annotated} carry a Temblast signer, {skipped_bad} dropped as known-bad.")
    print(f"  {skipped_known} skipped as already catalogued, {skipped_dup} intra-repo duplicates"
          + (f", {skipped_opaque} opaque blobs." if args.skip_opaque else "."))
    if repaired:
        print(f"  {repaired} had a neutered magic byte, repaired on copy.")
    print(f"  {len(records)} new loader(s): " + ", ".join(f"{k or 'unknown'}={v}" for k, v in sorted(by_type.items())))
    if records and not args.dry_run:
        print(f"\nNext: go-unbrick library import-loaders {args.out}")


if __name__ == "__main__":
    main()
