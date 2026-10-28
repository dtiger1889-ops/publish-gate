#!/usr/bin/env python3
"""publish-gate: screen a git repo before it goes public, then publish it in one locked run.

Commands
  check     scan what the repo would publish (the files in the index plus history)
  publish   scope lock -> stage -> check -> review stop -> commit -> re-check -> push -> certify
  certify   check, review and pin a commit that is already pushed
  monitor   re-check a published repo: visibility, drift past the pin, new history
  selftest  prove every check fires on planted bad content (the positive control)

Exit codes
  0 clean   1 findings   2 a check could not run (never a pass)   3 stopped for review
  4 refused (usage, identity, scope)   5 push failed   6 certify failed

Python 3.9+, standard library only. Optional tools are used when they are on PATH:
gitleaks (secret detection) and exiftool (photo and video metadata).
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import posixpath
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

VERSION = "1.0.0"

EXIT_CLEAN, EXIT_FINDINGS, EXIT_UNVERIFIABLE, EXIT_REVIEW, EXIT_REFUSED, EXIT_PUSH, EXIT_CERTIFY = range(7)

CONFIG_NAME = ".publish-gate.json"
DENYLIST_ENV = "PUBLISH_GATE_DENYLIST"
DEFAULT_DENYLIST = Path.home() / ".publish-gate" / "denylist.txt"
GITLEAKS_MIN = (8, 21, 2)  # the oldest release this tool is tested against
BATCH_BYTES = 64 * 1024 * 1024
SCAN_CAP = 200 * 1024 * 1024  # contents of a bigger file are not read; the run says so

# Replacement refs could show the scanner a different history than the one that gets pushed.
GIT_ENV = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0")

TEXT_CHECKS = {"denylist", "secret", "home-path", "email", "private-ip", "internal-host"}
FILE_CHECKS = {"forbidden-file", "conflict-copy", "large-file", "image-gps", "notebook-output",
               "link-preview", "required-file", "lfs"}
ALL_CHECKS = TEXT_CHECKS | FILE_CHECKS | {"identity", "denylist-location"}

DEFAULTS = {
    "allowed_commit_emails": ["*@users.noreply.github.com"],
    "allowed_content_emails": ["*@example.com", "*@example.org", "*@example.net",
                               "*@users.noreply.github.com", "noreply@*"],
    "required_files": ["README*", "LICENSE*"],
    "forbidden_files": [".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*",
                        "id_ecdsa*", "id_ed25519*", "*.kdbx", "*.sqlite", "*.sqlite3", "*.db",
                        ".npmrc", ".pypirc", ".netrc", "credentials.json", ".DS_Store",
                        "Thumbs.db", "*.log"],
    "forbidden_files_except": [".env.example", ".env.sample", ".env.template"],
    "max_file_mb": 5,
    "home_path_placeholders": ["you", "me", "user", "username", "name", "yourname",
                               "your-name", "your_name", "example", "runner", "someone",
                               "public", "default", "shared", "all users"],
    "internal_domains": [],
    "site_pages": ["index.html", "docs/index.html"],
    "link_preview_tags": ["og:title", "og:description", "og:url", "og:image", "twitter:card"],
    "expected_visibility": None,
    "require_gitleaks": False,
    "media_without_exiftool": "unverifiable",
    "severity": {"private-ip": "warn"},
    "allow": [],
}

PLACEHOLDER_IPS = {"10.0.0.0", "192.168.0.0", "172.16.0.0"}

SECRET_PATTERNS = [
    ("private key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b")),
    ("Anthropic or OpenAI key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b")),
    ("credential in URL", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:[^\s/@]{3,}@[\w.\-]+")),
]
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
HOME_RE = re.compile(r"(?i)(?:\b[A-Z]:[\\/]+Users[\\/]+|/Users/|/home/)([^\\/\s\"'`<>:|*?]+)")
IP_RE = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
                   r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
CONFLICT_RE = re.compile(r"(?: \(\d+\)| - Copy(?: \(\d+\))?|\.orig)(?:\.[^/]*)?$|~$")
BUILTIN_GPS_EXT = {".jpg", ".jpeg", ".png", ".tif", ".tiff"}
MEDIA_EXT = BUILTIN_GPS_EXT | {".heic", ".heif", ".webp", ".avif", ".gif", ".dng", ".cr2", ".cr3",
                               ".nef", ".arw", ".orf", ".rw2", ".mov", ".mp4", ".m4v", ".3gp"}
LFS_POINTER = b"version https://git-lfs.github.com/spec/v1"
CANARY = "publish-gate-canary-7f3a"


@dataclass
class Finding:
    check: str
    where: str
    detail: str
    severity: str = "block"
    path: str = ""
    line: str = ""

    def show(self) -> str:
        tag = "FINDING" if self.severity == "block" else "warning"
        return f"  [{tag}] {self.check}: {self.where}: {self.detail}"


@dataclass
class Report:
    findings: list = field(default_factory=list)
    unverifiable: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def blocking(self):
        return [f for f in self.findings if f.severity == "block"]

    def exit_code(self) -> int:
        if self.unverifiable:
            return EXIT_UNVERIFIABLE
        return EXIT_FINDINGS if self.blocking() else EXIT_CLEAN

    def print(self) -> None:
        for n in self.notes:
            print(f"  note: {n}")
        for f in self.findings:
            print(f.show())
        for u in self.unverifiable:
            print(f"  [UNVERIFIABLE] {u}")
        code = self.exit_code()
        print({EXIT_CLEAN: "CLEAN", EXIT_FINDINGS: f"{len(self.blocking())} finding(s)",
               EXIT_UNVERIFIABLE: "UNVERIFIABLE: at least one check could not run; this is not a pass"}[code])


class Refused(Exception):
    pass


# ---------- git plumbing ----------

def fsdecode(raw: bytes) -> str:
    """Keep undecodable file-name bytes intact so a name never silently changes identity."""
    return raw.decode("utf-8", errors="surrogateescape")


def git(repo: Path, *args, check=True, input_bytes=None) -> bytes:
    proc = subprocess.run(["git", "-C", str(repo), *args], input=input_bytes, env=GIT_ENV,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and proc.returncode != 0:
        raise Refused(f"git {' '.join(args)} failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def git_text(repo: Path, *args, check=True) -> str:
    return git(repo, *args, check=check).decode("utf-8", errors="replace").strip()


def repo_root(start: Path) -> Path:
    out = subprocess.run(["git", "-C", str(start), "rev-parse", "--show-toplevel"], env=GIT_ENV,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if out.returncode != 0:
        raise Refused(f"{start} is not inside a git repository")
    return Path(out.stdout.decode().strip())


def current_branch(repo: Path) -> str:
    """Works before the first commit too, where rev-parse HEAD has nothing to name."""
    name = git_text(repo, "symbolic-ref", "--quiet", "--short", "HEAD", check=False)
    if not name:
        raise Refused("detached HEAD: check out the branch you publish, or pass --branch")
    return name


def rev_exists(repo: Path, rev: str) -> bool:
    return subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"{rev}^{{commit}}"], env=GIT_ENV,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def head_sha(repo: Path) -> str | None:
    return git_text(repo, "rev-parse", "HEAD") if rev_exists(repo, "HEAD") else None


def object_sizes(repo: Path, shas: list) -> dict:
    if not shas:
        return {}
    proc = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
                          input=("\n".join(shas) + "\n").encode(), env=GIT_ENV,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sizes = {}
    for ln in proc.stdout.decode().splitlines():
        parts = ln.split()
        if len(parts) == 3 and parts[1] == "blob":
            sizes[parts[0]] = int(parts[2])
    return sizes


def read_blobs(repo: Path, shas: list, report: Report, limit: int) -> dict:
    """Read blobs in bounded batches; a blob over `limit` bytes is sized but never loaded."""
    wanted = list(dict.fromkeys(shas))
    sizes = object_sizes(repo, wanted)
    missing = [s for s in wanted if s not in sizes]
    if missing:
        report.unverifiable.append(f"{len(missing)} object(s) could not be read from git (first {missing[0][:8]})")
    blobs, batch, batch_bytes = {}, [], 0

    def flush():
        if not batch:
            return
        proc = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch"], env=GIT_ENV,
                              input=("\n".join(batch) + "\n").encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, pos = proc.stdout, 0
        for sha in batch:
            nl = out.find(b"\n", pos)
            header = out[pos:nl].split() if nl >= 0 else []
            if len(header) != 3 or header[1] != b"blob":
                report.unverifiable.append(f"git returned no content for object {sha[:8]}")
                return
            size = int(header[2])
            if header[0].decode() != sha or size != sizes.get(sha) or len(out) < nl + 1 + size:
                report.unverifiable.append(f"git returned a short or mismatched read for object {sha[:8]}")
                return
            blobs[sha] = out[nl + 1:nl + 1 + size]
            pos = nl + 1 + size + 1
        if proc.returncode != 0:
            report.unverifiable.append("git cat-file failed while reading file contents")

    for sha in wanted:
        size = sizes.get(sha)
        if size is None or size > limit:
            continue
        if batch and batch_bytes + size > BATCH_BYTES:
            flush()
            batch, batch_bytes = [], 0
        batch.append(sha)
        batch_bytes += size
    flush()
    return {"blobs": blobs, "sizes": sizes}


def index_entries(repo: Path) -> list:
    """(path, blob sha) for every file in the index: exactly what the next commit ships."""
    entries = []
    for rec in git(repo, "ls-files", "-s", "-z").split(b"\0"):
        if not rec:
            continue
        meta, path = rec.split(b"\t", 1)
        mode, sha, _stage = meta.split()
        if mode == b"160000":  # submodule: its content lives in another repo
            continue
        entries.append((fsdecode(path), sha.decode()))
    return entries


def history_entries(repo: Path, rev_range: list) -> list:
    """Every (path, blob sha) written by a commit in rev_range, read NUL-delimited so names stay exact."""
    raw = git(repo, "log", "--raw", "-z", "--no-abbrev", "--no-renames", "--root", "-m",
              "--format=%x01%H", *rev_range)
    out, tokens, i = [], raw.split(b"\0"), 0
    while i < len(tokens):
        tok = tokens[i].lstrip(b"\n")
        if tok.startswith(b":"):
            fields = tok[1:].split()
            path = fsdecode(tokens[i + 1]) if i + 1 < len(tokens) else ""
            i += 2
            if len(fields) >= 5 and fields[1] != b"160000" and not fields[4].startswith(b"D"):
                out.append((path, fields[3].decode()))
            continue
        i += 1
    return list(dict.fromkeys(out))


def commits(repo: Path, rev_range: list) -> list:
    if not rev_range:
        return []
    fmt = "%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x1e"
    raw = git(repo, "log", f"--format={fmt}", *rev_range).decode("utf-8", errors="replace")
    result = []
    for rec in raw.split("\x1e"):
        rec = rec.strip("\n")
        if rec:
            sha, an, ae, cn, ce, body = (rec.split("\0") + [""] * 6)[:6]
            result.append({"sha": sha, "an": an, "ae": ae, "cn": cn, "ce": ce, "body": body})
    return result


def history_complete(repo: Path, report: Report) -> bool:
    if git_text(repo, "rev-parse", "--is-shallow-repository") == "true":
        report.unverifiable.append("shallow clone: older history is missing, so it could not be checked "
                                   "(in CI use a full checkout, e.g. fetch-depth: 0)")
        return False
    gitdir = Path(git_text(repo, "rev-parse", "--absolute-git-dir"))
    if (gitdir / "info" / "grafts").exists():
        report.unverifiable.append("this clone uses grafts, which rewrite the history git shows")
        return False
    return True


def gate_dir(repo: Path) -> Path:
    return Path(git_text(repo, "rev-parse", "--absolute-git-dir")) / "publish-gate"


def load_state(repo: Path) -> dict:
    p = gate_dir(repo) / "state.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def save_state(repo: Path, data: dict) -> None:
    p = gate_dir(repo) / "state.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


class GateLock:
    """One publish or certify at a time per repo; a second run refuses instead of interleaving."""

    def __init__(self, repo: Path):
        self.path = gate_dir(repo) / "lock"

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            raise Refused(f"another publish-gate run holds {self.path}; if none is running, delete that file")
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return self

    def __exit__(self, *exc):
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


# ---------- configuration ----------

def load_config(repo: Path, explicit: str | None = None) -> dict:
    cfg = json.loads(json.dumps(DEFAULTS))
    path = Path(explicit) if explicit else repo / CONFIG_NAME
    if path.exists():
        user = json.loads(path.read_text(encoding="utf-8"))
        for key, value in user.items():
            if key.startswith("_"):
                continue
            if key not in cfg:
                raise Refused(f"{path}: unknown setting '{key}'")
            if key == "severity":
                cfg[key].update(value)
            else:
                cfg[key] = value
    elif explicit:
        raise Refused(f"config file not found: {path}")
    for check, level in cfg["severity"].items():
        if check not in ALL_CHECKS:
            raise Refused(f"severity: unknown check '{check}'")
        if level not in ("block", "warn", "off"):
            raise Refused(f"severity for {check} must be block, warn or off, not '{level}'")
    if cfg["media_without_exiftool"] not in ("unverifiable", "warn"):
        raise Refused("media_without_exiftool must be 'unverifiable' or 'warn'")
    for entry in cfg["allow"]:
        if not entry.get("path") or not entry.get("reason") or entry.get("check") not in ALL_CHECKS:
            raise Refused("every allow entry needs a known check, a path and a reason")
        if entry["check"] in TEXT_CHECKS and not str(entry.get("line_contains", "")).strip():
            raise Refused(f"allow entry for {entry['check']} on {entry['path']} needs line_contains "
                          "(the text on the one line it clears)")
    return cfg


def load_denylist(repo: Path, explicit: str | None, skip: bool, report: Report) -> list:
    if skip:
        report.notes.append("denylist SKIPPED by --no-denylist: your own names, addresses and "
                            "handles were not searched for")
        return []
    path = Path(explicit or os.environ.get(DENYLIST_ENV) or DEFAULT_DENYLIST).expanduser()
    if not path.exists():
        report.unverifiable.append(f"denylist not found at {path}: create it (one personal token per "
                                   "line) or pass --no-denylist to skip on purpose")
        return []
    try:
        rel = path.resolve().relative_to(repo.resolve())
        report.findings.append(Finding("denylist-location", str(rel),
                                       "the denylist lives inside the repo; it IS your personal data, "
                                       "keep it outside"))
    except ValueError:
        pass
    tokens = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            tokens.append(ln.lower())
    if not tokens:
        report.unverifiable.append(f"denylist {path} is empty: the personal-token search would pass "
                                   "anything")
    return tokens


def allowed(cfg: dict, check: str, path: str, line: str) -> bool:
    for entry in cfg["allow"]:
        if entry["check"] == check and fnmatch.fnmatchcase(path, entry["path"]):
            needle = entry.get("line_contains")
            if check not in TEXT_CHECKS and not needle:
                return True
            if needle and needle in line:
                return True
    return False


def any_match(value: str, patterns: list) -> bool:
    return any(fnmatch.fnmatchcase(value.lower(), p.lower()) for p in patterns)


def add(cfg: dict, report: Report, f: Finding) -> None:
    if allowed(cfg, f.check, f.path, f.line):
        return
    f.severity = cfg["severity"].get(f.check, "block")
    if f.severity != "off":
        report.findings.append(f)


# ---------- content checks ----------

def jpeg_has_gps(data: bytes) -> bool:
    if not data.startswith(b"\xff\xd8"):
        return False
    pos = 2
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker in (0xD9, 0xDA):
            break
        seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        seg = data[pos + 4:pos + 2 + seg_len]
        if marker == 0xE1 and seg.startswith(b"Exif\0\0") and tiff_has_gps(seg[6:]):
            return True
        pos += 2 + seg_len
    return False


def png_has_gps(data: bytes) -> bool:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    pos = 8
    while pos + 8 <= len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        if kind == b"eXIf" and tiff_has_gps(data[pos + 8:pos + 8 + length]):
            return True
        if kind == b"IEND":
            break
        pos += 12 + length
    return False


def tiff_has_gps(tiff: bytes) -> bool:
    """True when the first IFD carries a GPS pointer (tag 0x8825)."""
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return False
    end = "<" if tiff[:2] == b"II" else ">"
    offset = struct.unpack(end + "I", tiff[4:8])[0]
    if offset + 2 > len(tiff):
        return False
    count = struct.unpack(end + "H", tiff[offset:offset + 2])[0]
    for i in range(count):
        at = offset + 2 + i * 12
        if at + 2 > len(tiff):
            return False
        if struct.unpack(end + "H", tiff[at:at + 2])[0] == 0x8825:
            return True
    return False


def builtin_gps(path: str, data: bytes) -> bool:
    if b"GPSLatitude" in data or b"GPSPosition" in data:  # XMP keeps location as plain text
        return True
    ext = Path(path).suffix.lower()
    if ext in (".jpg", ".jpeg"):
        return jpeg_has_gps(data)
    if ext == ".png":
        return png_has_gps(data)
    if ext in (".tif", ".tiff"):
        return tiff_has_gps(data)
    return False


def notebook_outputs(data: bytes) -> bool:
    try:
        nb = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False
    return any(cell.get("outputs") for cell in nb.get("cells", []))


class MetaTags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = {}

    def handle_starttag(self, tag, attrs):
        if tag == "meta":
            a = dict(attrs)
            key = a.get("property") or a.get("name")
            if key:
                self.tags[key.strip().lower()] = (a.get("content") or "").strip()


def link_preview_problems(text: str, wanted: list) -> list:
    parser = MetaTags()
    parser.feed(text)
    problems = []
    for tag in wanted:
        value = parser.tags.get(tag.lower(), "")
        if not value:
            problems.append(f"{tag} missing or empty")
        elif tag in ("og:image", "og:url") and not re.match(r"https?://[^/\s:]+\.[^/\s]+", value):
            problems.append(f"{tag} must be an absolute URL")
        elif tag == "twitter:card" and value not in ("summary", "summary_large_image", "app", "player"):
            problems.append(f"twitter:card value '{value}' is not a card type")
    return problems


def decoded_texts(data: bytes) -> list:
    """(text, strong_checks_only) views of a file. Files with NULs may be BOM-less UTF-16 in either byte
    order, so both orders and both alignments get every check; the raw-byte view gets only the strong ones."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return [(data.decode("utf-16", errors="replace"), False)]
    if b"\0" not in data[:8192]:
        return [(data.decode("utf-8", errors="replace"), False)]
    views = [(data.decode("latin-1"), True)]
    for enc in ("utf-16-le", "utf-16-be"):
        for start in (0, 1):
            views.append((data[start:].decode(enc, errors="ignore"), False))
    return views


def scan_path_name(cfg: dict, denylist: list, path: str, where: str, report: Report) -> None:
    name = path.rsplit("/", 1)[-1]
    if any_match(name, cfg["forbidden_files"]) and not any_match(name, cfg["forbidden_files_except"]):
        add(cfg, report, Finding("forbidden-file", where, f"{path} should never be published", path=path))
    if CONFLICT_RE.search(path):
        add(cfg, report, Finding("conflict-copy", where, f"{path} looks like a sync conflict or backup copy",
                                 path=path))
    low = path.lower()
    for tok in denylist:
        if tok in low:
            add(cfg, report, Finding("denylist", where, f"file name {path} contains a denylisted token",
                                     path=path, line=path))


def scan_content(cfg: dict, denylist: list, path: str, data: bytes, where: str, report: Report) -> None:
    if data.startswith(LFS_POINTER):
        add(cfg, report, Finding("lfs", where, f"{path} is a Git LFS pointer: the real file is uploaded by "
                                 "LFS and was not checked", path=path))
        report.unverifiable.append(f"Git LFS content not checked ({path})")
        return
    if Path(path).suffix.lower() in BUILTIN_GPS_EXT and builtin_gps(path, data):
        add(cfg, report, Finding("image-gps", where, f"{path} carries GPS location metadata", path=path))
    texts = decoded_texts(data)
    binary = len(texts) > 1
    if not binary:
        if path.lower().endswith(".ipynb") and notebook_outputs(data):
            add(cfg, report, Finding("notebook-output", where, f"{path} still holds cell outputs (clear them)",
                                     path=path))
        if where == "publish set" and any(fnmatch.fnmatchcase(path, p) for p in cfg["site_pages"]):
            problems = link_preview_problems(texts[0][0], cfg["link_preview_tags"])
            if problems:
                add(cfg, report, Finding("link-preview", where, f"{path}: {'; '.join(problems)}", path=path))
    for text, strong_only in texts:
        for lineno, line in enumerate(text.splitlines(), 1):
            scan_line(cfg, denylist, path, 0 if binary else lineno, line, where, report, strong_only)


def scan_line(cfg, denylist, path, lineno, line, where, report, binary=False) -> None:
    loc = f"{path}:{lineno}" if lineno else path
    low = line.lower()
    for tok in denylist:
        if tok in low:
            add(cfg, report, Finding("denylist", f"{where} {loc}", "contains a denylisted token",
                                     path=path, line=line))
    for label, rx in SECRET_PATTERNS:
        if rx.search(line):
            add(cfg, report, Finding("secret", f"{where} {loc}", f"matches the {label} pattern",
                                     path=path, line=line))
    if binary:  # inside binary data only the strongest signals are meaningful
        return
    for m in HOME_RE.finditer(line):
        user = m.group(1).strip().lower()
        if user not in cfg["home_path_placeholders"] and not user.startswith(("<", "{", "$", "%")):
            add(cfg, report, Finding("home-path", f"{where} {loc}",
                                     f"names a real home folder ({m.group(0)})", path=path, line=line))
    for m in EMAIL_RE.finditer(line):
        if not any_match(m.group(0), cfg["allowed_content_emails"]):
            add(cfg, report, Finding("email", f"{where} {loc}", f"email address {m.group(0)}",
                                     path=path, line=line))
    for m in IP_RE.finditer(line):
        if m.group(0) not in PLACEHOLDER_IPS:
            add(cfg, report, Finding("private-ip", f"{where} {loc}", f"private network address {m.group(0)}",
                                     path=path, line=line))
    for dom in cfg["internal_domains"]:
        if dom.lower() in low:
            add(cfg, report, Finding("internal-host", f"{where} {loc}", f"internal domain {dom}",
                                     path=path, line=line))


# ---------- optional outside tools ----------

def gitleaks_version() -> tuple | None:
    exe = shutil.which("gitleaks")
    if not exe:
        return None
    out = subprocess.run([exe, "version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode()
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def run_gitleaks(cfg: dict, args: list, report: Report, where: str, line_of) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.json"
        proc = subprocess.run(["gitleaks", *args, "--report-format", "json", "--report-path", str(out),
                               "--exit-code", "0", "--redact", "--no-banner", "--ignore-gitleaks-allow"],
                              env=GIT_ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode != 0 or not out.exists():
            report.unverifiable.append(f"gitleaks failed on the {where}: "
                                       f"{proc.stderr.decode(errors='replace').strip()[:300]}")
            return
        for leak in json.loads(out.read_text(encoding="utf-8") or "[]"):
            path, commit = line_of(leak)
            line = leak.get("_line", "")
            loc = f"{path}:{leak.get('StartLine')}" + (f" @ {commit[:8]}" if commit else "")
            add(cfg, report, Finding("secret", f"{where} {loc}", f"gitleaks rule {leak.get('RuleID')}",
                                     path=path, line=line))


def gitleaks_dir(cfg: dict, tree: Path, report: Report) -> None:
    def locate(leak):
        try:
            rel = Path(leak.get("File", "")).resolve().relative_to(tree.resolve()).as_posix()
        except ValueError:
            rel = leak.get("File", "")
        try:
            lines = (tree / rel).read_text(encoding="utf-8", errors="replace").splitlines()
            leak["_line"] = lines[int(leak.get("StartLine", 1)) - 1]
        except (OSError, IndexError, ValueError):
            pass
        return rel, ""
    run_gitleaks(cfg, ["dir", str(tree)], report, "publish set", locate)


def gitleaks_git(cfg: dict, repo: Path, rng: list, report: Report) -> None:
    def locate(leak):
        path, commit = leak.get("File", ""), leak.get("Commit", "")
        blob = subprocess.run(["git", "-C", str(repo), "show", f"{commit}:{path}"], env=GIT_ENV,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
        try:
            leak["_line"] = blob.decode("utf-8", errors="replace").splitlines()[int(leak.get("StartLine", 1)) - 1]
        except (IndexError, ValueError):
            pass
        return path, commit
    # -m: give merge commits their own diffs, so a secret added only in a merge resolution is seen
    run_gitleaks(cfg, ["git", "--log-opts", " ".join(["-m", "--text", *rng]), str(repo)], report, "history", locate)


def check_media(cfg: dict, media: list, report: Report) -> None:
    """media: (where, path, bytes). Uses exiftool for every photo and video format when installed."""
    if not media:
        return
    if not shutil.which("exiftool"):
        others = [(w, p) for w, p, _ in media if Path(p).suffix.lower() not in BUILTIN_GPS_EXT]
        msg = (f"{len(others)} HEIC/WebP/RAW/video file(s) could not be checked for location metadata "
               f"(first: {others[0][1]}); install exiftool") if others else ""
        if others and cfg["media_without_exiftool"] == "unverifiable":
            report.unverifiable.append(msg + ", or set media_without_exiftool to warn")
        elif others:
            report.notes.append(msg)
        return
    with tempfile.TemporaryDirectory() as tmp:
        names = {}
        for i, (where, path, data) in enumerate(media):
            f = Path(tmp) / f"{i}{Path(path).suffix.lower()}"
            f.write_bytes(data)
            names[f.name] = (where, path)
        argfile = Path(tmp) / "args.txt"
        argfile.write_text("\n".join(str(Path(tmp) / n) for n in names) + "\n", encoding="utf-8")
        proc = subprocess.run(["exiftool", "-json", "-G", "-a", "-n", "-charset", "filename=utf8",
                               "-@", str(argfile)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            rows = json.loads(proc.stdout.decode("utf-8", errors="replace") or "[]")
        except ValueError:
            report.unverifiable.append("exiftool output could not be read")
            return
        seen = set()
        for row in rows:
            name = Path(row.get("SourceFile", "")).name
            if name not in names:
                continue
            seen.add(name)
            where, path = names[name]
            if any("error" in k.lower() for k in row):
                report.unverifiable.append(f"exiftool could not read {path}")
            if any("gps" in k.lower() for k in row):
                add(cfg, report, Finding("image-gps", where, f"{path} carries GPS location metadata", path=path))
        if proc.returncode != 0:
            report.unverifiable.append(f"exiftool exited {proc.returncode}: "
                                       f"{proc.stderr.decode(errors='replace').strip()[:200]}")
        if len(seen) != len(names):
            report.unverifiable.append(f"exiftool returned results for {len(seen)} of {len(names)} media files")


# ---------- the check ----------

def run_check(repo: Path, cfg: dict, denylist: list, report: Report, since: str | None,
              tip: str = "HEAD", scan_index: bool = True, extra_messages: list | None = None) -> Report:
    gl = gitleaks_version()
    use_gitleaks = gl is not None and gl >= GITLEAKS_MIN
    if gl is not None and not use_gitleaks:
        report.notes.append(f"gitleaks {'.'.join(map(str, gl))} is older than the tested "
                            f"{'.'.join(map(str, GITLEAKS_MIN))}; it was not used")
    if not use_gitleaks:
        msg = "gitleaks not used: secret detection relies on the built-in patterns, which cover far fewer key types"
        if cfg["require_gitleaks"]:
            report.unverifiable.append(msg + " (require_gitleaks is on)")
        else:
            report.notes.append(msg)

    # positive control: every text matcher must fire on planted content before its silence means anything
    probe = Report()
    probe_cfg = dict(cfg, allow=[], severity={}, internal_domains=["internal.invalid"])
    scan_line(probe_cfg, [CANARY], "probe.txt", 1,
              f"{CANARY} AKIA{'A' * 16} /home/realperson/x who@realmail.test 10.1.2.3 db.internal.invalid",
              "probe", probe)
    fired = {f.check for f in probe.findings}
    for needed in TEXT_CHECKS:
        if needed not in fired:
            report.unverifiable.append(f"positive control: the {needed} check did not fire on planted content")

    limit = int(float(cfg["max_file_mb"]) * 1024 * 1024)
    media = []
    export = Path(tempfile.mkdtemp(prefix="publish-gate-")) / "tree"

    def scan_entries(entries, where):
        got = read_blobs(repo, [s for _, s in entries], report, SCAN_CAP)
        for path, sha in entries:  # every path gets every check: exemptions and page rules are per path
            scan_path_name(cfg, denylist, path, where, report)
            size = got["sizes"].get(sha)
            if size is not None and size > limit:
                add(cfg, report, Finding("large-file", where, f"{path} is {size / 1048576:.1f} MB "
                                         f"(limit {cfg['max_file_mb']} MB)", path=path))
            if size is not None and size > SCAN_CAP:
                report.unverifiable.append(f"{path} ({where}) is over {SCAN_CAP // 1048576} MB, so its "
                                           "contents were not scanned")
                continue
            data = got["blobs"].get(sha)
            if data is None:
                continue
            scan_content(cfg, denylist, path, data, where, report)
            if Path(path).suffix.lower() in MEDIA_EXT:
                media.append((where, path, data))
            if where == "publish set" and use_gitleaks:
                # raw index bytes, never a checkout: smudge filters and sparse checkouts must not change what is scanned
                try:
                    out = export / path
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(data)
                except (OSError, UnicodeEncodeError):
                    report.unverifiable.append(f"could not hand {path} to gitleaks (file name not usable here)")

    try:
        return _run_check_body(repo, cfg, denylist, report, since, tip, scan_index, extra_messages,
                               use_gitleaks, media, export, scan_entries)
    finally:
        shutil.rmtree(export.parent, ignore_errors=True)


def _run_check_body(repo, cfg, denylist, report, since, tip, scan_index, extra_messages,
                    use_gitleaks, media, export, scan_entries) -> Report:
    entries = []
    if scan_index:
        entries = index_entries(repo)
        if not entries:
            report.unverifiable.append("the index is empty: nothing would be published, so nothing was checked")
        scan_entries(entries, "publish set")
        names = [p for p, _ in entries]
        for pattern in cfg["required_files"]:
            if not any(fnmatch.fnmatchcase(p, pattern) for p in names):
                add(cfg, report, Finding("required-file", "publish set", f"no file matches {pattern}"))

    rng = [tip, f"^{since}"] if since else [tip]
    if rev_exists(repo, tip) and history_complete(repo, report):
        if since and not rev_exists(repo, since):
            report.unverifiable.append(f"certified commit {since[:8]} is not in this clone; run with --full-history")
        else:
            current = {(p, s) for p, s in entries}
            scan_entries([e for e in history_entries(repo, rng) if e not in current], "history")
            for c in commits(repo, rng):
                for who, email in (("author", c["ae"]), ("committer", c["ce"])):
                    if not any_match(email, cfg["allowed_commit_emails"]):
                        add(cfg, report, Finding("identity", f"commit {c['sha'][:8]}",
                                                 f"{who} email {email} is not an allowed public address"))
                text = f"{c['an']}\n{c['cn']}\n{c['body']}"
                for line in text.splitlines():
                    scan_line(cfg, denylist, f"commit {c['sha'][:8]} message", 0, line, "history", report)
            report.notes.append(f"history checked: {' '.join(rng)}")
            if use_gitleaks:
                gitleaks_git(cfg, repo, rng, report)
    for msg in extra_messages or []:
        for line in msg.splitlines():
            scan_line(cfg, denylist, "commit message", 0, line, "publish set", report)

    if scan_index and use_gitleaks and export.exists():
        gitleaks_dir(cfg, export, report)
    check_media(cfg, media, report)
    return report


# ---------- commands ----------

def cmd_check(a) -> int:
    repo = repo_root(Path(a.repo))
    cfg = load_config(repo, a.config)
    report = Report()
    denylist = load_denylist(repo, a.denylist, a.no_denylist, report)
    since = None if a.full_history else (a.since or load_state(repo).get("certified"))
    run_check(repo, cfg, denylist, report, since)
    report.print()
    return report.exit_code()


def assert_identity(repo: Path, cfg: dict) -> str:
    email = git_text(repo, "config", "user.email", check=False)
    if not email or not any_match(email, cfg["allowed_commit_emails"]):
        raise Refused(f"git user.email is '{email or '(unset)'}', not an allowed public address. Set it in "
                      f"this repo: git config user.email <your-id>+<user>@users.noreply.github.com")
    return email


def dirty_paths(repo: Path) -> list:
    """Every path git status reports, including BOTH ends of a rename or copy."""
    raw = git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all").split(b"\0")
    paths, i = [], 0
    while i < len(raw):
        rec = raw[i]
        i += 1
        if not rec:
            continue
        status, path = rec[:2].decode(), fsdecode(rec[3:])
        paths.append(path)
        if status[0] in "RC" or status[1] in "RC":
            paths.append(fsdecode(raw[i]))
            i += 1
    return paths


def normalize_scopes(scopes: list) -> list:
    out = []
    for s in scopes:
        s = posixpath.normpath(s.replace("\\", "/")).lstrip("/")
        if s == ".." or s.startswith("../"):
            raise Refused(f"--paths entry '{s}' points outside the repo")
        out.append("" if s == "." else s)
    return out


def under(path: str, scopes: list) -> bool:
    return any(s == "" or path == s or path.startswith(s + "/") for s in scopes)


def review(repo: Path, base: str | None, against_index: bool) -> None:
    print("== review ==")
    if base:
        args = ["diff", "--cached", base] if against_index else ["diff", base, "HEAD"]
        print(git(repo, *args, "--stat").decode(errors="replace"))
        sys.stdout.write(git(repo, *args).decode(errors="replace"))
        print(f"\nReview every added and changed line above (changes since certified {base[:8]}).")
    else:
        files = index_entries(repo) if against_index else [
            (fsdecode(p), "") for p in git(repo, "ls-tree", "-r", "-z", "--name-only", "HEAD").split(b"\0") if p]
        print("No certified commit to diff against: read EVERY file, and the history, before publishing:")
        print("\n".join(p for p, _ in files))
    print("Look for what no scanner knows: names, places, real records, someone else's data.\n"
          "Then re-run the same command with --reviewed.")


def cmd_publish(a) -> int:
    repo = repo_root(Path(a.repo))
    cfg = load_config(repo, a.config)
    assert_identity(repo, cfg)
    scopes = normalize_scopes(a.paths)
    with GateLock(repo):
        return publish_locked(repo, cfg, a, scopes)


def assert_one_destination(repo: Path, remote: str) -> None:
    """The remote that is checked must be the only place the push goes."""
    fetch = git_text(repo, "remote", "get-url", "--all", remote, check=False).splitlines()
    push = git_text(repo, "remote", "get-url", "--push", "--all", remote, check=False).splitlines()
    if not fetch:
        raise Refused(f"no remote named '{remote}'")
    if len(push) != 1 or push != fetch[:1] or len(fetch) != 1:
        raise Refused(f"remote '{remote}' fetches from {fetch} but pushes to {push}: the gate checks one place "
                      "and must push to that same one place. Remove the extra or differing push URL")


def publish_locked(repo: Path, cfg: dict, a, scopes: list) -> int:
    branch = current_branch(repo)
    if a.branch and a.branch != branch:
        raise Refused(f"--branch {a.branch} but {branch} is checked out: check out {a.branch} first")
    assert_one_destination(repo, a.remote)
    remote_sha = remote_head(repo, a.remote, branch)
    if a.first_publish and remote_sha:
        raise Refused(f"--first-publish, but {a.remote}/{branch} already exists at {remote_sha[:8]}")
    if not a.first_publish and not remote_sha:
        raise Refused(f"{a.remote}/{branch} does not exist yet: pass --first-publish for the first push")
    pin = load_state(repo).get("certified")
    if remote_sha:
        if not rev_exists(repo, remote_sha):
            raise Refused(f"local clone lacks {remote_sha[:8]}: run git fetch {a.remote} first")
        if pin and pin != remote_sha:
            raise Refused(f"{a.remote}/{branch} is at {remote_sha[:8]} but the last certified commit is "
                          f"{pin[:8]}: something was pushed outside the gate. Review it, then run certify")
        if subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", remote_sha, "HEAD"],
                          env=GIT_ENV).returncode != 0:
            raise Refused(f"local {branch} does not contain {a.remote}/{branch}; pull or rebase first")
    since = pin if (pin and pin == remote_sha) else None  # no certified baseline means the whole history

    outside = [p for p in dirty_paths(repo) if not under(p, scopes)]
    if outside:
        raise Refused("scope lock: these changed paths are outside --paths:\n    " + "\n    ".join(outside))

    saved_tree = git_text(repo, "write-tree")
    staged_tree = None

    def restore():
        # Undo only our own staging: if the index changed under us, leave it and say so.
        if staged_tree and git_text(repo, "write-tree", check=False) != staged_tree:
            print("warning: the index changed during this run; it was left as it is")
            return
        git(repo, "read-tree", saved_tree, check=False)

    try:
        git(repo, "add", "-A", "--", *[s or "." for s in scopes])
        staged_tree = git_text(repo, "write-tree")
        head = head_sha(repo)
        head_tree = git_text(repo, "rev-parse", "HEAD^{tree}") if head else None
        has_change = staged_tree != head_tree
        if not has_change and head == remote_sha:
            raise Refused("nothing to publish: the named paths have no changes and no commit is unpushed")
        report = Report()
        denylist = load_denylist(repo, a.denylist, a.no_denylist, report)
        run_check(repo, cfg, denylist, report, since, extra_messages=[a.message] if has_change else [])
        print("== check ==")
        report.print()
        if report.exit_code() != EXIT_CLEAN:
            restore()
            return report.exit_code()
        if not a.reviewed:
            review(repo, since, against_index=True)
            restore()
            return EXIT_REVIEW
        if git_text(repo, "write-tree") != staged_tree:
            restore()
            raise Refused("the index changed after it was checked; nothing was committed")
    except BaseException:
        restore()
        raise

    if has_change:
        git(repo, "commit", "--quiet", "-m", a.message)
    new_head = head_sha(repo)
    parent = git_text(repo, "rev-parse", f"{new_head}^", check=False) if has_change and head else None
    if git_text(repo, "rev-parse", "HEAD^{tree}") != staged_tree or (has_change and head and parent != head) \
            or (not has_change and new_head != head):
        print("refused to push: HEAD is not the commit that was checked (a commit hook or another process "
              "changed it). Inspect it, then run the publish again.")
        return EXIT_REFUSED
    # The commit itself (message, identity) is new since the check; screen it before anything leaves.
    post = Report()
    rng = [new_head, f"^{remote_sha}"] if remote_sha else [new_head]
    for c in commits(repo, rng):
        for who, email in (("author", c["ae"]), ("committer", c["ce"])):
            if not any_match(email, cfg["allowed_commit_emails"]):
                add(cfg, post, Finding("identity", f"commit {c['sha'][:8]}", f"{who} email {email}"))
        for line in f"{c['an']}\n{c['cn']}\n{c['body']}".splitlines():
            scan_line(cfg, denylist, f"commit {c['sha'][:8]} message", 0, line, "history", post)
    if post.exit_code() != EXIT_CLEAN:
        print("refused to push: the new commit failed its own check")
        post.print()
        return EXIT_REFUSED
    push = subprocess.run(["git", "-C", str(repo), "push", "--no-follow-tags", a.remote,
                           f"{new_head}:refs/heads/{branch}"], env=GIT_ENV)
    if push.returncode != 0:
        print("push failed; nothing was certified. Fix the cause and re-run (the commit is kept).")
        return EXIT_PUSH
    return pin_commit(repo, a.remote, branch, new_head)


def remote_head(repo: Path, remote: str, branch: str) -> str | None:
    proc = subprocess.run(["git", "-C", str(repo), "ls-remote", "--heads", remote, branch], env=GIT_ENV,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise Refused(f"cannot reach remote '{remote}': {proc.stderr.decode(errors='replace').strip()}")
    for ln in proc.stdout.decode().splitlines():
        sha, ref = ln.split("\t")
        if ref == f"refs/heads/{branch}":
            return sha
    return None


def pin_commit(repo: Path, remote: str, branch: str, sha: str) -> int:
    pushed = remote_head(repo, remote, branch)
    if pushed != sha:
        print(f"certify refused: {remote}/{branch} is {pushed and pushed[:8]}, expected {sha[:8]}")
        return EXIT_CERTIFY
    save_state(repo, {"certified": sha, "remote": remote, "branch": branch,
                      "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "tool": VERSION})
    print(f"PINNED {sha} ({remote}/{branch})")
    return EXIT_CLEAN


def cmd_certify(a) -> int:
    """Clear a commit that is already on the remote: the same check and review a publish gets."""
    repo = repo_root(Path(a.repo))
    cfg = load_config(repo, a.config)
    with GateLock(repo):
        branch = a.branch or current_branch(repo)
        if git_text(repo, "status", "--porcelain"):
            print("certify refused: the working tree has uncommitted changes")
            return EXIT_CERTIFY
        head = head_sha(repo)
        if not head or remote_head(repo, a.remote, branch) != head:
            print(f"certify refused: local HEAD is not what {a.remote}/{branch} holds; push or fetch first")
            return EXIT_CERTIFY
        pin = load_state(repo).get("certified")
        since = pin if pin and rev_exists(repo, pin) and pin != head else None
        report = Report()
        denylist = load_denylist(repo, a.denylist, a.no_denylist, report)
        run_check(repo, cfg, denylist, report, since)
        print("== check ==")
        report.print()
        if report.exit_code() != EXIT_CLEAN:
            return report.exit_code()
        if not a.reviewed:
            review(repo, since, against_index=False)
            return EXIT_REVIEW
        return pin_commit(repo, a.remote, branch, head)


def cmd_monitor(a) -> int:
    repo = repo_root(Path(a.repo))
    cfg = load_config(repo, a.config)
    report = Report()
    state = load_state(repo)
    branch = a.branch or state.get("branch") or current_branch(repo)
    if cfg["expected_visibility"]:
        url = git_text(repo, "remote", "get-url", a.remote, check=False)
        if not shutil.which("gh"):
            report.unverifiable.append("expected_visibility is set but the GitHub CLI (gh) is not installed")
        else:
            proc = subprocess.run(["gh", "repo", "view", url, "--json", "visibility", "-q", ".visibility"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            seen = proc.stdout.decode().strip().lower()
            if proc.returncode != 0 or not seen:
                report.unverifiable.append(f"could not read visibility of {url}")
            elif seen != cfg["expected_visibility"].lower():
                report.findings.append(Finding("visibility", url, f"is {seen}, expected "
                                               f"{cfg['expected_visibility']}"))
    remote_sha = remote_head(repo, a.remote, branch)
    pin = state.get("certified")
    if not remote_sha:
        report.findings.append(Finding("sync", f"{a.remote}/{branch}", "branch is missing on the remote"))
    elif not pin:
        report.unverifiable.append("no certified commit recorded in this clone: run publish or certify first")
    elif remote_sha != pin:
        git(repo, "fetch", "--quiet", "--no-tags", a.remote, branch)
        report.findings.append(Finding("sync", f"{a.remote}/{branch}", f"moved to {remote_sha[:8]} since the "
                                       f"certified {pin[:8]}: pushed outside the gate"))
        denylist = load_denylist(repo, a.denylist, a.no_denylist, report)
        run_check(repo, cfg, denylist, report, pin if rev_exists(repo, pin) else None,
                  tip=remote_sha, scan_index=False)
    report.print()
    return report.exit_code()


def cmd_selftest(_a) -> int:
    """Plant one example of every problem in a throwaway repo; every check must catch its own."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        repo.mkdir()
        git(repo, "init", "--quiet")
        git(repo, "config", "user.email", "1+tester@users.noreply.github.com")
        git(repo, "config", "user.name", "tester")
        (repo / "old-notes.txt").write_text("server db.corp.invalid\n", encoding="utf-8")
        git(repo, "add", "-A")
        git(repo, "-c", "user.email=someone@realmail.test", "commit", "-q", "-m", "first")
        (repo / "old-notes.txt").unlink()
        files = {
            "README.md": f"Written by {CANARY}.\n",
            "LICENSE": "MIT\n",
            "keys.txt": "AKIA" + "B" * 16 + "\n",
            "deploy.js": 'const t = "npm_' + "k3x9q2m7v4b8n1c5z6l0p2r8t4w7y1u3h5j9" + '";\n',  # gitleaks-only format
            "setup.md": "cd /home/realperson/project\nmail someone@realmail.test\nssh 10.20.30.40\n",
            ".env": "X=1\n",
            "notes (1).md": "copy\n",
            "nb.ipynb": json.dumps({"cells": [{"outputs": [{"text": "x"}]}]}),
            "index.html": "<html><head><title>x</title></head></html>\n",
        }
        for name, body in files.items():
            (repo / name).write_text(body, encoding="utf-8")
        (repo / "utf16.txt").write_bytes(f"by {CANARY}\n".encode("utf-16"))
        exif = b"Exif\0\0" + b"II*\0" + struct.pack("<I", 8) + struct.pack("<H", 1) + \
            struct.pack("<HHII", 0x8825, 4, 1, 26) + struct.pack("<I", 0)
        (repo / "photo.jpg").write_bytes(b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(exif) + 2) + exif +
                                         b"\xff\xd9")
        (repo / "big.bin").write_bytes(b"\0" * (2 * 1024 * 1024))
        git(repo, "add", "-A")
        cfg = load_config(repo)
        cfg.update(max_file_mb=1, severity={}, internal_domains=["corp.invalid"])
        report = run_check(repo, cfg, [CANARY], Report(), None)
        fired = {f.check for f in report.findings}
        hist = {f.check for f in report.findings if f.where.startswith(("history", "commit"))}
        expected = {"denylist", "secret", "home-path", "email", "private-ip", "forbidden-file", "conflict-copy",
                    "notebook-output", "link-preview", "image-gps", "large-file", "identity"}
        rows = [(c, c in fired) for c in sorted(expected)]
        rows.append(("internal-host (in history)", "internal-host" in hist))
        rows.append(("denylist (UTF-16 file)", any(f.check == "denylist" and "utf16.txt" in f.where
                                                   for f in report.findings)))
        gl = gitleaks_version()
        if gl and gl >= GITLEAKS_MIN:
            rows.append(("secret (through gitleaks)", any(f.check == "secret" and "gitleaks" in f.detail
                                                          for f in report.findings)))
        for label, ok in rows:
            print(f"  {'ok  ' if ok else 'MISS'} {label}")
        problems = [u for u in report.unverifiable if "exiftool" not in u]
        for u in problems:
            print(f"  [UNVERIFIABLE] {u}")
        if not all(ok for _, ok in rows) or problems:
            print("SELFTEST FAILED")
            return EXIT_UNVERIFIABLE
        print("SELFTEST PASSED" + (" (secret detection via gitleaks and the built-in patterns)"
                                   if gitleaks_version() and gitleaks_version() >= GITLEAKS_MIN else ""))
        return EXIT_CLEAN


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except AttributeError:
            pass
    p = argparse.ArgumentParser(prog="publish-gate", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, remote=False):
        sp.add_argument("--repo", default=".", help="path inside the repo (default: current folder)")
        sp.add_argument("--config", help=f"settings file (default: <repo>/{CONFIG_NAME})")
        sp.add_argument("--denylist", help=f"personal tokens file (default: ${DENYLIST_ENV} or {DEFAULT_DENYLIST})")
        sp.add_argument("--no-denylist", action="store_true", help="skip the personal-token search on purpose")
        if remote:
            sp.add_argument("--remote", default="origin")
            sp.add_argument("--branch", help="branch to publish (default: the current branch)")

    sp = sub.add_parser("check", help="scan the publish set and history")
    common(sp)
    sp.add_argument("--since", help="only check history after this commit (default: the certified pin)")
    sp.add_argument("--full-history", action="store_true", help="check every commit, ignoring the pin")
    sp.set_defaults(fn=cmd_check)

    sp = sub.add_parser("publish", help="scope lock, check, review stop, commit, push, certify")
    common(sp, remote=True)
    sp.add_argument("--paths", nargs="+", required=True,
                    help="the only paths this publish may touch, relative to the repo root")
    sp.add_argument("--message", "-m", required=True)
    sp.add_argument("--reviewed", action="store_true", help="you have read the diff it printed")
    sp.add_argument("--first-publish", action="store_true", help="the remote branch does not exist yet")
    sp.set_defaults(fn=cmd_publish)

    sp = sub.add_parser("certify", help="check, review and pin a commit that is already pushed")
    common(sp, remote=True)
    sp.add_argument("--reviewed", action="store_true", help="you have read the diff it printed")
    sp.set_defaults(fn=cmd_certify)

    sp = sub.add_parser("monitor", help="re-check a published repo")
    common(sp, remote=True)
    sp.set_defaults(fn=cmd_monitor)

    sp = sub.add_parser("selftest", help="prove every check fires")
    sp.set_defaults(fn=cmd_selftest)

    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except Refused as e:
        print(f"refused: {e}")
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
