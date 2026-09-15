#!/usr/bin/env python3
"""Repository hygiene scanner. Exits non-zero if the tree contains anything
that must not ship: private network addresses, deployment-specific hostnames,
known private identifiers (checked as salted hashes so this file does not
republish them), secret-shaped strings, proprietary game-data file types, or
editorial markers that do not belong in a public tree.

Run from the repository root:  python check.py
Positive control (proves the scanner can fail): python check.py --selftest
"""
import hashlib
import os
import re
import subprocess
import sys
import tempfile

# survive legacy Windows console codepages when printing findings
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules"}
SKIP_FILES = {"check.py"}
TEXT_EXT = {".py", ".md", ".yaml", ".yml", ".tsv", ".conf", ".sh", ".txt",
            ".html", ".js", ".css", ".json", ".ini", ".cfg", ".sql", ""}

# File types that are never acceptable in this repository: proprietary
# game/portal formats that would mean extracted client or portal content.
BANNED_EXT = {".pml", ".ang", ".pcb", ".slc", ".p2s", ".pms", ".dat",
              ".woff", ".woff2", ".ttf", ".otf"}

PATTERNS = [
    ("private-ip-192.168", re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b")),
    ("private-ip-10.x", re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")),
    # 172.17.x / 172.18.x are Docker's default bridge networks and appear in
    # comments explaining container networking; the rest of 172.16/12 is
    # treated as potentially site-specific.
    ("private-ip-172.16-31",
     re.compile(r"\b172\.(16|19|2\d|3[01])\.\d{1,3}\.\d{1,3}\b")),
    ("cgnat-100.64-127",
     re.compile(r"\b100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b")),
    ("discord-token",
     re.compile(r"\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}\b")),
    ("discord-webhook", re.compile(r"discord\.com/api/webhooks/\d{6,}")),
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("status-emoji", re.compile("[\U0001F7E2\U0001F7E1\U0001F534\U0001F511"
                                "⚠⛔✅\U0001F9E9❌]")),
    # the literal character, the HTML entities, and source-escape spellings
    ("em-dash", re.compile(r"—|&mdash;|&#8212;|\\u2014")),
]

# Known private identifiers, stored as sha256(salt + lowercase token) so the
# scanner does not itself contain them. Tokens are words split on
# [^a-z0-9.@-]. Regenerating this list requires the private dev project.
SALT = b"openlobby-denylist-v1:"
DENY_HASHES = {
    # one hash per denied token: private handles, account ids, login tokens,
    # hostnames, member guids, and editorial markers that must not ship;
    # regenerating the list requires the private source
    "bd93530013bec5be22d2f639ccb05c76a16e0baa4bd4a24269d917672e22782f",
    "bd6be2c95b423903d5315a4e6e00f2e541b5eb869a9a6ea00c009ee932f1679b",
    "4036ec91794b64dbbbbc10e583617781f56b2e92adace31b1c732707fc025c59",
    "68be269c45260a214313886aab150838f08d45f00b9a7e4bc5fd3f6e4f693179",
    "8dc77fe9c2c5368f17c645b58b62cee7c3388f18e2f54b3342f8b71cdbba081d",
    "81507987fa546420ba2d0a7c942dffcf429fb3b43a322a0440a48b1a33136590",
    "647060913b7821e31f6023da05b5f9dcaed0dcaebe390e3dc9e3c31abca6eca0",
    "32468dcc3076fadebee76f99baff5409198f8a11e44913791e29bcd23601b3ab",
    "07340f819c18bbff71c8438469549029cdb95a9a06cd01e3213e8d344ce905a6",
    "7d1e600c7ff8a46ce84c255abeb553451b6ca80bf3beaf39be0b24848fcce5eb",
    "9999052197f2db91791bf8375f5c476e6828140d0a7bb2088c7d503c6d243ca6",
    "c80c84e8b9b971122d6641fb64cf0289b714806adbf5d593a3142e432a89bd17",
    "f63f766cadd1eada26f8dda51789828f81731177090ad6e196033987ef0f2808",
    "713d5e0e3b26caf0275b73e9010ddcb57c84bd2d7e87a565733087adbbf1fe2e",
    "fd8150bcea63e250b67714c2835e0c0c5b9e7e4edd731f851cc2e5065a3d4e03",
    "6c0161fa2d75054853ea61bb9f15b7b7462213ecd974877d5a70ccc185bf887e",
    "be6c91843a61dfec36ca04ce7837f783e63656a871f4a9d83cfbdaff3305bdc8",
    "5f89a277d4ddf23c65733f59f722e598eada06a19a3155fff55bc237de617849",
    "984f000d781002a9fb62b8b06b607e7c70f45b93391e343b45c0026e913f074f",
    "5268d2e9cf01c7c3d41d167f6416bd9ff213a3246009542cf8762408f48c9c8d",
    "5f92edbb293b9247b71ed124149fb25d3156e8c9ecd47ac8bf693a02034a39ff",
    "aa7730863dc84983eefd34c7fcbfa9a3b078eed93baf745d243eaa1b871bc9d3",
    "a451ad959198067398ac33f9165ee458cf4c65bdc9bd667337bde4bf7945c066",
    "e4ce8148b8b2656929244201de35e644fefda70b4429ce546fa68b1004c26c6d",
    "ed29eefe29b67e1eca9be7d79ec78ab8e4eab500b21e89a44990abb7b224c2a8",
    "7983f25d2f3500f87a93f812147cb180e99c5fa292359f213469bd82028ec503",
    "f6398758453383ec41b215c40cff0ca7bd8fe13c4ff56c270cc1f5fa443c1eac",
    "c90110b3b5ebd3eb9a9d37fa5d8a20ed33ef7683c7f0f61d0354717508751df4",
    "cca77121e651deff5cf6e4799e6f68de52f511b6cb6d976b4efbbc1f11bb50b3",
    "86b73af426705e9ff4af232586d806b035e90cd36931da0ae30719faff7e79eb",
}
TOKEN_RE = re.compile(r"[a-z0-9.@-]{3,64}")


def denied(token):
    return hashlib.sha256(SALT + token.encode()).hexdigest() in DENY_HASHES


def git_ignored(root):
    """The paths under `root` that git ignores (relative, OS separators), or
    an empty set when `root` is not a work tree or git is not installed. An
    ignored file (a local .env, a build product) can never be committed, so
    it is not the repository's content and is not scanned."""
    try:
        out = subprocess.run(
            ["git", "-C", root, "ls-files", "-z", "--others", "--ignored",
             "--exclude-standard"],
            capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return set()
    return {os.path.normpath(p.decode("utf-8", "replace"))
            for p in out.split(b"\0") if p}


def scan_tree(root):
    findings = []
    ignored = git_ignored(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            rel = os.path.relpath(os.path.join(dirpath, fn), root)
            if rel in ignored:
                continue
            if fn in SKIP_FILES and os.path.dirname(rel) == "":
                continue
            ext = os.path.splitext(fn)[1].lower()
            if ext in BANNED_EXT:
                findings.append((rel, 0, "banned-file-type", ext))
                continue
            if ext not in TEXT_EXT and not fn.startswith("Dockerfile"):
                continue
            try:
                with open(os.path.join(dirpath, fn), encoding="utf-8") as fh:
                    text = fh.read()
            except (UnicodeDecodeError, OSError):
                findings.append((rel, 0, "undecodable", ""))
                continue
            for i, line in enumerate(text.splitlines(), 1):
                # explicit per-line waiver for documented false positives
                # (e.g. an in-game constant that merely looks like an IP)
                if "polcheck: allow" in line:
                    continue
                for name, pat in PATTERNS:
                    m = pat.search(line)
                    if m:
                        findings.append((rel, i, name, m.group(0)[:40]))
                if DENY_HASHES:
                    toks = set(TOKEN_RE.findall(line.lower()))
                    for tok in list(toks):
                        toks.update(p for p in re.split(r"[-.@]", tok) if len(p) >= 3)
                    for tok in sorted(toks):
                        if denied(tok):
                            findings.append((rel, i, "denied-identifier",
                                             tok[:2] + "..."))
    return findings


PLANTS = {
    "private-ip-192.168": "server = '192.168.50.4'\n",
    "cgnat-100.64-127": "peer = '100.64.9.9'\n",
    "discord-webhook": "u = 'https://discord.com/api/webhooks/1234567/x'\n",
    "private-key-block": "-----BEGIN RSA PRIVATE KEY-----\n",
    "denied-identifier": "# polcheck-canary-2f9c\n",
    "status-emoji": "# \U0001F7E2 works\n",
    "em-dash": "# a — b\n",
    "banned-file-type": ("planted.pml", "<pml>\n"),
}


def _ignored_control():
    """A finding in a gitignored file is not the repository's. Plant the same
    address in a tracked-to-be file and in an ignored one inside a scratch
    git repository; exactly the first must be reported. None = git missing."""
    with tempfile.TemporaryDirectory() as td:
        try:
            subprocess.run(["git", "-C", td, "init", "-q"], check=True,
                           capture_output=True)
        except (OSError, subprocess.CalledProcessError):
            return None
        with open(os.path.join(td, ".gitignore"), "w", encoding="utf-8") as fh:
            fh.write(".env\n")
        for name in (".env", "planted.py"):
            with open(os.path.join(td, name), "w", encoding="utf-8") as fh:
                fh.write(PLANTS["private-ip-192.168"])
        found = {f for f, _l, k, _m in scan_tree(td) if k == "private-ip-192.168"}
        return found == {"planted.py"}


def selftest():
    ok = True
    with tempfile.TemporaryDirectory() as td:
        for kind, plant in PLANTS.items():
            name, body = plant if isinstance(plant, tuple) else ("planted.py", plant)
            p = os.path.join(td, name)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(body)
            hits = {k for _f, _l, k, _m in scan_tree(td)}
            if kind in hits:
                print(f"  control {kind:24} CAUGHT")
            else:
                print(f"  control {kind:24} MISSED  <- scanner is broken")
                ok = False
            os.remove(p)
    r = _ignored_control()
    kind = "ignored-file-skipped"
    if r is None:
        print(f"  control {kind:24} NOT RUN  <- git is not installed")
        ok = False
    elif r:
        print(f"  control {kind:24} CAUGHT")
    else:
        print(f"  control {kind:24} MISSED  <- scanner is broken")
        ok = False
    return ok


def main():
    if "--selftest" in sys.argv:
        print("planting one bad file per class; each must be caught:")
        sys.exit(0 if selftest() else 1)
    root = os.path.dirname(os.path.abspath(__file__))
    findings = scan_tree(root)
    if findings:
        for rel, line, kind, m in findings:
            print(f"{rel}:{line}: {kind}: {m}")
        print(f"FAIL: {len(findings)} finding(s)")
        sys.exit(1)
    print("clean")


if __name__ == "__main__":
    main()
