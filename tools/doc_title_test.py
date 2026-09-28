#!/usr/bin/env python3
"""The Dirge of Cerberus title plugin: the Viewer's profile out of the responder's files.

    python tools/doc_title_test.py

Needs the OpenLobby core checked out beside this repository (or OPENLOBBY_DIR
pointing at it) for `titles.py`. Offline; writes the two files in a temp
directory.
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPENLOBBY = os.environ.get("OPENLOBBY_DIR", os.path.join(ROOT, os.pardir, "openlobby"))
sys.path.insert(0, os.path.join(OPENLOBBY, "services"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

TMP = tempfile.mkdtemp(prefix="doc-title-")
CHARS = os.path.join(TMP, "doc-characters.json")
STATS = os.path.join(TMP, "doc-stats.json")
os.environ["POL_DOC_CHARA_STORE"] = CHARS
os.environ["POL_DOC_STATS"] = STATS

import titles          # noqa: E402
import doctitle        # noqa: E402

MEMBER = 7
CID = 30000010
FAILS = []


def check(ok, label, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  --  {detail}" if detail else ""))
    if not ok:
        FAILS.append(label)


def dump(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)


def main():
    t = doctitle.register()
    check(titles.for_code(10) is t, "registers as content code 10")
    check(titles.profile_fields(10, CID, MEMBER) == {},
          "no files yet: nothing, not a guess")

    dump(CHARS, {f"member:{MEMBER}": [{"slot": 1, "name": "Vincent"},
                                       {"slot": 0, "name": ""},
                                       {"slot": 2, "name": "Cid"}]})
    f = titles.profile_fields(10, CID, MEMBER)
    check(f == {doctitle.SLOT_NAME: "Vincent"},
          "the lowest-slot NAMED character; no stats file, so no rank", repr(f))

    dump(STATS, {"chars": {f"member:{MEMBER}/1": {"name": "Vincent", "rank": 4, "rp": 120},
                           f"member:{MEMBER}/2": {"name": "Cid", "rank": 9, "rp": 5},
                           "member:99/1": {"name": "Vincent", "rank": 16, "rp": 1}}})
    f = titles.profile_fields(10, CID, MEMBER)
    check(f == {doctitle.SLOT_NAME: "Vincent", doctitle.SLOT_RANK: 4,
                doctitle.SLOT_RANKPOINT: 120},
          "rank and ranking points from THIS member's career for that name", repr(f))

    dump(STATS, {"chars": {f"member:{MEMBER}/1": {"name": "Vincent", "rank": 40, "rp": -3}}})
    f = titles.profile_fields(10, CID, MEMBER)
    check(f.get(doctitle.SLOT_RANK) == 16 and f.get(doctitle.SLOT_RANKPOINT) == 0,
          "rank clamps to the 16-rung ladder, points to zero")
    check(titles.profile_fields(10, CID, None) == {}, "no member id: nothing")

    print()
    if FAILS:
        print(f"FAILED: {len(FAILS)}: " + ", ".join(FAILS))
        return 1
    print("all Dirge of Cerberus title checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
