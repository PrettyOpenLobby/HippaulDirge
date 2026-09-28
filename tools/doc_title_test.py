#!/usr/bin/env python3
"""The Dirge of Cerberus title plugin: the Viewer's profile out of the responder's tables.

    python tools/doc_title_test.py

Needs the OpenLobby core checked out beside this repository (or OPENLOBBY_DIR
pointing at it) for `titles.py`, and a PostgreSQL server for the character and
career tables (docpg.py: Docker, or POL_TEST_DATABASE_URL).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPENLOBBY = os.environ.get("OPENLOBBY_DIR", os.path.join(ROOT, os.pardir, "openlobby"))
sys.path.insert(0, os.path.join(OPENLOBBY, "services"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import titles          # noqa: E402
import docpg           # noqa: E402
import doctitle        # noqa: E402

MEMBER = 7
CID = 30000010
FAILS = []


def check(ok, label, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  --  {detail}" if detail else ""))
    if not ok:
        FAILS.append(label)


def main():
    docpg.need_database("doc_title")
    docpg.reset("characters")
    docpg.reset("stats")
    t = doctitle.register()
    check(titles.for_code(10) is t, "registers as content code 10")
    check(titles.profile_fields(10, CID, MEMBER) == {},
          "no rows yet: nothing, not a guess")

    docpg.seed("characters", {f"member:{MEMBER}": [{"slot": 1, "name": "Vincent"},
                                       {"slot": 0, "name": ""},
                                       {"slot": 2, "name": "Cid"}]})
    f = titles.profile_fields(10, CID, MEMBER)
    check(f == {doctitle.SLOT_NAME: "Vincent"},
          "the lowest-slot NAMED character; no career, so no rank", repr(f))

    docpg.seed("stats", {"chars": {f"member:{MEMBER}/1": {"name": "Vincent", "rank": 4, "rp": 120},
                                   f"member:{MEMBER}/2": {"name": "Cid", "rank": 9, "rp": 5},
                                   "member:99/1": {"name": "Vincent", "rank": 16, "rp": 1}}})
    f = titles.profile_fields(10, CID, MEMBER)
    check(f == {doctitle.SLOT_NAME: "Vincent", doctitle.SLOT_RANK: 4,
                doctitle.SLOT_RANKPOINT: 120},
          "rank and ranking points from THIS member's career for that name", repr(f))

    docpg.seed("stats", {"chars": {f"member:{MEMBER}0/1": {"name": "Vincent", "rank": 15, "rp": 2}}})
    f = titles.profile_fields(10, CID, MEMBER)
    check(f == {doctitle.SLOT_NAME: "Vincent"},
          "member 70's career is not member 7's (its key starts with member:7)",
          repr(f))

    docpg.seed("stats", {"chars": {f"member:{MEMBER}/1": {"name": "Vincent", "rank": 40, "rp": -3}}})
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
