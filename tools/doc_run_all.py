#!/usr/bin/env python3
"""Run every Dirge of Cerberus selftest, and exit non-zero if any fails.

    python tools/doc_run_all.py              # everything
    python tools/doc_run_all.py -k shop      # only suites whose name contains
    python tools/doc_run_all.py -v           # stream each suite's own output

The list is explicit, not globbed: a suite that is not registered here does
not exist. Nothing here opens a socket or needs the core beside it; every
suite builds the datagrams the responder sends and reads the fields back at
the offsets the client reads them from.
"""
import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")
PY = sys.executable

#: (name, argv)  -- all run with cwd = tools/
SUITES = [
    # the cipher: the published Twofish known-answer test, then packets of
    # every mode and length round-tripped through header()
    ("doc_kelcrypt",   [PY, "doc_kelcrypt.py", "--selftest"]),
    # every MEASURED byte offset the responder ships, checked on the wire
    ("doc_udp",        [PY, "doc_udp_test.py"]),
    # the per-player character store: parse a REGISTER, persist it, serve it
    ("doc_charastore", [PY, "doc_charastore.py"]),
    # career stats: the battle tally, the medal rules, the exam ladder
    ("doc_stats",      [PY, "doc_stats.py"]),
    # the title plugin: the Viewer's profile out of the character and stats files
    ("doc_title",      [PY, "doc_title_test.py"]),
    # play time (lobby command 20) accrual and the player search
    ("doc_playtime",   [PY, "doc_playtime.py"]),
    # lobby NPC conversations: the quest-event tables and the 26/27/39 answers
    ("doc_npc",        [PY, "doc_npc.py"]),
    # lobby NPC push: notify kind 15 entries (placement checks need your table)
    ("doc_npc_spawn",  [PY, "doc_npc_spawn.py"]),
    # the shop: stock, buy, sell, recipes, the per-character wallet and bag
    ("doc_shop",       [PY, "doc_shop.py"]),
    # rankings: the 137/149 answers
    ("doc_rank",       [PY, "doc_rank.py"]),
    # units (the friend-list groups registered with the game)
    ("doc_unit",       [PY, "doc_unit.py"]),
    # equipped mask and armour on the world door
    ("doc_gear",       [PY, "doc_gear.py"]),
    # player-to-player trade relay
    ("doc_trade",      [PY, "doc_trade.py"]),
    # Mission Mode: the per-player mission ledger, exams, objectives, supplies
    ("doc_missions",   [PY, "doc_missions.py"]),
    # the new-player intro and the novice mark
    ("doc_novice",     [PY, "doc_novice.py"]),
    # the lobby item quests (Soar, Este-D, Hiren) and Sturm's lines
    ("doc_npcquests",  [PY, "doc_npcquests.py"]),
    # the quest reward notice block
    ("doc_reward",     [PY, "doc_reward.py"]),
    # the MP ledger (magic casts, refills)
    ("doc_magic",      [PY, "doc_magic.py"]),
    # item use answers and MP points
    ("doc_items",      [PY, "doc_items.py"]),
    # arena item generators (checks against the arena data need your table)
    ("doc_field",      [PY, "doc_field.py"]),
    # chat relay: say / shout / tell / entry / team scopes
    ("doc_chat",       [PY, "doc_chat.py"]),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", default="", help="only suites whose name contains this")
    ap.add_argument("-v", action="store_true", help="stream each suite's output")
    a = ap.parse_args()
    chosen = [s for s in SUITES if a.k in s[0]]
    failed = []
    for name, argv in chosen:
        t0 = time.time()
        r = subprocess.run(argv, cwd=HERE, capture_output=not a.v, text=True)
        dt = time.time() - t0
        ok = r.returncode == 0
        print("%-16s %s  (%.1fs)" % (name, "ok" if ok else "FAIL", dt), flush=True)
        if not ok:
            failed.append(name)
            if not a.v:
                tail = (r.stdout or "").splitlines()[-25:] + (r.stderr or "").splitlines()[-25:]
                for line in tail:
                    print("    " + line)
    print("%d/%d suites passed" % (len(chosen) - len(failed), len(chosen)))
    if failed:
        print("failed: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
