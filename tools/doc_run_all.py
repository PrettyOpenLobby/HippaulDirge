#!/usr/bin/env python3
"""Run every Dirge of Cerberus selftest, and exit non-zero if any fails.

    python tools/doc_run_all.py              # everything
    python tools/doc_run_all.py -k shop      # only suites whose name contains
    python tools/doc_run_all.py -v           # stream each suite's own output
    python tools/doc_run_all.py --e2e        # the loopback end-to-end scripts
    python tools/doc_run_all.py --all        # both groups

The list is explicit, not globbed: a suite that is not registered here does
not exist. Nothing here opens a socket or needs the core beside it; every
suite builds the datagrams the responder sends and reads the fields back at
the offsets the client reads them from.

The end-to-end group (--e2e) is separate and does not run by default: each
script starts a real docudp.py on a loopback port and drives it with
synthetic client datagrams, which takes a few minutes. A script that needs
data you have not generated (README.md, "Arena data") prints a line
starting with "SKIP " and exits 0; it is counted as skipped.

The exception is storage. The stores are tables in the OpenLobby core's
PostgreSQL database (docdb.py), so every suite imports the core's polcore
(found beside this repository, or through OPENLOBBY_SERVICES / OPENLOBBY_DIR),
and a suite that uses a store makes a throwaway database on a PostgreSQL
server (docpg.py: Docker, or POL_TEST_DATABASE_URL). With no server such a
suite reports SKIP, or FAIL when POL_TEST_REQUIRE_DB=1.
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
    # docudp.py forwards every read and write to the docworld module that owns it
    ("docudp_facade",  [PY, "facade_rebind_check.py"]),
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
    # the arena data reader, on a made-up arena file (no game files needed)
    ("doc_extract_arena", [PY, "doc_extract_arena.py", "--selftest"]),
]


#: (name, argv)  -- the loopback end-to-end group, run with --e2e (cwd = tools/)
E2E = [
    # the client socket the scripts use: a send to a closed port, then a receive
    ("doc_e2e_udp",            [PY, "doc_e2e_udp.py"]),
    # a client that closes its socket does not stop the server
    ("doc_connreset_e2e",      [PY, "doc_connreset_e2e.py"]),
    # a battle from table to result screen (and the accounts twin)
    ("doc_battle_e2e",         [PY, "doc_battle_e2e.py"]),
    # leaving and dissolving a table, the leave penalty
    ("doc_battle_leave_e2e",   [PY, "doc_battle_leave_e2e.py"]),
    # the leader's own battle flow
    ("doc_leader_battle_e2e",  [PY, "doc_leader_battle_e2e.py"]),
    # automatic team distribution
    ("doc_autoteam_e2e",       [PY, "doc_autoteam_e2e.py"]),
    # the briefing countdown, the start at 0, the one-sided rebalance
    ("doc_briefing_clock_e2e", [PY, "doc_briefing_clock_e2e.py"]),
    # Team Base battles (skips without doc_arena_table.json)
    ("doc_base_e2e",           [PY, "doc_base_e2e.py"]),
    # Chocobo Coins: drop, pick-up, the cut at the result
    ("doc_coins_e2e",          [PY, "doc_coins_e2e.py"]),
    # the launch medals in the result records
    ("doc_medals_e2e",         [PY, "doc_medals_e2e.py"]),
    # MP and healing in battle
    ("doc_mp_heal_e2e",        [PY, "doc_mp_heal_e2e.py"]),
    # the mission supplies
    ("doc_supplies_e2e",       [PY, "doc_supplies_e2e.py"]),
    # mission NPCs at their spawn nodes (skips without doc_mission_spawns.json)
    ("doc_mission_npc_e2e",    [PY, "doc_mission_npc_e2e.py"]),
    # the launch lobby rules: new characters, RP limits, line drops
    ("doc_launch_e2e",         [PY, "doc_launch_e2e.py"]),
    # the new-player intro and the novice mark
    ("doc_novice_e2e",         [PY, "doc_novice_e2e.py"]),
    # the lobby item quests
    ("doc_npcquest_e2e",       [PY, "doc_npcquest_e2e.py"]),
    # Argento's lines
    ("doc_argento_e2e",        [PY, "doc_argento_e2e.py"]),
    # chat scopes
    ("doc_chat_e2e",           [PY, "doc_chat_e2e.py"]),
    # units in battle, and unit character ids
    ("doc_unit_battle_e2e",    [PY, "doc_unit_battle_e2e.py"]),
    ("doc_unit_charid_e2e",    [PY, "doc_unit_charid_e2e.py"]),
    # the weekly close
    ("doc_weekly_e2e",         [PY, "doc_weekly_e2e.py"]),
    # two consoles behind one address
    ("doc_session_nat",        [PY, os.path.join("..", "tests",
                                                 "test_doc_session_nat.py")]),
]
E2E_NAMES = {name for name, _argv in E2E}
#: an end-to-end script that runs longer than this is stopped and failed
E2E_TIMEOUT_S = 900


def run_e2e(argv, stream):
    """(returncode, stdout, stderr) of one end-to-end script. The output is
    always captured, so a SKIP line can be seen; with `stream` it is printed
    once the script ends."""
    try:
        r = subprocess.run(argv, cwd=HERE, capture_output=True, text=True,
                           encoding="utf-8", errors="replace",
                           env=dict(os.environ, PYTHONIOENCODING="utf-8"),
                           timeout=E2E_TIMEOUT_S)
        rc, out, err = r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired as ex:
        rc = -1
        out = ex.stdout.decode("utf-8", "replace") if isinstance(ex.stdout, bytes) else (ex.stdout or "")
        err = "stopped after %d s" % E2E_TIMEOUT_S
    if stream:
        sys.stdout.write(out)
        sys.stdout.write(err)
    return rc, out, err


def skipped(out):
    return any(line.startswith("SKIP ") for line in out.splitlines())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", default="", help="only suites whose name contains this")
    ap.add_argument("-v", action="store_true", help="stream each suite's output")
    ap.add_argument("--e2e", action="store_true",
                    help="run the loopback end-to-end scripts instead")
    ap.add_argument("--all", action="store_true",
                    help="run the selftests, then the end-to-end scripts")
    a = ap.parse_args()
    group = E2E if a.e2e else SUITES + (E2E if a.all else [])
    chosen = [s for s in group if a.k in s[0]]
    # The stores are PostgreSQL tables: every suite that uses one makes its own
    # empty database (docpg.py). One server serves them all, handed on as
    # POL_TEST_DATABASE_URL, so the run starts at most one container. A
    # POL_DATABASE_URL from this environment never reaches a suite.
    os.environ.pop("POL_DATABASE_URL", None)
    os.environ.pop("DOC_TEST_DATABASE", None)
    sys.path.insert(0, HERE)
    import docpg
    if docpg.server_available():
        os.environ["POL_TEST_DATABASE_URL"] = docpg.pgtest.server_url()
    failed = []
    skips = []
    width = max([16] + [len(name) for name, _argv in chosen])
    for name, argv in chosen:
        t0 = time.time()
        if name in E2E_NAMES:
            rc, out, err = run_e2e(argv, a.v)
            r = subprocess.CompletedProcess(argv, rc, out, err)
        else:
            r = subprocess.run(argv, cwd=HERE, capture_output=not a.v, text=True)
        dt = time.time() - t0
        ok = r.returncode == 0
        skip = ok and name in E2E_NAMES and skipped(r.stdout)
        if skip:
            skips.append(name)
        print("%-*s %s  (%.1fs)" % (width, name, "skip" if skip else
                                    "ok" if ok else "FAIL", dt), flush=True)
        if not ok:
            failed.append(name)
            if not a.v:
                tail = (r.stdout or "").splitlines()[-25:] + (r.stderr or "").splitlines()[-25:]
                for line in tail:
                    print("    " + line)
    print("%d/%d suites passed" % (len(chosen) - len(failed) - len(skips),
                                   len(chosen))
          + (", %d skipped" % len(skips) if skips else ""))
    if skips:
        print("skipped: " + ", ".join(skips))
    if failed:
        print("failed: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
