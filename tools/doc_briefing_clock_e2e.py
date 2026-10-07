#!/usr/bin/env python3
"""End-to-end: the battle starts when the BRIEFING COUNTDOWN the players see
reaches 0. Before, a 5:00 briefing started 0:35 in, 25 s after the first
team step.

The client counts the table record's Briefing Time (wire+111, minutes) down
from its selector-38 BATTLE READY and does nothing at zero; the start (kind 20,
the distribution) is ours. Runs the real docudp on loopback with a 1-"minute"
briefing shortened by --gs-briefing-minute=6 (so the countdown is 6 s):

  1. two players on opposite teams at once -> kind 20 NOT before 6 s, then yes
  2. TWIN, --gs-no-briefing-clock          -> kind 20 within ~2 s (the old bug)
  3. solo, steps on a team at once        -> kind 20 2 s after the step
                                             (--gs-battle-after-join): a solo
                                             table does not wait for the
                                             countdown (live 09-28, "stuck in
                                             briefing" on Beginner's Course)
  4. solo, NEVER steps on a team          -> still starts (auto-team)
  5. two players BOTH on team 0            -> rebalanced at 0, kind 20
  6. TWIN, --gs-no-rebalance               -> stuck, no kind 20 (the stall)

    python doc_briefing_clock_e2e.py
"""
import io
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import docudp as D                                          # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening  # noqa: E402
import doc_battle_e2e as E                                  # noqa: E402

FAILS = []
BRIEF_S = 6.0


def check(name, cond, detail=""):
    print("  %s  %s%s" % ("ok" if cond else "FAIL", name,
                          (" -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


def is_kind20(p):
    return (len(p) >= D.BODY_OFF + 16
            and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 35
            and struct.unpack_from("<I", p, D.BODY_OFF + 12)[0] == 20)


def run(tag, extra=(), solo=False, step=True, span=11.0, b_team=1, maximum=4):
    """-> (log text, seconds after START of the first kind 20 to A, to B)."""
    log_path = os.path.join(os.environ.get("TEMP", HERE),
                            "doc_briefing_clock_e2e_%s.log" % tag)
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(E.PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--bt-no-onfly-reserve",
            "--gs-real-dist-settle=1", "--gs-battle-after-join=2",
            "--session-idle-drop=0", "--intro=off",
            "--gs-auto-team-after=3",
            "--gs-briefing-minute=%g" % BRIEF_S] + list(extra)
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    first = {"A": None, "B": None}
    try:
        wait_listening(log, srv)
        check("[%s] docudp is up" % tag, srv.poll() is None)
        dst = ("127.0.0.1", E.PORT)
        ca = udp_socket()
        cb = udp_socket()
        for c in (ca, cb):
            c.bind(("127.0.0.1", 0))
            c.settimeout(0.05)

        def drain(sock):
            got = []
            try:
                while True:
                    got.append(sock.recv(65535))
            except socket.timeout:
                pass
            return got

        rec = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                                   maximum=maximum, map_idx=0, mode=1,
                                                   comment="e2e"))
        rec[D.BT_OFF_BRIEFING] = 1          # Briefing Time: 1 minute
        ca.sendto(E.world_req(E.A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.5)
        drain(ca)
        if not solo:
            cb.sendto(E.world_req(E.B_CID, D.BT_REQ_JOIN, struct.pack("<H", 1)),
                      dst)
            time.sleep(0.5)
            drain(cb)
        ca.sendto(E.world_req(E.A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                              struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        t0 = time.time()
        time.sleep(0.3)
        drain(ca)
        drain(cb)
        if step:
            ca.sendto(E.gs_req(E.A_CID, 31, arg=0, session=1), dst)
            if not solo:
                cb.sendto(E.gs_req(E.B_CID, 31, arg=b_team, session=1), dst)
        while time.time() - t0 < span:
            ca.sendto(E.gs_req(E.A_CID, 1, session=1), dst)
            if not solo:
                cb.sendto(E.gs_req(E.B_CID, 1, session=1), dst)
            end = time.time() + 0.25
            while time.time() < end:
                for who, sock in (("A", ca), ("B", cb)):
                    for p in drain(sock):
                        if is_kind20(p) and first[who] is None:
                            first[who] = time.time() - t0
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
            srv.wait()          # until it has exited it still holds the port
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check("[%s] no traceback in the server log" % tag, "Traceback" not in text,
          log_path)
    return text, first["A"], first["B"], log_path


def fmt(t):
    return "never" if t is None else "%.1f s" % t


def main():
    # 2026-10-01, manual p.30: "when every member is ready, or the time limit
    # runs out" -- the default (--briefing-start ready)
    print("run 1: two players, opposite teams at once, 6 s briefing")
    text, ta, tb, lp = run("2p")
    check("log: the Start announced the briefing countdown",
          "briefing countdown 6 s" in text, lp)
    check("kind 20 reached both clients", ta is not None and tb is not None,
          "A %s, B %s" % (fmt(ta), fmt(tb)))
    check("everyone ready: kind 20 BEFORE the countdown ends (manual p.30)",
          ta is not None and ta < BRIEF_S - 2 and tb is not None
          and tb < BRIEF_S - 2, "A %s, B %s" % (fmt(ta), fmt(tb)))

    # TWIN: the 09-29 rule (--briefing-start full) waits out the countdown
    # for a table that is not full
    print("run 1c: TWIN -- --briefing-start=full, two of four seats")
    text, ta, tb, lp = run("2p_fullrule", extra=("--briefing-start=full",))
    check("TWIN (full rule): kind 20 NOT before the countdown ends (>= %.0f s)"
          % BRIEF_S, ta is not None and ta >= BRIEF_S and tb is not None
          and tb >= BRIEF_S, "A %s, B %s" % (fmt(ta), fmt(tb)))
    check("TWIN (full rule): kind 20 soon after it (< %.0f s)" % (BRIEF_S + 3),
          ta is not None and ta < BRIEF_S + 3, fmt(ta))

    # 2026-09-29: a table FULL of ready players (2 of a 2-player
    # limit) starts without waiting out the countdown
    print("run 1b: two players at a FULL 2-player table")
    text, ta, tb, lp = run("2p_full", maximum=2)
    check("FULL table: kind 20 reached both, BEFORE the countdown ends",
          ta is not None and tb is not None and ta < BRIEF_S - 2
          and tb < BRIEF_S - 2, "A %s, B %s" % (fmt(ta), fmt(tb)))

    print("run 2: TWIN -- --gs-no-briefing-clock (the old start)")
    text, ta, tb, lp = run("2p_twin", extra=("--gs-no-briefing-clock",))
    check("TWIN: kind 20 goes out long before the countdown ends (the bug)",
          ta is not None and ta < BRIEF_S - 2, fmt(ta))

    print("run 3: solo, steps on a team at once")
    text, ta, _, lp = run("solo", solo=True)
    check("log: a solo Start holds no briefing countdown",
          "briefing countdown" not in text, lp)
    check("solo: kind 20 ~2 s after the step, well before the countdown",
          ta is not None and ta < BRIEF_S - 2, fmt(ta))

    print("run 4: solo, NEVER steps on a team")
    text, ta, _, lp = run("solo_nostep", solo=True, step=False, span=13.0)
    check("log: the solo player was started without a team",
          "SOLO 0x%x never chose a team" % E.A_CID in text, lp)
    check("solo, no step: kind 20 still arrives",
          ta is not None, fmt(ta))

    print("run 5: two players BOTH on team 0 (a one-sided table)")
    text, ta, tb, lp = run("onesided", b_team=0)
    check("log: REBALANCED B onto team 1 at the end of the briefing",
          ("REBALANCED 0x%x -> team 1" % E.B_CID) in text, lp)
    check("one-sided: kind 20 to both, at the countdown (not stuck)",
          ta is not None and tb is not None and BRIEF_S <= ta < BRIEF_S + 3,
          "A %s, B %s" % (fmt(ta), fmt(tb)))

    print("run 6: TWIN -- both on team 0 with --gs-no-rebalance")
    text, ta, tb, lp = run("onesided_twin", b_team=0,
                           extra=("--gs-no-rebalance",))
    check("TWIN: no rebalance, no kind 20 -- the stall",
          "REBALANCED" not in text and ta is None and tb is None,
          "A %s, B %s" % (fmt(ta), fmt(tb)))

    print()
    if FAILS:
        print("FAILED %d: %s" % (len(FAILS), "; ".join(FAILS)))
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
