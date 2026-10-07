#!/usr/bin/env python3
"""End-to-end: a joiner who never chooses a team is AUTO-TEAMED when the
briefing time runs out, and the distribution goes out (live: the
joiner's client sent only keepalives, the leader's countdown hit 0 and nothing
started).

Runs the real docudp on loopback twice with doc_battle_e2e's two clients:
  A CREATE -> B JOIN -> A START -> A picks team 1 -> B sends ONLY keepalives
  1. --gs-auto-team-after=3  -> B auto-teamed to 0, kind 20 to both
  2. --gs-auto-team-after=-1 -> the TWIN: no kind 20 (the live bug)

    python doc_autoteam_e2e.py
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


def check(name, cond, detail=""):
    print("  %s  %s%s" % ("ok" if cond else "FAIL", name,
                          (" -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


def kind(pkts, k):
    return [p for p in pkts if len(p) >= D.BODY_OFF + 16
            and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 35
            and struct.unpack_from("<I", p, D.BODY_OFF + 12)[0] == k]


def kind20(pkts):
    return kind(pkts, 20)


def msg(pkts, m):
    return [p for p in pkts if len(p) >= D.BODY_OFF + 2
            and struct.unpack_from("<H", p, D.BODY_OFF)[0] == m]


def run(auto_after, extra=(), a_leaves=False, solo=False, go=False):
    log_path = os.path.join(os.environ.get("TEMP", HERE),
                            "doc_autoteam_e2e_%s.log" % auto_after)
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(E.PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--bt-no-onfly-reserve",
            "--gs-real-dist-settle=1", "--gs-battle-after-join=60",
            "--session-idle-drop=0", "--intro=off",
            "--gs-auto-team-after=%s" % auto_after] + list(extra)
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    got_a, got_b = [], []
    try:
        wait_listening(log, srv)
        check("docudp is up", srv.poll() is None)
        dst = ("127.0.0.1", E.PORT)
        ca = udp_socket()
        cb = udp_socket()
        for c in (ca, cb):
            c.bind(("127.0.0.1", 0))
            c.settimeout(0.3)

        def drain(sock):
            got = []
            try:
                while True:
                    got.append(sock.recv(65535))
            except socket.timeout:
                pass
            return got

        rec = bytes(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                               maximum=4, map_idx=0, mode=1,
                                               comment="e2e"))
        ca.sendto(E.world_req(E.A_CID, D.BT_REQ_CREATE, rec), dst)
        time.sleep(0.5)
        drain(ca)
        if not solo:
            cb.sendto(E.world_req(E.B_CID, D.BT_REQ_JOIN, struct.pack("<H", 1)),
                      dst)
            time.sleep(0.5)
            drain(cb)
        ca.sendto(E.world_req(E.A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                              struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.6)
        drain(ca)
        drain(cb)
        # A stands on team 1 (like the live leader); B only keeps alive
        ca.sendto(E.gs_req(E.A_CID, 31, arg=1, session=1), dst)
        for _ in range(3 if solo else 8):
            if not solo:
                cb.sendto(E.gs_req(E.B_CID, 1, session=1), dst)
            ca.sendto(E.gs_req(E.A_CID, 1, session=1), dst)
            time.sleep(0.5)
            got_a += drain(ca)
            got_b += drain(cb)
        if a_leaves:
            # A steps OFF its space: leaveTeam = request 33
            ca.sendto(E.gs_req(E.A_CID, 33, session=1), dst)
        time.sleep(1.0)
        got_a += drain(ca)
        got_b += drain(cb)
        if go:
            # 2026-10-03 (live, table 7): both leave the briefing room
            # (request 47) and wait out the shared GO. B never sent 31.
            ca.sendto(E.gs_req(E.A_CID, 47, session=1), dst)
            cb.sendto(E.gs_req(E.B_CID, 47, session=1), dst)
            for _ in range(8):
                ca.sendto(E.gs_req(E.A_CID, 1, session=1), dst)
                cb.sendto(E.gs_req(E.B_CID, 1, session=1), dst)
                time.sleep(0.5)
                got_a += drain(ca)
                got_b += drain(cb)
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
            srv.wait()          # until it has exited it still holds the port
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check("no traceback in the server log", "Traceback" not in text)
    return text, got_a, got_b, log_path


def main():
    print("run 1: --gs-auto-team-after=3")
    text, pa, pb, lp = run(3, extra=["--gs-battle-go-after=1"], go=True)
    ka, kb = kind20(pa), kind20(pb)
    check("A (sent 31) gets the battle START (kind 5)", kind(pa, 5),
          "A %d" % len(kind(pa, 5)))
    check("B (AUTO-TEAMED, never sent 31) gets the battle START (kind 5)",
          kind(pb, 5), lp)
    check("log: B was AUTO-TEAMED onto team 0",
          ("AUTO-TEAMED 0x%x -> team 0" % E.B_CID) in text, lp)
    check("log: the REAL distribution went out",
          "SENT notify 20 (PLAYER DISTRIBUTION) over the REAL" in text, lp)
    # 2026-10-03 (live: TEAM battles, only the leader hit): before the 20,
    # each client gets a kind 31 naming the OTHER member WITH its team
    def add31(pkts, other, team):
        idx31 = [i for i, p in enumerate(pkts)
                 if len(p) >= D.BODY_OFF + 48
                 and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 35
                 and struct.unpack_from("<I", p, D.BODY_OFF + 12)[0] == 31
                 and struct.unpack_from("<I", p, D.BODY_OFF + 20)[0] == other
                 and p[D.BODY_OFF + 42] >> 4 == team]
        idx20 = [i for i, p in enumerate(pkts) if p in kind20(pkts)]
        return bool(idx31 and idx20 and idx31[0] < idx20[0])
    check("A gets kind 31 {B, team 0} BEFORE its kind 20", add31(pa, E.B_CID, 0), lp)
    check("B gets kind 31 {A, team 1} BEFORE its kind 20", add31(pb, E.A_CID, 1), lp)
    check("kind 20 reached BOTH clients", ka and kb,
          "A %d, B %d" % (len(ka), len(kb)))
    # B never sent 31 -> re-armed on keepalives
    check("B (no team request) is RE-ARMED on its keepalives",
          ("no team request from 0x%08x" % E.B_CID) in text
          and len(msg(pb, D.GS_ARM_MSG)) >= 1, lp)
    check("A (sent 31) is NOT re-armed on its keepalives",
          ("no team request from 0x%08x" % E.A_CID) not in text, lp)
    # the other player's team reaches B as a KIND 0 (a kind 31 never moves a
    # count); the 31s come only with the distribution, after the briefing
    check("A's team reaches B as kind 0 (first sight); the only kind 31 is "
          "the distribution's",
          ("SENT notify 0 (set team) 0x%08x -> team 1 -> 0x%08x's briefing "
           "(first sight)" % (E.A_CID, E.B_CID)) in text
          and kind(pb, 0) and len(kind(pb, 31)) == 1, lp)
    print("run 1b (TWIN): the same with --gs-add-chara-before-dist=off")
    text, pa, pb, lp = run(3, extra=["--gs-add-chara-before-dist=off"])
    check("TWIN: no kind 31 to either client, the 20 still goes out",
          not kind(pa, 31) and not kind(pb, 31) and kind20(pa) and kind20(pb), lp)
    print("run 2 (TWIN): --gs-auto-team-after=-1 --no-gs-rearm-until-team, "
          "A steps off its space")
    text, pa, pb, lp = run(-1, extra=["--no-gs-rearm-until-team"],
                           a_leaves=True)
    ka, kb = kind20(pa), kind20(pb)
    check("TWIN: no keepalive re-arm with --no-gs-rearm-until-team",
          "no team request from" not in text, lp)
    check("request 33 -> kind 1 (leave team) for A reaches B",
          ("SENT notify 1 (leave team) 0x%08x -> 0x%08x's briefing"
           % (E.A_CID, E.B_CID)) in text and kind(pb, 1), lp)
    check("TWIN: no auto-team", "AUTO-TEAMED" not in text, lp)
    check("TWIN: the table stalls on 'no team yet' (the live bug)",
          ("no team yet for 0x%x" % E.B_CID) in text, lp)
    check("TWIN: no kind 20 to anyone", not ka and not kb)
    print("run 3: SOLO table (live '1-member MS: Ready 0 player(s)')")
    text, pa, pb, lp = run(-1, a_leaves=True, solo=True)
    check("solo: request 31 -> kind 0 (set team) to ITSELF",
          ("solo: SENT notify 0 (set team) 0x%08x -> team 1 to ITSELF" % E.A_CID)
          in text and kind(pa, 0), lp)
    check("solo: request 33 -> kind 1 (leave team) to ITSELF",
          ("solo: SENT notify 1 (leave team) 0x%08x to ITSELF" % E.A_CID) in text
          and kind(pa, 1), lp)
    print("run 4 (TWIN): the same solo table with --gs-no-real-roster")
    text, pa, pb, lp = run(-1, extra=["--gs-no-real-roster"], a_leaves=True,
                           solo=True)
    check("TWIN: no solo kind 0 (the live 'Ready 0' shape)",
          "solo: SENT notify 0" not in text and not kind(pa, 0), lp)
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
