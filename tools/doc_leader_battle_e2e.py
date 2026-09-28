#!/usr/bin/env python3
"""LOOPBACK end-to-end for TEAM LEADER (mode byte 5, "TLD"; 2026-09-24).

SE's 28:205: "Two teams compete to defeat one another's team leader.
Defeating the enemy leader earns points." The client keeps no leader, so the
server picks one per team and scores only leader kills; each leader is shown
to the others as "[L]Name" through an unsolicited peer answer (--leader-tag).

    A CREATE a mode-5 table (A = the table leader) -> B JOIN -> C JOIN
    START, teams A=0, B=1, C=1, briefing              -> leaders A (team 0), B (team 1)
    A kills C (not a leader)                          -> kind 9, NO team point
    A kills B (team 1's leader)                       -> kind 9, team 0 point 1
    the clock ends it                                 -> A WINS, leaders untagged

    python doc_leader_battle_e2e.py
    python doc_leader_battle_e2e.py --twin    # --leader-tag off + a plain TBT
                                              # table: the leader checks FAIL
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
import docudp as D           # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening  # noqa: E402
from doc_battle_e2e import world_req, gs_req, check, FAILS   # noqa: E402

PORT = int(os.environ.get("DOC_LEADER_E2E_PORT", "41558"))
A_CID, B_CID, C_CID = 0x0002A664, 0x00041018, 0x00041020


def sel(p):
    return p[D.BODY_OFF + 1] if len(p) > D.BODY_OFF + 1 else None


def kind9(pkts):
    return [struct.unpack_from("<HHHH", p, D.BODY_OFF + 20) for p in pkts
            if len(p) >= D.BODY_OFF + 40
            and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 35
            and struct.unpack_from("<I", p, D.BODY_OFF + 12)[0] == 9]


def main():
    twin = "--twin" in sys.argv
    tmp = os.environ.get("TEMP", HERE)
    log_path = os.path.join(tmp, "doc_leader_battle_e2e.log")
    stats = os.path.join(tmp, "doc_leader_battle_e2e_stats.json")
    try:
        os.remove(stats)
    except OSError:
        pass
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--gs-fake-teammates=2", "--bt-no-onfly-reserve",
            "--gs-battle-length=6", "--gs-battle-go-after=1",
            "--gs-real-dist-settle=1", "--gs-battle-reset-after=1",
            "--gs-battle-after-join=30", "--session-idle-drop=0", "--intro=off",
            "--stats", stats, "--leader-tag=%s" % ("off" if twin else "on")]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=HERE)
    got = {A_CID: [], B_CID: [], C_CID: []}
    ever = {A_CID: [], B_CID: [], C_CID: []}     # every packet, never cleared
    try:
        wait_listening(log, srv)
        check("docudp is up", srv.poll() is None)
        dst = ("127.0.0.1", PORT)
        socks = {}
        for cid in (A_CID, B_CID, C_CID):
            so = udp_socket()
            so.bind(("127.0.0.1", 0))
            so.settimeout(0.4)
            socks[cid] = so

        def drain_all():
            for cid, so in socks.items():
                try:
                    while True:
                        pk = so.recv(65535)
                        got[cid].append(pk)
                        ever[cid].append(pk)
                except socket.timeout:
                    pass

        for cid, so in socks.items():
            so.sendto(world_req(cid, D.BATTLETABLE_LIST_REQ), dst)
        time.sleep(0.5)
        drain_all()
        rec = D.build_battletable_record(table_id=0, leader=0, cur=1, maximum=6,
                                         map_idx=0, mode=1 if twin else 5,
                                         comment="leader e2e")
        socks[A_CID].sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.5)
        for cid in (B_CID, C_CID):
            socks[cid].sendto(world_req(cid, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
            time.sleep(0.5)
        socks[A_CID].sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                                      struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.8)
        for cid, team in ((A_CID, 0), (B_CID, 1), (C_CID, 1)):
            socks[cid].sendto(gs_req(cid, 31, arg=team, session=1), dst)
        time.sleep(2.5)
        for cid in (A_CID, B_CID, C_CID):
            socks[cid].sendto(gs_req(cid, 47, session=1), dst)
            time.sleep(0.2)
        time.sleep(0.4)
        drain_all()
        for v in got.values():
            v.clear()
        # A kills C (team 1, NOT its leader), then B (team 1's leader)
        socks[C_CID].sendto(gs_req(C_CID, 30, arg=A_CID, hdr_arg=C_CID, session=1), dst)
        time.sleep(0.6)
        drain_all()
        k_c = kind9(got[A_CID])
        for v in got.values():
            v.clear()
        socks[B_CID].sendto(gs_req(B_CID, 30, arg=A_CID, hdr_arg=B_CID, session=1), dst)
        time.sleep(0.6)
        drain_all()
        k_b = kind9(got[A_CID])
        check("A kills C (not a leader): kind 9 with NO team point",
              k_c and k_c[0] == (0, 0, 0, 0), repr(k_c))
        check("A kills B (team 1's leader): team 0 scores 1",
              k_b and k_b[0] == (1, 0, 0, 0), repr(k_b))
        time.sleep(7.0)
        drain_all()
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    lines = text.splitlines()

    def has(s):
        return any(s in ln for ln in lines)
    check("no traceback in the server log", "Traceback" not in text)
    check("log: TEAM LEADER battle, leaders A (team 0) and B (team 1)",
          has("[leader] TEAM LEADER battle, table 1: leaders {0: '0x%x', 1: '0x%x'}"
              % (A_CID, B_CID)))
    check("log: B tagged for the other two, then untagged at the end",
          has("[leader] TAGGED 0x%08x as '[L]" % B_CID)
          and has("[leader] UNTAGGED 0x%08x" % B_CID))
    tag_b = b"[L]0x%08x" % B_CID
    check("wire: C (B's teammate) and A both RECEIVED a peer answer naming B '[L]...'",
          any(tag_b in p for p in ever[C_CID]) and any(tag_b in p for p in ever[A_CID]))
    check("wire: B was not sent its own tag",
          not any(tag_b in p for p in ever[B_CID]))
    check("log: A WON on the leader kill",
          has("RESULT [anon/0x%08x] TBT WIN" % A_CID)
          or has("RESULT [anon/0x%08x] TLD WIN" % A_CID))
    # 2026-09-26: the launch medal 60:[51] Leader Slayer "defeated the enemy
    # team's leader the most times" -- A's one leader kill (the --twin plain
    # TBT table pays Team Merit / Slayer instead, so this FAILS there)
    _ra = [ln for ln in lines if "RESULT [anon/0x%08x]" % A_CID in ln]
    check("log: A's RESULT pays the Leader Slayer Medal",
          _ra and "'Leader Slayer Medal'" in _ra[0], _ra[0] if _ra else "")
    check("log: nobody else's RESULT names it",
          sum("Leader Slayer Medal" in ln for ln in lines
              if "[stats] RESULT" in ln) == 1)
    print("log: %s (%d lines)" % (log_path, len(lines)))
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
