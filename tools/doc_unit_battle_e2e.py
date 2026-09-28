#!/usr/bin/env python3
"""LOOPBACK end-to-end for UNIT BATTLE (2026-09-24).

Launches the real docudp.py on a loopback port with a units store where A, B
and C are enlisted in three different units, and drives them with mode-0
datagrams (the shapes doc_battle_e2e.py already uses):

    A CREATE a UNIT table (flags 0x01000000)       -> seated, unit U1's side
    B JOIN                                          -> seated (the 2nd unit)
    C JOIN                                          -> REFUSED -6: SE's 28:197,
                                                       only the first two units
    A START, teams, briefing, A kills B, the clock  -> kind 4 to both
    the result settles the units                    -> U1 WIN +pts, U2 LOSS,
                                                       U3 untouched

    python doc_unit_battle_e2e.py            # ~45 s (a battle must last 30 s to pay)
    python doc_unit_battle_e2e.py --open     # the twin: --unit-tables open
                                             # seats C, so the refusal checks FAIL
"""
import io
import json
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import docudp as D           # noqa: E402
from doc_e2e_udp import udp_socket  # noqa: E402
import doc_unit              # noqa: E402
from doc_battle_e2e import world_req, gs_req, check, FAILS   # noqa: E402

PORT = int(os.environ.get("DOC_UNIT_E2E_PORT", "41557"))
A_CID, B_CID, C_CID = 0x0002A664, 0x00041018, 0x00041020
U1, U2, U3 = 0x0000000700000101, 0x0000000700000202, 0x0000000700000303


def key(cid):
    return "anon/0x%08x" % cid          # _wallet_key with no accounts db


def seed_units(path):
    units = {}
    for uid, name, who in ((U1, "Alpha", A_CID), (U2, "Bravo", B_CID),
                           (U3, "Charlie", C_CID)):
        units[doc_unit.hexid(uid)] = {"name": name, "pts": 100, "stats": [],
                                      "registrant": key(who), "members": [key(who)],
                                      "created": 0, "emblem": 0, "cls": 0, "area": 0}
    data = {"units": units,
            "enlist": {key(A_CID): doc_unit.hexid(U1), key(B_CID): doc_unit.hexid(U2),
                       key(C_CID): doc_unit.hexid(U3)}}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def sel(p):
    return p[D.BODY_OFF + 1] if len(p) > D.BODY_OFF + 1 else None


def main():
    open_mode = "--open" in sys.argv
    tmp = os.environ.get("TEMP", HERE)
    log_path = os.path.join(tmp, "doc_unit_battle_e2e.log")
    units_path = os.path.join(tmp, "doc_unit_battle_e2e_units.json")
    stats_path = os.path.join(tmp, "doc_unit_battle_e2e_stats.json")
    seed_units(units_path)
    try:
        os.remove(stats_path)
    except OSError:
        pass
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--gs-fake-teammates=2", "--bt-no-onfly-reserve",
            "--gs-battle-length=31", "--gs-battle-go-after=1",
            "--gs-real-dist-settle=1", "--gs-battle-reset-after=1",
            "--gs-battle-after-join=30", "--session-idle-drop=0", "--intro=off",
            "--units", units_path, "--stats", stats_path,
            "--unit-tables=%s" % ("open" if open_mode else "enforce")]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=HERE)
    try:
        time.sleep(2.5)
        check("docudp is up", srv.poll() is None)
        dst = ("127.0.0.1", PORT)
        socks = {}
        for cid in (A_CID, B_CID, C_CID):
            s = udp_socket()
            s.bind(("127.0.0.1", 0))
            s.settimeout(0.5)
            socks[cid] = s
        ca, cb, cc = socks[A_CID], socks[B_CID], socks[C_CID]

        def drain(sock):
            got = []
            try:
                while True:
                    got.append(sock.recv(65535))
            except socket.timeout:
                pass
            return got

        # every client says hello first, so the server has a session per charid
        for cid, s in socks.items():
            s.sendto(world_req(cid, D.BATTLETABLE_LIST_REQ), dst)
        time.sleep(0.6)
        for s in socks.values():
            drain(s)
        # 1. A creates a UNIT table (mode 1 = TBT, max 6)
        rec = bytearray(D.build_battletable_record(
            table_id=0, leader=0, cur=1, maximum=6, map_idx=0, mode=1,
            comment="unit e2e", flags=D.BT_FLAG_UNIT))
        ca.sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.6)
        check("CREATE answered (25)", any(sel(p) == 25 for p in drain(ca)))

        def versus(sock, cid):
            """Command 34 for table 1 -> (unit A, unit B, count A, count B)."""
            sock.sendto(world_req(cid, D.LOBBY_CMD_SELECTOR_REQ,
                                  struct.pack("<II", doc_unit.CMD_VERSUS, 1)), dst)
            time.sleep(0.5)
            got = [p[D.BODY_OFF:] for p in drain(sock) if sel(p) == 241]
            got = [b for b in got if len(b) >= 78
                   and struct.unpack_from("<H", b, 12)[0] == doc_unit.CMD_VERSUS]
            if len(got) != 1:
                return None
            b = got[0]
            return (struct.unpack_from("<Q", b, doc_unit.VS_UNIT_A)[0],
                    struct.unpack_from("<Q", b, doc_unit.VS_UNIT_B)[0],
                    b[doc_unit.VS_COUNT_A], b[doc_unit.VS_COUNT_B])
        # 1b. alone at the table: ONE unit -> the client's gate count is 1
        v = versus(ca, A_CID)
        check("command 34 with only A seated: unit A = U1, unit B = 0 (Start refused)",
              v == (U1, 0, 1, 0), repr(v))
        # 2. B (unit 2) joins -> seated
        cb.sendto(world_req(B_CID, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
        time.sleep(0.6)
        check("B JOIN answered (21)", any(sel(p) == 21 for p in drain(cb)))
        # 2b. two units -> the gate count is 2, Start allowed
        v = versus(ca, A_CID)
        check("command 34 after B joins: U1 vs U2, one member each (Start allowed)",
              v == (U1, U2, 1, 1), repr(v))
        # 3. C (a THIRD unit) joins -> refused under enforce
        cc.sendto(world_req(C_CID, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
        time.sleep(0.6)
        drain(cc)
        # 4. start, teams, briefing, a kill, the clock
        ca.sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                            struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.8)
        for s in socks.values():
            drain(s)
        ca.sendto(gs_req(A_CID, 31, arg=0, session=1), dst)
        cb.sendto(gs_req(B_CID, 31, arg=1, session=1), dst)
        time.sleep(2.5)
        ca.sendto(gs_req(A_CID, 47, session=1), dst)
        time.sleep(0.3)
        cb.sendto(gs_req(B_CID, 47, session=1), dst)
        time.sleep(0.5)
        cb.sendto(gs_req(B_CID, 30, arg=A_CID, hdr_arg=B_CID, session=1), dst)
        # 31 s: doc_stats pays no rank points under RP_MIN_SECONDS (30)
        time.sleep(34.0)
        for s in socks.values():
            drain(s)
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
    check("log: B seated (the second unit)",
          has("JOIN table 1 by 0x%08x -> 0 (seated)" % B_CID))
    check("log: C REFUSED -6 (a third unit, SE 28:197)",
          has("JOIN table 1 by 0x%08x -> -6" % C_CID)
          and has("[units] JOIN table 1 refused: unit %s is not one of the first two"
                  % doc_unit.hexid(U3)))
    check("log: sides seated by unit", has("is a UNIT table: sides by unit"))
    check("log: ROOM OPENED", has("ROOM OPENED for table 1"))
    check("log: the unit battle SETTLED", has("[units] UNIT BATTLE table 1 settled:"))
    with open(units_path, encoding="utf-8") as f:
        units = json.load(f)["units"]
    u1, u2, u3 = (units[doc_unit.hexid(u)] for u in (U1, U2, U3))
    row = doc_unit.UNIT_BATTLE_ROW
    # A's WIN with 1 kill pays RP_WIN + RP_PER_KILL; U1 gets exactly that
    want = 100 + D.doc_stats.battle_rp("w", 1, 31)
    check("store: U1 (A's unit, 1 kill) WON and gained its member's %d rank points"
          % (want - 100),
          (u1.get("stats") or [[0, 0, 0]])[row] == [1, 0, 0] and u1["pts"] == want,
          "stats %s pts %d" % (u1.get("stats"), u1["pts"]))
    check("store: U2 (B's unit) LOST and gained B's loss points",
          (u2.get("stats") or [[0, 0, 0]])[row] == [0, 0, 1]
          and u2["pts"] == 100 + D.doc_stats.battle_rp("l", 0, 31),
          "stats %s pts %d" % (u2.get("stats"), u2["pts"]))
    check("store: U3 (refused) untouched", not u3.get("stats") and u3["pts"] == 100,
          "stats %s pts %d" % (u3.get("stats"), u3["pts"]))
    print("log: %s (%d lines)" % (log_path, len(lines)))
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
