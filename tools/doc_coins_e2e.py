#!/usr/bin/env python3
"""LOOPBACK end-to-end for CHOCOBO COINS + PvP GIL (2026-09-26).

Launches the real docudp.py (--stats, --shop) and drives two fake clients
through a TBT battle with mode-0 datagrams (doc_battle_e2e's shapes):

    A CREATE -> B JOIN -> A START -> teams -> both leave the briefing (47)
    A drops 3 Chocobo Coins (118)       -> kind 10, ident A (A holds 0 now)
    B picks them up (119)               -> kind 11, ident B (B holds 3)
    B dies, killer A (request 30)       -> A wins on kills
    the room clock ends the battle      -> B: kind 21 {coin x3} (the CUT)
                                           BEFORE its kind 4; A: no kind 21
    kind 4 gil totals: A 20000 + 1300 (win), B 20000 + 300 (loss) + 3000

TWIN: --chocobo-coins off -- no kind 21, and B's total is 20000 + 300.
The pay rule itself (1000 each, cap 9, PvP 1300 / 300) is doc_stats' self-test;
what kind 21 does to the client's bag is static RE (docudp end_battle note).

    python doc_coins_e2e.py            # ~40 s
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
import docudp as D                                                 # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening  # noqa: E402
import doc_stats as DS                                             # noqa: E402
import docpg                                                       # noqa: E402
from doc_battle_e2e import (world_req, gs_req, field_req, notifies,  # noqa: E402
                            check, FAILS)

PORT = int(os.environ.get("DOC_COINS_E2E_PORT", "41561"))
A_CID, B_CID = 0x0002A664, 0x00041018
START = 20000


def result_gil(pkt):
    """The kind-4 record's GIL total (record at body[20], gil at +16)."""
    return struct.unpack_from("<I", pkt, D.BODY_OFF + 20 + DS.RES_GIL_TOTAL)[0]


def run(twin):
    tag = "doc_coins_e2e" + ("_twin" if twin else "")
    tmp = os.environ.get("TEMP", HERE)
    log_path = os.path.join(tmp, tag + ".log")
    # the career and wallet stores: a fresh database for this run
    docpg.e2e_database(tag)
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--gs-fake-teammates=2", "--bt-no-onfly-reserve",
            "--gs-battle-length=12", "--gs-battle-go-after=1",
            "--gs-real-dist-settle=1", "--gs-battle-reset-after=1",
            "--gs-battle-after-join=30", "--session-idle-drop=0", "--intro=off",
            "--stats", "on", "--shop", "on", "--shop-start-gil", str(START)]
    if twin:
        argv.append("--chocobo-coins=off")
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    t = "[twin] " if twin else ""
    res_a = res_b = []
    try:
        wait_listening(log, srv)
        check(t + "docudp is up", srv.poll() is None)
        dst = ("127.0.0.1", PORT)
        ca = udp_socket()
        cb = udp_socket()
        ca.bind(("127.0.0.1", 0))
        cb.bind(("127.0.0.1", 0))
        ca.settimeout(0.5)
        cb.settimeout(0.5)

        def drain(sock):
            got = []
            try:
                while True:
                    got.append(sock.recv(65535))
            except socket.timeout:
                pass
            return got

        rec = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                                   maximum=4, map_idx=0, mode=1,
                                                   comment="coins"))
        ca.sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.6)
        cb.sendto(world_req(B_CID, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
        time.sleep(0.6)
        ca.sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                            struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.8)
        ca.sendto(gs_req(A_CID, 31, arg=0, session=1), dst)
        cb.sendto(gs_req(B_CID, 31, arg=1, session=1), dst)
        time.sleep(2.5)
        ca.sendto(gs_req(A_CID, 47, session=1), dst)
        time.sleep(0.3)
        cb.sendto(gs_req(B_CID, 47, session=1), dst)
        time.sleep(0.8)
        drain(ca)
        drain(cb)
        # A drops 3 coins; B picks them up
        ca.sendto(field_req(A_CID, D.P2P_DROP, struct.pack(
            "<IIIfff", DS.COIN_ITEM, 3, 1, 10.0, 0.0, 20.0)), dst)
        time.sleep(0.4)
        d_b = [p for p in notifies(drain(cb), 10)
               if struct.unpack_from("<I", p, 16)[0] == A_CID]
        drain(ca)
        check(t + "A's coin DROP reached B as kind 10 {coin x3}",
              len(d_b) == 1 and struct.unpack_from("<IH", d_b[0], D.BODY_OFF + 20)
              == (DS.COIN_ITEM, 3), "%d" % len(d_b))
        slot = struct.unpack_from("<H", d_b[0], D.BODY_OFF + 26)[0] if d_b else 0
        cb.sendto(field_req(B_CID, D.P2P_PICKUP, struct.pack(
            "<IIIfff", slot, 1, 1, 10.0, 0.0, 20.0)), dst)
        time.sleep(0.4)
        p_b = notifies(drain(cb), 11)
        drain(ca)
        check(t + "B's PICK-UP: kind 11 {coin x3}, ident B",
              any(struct.unpack_from("<I", p, 16)[0] == B_CID
                  and struct.unpack_from("<IH", p, D.BODY_OFF + 20)
                  == (DS.COIN_ITEM, 3) for p in p_b))
        # B dies to A: A wins on kills
        cb.sendto(gs_req(B_CID, 30, arg=A_CID, hdr_arg=B_CID, session=1), dst)
        time.sleep(0.5)
        drain(ca)
        drain(cb)
        time.sleep(11.0)
        got_a, got_b = drain(ca), drain(cb)
        res_a, res_b = notifies(got_a, 4), notifies(got_b, 4)
        cut_a, cut_b = notifies(got_a, 21), notifies(got_b, 21)
        check(t + "kind 4 reached both", len(res_a) == 1 and len(res_b) == 1,
              "A %d, B %d" % (len(res_a), len(res_b)))
        if twin:
            check("TWIN: --chocobo-coins off sends no kind 21", not cut_a and not cut_b)
            if res_b:
                check("TWIN: B's gil total is the loss rate only (20000 + 300)",
                      result_gil(res_b[0]) == START + DS.BATTLE_GIL["l"],
                      "%d" % result_gil(res_b[0]))
        else:
            check("B: kind 21 CUT {coin x3}, ident B, before its kind 4",
                  len(cut_b) == 1
                  and struct.unpack_from("<I", cut_b[0], 16)[0] == B_CID
                  and struct.unpack_from("<IH", cut_b[0], D.BODY_OFF + 20)
                  == (DS.COIN_ITEM, 3)
                  and res_b and got_b.index(cut_b[0]) < got_b.index(res_b[0]))
            check("A (dropped its coins, holds none): no kind 21", not cut_a)
            if res_a and res_b:
                check("kind 4 gil totals: A 20000 + 1300 (win), B 20000 + 300 "
                      "(loss) + 3 coins x 1000",
                      (result_gil(res_a[0]), result_gil(res_b[0]))
                      == (START + 1300, START + 300 + 3000),
                      "A %d, B %d" % (result_gil(res_a[0]), result_gil(res_b[0])))
            w = docpg.read("shop")
            gb = [v["gil"] for k, v in w.items() if k.endswith("/0x%08x" % B_CID)]
            check("B's wallet persisted the same total, and no coin in its bag",
                  gb == [START + 3300] and not any(
                      "0x%08x" % DS.COIN_ITEM in v["bag"] for v in w.values()),
                  "%s" % gb)
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
            srv.wait()          # until it has exited it still holds the port
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check(t + "no traceback in the server log", "Traceback" not in text)
    check(t + "no RESULT tally FAILED", "RESULT tally FAILED" not in text)
    if not twin:
        check("log: B's coin ledger reached 3 and the cut was logged",
              "0x%08x holds 3 Chocobo Coin(s)" % B_CID in text
              and "CUT 3 Chocobo Coin(s) from the bag (paid 3000 gil)" in text)
    print("log: %s" % log_path)


def main():
    run(False)
    run(True)
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
