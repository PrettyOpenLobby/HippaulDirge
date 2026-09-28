#!/usr/bin/env python3
"""LOOPBACK end-to-end for the JANUARY LAUNCH lobby rules (2026-09-26), through
the real docudp main() with --stats / --shop:

  run "door"  (world door, selector 1 -> 2)
    N, a NEW character      -> 3000 gil at body[52]; the launch kit (every
                               part but the suits) + its suit in the bag;
                               NO mask: body[76] = 0xFFFFFFFF
    L, a character from before the rule (wallet without the mark)
                            -> keeps the DG Soldier Mask: body[76], and now
                               in its persisted bag
    N clears the DG Drone 2nd exam (quest 1: 10 enemy kills, request 30)
                            -> the mask is OWED; N's next world door wears it
  run "rp"    A creates a table with Maximum RP 500
                            -> B (900 RP) JOIN refused (-7), C (20 RP) seated
  run "drop"  A and B in a TBT battle, B goes silent (--battle-drop-s 4)
                            -> B LINE DROPPED, -10 RP, recorded "left";
                               the room ends on its clock: A scored as usual,
                               B not scored again; nobody charged after the
                               end (TWIN: A, silent after the end, keeps its
                               result)

    python doc_launch_e2e.py            # ~75 s
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
import docudp as D            # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening  # noqa: E402
import doc_gear as G          # noqa: E402
import doc_shop as S          # noqa: E402
from doc_battle_e2e import world_req, gs_req, check, FAILS   # noqa: E402

PORT = int(os.environ.get("DOC_E2E_PORT", "41573"))
TMP = os.environ.get("TEMP", HERE)
N_CID, L_CID = 0x0002A664, 0x00041018
A_CID, B_CID, C_CID = 0x00051001, 0x00052002, 0x00053003


def key(cid):
    return "anon/0x%08x" % cid


def sel_of(p):
    return p[D.BODY_OFF + 1] if len(p) > D.BODY_OFF + 1 else None


def drain(sock):
    got = []
    try:
        while True:
            got.append(sock.recv(65535))
    except socket.timeout:
        pass
    return got


def door(sock, cid):
    """A world door (1 -> 2) for `cid`: its answer body, or None."""
    tail = bytearray(80)
    struct.pack_into("<I", tail, 80 - 12, cid)        # body[80] = the selected char
    drain(sock)
    sock.sendto(world_req(cid, 1, bytes(tail)), ("127.0.0.1", PORT))
    time.sleep(0.6)
    d = [p for p in drain(sock) if sel_of(p) == 2]
    return d[0][D.BODY_OFF:] if d else None


def door_bag(b):
    n = struct.unpack_from("<I", b, S.LOGIN_BAG_COUNT_OFF)[0]
    return {struct.unpack_from("<I", b, S.LOGIN_BAG_OFF + 8 * i)[0]:
            struct.unpack_from("<H", b, S.LOGIN_BAG_OFF + 8 * i + 6)[0]
            for i in range(n)}


def start(tag, extra=(), stats_seed=None, shop_seed=None):
    stats = os.path.join(TMP, "doc_launch_e2e_%s_stats.json" % tag)
    shop = os.path.join(TMP, "doc_launch_e2e_%s_shop.json" % tag)
    for p, seed in ((stats, stats_seed), (shop, shop_seed)):
        try:
            os.remove(p)
        except OSError:
            pass
        if seed is not None:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(seed, f)
    log_path = os.path.join(TMP, "doc_launch_e2e_%s.log" % tag)
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--bt-no-onfly-reserve",
            "--gs-battle-go-after=1", "--gs-real-dist-settle=1",
            "--gs-battle-reset-after=1", "--gs-battle-after-join=2",
            "--session-idle-drop=0", "--intro=off",
            "--stats", stats, "--shop", shop] + list(extra)
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    wait_listening(log, srv)
    check("[%s] docudp is up" % tag, srv.poll() is None)
    return srv, log, log_path, stats, shop


def stop(srv, log, log_path):
    srv.terminate()
    try:
        srv.wait(5)
    except Exception:
        srv.kill()
        srv.wait()          # until it has exited it still holds the port
    log.close()
    return io.open(log_path, encoding="utf-8", errors="replace").read()


def sock():
    c = udp_socket()
    c.bind(("127.0.0.1", 0))
    c.settimeout(0.4)
    return c


def run_door():
    legacy = {key(L_CID): {"gil": 777, "bag": {"0x6f300000": 1},
                           S.Shop.KIT_MARK: 1, S.Shop.KIT2_MARK: 1}}
    srv, log, lp, stats, shop = start("door", extra=("--gs-battle-length=600",),
                                      shop_seed=legacy)
    try:
        c = sock()
        b = door(c, N_CID)
        check("[door] N's world door answered", b is not None)
        if b is not None:
            bag = door_bag(b)
            check("[door] N (new): 3000 gil at body[52] (January 2006 player blog)",
                  struct.unpack_from("<I", b, S.LOGIN_GIL_OFF)[0] == 3000,
                  "%d" % struct.unpack_from("<I", b, S.LOGIN_GIL_OFF)[0])
            check("[door] N: the launch kit -- every stocked part but the suits",
                  all(bag.get(i) == 1 for i, _q in S.STARTER_KIT)
                  and S.NELSON in bag, "%r" % sorted(hex(i) for i in bag))
            check("[door] N: NO mask -- body[76] = 0xFFFFFFFF, none in the bag",
                  struct.unpack_from("<I", b, 76)[0] == 0xFFFFFFFF
                  and not [i for i in bag if i >> 16 == 0x6330],
                  "0x%08x" % struct.unpack_from("<I", b, 76)[0])
            check("[door] N: the suit is still issued at body[80]",
                  struct.unpack_from("<I", b, 80)[0] == G.SUIT_DG
                  and bag.get(G.SUIT_DG) == 1)
        b = door(c, L_CID)
        check("[door] L (before the rule) keeps the DG Soldier Mask at body[76]",
              b is not None and struct.unpack_from("<I", b, 76)[0] == G.MASK_DG_M)
        w = json.load(open(shop, encoding="utf-8"))
        check("[door] L: the mask is now in its PERSISTED bag, gil untouched",
              w[key(L_CID)]["bag"].get("0x%08x" % G.MASK_DG_M) == 1
              and w[key(L_CID)]["gil"] == 777, "%r" % w[key(L_CID)])

        # N clears the Drone 2nd exam: quest 1, "Defeat 10 Beast Soldiers"
        dst = ("127.0.0.1", PORT)
        rec = D.build_battletable_record(table_id=0, leader=0, cur=1, maximum=1,
                                         map_idx=0, mode=1, comment="exam",
                                         flags=D.BT_FLAG_MISSION,
                                         mission=G.SOLDIER_MASK_EXAM)
        c.sendto(world_req(N_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.6)
        c.sendto(world_req(N_CID, D.LOBBY_CMD_SELECTOR_REQ,
                           struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.6)
        c.sendto(gs_req(N_CID, 31, arg=0, session=1), dst)
        time.sleep(4.0)
        c.sendto(gs_req(N_CID, 47, session=1), dst)
        time.sleep(2.0)
        drain(c)
        for i in range(10):
            c.sendto(gs_req(N_CID, 30, arg=N_CID, hdr_arg=0x7F000001 + i,
                            session=1), dst)
            time.sleep(0.15)
        time.sleep(3.0)
        drain(c)
        w = json.load(open(shop, encoding="utf-8"))
        check("[door] the exam clear OWES N the mask (wallet smask_due)",
              w[key(N_CID)].get(G.MASK_DUE) == 1, "%r" % {
                  k: v for k, v in w[key(N_CID)].items() if k != "bag"})
        b = door(c, N_CID)
        check("[door] N's next world door wears it: body[76] = DG Soldier Mask M",
              b is not None and struct.unpack_from("<I", b, 76)[0] == G.MASK_DG_M)
        w = json.load(open(shop, encoding="utf-8"))
        check("[door] ...and it is in N's persisted bag, the debt settled",
              w[key(N_CID)]["bag"].get("0x%08x" % G.MASK_DG_M) == 1
              and G.MASK_DUE not in w[key(N_CID)])
    finally:
        text = stop(srv, log, lp)
    check("[door] no traceback", "Traceback" not in text)
    check("[door] logged: the exam clear and the owed mask",
          "cleared the Drone 2nd exam: Soldier Mask OWED" in text)


def run_rp():
    seed = {"chars": {key(B_CID): {"rp": 900}, key(C_CID): {"rp": 20}}}
    srv, log, lp, stats, shop = start("rp", extra=("--gs-battle-length=600",),
                                      stats_seed=seed)
    try:
        dst = ("127.0.0.1", PORT)
        ca, cb, cc = sock(), sock(), sock()
        rec = bytearray(D.build_battletable_record(
            table_id=0, leader=0, cur=1, maximum=6, map_idx=3, mode=1,
            comment="rp", flags=D.BT_FLAG_MAX_RP))
        struct.pack_into("<I", rec, D.BT_OFF_MAX_RP, 500)
        ca.sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.6)
        drain(ca)
        res = {}
        for cid, cs in ((B_CID, cb), (C_CID, cc)):
            cs.sendto(world_req(cid, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
            time.sleep(0.6)
            a21 = [p for p in drain(cs) if sel_of(p) == D.BT_REQ_JOIN + 1]
            res[cid] = (struct.unpack_from("<i", a21[0], D.BODY_OFF + 12)[0]
                        if a21 else None)
    finally:
        text = stop(srv, log, lp)
    check("[rp] no traceback", "Traceback" not in text)
    check("[rp] B (900 RP) at a Maximum-500 table: JOIN refused, result -7",
          res.get(B_CID) == D.BT_REFUSE_RP, "%r" % res.get(B_CID))
    check("[rp] C (20 RP): seated (result >= 0)",
          res.get(C_CID) is not None and res[C_CID] >= 0, "%r" % res.get(C_CID))
    check("[rp] logged as an RP LIMIT refusal naming the numbers",
          "RP LIMIT: 900 RP > the table's maximum 500" in text)


def run_drop():
    seed = {"chars": {key(A_CID): {"rp": 100}, key(B_CID): {"rp": 100}}}
    srv, log, lp, stats, shop = start(
        "drop", stats_seed=seed,
        extra=("--gs-battle-length=34", "--battle-drop-s=4"))
    try:
        dst = ("127.0.0.1", PORT)
        ca, cb = sock(), sock()
        rec = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                                   maximum=6, map_idx=3,
                                                   mode=1, comment="drop"))
        ca.sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.6)
        cb.sendto(world_req(B_CID, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
        time.sleep(0.6)
        ca.sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                            struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.8)
        ca.sendto(gs_req(A_CID, 31, arg=0, session=1), dst)
        cb.sendto(gs_req(B_CID, 31, arg=1, session=1), dst)
        time.sleep(3.0)
        ca.sendto(gs_req(A_CID, 47, session=1), dst)
        cb.sendto(gs_req(B_CID, 47, session=1), dst)
        # A keeps talking (the in-battle stream); B falls silent
        t_end = time.time() + 40.0
        while time.time() < t_end:
            ca.sendto(gs_req(A_CID, 24, session=1), dst)   # the 1 Hz report
            time.sleep(1.0)
            drain(ca)
        drain(cb)
        time.sleep(7.0)                          # both silent AFTER the end
        drain(ca)
    finally:
        text = stop(srv, log, lp)
    chars = json.load(open(stats, encoding="utf-8"))["chars"]
    ca_, cb_ = chars.get(key(A_CID), {}), chars.get(key(B_CID), {})
    lines = text.splitlines()
    check("[drop] no traceback", "Traceback" not in text)
    check("[drop] B went silent in the running room -> LINE DROPPED",
          any("0x%08x silent" % B_CID in ln and "LINE DROPPED" in ln
              for ln in lines))
    check("[drop] B paid the manual's -10 once (line drop), recorded 'left'",
          cb_.get("rp") == 90
          and [h.get("outcome") for h in cb_.get("history", [])] == ["left"]
          and sum(1 for ln in lines if "LINE DROP out of a running battle"
                  in ln) == 1,
          "B %r" % {k: cb_.get(k) for k in ("rp", "battles", "history")})
    check("[drop] B was NOT scored again by the end tally",
          not cb_.get("battles"))
    check("[drop] the room ended on its CLOCK (a normal end)",
          any("[battle] END table 1" in ln for ln in lines))
    check("[drop] TWIN: A, in to the end and silent after it, is scored as "
          "usual and never charged",
          ca_.get("battles") == 1
          and "left" not in [h.get("outcome") for h in ca_.get("history", [])]
          and not any("0x%08x silent" % A_CID in ln for ln in lines),
          "A %r" % {k: ca_.get(k) for k in ("rp", "battles", "history")})


def main():
    run_door()
    run_rp()
    run_drop()
    if FAILS:
        print("%d check(s) failed" % len(FAILS))
        sys.exit(1)
    print("ALL PASS")


if __name__ == "__main__":
    main()
