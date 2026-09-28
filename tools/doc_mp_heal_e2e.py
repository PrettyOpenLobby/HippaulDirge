#!/usr/bin/env python3
"""LOOPBACK end-to-end for MP POINTS, ITEM USE and ETHER MP (2026-09-26).

Launches the real docudp.py and drives two fake clients (mode-0 datagrams of
the client's shapes) into one battle room, then:

    GO burst               -> kind 28 carries the MP-point count 64 + mask
    B uses a Potion (21)   -> message 22 {ident B, item} to BOTH (the effect)
    its resend (same seq)  -> nothing; a second use (new seq) -> 22 again
    A casts Fire twice     -> 61 MP 70, 40
    A uses an Ether (21)   -> 22 + notify kind 44 {90 << 16}
    A touches MP point 2   -> kind 44 {95} (--mp-point-amount 5), a touch inside
    (117, reliable)           the cooldown -> nothing, one after it -> {100}

TWIN (the DEFAULT --mp-points, off since 2026-09-26 -- the January manual
abolished Mako Points -- plus --item-use-broadcast off): the bare kind 28
(count 0, byte for byte the pre-MP-point GO record, which still opens the
damage gate), 117 ignored, and message 22 to the user only. What 22 / kind 44 / kind 28 do
inside the retail client is proven by an offline run of the client's own code (doc_mp_heal_proof).

    python doc_mp_heal_e2e.py           # ~30 s
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
import docudp as D                                                # noqa: E402
from doc_e2e_udp import udp_socket  # noqa: E402
import doc_items as DI                                            # noqa: E402
from doc_battle_e2e import (world_req, seal, check, FAILS,        # noqa: E402
                            field_req)

PORT = int(os.environ.get("DOC_MPHEAL_E2E_PORT", "41561"))
A_CID, B_CID = 0x0002A664, 0x00041018
POTION, ETHER = 0x69320000, 0x69320006


def gs_req(cid, mtype, arg=0, session=1, seq=0):
    """doc_battle_e2e.gs_req plus the transport seq at wire+14 (the one a
    readable header carries; a resend repeats it)."""
    pkt = bytearray(D.BODY_OFF + 12)
    pkt[0] = 0x04
    pkt[8], pkt[9] = D.GS_INNER_TYPE, 1
    struct.pack_into("<H", pkt, 14, seq)
    struct.pack_into("<I", pkt, 16, cid)
    struct.pack_into("<HHII", pkt, D.BODY_OFF, mtype, session, 0, arg)
    return seal(pkt)


def notifies(pkts, kind):
    """Message 35 of `kind` (any length: kind 44's record is one u32)."""
    return [p for p in pkts if len(p) >= D.BODY_OFF + 16
            and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 35
            and struct.unpack_from("<I", p, D.BODY_OFF + 12)[0] == kind]


def msgs(pkts, mtype):
    return [p for p in pkts if len(p) >= D.BODY_OFF + 12
            and struct.unpack_from("<H", p, D.BODY_OFF)[0] == mtype]


def mp44(pkts):
    return [struct.unpack_from("<I", p, D.BODY_OFF + 16)[0] >> 16
            for p in notifies(pkts, 44)]


def run(twin):
    tag = "[twin] " if twin else ""
    tmp = os.environ.get("TEMP", HERE)
    log_path = os.path.join(tmp, "doc_mp_heal_e2e%s.log" % ("_twin" if twin else ""))
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--gs-fake-teammates=2", "--bt-no-onfly-reserve",
            "--gs-battle-length=90", "--gs-battle-go-after=1",
            "--gs-real-dist-settle=1", "--gs-battle-reset-after=1",
            "--gs-battle-after-join=30", "--session-idle-drop=0", "--intro=off",
            "--mp-point-amount=5", "--mp-point-every=0.5"]
    if twin:
        # no --mp-points: the default must be off
        argv += ["--item-use-broadcast=off"]
    else:
        argv += ["--mp-points=on"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=HERE)
    try:
        time.sleep(2.5)
        check(tag + "docudp is up", srv.poll() is None)
        dst = ("127.0.0.1", PORT)
        ca = udp_socket()
        cb = udp_socket()
        ca.bind(("127.0.0.1", 0))
        cb.bind(("127.0.0.1", 0))
        ca.settimeout(0.4)
        cb.settimeout(0.4)

        def drain(sock):
            got = []
            try:
                while True:
                    got.append(sock.recv(65535))
            except socket.timeout:
                pass
            return got

        # the battle-room lifecycle of doc_battle_e2e, up to both 47s
        rec = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                                   maximum=4, map_idx=0, mode=1,
                                                   comment="mp"))
        ca.sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.6)
        cb.sendto(world_req(B_CID, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
        time.sleep(0.6)
        ca.sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                            struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.8)
        ca.sendto(gs_req(A_CID, 31, arg=0, seq=1), dst)
        cb.sendto(gs_req(B_CID, 31, arg=1, seq=1), dst)
        time.sleep(2.5)
        drain(ca)
        drain(cb)
        ca.sendto(gs_req(A_CID, 47, seq=2), dst)
        time.sleep(0.3)
        cb.sendto(gs_req(B_CID, 47, seq=2), dst)
        time.sleep(2.0)                     # the GO burst (--gs-battle-go-after 1)
        ga = drain(ca)
        drain(cb)
        k28 = [p[D.BODY_OFF + 22] if len(p) > D.BODY_OFF + 22 else 0
               for p in notifies(ga, 28)]
        if twin:
            check(tag + "TWIN: the GO burst's kind 28 carries count 0 (no MP point)",
                  k28 and all(c == 0 for c in k28), str(k28))
            _old28 = [pk for k, pk in D.gs_battle_sequence("28")][0][D.BODY_OFF + 16:]
            check(tag + "TWIN (default): kind 28's payload is byte for byte the "
                  "pre-MP-point record (e11b080a^)",
                  all(p[D.BODY_OFF + 16:] == _old28 for p in notifies(ga, 28)),
                  "%d B" % len(_old28))
        else:
            check("GO burst: kind 28 carries the MP-point count 64 (rec[2]) and "
                  "the full mask", k28 and all(c == 64 for c in k28)
                  and all(struct.unpack_from("<Q", p, D.BODY_OFF + 24)[0]
                          == (1 << 64) - 1 for p in notifies(ga, 28)), str(k28))
        # B uses a Potion: seq 10, its resend (seq 10), a second use (seq 11)
        cb.sendto(gs_req(B_CID, 21, arg=POTION, seq=10), dst)
        time.sleep(0.4)
        a22, b22 = msgs(drain(ca), 22), msgs(drain(cb), 22)

        def ok22(ps):
            return all(struct.unpack_from("<I", p, 16)[0] == B_CID
                       and struct.unpack_from("<I", p, D.BODY_OFF + 8)[0] == POTION
                       for p in ps)
        check(tag + "Potion: message 22 {ident B, item} to B", len(b22) == 1 and ok22(b22),
              "%d" % len(b22))
        if twin:
            check(tag + "TWIN: --item-use-broadcast off -> A gets no 22", not a22)
        else:
            check("Potion: the same 22 reached A too (others play the effect)",
                  len(a22) == 1 and ok22(a22), "%d" % len(a22))
        cb.sendto(gs_req(B_CID, 21, arg=POTION, seq=10), dst)
        time.sleep(0.4)
        check(tag + "Potion resend (same seq): no second 22",
              not msgs(drain(cb), 22) and not msgs(drain(ca), 22))
        cb.sendto(gs_req(B_CID, 21, arg=POTION, seq=11), dst)
        time.sleep(0.4)
        check(tag + "a SECOND Potion (new seq, 0.8 s later) is answered again",
              len(msgs(drain(cb), 22)) == 1)
        drain(ca)
        # A: Fire, Fire (1 s apart -- off the resend schedule), then an Ether
        ca.sendto(gs_req(A_CID, 60, arg=0x10001, seq=20), dst)
        time.sleep(1.0)
        ca.sendto(gs_req(A_CID, 60, arg=0x10001, seq=21), dst)
        time.sleep(0.4)
        m61 = [struct.unpack_from("<iI", p, D.BODY_OFF + 4)[1]
               for p in msgs(drain(ca), 61)]
        check(tag + "two Fires: 61 MP 70, 40", m61 == [70, 40], str(m61))
        ca.sendto(gs_req(A_CID, 21, arg=ETHER, seq=22), dst)
        time.sleep(0.4)
        ga = drain(ca)
        check(tag + "Ether: message 22 {ident A, Ether}",
              any(struct.unpack_from("<I", p, D.BODY_OFF + 8)[0] == ETHER
                  for p in msgs(ga, 22)))
        if twin:
            check(tag + "Ether: kind 44 MP 90 (the Ether does not hang on "
                  "--mp-points)", mp44(ga) == [90], str(mp44(ga)))
        else:
            check("Ether: notify kind 44 MP 40 + 50 = 90", mp44(ga) == [90],
                  str(mp44(ga)))
        drain(cb)
        # A touches MP point 2 (reliable 117): credit, cooldown, credit
        ca.sendto(field_req(A_CID, DI.P2P_MP_POINT, DI.build_mp_point_body(2, n=1)), dst)
        time.sleep(0.2)
        ca.sendto(field_req(A_CID, DI.P2P_MP_POINT, DI.build_mp_point_body(2, n=2)), dst)
        time.sleep(0.2)
        g1 = mp44(drain(ca))
        time.sleep(0.3)
        ca.sendto(field_req(A_CID, DI.P2P_MP_POINT, DI.build_mp_point_body(2, n=3)), dst)
        time.sleep(0.3)
        g2 = mp44(drain(ca))
        if twin:
            check(tag + "TWIN: default --mp-points (off) -> 117 credits nothing", g1 == [] and g2 == [],
                  "%s %s" % (g1, g2))
        else:
            check("MP point: first touch -> kind 44 {95}, the touch 0.2 s later "
                  "is cooling down", g1 == [95], str(g1))
            check("MP point: a touch after the cooldown -> kind 44 {100}", g2 == [100],
                  str(g2))
        check(tag + "no kind 44 leaked to B", not notifies(drain(cb), 44))
    finally:
        try:
            srv.terminate()
            srv.wait(5)
        except Exception:
            srv.kill()
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check(tag + "no traceback in the server log", "Traceback" not in text)
    if not twin:
        check("log: the resend was recognised by its seq",
              "resend (seq 10)" in text)
        check("log: the MP point credit is logged",
              "MP point 2 +5, reliable" in text)
    print("log: %s" % log_path)


def main():
    run(False)
    run(True)
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
