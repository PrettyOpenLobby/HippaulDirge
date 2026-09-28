#!/usr/bin/env python3
"""LOOPBACK end-to-end for MISSION SUPPLIES (2026-09-26).

Launches the real docudp.py and drives one fake client with mode-0 datagrams:

    world door (1 -> 2)        -> the ledger starts at the standard issue 36/18/60
    request 47 (battle 1)      -> no message 27: the bag already holds it
    request 44 (end of battle) -> fired handgun 4, rifle 6 (a live body)
    request 44 again           -> a resend: NOT counted twice
    request 47 (battle 2)      -> message 27 granting exactly handgun 4 + rifle 6

TWIN: --no-mission-supplies sends no message 27 at all. What message 27 does
to the client's bag is proven on the retail client by
an offline run of the client's own code (doc_supplies_proof).

    python doc_supplies_e2e.py          # ~20 s
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
import docudp as D                                       # noqa: E402
from doc_e2e_udp import udp_socket  # noqa: E402
from doc_battle_e2e import world_req, gs_req, seal, check, FAILS   # noqa: E402
from doc_novice_e2e import door_req                      # noqa: E402

PORT = int(os.environ.get("DOC_SUPPLIES_E2E_PORT", "41557"))
A_CID = 0x0002A664
#: live request 44 body (0x3000 x4, 0x3001 x6)
B44 = bytes.fromhex("2c000100000000000000000000300000040000000130000006000000") + bytes(48)


def req44(cid):
    pkt = bytearray(D.BODY_OFF) + bytearray(B44)
    pkt[0] = 0x04
    pkt[8], pkt[9] = D.GS_INNER_TYPE, 1
    struct.pack_into("<I", pkt, 16, cid)
    return seal(pkt)


def grants(pkts):
    """(item, qty) pairs of every message 27 carrying entries."""
    out = []
    for p in pkts:
        b = p[D.BODY_OFF:]
        if len(b) >= 16 and struct.unpack_from("<H", b, 0)[0] == 27 and b[12]:
            out += [struct.unpack_from("<IH", b, 16 + 8 * i) for i in range(b[12])]
    return out


def run(twin):
    tmp = os.environ.get("TEMP", HERE)
    log_path = os.path.join(tmp, "doc_supplies_e2e%s.log" % ("_twin" if twin else ""))
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--bt-no-onfly-reserve", "--session-idle-drop=0", "--intro=off",
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--gs-battle-length=2", "--gs-battle-reset-after=1",
            "--gs-battle-go-after=1"]
    if twin:
        argv.append("--no-mission-supplies")
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=HERE)
    tag = "[twin] " if twin else ""
    try:
        time.sleep(2.5)
        check(tag + "docudp is up", srv.poll() is None)
        dst = ("127.0.0.1", PORT)
        ca = udp_socket()
        ca.bind(("127.0.0.1", 0))
        ca.settimeout(0.4)

        def drain():
            got = []
            try:
                while True:
                    got.append(ca.recv(65535))
            except socket.timeout:
                pass
            return got

        ca.sendto(door_req(A_CID), dst)
        time.sleep(0.5)
        ca.sendto(world_req(A_CID, D.BATTLETABLE_LIST_REQ), dst)   # arms the GS channel
        time.sleep(0.6)
        ca.sendto(gs_req(A_CID, 31, arg=0), dst)       # team -> the GS join source
        time.sleep(0.4)
        drain()
        ca.sendto(gs_req(A_CID, D.GS_LEAVE_BRIEFING), dst)         # battle 1
        time.sleep(0.8)
        g1 = grants(drain())
        check(tag + "battle 1: no grant -- the login bag already holds the supplies",
              g1 == [], "%s" % g1)
        time.sleep(3.5)                                            # the battle ends
        drain()
        ca.sendto(req44(A_CID), dst)
        time.sleep(0.3)
        ca.sendto(req44(A_CID), dst)                               # its resend
        time.sleep(0.3)
        ca.sendto(gs_req(A_CID, D.GS_LEAVE_BRIEFING), dst)         # battle 2
        time.sleep(0.8)
        g2 = grants(drain())
        if twin:
            check(tag + "TWIN: --no-mission-supplies sends no message 27", g2 == [],
                  "%s" % g2)
        else:
            check("battle 2: message 27 grants exactly what battle 1 fired "
                  "(handgun 4, rifle 6; the resent 44 not counted twice)",
                  sorted(g2) == [(0x62300000, 4), (0x62300001, 6)], "%s" % g2)
    finally:
        try:
            srv.terminate()
            srv.wait(5)
        except Exception:
            srv.kill()
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check(tag + "no traceback in the server log", "Traceback" not in text)
    print("log: %s" % log_path)


def main():
    run(False)
    run(True)
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
