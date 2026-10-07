#!/usr/bin/env python3
"""LOOPBACK end-to-end for the character DELETE guard (2026-10-06), through
the real docudp main().

Live: member 30's only character vanished mid-battle (one roster row written,
no menu open). The delete answer matched ANY datagram whose body[1] == 17 and
deleted slot body[4]; enciphered battle traffic hits that 1 in 256.

  REGISTER 'Keeper'        -> slot 0 stored
  TWIN: a 64-byte datagram, body 05 11 00 00 00 ...   -> NOT deleted
  the real 40-byte DELETE, body 05 11 00 00 00         -> deleted

    python doc_delete_e2e.py
"""
import io
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import docudp as D                                          # noqa: E402
import docdb                                                # noqa: E402
import docpg                                                # noqa: E402
import doc_charastore as CS                                 # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening          # noqa: E402
from doc_battle_e2e import seal, pose, check, FAILS         # noqa: E402
from doc_contentid_e2e import seed_member, UID              # noqa: E402

PORT = int(os.environ.get("DOC_E2E_PORT", "41713"))
NAME = "Fitter"                 # doc_contentid_e2e's REGISTER


def delete_pkt(length, slot=0):
    pkt = bytearray(length)
    pkt[0] = 0x04
    pkt[D.BODY_OFF:D.BODY_OFF + 5] = bytes((0x05, 0x11, 0x00, 0x00, slot))
    return seal(pkt)


def roster_names(mid):
    store = CS.CharaStore(docdb.store("characters"))
    return [c and c.get("name") for c in store.roster("member:%d" % mid)]


def main():
    from doc_contentid_e2e import register_pkt
    url = docpg.e2e_database("doc_delete_e2e")
    mid, _cid = seed_member()
    log_path = os.path.join(os.environ.get("TEMP", HERE), "doc_delete_e2e.log")
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--session-idle-drop=0", "--intro=off",
            "--chara-store", "on", "--pol-members", "on"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1",
               POL_DATABASE_URL=url)
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    after_twin = after_real = None
    try:
        wait_listening(log, srv)
        dst = ("127.0.0.1", PORT)
        c = udp_socket()
        c.bind(("127.0.0.1", 0))
        c.settimeout(0.3)
        c.sendto(seal(bytearray(96)), dst)          # the keepalive template
        c.sendto(pose(UID), dst)
        time.sleep(0.6)
        c.sendto(register_pkt(), dst)
        time.sleep(1.5)
        check("registered: slot 0 holds the character",
              roster_names(mid)[0] == NAME, "%r" % roster_names(mid))
        c.sendto(delete_pkt(64), dst)                # battle-shaped noise
        time.sleep(1.0)
        after_twin = roster_names(mid)
        c.sendto(delete_pkt(40), dst)                # the real DELETE
        time.sleep(1.0)
        after_real = roster_names(mid)
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
            srv.wait()
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check("no traceback", "Traceback" not in text)
    check("TWIN: a 64-byte datagram with body[1] == 17 deletes NOTHING",
          after_twin is not None and after_twin[0] == NAME, "%r" % (after_twin,))
    check("the real 40-byte DELETE removes slot 0 and is logged",
          after_real is not None and after_real[0] is None
          and "DELETED slot 0" in text, "%r" % (after_real,))
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
