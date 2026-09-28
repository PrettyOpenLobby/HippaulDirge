#!/usr/bin/env python3
"""End-to-end: a Unit command that arrives before any request has named the
character is still keyed by that character (live: the player went
straight to Unit Management after the world door; selector 240 carries ident
0, so the server keyed them as the bare account, showed 0 units, and refused
every Create as "already a unit").

Runs the real docudp on loopback:
  1. world door (selector 1, ident 0, character id at body[80]) -> MY UNITS
     (lobby command 25, ident 0): the unit line's key must carry the id.
  2. TWIN: the same MY UNITS with no world door first: the key is bare.

    python doc_unit_charid_e2e.py
"""
import io
import os
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import docudp as D                                          # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening  # noqa: E402
import doc_battle_e2e as E                                  # noqa: E402
import doc_unit                                             # noqa: E402

FAILS = []
CID = 0x0004103C


def check(name, cond, detail=""):
    print("  %s  %s%s" % ("ok" if cond else "FAIL", name,
                          (" -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


def run(world_door):
    tmp = os.environ.get("TEMP", HERE)
    log_path = os.path.join(tmp, "doc_unit_charid_e2e_%d.log" % world_door)
    units = os.path.join(tmp, "doc_unit_charid_e2e_units.json")
    try:
        os.remove(units)
    except OSError:
        pass
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(E.PORT),
            "--session-idle-drop=0", "--intro=off", "--units=" + units]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    try:
        wait_listening(log, srv)
        check("docudp is up", srv.poll() is None)
        dst = ("127.0.0.1", E.PORT)
        c = udp_socket()
        c.bind(("127.0.0.1", 0))
        if world_door:
            tail = bytearray(80)
            struct.pack_into("<I", tail, 80 - 12, CID)   # body[80]
            c.sendto(E.world_req(0, 1, bytes(tail)), dst)
            time.sleep(0.6)
        c.sendto(E.world_req(0, D.LOBBY_CMD_SELECTOR_REQ,
                             struct.pack("<II", doc_unit.CMD_MINE, 0)), dst)
        time.sleep(0.8)
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
    lines = [ln for ln in text.splitlines() if "UNIT selector" in ln]
    check("the MY UNITS command was answered", bool(lines), log_path)
    return text, (lines[-1] if lines else "")


def main():
    print("run 1: world door (body[80] = 0x%08x), then MY UNITS with ident 0"
          % CID)
    text, line = run(1)
    check("log: the character id was learned from the world door",
          ("[charid] 0x%08x from the world-door request body[80]" % CID) in text)
    check("MY UNITS is keyed by the CHARACTER (/0x%08x)" % CID,
          ("/0x%08x]" % CID) in line, line)
    print("run 2 (TWIN): MY UNITS with no world door")
    text, line = run(0)
    check("TWIN: the key is the bare account (the live bug's shape)",
          line and ("/0x%08x]" % CID) not in line, line)
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
