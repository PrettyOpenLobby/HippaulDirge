#!/usr/bin/env python3
"""LOOPBACK end-to-end: a client that goes away does not take docudp with it.

Client A sends a world door request and closes its socket before the answer
arrives, so docudp's answer goes to a closed port. On Windows the ICMP
port-unreachable for it comes back as an error on the server socket's next
receive (WinError 10054). docudp has to skip it: client B, sending after A
has gone, must still be heard and the server must still be running, with no
traceback in its log. On Linux the error never happens and the check passes
trivially.

    python doc_connreset_e2e.py     # ~8 s; DOC_E2E_PORT picks the port
"""
import io
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from doc_e2e_udp import udp_socket, wait_listening  # noqa: E402
from doc_battle_e2e import world_req, check, FAILS  # noqa: E402

PORT = int(os.environ.get("DOC_E2E_PORT", "41591"))
A_CID, B_CID = 0x0002A664, 0x00041018


def main():
    tmp = os.environ.get("TEMP", HERE)
    log_path = os.path.join(tmp, "doc_connreset_e2e.log")
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--session-idle-drop=0", "--intro=off"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    try:
        wait_listening(log, srv)
        check("docudp is up", srv.poll() is None)
        dst = ("127.0.0.1", PORT)
        door = bytes(80)
        a = udp_socket()
        a.bind(("127.0.0.1", 0))
        a.sendto(world_req(A_CID, 1, door), dst)       # selector 1: the world door
        a.close()                            # the answer finds a closed port
        time.sleep(1.5)
        b = udp_socket()
        b.bind(("127.0.0.1", 0))
        b.settimeout(0.5)
        b.sendto(world_req(B_CID, 1, door), dst)
        time.sleep(1.5)
        b.close()
        check("docudp still runs after answering a client that went away",
              srv.poll() is None)
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
            srv.wait()          # until it has exited it still holds the port
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check("both requests reached the server",
          text.count("RECV #") >= 2, "%d" % text.count("RECV #"))
    check("no traceback in the server log", "Traceback" not in text)
    print("log: %s" % log_path)
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
