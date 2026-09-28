#!/usr/bin/env python3
"""LOOPBACK end-to-end for Argento's story chain (lnpc 4, doc_missions.argento_event).

Launches the real docudp.py on a loopback port and drives one fake client with
command 26 (checkQuestEvent) of the shape quest_scr003.ev_n04 sends:

    walk-up (4, 0)                 -> event 302, the first meeting; "met" stored
    walk-up again, no accept       -> event 304, the question again
    accept (4, 2)                  -> event 305, the chain; rank held stored
    walk-up                        -> event 305 (chain open)
    [server restarted with rank +1 and quests 16/18/22 cleared in the store]
    walk-up                        -> event 300 (chain complete)
    [server restarted with --npc-events 4:2:303]
    accept (4, 2)                  -> event 303: an exact admin override wins

    python doc_argento_e2e.py            # ~15 s
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
from doc_e2e_udp import udp_socket, wait_listening, LISTENING  # noqa: E402
import doc_npc as N          # noqa: E402
from doc_battle_e2e import world_req, check, FAILS   # noqa: E402

PORT = int(os.environ.get("DOC_ARGENTO_E2E_PORT", "41557"))
CID = 0x0002A664


def sel_of(p):
    return p[D.BODY_OFF + 1] if len(p) > D.BODY_OFF + 1 else None


def run(stats, log, extra=()):
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--bt-no-onfly-reserve", "--session-idle-drop=0",
            "--stats", stats] + list(extra)
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    # every run writes to the same log: wait for THIS start's listening line
    with io.open(log.name, encoding="utf-8", errors="replace") as f:
        started = f.read().count(LISTENING)
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=HERE)
    wait_listening(log, srv, count=started + 1)
    check("docudp is up", srv.poll() is None)
    return srv


def stop(srv):
    srv.terminate()
    try:
        srv.wait(5)
    except Exception:
        srv.kill()


def ask(sock, b):
    """Send command 26 (trigger 4, sub-code b); return the answered event."""
    try:
        while True:
            sock.recv(65535)
    except (socket.timeout, ConnectionResetError):   # Windows: ICMP from a restarted server
        pass
    sock.sendto(world_req(CID, D.LOBBY_CMD_SELECTOR_REQ,
                          struct.pack("<IIHH", N.CMD_CHECK, 0, b, 4)),
                ("127.0.0.1", PORT))
    time.sleep(0.5)
    try:
        while True:
            p = sock.recv(65535)
            if sel_of(p) == D.LOBBY_CMD_SELECTOR_ANS:
                return struct.unpack_from("<H", p, D.BODY_OFF + 6)[0]
    except (socket.timeout, ConnectionResetError):   # Windows: ICMP from a restarted server
        return None


def mission_list(sock):
    """Send selector 147 (retail Accept Mission); return [(quest, rank byte)]."""
    try:
        while True:
            sock.recv(65535)
    except (socket.timeout, ConnectionResetError):   # Windows: ICMP from a restarted server
        pass
    sock.sendto(world_req(CID, D.LIST148_REQ, struct.pack("<I", 256)),
                ("127.0.0.1", PORT))
    time.sleep(0.5)
    try:
        while True:
            p = sock.recv(65535)
            if sel_of(p) == D.LIST148_ANS:
                b = p[D.BODY_OFF:]
                return [(struct.unpack_from("<H", b, 16 + 4 * k)[0], b[18 + 4 * k])
                        for k in range(b[15])]
    except (socket.timeout, ConnectionResetError):   # Windows: ICMP from a restarted server
        return None


def main():
    tmp = os.environ.get("TEMP", HERE)
    log_path = os.path.join(tmp, "doc_argento_e2e.log")
    stats = os.path.join(tmp, "doc_argento_e2e_stats.json")
    try:
        os.remove(stats)
    except OSError:
        pass
    log = io.open(log_path, "w", encoding="utf-8")
    sock = udp_socket()
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.4)
    try:
        srv = run(stats, log)
        try:
            ml = mission_list(sock) or []
            ids = [q for q, _ in ml]
            check("fresh Drone: 148 leads with Beginner's Course I/II", ids[:2] == [39, 40],
                  str(ids))
            check("fresh Drone: every row on the Drone tab (rank byte 0), no Scout/Trooper",
                  bool(ml) and all(r == 0 for _, r in ml)
                  and not set(ids) & {5, 20, 23, 24, 26, 19, 25, 27, 30, 36, 17})
            check("walk-up -> 302 (first meeting)", ask(sock, 0) == 302)
            check("walk-up again, never accepted -> 304", ask(sock, 0) == 304)
            check("accept (4, 2) -> 305 (the chain)", ask(sock, 2) == 305)
            check("walk-up after the accept -> 305", ask(sock, 0) == 305)
        finally:
            stop(srv)
        with open(stats, encoding="utf-8") as f:
            data = json.load(f)
        keys = [k for k, c in data["chars"].items() if "argento" in c]
        check("the store holds one Argento state", len(keys) == 1, str(keys))
        if keys:
            c = data["chars"][keys[0]]
            check("... met + the rank held at the accept",
                  c["argento"] == {"met": 1, "rank": c.get("rank", 1)}, str(c["argento"]))
            c["rank"] = c["argento"]["rank"] + 1
            c.setdefault("quests", {}).update({"16": 1, "18": 1, "22": 1})
            with open(stats, "w", encoding="utf-8") as f:
                json.dump(data, f)
        srv = run(stats, log)
        try:
            check("rank raised + 16/18/22 cleared -> 300 (chain complete)",
                  ask(sock, 0) == 300)
            ml = dict(mission_list(sock) or [])
            check("Drone 3rd -> 2nd: still no Scout tab on the wire", 5 not in ml and 16 in ml)
        finally:
            stop(srv)
        with open(stats, encoding="utf-8") as f:
            data = json.load(f)
        for c in data["chars"].values():
            if "argento" in c:
                c["rank"] = 4
        with open(stats, "w", encoding="utf-8") as f:
            json.dump(data, f)
        srv = run(stats, log)
        try:
            ml = dict(mission_list(sock) or [])
            check("Scout 3rd: Scout tab (rank byte 3) added, Drone kept, Trooper hidden",
                  ml.get(5) == 3 and ml.get(23) == 3 and ml.get(16) == 0
                  and 30 not in ml, str(ml))
        finally:
            stop(srv)
        srv = run(stats, log, ["--npc-events", "4:2:303"])
        try:
            check("--npc-events 4:2:303 wins over the ledger", ask(sock, 2) == 303)
        finally:
            stop(srv)
    finally:
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check("no traceback in the server log", "Traceback" not in text)
    check("log names the ledger arm", "[missions] Argento for" in text
          and "chain COMPLETE" in text and "ACCEPTED at rank" in text)
    print("log: %s" % log_path)
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
