#!/usr/bin/env python3
"""LOOPBACK end-to-end for the new-player intro and the novice mark (sec 4hc).

Launches the real docudp.py on a loopback port and drives two fake clients with
mode-0 datagrams of the shapes the client sends:

    A world door (1 -> 2)       -> body[129] carries the novice bit 0x40
    A lobby spawn (12 -> 13)    -> selector 134 sub 10 event 1 arrives ~0.5 s later
    A command 27 id 1           -> "intro seen" recorded, no notify
    A lobby spawn again         -> NO second intro push
    B lobby spawn + command 33  -> 241 (command 33) + selector 134 sub 11 with
                                   B's ident, to BOTH clients
    B command 33 again          -> answered, no second broadcast
    A CREATE a Novice table     -> B (graduated) JOIN refused, NOVICES ONLY
    A world door again          -> still a novice; B's -> graduated, no bit

The client-side meaning of every one of these bytes is proven separately, on
the retail client, by an offline run of the client's own code (doc_novice_proof).

    python doc_novice_e2e.py            # ~10 s

The intro itself is OFF by default on the server since sec 4hg addendum 3 (the
return from zone 242 crashes this client build); the test turns it on.
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
import doc_novice as NV      # noqa: E402
import doc_gear              # noqa: E402
from doc_battle_e2e import world_req, check, FAILS   # noqa: E402

PORT = int(os.environ.get("DOC_NOVICE_E2E_PORT", "41556"))
A_CID, B_CID = 0x0002A664, 0x00041018


def sel_of(p):
    return p[D.BODY_OFF + 1] if len(p) > D.BODY_OFF + 1 else None


def pushes(pkts, sub):
    return [p for p in pkts if sel_of(p) == NV.SEL_PUSH and len(p) >= D.BODY_OFF + 18
            and struct.unpack_from("<I", p, D.BODY_OFF + 12)[0] == sub]


def door_req(cid):
    tail = bytearray(80)
    struct.pack_into("<I", tail, 80 - 12, cid)        # body[80] = the selected char
    return world_req(cid, 1, bytes(tail))


def main():
    tmp = os.environ.get("TEMP", HERE)
    log_path = os.path.join(tmp, "doc_novice_e2e.log")
    stats = os.path.join(tmp, "doc_novice_e2e_stats.json")
    try:
        os.remove(stats)
    except OSError:
        pass
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--bt-no-onfly-reserve", "--session-idle-drop=0",
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--intro=on", "--intro-delay=0.5", "--stats", stats]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=HERE)
    try:
        wait_listening(log, srv)
        check("docudp is up", srv.poll() is None)
        dst = ("127.0.0.1", PORT)
        ca = udp_socket()
        cb = udp_socket()
        for c in (ca, cb):
            c.bind(("127.0.0.1", 0))
            c.settimeout(0.4)

        def drain(sock):
            got = []
            try:
                while True:
                    got.append(sock.recv(65535))
            except socket.timeout:
                pass
            return got

        # 1. world door for A: a fresh character is a novice
        ca.sendto(door_req(A_CID), dst)
        time.sleep(0.5)
        doors = [p for p in drain(ca) if sel_of(p) == 2]
        check("A's world door answered (selector 2)", bool(doors))
        if doors:
            b = doors[0][D.BODY_OFF:]
            check("A's world door carries the novice bit at body[129]",
                  len(b) > 129 and b[129] & 0x40)
            check("A's world door carries the LOBBY ZONE 217 at body[42..43] (sec 4hg add. 4)",
                  len(b) > 43 and struct.unpack_from("<H", b, 42)[0] == 217)
            # 2026-09-24: HP follows the served suit (retail durability table);
            # the starter suit is the DG Soldier Suit -> 270, never the 100 fallback
            _suit = struct.unpack_from("<I", b, 80)[0] if len(b) >= 84 else None
            check("A's world door HP at body[48..51] = the suit's (0x%s -> %s)"
                  % ("%08x" % _suit if _suit is not None else "?",
                     doc_gear.suit_hp(_suit) if _suit is not None else "?"),
                  _suit is not None and len(b) >= 52
                  and struct.unpack_from("<I", b, 48)[0] == doc_gear.suit_hp(_suit) == 270)

        # 2. lobby spawn -> intro push after --intro-delay
        ca.sendto(world_req(A_CID, 12), dst)
        time.sleep(1.2)
        got = drain(ca)
        ip = pushes(got, NV.SUB_QUEST_EVENT)
        check("selector 13 answered", any(sel_of(p) == 13 for p in got))
        check("the intro push arrived: selector 134 sub 10", len(ip) == 1,
              "%d push(es)" % len(ip))
        if ip:
            check("... event 1, ident = A",
                  struct.unpack_from("<H", ip[0], D.BODY_OFF + 16)[0] == NV.EV_INTRO
                  and struct.unpack_from("<I", ip[0], 16)[0] == A_CID)

        # 2b. world entry (the battletable list request) arms the game-server
        #     channel, as on a deployment (--gs-connect)
        ca.sendto(world_req(A_CID, D.BATTLETABLE_LIST_REQ), dst)
        time.sleep(0.6)
        drain(ca)
        # 3. A finishes the intro: command 27 id 1 -> recorded, answered, and
        #    NO game-server notify (sec 4hg addendum 3: the client drops them
        #    in the lobby, and the crash is the zone loader, not the standby)
        ca.sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                            struct.pack("<II", NV.CMD_EVENT_DONE, NV.EV_INTRO)), dst)
        time.sleep(0.5)
        got27 = drain(ca)
        k39 = [p for p in got27 if len(p) >= D.BODY_OFF + 16
               and struct.unpack_from("<H", p, D.BODY_OFF)[0] == D.GS_NOTIFY_MSG]
        check("command 27 id 1 answered with a 241", any(sel_of(p) == D.LOBBY_CMD_SELECTOR_ANS for p in got27))
        check("no game-server notify rides the intro's command 27", not k39, "%d packet(s)" % len(k39))
        # 4. a second lobby spawn must not push again
        ca.sendto(world_req(A_CID, 12), dst)
        time.sleep(1.2)
        check("no second intro push after command 27 id 1",
              not pushes(drain(ca), NV.SUB_QUEST_EVENT))

        # 5. B enters the lobby and graduates at the Cactuar
        cb.sendto(world_req(B_CID, 12), dst)
        time.sleep(1.2)
        drain(cb)
        drain(ca)
        cb.sendto(world_req(B_CID, D.LOBBY_CMD_SELECTOR_REQ,
                            struct.pack("<II", NV.CMD_GRADUATE, 0)), dst)
        time.sleep(0.6)
        gb, ga = drain(cb), drain(ca)
        ans = [p for p in gb if sel_of(p) == D.LOBBY_CMD_SELECTOR_ANS]
        check("command 33 answered with a 241 carrying command 33 at body[12]",
              any(struct.unpack_from("<H", p, D.BODY_OFF + 12)[0] == 33 for p in ans))
        for who, pk in (("B", gb), ("A", ga)):
            s11 = pushes(pk, NV.SUB_NOVICE_CLEAR)
            check("mark-removed push (134 sub 11, ident B) reached %s" % who,
                  len(s11) == 1 and struct.unpack_from("<I", s11[0], 16)[0] == B_CID,
                  "%d push(es)" % len(s11))
        cb.sendto(world_req(B_CID, D.LOBBY_CMD_SELECTOR_REQ,
                            struct.pack("<II", NV.CMD_GRADUATE, 0)), dst)
        time.sleep(0.6)
        check("a second command 33 broadcasts nothing",
              not pushes(drain(ca), NV.SUB_NOVICE_CLEAR))
        drain(cb)

        # 6. a Novice table: A (novice) creates, B (graduated) is refused
        rec = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                                   maximum=4, map_idx=0, mode=1,
                                                   comment="novice"))
        struct.pack_into("<I", rec, D.BT_OFF_FLAGS,
                         struct.unpack_from("<I", rec, D.BT_OFF_FLAGS)[0] | D.BT_FLAG_NOVICE)
        ca.sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.6)
        drain(ca)
        cb.sendto(world_req(B_CID, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
        time.sleep(0.6)
        drain(cb)

        # 7. world doors again: A still a novice, B graduated
        for c, cid, want in ((ca, A_CID, True), (cb, B_CID, False)):
            c.sendto(door_req(cid), dst)
            time.sleep(0.5)
            d = [p for p in drain(c) if sel_of(p) == 2]
            got_bit = bool(d) and bool(d[0][D.BODY_OFF + 129] & 0x40)
            check("world door for 0x%08x: novice bit %s" % (cid, "SET" if want else "clear"),
                  bool(d) and got_bit == want)
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
            srv.wait()          # until it has exited it still holds the port
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()

    def has(s):
        return s in text
    check("no traceback in the server log", "Traceback" not in text)
    check("log: intro scheduled then sent", has("[intro]") and has("sub 10 event 1 (the new-player intro)"))
    check("log: intro recorded on command 27 id 1", has("finished the new-player intro"))
    check("log: no kind-39 release anywhere", not has("notify kind 39"))
    check("log: B GRADUATED once (Beginner's Machine)",
          text.count("0x%08x GRADUATED" % B_CID) == 1)
    check("log: the Novice table refused B's JOIN", has("NOVICES ONLY"))
    print("log: %s" % log_path)
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
