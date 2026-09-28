#!/usr/bin/env python3
"""LOOPBACK end-to-end for chat relay (world selector 255, 2026-09-26).

Four fake clients enter the lobby (selector 12). The SAY body is the BYTES
CAPTURED LIVE; the other kinds are the same layout with the
kind numbers read out of the retail client (doc_chat: 0x00b1b1e8).

  Unscoped (no position streamed yet):
    A SAY "yo"             -> B, C, D get selector 255, ident A, text intact;
                              A gets no selector 255 and no selector 2
    B TELL A               -> only A gets it (ident B)
  Scoped (each client streams a type-0x83 position; vl_main's wings):
    A (east) SAY           -> B (east) only
    A SHOUT                -> B + C (south, adjacent); not D (west, opposite)
    D (west) SHOUT         -> C (south) only
    A creates a table, B and C sit: A ENTRY -> B + C, not D; D ENTRY -> nobody
    Start, teams A 0 / B 1 / C 0, ROOM OPENED:
    A TEAM                 -> C only (never B, the enemy); A SAY -> B + C only

TWINS: --twin runs the server with --chat=off and REQUIRES that nobody hears
anything; --all runs --chat=all (the first, unscoped relay) and REQUIRES that
D hears A's east-wing SAY -- so a pass above is not a harness that cannot see
a leak.

    python doc_chat_e2e.py          # expect all ok
    python doc_chat_e2e.py --twin   # expect all ok (proves the drop is seen)
    python doc_chat_e2e.py --all    # expect all ok (proves a leak is seen)
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
import docudp as D                                   # noqa: E402
from doc_e2e_udp import udp_socket  # noqa: E402
import doc_chat as DC                                # noqa: E402
from doc_battle_e2e import world_req, gs_req, seal, check, FAILS   # noqa: E402

PORT = int(os.environ.get("DOC_CHAT_E2E_PORT",
                          os.environ.get("DOC_E2E_PORT", "41571")))
A_CID, B_CID, C_CID, D_CID = 0x00041050, 0x00041068, 0x00041078, 0x00041088
NAMES = {A_CID: "A", B_CID: "B", C_CID: "C", D_CID: "D"}

# live (0x41078 / 0x41050): SAY "yo", body[12..] verbatim
SAY_YO = bytes.fromhex("050003 00ffffffff796f0000".replace(" ", ""))
# the TELL shape seen live: target at stream+4 (text synthetic)
TELL_TXT = b"hello from B\0"

# lobby positions (x, y, z): vl_main regions + the map anchors ID_PLACE_n
POSES = {A_CID: (900.0, 0.0, 145.0),        # east  (quest.ev's spot)
         B_CID: (679.6, 0.0, -3.4),         # east  (ID_PLACE_0)
         C_CID: (1.7, 0.0, -632.2),         # south (ID_PLACE_1)
         D_CID: (-679.8, 0.0, -6.1)}        # west  (ID_PLACE_2)


def tell(target):
    return (struct.pack("<BBBBI", 3, 0, len(TELL_TXT), 0, target) + TELL_TXT)


def stream(kind, text):
    t = text + b"\0"
    return struct.pack("<BBBBI", kind, 0, len(t), 0, DC.BROADCAST) + t


def chat_req(cid, stream):
    # body[2..11] as captured: 00 3f | 01 00 00 00 | 00 00 00 00
    pkt = bytearray(world_req(cid, 255, stream, pad=0))
    pkt[D.BODY_OFF + 2:D.BODY_OFF + 12] = bytes.fromhex("003f0100000000000000")
    return seal(pkt)


def pose_req(cid, x, y, z):
    """The client's type-0x83 position broadcast (ingame_pose), mode 0."""
    pkt = bytearray(D.BODY_OFF) + struct.pack("<Iffffff", cid, x, y, z,
                                              1.0, 0.0, 0.0)
    pkt[0] = 0x04
    pkt[8], pkt[9] = 0x83, 1
    struct.pack_into("<I", pkt, 16, cid)
    return seal(pkt)


def sel_of(p):
    return p[D.BODY_OFF + 1] if len(p) > D.BODY_OFF + 1 else None


def chats(pkts, text=None):
    out = []
    for p in pkts:
        if sel_of(p) != 255 or p[D.BODY_OFF] != 7:
            continue
        c = DC.parse(p[D.BODY_OFF:])
        if c is not None and (text is None or c[2] == text):
            out.append(p)
    return out


def ident(p):
    return struct.unpack_from("<I", p, 16)[0]


def main():
    twin, legacy = "--twin" in sys.argv, "--all" in sys.argv
    log_path = os.path.join(os.environ.get("TEMP", HERE), "doc_chat_e2e.log")
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--bt-no-onfly-reserve",
            "--gs-battle-length=60", "--gs-battle-go-after=1",
            "--gs-real-dist-settle=1", "--gs-battle-reset-after=1",
            "--gs-battle-after-join=30", "--session-idle-drop=0",
            "--intro=off"]
    if twin:
        argv.append("--chat=off")
    if legacy:
        argv.append("--chat=all")
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=HERE)
    try:
        time.sleep(2.5)
        check("docudp is up", srv.poll() is None)
        dst = ("127.0.0.1", PORT)
        cl = {}
        for cid in (A_CID, B_CID, C_CID, D_CID):
            c = udp_socket()
            c.bind(("127.0.0.1", 0))
            c.settimeout(0.4)
            cl[cid] = c

        def drain(sock):
            got = []
            try:
                while True:
                    got.append(sock.recv(65535))
            except socket.timeout:
                pass
            return got

        def drain_all():
            return {cid: drain(c) for cid, c in cl.items()}

        def say(frm, kind, text, want, label):
            """frm speaks; exactly `want` hear it, each once, ident frm."""
            cl[frm].sendto(chat_req(frm, stream(kind, text)), dst)
            time.sleep(0.6)
            got = drain_all()
            heard = sorted(c for c in cl if c != frm and chats(got[c], text))
            ok = (heard == sorted(want) and all(
                len(chats(got[c], text)) == 1
                and ident(chats(got[c], text)[0]) == frm for c in want)
                and not chats(got[frm]))
            check("%s -> %s" % (label, "+".join(NAMES[c] for c in sorted(want))
                                or "nobody"), ok,
                  "heard by %s" % ("+".join(NAMES[c] for c in heard) or "nobody"))
            return heard

        for cid, c in cl.items():              # enter the lobby: learns the charid
            c.sendto(world_req(cid, 12), dst)
        time.sleep(1.2)
        drain_all()

        # 1. A says "yo" before anyone streamed a position: the old broadcast
        cl[A_CID].sendto(chat_req(A_CID, SAY_YO), dst)
        time.sleep(0.6)
        got = drain_all()
        for who in (B_CID, C_CID, D_CID):
            m = chats(got[who])
            ok = (len(m) == 1 and ident(m[0]) == A_CID
                  and m[0][D.BODY_OFF + 12:D.BODY_OFF + 24] == SAY_YO[:12])
            if twin:
                check("TWIN (--chat off): %s hears NOTHING" % NAMES[who], not m,
                      "%d packet(s)" % len(m))
            else:
                check("SAY 'yo' (no position yet) reached %s as selector 255, "
                      "ident A, stream intact" % NAMES[who], ok,
                      "%d packet(s)" % len(m))
        check("speaker gets no selector 255 / selector 2 back (sec 4bz)",
              not [p for p in got[A_CID] if sel_of(p) in (2, 255)])
        if twin:
            return

        # 2. B tells A
        cl[B_CID].sendto(chat_req(B_CID, tell(A_CID)), dst)
        time.sleep(0.6)
        got = drain_all()
        m = chats(got[A_CID])
        check("TELL reached its target A, ident B, text intact",
              len(m) == 1 and ident(m[0]) == B_CID and TELL_TXT in m[0])
        check("TELL did NOT reach C or D",
              not chats(got[C_CID]) and not chats(got[D_CID]))
        check("TELL did NOT echo to B", not chats(got[B_CID]))

        # 3. positions: A, B east; C south; D west
        for cid, (x, y, z) in POSES.items():
            cl[cid].sendto(pose_req(cid, x, y, z), dst)
        time.sleep(0.8)
        drain_all()

        if legacy:
            heard = say(A_CID, DC.KIND_SAY, b"east only", [B_CID, C_CID, D_CID],
                        "TWIN (--chat=all): A's east-wing SAY LEAKS to every wing")
            check("TWIN (--chat=all): D (west) hears the east SAY -- the "
                  "scoped run's 'not D' can fail", D_CID in heard)
            return

        # 4. area scopes
        say(A_CID, DC.KIND_SAY, b"east only", [B_CID], "A SAY (east)")
        say(A_CID, DC.KIND_SHOUT, b"east shout", [B_CID, C_CID],
            "A SHOUT (east + adjacent south; not west)")
        say(D_CID, DC.KIND_SHOUT, b"west shout", [C_CID],
            "D SHOUT (west + adjacent south; not east)")
        say(D_CID, DC.KIND_ENTRY, b"no table", [], "D ENTRY with no table")
        say(A_CID, DC.KIND_TEAM, b"no team", [], "A TEAM with no team")

        # 5. A creates a table, B and C sit
        rec = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                                   maximum=4, map_idx=0, mode=1,
                                                   comment="chat"))
        cl[A_CID].sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.6)
        for cid in (B_CID, C_CID):
            cl[cid].sendto(world_req(cid, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
            time.sleep(0.5)
        drain_all()
        say(A_CID, DC.KIND_ENTRY, b"table talk", [B_CID, C_CID],
            "A ENTRY (table 1: B, C seated; D not)")

        # 6. start, teams A 0 / B 1 / C 0, into the room
        cl[A_CID].sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                                   struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.8)
        for cid, t in ((A_CID, 0), (B_CID, 1), (C_CID, 0)):
            cl[cid].sendto(gs_req(cid, 31, arg=t, session=1), dst)
        time.sleep(2.5)
        for cid in (A_CID, B_CID, C_CID):
            cl[cid].sendto(gs_req(cid, 47, session=1), dst)
            time.sleep(0.3)
        time.sleep(0.5)
        drain_all()
        say(A_CID, DC.KIND_TEAM, b"flank left", [C_CID],
            "A TEAM in battle (team 0: C; never B)")
        say(B_CID, DC.KIND_TEAM, b"alone", [], "B TEAM (only member of team 1)")
        say(A_CID, DC.KIND_SAY, b"in battle", [B_CID, C_CID],
            "A SAY in battle (the room; not D in the lobby)")
        say(D_CID, DC.KIND_SHOUT, b"lobby shout", [],
            "D SHOUT from the lobby does not reach the battle")
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
        log.close()
        print("server log:", log_path)
    txt = io.open(log_path, encoding="utf-8", errors="replace").read()
    if not twin and not legacy:
        check("log: ROOM OPENED for table 1", "ROOM OPENED for table 1" in txt)
    check("log: no traceback", "Traceback" not in txt)


if __name__ == "__main__":
    main()
    print("FAILS: %d" % len(FAILS))
    sys.exit(1 if FAILS else 0)
