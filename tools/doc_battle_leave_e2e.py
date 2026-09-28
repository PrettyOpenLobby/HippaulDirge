#!/usr/bin/env python3
"""LOOPBACK: a SOLO player LEAVES a running battle, and a dissolved table's room
does not swallow the next battle (live).

Live: a player quit the Wastelands arena (lobby command 4 = return to
lobby), the room ran on for its 600 s, the table stayed on the list; they
dissolved it by hand and the church battle then "ARRIVED in table 1's room"
and never opened its own. Driven here with the deployment's battle flags (no fake
teammates) and a 600 s clock, so only the fix can end anything:

    run 1: CREATE -> START -> 31 -> 47 -> COMMAND 4
           -> "RETURNED TO LOBBY", the room ENDs, table 1 DISSOLVED, list empty
    run 2: CREATE -> START -> 31 -> 47 -> DISSOLVE (125) -> CREATE
           -> START -> 31 -> 47 -> "ROOM OPENED for table 2", no ARRIVED in 1
           -> CONFIG of an unknown key -> a selector-110 RESERVATION CLEAR
    Every dissolve also pushes selector 110, the clear the retail client
    actually runs (an offline run of the client's own code (doc_reservation_clear_proof)).

    python doc_battle_leave_e2e.py      # ~40 s
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
import docudp as D  # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening  # noqa: E402

PORT = int(os.environ.get("DOC_E2E_PORT", "41556"))
A_CID = 0x0002A664
FAILS = []


def check(name, cond, detail=""):
    print("  %s %s%s" % ("ok " if cond else "FAIL", name,
                         ("  " + detail) if detail else ""))
    if not cond:
        FAILS.append(name)


def seal(pkt):
    pkt = bytearray(pkt)
    struct.pack_into("<H", pkt, 2, len(pkt))
    pkt[D.CKSUM_OFF:D.CKSUM_OFF + 2] = bytes(2)
    pkt[D.CKSUM_OFF:D.CKSUM_OFF + 2] = struct.pack("<H", D.cksum(pkt))
    return bytes(pkt)


def world_req(cid, selector, body_tail=b"", pad=176):
    """A type-127 kelsvc request, mode 0: subchannel 7 + selector at body[0..1],
    the sender's charid at packet[16..19] (what packet_charid reads)."""
    body = bytearray(max(pad, 12 + len(body_tail)))
    body[0], body[1] = 7, selector
    body[12:12 + len(body_tail)] = body_tail
    pkt = bytearray(D.BODY_OFF) + body
    pkt[0] = 0x04
    pkt[8], pkt[9] = D.PTYPE_WORLD if hasattr(D, "PTYPE_WORLD") else 127, 1
    struct.pack_into("<I", pkt, 16, cid)
    return seal(pkt)


def gs_req(cid, mtype, arg=0, hdr_arg=0, session=0):
    """A type-130 game-server request, mode 0 (the real ones are mode 4):
    wire+16 = own id, wire+20 = header arg, body {u16 type, u16 session,
    u32 0, u32 arg} at wire+24 (0x0058a3c8, sec 4he)."""
    pkt = bytearray(D.BODY_OFF + 12)
    pkt[0] = 0x04
    pkt[8], pkt[9] = D.GS_INNER_TYPE, 1
    struct.pack_into("<I", pkt, 16, cid)
    struct.pack_into("<I", pkt, 20, hdr_arg)
    struct.pack_into("<HHII", pkt, D.BODY_OFF, mtype, session, 0, arg)
    return seal(pkt)


def run(tag, drive, extra=()):
    log_path = os.path.join(os.environ.get("TEMP", HERE),
                            "doc_battle_leave_e2e_%s.log" % tag)
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--bt-no-onfly-reserve",
            "--gs-battle-length=600", "--gs-battle-go-after=1",
            "--gs-real-dist-settle=1", "--gs-battle-reset-after=1",
            "--gs-battle-after-join=2", "--session-idle-drop=0", "--intro=off"]
    argv += list(extra)
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    listed = None
    try:
        wait_listening(log, srv)
        check("[%s] docudp is up" % tag, srv.poll() is None)
        ca = udp_socket()
        ca.bind(("127.0.0.1", 0))
        ca.settimeout(0.5)
        listed = drive(ca, ("127.0.0.1", PORT))
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
        log.close()
    return io.open(log_path, encoding="utf-8", errors="replace").read(), listed


def drain(sock):
    got = []
    try:
        while True:
            got.append(sock.recv(65535))
    except socket.timeout:
        pass
    return got


def into_battle(ca, dst, map_idx):
    rec = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                               maximum=6, map_idx=map_idx,
                                               mode=1, comment="e2e"))
    ca.sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
    time.sleep(0.6)
    drain(ca)
    ca.sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                        struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
    time.sleep(0.6)
    drain(ca)
    ca.sendto(gs_req(A_CID, 31, arg=0, session=1), dst)
    time.sleep(4.0)                      # the post-join timer: kind 2 + 20
    drain(ca)
    ca.sendto(gs_req(A_CID, 47, session=1), dst)
    time.sleep(1.0)
    drain(ca)


def table_count(ca, dst):
    """How many records the browser list (16 -> 17) serves."""
    ca.sendto(world_req(A_CID, D.BATTLETABLE_LIST_REQ, b""), dst)
    time.sleep(0.8)
    lst = [p for p in drain(ca) if len(p) > D.BODY_OFF + 1
           and p[D.BODY_OFF + 1] == D.BATTLETABLE_LIST_ANS]
    # body[12] u16 = the record count (build_battletable_list); an empty
    # store answers with the generic zero body, which reads 0 there too
    return struct.unpack_from("<H", lst[-1], D.BODY_OFF + 12)[0] if lst else 0


def drive_leave(ca, dst):
    into_battle(ca, dst, 3)
    before = table_count(ca, dst)
    ca.sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                        struct.pack("<II", D.LOBBY_CMD_RETURN, 0)), dst)
    time.sleep(3.0)
    drain(ca)
    return before, table_count(ca, dst)


def drive_dissolve(ca, dst):
    into_battle(ca, dst, 3)
    ca.sendto(world_req(A_CID, D.BT_REQ_DISSOLVE, struct.pack("<H", 1)), dst)
    time.sleep(1.5)
    drain(ca)
    into_battle(ca, dst, 7)
    # the restart orphan (live): CONFIG of a key the store never had
    ca.sendto(world_req(A_CID, D.BT_REQ_CONFIG, struct.pack("<H", 9) + bytes(2)), dst)
    time.sleep(0.8)
    return [p for p in drain(ca) if len(p) > D.BODY_OFF + 1
            and p[D.BODY_OFF + 1] == D.BT_RESERVATION_CLEAR_SEL]


def main():
    text, (before, after) = run("leave", drive_leave)
    lines = text.splitlines()
    has = lambda s: any(s in ln for ln in lines)
    count = lambda s: sum(1 for ln in lines if s in ln)
    check("[leave] no traceback", "Traceback" not in text)
    check("[leave] the room OPENED and its clock STARTED",
          has("ROOM OPENED for table 1")
          and (has("table 1 clock STARTED")
               or has("table 1 shared GO: clock STARTED")))
    check("[leave] the table is listed while the battle runs", before >= 1,
          "%d" % before)
    check("[leave] command 4 = RETURNED TO LOBBY, left the room",
          has("0x%08x RETURNED TO LOBBY (command 4) -- LEFT table 1's room, 0 "
              "still in it" % A_CID))
    check("[leave] the empty room ENDED (everyone left)",
          count("[battle] END table 1") == 1 and has("everyone left"))
    check("[leave] no selector 39 to a player already in the lobby",
          not has("SENT selector 39 (battle over / reset, arm 0x00bcbd70) to "
                  "0x%08x" % A_CID))
    check("[leave] table 1 DISSOLVED once", count("DISSOLVED after the battle") == 1)
    check("[leave] the browser list is EMPTY afterwards", after == 0,
          "%d table(s)" % after)
    check("[leave] the dissolve pushed the selector-110 RESERVATION CLEAR to A",
          has("RESERVATION CLEAR (selector 110, ident 0x%08x)" % A_CID))

    text, clears = run("dissolve", drive_dissolve)
    lines = text.splitlines()
    check("[dissolve] DISSOLVE-ok pushed the selector-110 clear",
          has("selector 110, ident 0x%08x) to 127.0.0.1" % A_CID)
          and has("(after the DISSOLVE-ok)"))
    check("[dissolve] an orphan CONFIG put a selector-110 packet on the wire "
          "with record+4 = A (the demux case compares it with kelsvc+272)",
          any(struct.unpack_from("<I", p, 16)[0] == A_CID for p in clears or []),
          "%d packet(s)" % len(clears or []))
    check("[dissolve] no traceback", "Traceback" not in text)
    check("[dissolve] DISSOLVE (125) took table 1 down",
          has("DISSOLVE table 1 -> gone"))
    check("[dissolve] its running room CLOSED with it",
          has("table 1 is GONE -- its room CLOSED"))
    check("[dissolve] the next table got its OWN room",
          has("ROOM OPENED for table 2"))
    check("[dissolve] and did NOT arrive in the dead table's room",
          not has("ARRIVED in table 1's room"))

    # run 3 (2026-09-24): leaving a RUNNING battle costs rank points -- the
    # client's own warning 0x5c0d. Seed 100 rp; --leave-rp-penalty 25.
    import json
    sp = os.path.join(os.environ.get("TEMP", HERE), "doc_battle_leave_e2e_stats.json")
    key = "anon/0x%08x" % A_CID
    seed = {"chars": {key: {"rp": 100}}}
    with open(sp, "w", encoding="utf-8") as f:
        json.dump(seed, f)
    text, _ = run("penalty", drive_leave,
                  extra=("--stats", sp, "--leave-rp-penalty", "25"))
    lines = text.splitlines()
    c = json.load(open(sp, encoding="utf-8"))["chars"].get(key, {})
    hist = c.get("history") or [{}]
    check("[penalty] no traceback", "Traceback" not in text)
    check("[penalty] the leave was logged with its cost",
          any("LEFT a running battle: -25 rank points" in ln for ln in lines))
    check("[penalty] 100 -> 75 rank points in the career store", c.get("rp") == 75,
          "rp %r" % c.get("rp"))
    check("[penalty] recorded as 'left', not a loss or a battle",
          hist[-1].get("outcome") == "left" and hist[-1].get("rp") == -25
          and not (c.get("tbt") or {}).get("l") and not c.get("battles"),
          "%r" % hist[-1])

    # run 4: TWO players; A leaves, B stays and the 40 s room CLOCK ends it
    # (past the 30 s void rule) -- the tally must not score A a second time
    # (A paid the leave penalty) while B is scored as usual, unpenalized.
    B_CID = 0x00041018
    with open(sp, "w", encoding="utf-8") as f:
        json.dump(seed, f)

    def drive_two(ca, dst):
        cb = udp_socket()
        cb.bind(("127.0.0.1", 0))
        cb.settimeout(0.5)
        rec = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                                   maximum=6, map_idx=3,
                                                   mode=1, comment="e2e"))
        ca.sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.6)
        cb.sendto(world_req(B_CID, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
        time.sleep(0.6)
        ca.sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                            struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.8)
        ca.sendto(gs_req(A_CID, 31, arg=0, session=1), dst)
        cb.sendto(gs_req(B_CID, 31, arg=1, session=1), dst)
        time.sleep(4.0)
        ca.sendto(gs_req(A_CID, 47, session=1), dst)
        cb.sendto(gs_req(B_CID, 47, session=1), dst)
        time.sleep(1.0)
        ca.sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                            struct.pack("<II", D.LOBBY_CMD_RETURN, 0)), dst)
        time.sleep(44.0)                     # the 40 s room clock ends it
        drain(ca)
        drain(cb)
        time.sleep(3.0)                      # result + reset
        drain(ca)
        drain(cb)
        return None

    text, _ = run("penalty2", drive_two,
                  extra=("--stats", sp, "--leave-rp-penalty", "25",
                         "--gs-battle-length", "40"))
    lines = text.splitlines()
    chars = json.load(open(sp, encoding="utf-8"))["chars"]
    ca_, cb_ = chars.get(key, {}), chars.get("anon/0x%08x" % B_CID, {})
    check("[penalty2] no traceback", "Traceback" not in text)
    check("[penalty2] the room ENDED on its clock", any("[battle] END table 1" in ln
                                                      for ln in lines))
    check("[penalty2] A kept its -25 and was NOT scored again by the end tally",
          ca_.get("rp") == 75 and not ca_.get("battles")
          and [h.get("outcome") for h in ca_.get("history", [])] == ["left"],
          "A %r" % {k: ca_.get(k) for k in ("rp", "battles", "history")})
    check("[penalty2] B (still in it at the end) was scored as usual, no penalty",
          cb_.get("battles") == 1
          and "left" not in [h.get("outcome") for h in cb_.get("history", [])],
          "B %r" % {k: cb_.get(k) for k in ("rp", "battles", "history")})

    if FAILS:
        print("%d check(s) failed" % len(FAILS))
        sys.exit(1)
    print("ALL PASS")


if __name__ == "__main__":
    main()
