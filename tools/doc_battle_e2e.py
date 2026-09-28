#!/usr/bin/env python3
"""LOOPBACK end-to-end for the DoC battle ROOM (sec 4he, 2026-09-23).

doc_udp_test.py never constructs a Session or runs main()'s timer loop -- the
09-13 crash-loop shipped that way. This launches the real
docudp.py on a loopback port with the deployment's battle flags and drives TWO fake
clients through the whole table lifecycle with mode-0 (plaintext) datagrams of
the shapes the client sends:

    A CREATE (24) -> B JOIN (20) -> A START (command 3) -> A/B team (31)
    -> distribution (kind 20) + ROOM OPENED -> A/B leave briefing (47)
    -> B dies (request 30: killer A) -> kind 9 -> the room clock ends the
    battle -> kind 4 to BOTH -> selector 39 to both -> table dissolved.

Then it reads the server log back and asserts on the lines, and fails on any
traceback. The P2P layer (shots / damage) cannot be driven here: mode 3/4 are
enciphered and doc_kelcrypt only decrypts; those builders are covered by
doc_udp_test.py.

    python doc_battle_e2e.py            # ~15 s
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
from doc_e2e_udp import udp_socket  # noqa: E402
import doc_field  # noqa: E402
import docpg  # noqa: E402

#: the arena item generators are the arenas' own data (doc_item_generators.json,
#: not shipped; README.md): without it the generator checks are skipped
_GEN = bool(doc_field.load())

PORT = int(os.environ.get("DOC_E2E_PORT", "41555"))
A_CID, B_CID = 0x0002A664, 0x00041018
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


def field_req(cid, ptype, payload):
    """2026-09-26: the client's RELIABLE item datagram to the server (inner
    type 118 DROP / 119 PICK-UP, flags 0x01), body = the P2P payload:
    118 {u32 item, u32 count, u32 seq, f32 x, y, z}, 119 {u32 slot, u32 1,
    u32 seq, f32 x, y, z}. Mode 0 (a readable header) -- live they are mode
    4, see field_req_mode4()."""
    pkt = bytearray(D.BODY_OFF) + bytearray(payload)
    pkt[0] = 0x04
    pkt[8], pkt[9] = ptype, 0x01
    struct.pack_into("<I", pkt, 16, cid)
    return seal(pkt)


def field_req_mode4(payload):
    """The same datagram as a PCSX2 client really sends it (live log
    2026-09-26): mode 4, the header enciphered under the cipher docudp does
    not hold -- so garbage here, with a checksum that does not match -- and
    the body plaintext. Only the body can name it."""
    pkt = bytearray(D.BODY_OFF) + bytearray(payload)
    pkt[0], pkt[1] = 0x04, 0x04
    struct.pack_into("<H", pkt, 2, len(pkt))
    pkt[4:D.BODY_OFF] = bytes((0x5b + 37 * i) & 0xFF for i in range(D.BODY_OFF - 4))
    return bytes(pkt)


def notifies(pkts, kind):
    return [p for p in pkts if len(p) >= D.BODY_OFF + 36
            and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 35
            and struct.unpack_from("<I", p, D.BODY_OFF + 12)[0] == kind]


def run(accounts=False):
    """accounts=True (2026-09-26): a deployment's shape -- --pol-members with an empty
    session table, so each client resolves to its own addr:<ip> account key,
    and B on its own address. Every other run bound both clients to one IP and
    ONE key, which hid the result-tally miss (live tables 30-32: every member
    but the last sender got the all-zero record = LOSS, 0 rank points, 0 gil)."""
    tag = "doc_battle_e2e_accounts" if accounts else "doc_battle_e2e"
    tmp = os.environ.get("TEMP", HERE)
    log_path = os.path.join(tmp, tag + ".log")
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--gs-fake-teammates=2", "--bt-no-onfly-reserve",
            "--gs-battle-length=12", "--gs-battle-go-after=1",
            "--gs-real-dist-settle=1", "--gs-battle-reset-after=1",
            "--gs-battle-after-join=30", "--session-idle-drop=0",
            # sec 4hc: one kill graduates, so A's kill drives the broadcast
            "--novice-kills=1", "--intro=off",
            "--stats", "on"]
    # a fresh database per run: empty careers and, for the accounts run, the
    # core's own (empty) session table
    db_url = docpg.new_database()
    if db_url is None:
        sys.exit(docpg.skip_or_fail("doc_battle_e2e"))
    if accounts:
        argv += ["--pol-members", "on", "--chara-store", "on"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1",
               POL_DATABASE_URL=db_url)
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    try:
        time.sleep(2.5)
        check("docudp is up", srv.poll() is None)
        dst = ("127.0.0.1", PORT)
        ca = udp_socket()
        cb = udp_socket()
        ca.bind(("127.0.0.1", 0))
        cb.bind(("127.0.0.2" if accounts else "127.0.0.1", 0))
        ca.settimeout(0.5)
        cb.settimeout(0.5)

        def drain(sock):
            got = []
            try:
                while True:
                    got.append(sock.recv(65535))
            except socket.timeout:
                pass
            return got

        # 1. A creates a table (mode 1 = TBT, max 4, no time limit byte ->
        #    the --gs-battle-length fallback of 12 s)
        rec = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                                   maximum=4, map_idx=0, mode=1,
                                                   comment="e2e"))
        ca.sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.6)
        ans_a = drain(ca)
        check("CREATE answered (25 + the reservation echo)",
              any(len(p) > D.BODY_OFF + 1 and p[D.BODY_OFF + 1] == 25 for p in ans_a),
              "%d packet(s)" % len(ans_a))
        # 2. B joins table 1
        cb.sendto(world_req(B_CID, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
        time.sleep(0.6)
        ans_b = drain(cb)
        check("JOIN answered (21)",
              any(len(p) > D.BODY_OFF + 1 and p[D.BODY_OFF + 1] == 21 for p in ans_b),
              "%d packet(s)" % len(ans_b))
        # 3. A starts: lobby command 3
        ca.sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                            struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.8)
        ans_a = drain(ca)
        ans_b = drain(cb)
        check("START -> BATTLE READY (38) to the leader",
              any(len(p) > D.BODY_OFF + 1 and p[D.BODY_OFF + 1] == 38 for p in ans_a))
        check("START -> BATTLE READY (38) fanned out to the member",
              any(len(p) > D.BODY_OFF + 1 and p[D.BODY_OFF + 1] == 38 for p in ans_b))
        # 3b. a retransmitted command 3 must NOT re-run the Start
        ca.sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                            struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.4)
        drain(ca)
        drain(cb)
        # 4. teams: A -> 0, B -> 1; the settle is 1 s
        ca.sendto(gs_req(A_CID, 31, arg=0, session=1), dst)
        cb.sendto(gs_req(B_CID, 31, arg=1, session=1), dst)
        time.sleep(0.5)
        ca.sendto(gs_req(A_CID, 31, arg=0, session=1), dst)   # the re-send
        time.sleep(2.0)
        drain(ca)
        drain(cb)
        # 5. both leave the briefing room
        ca.sendto(gs_req(A_CID, 47, session=1), dst)
        time.sleep(0.3)
        cb.sendto(gs_req(B_CID, 47, session=1), dst)
        time.sleep(0.5)
        drain(ca)
        drain(cb)
        # 5b. 2026-09-26 (before the kill ends it): A drops 18 rifle rounds for B (118); B picks them up
        #     (119). Kind 10 (ident A) then kind 11 (ident B) reach BOTH.
        ca.sendto(field_req(A_CID, D.P2P_DROP, struct.pack(
            "<IIIfff", 0x62300001, 18, 1, 10.0, 0.0, 20.0)), dst)
        time.sleep(0.4)
        # (the arena's own generators send kind 10s too -- ident = each
        #  recipient, head FIELD_QUIET; the drop is the one with ident A)
        d_a = [p for p in notifies(drain(ca), 10)
               if struct.unpack_from("<I", p, 16)[0] == A_CID
               and struct.unpack_from("<I", p, D.BODY_OFF + 16)[0] == 0]
        d_b = [p for p in notifies(drain(cb), 10)
               if struct.unpack_from("<I", p, 16)[0] == A_CID]
        check("A's DROP (118): kind 10 {rifle x18} reached BOTH, ident A",
              len(d_a) == 1 and len(d_b) == 1 and all(
                  struct.unpack_from("<IH", p, D.BODY_OFF + 20) == (0x62300001, 18)
                  for p in d_a + d_b), "%d / %d" % (len(d_a), len(d_b)))
        slot = (struct.unpack_from("<H", d_b[0], D.BODY_OFF + 26)[0]
                if d_b else 0)
        cb.sendto(field_req(B_CID, D.P2P_PICKUP, struct.pack(
            "<IIIfff", slot, 1, 1, 10.0, 0.0, 20.0)), dst)
        time.sleep(0.4)
        p_a, p_b = notifies(drain(ca), 11), notifies(drain(cb), 11)
        check("B's PICK-UP (119): kind 11 {rifle x18, same slot} reached BOTH, "
              "ident B",
              p_a and p_b and all(
                  struct.unpack_from("<I", p, 16)[0] == B_CID
                  and struct.unpack_from("<IHH", p, D.BODY_OFF + 20)
                  == (0x62300001, 18, slot) for p in p_a + p_b),
              "%d / %d" % (len(p_a), len(p_b)))
        cb.sendto(field_req(B_CID, D.P2P_PICKUP, struct.pack(
            "<IIIfff", slot, 1, 2, 10.0, 0.0, 20.0)), dst)
        time.sleep(0.4)
        check("TWIN: a second PICK-UP of the taken slot sends nothing",
              not notifies(drain(ca), 11) and not notifies(drain(cb), 11))
        # 5c. B picks up a GENERATOR's item (slot 1, placed at the GO): kind 11
        #     to both, and that generator rolls again later (log below)
        cb.sendto(field_req(B_CID, D.P2P_PICKUP, struct.pack(
            "<IIIfff", 1, 1, 3, 0.0, 0.0, 0.0)), dst)
        time.sleep(0.4)
        _gen_ok = (not _GEN) or (
              any(struct.unpack_from("<I", p, 16)[0] == B_CID
                  for p in notifies(drain(ca), 11))
              and any(struct.unpack_from("<I", p, 16)[0] == B_CID
                      for p in notifies(drain(cb), 11)))
        check("B's PICK-UP of generator slot 1: kind 11 reached BOTH, ident B"
              + ("" if _GEN else " (SKIPPED: no generator data)"), _gen_ok)
        # 5d. (live): the PCSX2 client's pick-up is MODE 4 with an
        #     unreadable header. Slot 45 is the one live read as GS request 45
        #     (leave) and answered with 46 -- it must be a pick-up, not a 46.
        m4 = field_req_mode4(struct.pack("<IIIfff", 45, 1, 4, 0.0, 0.0, 0.0))
        _in4 = D.describe_inner(m4)
        check("TWIN: the mode-4 pick-up's header is UNREADABLE to docudp "
              "(else this step would ride the old path)",
              _in4 is None or _in4.get("plain") is None)
        cb.sendto(m4, dst)
        time.sleep(0.4)
        p4a, rb = notifies(drain(ca), 11), drain(cb)
        p4b = notifies(rb, 11)
        check("B's MODE-4 PICK-UP of generator slot 45: kind 11 {slot 45} "
              "reached BOTH, ident B"
              + ("" if _GEN else " (SKIPPED: no generator data)"),
              (not _GEN) or p4a and p4b and all(
                  struct.unpack_from("<I", p, 16)[0] == B_CID
                  and struct.unpack_from("<H", p, D.BODY_OFF + 26)[0] == 45
                  for p in p4a + p4b), "%d / %d" % (len(p4a), len(p4b)))
        check("TWIN: ... and it was NOT answered as GS request 45 (no 46)",
              not any(len(p) >= D.BODY_OFF + 2
                      and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 46
                      for p in rb))
        # 6. B dies: request 30 from B, victim = B (wire+20), killer = A (body+8)
        cb.sendto(gs_req(B_CID, 30, arg=A_CID, hdr_arg=B_CID, session=1), dst)
        time.sleep(0.5)
        k9a = [p for p in drain(ca) if len(p) >= D.BODY_OFF + 40
               and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 35
               and struct.unpack_from("<I", p, D.BODY_OFF + 12)[0] == 9]
        k9b = [p for p in drain(cb) if len(p) >= D.BODY_OFF + 40
               and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 35
               and struct.unpack_from("<I", p, D.BODY_OFF + 12)[0] == 9]
        check("request 30 -> notify kind 9 reached BOTH members", k9a and k9b)
        if k9a:
            pts = struct.unpack_from("<HHHH", k9a[0], D.BODY_OFF + 20)
            kv = struct.unpack_from("<II", k9a[0], D.BODY_OFF + 28)
            check("kind 9 carries team points [1,0,0,0], killer A, victim B",
                  pts == (1, 0, 0, 0) and kv == (A_CID, B_CID), "%s %s" % (pts, kv))
        # 7. the room clock (12 s from the shared GO) ends it; reset 1 s later
        time.sleep(11.0)
        res_a = [p for p in drain(ca) if len(p) >= D.BODY_OFF + 24
                 and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 35
                 and struct.unpack_from("<I", p, D.BODY_OFF + 12)[0] == 4]
        res_b = [p for p in drain(cb) if len(p) >= D.BODY_OFF + 24
                 and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 35
                 and struct.unpack_from("<I", p, D.BODY_OFF + 12)[0] == 4]
        check("kind 4 (RESULT) reached BOTH members from ONE room clock",
              len(res_a) == 1 and len(res_b) == 1,
              "A %d, B %d" % (len(res_a), len(res_b)))
        if res_a and res_b:
            oa = res_a[0][D.BODY_OFF + 20]
            ob = res_b[0][D.BODY_OFF + 20]
            check("the verdict: A (1 kill) WINS, B LOSES -- not the old always-DRAW",
                  (oa, ob) in ((1, 0), (3, 0)), "A=%d B=%d" % (oa, ob))
            # 2026-09-26: the launch medals of a TBT (doc_stats.MODE_MEDALS):
            # Team Merit (holder 3) and Slayer (holder 5) name A -- roster
            # slot 1 in A's record ([B, A]), slot 0 in B's ([A, B])
            ha = list(res_a[0][D.BODY_OFF + 50:D.BODY_OFF + 65])
            hb = list(res_b[0][D.BODY_OFF + 50:D.BODY_OFF + 65])
            check("kind 4 holders: Team Merit + Slayer name A in both records",
                  ha[3] == ha[5] == 1 and hb[3] == hb[5] == 0,
                  "A %r B %r" % (ha, hb))
            check("TWIN: holder 2 (the 2005 beta's Iron Seal id, the launch "
                  "client's BT Medal of Dishonor) names nobody in a TBT",
                  ha[2] == hb[2] == 0xFF)
        # 8. A casts Fire AFTER the battle checks (the ~3 s it takes shifted the
        #    battle timeline when it ran earlier) (live request 60 arg 0x10001) -> message 61
        #     {status 0, MP 100}; the old zero 61 set MP 0 after one cast
        #     --mp-model ledger: a cast, its resend on the client's schedule
        #     (+0.6 s), then a genuine recast off it (+2.4 s): Fire costs 30
        drain(ca)
        _t0 = time.time()
        for _at in (0.0, 0.6, 2.4):
            time.sleep(max(0.0, _t0 + _at - time.time()))
            ca.sendto(gs_req(A_CID, 60, arg=0x10001, session=1), dst)
        time.sleep(0.5)
        m61 = [struct.unpack_from("<iI", p, D.BODY_OFF + 4) for p in drain(ca)
               if len(p) >= D.BODY_OFF + 12
               and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 61]
        check("request 60 x3 -> three 61s: cast 70, resend 70, recast 40",
              m61 == [(0, 70), (0, 70), (0, 40)], str(m61))
        check("TWIN: the old zero answer would carry MP 0",
              struct.unpack_from("<I", D.build_gs_message(61) + bytes(12),
                                 D.BODY_OFF + 8)[0] == 0)
        drain(cb)
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    lines = text.splitlines()

    def has(s):
        return any(s in ln for ln in lines)

    def count(s):
        return sum(1 for ln in lines if s in ln)
    check("no traceback in the server log", "Traceback" not in text)
    check("log: CREATE -> table 1", has("CREATE -> table 1"))
    check("log: JOIN seated", has("JOIN table 1 by 0x%08x -> 0 (seated)" % B_CID))
    check("log: the Start retransmit was recognised", has("a retransmit, 241 only"))
    check("log: table READY then the distribution",
          has("table 1 READY") and has("SENT notify 20 (PLAYER DISTRIBUTION) over the REAL"))
    check("log: ROOM OPENED", has("ROOM OPENED for table 1"))
    check("log: the clock started once, the second player ARRIVED",
          count("clock STARTED") == 1 and has("ARRIVED in table 1's room"))
    check("log: KILL REPORT tallied", has("KILL REPORT) 0x%x killed 0x%x -> SENT notify 9 to 2"
                                          % (A_CID, B_CID)))
    check("log: the room END fired once", count("[battle] END table 1") == 1)
    check("log: RESULT logged for both", count("SENT notify 4 (the RESULT") == 2)
    check("log: selector 39 to both", count("SENT selector 39 (battle over") == 2)
    check("log: table DISSOLVED exactly once", count("DISSOLVED after the battle") == 1)
    check("log: no 'waiting for' stall", not has("waiting for 1 member"))
    check("log: A graduated from the novice mark by kills (sec 4hc), B did not",
          count("0x%08x GRADUATED (1 career kills)" % A_CID) == 1
          and not has("0x%08x GRADUATED" % B_CID))
    if _GEN:
        check("log: the arena's item generators ran (z201 situation 1100) and "
              "placed items for both members",
              has("[field] table 1: zone 201 situation 1100 ->")
              and has("[field] table 1: SENT notify kind 10 x"))
        check("log: the picked generator is emptied and rolls again later",
              has("[field] table 1: generator 1 emptied"))
    else:
        print("  SKIP the generator log checks: no doc_item_generators.json")
    check("log: no RESULT tally FAILED (each member found its own tally row)",
          not has("RESULT tally FAILED"))
    check("log: a [stats] RESULT row for BOTH players",
          count("[stats] RESULT [") == 2)
    print("log: %s (%d lines)" % (log_path, len(lines)))


def main():
    for accounts in (False, True):
        print("run: %s" % ("--pol-members, two addresses (a deployment's shape)"
                           if accounts else "one address, no accounts db"))
        run(accounts)
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
