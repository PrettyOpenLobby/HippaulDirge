#!/usr/bin/env python3
"""LOOPBACK end-to-end for the LAUNCH medals (2026-09-26).

doc_stats.MEDALS is SE's 20060124_3 lobby.bin group 60 (the January 2006
launch build the served clients run); the inputs of the mode medals are filled
by docudp's room tally. This drives the real docudp.py with two fake clients
through a Team Capsule and a Team Survival table and reads the kind-4 RESULT
records (the medal-holder slots at rec+30+h, holder h = medal id h =
group-60 index - 16) and the server log back:

  tcp        mode 4, 2 capsules: B picks one up, A KOs B (request 30), B's
             client drops it (118) -> Capsule Seeker (23, holder 7) names A in
             BOTH records, once (the drop is the same KO)
  tcp_twin   the same with B holding nothing when KO'd -> nobody holds 7
  tdm        mode 2 (Team Survival): A KOs B, B's side is wiped -> Survivor
             (20, holder 4) and Slayer (21, holder 5) name A; nothing names B

    python doc_medals_e2e.py        # ~60 s; DOC_E2E_PORT picks the port
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
import docudp as D                                          # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening  # noqa: E402
import doc_stats as S                                       # noqa: E402
from doc_battle_e2e import (world_req, gs_req, field_req, check,  # noqa: E402
                            notifies, FAILS)
from doc_base_e2e import touch_req, k10_items, notes_of     # noqa: E402

PORT = int(os.environ.get("DOC_E2E_PORT", "41566"))
A_CID, B_CID = 0x0002A664, 0x00041018
NOBODY = 0xFF


def drain(sock):
    got = []
    try:
        while True:
            got.append(sock.recv(65535))
    except socket.timeout:
        pass
    return got


def holders_of(pkt):
    """The 15 medal-holder roster slots of a kind-4 notify (record at
    body[20], holders at record+30)."""
    rec = pkt[D.BODY_OFF + 20:]
    return list(rec[S.RES_HOLDERS:S.RES_HOLDERS + S.RES_HOLDER_COUNT])


def run(tag, mode, capsules=0, carrier=True):
    tmp = os.environ.get("TEMP", HERE)
    log_path = os.path.join(tmp, "doc_medals_e2e_%s.log" % tag)
    # the career store: a fresh database for this server
    import docpg
    docpg.e2e_database("doc_medals_e2e")
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--bt-no-onfly-reserve",
            "--gs-battle-length=10", "--gs-battle-go-after=1",
            "--gs-real-dist-settle=1", "--gs-battle-reset-after=1",
            "--gs-battle-after-join=30", "--session-idle-drop=0", "--intro=off",
            "--stats", "on"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    got = {A_CID: [], B_CID: []}
    try:
        wait_listening(log, srv)
        check("[%s] docudp is up" % tag, srv.poll() is None)
        dst = ("127.0.0.1", PORT)
        so = {}
        for cid in (A_CID, B_CID):
            so[cid] = udp_socket()
            so[cid].bind(("127.0.0.1", 0))
            so[cid].settimeout(0.4)

        def pump():
            for cid in so:
                got[cid] += drain(so[cid])

        rec = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                                   maximum=4, map_idx=2,
                                                   mode=mode, comment=tag))
        rec[D.BT_OFF_CAPSULES] = capsules
        so[A_CID].sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.5)
        so[B_CID].sendto(world_req(B_CID, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
        time.sleep(0.5)
        so[A_CID].sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                                   struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.8)
        so[A_CID].sendto(gs_req(A_CID, 31, arg=0, session=1), dst)
        so[B_CID].sendto(gs_req(B_CID, 31, arg=1, session=1), dst)
        time.sleep(2.5)
        so[A_CID].sendto(gs_req(A_CID, 47, session=1), dst)
        time.sleep(0.2)
        so[B_CID].sendto(gs_req(B_CID, 47, session=1), dst)
        time.sleep(2.0)                          # the shared GO after 1 s
        pump()
        caps = [c for c in k10_items(notes_of(got[B_CID]))
                if c[0] == D.MAKO_CAPSULE]
        if capsules:
            check("[%s] the capsules went out at GO" % tag,
                  len(caps) == capsules, "%r" % caps)
        if carrier and caps:
            _i, _c, slot, (x, y, z) = caps[0]
            so[B_CID].sendto(touch_req(B_CID, slot, 0, (x + 8.0, y, z)), dst)
            time.sleep(0.5)
            pump()
        # A KOs B: B's client reports its own death (request 30, killer A)
        so[B_CID].sendto(gs_req(B_CID, 30, arg=A_CID, hdr_arg=B_CID, session=1), dst)
        time.sleep(0.3)
        if carrier and caps:
            # ...and drops what it held (118 {item, count, seq, f32 pos})
            so[B_CID].sendto(field_req(B_CID, D.P2P_DROP, struct.pack(
                "<IIIfff", D.MAKO_CAPSULE, 1, 1, 0.0, 0.0, 0.0)), dst)
        time.sleep(0.5)
        pump()
        deadline = time.time() + 14.0
        while time.time() < deadline and not (
                notifies(got[A_CID], 4) and notifies(got[B_CID], 4)):
            time.sleep(0.5)
            pump()
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
            srv.wait()          # until it has exited it still holds the port
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    res = {c: notifies(got[c], 4) for c in got}
    check("[%s] no traceback" % tag, "Traceback" not in text)
    check("[%s] kind 4 reached both" % tag, res[A_CID] and res[B_CID],
          "A %d, B %d" % (len(res[A_CID]), len(res[B_CID])))
    # roster = the others in seat order, then self: A's = [B, A], B's = [A, B]
    ha = holders_of(res[A_CID][0]) if res[A_CID] else [None] * 15
    hb = holders_of(res[B_CID][0]) if res[B_CID] else [None] * 15
    return text, ha, hb


def main():
    M = lambda idx: idx - S.MEDAL_BASE          # medal id = holder slot

    text, ha, hb = run("tcp", 4, capsules=2)
    check("[tcp] Capsule Seeker names A in A's record (slot 1) and B's (slot 0)",
          ha[M(S.M_CAPSULE_SEEKER)] == 1 and hb[M(S.M_CAPSULE_SEEKER)] == 0,
          "A %r B %r" % (ha, hb))
    check("[tcp] the result log lists it for A only",
          "RESULT [anon/0x%08x] TCP" % A_CID in text
          and "'Capsule Seeker Medal'" in text
          and text.count("'Capsule Seeker Medal'") == 1)
    check("[tcp] no 2005-beta medal (Iron Seal / First Attack) anywhere",
          "Iron Seal" not in text and "First Attack" not in text)

    text, ha, hb = run("tcp_twin", 4, capsules=2, carrier=False)
    check("[tcp_twin] TWIN: B held nothing when KO'd -> nobody holds Capsule "
          "Seeker", ha[M(S.M_CAPSULE_SEEKER)] == NOBODY
          and hb[M(S.M_CAPSULE_SEEKER)] == NOBODY, "A %r B %r" % (ha, hb))

    text, ha, hb = run("tdm", 2)
    check("[tdm] Survivor and Slayer name A in both records",
          ha[M(S.M_SURVIVOR)] == 1 and ha[M(S.M_SLAYER)] == 1
          and hb[M(S.M_SURVIVOR)] == 0 and hb[M(S.M_SLAYER)] == 0,
          "A %r B %r" % (ha, hb))
    check("[tdm] TWIN: Team Merit (a TBT medal) is not paid in Team Survival",
          ha[M(S.M_TEAM_MERIT)] == NOBODY)
    check("[tdm] no medal names B (B is slot 1 in its own record, 0 in A's)",
          1 not in hb and 0 not in ha, "A %r B %r" % (ha, hb))
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
