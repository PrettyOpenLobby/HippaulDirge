#!/usr/bin/env python3
"""LOOPBACK end-to-end for --mission-shared-npcs (2026-10-05), through the real
docudp main(): ONE enemy set per mission room, simulated by one console and
MOVED on the others by relaying its NPC pose stream.

Dual Horn Duel (quest 18, max 3), two players A and B, both through GO:
  * both get the SAME kind-15 Add Npc ids;
  * only the room's controller gets kind 27 (a non-controller's NPC stays
    uncontrolled, which the retail receive gate accepts relayed poses for);
  * the controller's NPC pose -- the real captured mode-4 bytes (header under
    a cipher we do not hold) and a readable type-3 one -- reaches the OTHER
    member as a mode-0, type-3, flags-8 datagram with the NPC id at +16, and
    is never echoed back to the controller;
  * the same pose from the NON-controller is not relayed;
  * TWIN: with --mission-shared-npcs off, nothing is relayed.

    python doc_mission_shared_e2e.py            # ~40 s
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
import docudp as D            # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening  # noqa: E402
from doc_battle_e2e import world_req, gs_req, seal, check, FAILS   # noqa: E402

PORT = int(os.environ.get("DOC_E2E_PORT", "41591"))
TMP = os.environ.get("TEMP", HERE)
A_CID, B_CID = 0x000410E4, 0x000410E8
NPC0 = 0x40000100
DUAL_HORN_DUEL = 18
# a controller's NPC pose as captured on prod 10-05 (mode 4, header enciphered)
NPC_POSE_MODE4 = bytes.fromhex(
    "0404400007320e001e0c4541dbf8e6fb57be4c008751718c"
    "000100400000e0c4adac48c2008000c400000000000000000000803f020080060001000000000000")


def npc_pose_readable(nid, ms=1234):
    """The same pose with a readable header: type 3, flags 8, the id at +16."""
    pkt = bytearray(NPC_POSE_MODE4)
    pkt[1] = 0
    pkt[8:24] = bytes(16)
    pkt[8], pkt[9] = 3, 0x08
    struct.pack_into("<I", pkt, 4, ms)
    struct.pack_into("<I", pkt, 16, nid)
    struct.pack_into("<I", pkt, D.BODY_OFF, nid)
    return seal(pkt)


def seq_pose(nid, seq, ms):
    """A readable NPC pose with header sequence `seq` (+14) and clock `ms`."""
    pkt = bytearray(npc_pose_readable(nid, ms=ms))
    struct.pack_into("<H", pkt, 14, seq)
    return seal(pkt)


def damage_113(sender, victim, dmg, shot):
    """A hit as the retail client builds it (0x00bee2e8 -> serializer
    0x005961a8): type 0x71, flags 8, +16 the sender, +20 the record target --
    for an NPC its controller id, 0 on a console never sent kind 27 --
    body {u32 1, u32 victim, s32 damage, u32 attacker, u32 shot id}."""
    pkt = bytearray(D.BODY_OFF + 4 + 16)
    pkt[0], pkt[1] = 0x04, 4         # MODE 4, as the console sends it ...
    # ... with a header under a cipher we do not hold (named by its body)
    pkt[8:24] = bytes((0x5b + 37 * i) & 0xFF for i in range(16))
    struct.pack_into("<IIiII", pkt, D.BODY_OFF, 1, victim, dmg, sender, shot)
    struct.pack_into("<H", pkt, 2, len(pkt))
    return bytes(pkt)


#: NPC_POSE_MODE4's position (body +4): where the NPC stood
NPC_POSE_AT = struct.unpack_from("<3f", NPC_POSE_MODE4, D.BODY_OFF + 4)


def shot_112(origin, direction=(0.0, 0.0, 1.0)):
    """A shot as a console whose mode-4 header we cannot read sends it: 56-byte
    body, the slot table first (one empty slot, as captured 10-03), origin and
    direction floats at body+24."""
    pkt = bytearray(D.BODY_OFF + 56)
    pkt[0], pkt[1] = 0x04, 4
    pkt[8:24] = bytes((0x2d + 53 * i) & 0xFF for i in range(16))
    pkt[D.BODY_OFF:D.BODY_OFF + 10] = bytes.fromhex("14300631ffffffff1734")
    struct.pack_into("<6f", pkt, D.BODY_OFF + 24, *(tuple(origin) + tuple(direction)))
    struct.pack_into("<H", pkt, 2, len(pkt))
    return bytes(pkt)


def shots_112(pkts):
    """The +16 shooter of every relayed (mode 0) 112."""
    return [struct.unpack_from("<I", p, 16)[0] for p in pkts
            if len(p) == D.BODY_OFF + 56 and p[1] == 0 and p[8] == 0x70]


def hits_113(pkts):
    """The +20 record target of every 113 received."""
    return [struct.unpack_from("<I", p, 20)[0] for p in pkts
            if len(p) >= D.BODY_OFF + 20 and p[8] == 0x71 and p[1] == 0]


def report_24(entries):
    from doc_mission_npc_e2e import report
    return report(entries)


def kind_of(p):
    if (len(p) >= D.BODY_OFF + 16
            and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 35):
        return struct.unpack_from("<I", p, D.BODY_OFF + 12)[0]
    return None


def k27_ids(pkts):
    return [struct.unpack_from("<I", p, D.BODY_OFF + 16)[0]
            for p in pkts if kind_of(p) == 27]


def k15_ids(pkts):
    out = []
    for p in pkts:
        if kind_of(p) == D.doc_npc_spawn.KIND_ADD_NPC:
            n = struct.unpack_from("<I", p, D.BODY_OFF + 16)[0]
            out += [struct.unpack_from("<I", p, D.BODY_OFF + 20 + 24 * k)[0]
                    for k in range(n)]
    return out


def relayed_poses(pkts):
    """Relayed NPC poses: mode 0, inner type 3, flags 8, NPC id at +16."""
    return [struct.unpack_from("<I", p, 16)[0] for p in pkts
            if len(p) == D.BODY_OFF + 40 and p[1] == 0 and p[8] == 3
            and p[9] & 0x08 and struct.unpack_from("<I", p, 16)[0] & 0x40000000]


def run(shared):
    import docpg
    db = docpg.new_database()
    if db is None:
        sys.exit(docpg.skip_or_fail("doc_mission_shared_e2e"))
    tag = "doc_mission_shared_e2e" + ("" if shared else "_off")
    port = PORT if shared else PORT + 1      # never the port a dying server holds
    log_path = os.path.join(TMP, tag + ".log")
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(port),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--bt-no-onfly-reserve",
            "--gs-battle-go-after=1", "--gs-real-dist-settle=1",
            "--gs-battle-reset-after=1", "--gs-battle-after-join=2",
            "--session-idle-drop=0", "--intro=off", "--npc-arena-after=1",
            "--mission-ledger=off", "--stats", "on",
            "--mission-shared-npcs", "on" if shared else "off"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1",
               POL_DATABASE_URL=db)
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    print("run: --mission-shared-npcs %s" % ("on" if shared else "off"))
    got = {"A": [], "B": []}
    try:
        wait_listening(log, srv)
        check("docudp is up", srv.poll() is None)
        dst = ("127.0.0.1", port)
        socks = {}
        for n in ("A", "B"):
            c = udp_socket()
            c.bind(("127.0.0.1", 0))
            c.settimeout(0.02)
            socks[n] = c

        def pump(secs):
            t_end = time.time() + secs
            while time.time() < t_end:
                for n, c in socks.items():
                    try:
                        got[n].append(c.recv(65535))
                    except socket.timeout:
                        pass

        rec = D.build_battletable_record(table_id=0, leader=0, cur=1, maximum=3,
                                         map_idx=0, mode=1, comment="shared",
                                         flags=D.BT_FLAG_MISSION,
                                         mission=DUAL_HORN_DUEL)
        socks["A"].sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        pump(0.8)
        socks["B"].sendto(world_req(B_CID, D.BT_REQ_JOIN, struct.pack("<H", 1)), dst)
        pump(0.8)
        socks["A"].sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                                    struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        pump(0.8)
        for n, cid in (("A", A_CID), ("B", B_CID)):
            socks[n].sendto(gs_req(cid, 31, arg=0, session=1), dst)
        pump(3.0)
        socks["A"].sendto(gs_req(A_CID, 47, session=1), dst)
        pump(0.4)
        socks["B"].sendto(gs_req(B_CID, 47, session=1), dst)
        pump(5.0)                     # GO + --npc-arena-after 1, for both
        a15, b15 = set(k15_ids(got["A"])), set(k15_ids(got["B"]))
        check("both members get the enemy (kind 15 for 0x%x)" % NPC0,
              NPC0 in a15 and NPC0 in b15, "A %s B %s" % (sorted(map(hex, a15)),
                                                         sorted(map(hex, b15))))
        a27, b27 = k27_ids(got["A"]), k27_ids(got["B"])
        if shared:
            check("ONE controller: exactly one member got kind 27",
                  bool(a27) != bool(b27), "A %r B %r" % (a27, b27))
        else:
            check("TWIN (off): each member controls its own copy (kind 27 to both)",
                  bool(a27) and bool(b27), "A %r B %r" % (a27, b27))
        ctl, other = ("A", "B") if a27 else ("B", "A")
        cids = {"A": A_CID, "B": B_CID}
        n_before = {n: len(got[n]) for n in got}
        # the controller's stream: the captured mode-4 bytes, then a readable one
        socks[ctl].sendto(NPC_POSE_MODE4, dst)
        pump(0.5)
        socks[ctl].sendto(npc_pose_readable(NPC0 + 0, ms=777), dst)
        pump(0.5)
        to_other = relayed_poses(got[other][n_before[other]:])
        to_ctl = relayed_poses(got[ctl][n_before[ctl]:])
        if shared:
            check("the controller's mode-4 + readable NPC poses reach the OTHER "
                  "member (mode 0, type 3, flags 8, id at +16)",
                  to_other.count(NPC0) == 2, "%r" % [hex(i) for i in to_other])
        else:
            check("TWIN (off): nothing is relayed", not to_other, "%r" % to_other)
        check("never echoed back to the controller", not to_ctl, "%r" % to_ctl)
        # a stray pose from the NON-controller is not relayed
        n_ctl = len(got[ctl])
        socks[other].sendto(npc_pose_readable(NPC0, ms=999), dst)
        pump(0.5)
        check("a non-controller's NPC pose is not relayed",
              not relayed_poses(got[ctl][n_ctl:]))
        # 2026-10-05: per-unit copies share the SEQUENCE; only the clock at +4
        # is re-read per copy -> one relay for two copies 1 ms apart
        n_o = len(got[other])
        for ms in (800, 801):
            socks[ctl].sendto(seq_pose(NPC0, seq=41, ms=ms), dst)
        socks[ctl].sendto(seq_pose(NPC0, seq=42, ms=834), dst)
        pump(0.6)
        if shared:
            check("dedupe: two copies (seq 41, ms 800/801) relay ONCE, seq 42 too",
                  relayed_poses(got[other][n_o:]).count(NPC0) == 2,
                  "%d relayed" % relayed_poses(got[other][n_o:]).count(NPC0))
        # 2026-10-05: an unreadable SHOT from the controller fired at the NPC's
        # last pose is the NPC's (relayed with +16 = the NPC id); one from far
        # away stays the controller's
        if shared:
            n_o = len(got[other])
            socks[ctl].sendto(shot_112(NPC_POSE_AT), dst)
            socks[ctl].sendto(shot_112((NPC_POSE_AT[0] + 900.0,) + NPC_POSE_AT[1:]), dst)
            pump(0.6)
            shooters = shots_112(got[other][n_o:])
            check("an unreadable controller shot from the NPC's spot is relayed as "
                  "the NPC's (+16), a far one as the controller's",
                  sorted(shooters) == sorted([NPC0, cids[ctl]]),
                  "%r" % [hex(i) for i in shooters])
        # a NON-controller's hit on the shared enemy: its client addresses the
        # 113 to the NPC's controller id, 0 there -> re-targeted to the controller
        n_c, n_o = len(got[ctl]), len(got[other])
        socks[other].sendto(damage_113(cids[other], NPC0, -30, shot=7), dst)
        pump(0.6)
        to_c = hits_113(got[ctl][n_c:])
        to_o = hits_113(got[other][n_o:])
        if shared:
            check("a non-controller's NPC hit reaches the controller, +20 = the "
                  "controller's id", to_c == [cids[ctl]], "%r" % [hex(t) for t in to_c])
            check("... and nobody else", not to_o, "%r" % to_o)
            # the controller's 1 Hz report: the enemy 100 -> 0 = a kill, credited
            # to the non-controller who hit it (Dual Horn Duel: 1 kill ends it)
            for hp in (100, 0):
                socks[ctl].sendto(report_24([(NPC0, hp)]), dst)
                pump(0.6)
            pump(1.5)
    finally:
        srv.terminate()
        try:
            srv.wait(10)
        except subprocess.TimeoutExpired:
            srv.kill()
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    if shared:
        end = [l for l in text.splitlines() if "END table" in l and "MISSION" in l]
        check("the enemy's death is credited to the non-controller who hit it",
              bool(end) and ("'0x%x': 1" % cids[other]) in end[0]
              and ("'0x%x': 0" % cids[ctl]) in end[0], end[0] if end else "no END")
    check("no traceback", "Traceback" not in text)
    check("no GS request 256 (the pose is no longer read as a request)",
          "GS request 256" not in text)
    if shared:
        check("logged: the NPC POSE relay", "NPC POSE 0x40000100" in text)
        check("logged: the NPC HIT re-target", "NPC HIT by" in text)
    print("log: %s" % log_path)


def main():
    run(shared=True)
    time.sleep(2.0)
    run(shared=False)
    print("ALL PASS" if not FAILS else "%d FAIL(S)" % len(FAILS))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
