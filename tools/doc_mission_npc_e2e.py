#!/usr/bin/env python3
"""LOOPBACK end-to-end for the MISSION NPC control handoff (2026-09-28), through
the real docudp main():

  Beginner's Course I (quest 39, 5 kills) -> GO -> kind 15 Add Npc x2 + kind 27
  x2 (control -> the player). The test plays the client's 1 Hz report (request
  24, mode 4, the NPC list in the clear from datagram+88).

    0x100 dies               -> 5 s later the REPLACEMENT 0x102: kind 15, then
                                its kind 27 >= 0.25 s LATER (sent back to back,
                                the two landed in one client frame, the 27 ran
                                first and was lost: the replacements never
                                entered the report and the mission stuck at 3
                                kills of 5)
    0x102 kept OUT of the report (the lost handoff)
                             -> its kind 27 is RE-SENT
    0x102 in the report      -> no more 27s for it
    TWIN: 0x101, in every report from the start, never gets a second 27
    a report with the 8-byte ammo trailer still counts a kill

    python doc_mission_npc_e2e.py            # ~35 s
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
from doc_e2e_udp import udp_socket  # noqa: E402
import doc_gear as G          # noqa: E402,F401
from doc_battle_e2e import world_req, gs_req, check, FAILS   # noqa: E402

PORT = int(os.environ.get("DOC_E2E_PORT", "41577"))
TMP = os.environ.get("TEMP", HERE)
CID = 0x000410DC
NPC0 = 0x40000100
COURSE_I = 39


def report(entries, trailer=False):
    """The client's 1 Hz report as a PCSX2 client sends it: mode 4, header
    enciphered (garbage here), type 24 at wire+24, NPC count at [87], 12-byte
    entries {u32 id, u16 HP, s16 x, y, z} from +88."""
    n = len(entries)
    pkt = bytearray(88 + 12 * n + (8 if trailer else 0))
    pkt[0], pkt[1] = 0x04, 0x04
    struct.pack_into("<H", pkt, 2, len(pkt))
    pkt[4:24] = bytes((0x5b + 37 * i) & 0xFF for i in range(20))
    struct.pack_into("<HHII", pkt, 24, 24, 1, 0, 1)
    pkt[87] = n
    for k, (nid, hp) in enumerate(entries):
        struct.pack_into("<IH", pkt, 88 + 12 * k, nid, hp)
    if trailer:
        struct.pack_into("<II", pkt, 88 + 12 * n, 0x62300002, 76)
    return bytes(pkt)


def kind_of(p):
    """Notify kind of message 35 `p`, else None (a kind-27 packet is shorter
    than doc_battle_e2e.notifies() accepts)."""
    if (len(p) >= D.BODY_OFF + 16
            and struct.unpack_from("<H", p, D.BODY_OFF)[0] == 35):
        return struct.unpack_from("<I", p, D.BODY_OFF + 12)[0]
    return None


def k27_ids(pkts):
    return [struct.unpack_from("<I", p, D.BODY_OFF + 16)[0]
            for p in pkts if kind_of(p) == 27]


def k15_ids(pkts):
    # payload {u32 count, 24-byte entries}; entry +0 = the NPC id
    out = []
    for p in pkts:
        if kind_of(p) == D.doc_npc_spawn.KIND_ADD_NPC:
            n = struct.unpack_from("<I", p, D.BODY_OFF + 16)[0]
            out += [struct.unpack_from("<I", p, D.BODY_OFF + 20 + 24 * k)[0]
                    for k in range(n)]
    return out


def unit():
    ok = D.mission_npc_report(report([(NPC0, 0), (NPC0 + 1, 100)], trailer=True))
    check("unit: a report with the 8-byte trailer parses",
          ok == [(NPC0, 0), (NPC0 + 1, 100)], "%r" % (ok,))
    bad = bytearray(report([(0x12345678, 5)], trailer=True))
    check("unit TWIN: a trailer-length datagram without NPC ids is not a report",
          D.mission_npc_report(bytes(bad)) is None)
    check("unit: the exact-length report still parses",
          D.mission_npc_report(report([(NPC0, 100)])) == [(NPC0, 100)])


def main():
    unit()
    if not D.MISSION_SPAWNS:
        # the mission enemies' spawn nodes are the arenas' own data
        # (doc_mission_spawns.json, not shipped; README.md, "Arena data")
        print("SKIP no doc_mission_spawns.json beside docudp.py: the mission "
              "run needs your own enemy spawn nodes (the unit checks ran: %s)"
              % ("ALL PASS" if not FAILS else "%d FAIL(S)" % len(FAILS)))
        return 1 if FAILS else 0
    stats =os.path.join(TMP, "doc_mission_npc_e2e_stats.json")
    try:
        os.remove(stats)
    except OSError:
        pass
    log_path = os.path.join(TMP, "doc_mission_npc_e2e.log")
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--bt-no-onfly-reserve",
            "--gs-battle-go-after=1", "--gs-real-dist-settle=1",
            "--gs-battle-reset-after=1", "--gs-battle-after-join=2",
            "--session-idle-drop=0", "--intro=off", "--npc-arena-after=1",
            "--mission-ledger=off", "--stats", stats]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                           cwd=HERE)
    got = []                                  # (recv time, packet)
    try:
        time.sleep(2.5)
        check("docudp is up", srv.poll() is None)
        c = udp_socket()
        c.bind(("127.0.0.1", 0))
        c.settimeout(0.05)
        dst = ("127.0.0.1", PORT)

        def pump(secs):
            t_end = time.time() + secs
            while time.time() < t_end:
                try:
                    got.append((time.time(), c.recv(65535)))
                except socket.timeout:
                    pass

        rec = D.build_battletable_record(table_id=0, leader=0, cur=1, maximum=1,
                                         map_idx=0, mode=1, comment="course",
                                         flags=D.BT_FLAG_MISSION,
                                         mission=COURSE_I)
        c.sendto(world_req(CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        pump(0.6)
        c.sendto(world_req(CID, D.LOBBY_CMD_SELECTOR_REQ,
                           struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        pump(0.6)
        c.sendto(gs_req(CID, 31, arg=0, session=1), dst)
        pump(4.0)
        c.sendto(gs_req(CID, 47, session=1), dst)
        pump(4.0)                             # GO + --npc-arena-after 1
        pk = [p for _t, p in got]
        check("GO: kind 15 Add Npc for 0x100 and 0x101",
              {NPC0, NPC0 + 1} <= set(k15_ids(pk)), "%r" % [hex(i) for i in k15_ids(pk)])
        check("GO: kind 27 for 0x100 and 0x101",
              sorted(k27_ids(pk)) == [NPC0, NPC0 + 1],
              "%r" % [hex(i) for i in k27_ids(pk)])
        n_go = len(got)

        # both listed; then 0x100 dies (with the ammo trailer)
        for _ in range(2):
            c.sendto(report([(NPC0, 100), (NPC0 + 1, 100)]), dst)
            pump(1.0)
        c.sendto(report([(NPC0, 0), (NPC0 + 1, 100)], trailer=True), dst)
        pump(1.0)
        # the lost handoff: 0x102 never listed for ~9 s
        for _ in range(9):
            c.sendto(report([(NPC0, 0), (NPC0 + 1, 100)]), dst)
            pump(1.0)
        after = got[n_go:]
        t15 = [t for t, p in after if NPC0 + 2 in k15_ids([p])]
        t27 = [t for t, p in after if NPC0 + 2 in k27_ids([p])]
        check("REPLACEMENT 0x102: one kind 15", len(t15) == 1, "%d" % len(t15))
        check("REPLACEMENT 0x102: its first kind 27 comes >= 0.25 s AFTER the 15",
              t15 and t27 and t27[0] - t15[0] >= 0.25,
              "gap %s" % (round(t27[0] - t15[0], 3) if t15 and t27 else None))
        check("0x102 kept out of the report: its kind 27 is RE-SENT",
              len(t27) >= 2, "%d sends" % len(t27))
        n_mid = len(got)
        # now the handoff takes: 0x102 listed
        for _ in range(5):
            c.sendto(report([(NPC0, 0), (NPC0 + 1, 100), (NPC0 + 2, 100)]), dst)
            pump(1.0)
        late = k27_ids([p for _t, p in got[n_mid:]])
        check("0x102 in the report: no more kind 27 for it",
              NPC0 + 2 not in late, "%r" % [hex(i) for i in late])
        check("TWIN: 0x101 (listed from the start) never got a second kind 27",
              k27_ids([p for _t, p in got]).count(NPC0 + 1) == 1)
        # two more kills through the report
        c.sendto(report([(NPC0, 0), (NPC0 + 1, 0), (NPC0 + 2, 100)]), dst)
        pump(1.0)
        c.sendto(report([(NPC0, 0), (NPC0 + 1, 0), (NPC0 + 2, 0)]), dst)
        pump(1.0)
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    check("no traceback", "Traceback" not in text)
    check("logged: the trailer report counted 0x100's death",
          "enemy down (1 Hz report): ['0x40000100'] -> 1 enemy kill(s)" in text)
    check("logged: the kind-27 RE-SEND for 0x102",
          "NPC 0x40000102 not in the 1 Hz report -- RE-SENT notify kind 27" in text)
    check("logged: control took once 0x102 was listed",
          "NPC 0x40000102 is in the 1 Hz report now" in text)
    check("logged: three enemy kills in all",
          "-> 3 enemy kill(s)" in text)
    print("\n%s  (log: %s)" % ("ALL PASS" if not FAILS else
                               "%d FAIL(S): %s" % (len(FAILS), FAILS), log_path))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
