#!/usr/bin/env python3
"""LOOPBACK: a TEAM BASE table gets its bases, a TEAM CAPSULE table its
capsules (2026-09-24).

Live, a Team Base battle showed no base to shoot at. The static RE (docudp BASE_GIMMICKS notes): the
client binds its arena's base gimmicks to the teams from notify kind 29 at
zone setup, and learns base HP / controller from kind 33; we sent kind 29
with a zero record. This drives the real docudp main() through a solo battle
on a Team Base table (mode byte 3, Base Durability 8000) and reads what went
out:

  Jungle (z201): kind 29 with bases [26, 23] right with the spawn, the same in
               the GO burst, then kind 33 x2 with HP 8000 and the controller
  Wastelands (z204, no base in any 11xx situation): no base messages
  Team Battle (mode 1) on Kalm: no base messages
  2026-09-26, TEAM BASE = destroy + OCCUPY (January Additional Manual): the
               controller reports base 1 at HP 0 -> no END; A's type-0x83
               poses on base 1's spot for --base-occupy-s -> END, A is the
               occupier. TWINS: poses off the spot never end it; a pose
               stream that walks off resets the hold; --base-occupy off ends
               the battle at HP 0 (the old rule).

    python doc_base_e2e.py      # ~40 s
"""
import io
import os
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import docudp as D   # noqa: E402
from doc_e2e_udp import udp_socket, wait_listening  # noqa: E402
import doc_stats as S   # noqa: E402
from doc_battle_leave_e2e import (world_req, gs_req, check, FAILS, A_CID,  # noqa: E402
                                  drain, seal)


def touch_req(cid, slot, n, pos):
    """A capsule touch as the live client sends it: a RELIABLE inner type 119
    (flags 0x01) to the server, body {u32 slot, u32 1, u32 n, f32 x, y, z}
    (2026-09-24 capture; mode 0 here, mode 4 live)."""
    pkt = bytearray(D.BODY_OFF + 24)
    pkt[0] = 0x04
    pkt[8], pkt[9] = D.P2P_PICKUP, 1
    struct.pack_into("<I", pkt, 16, cid)
    struct.pack_into("<III3f", pkt, D.BODY_OFF, slot, 1, n, *pos)
    return seal(pkt)


def k10_items(notes, kind=10):
    """[(item, count, slot, (x, y, z))] of the kind-10/11 notes."""
    out = []
    for k, p in notes:
        if k == kind:
            iid, cnt, slot, _z, x, y, z = struct.unpack_from("<IHHHhhh", p,
                                                            D.BODY_OFF + 20)
            out.append((iid, cnt, slot, (x, y, z)))
    return out

PORT = int(os.environ.get("DOC_E2E_PORT", "41562"))


def r24_req(cid, hps):
    """The controller's request 24 (live shape): count at body+61,
    {u32 HP, u16 index, u16 0, u32 mask} from body+64."""
    body = bytearray(64 + 12 * len(hps))
    struct.pack_into("<H", body, 0, 24)
    body[61] = len(hps)
    for i, hp in enumerate(hps):
        struct.pack_into("<IHHI", body, 64 + 12 * i, hp, i, 0, 1 if hp == 0 else 0)
    pkt = bytearray(D.BODY_OFF) + body
    pkt[0] = 0x04
    pkt[8], pkt[9] = D.GS_INNER_TYPE, 1
    struct.pack_into("<I", pkt, 16, cid)
    return seal(pkt)


def pose_req(cid, pos):
    """A type-0x83 position report: body {u32 id, f32 x, y, z, f32 dir x, y, z}
    (docudp.ingame_pose), mode 0 here."""
    pkt = bytearray(D.BODY_OFF + 0x28)
    pkt[0] = 0x04
    pkt[8], pkt[9] = 0x83, 1
    struct.pack_into("<I", pkt, 16, cid)
    struct.pack_into("<I3f3f", pkt, D.BODY_OFF, cid, pos[0], pos[1], pos[2],
                     0.0, 0.0, 1.0)
    return seal(pkt)


def occupy_drive(poses):
    """after-GO driver: bases 8000 / 8000, then base 1 at 0, then one pose
    per 0.25 s from `poses` (a list of positions)."""
    def drive(ca, dst, got):
        ca.sendto(r24_req(A_CID, [8000, 8000]), dst)
        time.sleep(0.3)
        ca.sendto(r24_req(A_CID, [8000, 0]), dst)
        time.sleep(0.5)
        got += drain(ca)
        for pos in poses:
            ca.sendto(pose_req(A_CID, pos), dst)
            time.sleep(0.25)
        time.sleep(0.5)
        got += drain(ca)
    return drive


def battle(tag, map_idx, mode, base_hp, capsules=0, mission=0, touch=0,
           drive=None, extra=()):
    log_path = os.path.join(os.environ.get("TEMP", HERE), "doc_base_e2e_%s.log" % tag)
    log = io.open(log_path, "w", encoding="utf-8")
    argv = [sys.executable, os.path.join(HERE, "docudp.py"),
            "--bind", "127.0.0.1", "--port", str(PORT),
            "--gs-connect", "--gs-connect-id=65535", "--gs-connect-ip=127.0.0.1",
            "--bt-start-ready", "--bt-no-onfly-reserve",
            "--gs-battle-length=600", "--gs-battle-go-after=1",
            "--gs-real-dist-settle=1", "--gs-battle-after-join=2",
            "--session-idle-drop=0", "--intro=off"] + list(extra)
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    srv = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=HERE)
    got = []
    try:
        wait_listening(log, srv)
        dst = ("127.0.0.1", PORT)
        ca = udp_socket()
        ca.bind(("127.0.0.1", 0))
        ca.settimeout(0.5)
        rec = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                                   maximum=6, map_idx=map_idx,
                                                   mode=mode, comment="base",
                                                   flags=(D.BT_FLAG_MISSION
                                                          if mission else 0),
                                                   mission=mission))
        struct.pack_into("<I", rec, D.BT_OFF_BASE_HP, base_hp)
        rec[D.BT_OFF_CAPSULES] = capsules
        ca.sendto(world_req(A_CID, D.BT_REQ_CREATE, bytes(rec)), dst)
        time.sleep(0.6)
        drain(ca)
        ca.sendto(world_req(A_CID, D.LOBBY_CMD_SELECTOR_REQ,
                            struct.pack("<II", D.LOBBY_CMD_START, 0)), dst)
        time.sleep(0.6)
        drain(ca)
        ca.sendto(gs_req(A_CID, 31, arg=0, session=1), dst)
        time.sleep(4.0)
        got += drain(ca)
        ca.sendto(gs_req(A_CID, 47, session=1), dst)
        time.sleep(3.0)                       # GO burst after 1 s
        got += drain(ca)
        if touch:
            # walk into the first `touch` capsules, 8 units off, each touch
            # sent twice (the client resends until answered)
            placed = [i for i in k10_items(notes_of(got))][:touch]
            for n, (_i, _c, slot, (x, y, z)) in enumerate(placed):
                for _ in range(2):
                    ca.sendto(touch_req(A_CID, slot, n, (x + 8.0, y, z)), dst)
                    time.sleep(0.15)
            ca.sendto(touch_req(A_CID, 99, 99, (0.0, 0.0, 0.0)), dst)
            time.sleep(2.0)
            got += drain(ca)
        if drive is not None:
            drive(ca, dst, got)
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
            srv.wait()          # until it has exited it still holds the port
        log.close()
    text = io.open(log_path, encoding="utf-8", errors="replace").read()
    return text, notes_of(got)


def notes_of(got):
    notes = []
    for p in got:
        if (len(p) >= D.BODY_OFF + 16
                and struct.unpack_from("<H", p, D.BODY_OFF)[0] == D.GS_NOTIFY_MSG):
            notes.append((struct.unpack_from("<I", p, D.BODY_OFF + 12)[0], p))
    return notes


def kind29_bases(p):
    rec = p[D.BODY_OFF + 20:]
    if len(rec) < 2:
        return []                      # the default kind 29: no record at all
    n = rec[1]
    return [struct.unpack_from("<HHH", rec, 4 + 16 * i) for i in range(n)]


def main():
    if not D.BASE_POSITIONS:
        # the team base and start positions are the arenas' own data
        # (doc_arena_table.json, not shipped; README.md, "Arena data")
        print("SKIP no doc_arena_table.json beside docudp.py: the Team Base "
              "run needs your own base and start positions")
        return
    text, notes = battle("jungle", 0, 3, 8000)      # Jungle (map 0), z201
    check("[jungle] no traceback", "Traceback" not in text)
    k29 = [p for k, p in notes if k == 29]
    k33 = [p for k, p in notes if k == 33]
    check("[jungle] kind 29 went out with the spawn AND in the GO burst",
          len(k29) >= 2, "%d" % len(k29))
    check("[jungle] every kind 29 names Jungle's bases 26 / 23 as type-1 "
          "entries for teams 0 / 1",
          k29 and all(kind29_bases(p) == [(1, 0, 26), (1, 1, 23)] for p in k29),
          "%r" % [kind29_bases(p) for p in k29])
    check("[jungle] kind 33 x2: table index 0 / 1, controller = A, HP 8000",
          sorted(struct.unpack_from("<III", p, D.BODY_OFF + 16) for p in k33)
          == [(0, A_CID, 8000), (1, A_CID, 8000)],
          "%r" % [struct.unpack_from("<III", p, D.BODY_OFF + 16) for p in k33])
    check("[jungle] team 0 spawns at Jungle's team-0 start",
          "spawns at team 0's start (482.8, -17.7, -993.2) (zone 201)" in text)
    check("[jungle] logged", "[base] SENT notify kind 29: bases [26, 23]" in text
          and "[base] SENT notify kind 33 x2: HP 8000" in text)

    # 2026-09-26: destroy + OCCUPY. A (team 0) must hold base 1's spot.
    _spot = D.base_spots(201)[1]
    _on = (_spot[0] + 20.0, _spot[1], _spot[2] + 20.0)
    _off = (_spot[0] + 400.0, _spot[1], _spot[2])
    _occ = ("--base-occupy-s=2", "--base-occupy-radius=100")
    text, notes = battle("occupy", 0, 3, 8000, extra=_occ,
                         drive=occupy_drive([_on] * 14))
    check("[occupy] no traceback", "Traceback" not in text)
    check("[occupy] base 1 at HP 0 opened the occupation phase (no END then)",
          "base 1 (team 1) DESTROYED -- team 0 must occupy it" in text
          and -1 < text.find("DESTROYED") < text.find("[battle] END"))
    check("[occupy] A on the spot 2 s -> END, A is the occupier, kind 4 sent",
          "WINS (occupier 0x%x)" % A_CID in text
          and "base destroyed and occupied by 0x%x" % A_CID in text
          and any(k == 4 for k, _ in notes))

    text, notes = battle("occupy_off_spot", 0, 3, 8000, extra=_occ,
                         drive=occupy_drive([_off] * 14))
    check("[occupy_off_spot] TWIN: poses 400 away -> no hold, no END, no kind 4",
          "DESTROYED" in text and "OCCUPYING" not in text
          and "[battle] END" not in text and not any(k == 4 for k, _ in notes))

    text, notes = battle("occupy_reset", 0, 3, 8000, extra=_occ,
                         drive=occupy_drive([_on] * 4 + [_off] * 2 + [_on] * 3
                                              + [_off] * 12))
    check("[occupy_reset] TWIN: 1 s on, walk off -> hold BROKEN; 0.75 s back "
          "on, then off again, is not enough",
          "BROKEN" in text and "[battle] END" not in text,
          "END" if "[battle] END" in text else "")

    text, notes = battle("occupy_disabled", 0, 3, 8000,
                         extra=("--base-occupy=off",),
                         drive=occupy_drive([]))
    check("[occupy_disabled] TWIN: --base-occupy off -> HP 0 ends it at once",
          "team 1's base destroyed" in text and "DESTROYED --" not in text
          and any(k == 4 for k, _ in notes))

    text, notes = battle("wastelands", 3, 3, 8000)
    check("[wastelands] no base message: its 11xx situations list no base",
          "[base]" not in text and not any(k == 33 for k, _ in notes))

    text, notes = battle("tbt", 2, 1, 8000)
    check("[tbt] a Team Battle table on Kalm sends no base message, no capsule",
          "[base]" not in text and "[capsule]" not in text)
    check("[tbt] and its GO kind 29 stays the zero record (the damage gate)",
          all(kind29_bases(p) == [] for k, p in notes if k == 29))

    # TEAM CAPSULE (mode 4) with 3 capsules on Kalm: the field goes out at GO
    text, notes = battle("capsule", 2, 4, 0, capsules=3)
    k10 = [struct.unpack_from("<IHH", p, D.BODY_OFF + 20) for k, p in notes if k == 10]
    check("[capsule] no traceback", "Traceback" not in text)
    check("[capsule] kind 10 x3 at GO: Mako Capsules in slots 0..2",
          sorted(k10) == [(D.MAKO_CAPSULE, 1, 0), (D.MAKO_CAPSULE, 1, 1),
                          (D.MAKO_CAPSULE, 1, 2)], "%r" % k10)
    check("[capsule] logged placed + sent",
          "[capsule] table 1: 3 Mako Capsule(s) placed" in text
          and "[capsule] SENT notify kind 10 x3" in text)
    check("[capsule] no base messages on a capsule table", "[base]" not in text)

    # CAPSULE MISSION: Collector's Mind (quest 16, collect 7) gets 7 at GO
    text, notes = battle("capmission", 0, 1, 0, mission=16)
    k10 = [struct.unpack_from("<IHH", p, D.BODY_OFF + 20) for k, p in notes if k == 10]
    check("[capmission] no traceback", "Traceback" not in text)
    check("[capmission] kind 10 x7 at GO: Mako Capsules in slots 0..6",
          sorted(k for k in k10 if k[0] == D.MAKO_CAPSULE)
          == [(D.MAKO_CAPSULE, 1, i) for i in range(7)], "%r" % k10)
    # 2026-09-26: + the church's Fuzzy Seed (doc_npcquests.mission_items,
    # doc_fuzzyseed_e2e) after them
    check("[capmission] ...and the Fuzzy Seed in slot 7",
          (0x6430001B, 1, 7) in k10, "%r" % k10)
    check("[capmission] no scoreboard / hold (46-48 are the Team Capsule HUD)",
          not any(k in (46, 47, 48) for k, _ in notes))

    # LIVE a touch is a RELIABLE inner-119 to the server, slot first
    text, notes = battle("captouch", 2, 4, 0, capsules=3, touch=2)
    k11 = k10_items(notes, 11)
    check("[captouch] no traceback", "Traceback" not in text)
    check("[captouch] two touches (each resent) -> kind 11 x2, slots 0 / 1 once "
          "each, ident = A", sorted(i[2] for i in k11) == [0, 1]
          and all(struct.unpack_from("<I", p, 16)[0] == A_CID
                  for k, p in notes if k == 11), "%r" % k11)
    check("[captouch] the scoreboard follows each pick-up (kind 46)",
          sum(1 for k, _ in notes if k == 46) == 2)
    check("[captouch] TWIN: an empty slot (99) grants nothing",
          "slot 99 empty" in text)
    check("[captouch] each touch is ACKed (stops the 500 ms resend)",
          text.count("SENT 1 reliable ACK") >= 4)

    # 2026-09-26: the launch medal 60:[48] Last Capsule -- A's second touch
    # completes the set, the 10 s hold wins it, A's result names the medal
    # (holder 8 = medal id 24 - 16 = A, the only roster slot 0)
    def _hold(touch):
        # past doc_stats.RP_MIN_SECONDS first (a shorter battle with no kill
        # is VOID and pays nothing), then touch `touch` capsules, then wait
        # out the hold
        def drive(ca, dst, got):
            time.sleep(S.RP_MIN_SECONDS + 1.0)
            for n, (_i, _c, slot, (x, y, z)) in enumerate(
                    [c for c in k10_items(notes_of(got))
                     if c[0] == D.MAKO_CAPSULE][:touch]):
                ca.sendto(touch_req(A_CID, slot, n, (x + 8.0, y, z)), dst)
                time.sleep(0.3)
            time.sleep(D.CAPSULE_HOLD_S + 2.0)
            got += drain(ca)
        return drive
    # the career store: a fresh database both battles below share
    import docpg
    docpg.e2e_database("doc_base_e2e")
    text, notes = battle("caplast", 2, 4, 0, capsules=2, drive=_hold(2),
                         extra=("--stats", "on"))
    k4 = [p for k, p in notes if k == 4]
    check("[caplast] both held for 10 s -> END, kind 4",
          "holds all 2" in text and k4 and "[battle] END" in text)
    check("[caplast] Last Capsule Medal: A's RESULT names it, holder 8 = A",
          "'Last Capsule Medal'" in text and k4
          and k4[0][D.BODY_OFF + 20 + 30 + 8] == 0,
          k4[0][D.BODY_OFF + 50:D.BODY_OFF + 65].hex() if k4 else "no kind 4")
    text, notes = battle("caplast_twin", 2, 4, 0, capsules=2, drive=_hold(1),
                         extra=("--stats", "on"))
    check("[caplast_twin] TWIN: 1 of 2 held -> no hold, no END, no Last Capsule",
          "holds all" not in text and not any(k == 4 for k, _ in notes)
          and "Last Capsule Medal" not in text)

    text, notes = battle("capwin", 0, 1, 0, mission=4, touch=3)
    check("[capwin] exam 4 (collect 3): 3 touches win it -- kind 4 result",
          "mission target reached (3 held)" in text
          and any(k == 4 for k, _ in notes)
          and "[battle] END" in text, "%r" % sorted({k for k, _ in notes}))

    # TWIN: a kill mission (quest 1) gets no capsules. (2026-09-26: it does
    # get its map's item generators -- ammo, Potions -- as kind 10s)
    text, notes = battle("killmission", 0, 1, 0, mission=1)
    check("[killmission] no capsule on a kill mission",
          "Mako Capsule(s) placed" not in text
          and not any(i == D.MAKO_CAPSULE for i, _c, _s, _p in k10_items(notes)))

    if FAILS:
        print("%d check(s) failed" % len(FAILS))
        sys.exit(1)
    print("ALL PASS")


if __name__ == "__main__":
    main()
