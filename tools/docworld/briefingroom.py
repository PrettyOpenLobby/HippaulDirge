"""The briefing room (selector 38's ready roster, a Solo quest as a mission) and the burst that starts a battle."""
import struct
from . import framing, gamemsg, tablerecords



# sec 4fy (live 09-13): kind 4 is the battle RESULT, not a setup -- its arm
# 0x00bc1760 opens with facade |= 0x40, and ev2045.battlefield's loop exits on
# 0x40 straight into act_win/act_lose. Pushed at the start it ended every
# battle at once. Selector 39's arm (0x00bcbd70) is the full battle reset.
# sec 4ga: kind 5 (START) sets facade 0x80, which switches getBattleInitPos to
# the player's own record -- so the start burst is the spawn alone, and 5/53
# ("GO") follow once ev2045 has placed the player (waitlogin waits for 0x80).
GS_BATTLE_START_DEFAULT = "2"
# sec 4he: the DAMAGE GATE. The 113 receiver 0x00be99d8 needs facade 0x20,
# which 0x00bc2aa0 posts only when [chan+204] holds 0x100 (kind 28), 0x200
# (kind 29), 0x400 (kind 30 / 28) AND 0x20 (kind 3) -- and it runs from kind 3
# and kind 30. With zero 64-byte records 28/29 register nothing (their loops
# run 0 times); 3 then sees 0x720 and opens the gate. The 09-13 arena
# savestates hold facade 0x2cf / 0x28f: bit 0x20 DOWN, so every relayed
# damage record would have been dropped. doc_zone_setup_proof.py ran
# 3+28+29+30 ALL PASS in the emulator; live-unproven.
# 2026-09-24: kind 53 DROPPED from the burst -- the retail game-server notify
# dispatcher 0x00bcb6d8 only dispatches kinds < 49 (`sltiu v0,v1,49` at
# 0x00bcb758), so the 53 ("new round") we sent never ran (static RE).
GS_NOTIFY_KIND_LIMIT = 49
GS_BATTLE_GO_DEFAULT = "5,28,29,3,30"


GS_DAMAGE_GATE_KINDS = (28, 29, 3, 30)
GS_BATTLE_OVER_SELECTOR = 39


def gs_battle_sequence(spec, spawn=None, seq_fn=None, ident=0, zone=0,
                       bmap=(0, 0)):
    """The pushes to send after answering 47 (leaveBriefingRoom) with 48.

    `spec` is a comma list of notify kinds, optionally KIND:HEXPAYLOAD; the
    kinds with a builder here (2, 4) get a sane default payload.  `zone` /
    `bmap` ride kind 2's record (+26 / +24..25, sec 4ft)."""
    if zone and spawn is None:
        spawn = (0.0, 0.0, 0.0)
    out = []
    for part in (spec or "").replace(" ", "").split(","):
        if not part:
            continue
        kind, _, hx = part.partition(":")
        kind = int(kind, 0)
        seq = seq_fn() if seq_fn else 0
        if hx:
            out.append((kind, gamemsg.build_gs_notify(kind, bytes.fromhex(hx), seq=seq,
                                              ident=ident)))
        elif kind == 4:
            out.append((kind, gamemsg.build_gs_notify(4, bytes(4) + bytes(gamemsg.GS_SETUP_LEN),
                                              seq=seq, ident=ident)))
        elif kind == 2 and spawn is not None:
            out.append((kind, gamemsg.build_gs_spawn(spawn[0], spawn[1], spawn[2],
                                             seq=seq, ident=ident, zone=zone,
                                             bmap=bmap)))
        else:
            out.append((kind, gamemsg.build_gs_notify(kind, seq=seq, ident=ident)))
    return out


def gs_ready_roster(pkt, ident, gs_id, members=(), kind=0, rec=None):
    """Fill selector 38's body.  sec 4eb: body[12..131] IS THE BATTLETABLE
    RECORD -- the arm hands body+12 to 0x00be0308, whose converter 0x0058b0b0
    is the browser record's twin (wire+24 key, +28 participants, +109 max,
    +113 map ...), so the "session id at body[36]" is rec+24 (the table key ->
    [chan+220], echoed at +22 of every game-server request) and the "roster
    count at body[40]" is rec+28.  28-byte roster entries from body[132] whose
    +0 is the character id (0x00bcb838).  The old all-zero 38 still enters
    br_main; this adds the table and the seat list."""
    b = bytearray(pkt)
    off = framing.BODY_OFF
    # KEY: 2026-09-13: the roster lists the OTHER members only. 0x00bcb838 zeroes
    # the 32 x 32-byte roster at [chan+1260] (== [chan+2144], what kind 0's
    # lookup 0x00bc5ee0 searches), copies COUNT-1 entries from body[132] and
    # then writes [kelsvc+272] -- the client itself -- into slot COUNT-1. Self
    # first made the joiner's roster [self, self] (the other player never in
    # it), and every kind-0 team change for them bailed: counts stuck at 0.
    ids = [m for m in members if m and m != ident][:31]
    count = len(ids) + 1
    need = off + gamemsg.GS_READY_ROSTER_OFF + gamemsg.GS_READY_ROSTER_STRIDE * len(ids)
    if len(b) < need:
        b += bytes(need - len(b))
        struct.pack_into("<H", b, 2, len(b))
    if rec is not None:
        b[off + tablerecords.BATTLETABLE_REC_OFF:off + tablerecords.BATTLETABLE_REC_OFF + tablerecords.BT_REC_LEN] = \
            bytes(rec[:tablerecords.BT_REC_LEN]).ljust(tablerecords.BT_REC_LEN, b"\x00")
        gs_id = struct.unpack_from("<H", rec, tablerecords.BT_OFF_ID)[0]
    struct.pack_into("<H", b, off + gamemsg.GS_READY_KIND_OFF, kind & 0xFFFF)
    struct.pack_into("<H", b, off + gamemsg.GS_READY_SESSION_OFF, gs_id & 0xFFFF)
    struct.pack_into("<H", b, off + gamemsg.GS_READY_COUNT_OFF, count)
    for i, cid in enumerate(ids):
        struct.pack_into("<I", b, off + gamemsg.GS_READY_ROSTER_OFF
                         + gamemsg.GS_READY_ROSTER_STRIDE * i, cid & 0xFFFFFFFF)
    b[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
    b[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(b))
    return bytes(b)


def quest_mission_record(rec, quest, flags=0x00010000, situation=0):
    """Selector 38's table record re-cut as a MISSION for Solo quest `quest`.

    2026-09-13 (static, sec 4gl follow-up): 38's record goes through converter
    0x0058b0b0 -> wire+0 flags -> obj+32, wire+26 mission -> obj+86 (the setup
    arm 0x00ada534 copies it to [mgr+12384]), wire+34 situation -> obj+100 (the
    arena resource set; 3000+ = the mission sets z201 ships). Without this the
    player's picked quest 17 played as a TEAM battle in the Jungle.
    INFERRED, not yet confirmed on a console: that flags 0x00010000 + mission id is what makes
    the client run the quest; the quest -> situation map is unknown (0 = keep
    the record's own)."""
    r = bytearray(rec)
    struct.pack_into("<I", r, tablerecords.BT_OFF_FLAGS,
                     (struct.unpack_from("<I", r, tablerecords.BT_OFF_FLAGS)[0] | flags)
                     & 0xFFFFFFFF)
    struct.pack_into("<H", r, tablerecords.BT_OFF_MISSION, quest & 0xFFFF)
    if situation:
        struct.pack_into("<H", r, tablerecords.BT_OFF_SITUATION, situation & 0xFFFF)
    return bytes(r)
