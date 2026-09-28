"""The 120-byte battletable record: its offsets and flag bits, the browser list and the --battletable-list spec."""
import struct
from . import framing



# --- the BATTLETABLE record (selector 26 -> 27), sec 4dn/4do -----------------
# The battletable config screen (KelStr group 26: Map / Max Players / Time Limit
# / Point Initiative / Comment / Restrictions / NPC) renders `!!na!!` in every
# field because we answer selector 26 with build_world_answer's ZERO body.
#
# Selector 27's inbound arm 0x00bcb740 (gate [kelsvc+12] == 11) runs the record
# converter 0x0058af88 over OUR answer at record+36 == body[16], scattering a
# ~117-byte wire record into the sink at [kelsvc+1052] that the lobby.pex UI
# reads.  The converter's source offsets, as body[] (record+K == body[16+K]):
#
#   body[16..19]  rec+0   lw  -> sink+8      body[76..79]  rec+60  lw  -> sink+36
#   body[24..27]  rec+8   lw  -> sink+68     body[80..83]  rec+64  lw  -> sink+40
#   body[32..35]  rec+16  lw  -> sink+80     body[84..91]  rec+68  8B  -> sink+44
#   body[38..39]  rec+22  lhu -> sink+54     body[52..75]  rec+36  24B -> sink+12
#   body[40..41]  rec+24  lhu -> sink+0      body[124]     rec+108 b   -> sink+52
#   body[42..43]  rec+26  lhu -> sink+62     body[125]     rec+109 b   -> sink+53
#   body[44..45]  rec+28  lhu -> sink+2  AND the LIST COUNT (loop copies COUNT
#                 u32s from body[136] into sink+92; keep it 0 or a real count)
#   body[46]      rec+30  b   -> sink+6      body[126]     rec+110 b   -> sink+84
#   body[128]     rec+112 low nibble -> sink+88, high nibble -> sink+89
#   body[127/129/130/131/132] rec+111/113/114/115/116 -> sink+57/59/60/61/64
#
# WARNING: We do NOT yet know which sink offset drives which screen row -- the UI is in
# the lobby.pex overlay.  build_battletable_probe fills every field with a
# distinct value so ONE screenshot names each row (the sec 4cq sentinel method);
# after that, replace the probe with the real values.
BATTLETABLE_ANSWER_SEL = 27       # request 26 + 1
# sec 4dz: the arm's a3 is the RAW DATAGRAM (the demux passes the packet),
# so a3+36 == body[12], not body[16]. Measured by running 0x00bcb558 over our
# own answer in an offline run of the client's own code (doc_bt_verbs_proof): with the record at body[16]
# the client read our port bytes as the table id (215 = 0x00d7). The probe
# shipped with 16 for four days and was never validated on screen.
BATTLETABLE_REC_OFF = 12          # record base within body (== a3+36)


def build_battletable_probe(req, seq=0, subchannel=7, ptype=127, mode_byte=0,
                            ident=None):
    """A selector-27 answer carrying ONE battletable whose every field holds a
    distinct sentinel, so the config screen names each row in one look.

    WARNING: The list COUNT at body[44..45] is kept 0: the arm copies that many u32s
    out of body[136] into sink+92, and a nonzero count over unwritten body is
    the sec 4bo wild-write class.  This is a PROBE -- it ships made-up values.
    """
    body = bytearray(176)
    body[0] = subchannel & 0xFF
    body[1] = BATTLETABLE_ANSWER_SEL
    struct.pack_into("<H", body, 4, 0)               # failure flag clear
    R = BATTLETABLE_REC_OFF
    # distinct numerics -- read which screen row shows which
    struct.pack_into("<I", body, R + 0,  1111)       # rec+0  -> sink+8
    struct.pack_into("<I", body, R + 8,  2222)       # rec+8  -> sink+68
    struct.pack_into("<I", body, R + 16, 3333)       # rec+16 -> sink+80
    struct.pack_into("<H", body, R + 22, 444)        # rec+22 -> sink+54
    struct.pack_into("<H", body, R + 24, 555)        # rec+24 -> sink+0
    struct.pack_into("<H", body, R + 26, 666)        # rec+26 -> sink+62
    struct.pack_into("<H", body, R + 28, 0)          # rec+28 -> sink+2 AND COUNT
    body[R + 30] = 30                                 # rec+30 -> sink+6
    struct.pack_into("<I", body, R + 60, 777)        # rec+60 -> sink+36
    struct.pack_into("<I", body, R + 64, 888)        # rec+64 -> sink+40
    # 24-byte string region rec+36..59 -> sink+12 (comment or table name)
    body[R + 36:R + 60] = b"PROBE_COMMENT_STRING_24_"[:24]
    # 8-byte region rec+68..75 -> sink+44 (second string / map?)
    body[R + 68:R + 76] = b"MAPFIELD"
    # byte fields: distinct small values, one per candidate index/flag
    body[R + 108] = 1        # -> sink+52
    body[R + 109] = 2        # -> sink+53
    body[R + 110] = 3        # -> sink+84
    body[R + 111] = 4        # -> sink+57
    body[R + 112] = 0x65     # low nibble 5 -> sink+88, high nibble 6 -> sink+89
    body[R + 113] = 7        # -> sink+59
    body[R + 114] = 8        # -> sink+60
    body[R + 115] = 9        # -> sink+61
    body[R + 116] = 10       # -> sink+64

    mid = bytearray(16)
    mid[0] = ptype & 0xFF
    struct.pack_into("<H", mid, 6, seq & 0xFFFF)
    if ident is None and req is not None and len(req) >= 20:
        ident = struct.unpack_from("<I", req, 16)[0]
    struct.pack_into("<I", mid, 8, (ident or 0) & 0xFFFFFFFF)

    pkt = bytearray([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", framing.HDR_LEN + len(body))
    pkt += struct.pack("<I", framing.now_ms() & 0xFFFF)
    pkt += mid + body
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(pkt))
    return bytes(pkt)


BATTLETABLE_LIST_REQ = 16          # the browser's list request (phase 34)
BATTLETABLE_LIST_ANS = 17          # ...and the answer, arm 0x00bccb30
BT_REC_LEN = 120                   # one wire record; 0x0058af88 blows it up to 220

# The 120-byte wire record, decoded by RUNNING the client's own converter
# 0x0058af88 on a marked record (an offline run of the client's own code (doc_btrec)) and then reading the
# ROW RENDERER 0x00aa2900, which is the only consumer that names the fields.
# Offsets below are into the WIRE record; the "-> +N" is where the converter
# puts it in the 220-byte browser slot at [manager+36 + row*220].
BT_OFF_FLAGS   = 0     # u32 -> +8   mode bitfield; 0x00010000 = Mission mode
BT_OFF_LEADER  = 8     # u32 -> +68  the LEADER's uid; the row resolves a name
                       #             for it through 0x00ad6ee8, i.e. the profile
                       #             cache the user list fills
# sec 4he (a current retail build, savestates 04/08/09 with the
# config screen open): every config row -> its wire byte, read off the picker
# commit 0x00aabfd0 and the CREATE packer 0x00bd83a8, converter 0x00596da0
# PROVEN by execution. Wire+4 u32 = TIME LIMIT IN SECONDS (600 = "10
# minute(s)"; 0 = None). The earlier "+116 = time limit" was a config-layout
# offset (+64) misread as a wire offset: wire+116 is the RESTRICTIONS mask.
BT_OFF_TIME    = 4     # u32 -> +72  time limit, SECONDS (0 = none)
BT_OFF_UNK16   = 16    # u32 -> +80
BT_OFF_UNK22   = 22    # u16 -> +54
# sec 4he (static 2026-09-23, converter 0x0058b0b0 obj+0x2e and the create
# initialiser's per-mode defaults): wire+22 is the TARGET SCORE the config
# screen's "Conditions for Victory: Kill Count: N" row writes -- 20 for a
# team kill table, 15 for individual. The room ends the battle on it.
BT_OFF_TARGET  = BT_OFF_UNK22   # "Kill Count: N" (0..999)
BT_OFF_BASE_HP = BT_OFF_UNK16   # u32 "Base Durability" (8000 for Team Base)
BT_OFF_MAX_RP  = 60    # u32 -> +36  "Maximum RP" (with flags 0x00080000)
BT_OFF_MIN_RP  = 64    # u32 -> +40  "Minimum RP" (with flags 0x00100000)
BT_OFF_PW_REC  = 68    # 8 B -> +44  the table PASSWORD (4 chars used; flags bit 0)
BT_OFF_BRIEFING = 111  # u8  -> +57  "Briefing Time" MINUTES, 0 = unlimited
BT_OFF_CAPSULES = 115  # u8  -> +61  "Mako Capsules" 0..7 (TCP)
BT_OFF_RESTRICT = 116  # u8  -> +64  battle restrictions: 0x01 Melee 0x02 Magic
                       #             0x04 Limit Break 0x08 Shooting 0x10 Bomb
                       #             0x20 S-Mines (flags 0x00020000 = any set)
BT_OFF_PENALTY = 117   # u8  -> +65  "Penalty Time" SECONDS = the respawn delay
                       #             (HUD: config[+57]*1000 + 4000 ms)
BT_OFF_KO_LIMIT = 118  # u8  -> +66  "KO Limit" 0..99 (with flags 0x00800000)
# flag bits the config rows set (wire+0)
BT_FLAG_PASSWORD = 0x00000001
BT_FLAG_FRIENDLY_FIRE = 0x00000004
BT_FLAG_CUSTOM_RESTRICT = 0x00000020
BT_FLAG_NPC = 0x00000040
BT_FLAG_HAS_RESTRICT = 0x00020000
BT_FLAG_MAX_RP = 0x00080000
BT_FLAG_MIN_RP = 0x00100000
BT_FLAG_ITEM_RESTRICT = 0x00200000
BT_FLAG_RANDOM_TEAMS = 0x00400000
BT_FLAG_KO_LIMIT = 0x00800000
BT_OFF_ID      = 24    # u16 -> +0    THE KEY the browser lists on
BT_OFF_MISSION = 26    # u16 -> +62   mission id, used when flags & 0x00010008
BT_OFF_CUR     = 28    # u16 -> +2    CURRENT participants ("%d/%d", first arg)
BT_OFF_STATE   = 30    # u8  -> +6    bit 0 -> the row prints "In Progress"
                       #              (group 28 [80]) instead of the count
BT_OFF_UNK31   = 31    # u8  -> +56
BT_OFF_UNK32   = 32    # u16 -> +86
BT_OFF_UNK34   = 34    # u16 -> +76
# sec 4gc (static 2026-09-13): wire +34 is the BATTLE SITUATION ID. The
# active-table converter 0x0058b0b0 puts it at [0x00bf4530]+100, which
# getBattleSituationId (vt+684 -> 0x00be2bf8) returns, and ev2045 feeds it to
# mdlResLoad: 1000..1098 -> "Res_bt1", 1100..1998 -> "Res_tbt1", 2000..2098 ->
# "Res_fa1", 2100..2998 -> "Res_tfa1", 3000.. -> "Res_3000".. (missions). We
# served 0 = no battle resource set (lead for the arena's blue boxes).
BT_OFF_SITUATION = BT_OFF_UNK34
BT_OFF_COMMENT = 36    # 40 bytes -> +12  the comment / table-name string block
BT_OFF_UNK108  = 108   # u8  -> +52
BT_OFF_MAX     = 109   # u8  -> +53   MAXIMUM participants ("%d/%d", second arg)
BT_OFF_MODE    = 110   # u8  -> +84   game mode; 0x00af2b38[v] is the mode index
                       #              the label tables 0x00af2b50 / 0x00af2b88
                       #              are read with
BT_OFF_UNK111  = 111   # u8  -> +57
BT_OFF_NIBBLES = 112   # u8  -> +88 (low nibble) and +89 (high nibble)
BT_OFF_MAP     = 113   # u8  -> +59   THE ARENA MAP: an index into the 12-byte
                       #              table 0x00afc68c whose +0 is the KelStr id
                       #              0=Jungle 1=Deepground 2=Kalm 3=Wastelands
                       #              4=Sewers 5=Laboratory 6=Training Grounds
                       #              7=Church 8=Train Graveyard 9=Shinra Building
                       #              10=Deepground 1 11=Mako Reactor
                       #              12=Deepground 2 13=Test Area 14=Edge
                       #              15=Mountain Pass 16=Shinra Manor
BT_OFF_UNK114  = 114   # u8  -> +60
BT_OFF_UNK116  = 116   # u8  -> +64

# The arena maps, by the index the record carries.  Names are the client's own
# (KelStr group 28); this table exists so --battletable-list can take a name.
BT_MAPS = ["jungle", "deepground", "kalm", "wastelands", "sewers", "laboratory",
           "training", "church", "traingraveyard", "shinrabuilding",
           "deepground1", "makoreactor", "deepground2", "testarea", "edge",
           "mountainpass", "shinramanor"]


def build_battletable_record(table_id=1, leader=0, cur=1, maximum=8, map_idx=0,
                             mode=1, comment=b"", flags=0, in_progress=False,
                             mission=0):
    """ONE 120-byte battletable, in the layout the browser's converter reads."""
    r = bytearray(BT_REC_LEN)
    struct.pack_into("<I", r, BT_OFF_FLAGS, flags & 0xFFFFFFFF)
    struct.pack_into("<I", r, BT_OFF_LEADER, leader & 0xFFFFFFFF)
    struct.pack_into("<H", r, BT_OFF_ID, table_id & 0xFFFF)
    struct.pack_into("<H", r, BT_OFF_MISSION, mission & 0xFFFF)
    struct.pack_into("<H", r, BT_OFF_CUR, cur & 0xFFFF)
    r[BT_OFF_STATE] = 1 if in_progress else 0
    if comment:
        c = comment if isinstance(comment, bytes) else \
            comment.encode("cp932", "replace")
        c = c[:39]
        r[BT_OFF_COMMENT:BT_OFF_COMMENT + len(c)] = c
    r[BT_OFF_MAX] = maximum & 0xFF
    r[BT_OFF_MODE] = mode & 0xFF
    r[BT_OFF_MAP] = map_idx & 0xFF
    return bytes(r)


def build_battletable_list(req, records, seq=0, subchannel=7, ptype=127,
                           mode_byte=0, ident=None, total=1, index=0):
    """The selector-17 answer that PUTS TABLES IN THE BROWSER (sec 4dv).

    The accumulator is 0x00bc9a70, arm 0x00bccb30, gate [kelsvc+12] == 15 --
    the state phase 34's own request (kelsvc vt+108 -> 0x00bd0558, which sends
    SELECTOR 16 with the destination array = manager+36 and capacity 50) parks
    the channel in.  It is the twin of the user list's 0x00bc9bf0 and reads,
    with a3 = the RAW DATAGRAM so a3+24 == body:

        body[12..13]  u16  records in THIS message
        body[16..17]  u16  total messages          -> [kelsvc+228]
        body[18..19]  u16  this message index      -> bit at [kelsvc+1068+..]
        body[20..]         records, stride 120, converted 120 -> 220 by
                           0x0058af88 into [kelsvc+1052] + [kelsvc+1060]*220,
                           capacity [kelsvc+1056]
        completion:   [kelsvc+228] == [kelsvc+232]

    Rejections, all silent: index > total, and a duplicate message index.

    KEY: `mult a3, a1, v0` at 0x00bc9b50 is the R5900 THREE-OPERAND mult (rd is
    a3) -- the destination stride.  Read as the 2-operand form the stride
    vanishes and the copy looks like it always writes slot 0.  Same class as
    an emulator trap (a mult read and a duplicate copy).
    """
    body = bytearray(20 + BT_REC_LEN * len(records))
    body[0] = subchannel & 0xFF
    body[1] = BATTLETABLE_LIST_ANS
    struct.pack_into("<H", body, 4, 0)                 # failure flag clear
    struct.pack_into("<H", body, 12, len(records))
    struct.pack_into("<H", body, 16, total)
    struct.pack_into("<H", body, 18, index)
    for i, rec in enumerate(records):
        off = 20 + i * BT_REC_LEN
        body[off:off + BT_REC_LEN] = bytes(rec[:BT_REC_LEN]).ljust(BT_REC_LEN,
                                                                   b"\x00")

    mid = bytearray(16)
    mid[0] = ptype & 0xFF
    struct.pack_into("<H", mid, 6, seq & 0xFFFF)
    if ident is None and req is not None and len(req) >= 20:
        ident = struct.unpack_from("<I", req, 16)[0]
    struct.pack_into("<I", mid, 8, (ident or 0) & 0xFFFFFFFF)

    pkt = bytearray([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", framing.HDR_LEN + len(body))
    pkt += struct.pack("<I", framing.now_ms() & 0xFFFF)
    pkt += mid + body
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(pkt))
    return bytes(pkt)


def parse_battletable_spec(spec, leader=0, name=None):
    """`--battletable-list` -> a list of 120-byte records.

    Either a bare COUNT ("3" -> three default tables, one per map) or
    semicolon-separated `map:cur/max:comment` entries, e.g.

        jungle:1/8:Come on in;church:0/16:Large-Scale

    `map` is a name out of BT_MAPS or a raw index.
    """
    out = []
    spec = (spec or "").strip()
    if not spec:
        return out
    if spec.isdigit():
        n = int(spec)
        for i in range(n):
            out.append(build_battletable_record(
                table_id=i + 1, leader=leader, cur=0, maximum=8,
                map_idx=i % len(BT_MAPS), mode=1,
                comment=(name or "Battletable %d" % (i + 1))))
        return out
    for i, part in enumerate(spec.split(";")):
        part = part.strip()
        if not part:
            continue
        bits = part.split(":")
        mp = bits[0].strip().lower()
        if mp in BT_MAPS:
            map_idx = BT_MAPS.index(mp)
        elif mp.isdigit():
            map_idx = int(mp)
        else:
            map_idx = 0
        cur, mx = 0, 8
        if len(bits) > 1 and "/" in bits[1]:
            cur, mx = (int(x) for x in bits[1].split("/", 1))
        comment = bits[2] if len(bits) > 2 else ""
        out.append(build_battletable_record(
            table_id=i + 1, leader=leader, cur=cur, maximum=mx,
            map_idx=map_idx, mode=1, comment=comment))
    return out
                           # body[52] -> quest struct Q+42 -> synthetic record
                           # +51 (0x00aa1568) = index into the MISSION map-name
                           # list 0x00afc878 (28:217 Jungle .. 28:224 Church):
                           # the Solo screen's map label. 0 = "Jungle" for all.
# sec 4he (retail 0x00aa1608 + proto 0x00aa0fd8): the FLAG bits.
BT_FLAG_INDIVIDUAL = 0x00000200  # BT "Individual Kill": everyone vs everyone
BT_FLAG_UNIT = 0x01000000        # window kind 1: a UNIT (guild) table, G labels
BT_FLAG_BEGINNER = 0x04000000    # window kind 3: Beginner (NOT "BT" -- that was
                                 # a misread; maps limited to index 3 / 7)
BT_FLAG_SOLO = 0x00000008        # proto window kind 4: a Solo quest table
# The MODE BYTE (wire+110) when neither 0x200 nor 0x04000000 is set -- retail
# index table 0x00b121a0: 0/1 = Team Kill, 2 = Team Survival (no respawns),
# 3 = Team Base, 4 = Team Capsule, 5 = Team Leader, 6 = Team Flag.
BT_MODE_NAMES = {0: "TBT", 1: "TBT", 2: "TDM", 3: "TBS", 4: "TCP", 5: "TLD",
                 6: "TFL"}
BT_FLAG_MISSION = 0x00010000   # battletable flags: Mission mode (0x00ada360 ->
                               # battle kind [mgr+12370] = 1; start gate passes)
BT_FLAG_NOVICE = 0x04000000    # 2026-09-23 (sec 4hc): a Novice battletable.
