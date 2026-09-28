"""The Solo quest list (selector 160), the mission list (selector 148) and the quest detail's map field."""
import struct

QUEST_LIST_REQ = 159      # Solo Battle (story mode) quest-id list, answer 160


def parse_id_ranges(spec):
    """'1-8,16-36' -> [1..8, 16..36] (order kept, duplicates dropped)."""
    out = []
    for part in (spec or "").replace(" ", "").split(","):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        for n in range(int(lo, 0), int(hi or lo, 0) + 1):
            if n not in out:
                out.append(n)
    return out


def build_quest_list_body(ids, subchannel=7):
    """Selector 160 body: the Solo Battle (story mode) quest list.

    MEASURED 2026-09-13 by a marker body through the client's own demux, arm
    0x00bcd74c -> 0x00bcaba8 (state 51): body[12..13] u16 -> [kelsvc+1056]
    (unused by the row builder), body[14] -> [kelsvc+232] (unused), body[15]
    = COUNT (clamped to the capacity phase 123 set, 128), u16 quest ids from
    body[16]. The row builder 0x00aa42c0 names id N from KelStr 0xBBFF+N
    (group 47, index N-1) and describes it from 0xBFFF+N (group 48).
    WARNING: NOT body+28: a static read put the record at body+12; the marker run
    put it at body+0."""
    ids = [i & 0xFFFF for i in ids][:128]
    body = bytearray(16 + 2 * len(ids))
    body[0] = subchannel & 0xFF
    body[1] = (QUEST_LIST_REQ + 1) & 0xFF
    struct.pack_into("<H", body, 12, len(ids))
    body[15] = len(ids)
    for k, q in enumerate(ids):
        struct.pack_into("<H", body, 16 + 2 * k, q)
    return bytes(body)


# --- the SELECTOR 147 -> 148 LIST SERVICE (sec 4gt add.1 probe, 2026-09-22) ---------
# The Select Server list's own feed, gated on state 10 (RE'd 2026-09-21 on
# THIS build, so its addresses are live):
#
#   arm 96 sends selector 147 (44 B, body[16..19] = capacity 256) and parks
#   [svc+12] = 48; the reply that clears it is selector 148, demux 0x00bf0300 ->
#   arm 0x00bd4720 -> handler 0x00bd1fc8:
#       body[15]   = COUNT
#       body[16 + 4*i] = {u16 id, u8 record index, u8 flags}  -> copied to obj+44
#   populator 0x00aae2d0 then writes, per entry:
#       rec+0  = -1
#       rec+4  = (flags & 2) ? 0 : 2
#       rec+26 = (flags & 1) ? 229 : -1
#   list builder 0x00aae890: for i < [obj+0x150]: rec = 0x00B89548 + idx[i]*52
#
# WARNING: We have always answered 147 with the GENERIC build_world_answer, which is a
# well-formed list of ZERO entries (body[15] = 0). The static reading predicted the
# consequence -- "it would advance the state and draw an EMPTY list" --
# and that is what a player sees: rows that can be hovered but are blank and
# will not select, over an ALL-ZERO record table (measured 0x00B89548 in
# savestates 04/07/08/09).
#
# WARNING: THIS IS A PROBE, NOT A DECODE. What the ids and record indices MEAN is
# unknown, and it is NOT established that this list feeds the battletable
# config's Map / Entry Restrictions rows (opening those sent no traffic at all).
# It exists to answer ONE question: does a non-zero 148 put rows on that screen?
# If yes, we know what to build. If nothing changes, 147/148 is the Select
# Server list only and it is eliminated. Do not ship a non-empty default, and do
# not read meaning into the values until a screenshot earns it
# ([[a-probe-window-write-is-a-live-bug]]).
LIST148_REQ = 147
LIST148_ANS = 148
MISSION_ROW_OPEN = 0x02  # 148 entry flags bit1 -> mission row rec+4 = 0 (not greyed)


def build_list148_body(entries, subchannel=7):
    """Selector 148: COUNT at body[15], then 4 bytes per entry from body[16]."""
    entries = list(entries)[:256]
    body = bytearray(16 + 4 * len(entries))
    body[0] = subchannel & 0xFF
    body[1] = LIST148_ANS
    body[15] = len(entries) & 0xFF
    for k, (eid, rec, flags) in enumerate(entries):
        struct.pack_into("<H", body, 16 + 4 * k, eid & 0xFFFF)
        body[16 + 4 * k + 2] = rec & 0xFF
        body[16 + 4 * k + 3] = flags & 0xFF
    return bytes(body)


def parse_list148_spec(spec):
    """`--list-148` -> [(id, record_index, flags)].

    Either a bare COUNT ("8" -> ids 1..8, record index i, flags 0) or
    comma/semicolon-separated `id:rec:flags` triples, each field an int
    literal (0x.. accepted), e.g. `1:0:1,2:1:1,3:2:3`.
    """
    spec = (spec or "").strip()
    if not spec:
        return []
    if spec.isdigit():
        return [(i + 1, i, 0) for i in range(int(spec))]
    out = []
    for part in spec.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        bits = (part.split(":") + ["0", "0"])[:3]
        out.append(tuple(int(b, 0) for b in bits))
    return out
                           # TITLE + description come from mgr+1068, filled by
                           # command 29's 241 arm 0x00bc9710: answer body[16]
                           # u16 = quest id (title 0xBBFF+id, desc 0xBFFF+id),
                           # body[20] fee, body[24]/[28] item id/count, body[37]
                           # participant limit. Request 0x00bd7008 (state
                           # machine 0x00ad5024). NEVER seen live (09-13).
QUEST_DETAIL_MAP_OFF = 52  # 2026-09-13 (static): command 41's 241 answer
