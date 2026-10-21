"""DoC chat: world selector 255 (subchannel 7), relayed to the players in scope.

MEASURED live: every chat line a player
typed arrived as a mode-2 type-127 request with selector 255, and the byte
stream at body[12] is

    +0  u8   kind       see THE KINDS below
    +1  u8   0
    +2  u8   LENGTH     text bytes INCLUDING the NUL ("yo" -> 3)
    +3  u8   0
    +4  u32  target     0xffffffff for SAY, the member's character id for TELL
    +8  text[LENGTH]

The receive side is the same selector (arm 0x00bcccdc, no state gate), and it
hands body[12..] to 0x00bcb450 (09-13 module layout): kinds 0..9 and 13..254
go to the chat ring 0x00bcb238 ([kelsvc+300] = 0x00b07e00, non-zero in both
09-13 states) as (kind, SENDER = record+4, text = stream+8, len = stream[2]).
Kinds 10..12 and 255 go to 0x00bcadf0 instead (avatar 0x009f3b80 + game-server
channel), which is not chat and is not relayed here.

So a relay is the sender's body VERBATIM, re-sealed with ident = the sender's
character id (record+4 is what the ring files as the speaker).

THE KINDS (2026-09-26, static, retail lobby doc_retail_lobby_20260923.p2s)
--------------------------------------------------------------------------
The chat UI keeps its channel as a MODE byte ([ui+108]); the send routine
0x00aefeb8(ui, mode, text, &target) turns it into the wire kind through the
u16 table at 0x00b1b1e8, indexed by mode:

    mode  label 0x00b1a758 / slash word 0x00b1a780    wire kind
     1    say   0x9001  "say"   "s"                     5   (live: MEASURED)
     2    shout 0x9016  "shout" "sh"                    6
     3    tell  0x9002  "tell"  "t"                     3   (live: MEASURED)
     4    group 0x9003  "group" "g"                   (254, never sent here)
     5    entry 0x9004  "entry" "e"                     2
     6    team  0x9005  "team"  "m"                     7
     7    tell  0x9002                                  3
     8    tell  0x9002                                  0   (unidentified)
     9    (GM desk, label -1)                         (253, its own path)

The mode indexes the label table 0x00b1a758 (read at 0x00ae0868) and, less
one, the slash-word table 0x00b1a780 (0x00ae01b0); a parsed command 3..8
becomes mode 1..6 at 0x00adfb08. The menu table at 0x00b1a7b0 pairs each
label with its help line: say "all PCs within a small radius",
shout "within a large radius", tell "a specific PC on this server", group
"all members on your grouplist regardless of their location", entry "all PCs
who have reservations at the same battletable as you", team "all members on
your team regardless of their location" (KelStr 36:9..23).

The comparisons that read each kind inside 0x00aefeb8:
  * mode 4 (group) branches at 0x00af0178 BEFORE the channel send and goes to
    0x00af6e50 -> a POL-library stub (0x005bbc0c, import 0x16c0) over the
    friend-list GROUP object 0x00ab3478 ("Chat group setting invalid" 0x9c4b).
    GROUP CHAT NEVER RIDES SELECTOR 255: it is the PlayOnline friend/group
    service, not this server.
  * mode 9 (GM) branches at 0x00af02a8 to 0x00b0de10 (the GM call task).
  * kind 3 with target 0xffffffff -> "Could not locate second party" 0x9c0e.
  * kind 2 when 0x00aed9a8() == 0xffff (the own user record's u16 at +64, the
    battletable reservation) -> "no battletable reservations" 0x9c10.
  * kind 7 when 0x00aeda40() == 255 (own record +72, read only in lobby
    phases 20/30/40 and not when [ui+11782] == 1) -> "not a member of any
    team" 0x9c0f.
  Everything else leaves through the channel object's vt+544 with the record
  {+0 own id, +4 target, +8 u16 kind, +12 len, +16 text}. It is the only chat
  send, so /team in battle is this selector too (static; no live capture of a
  kind 2/6/7 yet).

THE SCOPES (source: 2006 player guide and player wiki, chat tips)
    say   = your own lobby AREA          shout = your area + adjacent areas
    entry = your battletable             team  = your team in that battle
    tell  = one player                   group = your unit (not this channel)

AREAS: the Visual Lobby's own classifier (vl_main, see the SPAWN_PRESETS
comment in docudp) splits z217 into region 0 EAST, 1 SOUTH, 2 WEST and 3 =
anywhere else (the north wing, the briefing room). The player guide says the
opening event puts you in Area 1 (quest.ev stands the player in the EAST
wing) and that walking on goes Area 1, 2, 3, 4 and back to 1 around a ring. The map anchors ID_PLACE_0..3 sit east,
south, west, north, consecutive around the centre, so ADJACENT = the ring
neighbours (r +- 1) % 4, and east/west, south/north are the non-adjacent
pairs. INFERRED (ring order from the anchors + the guide), not a client
table. A player inside a battle room is in that BATTLE's area: say and shout
reach the room's members only.
"""
import collections
import struct

SEL_CHAT = 255
STREAM_OFF = 12
BROADCAST = 0xFFFFFFFF

KIND_ENTRY = 2
KIND_TELL = 3
KIND_SAY = 5
KIND_SHOUT = 6
KIND_TEAM = 7
KIND_GM = 253       # mode 9: its own path; parse() drops >= 10 anyway
KIND_GROUP = 254    # mode 4: never on this selector (POL group service)

KIND_NAMES = {KIND_ENTRY: "ENTRY", KIND_TELL: "TELL", KIND_SAY: "SAY",
              KIND_SHOUT: "SHOUT", KIND_TEAM: "TEAM"}

# the Visual Lobby's regions (vl_main bytecode 150..302): x/z rectangles
LOBBY_REGIONS = (
    (0, 430.0, 1530.0, -600.0, 560.0),       # EAST  = Area 1
    (1, -550.0, 550.0, -1560.0, -430.0),     # SOUTH = Area 2
    (2, -1550.0, -400.0, -600.0, 560.0),     # WEST  = Area 3
)
REGION_ELSE = 3                              # anywhere else = Area 4
N_AREAS = 4

# Where a player is, for scoping. area: ("lobby", 0..3), ("battle", key) or
# None (no position heard yet); table: battletable key or None; battle: room
# key or None; team: team number or None.
Where = collections.namedtuple("Where", "area table battle team pos",
                               defaults=(None,))
NOWHERE = Where(None, None, None, None)

# 2026-10-01: the help text's "small radius" (36:9) as a distance in world
# units (x/z), for two players in the lobby whose positions are known. OURS --
# SE's number is not in the client: about half a lobby wing (a wing is ~1100
# units across). A shout keeps "its wing and the neighbouring ones" (the
# "large radius"), and battle chat stays in the room: an arena position is
# not reliably fresh on the server.
SAY_RADIUS = 600.0


def lobby_region(x, z):
    """The vl_main region (0..3) of a lobby position."""
    for r, x0, x1, z0, z1 in LOBBY_REGIONS:
        if x0 < x < x1 and z0 < z < z1:
            return r
    return REGION_ELSE


def lobby_area(pose):
    """("lobby", region) for an (x, y, z, ...) pose, None without one."""
    if not pose:
        return None
    return ("lobby", lobby_region(pose[0], pose[2]))


def adjacent(area):
    """The areas a SHOUT from `area` reaches: itself and its ring neighbours
    in the lobby; a battle's shout stays in the battle."""
    if area is None:
        return set()
    if area[0] != "lobby":
        return {area}
    r = area[1]
    return {area, ("lobby", (r + 1) % N_AREAS), ("lobby", (r - 1) % N_AREAS)}


def parse(body):
    """(kind, target, text) of a selector-255 body, or None if it is not chat."""
    if body is None or len(body) < STREAM_OFF + 8 or body[1] != SEL_CHAT:
        return None
    kind, n = body[STREAM_OFF], body[STREAM_OFF + 2]
    if kind >= 10:                 # 10..12 / 255 are the avatar notifications
        return None
    target = struct.unpack_from("<I", body, STREAM_OFF + 4)[0]
    raw = bytes(body[STREAM_OFF + 8:STREAM_OFF + 8 + n])
    return kind, target, raw.split(b"\0", 1)[0]


def kind_name(kind):
    return KIND_NAMES.get(kind, "kind %d" % kind)


def recipients(body, sender, live, where=None):
    """Character ids that must receive this chat line. `live` = every live
    world session's character id; `where(cid)` -> Where. Without `where`
    (--chat=all) every non-TELL kind goes to everyone, the 09-26 behaviour.
    The sender never gets its own line back: 0x00aefeb8 prints it locally."""
    p = parse(body)
    if p is None or not sender:
        return []
    kind, target, _ = p
    others = [c for c in live if c and c != sender]
    if kind == KIND_TELL:
        return [target] if target in live and target != sender else []
    if where is None:
        return others
    me = where(sender) or NOWHERE
    at = {c: (where(c) or NOWHERE) for c in others}
    if kind in (KIND_SAY, KIND_SHOUT):
        # 2026-10-01: no position heard yet = nobody in range (the old
        # broadcast sent a "nearby" line to the whole server)
        if me.area is None:
            return []
        reach = {me.area} if kind == KIND_SAY else adjacent(me.area)
        if kind == KIND_SHOUT or me.area[0] != "lobby" or me.pos is None:
            return [c for c in others if at[c].area in reach]
        out = []
        for c in others:
            w = at[c]
            if w.pos is not None and w.area is not None and w.area[0] == "lobby":
                d = ((w.pos[0] - me.pos[0]) ** 2
                     + (w.pos[1] - me.pos[1]) ** 2) ** 0.5
                if d <= SAY_RADIUS:
                    out.append(c)
            elif w.area in reach:
                out.append(c)
        return out
    if kind == KIND_ENTRY:
        if me.table is None:       # the client refuses this itself (0x9c10)
            return []
        return [c for c in others if at[c].table == me.table]
    if kind == KIND_TEAM:
        if me.team is None:        # the client refuses this itself (0x9c0f)
            return []
        if me.battle is not None:
            return [c for c in others if at[c].battle == me.battle
                    and at[c].team == me.team]
        if me.table is not None:   # seated, team picked, room not open yet
            return [c for c in others if at[c].table == me.table
                    and at[c].team == me.team]
        return []
    return others                  # kinds 0 / 1 / 4 / 8 / 9: not pinned


def relay_body(body):
    """The body forwarded to a recipient: exactly what the sender sent."""
    return bytes(body)


# ---------------------------------------------------------------------------
# 2026-10-08: THE GAME-SERVER COPY OF THE SAME STREAM (request 42 -> message 42)
#
# Once a client is in a battle ([kelsvc+28] bit 0x20), the one chat send
# routine (kelsvc vt+760/764 on retail 0x00bd7da0, proto 0x00bd1070) stops
# using selector 255 and hands the record to the game-server channel's
# sender (retail 0x00bcdf30, proto 0x00bc6488), whose builder (retail
# 0x00bc8408, proto 0x00bc0448) lays the request out as
#
#     body+0   u16 42           body+2  u16 session (the table key)
#     body+12  u8  kind         body+13 0
#     body+14  u16 LENGTH       (retail: lhu rec+12; proto: the u8 at rec+10)
#     body+16  u32 0            ALWAYS ZERO: `sw zero, 4(a2)` -- the record's
#                               target (rec+4) is NOT copied, so a battle TELL
#                               carries no addressee on the wire
#     body+20  text[LENGTH]     (<= 200), only when kind < 10 or 13..254;
#                               kinds 10..12 and 255 send no text (length 8)
#
# captured from a live battle on our own server: kind 5 SAY
#   2a00 0300 00000000 00000000 05 00 0800 00000000 "sssssss\0"
# and 417 payload-free kind 255 lines 2a00 1000 .. ff 00 8000 00000000 (the
# bytes at +14/+15 are 0x80 or 0x84 there, see AVATAR_KINDS).
#
# The receive side is message 42 (table 0x00bf2dc0 entry 41 -> arm proto
# 0x00bc51bc): it calls the kelsvc wrapper 0x00bd52d8 with the stream at
# body+12 and the length [record+18]-12, which runs 0x00bcb450 -- the SAME
# dispatcher selector 255 uses -- with the SENDER = record+4 (the datagram's
# ident). Kinds < 10 and 13..254 file (kind, sender, text) into the chat
# ring (0x00bcb238); the sender's own line is printed locally by the send
# routine, so the speaker must not get a copy back.
#
# A relay is therefore: build_gs_message(42, body_extra = the sender's body
# from +4, ident = sender), to every room member the kind reaches.
GS_CHAT_REQ = 42
GS_STREAM_OFF = STREAM_OFF            # the stream sits at body+12 on both channels
GS_TEXT_OFF = 20
GS_TEXT_MAX = 200

#: kinds 10, 11, 12 and 255 are not chat: 0x00bcb450 routes them to
#: 0x00bcadf0, which (a) finds the SENDER's unit on the avatar (0x00bdf010,
#: 32 units of 700 bytes at [avatar+3488]) and stores stream[2] (the byte at
#: body+14) into unit+535 with flag 0x8000 (an engine callback reads it back
#: through the unit's vt+120), and (b) raises HUD event 10 (kinds 10 / 255),
#: 21 (11) or 22 (12) through 0x00bc6ed0 -> 0x00bc31b0 with the sender id and
#: the byte at body+15. The client sends kind 255 from kelsvc vt+72 (retail
#: 0x00bda710: rec+8 = 255, rec+12 = the u16 the engine passes in; live
#: values 0x0080 / 0x0084). WHAT the byte means is not identified (the
#: engine-side callback was not opened); it is a per-player signal every
#: other member's client expects, so it is relayed verbatim like a SAY.
AVATAR_KINDS = (10, 11, 12, 255)


def parse_gs(body):
    """(kind, length, text) of a game-server request-42 body, or None."""
    if body is None or len(body) < GS_STREAM_OFF + 8:
        return None
    if struct.unpack_from("<H", body, 0)[0] != GS_CHAT_REQ:
        return None
    kind = body[GS_STREAM_OFF]
    n = struct.unpack_from("<H", body, GS_STREAM_OFF + 2)[0]
    if kind in AVATAR_KINDS:
        return kind, n, b""
    raw = bytes(body[GS_TEXT_OFF:GS_TEXT_OFF + min(n, GS_TEXT_MAX)])
    return kind, n, raw.split(b"\0", 1)[0]


def is_avatar_signal(body):
    """A selector-255 body carrying one of AVATAR_KINDS (the lobby copy of
    the same signal, which parse() does not treat as chat)."""
    return (body is not None and len(body) >= STREAM_OFF + 8
            and body[1] == SEL_CHAT and body[STREAM_OFF] in AVATAR_KINDS)


def gs_recipients(kind, sender, members, team_of):
    """The room members a battle chat line of `kind` from `sender` reaches.
    `members` = the room's present members, `team_of(cid)` -> the team or
    None (individual play).
      SAY / SHOUT / ENTRY -> the whole room (a battle is one area and one
                             table; the lobby help's radius does not apply)
      TEAM                -> the sender's team (the client itself refuses
                             /team with no team, 0x9c0f)
      TELL                -> nobody: the builder drops the target (OURS: a
                             line nobody can route is dropped, not broadcast)
      10 / 11 / 12 / 255  -> everyone else (the avatar signal)
      anything else       -> everyone else (unpinned, as the lobby)"""
    others = [m for m in members if m and m != sender]
    if kind == KIND_TELL:
        return []
    if kind == KIND_TEAM:
        t = team_of(sender)
        if t is None:
            return []
        return [m for m in others if team_of(m) == t]
    return others


def gs_chat_body(kind, text=b"", session=0, value=0):
    """A request-42 body the way the client's builder lays it out (tests and
    proofs): `value` = the u16 at +14 of a kind-255 signal."""
    b = bytearray(GS_TEXT_OFF)
    struct.pack_into("<HH", b, 0, GS_CHAT_REQ, session & 0xFFFF)
    b[GS_STREAM_OFF] = kind & 0xFF
    if kind in AVATAR_KINDS:
        struct.pack_into("<H", b, GS_STREAM_OFF + 2, value & 0xFFFF)
        return bytes(b)
    t = bytes(text)[:GS_TEXT_MAX - 1] + b"\0"
    struct.pack_into("<H", b, GS_STREAM_OFF + 2, len(t))
    return bytes(b) + t


def chat_body(kind, text, target=BROADCAST):
    """A selector-255 body the way the client lays it out (tests)."""
    t = text + b"\0"
    b = bytearray(STREAM_OFF) + struct.pack("<BBBBI", kind, 0, len(t), 0,
                                            target) + t
    b[0], b[1] = 7, SEL_CHAT
    return bytes(b)


def _selftest():
    ok = [True]

    def chk(name, cond):
        if not cond:
            print("  doc_chat FAIL", name)
            ok[0] = False

    E, S, W, N = (("lobby", r) for r in range(4))
    B = ("battle", 9)
    world = {
        1: Where(E, 5, None, None), 2: Where(E, None, None, None),
        3: Where(S, 5, None, None), 4: Where(W, None, None, None),
        5: Where(N, None, None, None), 6: Where(None, None, None, None),
        10: Where(B, 9, 9, 0), 11: Where(B, 9, 9, 1), 12: Where(B, 9, 9, 0),
        13: Where(E, 9, None, 0),
    }
    live = set(world)

    def to(kind, frm, target=BROADCAST, where=world.get):
        return sorted(recipients(chat_body(kind, b"x", target), frm, live,
                                 where))

    chk("region east/south/west/else",
        [lobby_region(900, 145), lobby_region(1.7, -632.2),
         lobby_region(-679.8, -6.1), lobby_region(-0.9, 632.2),
         lobby_region(1935.19, -42.7)] == [0, 1, 2, 3, 3])
    chk("say: same area only", to(KIND_SAY, 1) == [2, 13])
    chk("shout: east reaches south + north, not west",
        to(KIND_SHOUT, 1) == [2, 3, 5, 13])
    chk("shout from south reaches east + west, not north",
        to(KIND_SHOUT, 3) == [1, 2, 4, 13])
    chk("say with no position: nobody (no longer the whole server)",
        to(KIND_SAY, 6) == [])
    near = {20: Where(E, None, None, None, (900.0, 100.0)),
            21: Where(E, None, None, None, (1300.0, 100.0)),
            22: Where(E, None, None, None, (1600.0, 900.0)),
            23: Where(S, None, None, None, (900.0, -1000.0))}
    live.update(near)
    wn = lambda c: near.get(c) or world.get(c)
    chk("say by distance: 400 units away hears, 1000 away does not",
        21 in to(KIND_SAY, 20, where=wn) and 22 not in to(KIND_SAY, 20, where=wn))
    chk("shout: the next wing, whatever the distance", 23 in to(KIND_SHOUT, 20, where=wn))
    chk("say by distance still crosses no battle", 10 not in to(KIND_SAY, 20, where=wn))
    for c in near:
        live.discard(c)
    chk("battle say stays in the room", to(KIND_SAY, 10) == [11, 12])
    chk("entry: same table (lobby)", to(KIND_ENTRY, 1) == [3])
    chk("entry: table 9 includes the seated lobby member",
        to(KIND_ENTRY, 10) == [11, 12, 13])
    chk("entry with no table: nobody", to(KIND_ENTRY, 2) == [])
    chk("team: same battle, same team", to(KIND_TEAM, 10) == [12])
    chk("team: never the enemy", 11 not in to(KIND_TEAM, 12))
    chk("team with no team: nobody", to(KIND_TEAM, 1) == [])
    chk("team before the room opens: table + team", to(KIND_TEAM, 13) == [10, 12])
    chk("tell: the target only", to(KIND_TELL, 1, target=4) == [4])
    chk("unpinned kind 0: everyone", len(to(0, 1)) == 9)
    chk("twin (--chat=all): say reaches the opposite wing",
        4 in to(KIND_SAY, 1, where=None))
    chk("twin: the scoped say does NOT", 4 not in to(KIND_SAY, 1))
    chk("avatar kinds are not chat", parse(chat_body(12, b"x")) is None)
    chk("...but they are the avatar signal", is_avatar_signal(chat_body(12, b"x"))
        and is_avatar_signal(chat_body(255, b"")) and not is_avatar_signal(chat_body(5, b"x")))
    # 2026-10-08: the game-server copy (request 42). The SAY line captured
    # live, verbatim, and the kind-255 signal captured live, verbatim.
    live_say = bytes.fromhex("2a000300000000000000000005000800000000007373737373737300")
    live_255 = bytes.fromhex("2a0010000000000000000000ff00800000000000")
    chk("GS: the live SAY parses (kind 5, length 8, text)",
        parse_gs(live_say) == (5, 8, b"sssssss"))
    chk("GS: the live kind-255 signal parses with its u16 value and no text",
        parse_gs(live_255) == (255, 0x80, b""))
    chk("GS: a selector-255 body is not a request 42", parse_gs(chat_body(5, b"x")) is None)
    chk("GS: gs_chat_body rebuilds the live SAY byte for byte",
        gs_chat_body(5, b"sssssss", session=3) == live_say)
    chk("GS: gs_chat_body rebuilds the live signal byte for byte",
        gs_chat_body(255, session=16, value=0x80) == live_255)
    room = [10, 11, 12, 13]
    teams = {10: 0, 11: 1, 12: 0, 13: 1}
    chk("GS: SAY reaches the whole room but the speaker",
        gs_recipients(KIND_SAY, 10, room, teams.get) == [11, 12, 13])
    chk("GS: SHOUT and ENTRY are the room too",
        gs_recipients(KIND_SHOUT, 11, room, teams.get) == [10, 12, 13]
        and gs_recipients(KIND_ENTRY, 11, room, teams.get) == [10, 12, 13])
    chk("GS: TEAM reaches the sender's team only",
        gs_recipients(KIND_TEAM, 10, room, teams.get) == [12])
    chk("GS: TEAM in individual play (no team) reaches nobody",
        gs_recipients(KIND_TEAM, 10, room, lambda c: None) == [])
    chk("GS: TELL carries no target on this channel -> nobody",
        gs_recipients(KIND_TELL, 10, room, teams.get) == [])
    chk("GS: the kind-255 signal reaches everyone else",
        gs_recipients(255, 13, room, teams.get) == [10, 11, 12])
    chk("GS: a member who left is not a member", gs_recipients(KIND_SAY, 10, [10, 11], teams.get) == [11])
    return ok[0]


if __name__ == "__main__":
    import sys
    r = _selftest()
    print("doc_chat selftest", "ok" if r else "FAILED")
    sys.exit(0 if r else 1)
