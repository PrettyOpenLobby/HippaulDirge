"""Positions in the lobby: the client's own uid and pose, the type-125 world update and the relayed position broadcast."""
import struct
from . import framing



ENTRANCE_UID_OFF = 16     # 80-byte entrance body[16..19], plaintext past the cipher
WORLD_DOOR_UID_OFF = 44   # 132-byte world-door body[44..47] = token[16..19]


def early_uid(data):
    """The client's own uid BEFORE it ever streams a position (the 2026-09-05 audit
    2026-09-05, defect A).

    Both the 80-byte entrance datagram and the 132-byte mode-1 world-door
    request carry the same 52-byte session token, and the uid the client later
    broadcasts on type-0x83 sits inside it: entrance `body[16..19]`, world door
    `body[44..47]` (the token starts at body[28] there).  Verified live
    captures 2026-09-05: every entrance/door packet of the 15:39 session reads
    0xa455a599, the uid its type-0x83 stream then carries.

    Why it matters: the first user-list requests of a session arrive ~1.4 s
    BEFORE the first position broadcast, so a responder that only learns the
    uid from type-0x83 answers them with either the empty body (fresh process)
    or the PREVIOUS session's uid -- both measured live.  Mode 1 enciphers
    only body[0..15], so both fields are plaintext on the wire.
    """
    if len(data) == 80 and data[1] == 1:
        return struct.unpack_from("<I", data, framing.BODY_OFF + ENTRANCE_UID_OFF)[0]
    if len(data) == 132 and data[1] == 1:
        return struct.unpack_from("<I", data, framing.BODY_OFF + WORLD_DOOR_UID_OFF)[0]
    return None


def ingame_uid(data, inner):
    """The client's OWN user id, learned off its in-game type-0x83 broadcast.

    The client streams position on inner type 0x83 at ~2 Hz and its own uid sits
    at body[0..3], plaintext (mode 2 enciphers only bytes 8..23, sec 4bj).  The
    emulog corroborates it twice over: `KelAppNetClient userid = -1487493478` is
    0xA756A69A, and the per-frame complaint is
    `[BT] Name plate error uid 0xa756a69a` -- the client is failing to find
    ITSELF in the user list, which is why echoing its own uid back is the
    conservative first record rather than an invented second player.
    """
    if inner is None or inner.get("type") != 0x83:
        return None
    if len(data) < framing.BODY_OFF + 4:
        return None
    return struct.unpack_from("<I", data, framing.BODY_OFF)[0]


WORLD_UPDATE_TYPE = 125        # inner type 0x7d -> router 0x00581384 -> 0x00bd2248
WORLD_REC_LEN = 24


def ingame_pose(data, inner):
    """(uid, x, y, z, dx, dy, dz) off the client's type-0x83 broadcast, or None.

    DECODED 2026-08-27 from `/logs/doc-rx`, by reading the body as floats instead
    of the s16 the type-125 RECORD uses -- they are different encodings and that
    is the whole trick:

        +00  u32  uid            9a a6 56 a7  = 0xa756a69a
        +04  f32  X              14 e6 f1 44  = 1935.19
        +08  f32  Y              08 00 80 bf  = -1.000
        +0c  f32  Z              17 d9 2a c2  = -42.712
        +10  f32  dir X / Y / Z  (-0.694, 0.0, 0.719)   -- normalised, |d| = 1.000

    Corroborated by the emulog: `copyMatrixFromActor() 0 p(1935.1,-0.0,-42.7)` is
    the same spot the same session, and a second capture reads (512.38, -0.50,
    -92.37) with direction (-0.99993, 0, -0.011), also unit length. Two samples,
    both unit-length directions, both matching a position the emulog printed.

    WARNING: The body is PLAINTEXT here (mode 2 enciphers only bytes 8..23, sec 4bj), so
    this needs no decrypt -- unlike the inner type, which is why the caller must
    use the decrypted `inner["type"]` rather than the raw byte.
    """
    if inner is None or inner.get("type") != 0x83:
        return None
    if len(data) < framing.BODY_OFF + 0x1C:
        return None
    uid = struct.unpack_from("<I", data, framing.BODY_OFF)[0]
    x, y, z = struct.unpack_from("<fff", data, framing.BODY_OFF + 4)
    dx, dy, dz = struct.unpack_from("<fff", data, framing.BODY_OFF + 0x10)
    return uid, x, y, z, dx, dy, dz


def build_world_update(records, seq=0, mode_byte=0, ms=None):
    """A type-125 world update -- the packet that puts entities in DoC's world.

    KEY: sec 4fu (2026-09-13): for an id whose top nibble is NOT 4 (a player's
    charid), the per-record consumer is 0x00bd2108: it resolves the id in the
    peer table [kelsvc+284], SPAWNS a remote unit (0x00bdce20 -> 0x00bdcc58,
    which needs only [0x009f3b80+3632] bit 0 -- set in the lobby, 0x207) and
    positions it (0x00bde7a0 -> the unit's vt+28 update). On that arm +4/+5
    are bytes and +6/+20 u16s copied into the unit's pose record (the nibble-4
    arm hard-codes 2 and 128 there), and +22 is ORed into `packet+4 &
    0xfff00000` to make the TIME word the unit update takes -- the same slot
    a relayed 0x83 fills with its sender's ms. `ms` stamps packet+4 (default:
    our own clock, low 16 bits, as before); optional record keys b4/b5/h6/
    h20/h22 fill those fields and stay zero when absent.

    NOTHING HAS EVER SENT ONE. The format is `doc_world_update_proof.py`'s, which
    proved the routing and the framing BY EXECUTION and read the per-field offsets
    statically:

        body[2]   u8   record count          (0x00bd231c `lbu v0, 2(s6)`)
        body[3]   u8   must be < 2           (0x00bd22f4 `sltiu v0, v0, 2`)
        body[4..]      count x 24-byte records, stride 24 (0x00bd256c)

        record +0   u32  entity id -- bit 30 picks the table, and the arm at
                         0x00bd2358 additionally wants the TOP NIBBLE == 4
               +8   s16  X    x 0.1
               +10  s16  Y    x 0.1
               +12  s16  Z    x 0.1
               +14  s16  orientation x 0.001
               +16  s16  orientation x 0.001
               +18  s16  orientation x 0.001

    WARNING:WARNING: **THE TWO SCALES ARE READ, NOT MEASURED.** `doc_eemu` has no FPU, so the
    harness NOPs every float op and its decoded coordinates are meaningless. The
    x0.1 and x0.001 come from the disassembly alone. The live check the proof
    itself names is the one to run first: echo the client's OWN broadcast position
    back at it and see whether the avatar lands where it already is.

    WARNING: `record+4` is NOT compared with `[kelsvc+272]` on this path, unlike every
    type-127 table arm -- so the usual echo-the-ident rule does not apply here.

    WARNING: Sending an id the client does not know makes it print `Cache miss %d` and
    ask selector 36 (sec 4bw). That is the DESIGNED behaviour, not a fault --
    answer it with --peer-answer.
    """
    body = bytearray(4 + WORLD_REC_LEN * len(records))
    body[2] = len(records) & 0xFF
    body[3] = 0
    for i, r in enumerate(records):
        o = 4 + i * WORLD_REC_LEN
        struct.pack_into("<I", body, o, r["id"] & 0xFFFFFFFF)
        for j, k in enumerate(("x", "y", "z")):
            struct.pack_into("<h", body, o + 8 + j * 2,
                             max(-32768, min(32767, int(round(r[k] * 10.0)))))
        for j, k in enumerate(("dx", "dy", "dz")):
            struct.pack_into("<h", body, o + 14 + j * 2,
                             max(-32768, min(32767, int(round(r.get(k, 0.0) * 1000.0)))))
        for k, off, fmt, mask in (("b4", 4, "B", 0xFF), ("b5", 5, "B", 0xFF),
                                  ("h6", 6, "<H", 0xFFFF), ("h20", 20, "<H", 0xFFFF),
                                  ("h22", 22, "<H", 0xFFFF)):
            if r.get(k) is not None:
                struct.pack_into(fmt, body, o + off, r[k] & mask)
    mid = bytearray(16)
    mid[0] = WORLD_UPDATE_TYPE
    struct.pack_into("<H", mid, 6, seq & 0xFFFF)
    pkt = bytearray()
    pkt += bytes([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", framing.HDR_LEN + len(body))
    pkt += struct.pack("<I", (framing.now_ms() & 0xFFFF) if ms is None else (ms & 0xFFFFFFFF))
    pkt += mid
    pkt += body
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(pkt))
    return bytes(pkt)


PEER_RELAY_FLAG = 0x08     # inner flags bit 3: a PEER datagram (sec 4fu)


def build_peer_relay(plain):
    """A client's type-0x83 position broadcast, re-sent to ANOTHER client (sec 4fu).

    `plain` is the DECRYPTED datagram (doc_kelcrypt.header()["plain"]). The
    0x83 a client sends US carries inner flags 0x00; a copy meant for a peer
    must carry bit 3, or the receiver drops it at one of two gates:

        parser 0x0058a0b0  flags & 8 -> 0x00be20b0(avatar, id = packet[16..19],
                           source ip/port) must return >= 0. It returns -1 unless
                           the id is a unit that ALREADY EXISTS (so the type-125
                           spawn has to come first), and it accepts the source
                           when it equals the game server mirrored at
                           [0x009f3b80+12..19] -- our own address, written by
                           selector 104 -- or the unit's own sockaddr.
        router arm 131     0x00581530 `lbu v0, 1(record); andi 8` -> 0x00bdd5c8,
                           which finds the unit by id and calls its vt+28 update
                           with (body, packet+4 = the sender's ms, 0).

    Everything else is VERBATIM -- the sender's ms, its id, the body -- and it
    goes out as MODE 0 (plaintext) with the checksum recomputed the way the
    client checks it, so nothing has to be re-enciphered.
    """
    pkt = bytearray(plain)
    pkt[1] = 0
    pkt[9] |= PEER_RELAY_FLAG
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(pkt))
    return bytes(pkt)


PEER_POS_LEN = framing.BODY_OFF + 40   # a position datagram: header + the 40-byte pose


def peer_pos_id(data):
    """body[0..3] of a datagram SHAPED like a position report, else None.

    sec 4fu (briefing, live 09-13): in the briefing room both clients stop the
    lobby 0x83 report and send their position as PEER datagrams to us instead
    -- 64 bytes, mode 4, inner flags 8, body[0..3] = their own charid. The
    Deck's mode-4 header is REJECTED by its own checksum under every key we
    hold (the PC's decrypts), so the header cannot identify it; the body can.
    The caller decides whether the id is the SENDER's own (a game-server
    request's body starts with a small message type, never a charid)."""
    if len(data) != PEER_POS_LEN or data[1] not in (2, 4):
        return None
    return struct.unpack_from("<I", data, framing.BODY_OFF)[0]
