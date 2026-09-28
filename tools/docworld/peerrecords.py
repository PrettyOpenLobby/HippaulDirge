"""Other players as the client caches them: the 56-byte user record (selectors 19 and 37) and the cache-miss request."""
import socket
import struct
from . import framing



PEER_REC_LEN = 56         # the selector-37 record, body[12..67]

PEER_SELECTOR_REQ = 36    # what the client asks with on a cache miss
PEER_SELECTOR_ANS = 37    # request + 1, the arm 0x00bccee8 -> 0x00bcaa70


def peer_miss_id(data, inner):
    """The entity id a selector-36 cache-miss request is asking about, or None.

    The client emits this ALL BY ITSELF whenever a type-125 world update names an
    entity it does not know: 0x00bd2788 misses in the table at [kelsvc+284],
    prints `Cache miss %d`, and -- iff [kelsvc+12] == 2, which is exactly what
    in-world means -- calls 0x00bd2dc8, which builds the request through
    0x00bcdc78 and sends it.  So the world is a PULL: we name an id, the client
    asks who it is, we answer.  Nothing has to push a peer list.

    Field map read off 0x00bcdc78 + the header builder 0x00bdb190 and confirmed
    by running the client's own builder in doc_eemu:

        body[0]      subchannel, = [kelsvc+16] = 7
        body[1]      SELECTOR 36
        body[4..5]   1
        body[12..15] the u16 argument, 0 on the cache-miss call
        body[16..19] u32 THE ENTITY ID            <- what we have to resolve

    Shape cross-checks against the live sec 4bt capture: phase 29's 40-byte
    request body was `07 0c 00 00 01 00 00 00`, and the built cache-miss body is
    `07 24 00 00 01 00 00 00` -- same fields, selector 12 vs 36.
    """
    plain = inner["plain"] if inner is not None else None
    buf = plain if plain is not None else (data if data[1] != 1 else None)
    if buf is None or len(buf) < framing.BODY_OFF + 20:
        return None
    if buf[framing.BODY_OFF + 1] != PEER_SELECTOR_REQ:
        return None
    return struct.unpack_from("<I", buf, framing.BODY_OFF + 16)[0]


PEER_NAME_OFF = 38        # wire +38..53, 16 bytes -> slot +16..31
PEER_NAME_LEN = 16


# sec 4ch: the 56-byte record, decoded by running the client's own converters
# (an offline run of the client's own code (doc_userrec)).  In world the user-list array [kelsvc+1052] is
# NULL, so selector 19 takes its OTHER branch and feeds the 80-byte PROFILE
# CACHE at [kelsvc+280] through 0x00bd8690; 0x00bda380 then builds the
# 112-byte record the UI reads.  Chain, per field:
#
#   wire  size  cache-80  profile-112  what it is
#   +0    u32   +24       +0     the KEY -- what 0x00bd82b8 searches on
#   +4    u32   +32       +80    unknown
#   +8    u32   +36       +96    unknown
#   +12   u32   +40       +48    unknown
#   +16   u32   +28       +56    IP ADDRESS, byte-swapped -> NETWORK ORDER
#   +20   8B    +16       +88    unknown 8-byte blob
#   +28   u16   +54       +60    PORT, byte-swapped -> NETWORK ORDER
#   +30   u16   +62       +62    FLAGS: bit1 -> the "$m03" marker on the label,
#                                bit4 -> "$m04"; 0x00bd36d0 sets bit3 itself
#   +32   u16   +56       +64    SERVER/ZONE id.  0xffff means "here": the label
#                                formatter 0x00ad7048 asks 0x00ad6f20, which is
#                                `return [rec+64] != 0xffff`, and indexes
#                                0x00afcfe8 -> msgid 0x7806 "LBY" / 0x7807 "RES"
#   +34   u16   -         -      read ONLY by 0x0058af08, which does not run
#   +36   u16   +52       +104   unknown
#   +38   16B   +0        +32    NAME
#   +54   u8    +61       +75    RANK, 1-BASED, via 0x00afd000[n] (n < 17):
#                                1 DGD-3  2 DGD-2  3 DGD-1  4 DGSC-3 ...
#                                14 DGG-2  15 DGG-1  16 TSV.  Entry 0 == entry
#                                1, and n >= 17 also falls back to entry 0, so
#                                0 and 99 both render "DGD-3" -- there is no
#                                value that means "no rank"
#   +55   u8    +64       +77    unknown
#
# WARNING: +31, +34 and +35 are read by NEITHER live path.
PEER_RANK_OFF = 54
PEER_FLAGS_OFF = 30
PEER_ZONE_OFF = 32
PEER_IP_OFF = 16
PEER_PORT_OFF = 28

# One boot's worth of differential.  Every still-unknown field gets a value that
# is unmistakable ON SCREEN if it is rendered, and the known ones get a value
# distinct from their default, so a single screenshot says which slot each field
# drives.  WARNING: This is a PROBE: it ships deliberately wrong data and must not be
# left on.
PEER_PROBE = dict(rank=16, flags=0x0012, zone=3,
                  f4=111111, f8=222222, f12=333333, f36=4444, f55=55)


def build_peer_record(ent_id, blob=None, name=None, rank=None, flags=None,
                      zone=None, ip=None, port=None, f4=None, f8=None,
                      f12=None, f36=None, f55=None, blob20=None):
    """One 56-byte user record -- the payload of a selector-19 or -37 answer.

    0x00bd9090 copies it into a 64-byte slot in the peer table [kelsvc+284] and
    bumps the count at [+8]; [+4] is the capacity, 1074 in the live savestates,
    and a full table returns -7, which 0x00bcaa70 forwards to 0x00bd7468.
    0x00bd8690 copies it into the 80-byte profile cache at [kelsvc+280], which
    is the one the Status/Profile UI reads.

    WARNING: Anything left None ships as ZERO.  A zero rank is a VALID rank (0 ->
    "DGD-3"), a zero zone is a valid zone, and only 0xffff means "none" -- so
    zeros here are not "unset", they are a claim.  See the table above for what
    each field actually drives.

    WARNING: `name` was an inference when it was written and is now measured: wire
    +38..53 lands at profile +32, which is what 0x00ad7048 prints.  The battle
    UI's name plate at 0x006b0ed4 reads a DIFFERENT object (the local avatar's
    [entity+480]) and only checks that byte 0 is alphanumeric, so its per-frame
    "Name plate error uid 0x%x" spam is not an oracle for this field.
    """
    rec = bytearray(PEER_REC_LEN)
    struct.pack_into("<I", rec, 0, ent_id & 0xFFFFFFFF)
    if blob:
        n = min(len(blob), PEER_REC_LEN - 4)
        rec[4:4 + n] = blob[:n]
    if blob20:
        rec[20:28] = blob20[:8].ljust(8, bytes(1))
    if name:
        nb = name.encode("ascii", "ignore")[:PEER_NAME_LEN - 1]
        rec[PEER_NAME_OFF:PEER_NAME_OFF + PEER_NAME_LEN] = (
            nb + bytes(PEER_NAME_LEN - len(nb)))
    if rank is not None:
        rec[PEER_RANK_OFF] = rank & 0xFF
    if flags is not None:
        struct.pack_into("<H", rec, PEER_FLAGS_OFF, flags & 0xFFFF)
    if zone is not None:
        struct.pack_into("<H", rec, PEER_ZONE_OFF, zone & 0xFFFF)
    if ip:
        # the client byte-swaps this into the profile record, so it wants
        # NETWORK order on the wire -- pack the dotted quad as-is.
        rec[PEER_IP_OFF:PEER_IP_OFF + 4] = socket.inet_aton(ip)
    if port is not None:
        struct.pack_into(">H", rec, PEER_PORT_OFF, port & 0xFFFF)
    for off, val, fmt in ((4, f4, "<I"), (8, f8, "<I"), (12, f12, "<I"),
                          (36, f36, "<H"), (55, f55, "B")):
        if val is None:
            continue
        if fmt == "B":
            rec[off] = val & 0xFF
        else:
            struct.pack_into(fmt, rec, off, val & (0xFFFF if fmt == "<H"
                                                   else 0xFFFFFFFF))
    return bytes(rec)


def _user_rec_fields(a):
    """The record fields the CLI sets, as kwargs for build_peer_record.

    WARNING: Only keys the user actually asked for are returned. An explicit 0 is a
    real value here (rank 0 is "DGD-3", zone 0 is a real zone) and is NOT the
    same as leaving the field alone, so None-vs-0 has to survive this hop.
    """
    if getattr(a, "user_rec_probe", False):
        return dict(PEER_PROBE)
    out = {}
    for arg, key in (("user_rank", "rank"), ("user_zone", "zone"),
                     ("user_flags", "flags"), ("user_ip", "ip"),
                     ("user_port", "port"), ("user_costume", "f36")):
        v = getattr(a, arg, None)
        if v is not None:
            out[key] = v & 0xFFFF if key == "f36" else v
    return out


def build_peer_answer(req, ent_id, seq=0, subchannel=7, ptype=127, mode_byte=0,
                      ident=None, blob=None, fail=False):
    """The selector-37 reply that PUTS AN ENTITY IN THE PEER TABLE.

    WARNING:WARNING: THIS CANNOT BE build_world_answer WITH selector=37.  That function writes
    its `result` word at body[12..15] (the field selector 13 reads), and body[12]
    is exactly where the peer RECORD starts on this rung -- so it would insert an
    entity whose id is the result code.  Different rung, different body.

    The arm, traced 2026-08-27:

        selector 37 -> jump table 0x00bf3230[33] = 0x00bccee8 -> 0x00bcaa70
        0x00bcaa70:  lhu v0, 24(a2) ; andi v0, 1   -- body[4] bit 0, the FAILURE
                     flag: set = do nothing at all, return 0
                     else 0x00bd9090(a0 = [kelsvc+284], a1 = record + 32)
                     and record+32 == body[12].

    Note the parity the jump table makes plain: every EVEN selector in 4..80 maps
    to the shared 0x00bcd788 and every ODD one has its own arm, which is the
    general form of sec 4bs's "answer = request + 1".
    """
    body = bytearray(12 + PEER_REC_LEN)
    body[0] = subchannel & 0xFF
    body[1] = PEER_SELECTOR_ANS
    # body[4] bit 0 is the FAILURE flag -- 0x00bcaa70 returns without inserting
    # when it is set.  Everything else in the first 12 bytes is left at zero.
    struct.pack_into("<H", body, 4, 1 if fail else 0)
    body[12:12 + PEER_REC_LEN] = build_peer_record(ent_id, blob)

    mid = bytearray(16)
    mid[0] = ptype & 0xFF
    struct.pack_into("<H", mid, 6, seq & 0xFFFF)
    # [record+4] -- every table arm drops the message silently unless this equals
    # [kelsvc+272] (0 in every in-world savestate), so echo the request's value.
    if ident is None and req is not None and len(req) >= 20:
        ident = struct.unpack_from("<I", req, 16)[0]
    struct.pack_into("<I", mid, 8, (ident or 0) & 0xFFFFFFFF)

    pkt = bytearray()
    pkt += bytes([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", framing.HDR_LEN + len(body))
    pkt += struct.pack("<I", framing.now_ms() & 0xFFFF)
    pkt += mid
    pkt += body
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(pkt))
    return bytes(pkt)
