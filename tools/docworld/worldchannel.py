"""The type-127 selector channel: selector names, request bodies, sealing an answer, the sender's ids."""
import struct
from . import framing

# sec 4ce: there are TWO user-list request paths. Selector 18 -> answer 19
# reaches the SAME handler 0x00bc9bf0 through arm 0x00bccb6c, with the same
# [kelsvc+12] == 7 gate. It first appeared on the wire once --gs-connect
# opened the game-server channel, and it was getting build_world_answer's
# EMPTY body -- exactly the bug sec 4bx fixed for 10/11.
# WARNING:KEY: sec 4dw: THE ANSWER RUNGS WHOSE ARM IS THE GAME-SERVER ENDPOINT WRITER.
# 0x00bca938 takes body[52..55] as the IP, body[56..57] as the port and
# body[58..59] as [kelsvc+268], and hands the first two to 0x0058a970, which
# fills the sockaddr at [0x009f2b40 + 184]. Three selectors reach it: 21 and 31
# (both gated on [kelsvc+12] == 8) and 104 (ungated), which is why --gs-connect
# can use 104 in world at all.
#
# Until 2026-09-06 selector 21 had NEVER been reached, so answering it with
# build_world_answer's zero body was harmless in the way an unexercised path is
# always harmless. The moment the sec 4dv fix let a reservation past phase 43,
# phase 44 asked for the endpoint on selector 20 -- and we told the client its
# game server is at 0.0.0.0:0, overwriting the good endpoint --gs-connect had
# written 25 seconds earlier. The avatar froze mid-lobby, still broadcasting.
# sec 4dx: the battle-READY flag. Arm 0x00bccf04 -> 0x00bcb838 -> 0x00bc0260 is
# the ONLY writer of [chan+2148] = 1 in the whole online module, and the client's
# game-server receive handler passes nothing but message 29 while that word is 0.
GS_READY_SELECTOR = 38

GS_ENDPOINT_SELECTORS = (21, 31)

# WARNING:KEY: sec 4gv (2026-09-23): 104 IS THE THIRD ENDPOINT RUNG, and the only one
# that can run in world -- it reaches the same writer 0x00bca938 as 21/31 with
# no [kelsvc+12] == 8 gate (sec 4cd). It is therefore the only thing that ever
# (re-)writes the game-server channel's peer sockaddr at [chan+184..191].
#
# WARNING: THAT SOCKADDR IS A SOURCE GATE. The client's game-server receive handler
# opens with (JP build 0x00bcca60)
#         lw   v1, 188(s1)      ; [chan+188] -- the port half of OUR endpoint
#         lw   v0, 4(s2)        ; the arriving datagram's source
#         bne  v1, v0, <exit>
# -- the datagram's source (IP, port) must EQUAL what selector 104 wrote, and
# that is tested BEFORE any dispatch and BEFORE the sequence window. A channel
# reset (0x00bc03b8, four callers -- sec 4cx) wipes it, and from then on every
# game-server datagram we send is dropped with nothing on the wire or in the
# emulog to say so: [chan+212] (the receive sequence, written on every datagram
# that passes the gate) simply stays at its uninitialised 65528, and [chan+224]
# is never refreshed -> CER-48101 forty seconds later.
# The US build relocates the handler; locate it structurally, never by VA.
GS_ENDPOINT_SELECTOR = 104
                               # The client ORs it in itself when a table is
                               # created from the Novice menu (lobby_rel
                               # 0x00aa1a84, category 3); isNoviceRoom() reads it.


SELECTOR_NAMES = {
    1: "world door", 2: "world door ok", 3: "nest close", 10: "user list",
    11: "user list", 12: "spawn", 13: "spawn", 16: "battletable list",
    17: "battletable list", 18: "user list (by id)", 19: "user list",
    20: "JOIN table", 21: "JOIN table (endpoint)", 22: "PRE-RESERVE",
    23: "PRE-RESERVE ok", 24: "CREATE table", 25: "CREATE table ok",
    26: "table CONFIG", 27: "table CONFIG", 28: "ADJUST rules",
    29: "ADJUST rules ok", 30: "JOIN table (password)",
    31: "JOIN table (endpoint)", 36: "peer pull", 37: "peer record",
    38: "BATTLE READY", 39: "battle over / reset", 64: "list kind 64",
    65: "list kind 64", 104: "game-server endpoint", 110: "RESERVATION CLEAR",
    125: "DISSOLVE table",
    126: "DISSOLVE ok", 127: "INVITE", 128: "INVITE ok / bare ack",
    137: "INDIVIDUAL RANKING", 138: "INDIVIDUAL RANKING",
    139: "CAREER RECORD", 149: "UNIT RANKING", 150: "UNIT RANKING",
    140: "CAREER RECORD", 141: "list kind 141", 142: "list kind 141",
    143: "list kind 143", 144: "list kind 143",
    147: "147 list service", 148: "147 list service",
    151: "RESERVE by id",
    152: "RESERVE ok", 153: "RESERVE by id (password)", 154: "RESERVE ok",
    155: "CANCEL reservation", 156: "CANCEL ok", 159: "list kind 159",
    160: "list kind 159", 240: "lobby command", 241: "command result",
    255: "chat / notification",
}


def seal_world_body(req, body, seq=0, ptype=127, ident=None, mode_byte=0):
    """Wrap a finished answer BODY in the plaintext type-127 header, exactly as
    build_battletable_list does (record+4 echoed from the request when no
    ident is given -- per-arm gates compare it with [kelsvc+272])."""
    mid = bytearray(16)
    mid[0] = ptype & 0xFF
    struct.pack_into("<H", mid, 6, seq & 0xFFFF)
    if ident is None and req is not None and len(req) >= 20:
        ident = struct.unpack_from("<I", req, 16)[0]
    struct.pack_into("<I", mid, 8, (ident or 0) & 0xFFFFFFFF)
    pkt = bytearray([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", framing.HDR_LEN + len(body))
    pkt += struct.pack("<I", framing.now_ms() & 0xFFFF)
    pkt += mid + bytes(body)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(pkt))
    return bytes(pkt)


def selector_name(sel):
    return SELECTOR_NAMES.get(sel, "?")


def request_body(data, inner):
    """The PLAINTEXT body of a type-127 request, or None when unreadable.

    In-world requests are mode 2: header enciphered, body plaintext (sec 4bs).
    Mode 1 (the 132-byte world door) is ciphertext from body[0..15] and only
    readable through doc_kelcrypt -- same rule lobby_cmd_id applies.
    """
    plain = inner["plain"] if inner is not None else None
    buf = plain if plain is not None else (data if data[1] != 1 else None)
    if buf is None or len(buf) < framing.BODY_OFF + 12:
        return None
    return bytes(buf[framing.BODY_OFF:])


def world_reply_fields(data, inner):
    """(request selector, record+4) for a type-127 request -- or (None, None).

    Split out of main() so it can be tested: this is the logic that decides
    which rung of the ladder we are answering, and both halves of it fail
    SILENTLY when they are wrong (a bad selector hits the jump table's default,
    a bad record+4 is dropped by the arm's own gate without a log line).

    The selector is body[1] and record+4 is packet[16..19]. Mode 1 enciphers 32
    bytes from offset 8, so on that mode both live in ciphertext and only the
    decrypt can read them; every other mode carries them in the clear.
    doc_kelcrypt.header() self-checks and returns None when the blob is missing
    or the mode is not one we can key, so the raw fallback has to stay -- phase
    29 is mode 2, and requiring the decrypt would drop it back to selector 2,
    which is precisely the bug sec 4bs fixes and would look like nothing at all.
    """
    plain = inner["plain"] if inner is not None else None
    if plain is not None and len(plain) > framing.BODY_OFF + 1:
        sel = plain[framing.BODY_OFF + 1]
    elif data[1] != 1 and len(data) > framing.BODY_OFF + 1:
        sel = data[framing.BODY_OFF + 1]
    else:
        sel = None
    if inner is not None:
        ident = inner["u32_16"]
    elif data[1] != 1 and len(data) >= 20:
        ident = struct.unpack_from("<I", data, 16)[0]
    else:
        ident = None
    return sel, ident


def packet_charid(data, inner, itype, world_type=127):
    """sec 4gz: the SENDER's own character id from a datagram, or 0.

    The identity a session is really about is [kelsvc+272], the selected
    character -- and the client stamps it into packet[16..19] of everything its
    own header builder 0x00bdb190 emits (sec 4dv), which is the inner header's
    `u32_16`. Only the two packet classes whose +16 is already proven to carry
    it are read here:

      * a type-127 WORLD request -- exactly the field world_reply_fields()
        echoes back as record+4, learned live on 09-11;
      * a type-0x83 POSITION report -- the id relay_peer_pose() keys the peer
        record and the remote spawn on (sec 4fu).

    Everything else answers 0: the game-server channel is mode 4 with a header
    we cannot decrypt, and reading a raw +16 out of a datagram whose type we
    could not establish would invent an identity. Bits 30/31 must be clear on a
    real charid (sec 4bw/4ch), so a value carrying them is refused too.
    """
    if itype == 0x83:
        cid = (inner.get("u32_16") or 0) if inner is not None else 0
    elif itype == world_type and len(data) > 1 and data[1] != 4:
        cid = world_reply_fields(data, inner)[1] or 0
    else:
        return 0
    return 0 if cid & 0xC0000000 else cid
