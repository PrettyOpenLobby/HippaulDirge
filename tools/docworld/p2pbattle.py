"""The battle layer between consoles (P2P types): decoding shots, damage and pick-ups the server has to see."""
import math
import struct
import doc_items
from . import fielditems, framing, worldpose



# ── The P2P BATTLE LAYER (2026-09-23, static; the protocol notes sec 4he) ──
# Shots and damage are NOT game-server requests. The battle object
# [0x00bf4c74] (0x009f2ac0 in doc_arena_slot03) sends 16-byte-header records
# whose INNER TYPE BYTE is the P2P type and whose inner flags carry bit 3, as
# mode 3 (shots, 150 ms) or mode 4 (damage, 500 ms) -- the same family as the
# 0x83 pose stream. Router 0x005812d0 hands inner types 96/97, 100..102,
# 112..114 and 121 with flags & 8 to the receiver 0x00be9860 ([0x00bf4c70]).
#
# KEY: They are all addressed to US. [obj+4] = 1 ("via server") is stored by the
# enter-battle routine 0x00bd28b8 unconditionally, the shot's endpoint is NULL
# and the transmitter 0x00580ed0 resolves NULL to avatar+280 = the game-server
# address selector 104 installed; the damage endpoint 0x00bddfc0 returns the
# same mirror for a relayed unit (unit+92 & 0x01000000) or a zero sockaddr for
# a fresh one, which resolves to us as well. Nothing ever crosses a NAT
# directly -- the server IS the relay, and before this it parsed every shot
# as "GS request 112" and dropped it on the floor.
#
# The record (body[0..] of the decrypted datagram):
#   +0 u8 P2P type, +1 u8 flags, +2 u8 weapon kind, +4 u32 sender id,
#   +8 s32 target (-1 = everyone), +18 u16 payload length, +20.. payload.
# Receiver 0x00be9860 drops a record whose target is neither -1 nor its own
# id ("Drop data to %x %d"), so relaying to every member is harmless.
#
# 113 = DAMAGE: +20 u32 count, then 20-byte entries {u32 target, s32 damage
# (negative = heal), u32 attacker, u32 shot id (0 is dropped as "Invalid
# shotid"), u32}. The VICTIM applies it (0x00be9778 -> 0x00be99d8, gated on
# facade & 0x20 -- see GS_BATTLE_GO_DEFAULT), and when its HP reaches 0 it
# sends game-server request 30 {killer, victim}: that is where the server's
# tally starts (BattleRoom.kill).
# 2026-09-24: 118 DROP / 119 PICK-UP (field items -- the Mako Capsules) are
# the SERVER's to arbitrate, never relayed (static RE, retail).
P2P_DROP, P2P_PICKUP = 118, 119
# 2026-09-26: 117 = an MP POINT touched (tools/doc_items.py): same reliable
# sender as 119, payload {u16 0, u16 point ordinal, u8 0, pad, u32 0, u32 n}.
# The SERVER's to credit (kind 44), never relayed.
P2P_MP_POINT = doc_items.P2P_MP_POINT
P2P_SERVER_TYPES = (P2P_MP_POINT, P2P_DROP, P2P_PICKUP)
P2P_BATTLE_TYPES = frozenset((96, 97, 100, 101, 102, 112, 113, 114, 121,
                              P2P_MP_POINT, P2P_DROP, P2P_PICKUP))
P2P_SHOT = 112
P2P_DAMAGE = 113
P2P_SENDER_OFF = 4
P2P_TARGET_OFF = 8
P2P_PAYLOAD_LEN_OFF = 18
P2P_PAYLOAD_OFF = 20
P2P_DAMAGE_STRIDE = 20
P2P_NAMES = {96: "entity msg", 97: "entity msg 2", 100: "misc",
             101: "rapid notify", 102: "object explosion", 112: "SHOT",
             113: "DAMAGE", 114: "p2p 114", 121: "p2p 121",
             P2P_DROP: "item DROP", P2P_PICKUP: "item PICK-UP",
             P2P_MP_POINT: "MP POINT"}


def p2p_battle_type(data, inner):
    """The P2P type of a battle-layer datagram, or None. Mode 3 or 4 on the
    wire, a decrypted inner header (mode 3 is the mode-2 cipher instance
    under another mode byte: dispatcher 0x00584230 maps both to 0x005842b8),
    inner flags bit 3, and a P2P type byte -- everything else on the channel
    is a game-server request or a pose report and stays on its own path."""
    if inner is None or len(data) < framing.BODY_OFF + P2P_PAYLOAD_OFF:
        return None
    if data[1] not in (3, 4) or not (inner.get("flags", 0) & worldpose.PEER_RELAY_FLAG):
        return None
    t = inner.get("type")
    if t not in P2P_BATTLE_TYPES or inner.get("plain") is None:
        return None
    return t


def p2p_server_type(data, inner):
    """Seen live, with static RE: a capsule PICK-UP / DROP sent to the
    SERVER, or None. Touching a kind-10 item goes 0x00683838 -> 0x004c9470 ->
    builder 0x00bee578 -> sender 0x00bee6d0; with netobj+4 bit 0 set it rides
    the RELIABLE sender 0x0058d288 to the game server (inner type 119, flags
    0x01, resent every 500 ms until ACKed), not the flags-0x08 P2P broadcast
    p2p_battle_type() reads. Body from wire+24 = the P2P payload: 119 {u32
    SLOT, u32 1, u32 n (a per-sender counter, never echoed), f32 x, y, z = the
    PICKER's position}. Live it was misread as "GS request 6" (slot 6).
    2026-09-26: 117 (an MP point, doc_items) rides the same sender."""
    if inner is None or not inner.get("is_data") or inner.get("plain") is None:
        return None
    if data[1] not in (0, 3, 4) or len(inner["plain"]) < framing.BODY_OFF + 4:
        return None
    t = inner.get("type")
    return t if t in P2P_SERVER_TYPES else None


def p2p_server_type_mode4(data, inner):
    """Seen in a live log: the same 119 / 118 from a PCSX2 client is
    MODE 4 -- header enciphered with the cipher we do not hold (REJECTED by
    its own checksum), body plaintext -- so p2p_server_type() never saw one,
    and every pick-up was read as "GS request <slot>" (slot 45 was answered
    with 46 = leave, slot 38 with 39). Named by its BODY instead: exactly 24
    bytes, {u32 a, u32 b, u32 n, f32 x, y, z = the sender's position}. 119 =
    a < FIELD_SLOTS and b == 1; 118 = a an item id (top byte set), b = count.
    Every 48-byte mode-4 datagram in the 09-26 log had the 119 shape; the
    118 arm is the documented layout, not yet seen in mode 4."""
    if len(data) != framing.BODY_OFF + 24 or data[1] != 4:
        return None
    if inner is not None and inner.get("plain") is not None:
        return None                 # readable: p2p_server_type()'s to name
    a_, b_, _n = struct.unpack_from("<III", data, framing.BODY_OFF)
    pos = struct.unpack_from("<fff", data, framing.BODY_OFF + 12)
    if not all(math.isfinite(v) and abs(v) < 100000.0 for v in pos):
        return None
    if a_ < fielditems.FIELD_SLOTS and b_ == 1:
        return P2P_PICKUP
    if a_ >> 24 and 1 <= b_ <= 0xFFFF:
        return P2P_DROP
    return None


def p2p_record(plain):
    """(type, flags, sender, target, payload) of a decrypted P2P datagram."""
    b = plain[framing.BODY_OFF:]
    n = struct.unpack_from("<H", b, P2P_PAYLOAD_LEN_OFF)[0]
    return (b[0], b[1], struct.unpack_from("<I", b, P2P_SENDER_OFF)[0],
            struct.unpack_from("<i", b, P2P_TARGET_OFF)[0],
            bytes(b[P2P_PAYLOAD_OFF:P2P_PAYLOAD_OFF + n]))


def p2p_damage_entries(payload):
    """The {target, damage, attacker, shot id} entries of a 113 payload."""
    if len(payload) < 4:
        return []
    n = struct.unpack_from("<I", payload, 0)[0]
    out = []
    for i in range(min(n, (len(payload) - 4) // P2P_DAMAGE_STRIDE)):
        t, d, atk, sid = struct.unpack_from("<IiII", payload,
                                            4 + P2P_DAMAGE_STRIDE * i)
        out.append((t, d, atk, sid))
    return out


def synth_peer_inner(data):
    """An `inner` for a position datagram whose header we cannot decrypt:
    the plaintext header the client's own peer 0x83 carries (type 0x83, flags
    8, the sender id at +8), the sender's ms and 40-byte body VERBATIM, and
    the checksum recomputed -- so build_peer_relay() can send it on as mode 0,
    which the lobby relay proved the receiver accepts (sec 4fu)."""
    rid = struct.unpack_from("<I", data, framing.BODY_OFF)[0]
    pkt = bytearray(data)
    pkt[8:24] = bytes(16)
    pkt[8] = 0x83
    pkt[9] = worldpose.PEER_RELAY_FLAG
    struct.pack_into("<I", pkt, 16, rid)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
    ck = framing.cksum(pkt)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", ck)
    return {"type": 0x83, "flags": worldpose.PEER_RELAY_FLAG, "cksum": ck, "ack_seq": 0,
            "seq": 0, "u32_16": rid, "u32_20": 0, "is_data": False,
            "is_ack": False, "plain": bytes(pkt), "synth": True}
