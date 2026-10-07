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


P2P_SHOT_LEN = framing.BODY_OFF + 56
P2P_ENTITY, P2P_121 = 96, 121
P2P_ENTITY_LEN = framing.BODY_OFF + 44
P2P_121_LEN = framing.BODY_OFF + 24
P2P_121_MAGIC = b"\x64\x65\xfb\x01"


def shot_slots(body):
    """A shot's slot table: five {u8 part, '0'+i} pairs, an EMPTY slot being
    ff ff (2026-10-03, live: 377 of the evening's shots had one, e.g.
    `14 30 06 31 ff ff ff ff 17 34`, and were read as GS 12288/12299/12308
    and dropped -- the leader's shots never reached anyone). Slot 0 always
    holds a part."""
    if len(body) < 10 or body[1] != 0x30:
        return False
    return all(body[2 * i + 1] == 0x30 + i or body[2 * i:2 * i + 2] == b"\xff\xff"
               for i in range(5))


def p2p_battle_type_mode4(data, inner, sender, members):
    """2026-09-28 (Dirge report, table 6 TBT): a SHOT or DAMAGE whose mode-4
    header we cannot decrypt, named by its plaintext BODY, else None. One
    client's headers failed the checksum under every key all evening, so its
    41 shots were read as "GS request 12317/12318" and its 26 damage records
    as keepalives (the body opens with the entry count, 1): it hit and nobody
    was ever hurt. Shapes, from the same evening's readable 112/113:
      113 = {u32 n, n x {u32 target, s32 damage, u32 attacker, u32 shot id}}
            -- MEASURED 16-byte entries (a 44-byte datagram = one hit), not
            the 20 of P2P_DAMAGE_STRIDE; 20 is accepted too until a
            multi-hit record is seen. Every attacker is `sender`, every
            target another seated member, no shot id 0 (the receiver drops
            those).
      112 = 56 bytes, a slot table {u8, '0', u8, '1', .. u8, '4'} first, six
            finite floats (origin, direction) at body+24.
    `sender` is the session's own id and `members` its room's seated ids;
    no room, no naming."""
    if inner is not None or len(data) < framing.BODY_OFF + 4 or data[1] != 4:
        return None
    if not sender or sender not in members:
        return None
    body = data[framing.BODY_OFF:]
    n = struct.unpack_from("<I", body, 0)[0]
    if 1 <= n <= 8 and len(body) in (4 + 16 * n, 4 + 20 * n):
        stride = (len(body) - 4) // n
        ents = [struct.unpack_from("<IiII", body, 4 + stride * i)
                for i in range(n)]
        # 2026-10-05: a hit on a mission NPC (bit 30) is a 113 too -- its
        # victim is no seated member, so it was never named (and never landed)
        if all(atk == sender and t != sender and sid
               and (t in members or (t & 0xC0000000) == NPC_ID_BIT)
               for t, _d, atk, sid in ents):
            return P2P_DAMAGE
        return None
    if len(data) == P2P_SHOT_LEN and shot_slots(body):
        vs = struct.unpack_from("<6f", body, 24)
        if all(math.isfinite(v) and abs(v) < 100000.0 for v in vs):
            return P2P_SHOT
    # 2026-10-03 (live, the leader's): 96 = 44 bytes, a position (3 finite
    # floats) first and the shot's slot table at +28 -- 79 read as GS
    # 3405/44122/55478..; 121 = 24 bytes opening 64 65 fb 01 -- all 50 read
    # as "GS 25956". Neither a GS request (42 is 44 bytes with no slots).
    if len(data) == P2P_ENTITY_LEN and shot_slots(body[28:]):
        if all(math.isfinite(v) and abs(v) < 100000.0
               for v in struct.unpack_from("<3f", body, 0)):
            return P2P_ENTITY
    if len(data) == P2P_121_LEN and body[:4] == P2P_121_MAGIC:
        return P2P_121
    return None


def synth_p2p_inner(data, ptype, sender):
    """An `inner` for a p2p_battle_type_mode4() datagram: the header the
    readable ones decrypt to (type, flags 8, sender id at +16, target at +20
    = -1 for a shot, the first entry's victim for a damage record), body
    verbatim, checksum recomputed -- the synth_peer_inner() recipe, so
    relay_p2p_battle() can send it on as mode 0."""
    target = 0xFFFFFFFF
    if ptype == P2P_DAMAGE:
        target = struct.unpack_from("<I", data, framing.BODY_OFF + 4)[0]
    pkt = bytearray(data)
    pkt[8:24] = bytes(16)
    pkt[8] = ptype
    pkt[9] = worldpose.PEER_RELAY_FLAG
    struct.pack_into("<II", pkt, 16, sender, target)
    ck = framing.cksum(pkt)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", ck)
    return {"type": ptype, "flags": worldpose.PEER_RELAY_FLAG, "cksum": ck,
            "ack_seq": 0, "seq": 0, "u32_16": sender, "u32_20": target,
            "is_data": False, "is_ack": False, "plain": bytes(pkt),
            "synth": True}


# 2026-10-05: a mission NPC's POSE, sent by the console that CONTROLS it
# (subagent static RE, retail; scratchpad re-peers/). The generic per-unit
# pose builder 0x00bea05c emits it for every unit the console simulates:
# type byte unit+0x215 = 0x83 for its own avatar, 3 for every other unit;
# header +16 = the UNIT id (the NPC's 0x400001xx), +20 = the unit's +4 word
# (not a target), flags 8; the 40-byte body is the same pose record a 0x83
# carries (+0 id, +4 pos, +16 facing, +28 u16 2, +30 u16 ...). The receiver's
# router 0x0058c9c8 sends types 3 and 0x83 to one arm -> pose handler
# 0x00be33e8 (finds the unit by the header id) -> the shared pose store
# 0x00be9ea0. We read it as "GS request 256/257" (the id's low half).
NPC_POSE_TYPE = 3
NPC_ID_BIT = 0x40000000
NPC_POSE_LEN = framing.BODY_OFF + 40


def npc_pose(data, inner):
    """The NPC id of a controller's NPC pose datagram, else None. Readable:
    inner type 3, flags & 8, header +16 == body +0 with bit 30 set.
    Unreadable (mode 4, header under a cipher we do not hold): named by its
    BODY -- exactly 64 bytes, body +0 an NPC id (bit 30 set, bit 31 clear),
    a finite position. A player's pose body carries its own charid, which
    never has bit 30, so the two cannot be confused."""
    if len(data) != NPC_POSE_LEN:
        return None
    nid = struct.unpack_from("<I", data, framing.BODY_OFF)[0]
    if (nid & 0xC0000000) != NPC_ID_BIT:
        return None
    if inner is not None and inner.get("plain") is not None:
        if (inner.get("type") != NPC_POSE_TYPE
                or not (inner.get("flags", 0) & worldpose.PEER_RELAY_FLAG)
                or (inner.get("u32_16") or 0) != nid):
            return None
        return nid
    if data[1] != 4:
        return None
    pos = struct.unpack_from("<fff", data, framing.BODY_OFF + 4)
    if not all(math.isfinite(v) and abs(v) < 100000.0 for v in pos):
        return None
    return nid


def synth_npc_inner(data, nid):
    """An `inner` for an NPC pose whose header we cannot decrypt: type 3,
    flags 8, the NPC id at +16, +20 = 0 (the controller's unit +4 word is in
    the enciphered header; the pose handler finds the unit by +16), sender
    ms and body verbatim, checksum recomputed -- synth_peer_inner()'s recipe,
    so build_peer_relay() can send it on as mode 0."""
    pkt = bytearray(data)
    pkt[8:24] = bytes(16)
    pkt[8] = NPC_POSE_TYPE
    pkt[9] = worldpose.PEER_RELAY_FLAG
    struct.pack_into("<I", pkt, 16, nid)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
    ck = framing.cksum(pkt)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", ck)
    return {"type": NPC_POSE_TYPE, "flags": worldpose.PEER_RELAY_FLAG, "cksum": ck,
            "ack_seq": 0, "seq": 0, "u32_16": nid, "u32_20": 0, "is_data": False,
            "is_ack": False, "plain": bytes(pkt), "synth": True}


def p2p_record(plain):
    """(type, flags, sender, target, payload) of a decrypted P2P datagram."""
    b = plain[framing.BODY_OFF:]
    n = struct.unpack_from("<H", b, P2P_PAYLOAD_LEN_OFF)[0]
    return (b[0], b[1], struct.unpack_from("<I", b, P2P_SENDER_OFF)[0],
            struct.unpack_from("<i", b, P2P_TARGET_OFF)[0],
            bytes(b[P2P_PAYLOAD_OFF:P2P_PAYLOAD_OFF + n]))


P2P_DAMAGE_ENTRY = 16


def p2p_damage(plain):
    """(sender, target, [(victim, damage, attacker, shot id)]) of a decrypted
    113. 2026-10-05 (subagent static RE + offline run of retail serializer
    0x005961a8): the HEADER carries the sender at +16 and the record's target
    at +20 (the victim's id for a player; the NPC's CONTROLLER id for an NPC,
    0 on a console never told one); the body is {u32 count, count x 16-byte
    {u32 victim, s32 damage, u32 attacker, u32 shot id}} -- NOT the generic
    record p2p_record() reads (566 captured 113s parsed as "flags 0, empty
    payload", the victim as sender and the damage as target)."""
    sender, target = struct.unpack_from("<Ii", plain, 16)
    b = plain[framing.BODY_OFF:]
    if len(b) < 4:
        return sender, target, []
    n = struct.unpack_from("<I", b, 0)[0]
    out = []
    for i in range(min(n, (len(b) - 4) // P2P_DAMAGE_ENTRY)):
        out.append(struct.unpack_from("<IiII", b, 4 + P2P_DAMAGE_ENTRY * i))
    return sender, target, out


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
