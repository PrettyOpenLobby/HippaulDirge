#!/usr/bin/env python3
"""Talk back to Dirge of Cerberus on its world channel (UDP 55040).

DoC dials `kel-1001.pol.com:55040` and re-sends an 80-byte datagram until it
gives up.  Nothing has ever answered it, so the server->client direction is
entirely unknown.  This is the instrument for changing that: it binds the port,
logs every datagram, and sends back a candidate reply that you choose on the
command line -- so a hypothesis costs one restart, not a code change.

    python3 docudp.py                          # log only, send nothing
    python3 docudp.py --mode subtype --subtype 4 --lobby-probe advance   # THE FIX
    python3 docudp.py --mode echo              # bounce the packet straight back
    python3 docudp.py --once                   # answer one datagram, then idle

## Current state (2026-08-24): the lobby handshake is SOLVED

`--mode subtype --subtype 4 --lobby-probe advance` answers the entrance with the
subtype-4 redirect (drives the main connection to state 7) AND answers the
96-byte type-129 lobby packets with a mode-0 selector-2 reply that advances the
UDATA nest 1->2 (and the main connection 7->8).  Proven offline end-to-end
against kel's real parser + driver (measured offline against the client's own
parser); expect DoC to
leave CER-48103 and enter the Kerberos event stage (the next wall: `can't find
event data` -> CER-40000, real game/user-data).  See `build_lobby_advance`.

## Why the client's own logging is the oracle

The preview build narrates its own rejections.  `[KEL NET ENT]Drop packet bad
packet` means the datagram reached the packet handler and failed validation;
silence means it never got that far.  So the emulog, not this script, tells you
whether a candidate was any good.  Run PCSX2 with its console visible and watch
it while this runs.

## What is known about the wire format (client->server), all measured

    +0   u8    0x04
    +1   u8    0x01
    +2   u16LE total length (80 on every packet seen)
    +4   u32LE millisecond timestamp
    +8   16B   varies every packet; PROVENANCE UNKNOWN -- see below
    +24  52B   body; mostly identical across sessions, lightly transformed
    +76  u16   0x0200
    +78  2B    flag, only 0000 or 8080 observed

## What the client checks on receive (static RE of kel.pex, base 0x00280000)

1. `0x00585b28` -- the datagram must come from the peer it dialled.  Replying
   from this socket satisfies that for free; there is no token to forge.
2. `0x00585f50` -- reads a SUBTYPE byte at **packet+25** (i.e. body[1]) and
   accepts subtype 3 only in connection state 3, subtype 4 only in state 5.
3. Live savestates show the connection parks in **state 5** and stays there for
   the whole ~40 s window, so **subtype 4 is the one to aim at**.

## The honest unknown

The 16 bytes at +8 are not understood.  An earlier reading concluded they were
ciphertext from the codec at `0x00584888`; that was RETRACTED when live states
showed the key pointer `[0x005ee4a0]` null on a working connection.  They may be
a nonce, a digest, or something the receive path ignores entirely.  `--crypto`
exists precisely because we do not know: try each option and let the client say.

The per-selector details are in the docstrings of the build_* functions below.
"""
import argparse
import datetime
import math
import os
import select
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ipaddress as _ipaddress

import doc_charastore
import doc_playtime
import doc_npc
import doc_novice
import doc_missions
import doc_field
import doc_npc_spawn
import doc_npcquests
import doc_rank
import doc_stats
import doc_shop
import doc_trade
import doc_chat
import doc_unit
import doc_gear
import doc_magic
import doc_items
try:
    import doc_kelcrypt                      # the client's own cipher, carved out
    _KELCRYPT = doc_kelcrypt.available()
except Exception:                            # blob or interpreter missing -> log-only
    doc_kelcrypt = None
    _KELCRYPT = False

PORT = 55040
HDR_LEN = 24          # 8-byte outer header + the 16-byte INNER header
BODY_OFF = 24         # confirmed twice: from the capture, and from packet+24 in the handler
CKSUM_OFF = 10        # u16 LE.  parser 0x0058a0b0 sets s3 = packet+8 and reads s3+2.
MODE_OFF = 1          # packet[1] selects the cipher; 0 is a NO-OP (0x00584364)


def cksum(buf):
    """The client's own checksum, transcribed from `0x0058a080`.

        u32 sum = 0;
        for (i = 0; i < len; i++) sum += buf[i];
        sum = (sum >> 16) + sum;
        return sum & 0xffff;

    The parser zeroes the field at packet+10 before computing, so we do too.
    """
    b = bytearray(buf)
    b[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    total = 0
    for x in b:
        total = (total + x) & 0xFFFFFFFF
    total = (total + (total >> 16)) & 0xFFFFFFFF
    return total & 0xFFFF


def now_ms():
    """The client stamps a u16 of milliseconds at +4; mirror the same clock."""
    return int(datetime.datetime.now().timestamp() * 1000) & 0xFFFFFFFF


def hexdump(b, indent="    "):
    out = []
    for o in range(0, len(b), 16):
        chunk = b[o:o + 16]
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append("%s%04x  %-47s  %s" % (indent, o, chunk.hex(" "), txt))
    return "\n".join(out)


def describe(b):
    """Decode the fields we actually know, so the log is readable at a glance."""
    if len(b) < 8:
        return "  (too short to parse)"
    t0, t1 = b[0], b[1]
    ln = struct.unpack_from("<H", b, 2)[0]
    ts = struct.unpack_from("<I", b, 4)[0]
    s = "  hdr=%02x %02x  len=%d(actual %d)  ms=%d" % (t0, t1, ln, len(b), ts)
    if len(b) >= 10:
        s += "  type@8=%d flags@9=%02x" % (b[8], b[9])
    if len(b) >= BODY_OFF + 2:
        s += "  subtype(body[1])=%d" % b[BODY_OFF + 1]
    if len(b) >= CKSUM_OFF + 2:
        declared = struct.unpack_from("<H", b, CKSUM_OFF)[0]
        s += "  cksum@10=%04x (recomputed %04x)" % (declared, cksum(b))
    if len(b) >= 80:
        s += "  tail=%s" % b[76:80].hex()
    return s


def describe_inner(b):
    """Decrypt pkt[8..23] with the client's own cipher and show the real header.

    The inner header is the only enciphered part of the datagram, and it carries
    the reliable-messaging SEQ we need in order to ACK precisely (sec 4ae/4ai).
    header() self-checks -- the decrypted cksum must equal the folded byte-sum of
    the decrypted packet -- so None here means the mode/key did not apply.
    """
    if not _KELCRYPT or len(b) < 24:
        return None
    try:
        hd = doc_kelcrypt.header(bytes(b))
        if hd is None and b[1] == 4:
            # sec 4ed: the game-server channel's MODE 4 is the mode-2 cipher
            # instance (the 16 zero bytes) under another mode byte -- the
            # dispatcher leaves mode 4 untouched, but decrypting the header
            # as mode 2 authenticates: measured on the 09-11 keepalives and
            # the team-join request 31.
            # WARNING:KEY: 2026-09-22: through decrypt_any, so EVERY shipped key object
            # is tried and not just the blob's own. The blob is JP; a US client's
            # mode-4 instance has different key words, and against the JP object
            # alone its briefing-room traffic authenticates under no mode at all.
            # That was CER-48101: unreadable keepalive requests, never answered,
            # [chan+224] stale, the 40 s watchdog. See doc_kelcrypt._profiles.
            out, _build = doc_kelcrypt.decrypt_any(bytes(b), mode=2)
            if out is not None:
                h = out[8:24]
                ck = struct.unpack_from("<H", h, 2)[0]
                hd = {
                    "type": h[0], "flags": h[1], "cksum": ck,
                    "ack_seq": struct.unpack_from("<H", h, 4)[0],
                    "seq": struct.unpack_from("<H", h, 6)[0],
                    "u32_16": struct.unpack_from("<I", h, 8)[0],
                    "u32_20": struct.unpack_from("<I", h, 12)[0],
                    "is_data": bool(h[1] & 0x01),
                    "is_ack": bool(h[1] & 0x02),
                    "plain": out, "mode4": True,
                }
        return hd
    except Exception:
        return None


def build_reply(req, mode, subtype, crypto, body_len, mode_byte=0, do_cksum=True,
                ptype=128, flags=0, lobby_ip=None, lobby_port=55040):
    """Assemble a candidate server->client datagram.

    Deliberately built from the same field layout the client sends, because that
    is the only layout we have ever seen.  Whether the server is supposed to use
    it is exactly what the experiment is testing.
    """
    if mode == "none":
        return None
    if mode == "echo":
        return req

    body = bytearray(body_len)
    # body[1] is the subtype the handler dispatches on.
    if body_len >= 2:
        body[1] = subtype

    # --- THE LOBBY REDIRECT ------------------------------------------------
    # Subtype-4's handler (0x00585ec8) reads exactly three fields out of the
    # body and hands two of them to the sockaddr builder 0x0058a970:
    #
    #     v1 = lw  [body+4]     ; must be >= 0 or the handler bails with -3
    #     a1 = lw  [body+12]    ; -> IP
    #     a2 = lhu [body+10]    ; -> port
    #
    # So the body of this message is a REDIRECT: it tells the client where the
    # lobby server lives.  Sending zeros made DoC dial 0.0.0.0:0, which the
    # emulog shows verbatim -- "Creating New UDP Connection ... to 0" 26 ms
    # after our reply, then "Closed Dead".  That is why the connection reached
    # state 7 and stuck: state 7 waits on the lobby sub-connection that never
    # came up.
    #
    # The encoding below was derived by INVERTING 0x0058a970 against the live
    # connection object's own address field (ctx+0x10 = 01 00 then the port
    # little-endian then the four octets REVERSED: 01 00 00 d7 3c 02 00 c0 for
    # 192.0.2.60:55040) rather than by reasoning about byte order, and it
    # reproduces the live deployment's eight bytes exactly.
    if body_len >= 16 and lobby_ip:
        o = [int(x) for x in lobby_ip.split(".")]
        ip_field = (o[3] << 24) | (o[2] << 16) | (o[1] << 8) | o[0]
        port_field = ((lobby_port >> 8) | (lobby_port << 8)) & 0xFFFF
        struct.pack_into("<H", body, 10, port_field)
        struct.pack_into("<I", body, 12, ip_field)
        # body+4 must be >= 0; 0 already satisfies it, left explicit for clarity.
        struct.pack_into("<i", body, 4, 0)

    if crypto == "echo" and len(req) >= HDR_LEN:
        mid = bytearray(req[8:24])      # give back the client's own 16 bytes
    elif crypto == "zero":
        mid = bytearray(16)
    else:                                # "copyhdr": echo, falling back to zeros
        mid = bytearray(req[8:24] if len(req) >= HDR_LEN else bytes(16))

    # The INNER HEADER, decoded from the parser at 0x0058a218:
    #   +0 (packet+8)  message type, dispatched at 0x0058a250ff
    #   +1 (packet+9)  flags; bit 3 (0x08) = "carries an ID at packet+16"
    #   +2 (packet+10) checksum, written later
    # Type dispatch, transcribed:  0 -> s6=12 | 1 -> s6=8 | 2 -> fallthrough
    #   3 -> s6=40 | 4 -> fallthrough | 126 -> s6=12 | 127,128 -> fallthrough
    #   254, 255 -> their own arms | anything else -> the generic arm
    # 128 (0x80) is the type the CLIENT itself sends, per its send record.
    mid[0] = ptype & 0xFF
    mid[1] = flags & 0xFF               # keep bit 3 clear => no ID lookup

    total = HDR_LEN + len(body)
    pkt = bytearray()
    pkt += bytes([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", total)
    pkt += struct.pack("<I", now_ms() & 0xFFFF)
    pkt += mid
    pkt += body
    # The checksum must be written LAST, over the finished packet, with its own
    # field zeroed -- exactly what the parser does before comparing.
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    if do_cksum:
        pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
    return bytes(pkt)


# --- the character-list payload of response code 8 ---------------------------
#
# CHARA_REC_OFF: the handler reads its records from p+16 where p = record+24,
# i.e. body[20].  CHARA_MAX_RECORDS: the parser 0x0058a0b0 decodes into the
# 560-byte stack record its caller 0x00581590 hands it (a3 = sp+32, and the
# frame saves ra at sp+592), and the body copy lands at record+20 -- so a body
# may be at most 540 bytes and (540-20)//96 = 5 records.  A sixth would write
# over the client's saved return address.  MEASURED, not guessed: the caller's
# frame is `addiu sp, sp, -736` / `sd ra, 592(sp)` / `addiu s3, sp, 32`.
# WARNING: CORRECTED LIVE 2026-08-25 (boot 15:55).  These were 20/17/16 -- four bytes
# too far in -- and the client itself printed the proof:
#     KelLobbyService: char=145,used=122
# 145 = 0x91 = our body[13] and 122 = 0x7a = our body[12], while the count we
# meant to send sat unread at body[17] = 0x01.  So the handler's `p` is the BODY,
# not body+4: count = body[13], allowance = body[12], records from body[16].
# doc_wire_record_map.py reported body[16]/body[17]; the running client disagrees,
# and the client wins.
CHARA_REC_OFF = 16
CHARA_MAX_RECORDS = 5

# wire -> buffer permute performed by 0x0058ad30, read out of the function
# (each row MEASURED from the disassembly, not inferred from a round trip):
#
#   wire +0x00 u32  -> buf +0x20      wire +0x40 u16  -> buf +0x36
#   wire +0x04 u32  -> buf +0x30      wire +0x42 u8   -> buf +0x58
#   wire +0x08 u32  -> buf +0x28      wire +0x43 u8   -> buf +0x59
#   wire +0x10 8B   -> buf +0x10      wire +0x44 16B  -> buf +0x00   <- string A
#   wire +0x18 u32  -> buf +0x24      wire +0x54 u8   -> buf +0x39
#   wire +0x20 24B  -> buf +0x40      wire +0x55 u8   -> buf +0x3A
#   wire +0x38 u16  -> buf +0x18      wire +0x57 u8   -> buf +0x3B
#   wire +0x3C u16  -> buf +0x34      wire +0x58 u8   -> buf +0x3C
#   wire +0x3E u16  -> buf +0x5A      wire +0x59 u8   -> buf +0x3E
#                                     wire +0x5B u8   -> buf +0x3F
#
# TWO blocks are wide enough to be a name: wire+0x20 (24 B) and wire+0x44 (16 B).
# Which one the UI draws is NOT known -- that code is in lobby.pex (230,944 B),
# never disassembled.  So the default record puts a DIFFERENT readable string in
# each, and one live boot tells us which offset is the name.

PROBE_SLOTS = [
    ("id+0x00",   lambda r: struct.pack_into("<I", r, 0x00, 1)),
    ("flag+0x04", lambda r: struct.pack_into("<I", r, 0x04, 1)),
    ("name+0x44", lambda r: r.__setitem__(slice(0x44, 0x44 + 6), b"PROBEC")),
    ("name+0x20", lambda r: r.__setitem__(slice(0x20, 0x20 + 6), b"PROBED")),
]


CHARA_ID_MEMBER_OFF = 0x40000   # member ids sit above every uid-derived id


def chara_id_for(base, uid, key, slot):
    """The CHARACTER ID for roster `slot` (sec 4dv; per MEMBER since 09-13).

    sec 4dv derived it from the entrance uid: base + ((uid & 0xffff) << 2) +
    slot. That was unique only while every client shared ONE account and
    picked different slots. Since --accounts-db (f8db8052) each POL member
    has its own roster -- but both machines present the SAME entrance uid
    (0xa756a69a, live 09-13), so every member's slot 0 got the same id
    (0x2aa68, then 0x2b9a0 for BOTH): each client dropped the other's 0x83s
    as its own (0x00bdd5c8's self check), the table list named the wrong
    leader, and the Start fan-out found the leader instead of the joiner.

    A `member:N` key now derives from N, in a range the uid formula cannot
    reach (it tops out at base + 0x3ffff): base + 0x40000 + (N << 2) + slot.
    Stable per character across sessions, as the peer table needs. Any other
    key (a uid, `addr:<ip>`, an --account string) keeps the old formula
    exactly. Bits 30/31 stay clear (sec 4bw/4ch)."""
    if not base:
        return 0
    if isinstance(key, str) and key.startswith("member:"):
        try:
            n = int(key.split(":", 1)[1], 0)
        except ValueError:
            n = None
        if n is not None:
            return (base + CHARA_ID_MEMBER_OFF + ((n & 0x3FFF) << 2) + slot) \
                & 0x3FFFFFFF
    return (base + ((uid & 0xFFFF) << 2) + slot) & 0x3FFFFFFF


def build_charamake_answer(template, reg_pkt, record, seq=0,
                           inner_ip="127.0.0.1"):
    """The selector-16 CHARAMAKE answer, CARRYING the new character's record.

    2026-09-13: the answer used to be an empty advance, so a freshly created
    character only appeared in the select list after the player backed out and
    the list was fetched again (seen in a live session). The state-10 handler 0x00587e98 does
    more than release phase 10: when [nest+232] is set it calls 0x00587cf0,
    which reads ONE 96-byte wire record at body[12] (the same layout as a code-8
    list record: name +68, slot +84, used +85) and then walks the list buffer
    [nest+244] for the entry whose slot byte (buf+57, scattered from wire+84)
    equals the new record's, and updates it in place (0x0058ae20). It also reads
    body[112..175] into the local record ([nest+232]+100..163) -- so the tail is
    the client's own REGISTER body from byte 108 on, unchanged.

    body[0..11] come from the client's 96-byte TEMPLATE (subchannel <= 5,
    selector, flag bit 0 clear); empty_records is NOT used, because it zeroes
    body[13], which is now a byte of the character id."""
    head = bytearray(template[BODY_OFF:BODY_OFF + 12]).ljust(12, b"\x00")
    tail = bytearray(reg_pkt[BODY_OFF + 108:]) if len(reg_pkt) > BODY_OFF + 108 else bytearray()
    body = head + bytearray(record[:96]).ljust(96, b"\x00") + tail
    if len(body) < 176:
        body += bytes(176 - len(body))
    return build_lobby_advance(bytes(template[:BODY_OFF]) + bytes(body),
                               selector=16, seq=seq, inner_ip=inner_ip)


def build_used_record(index=0, name=None, appearance=None, char_id=0,
                      chr_code=None):
    """A 96-byte WIRE record the client renders as a REAL character.

    Two hops, both MEASURED, and the second one is why the obvious offsets fail.

    1. The CONSUMER's branch 0x00ad591c decides which format string to print:

           lbu  v0, 106(service + index*96)
           andi v0, v0, 0x0001
           beq  v0, zero -> "#%d (not use)"
                         -> "#%d %s"  , %s = service + index*96 + 48

       and the copy feeding it moves 96 B from buf+16+n*96 to service+48+n*96,
       so in the BUF record: name at +0, USED = bit 0 of +58.

    2. But 0x0058ad30, which fills the buf record from OUR wire record, is NOT a
       memcpy -- it is a field-by-field SCATTER:

           lbu 85(src) -> sb 58(dst)      the USED flag
           ldr 68(src) -> sdr  0(dst)     the name, 16 B: wire+68..83
           ldr 76(src) -> sdr  8(dst)
           lw   0(src) -> sw  32(dst)
           lhu 60(src) -> sh  52(dst)
           ...

    ⇒ on the WIRE the name is at +68 and the used flag at +85.  Serving them at
    the buf offsets (0 and 58) renders nothing, which is exactly what boot 19414
    showed: four slots, all "(not use)".
    """
    r = bytearray(96)
    nm = (name or "SLOT%d" % index).encode("ascii", "replace")[:15]
    r[68:68 + len(nm)] = nm          # -> record+0, the %s the used branch prints
    r[85] |= 0x01                    # -> record+58 bit 0, the USED flag
    # KEY:KEY: sec 4dv: WIRE+0..3 IS THE CHARACTER ID, AND IT IS [kelsvc+272].
    # We shipped it as zero for every character we have ever served, and
    # [kelsvc+272] == 0 is the root of the name-plate error, the bogus
    # "you already have a reservation" table id, and the self-lookup that made
    # --peer-push have to push id 0 (the 2026-09-05 audit, missing #1).
    #
    # The chain, all static:
    #   lobby phase 25 (0x00ad3e94) calls mainconn vt+116 = 0x00587008 with
    #     a1 = [manager+11768], the slot the player picked;
    #   0x00587008 -> 0x00588ee0(nest, slot): v0 = [nest+244] + slot*96, returns
    #     [v0+48].  [nest+244] is the 1552-byte chara buffer (16-byte header +
    #     16 x 96), so v0+48 is buf-record+32 -- and 0x0058ad30's scatter is
    #     `lw 0(src) -> sw 32(dst)`, i.e. OUR WIRE +0..3;
    #   if it is not -1, 0x00587008 calls kelsvc vt+1212 = 0x00bd0fe8, whose
    #     whole body is `[kelsvc+272] = a1`.
    #
    # WARNING: SAFE TO CHANGE, and this is why: the client's own outgoing header
    # builder 0x00bdb190 does `lw v1, 272(a0); sw v1, 4(a1)` -- it stamps
    # [kelsvc+272] into record+4 of every message it sends, which is the field
    # every gated arm compares against [kelsvc+272] and the field we already
    # ECHO. Serve a nonzero id and both sides move together.
    #
    # WARNING: KEEP BITS 30 AND 31 CLEAR. Bit 30 picks which peer table an id belongs
    # to and only the bit-30-CLEAR side may ask (sec 4bw); and the profile cache
    # compares its key 64 bits wide after a SIGN-EXTENDING `lw` (sec 4ch), so an
    # id with bit 31 set stores fine and is never found again.
    struct.pack_into("<I", r, 0, char_id & 0x3FFFFFFF)
    # KEY: sec 4fs: WIRE+84 IS THE RECORD'S OWN SLOT NUMBER, and it is what the
    # select picks -- NOT the cursor. sec 4dv read `[manager+11768]` as "the
    # slot the player picked"; it is not. The select handler 0x00ad5980
    # (called from 0x00aac0b4 with a1 = the menu cursor) does
    #     [mgr+11760] = cursor
    #     [mgr+11764] = [mgr+48 + cursor*96 + 32]        the id (wire+0)
    #     [mgr+11768] = (s8)[mgr+48 + cursor*96 + 57]    buf+57
    # and the scatter 0x0058ad30 has `lbu 84(src) -> sb 57(dst)`. Phase 25
    # hands [mgr+11768] to the picker, which reads that CHARA-BUFFER slot's id.
    # We served 0 here for every character, so every pick resolved to buffer
    # slot 0: the Deck picked "Test" and reported Lex's 0x2aa68 (live 09-12).
    # Signed byte (`lb`), and the picker errors on < 0; empty slots stay 0.
    r[84] = index & 0x7F
    # sec 4dr APPEARANCE PROBE: the select-screen preview renders the created
    # character's look, and the look lives in single-byte fields of THIS record
    # (0x0058ad30 scatters wire+66/67/84/87/88/89/91 -> buf+88/89/57/59/60/62/63).
    # Which buf byte drives gender/face/armor/color/voice is in lobby.pex and is
    # NOT mapped, so we write the stored values across every candidate and let the
    # preview say whether this record is even the source. The charamake packs
    # face/armor/color as nibbles of wire+92/93 (sec 4bd); we both spread the
    # nibbles and copy the raw bytes so one of them lands.
    # sec 4dt: the appearance is NOT in this record -- a broad probe (every byte
    # but id/name/used stamped) moved neither the select preview nor the lobby
    # model. It rides the 1552-byte chara-data blob on the USER-DATA channel
    # (emulog `can't get userdata !`), a separate chapter. RETRACTED sec 4fy:
    # the select-screen look IS in this record, at wire+56 -- see below. The
    # broad probe put 0x0303 there, which renders male colour 3 and was read
    # as "the default".
    if False and appearance:
        # sec 4ds/4dt: the 7 single-byte candidates (66/67/84/87/88/89/91) did
        # NOT move the preview, and the live actor record shows appearance as a
        # small byte field (`02 04 02 01`) next to the o099 model name. So either
        # the appearance sits in this record's OTHER fields or the preview reads a
        # separate structure. BROAD PROBE: stamp a visible non-default value (3)
        # into every byte that is NOT the id (0..3), name (68..83) or used flag
        # (85). If the preview/model changes AT ALL, the list record drives it and
        # we narrow; if not, it is a separate character-detail fetch (sec 4ds).
        MARK = 3
        for _i in range(4, 96):
            if 68 <= _i <= 83 or _i == 85:
                continue
            r[_i] = MARK
    # sec 4dr EXPERIMENT (2026-09-10): the o099 costume builder 0x006ec748 reads
    # a 64-bit "chr code" as `ld [actor+0x440]` -- bit32 = gender (0='m',1='f'),
    # bit33 = face-model flag, then a 6-bit cursor walks out the six part
    # variants (`o099_<m|f>_<NN>`; two of them are (code>>34)&0xff and
    # (code>>42)&0xff). The record's ONLY 8-byte field is wire+0x10..0x17, which
    # 0x0058ad30 moves as one unit to buf+0x10, so IF the list record feeds the
    # costume it is here. That link is UNPROVEN and a broad 09-05 probe (the
    # `if False` block above) argued against it -- but that probe rode the flaky
    # one-per-session state-6 window, so it is not decisive. --chara-chrcode
    # stamps a KNOWN value here (not the stored appearance, which may be all
    # default and thus invisible): select the character, enter, and read the
    # emulog `chr load request [o099][0x...]` / `chr resource loaded o099 [...]`
    # / `o099_f_NN` names. If they change, this field IS the appearance; if not,
    # the costume rides the user-data/JVM path (sec 4dt/4du). 8 bytes, LE.
    if chr_code is not None:
        struct.pack_into("<Q", r, 0x10, chr_code & 0xFFFFFFFFFFFFFFFF)
    # KEY: sec 4fy (2026-09-13): THE SELECT-SCREEN PREVIEW LOOK IS WIRE+56, a u16
    # LE o099 code -- the same value the lobby uses (doc_charastore.chr_code =
    # app92 | app93 << 8). The select screen is Java: ev2046.select_main() calls
    # get_charamake(window.getvalue(1, row)); the kind-10 window handler
    # 0x00aab9f8 returns `lhu buf+24` for a USED row (bit 0 of buf+58), and the
    # scatter 0x0058ad30 has `lhu 56(src) -> sh 24(dst)`. We served 0 -- and
    # repack(0) is the default male every row showed. No message is sent when a
    # row is highlighted; the preview reads only the rows it already holds.
    # Proof: an offline run of the client's own code (doc_select_costume_proof) (client code, slot .06 = the
    # select screen with Lex in row 0).
    if appearance:
        from doc_charastore import chr_code as _chr_code
        struct.pack_into("<H", r, 0x38, _chr_code(appearance) & 0xFFFF)
    return bytes(r)


def build_probe_record(index):
    """One 96-byte record that is ALL ZERO except a single candidate field.

    Finding the record's "used" marker is a search, and the four character slots
    are independent -- so serve four DIFFERENT records in one boot and let the
    client tell us which candidate stops a slot printing "(not use)".  Four
    hypotheses per boot instead of one.

    Everything here is a hypothesis: build_chara_record's field guesses come from
    offline mapping and have never been tested against a client that actually
    rendered a row.  MEASURED so far is only the negative -- arbitrary bytes read
    as unused (sec 4bb), so the marker is POSITIVE and inside these 96 bytes.
    """
    r = bytearray(96)
    if index < len(PROBE_SLOTS):
        PROBE_SLOTS[index][1](r)
    return bytes(r)


def build_chara_record(index=0, name_a=None, name_b=None, fill=1):
    """One 96-byte WIRE character record for a code-8 reply.

    `name_b` goes at wire+0x20 (24 B, -> buf+0x40) and `name_a` at wire+0x44
    (16 B, -> buf+0x00).  Defaults are deliberately distinguishable on screen so
    a tester can report WHICH string rendered as the character name.

    Unknown small fields default to `fill` (1, not 0) because a zeroed level /
    class / slot may well render as an empty row -- the thing we are trying to
    tell apart from "no characters at all".  Pass fill=0 to test the opposite.
    """
    if name_b is None:
        name_b = "BBBBBB%d" % index
    if name_a is None:
        name_a = "AAAAAA%d" % index
    r = bytearray(96)
    struct.pack_into("<I", r, 0x00, index + 1)      # -> buf+0x20 (an id?)
    struct.pack_into("<I", r, 0x04, fill)           # -> buf+0x30
    struct.pack_into("<I", r, 0x08, fill)           # -> buf+0x28
    struct.pack_into("<I", r, 0x18, fill)           # -> buf+0x24
    b = name_b.encode("ascii", "replace")[:23]
    r[0x20:0x20 + len(b)] = b                        # -> buf+0x40, 24 B
    a = name_a.encode("ascii", "replace")[:15]
    r[0x44:0x44 + len(a)] = a                        # -> buf+0x00, 16 B
    struct.pack_into("<H", r, 0x38, fill)           # -> buf+0x18
    struct.pack_into("<H", r, 0x3C, fill)           # -> buf+0x34
    struct.pack_into("<H", r, 0x3E, fill)           # -> buf+0x5A
    struct.pack_into("<H", r, 0x40, fill)           # -> buf+0x36
    for off in (0x42, 0x43, 0x54, 0x55, 0x57, 0x58, 0x59, 0x5B):
        r[off] = fill & 0xFF
    return bytes(r)


def build_lobby_advance(req, selector=2, subchannel=None, seq=0,
                        mode_byte=0, ptype=0x81, inner_ip="127.0.0.1",
                        empty_records=False, chara_count=None,
                        chara_allow=None, chara_records=None):
    """The type-129 reply that advances the UDATA nest 1->2 (and main conn 7->8).

    PROVEN OFFLINE END-TO-END (measured against the client's own parser): kel's real parser
    `0x0058a0b0` decodes the datagram into the record the driver `0x005895b0`
    dispatches on, where record `+20..` is a straight copy of the body
    (packet+24+).  So:

        [record+20] subchannel = body[0]   (must be <= nest+12 == 5)
        [record+21] SELECTOR   = body[1]   (== 2 at nest state 1 -> m5 advances)
        [record+24] flag       = body[4]   (bit 0 must be clear for m5)

    Running the real parser + real driver against the live nest in
    `doc_udata_state1.bin` with this reply (body[1]=2) flips [nest+8] 1->2; the
    control (body[1]=1) does not.  No cipher and no session key are needed: this
    is a MODE-0 packet, and mode 0 is a verified no-op on the client's decrypt
    path (0x00584364), so the plaintext inner header is read straight through.

    The peer-address gates (0x00588000 / m2) check the SOCKADDR, not the body, so
    they pass for free because we reply from the dialled socket.

    The body is taken from the client's own inbound 96-byte packet (its body is
    PLAINTEXT on the wire -- the 52-byte session token is visible) so the token
    and structure are preserved; only body[1] (selector) and body[4] (flag) are
    overridden.  A minimal all-zero body advances too, but preserving the token
    is safer for whatever reads the body after the advance.
    """
    if len(req) < BODY_OFF:
        return None
    body = bytearray(req[BODY_OFF:])
    if len(body) < 5:
        body += bytes(5 - len(body))
    if chara_count is not None and len(body) < CHARA_REC_OFF:
        # The 36-byte mode-2 packets carry only a 12-byte body; a code-8 chara
        # reply needs at least the 20-byte header (count at body[17], records
        # from body[20]).  Pad rather than refuse -- subchannel/selector/flag all
        # sit in the first 5 bytes and are preserved.
        body += bytes(CHARA_REC_OFF - len(body))
    if subchannel is not None:
        body[0] = subchannel & 0xFF          # else keep the client's (0x05, <=5)
    body[1] = selector & 0xFF                 # THE selector: 2 advances at state 1,
                                              # 8 advances the state-6 data loop (router
                                              # jump table idx = selector-4; idx 4 -> the
                                              # nest[8]==6 handler 0x00587c10).
    body[4] &= 0xFE                            # m5 needs [record+24] & 1 == 0
    if empty_records:
        # The state-6 handler 0x00587c10 reads body[17] as the record count and, if
        # non-zero, parses `count` 96-byte entries from body[20]+.  Zero it so an
        # advance-only reply parses no records (LIVE-safe: the handler then just sets
        # state 2 and the nest self-advances 2->6, re-stamping liveness).  MEASURED:
        # slot-1 savestate has nest[+0xe8]==0, so the bulk-copy path is skipped too.
        if len(body) > 13:
            body[13] = 0x00

    if chara_count is not None:
        # THE CHARACTER LIST.  Handler 0x00587c10 (response code 8, gated on
        # nest[+8]==6) does, with p = record+24 and buf = [nest+0xF4]:
        #
        #     buf[1] = p[12]  = body[12]      <- slot allowance
        #     buf[0] = p[13]  = body[13]      <- THE CHARACTER COUNT
        #     for n in range(buf[0]):
        #         0x0058ad30(buf + 16 + n*96, p + 16 + n*96)   ; p+16 = body[16]
        #
        # The wire offsets are MEASURED, not inferred: an offline run of the client's own code (doc_wire_record_map)
        # runs kel's real parser 0x0058a0b0 on a marked packet and reports
        # rec+36 = wire[+40] = body[16] and rec+37 = wire[+41] = body[17].
        # (An earlier reading quoted these as body[12]/body[13]; those numbers are
        # relative to the handler's own p = record+24, i.e. body+4.  Same bytes.)
        #
        # NB body[16] is NOT zero in the sustain reply we have been sending all
        # along: it is token byte 0x4c (76) in every captured packet, so buf[1]
        # has been 76 on every boot to date and no create-character affordance
        # appeared.  Set it explicitly here so the experiment is deliberate.
        if chara_allow is not None:
            body[12] = chara_allow & 0xFF
        recs = list(chara_records or [])
        n = max(0, int(chara_count))
        if n and not recs:
            recs = [build_chara_record(i) for i in range(n)]
        n = min(n, len(recs) if recs else n, CHARA_MAX_RECORDS)
        body[13] = n & 0xFF
        if n:
            body = body[:CHARA_REC_OFF] + bytearray(b"".join(recs[:n]))

    # inner header (plaintext, since mode 0 skips the cipher):
    #   +0 -> record+0 type ;  +1 -> record+1 flags (bit3 clear = no ID lookup)
    #   +6 -> record+16 seq ;  +8 -> record+4 ID (our IP; not gated, harmless)
    mid = bytearray(16)
    mid[0] = ptype & 0xFF
    mid[1] = 0x00
    struct.pack_into("<H", mid, 6, seq & 0xFFFF)
    if inner_ip:
        o = [int(x) for x in inner_ip.split(".")]
        struct.pack_into("<I", mid, 8, (o[3] << 24) | (o[2] << 16) | (o[1] << 8) | o[0])

    total = HDR_LEN + len(body)
    pkt = bytearray()
    pkt += bytes([0x04, mode_byte & 0xFF])    # mode 0 = no cipher
    pkt += struct.pack("<H", total)
    pkt += struct.pack("<I", now_ms() & 0xFFFF)
    pkt += mid
    pkt += body
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
    return bytes(pkt)


def build_world_answer(req, selector=2, subchannel=7, ptype=127, seq=0,
                       inner_ip="127.0.0.1", mode_byte=0, pad_to=0,
                       ident=None, result=0, gs_ip=None, gs_port=0,
                       gs_id=0, cmd_arg=None, spawn=None, self_probe=False,
                       self_costume=None, self_id=None, self_hp=None,
                       self_name=None, self_gil=None, self_bag=None,
                       self_unit=None, self_career=None, self_gear=None,
                       self_novice=False):
    """The type-0x7f reply that takes [kelsvc+12] 1 -> 2 and releases phase 28.

    WARNING:WARNING: `pad_to` IS NOT COSMETIC -- it is the fix for the SE crash (sec 4bo).
    The client builds an OBJECT out of this reply's body at body[44], and reads a
    32-bit ARRAY COUNT from that object's +0x60, i.e. **body[140]**.  Echoing the
    132-byte request gives a 108-byte body, so body[140] is 33 bytes past the end
    of what we send and the client reads stale RAM.  Measured values of that
    stale word across six savestates: 0, 1040, 2149, -1529, 15360, 15360.  The
    copy loop at 0x00be66e4 then writes count*8 bytes -- 122,880 of them at
    15360 -- straight over the SE record-array base at 0x009F4920, and the next
    `request SE` dereferences the wreckage.  The game's own bulk setter
    (0x00be74a8) clamps that count to 256; this path does not check it at all.
    Padding the body with zeros puts a 0 there, and `beq v0, zero` skips the loop
    entirely.

    Same gates as the nest's selector-2 advance -- driver 0x005895b0 is shared --
    on kelsvc (= [0x00BF2F70] - 236 = 0x009f3480) with looser constants:

        [record+20] body[0]  subchannel, must be <= [kelsvc+16] == 7   (nest: 5)
        [record+21] body[1]  SELECTOR 2 at state 1 -> arm 0x00589660
                             -> sub vt entry 6 = 0x00bc8aa0 -> 0x005894f0
        [record+24] body[4]  u16, bit 0 is the FAILURE flag -- must be clear
        [record+26] body[6]  u16 error code, reported as -value when bit 0 is set

    WARNING:WARNING: THE REQUEST IS MODE 1 AND ITS FIRST 16 BODY BYTES ARE CIPHERTEXT.  This
    cost the 18:32 boot.  Echoing the request body wholesale -- which is what the
    nest answers do, and which is safe there because those bodies arrive
    plaintext -- put `d8 be 82 13 ...` into body[0..15], so body[0] read as 216
    and the driver's very first gate (`[record+20] > [kelsvc+16]`) rejected it
    before the selector was ever looked at.  The log said
    `SENT ... body[0]=216` and that number is the whole bug.

    MEASURED, by lining the live capture up against the payload connectServer
    0x00bce620 builds in the emulator:

        body[0..15]   ENCIPHERED on the wire.  Plaintext is
                      07 01 00 00 01 00 00 00 00 00 00 00 00 00 00 00
        body[16..27]  plaintext zeros, in the capture AND in the emulator
        body[28..79]  the 52-byte session token, plaintext (wire+52 = +0x34)

    So the first 16 bytes are SYNTHESISED here rather than echoed, and everything
    from body[16] on is copied from the request so the token survives.  Our reply
    is mode 0, which the client's decrypt path treats as a no-op (0x00584364), so
    what we write is what the driver reads.
    """
    if len(req) < BODY_OFF + 12:
        return None
    body = bytearray(req[BODY_OFF:])
    # KEY: sec 4dv: NOT every rung of the ladder is 40 bytes.  The reserve's own
    # server-handoff request (selector 22, phase 42) is a 36-BYTE datagram --
    # a 12-byte body -- and the old `< BODY_OFF + 16` bail returned None for it,
    # so the one message the reservation waits on was never answered at all.
    # A short body is padded out to the 16 bytes this builder synthesises;
    # there is nothing of the client's past body[11] to preserve.
    if len(body) < 16:
        body += bytes(16 - len(body))
    body[0] = subchannel & 0xFF
    body[1] = selector & 0xFF
    body[2] = 0
    body[3] = 0
    struct.pack_into("<H", body, 4, 0)        # command echo; bit 0 = failure flag
    struct.pack_into("<H", body, 6, 0)        # error code
    body[8:16] = bytes(8)
    # body[12..15] is `record+32`, the RESULT the selector-13 handler 0x00bca868
    # reads first: negative is an error and phase 30 reports it verbatim out of
    # [kelsvc+1064].  0 = success (sec 4bs).
    struct.pack_into("<i", body, 12, result)
    # body[16:] is left exactly as it arrived -- plaintext, and it carries the token.
    # ...EXCEPT when the caller has a value for body[16..19].  Selector 241's arms
    # read their argument there (`lw v0, 4(s0)` with s0 = body+12), and echoing the
    # request leaves whatever stale stack the client's one-byte command write did
    # not cover -- for command 20 the capture holds 0x003bba30, a CODE ADDRESS.
    # That is nonzero, so it would close the loop with garbage.
    # WARNING:KEY: sec 4dy: AND ON SELECTOR 241 THE WHOLE 12-BYTE ARGUMENT MUST BE ZEROED,
    # not echoed. the 2026-09-05 audit filed this as defect H -- "harmless today only
    # because those arms' consumers are unread" -- and the Unit Management panel
    # reads them. Two of the sub-command arms are LIST WRITERS that take their
    # element COUNT out of this very field:
    #
    #   sub 13  0x00bc9520   count = u32 at body[16], clamped to [kelsvc+1056],
    #                        then count x 8 bytes copied from body[20]
    #   sub 25  0x00bc94c4   count = SIGNED BYTE at body[16], then
    #                        count x 176 bytes copied from body[24]
    #
    # Echoing the request left the client's own uninitialised stack there. Live
    # 2026-09-06, the Unit panel sent exactly these two and we answered with
    #   sub 13  body[16..19] = 04 80 00 00 -> count 32772 -> a 262,176-byte READ
    #   sub 25  body[16..19] = 6c 35 9f 00 -> count 108   -> a 19,008-byte WRITE
    # out of a 176-byte body. (`6c 35 9f 00` is 0x009f356c, the kelsvc pointer
    # itself.) The unit list was therefore built out of whatever followed our
    # packet, and the alert it then tried to name resolved to `!!na!!`.
    #
    # Zero is the honest answer -- both arms `blez` on a count <= 0 and take the
    # shared no-op, i.e. "you have no units", which is true. WARNING: This must come
    # BEFORE the cmd_arg store below, which is the one derived value we do have.
    if selector == LOBBY_CMD_SELECTOR_ANS and len(body) >= 28:
        body[16:28] = bytes(12)
    # Extend the body with zeros so the fields the client reads past the echoed
    # request actually exist.  body[140] is the one that matters (see above); the
    # rest of the object is zeroed rather than guessed, which is the conservative
    # choice -- a zero count means "no entries", which is what we in fact have.
    if pad_to and len(body) < pad_to:
        body += bytes(pad_to - len(body))
    # AFTER the pad: a 16-byte request body (selector 151 carries only its u16
    # key) used to skip this write entirely, sec 4dz.
    if cmd_arg is not None and len(body) >= 20:
        struct.pack_into("<I", body, 16, cmd_arg & 0xFFFFFFFF)

    # THE GAME SERVER ENDPOINT, for the selector-21 rung (sec 4bs).  0x00bca938
    # reads body[52..55] as the IP and body[56..57] as the port and hands both to
    # 0x0058a970, which builds the sockaddr at [0x009f2b40 + 184] -- the channel
    # that sat at 0.0.0.0:0 for three sessions.  The encoding was CALIBRATED, not
    # guessed: with the octets in network order and the port big-endian, the bytes
    # the client ends up storing are IDENTICAL to the live lobby sockaddr at
    # [kelsvc+48] (01 00, port little-endian, octets reversed: 01 00 00 d7 3c 02
    # 00 c0 for 192.0.2.60:55040).
    if gs_ip and len(body) >= 60:
        body[52:56] = bytes(int(x) for x in gs_ip.split("."))
        struct.pack_into(">H", body, 56, gs_port & 0xFFFF)
        # WARNING: LITTLE-endian, unlike the two fields above it. body[56..57] is a
        # PORT and goes into a sockaddr, so it is network order (calibrated in
        # sec 4bs). body[58..59] is NOT part of the sockaddr -- 0x00bca938
        # reads it with a plain `lhu` and stores it at [kelsvc+268]. Packing it
        # big-endian made gs_id=1 arrive as 256; measured 2026-08-27.
        struct.pack_into("<H", body, 58, gs_id & 0xFFFF)

    # THE LOBBY SPAWN, for the selector-13 rung (sec 4dh).  0x00bca868 reads
    # body[28..53] and stores the 28-byte descriptor the zone script later reads
    # back through KerberosNetLobby.getLobbyInitPos().  Zeros here are the
    # p(0,0,0) spawn the account holder has been landing on.
    #
    # WARNING:WARNING: SAME OFFSET, TWO MEANINGS -- AGAIN.  body[52..55] is the GAME SERVER IP
    # on selector 21 and the spawn INDEX on selector 13, and the caller passes
    # gs_ip on every rung.  So this must run AFTER the gs_ip block and must be
    # keyed on the selector, never on "the caller gave me a spawn".
    if spawn is not None and selector == WORLD_SPAWN_SELECTOR_ANS and len(body) >= 54:
        sx, sy, sz, dx, dy, dz, sidx = spawn
        struct.pack_into("<f", body, SPAWN_OFF_X, sx)
        struct.pack_into("<f", body, SPAWN_OFF_Y, sy + SPAWN_Y_BIAS)
        struct.pack_into("<f", body, SPAWN_OFF_Z, sz)
        struct.pack_into("<f", body, SPAWN_OFF_DIR_X, dx)
        struct.pack_into("<f", body, SPAWN_OFF_DIR_Y, dy)
        struct.pack_into("<f", body, SPAWN_OFF_DIR_Z, dz)
        # TWO byte stores, not a halfword: 0x00bca8a4/0x00bca89c do `lbu`/`lhu>>8`
        # and the arm writes them to the descriptor's +24 and +25 separately.
        body[SPAWN_OFF_INDEX] = sidx & 0xFF
        body[SPAWN_OFF_INDEX + 1] = (sidx >> 8) & 0xFF

    # THE MAP-PICKER MASK, same rung, body[72..79] (sec 4gv).  Keyed on the
    # selector for the same reason the spawn is: these bytes mean something
    # else on the other rungs that share this builder.
    #
    # WARNING: This is NOT conditional on `spawn`.  The mask has to go out even when
    # --lobby-spawn is empty: it is the only thing that fills the map roster,
    # and the same arm writes it either way.
    #
    # KEY: The arm bails BEFORE the two mask stores when body[12] is negative as
    # a signed int -- that is `--world-result`, already documented here as
    # "copied verbatim into [kelsvc+1064], and phase 30 fails if it is
    # negative".  Two independent reads of the same handler agree, which is why
    # that field is only checked here, never rewritten.
    if (selector == WORLD_SPAWN_SELECTOR_ANS
            and len(body) >= LOBBY_MAP_MASK_OFF + 8):
        if LOBBY_MAP_MASK:
            _z = struct.unpack_from("<i", body, 12)[0]
            if _z < 0:
                # Do NOT rewrite it here -- body[12] is the client's own echoed
                # field and this rung already works.  Say so loudly instead, so
                # a mask that never lands is not mistaken for a mask that
                # landed and did nothing.
                print("  [map] WARNING: body[12] = %d is NEGATIVE; the arm bails "
                      "before storing the map mask, so the picker will stay "
                      "empty. Investigate the echo before blaming the mask."
                      % _z, flush=True)
            struct.pack_into("<II", body, LOBBY_MAP_MASK_OFF,
                             LOBBY_MAP_MASK & 0xFFFFFFFF,
                             (LOBBY_MAP_MASK >> 32) & 0xFFFFFFFF)

    # sec 4ev (2026-09-11): OVERRIDE body[44..47] with the CHARAID on the
    # world-door answer. mgr+304 [rec+52] = record+32 = body[44] (the earlier
    # measured chain 0x00bc8aa0->0x00bdeb38 setMySelfRecord->0x00be45d8); the
    # client echoes its own UID there (token+16), so the battletable-data
    # manager's self record is keyed by the UID while getMyReservationTableId()
    # looks it up by the CHARAID [kelsvc+272] -> MISS -> the getter returns an
    # uninitialised buffer read (0x8AC0) that the 0x6835 gate reads as a phantom
    # reservation (sec 4eu). Keying by the charaid makes the lookup HIT a clean
    # record -> 0xffff -> Create allowed. Caller passes self_id only on the
    # world-door (selector 2), where it does not collide with the spawn (sel 13
    # body[44]=dir float) or the gs endpoint (sel 21 body[52]).
    # WARNING: body[44] overlaps the echoed 52-byte session token (token+16); if
    # the client re-validates the token this could disturb world entry. Gated
    # behind --world-self-charaid; revert by dropping the flag.
    if self_id is not None and len(body) >= 48:
        struct.pack_into("<I", body, 44, self_id & 0xFFFFFFFF)

    # sec 4hg addendum 4: THE LOBBY ZONE at body[42..43] of the world-door
    # answer (see LOBBY_ZONE above).  Selector 2 only: 13 carries the spawn
    # floats there and 21 the endpoint.  0 = leave the echoed token bytes.
    if selector == 2 and LOBBY_ZONE and len(body) >= LOBBY_ZONE_OFF + 2:
        struct.pack_into("<H", body, LOBBY_ZONE_OFF, LOBBY_ZONE & 0xFFFF)

    # KEY: 2026-09-13: THE HP. The self record setUserData 0x00be6580 reads starts
    # at body[44] (its +0 is the id above), and it copies record+4 -- body[48..51]
    # -- into R+44 and R+752 of the self record R = 0x009f3cb0: the CURRENT and
    # MAX HP (setters 0x00be8350/0x00be8548 do `R+44 = R+752`, i.e. cur = max).
    # We echoed the 52-byte session token there, whose word after the uid is
    # 0x9dd38642 on the private deployment's install (live world-door request 09-13:
    # `9a a6 56 a7 42 86 d3 9d` at body[44..51]) -- the HUD's 16-bit view of it
    # is 0x8642 = -31166 for BOTH halves, the "HP -31166/-31166" since 08-27
    # (sec 4cz's garbage halfword, sec 9195's spawn-record +00 `42 86 ff ff`).
    # Selector 2 only: body[48] is spawn data on 13 and the endpoint on 21.
    if self_hp is not None and selector == 2 and len(body) >= 52:
        struct.pack_into("<I", body, 48, self_hp & 0xFFFFFFFF)

    # sec 4gk: GIL and the BAG ride the same self record. body[52] -> R+744 (the
    # gil 146 spends; MEASURED by marker, doc_shop_proof.py) -- until now the
    # echoed token put ~1.09 billion there. body[140] is the sec 4bo count and
    # body[240+8i] the entries; the client does not clamp the count, so
    # apply_login caps it at 50. Selector 2 only (body[52] is the GS IP on 21
    # and the spawn index on 13).
    if selector == 2 and (self_gil is not None or self_bag is not None):
        body = doc_shop.apply_login(body, self_gil, self_bag)

    # 2026-09-13: the CAREER rides the same self record (doc_stats.py; routes
    # MEASURED offline against the client's own store routine): body[56..59]
    # medal-earned mask -> R+732, body[68..71] rank points -> R+740, body[131]
    # rank (1..16) -> R+763. The echoed session token sat in all three. The
    # battle result (kind 4) sends NEW TOTALS and the client shows the gain
    # against these, so both come from one store. Selector 2 only.
    if selector == 2 and self_career is not None:
        body = doc_stats.apply_login(body, self_career)

    # 2026-09-23 (sec 4hc): the NOVICE ("Beginner") mark. body[129] = wire+85
    # -> self R+0x2fa, whose bit 0x40 is isNovicePlayer() (MEASURED through the
    # retail converter, an offline run of the client's own code (doc_novice_proof) D). Bit 0x01 of
    # the same byte is the reservation, so the mark is OR-ed in. Selector 2 only.
    if selector == 2 and self_novice:
        body = bytearray(doc_novice.apply_door(body, True))

    # 2026-09-13: the ENLISTED UNIT rides the same self record. setUserData
    # copies src+16..23 = body[60..67] to R+720, the unit id the Unit screens
    # read (doc_unit.py). That is token+32..39 of the echoed session token, so
    # without --units a character's unit was 8 token bytes. Selector 2 only.
    if selector == 2 and self_unit is not None:
        body = doc_unit.apply_login(body, self_unit)

    # 2026-09-13: the EQUIPPED MASK + SUIT. setUserData copies body[76..99]
    # (src+32..55) to R+768..791, which getEquipItems hands the actor: word 0
    # (body[76]) = the MASK (type 7), word 1 (body[80]) = the SUIT (type 8),
    # each honoured only if that id is also in the bag (0x004aa430). body[80]
    # used to echo the request's selected charaid. Selector 2 only.
    if selector == 2 and self_gear is not None:
        if len(body) < 84:
            body += bytes(84 - len(body))
        struct.pack_into("<II", body, 76, self_gear[0] & 0xFFFFFFFF,
                         self_gear[1] & 0xFFFFFFFF)

    # sec 4dr APPEARANCE OFFSET PROBE (2026-09-11). The self-avatar's costume
    # code X is stored at avatar+304+728 = [0x009f3f88] by setUserData 0x00be6580
    # from a field of THIS reply's record; the getter 0x0050ed28 reads it and the
    # o099 builder dresses from it. The exact wire offset of X is derived to
    # ~body+100..104 (record=body-20, X=record+124) but not byte-pinned. Rather
    # than ship a guess into the entry reply, stamp DISTINCT u16 markers across a
    # safe candidate window and read which one lands at [0x009f3f88] in one boot.
    #   * window body[96..112]: PAST the 52-byte session token (body[28..79]),
    #     clear of position/name/spawn (body[28..53]) and the gs endpoint
    #     (body[52..59]), and well below the body[140] array-count that MUST stay
    #     0 (the sec 4bo SE-crash field) -- so no landmine is touched.
    #   * marker at body[N] = base|N, base 0xB000 for selector 2 (the self store
    #     handler 0x00bc8aa0) and 0xC000 for selector 13 (the spawn twin), so the
    #     landed value names BOTH the selector and the offset. e.g. 0xB068 -> the
    #     selector-2 reply, X at body+0x68 = body+104.
    # OFF by default; a proven-inert diagnostic, like --chara-chrcode.
    if self_probe and selector in (2, WORLD_SPAWN_SELECTOR_ANS) and len(body) >= 114:
        _pbase = 0xB000 if selector == 2 else 0xC000
        for _po in range(96, 113, 2):
            struct.pack_into("<H", body, _po, _pbase | _po)

    # sec 4dr FIX (CORRECTED 2026-09-11 by a proper differential): the VISIBLE
    # costume X is the low u16 of the avatar's costume word [actor+0x444], and
    # that word is sourced from **body+96** of the selector-2 reply -- NOT body+100.
    # MEASURED across savestates: female-probe [actor+0x444]=0xb062b060 (low u16
    # 0xb060 = the body+96 marker, bit6=female, bits3-5=armor 4 = the "weird
    # armor"); default 0xc6190000 (low u16 0x0000 = the echoed request body+96..99
    # `00 00 19 c6`); the 0x0040 test written to body+100 landed in the GETTER word
    # [0x009f3f88] but never touched [actor+0x444], so the avatar never changed.
    # So write X at body+96. Also mirror it to body+100 (the getuserdata getter's
    # own copy) in case a downstream reader wants it; harmless. Selector 2 only.
    # body+96 is past the token (body[28..79]) and below the body[140] count.
    if self_costume is not None and selector == 2 and len(body) >= 114:
        # sec 4dr (RE-CORRECTED 2026-09-11, MEASURED off the render object itself):
        # the earlier "body+96 / body+98+102" pins were BOTH wrong. The render
        # object is a fixed heap alloc at 0x01374b80 (found by its +0x440 signature
        # word 0x6440f000 -- it IS savestate-pinnable, refuting the handoff), and
        # its costume word [render_obj+0x444] = repack(X) where X is the compact
        # code the getuserdata getter [0x009f3f88] returns. PROVEN by the probe
        # savestate doc_x_slot03: the getter word landed 0xb064 (= the body+100
        # marker, base 0xB000|0x64), the self actor 0x002b36e0+552 also read 0xb064,
        # and render_obj+0x444 = 0x00001003 = repack(0xb064) EXACTLY. So the value
        # the avatar dresses from rides **body+100** (u16), and repack(R) on the
        # client reproduces the creation preview (repack(0x1012)=0x00080806=Lex).
        #
        # ONE catch the single-offset tests missed: writing body+100 ALONE updated
        # the getter word but did NOT re-dress the model (doc_x_slot07: getter=0x0040
        # yet render stayed at the stale repack(0)=0x02). The full-window probe
        # (body[96..112] all set) is the only config that re-dressed. So the value
        # carrier is body+100, and a re-dress TRIGGER lives elsewhere in body[96..112].
        # We therefore replicate the proven-to-render probe with the REAL value:
        # write R across the whole even window 96..112. This is exactly the write
        # that produced female+armor live; entry succeeded with it, so the window
        # is safe (past the token body[28..79], clear of position/spawn/gs, below
        # the body[140] SE-crash count). body+100 carries the value the getter reads;
        # the surrounding bytes fire the re-dress.
        for _co in range(96, 113, 2):
            struct.pack_into("<H", body, _co, self_costume & 0xFFFF)
        # WARNING: sec 4gt (2026-09-22, MEASURED on the NEW build, savestates 06/07):
        # body[104] IS NOT FREE WINDOW -- it is wire+60 of setUserData's record
        # (base body[44], calibrated twice: wire+4 -> R+752 the HP, wire+8 ->
        # R+744 the gil), and the converter 0x00bebb1c does
        # `lhu v0,60(s2); sh v0,756(s1)`, so it lands on R+756 -- THE VALUE
        # getMyReservationTableId() RETURNS. The chain, every link disassembled:
        # getter 0x00aed9a8 -> key [kelsvc+272] (0x00be1348) -> self lookup
        # 0x00bda390 -> 0x00be3768 -> search 0x00be3660 (gate: [selfrec+92]&1,
        # then [selfrec+52]==charaid -- both already correct, it HITS) -> copier
        # 0x00bebce0 `lhu a2,756(a0); sh a2,64(a1)` -> the getter returns
        # scratch+64. The console caches it at [console+72]+956 and the gate
        # (0x00aa0620) allows Create only when it == 0xffff.
        # So the costume code was read back as a RESERVATION at a battletable
        # whose id IS the costume: Lex 0x1012 -> table 4114, Malk 0x2000 ->
        # table 8192 (measured [selfrec+756]=0x2000 against a live log's
        # "CONFIG of unknown table 8192"). Battle Entry then opens with a
        # phantom "Confirm Reserved Battletable" row, and NOTHING clears it --
        # the console re-snapshots from the getter on every init, so an in-game
        # Cancel does not survive re-entry and the player can never reach
        # Create. 0xffff = no reservation. The re-dress trigger keeps the other
        # seven slots of the window.
        struct.pack_into("<H", body, 104, 0xFFFF)

    # KEY: 2026-09-13: THE SELF NAME. setUserData's record starts at body[44] and
    # is the 96-byte CHARACTER record (0x0058ab88 = the roster scatter: src+0 ->
    # dst+32, src+4 -> dst+48 = R+752 the HP, src+56 -> R+728 the costume);
    # record+68..83 = body[112..127] is the NAME, copied to R+704..719. The own
    # table's owner and the own team entry resolve the SELF id through R, not the
    # user list -- and R+704 read `12 10 00..` in a live briefing-room
    # savestate: zeros, plus the costume window's last halfword at body[112].
    # Written AFTER the costume window (its value carrier is body[100]).
    if self_name and selector == 2 and len(body) >= 128:
        _nb = self_name.encode("ascii", "ignore")[:15]
        body[112:128] = _nb + bytes(16 - len(_nb))

    mid = bytearray(16)
    mid[0] = ptype & 0xFF
    mid[1] = 0x00
    struct.pack_into("<H", mid, 6, seq & 0xFFFF)
    # mid[8..11] is `record+4`.  Every jump-table arm (selectors 13, 21, 23, ...)
    # gates on `[record+4] == [kelsvc+272]` and drops the message silently when it
    # differs -- so for those, ECHO the value out of the request, which the client
    # itself filled from [kelsvc+272] (builder 0x00bdb190, `sw v1, 4(a1)`).  The
    # selector-2 world door never reads it, so that rung keeps the lobby-IP value
    # it has been proven live with.
    if ident is not None:
        struct.pack_into("<I", mid, 8, ident & 0xFFFFFFFF)
    elif inner_ip:
        o = [int(x) for x in inner_ip.split(".")]
        struct.pack_into("<I", mid, 8, (o[3] << 24) | (o[2] << 16) | (o[1] << 8) | o[0])

    pkt = bytearray()
    pkt += bytes([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", HDR_LEN + len(body))
    pkt += struct.pack("<I", now_ms() & 0xFFFF)
    pkt += mid
    pkt += body
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
    return bytes(pkt)


LOBBY_CMD_PLAYTIME = 20        # the Status screen's PLAY TIME (doc_playtime.py)
LOBBY_CMD_CLOCK = LOBBY_CMD_PLAYTIME   # sec 4dc's name for it; the proofs import it


def lobby_clock_value(mode):
    """A FIXED value for command 20's answer body[16], or None.

    WARNING:KEY: 2026-09-13: command 20 is the character's PLAY TIME, not a clock.
    sec 4dc read it as the server clock and served Unix seconds, but the one
    consumer of [kelsvc+256] is the Status window: lobby phase 65 -> vt+1024
    (0x00bd5bc8, whose only caller is 0x00ad48b0) writes lobby mgr+300, and
    0x00ac9e48 / 0x00ac9f58 print that as "PLAY TIME %d:%02d:%02d" (KelStr
    0x7c10). Unix seconds rendered as ~496,000 hours. The default is now
    `--lobby-clock play`, served per character by doc_playtime.PlayTime; this
    function covers only the fixed modes: 'unix' (the old value), an INTEGER,
    and 'off' / 'play' (None here).

    The mechanism below (sec 4db/4dc) is unchanged and right. The sender only fires while the answer slot is empty (`0x00bd5b20`):

        v0 = [kelsvc+256]
        bnel v0, zero -> skip          ; ask ONLY while +256 == 0
        a2 = 20 ; call [conn_vt+116]

    and its arm stores the pair (`0x00bc9318`, sec 4db -- mind the delay slot):

        [kelsvc+256]  = body[16]       ; the value
        [kelsvc+1060] = body[16]
        [kelsvc+260]  = 0x003bba18()   ; the local tick it arrived

    then the consumer `0x00bd5bf0` extrapolates:

        v1 = [kelsvc+256]
        v0 = (now() - [kelsvc+260]) / 1000     ; ms -> SECONDS
        v1 = v1 + v0
        *out = v1 ; return 1

    So body[16] is SECONDS, cached once per login and advanced locally -- and
    must never be 0: a 0 leaves the slot empty, the client asks again, and the
    poll never fills mgr+300.
    """
    if mode in (None, "", "off", "play"):
        return None
    if mode == "unix":
        return int(time.time()) & 0xFFFFFFFF
    return int(mode, 0) & 0xFFFFFFFF


LOBBY_CMD_SELECTOR_REQ = 240   # "Command"        -- the client's own action
LOBBY_CMD_SELECTOR_ANS = 241   # "Command Result"  -- ours, handler 0x00bc9210


def lobby_cmd_id(data, inner):
    """The COMMAND ID a selector-240 request is issuing, or None.

    Selector 240 is the most-requested message on the wire (10-14 x per world
    session) and it is what the account holder sees as *"go to lobby, get bounced
    back to the briefing room"*.  We have always answered it -- 10 requests, 10
    answers -- with `build_world_answer(selector=241)`, and that answer could
    never dispatch.

    The handler `0x00bc9210` ends in a 39-way jump:

        sub = (u16)[body+12]
        if ((u32)(sub - 3) >= 39) goto bail          ; 0x00bc9274
        jump [0x00bf3020 + (sub-3)*4]                ; 25 of 39 arms are real

    and `build_world_answer` packs its `result` word at exactly body[12..15].
    `result` defaults to 0, `(u32)(0 - 3)` is 0xfffffffd, so every answer we have
    ever sent bailed at 0x00bc9274 -- unconditionally, whatever the state gate
    did.  WARNING: This is the sec 4bw collision a second time: one body offset carrying
    two unrelated meanings on two different rungs.  On selector 13 body[12] IS
    the result (0x00bca868 reads it as one); on selector 241 it is the command id.

    KEY: The command id is at body[12] IN THE REQUEST TOO, and the request's own
    builder says so.  `0x00589c48`:

        s0 = a2 & 0xff                      ; the command id, ONE BYTE
        call [conn_vt+108], a2 = 240        ; 240 is the message KIND
        [buf+18] += 16                      ; the body grows 16
        [buf+32] = (u8) s0                  ; <- the command id
        if (a3) { [buf+36..43] = *(u64*)a3 ; [buf+44] = *(u32*)(a3+8) }
        else    { [buf+36] = 0 }            ; a 12-byte argument, or nothing

    Only ONE byte is written at buf+32, and buf+33..35 are never written at all --
    which is exactly what the capture shows (`04 ea 6e 00`, `0d 27 3b 00`,
    `19 0d fd c4`: a sane id followed by stale RAM).  That stale tail is the proof
    the field is a byte rather than a word, and it is why the id must be re-packed
    rather than echoed as four bytes: the handler reads a HALFWORD, so body[13]
    has to be zero or the sub-type is 0xea04 instead of 4.

    MEASURED over all 324 selector-240 requests in /logs/doc-rx, body[12] is:

        4 x183   6 x9   7 x6   13 x5   20 x109   24 x6   25 x5   29 x1

    Every one of the eight distinct values is inside the handler's own [3, 41]
    window, and 13/20/24/25/29 hit REAL arms (4, 6 and 7 take the shared bail).
    A byte that was noise would not land inside a 39-wide window 324 times out of
    324; a byte that is the command id is the only thing that would.

    WARNING: WHAT THIS DOES NOT ESTABLISH.  That echoing the id is the whole answer.  It
    makes the arm RUN, which it never has -- `Command Result %d` (0x00bf3008, and
    sec 4cz measured that only sub 28's arm materialises it) has never appeared in
    an emulog.  The arms also read the 12-byte argument at body[16..27], which we
    echo because we cannot yet derive a result; that is a first move, not a
    decoded reply format, and it is the same "zeros satisfy one field" caveat
    sec 4bo carries.
    """
    plain = inner["plain"] if inner is not None else None
    buf = plain if plain is not None else (data if data[1] != 1 else None)
    if buf is None or len(buf) < BODY_OFF + 13:
        return None
    if buf[BODY_OFF + 1] != LOBBY_CMD_SELECTOR_REQ:
        return None
    return buf[BODY_OFF + 12]


PEER_REC_LEN = 56         # the selector-37 record, body[12..67]
WORLD_SPAWN_SELECTOR_ANS = 13  # phase 30's answer -- and it carries the SPAWN

# The lobby spawn descriptor, proven by running the client's own parser + demux +
# arm over a marked body (an offline run of the client's own code (doc_spawn_body_proof), sec 4dh).  Selector
# 13's arm 0x00bca868 reads these BODY offsets and stores a 28-byte descriptor to
# [0x009f3b80 + 3232], which is what `KerberosNetLobby.getLobbyInitPos()` returns
# to the zone script.  We have always shipped this region as zeros, and that is
# the p(0,0,0) spawn.
SPAWN_OFF_X     = 28      # float32 LE
SPAWN_OFF_Y     = 32
SPAWN_OFF_Z     = 36
SPAWN_OFF_DIR_X = 40
SPAWN_OFF_DIR_Y = 44
SPAWN_OFF_DIR_Z = 48
SPAWN_OFF_INDEX = 52      # two BYTE stores: body[52] low, body[53] high

# KEY: THE MAP-PICKER MASK -- the same selector-13 answer, eight bytes further on.
# (sec 4gv, 2026-09-22.  an offline run of the client's own code (doc_mapmask_proof) re-derives every address
# below out of whatever image you hand it and REFUSES on one it cannot pin.)
#
# The battletable config screen's `Map` row built an EMPTY list for ten days
# while every other row on the same screen worked.  It is not the row, not the
# label, not a request we failed to answer -- opening it sends nothing.  The
# picker's populate function takes its candidates from a 28-entry roster of
# {label msgid, help msgid} records, and for THE MAP ROW ONLY it first asks the
# lobby service for a 64-bit "which maps may this player pick" bitmask:
#
#     if (row.kind == 1)  mask = lobby_service.get_map_mask()   # 8 bytes
#     else                mask = ff ff ff ff ff ff ff ff        # all allowed
#     for (i = 0; roster[i].label; i++)
#         if (i < 64 && (mask[i >> 5] & (1 << (i & 31))))
#             add_row(roster[i])                     # ...otherwise SKIPPED
#
# so a zero mask builds a list with zero rows, and it can only ever affect the
# Map row.  That is exactly the shape seen on a console.
#
# `get_map_mask` returns two words out of the lobby service object (US Viewer
# build: +1668/+1672 of [0x00bf0228]; JP rig: the same two offsets of
# [0x00bf2f88] -- the OFFSETS are stable across builds, the addresses are not),
# and the ONLY writer of those two words is the arm for lobby message 13 --
# this answer.  It copies them straight off the wire at record+92/record+96,
# and record == body + 20, which is cross-checked here by the seven spawn
# fields above: the same arm reads record+48..+73 and those are SPAWN_OFF_X ..
# SPAWN_OFF_INDEX+1 exactly.  So:
LOBBY_MAP_MASK_OFF = 72   # u32 lo at body[72], u32 hi at body[76]

# The roster, in the order the picker walks it -- this IS the index space, and
# it is the same index the battletable record's map byte (BT_OFF_MAP) uses.
# Read out of the client's own table (help id 0x682d, "Selects the map to use
# in this battle."); the config screen's copy carries the size class in the
# label, the browser's copy does not, and both tables are 28 entries in the
# same order.
LOBBY_MAP_NAMES = (
    "Jungle (S-M)", "Deepground (M)", "Kalm (M)", "Wastelands (M)",
    "Sewers (S-M)", "Laboratory (S)", "Training Grounds (L)", "Church (S-M)",
    "Train Graveyard (S)", "Shinra Building (S-M)", "Mako Reactor (S-M)",
    "<KelStr hole>", "Deepground 2", "Test Area (M)", "Warehouse (M)",
    "Bridge (M)", "Shinra Manor (M)", "Base 1 (M)", "Base 2 (M)", "Base 3 (M)",
    "Huge Facility (L)", "Battlefield Ruins (L)", "Canyon (L)",
    "Great Fault (L)", "Desert (L)", "Plateau (L)", "Wreckage (L)",
    "Rooftop (L)")

# WARNING: Index 11 is msgid 0x706c and 0x706c is a HOLE in group 28 -- SE's OWN hole,
# not ours: the disc's lobby.bin has 魔晄炉 there, and SE's patch 20060124_3
# blanked 0x706c/0x706d while renaming 0x706a DG1 -> 魔晄炉前.  The client's
# roster still lists it, so setting bit 11 puts a literal `!!na!!` row in the
# picker.  Leave it clear unless you are deliberately testing that.
LOBBY_MAP_HOLES = (11,)
# 2026-09-23 (design decision): hide the picker maps no shipped zone backs -- 13 Test
# Area (its オンラインテストマップ z200 exists only in the prototype install,
# bzd034) and 17/18/19 Base 1-3 (no base zone ships). A table on one of them
# played in the Jungle. Name them in --lobby-map-mask to show them again.
LOBBY_MAP_HIDDEN = (13, 17, 18, 19)
LOBBY_MAP_MASK_ALL = ((1 << len(LOBBY_MAP_NAMES)) - 1) & ~sum(
    1 << i for i in LOBBY_MAP_HOLES + LOBBY_MAP_HIDDEN)

# Set from --lobby-map-mask at startup.  Module-level so that EVERY path that
# answers selector 13 carries it, not just the one that happens to pass a spawn.
LOBBY_MAP_MASK = LOBBY_MAP_MASK_ALL

# KEY: THE LOBBY ZONE (sec 4hg addendum 4, 2026-09-23).  The world-door answer
# (selector 1 -> 2) is parsed by 0x00bd0310 (lobby-service iface virtual 6,
# reached from the phase machine 0x00bd37d8 at phase 1): record+0x1e ->
# u16 [mgr+0xd94] and mgr+0xe30 |= 0x200.  MEASURED by delivering a marked
# body to the retail client with the service at phase 1: the halfword that
# lands there is body[42..43] (an offline run of the client's own code (doc_lobbyzone_proof)).  We used to
# echo the client's 52-byte session token here, so the field held two key
# bytes (122 live) and z217's lobby-entry fallback -- the route the intro's
# return always takes, because the exit teardown unloads the loader -- loaded
# a zone the install does not have and the zone thread died on the null
# lighting table.  Holding the field at 217 over PINE landed the player.
LOBBY_ZONE = 217
LOBBY_ZONE_OFF = 42

# KEY: THE ARENA ZONE EACH ROSTER MAP IS PLAYED IN (sec 4hb, 2026-09-23).
#
# The picker works, and the chosen map REACHES US -- yet every battle started
# in the Jungle. A live log:
#
#     CREATE -> table 1 (map 9, mode 1, max 12) for 0x0004103c
#     CREATE -> table 2 (map 7, mode 1 [coerced 0->1], max 6) for 0x00041050
#     [gs] sec 4ft: kind 2 serves arena zone 201 map (0, 0)
#
# ...and then we threw the map away.  The record's map byte is DISPLAY ONLY on
# the client -- its one reader is the browser row renderer (sec 4gr.5).  What
# LOADS an arena is notify kind 2's zone byte (rec+26 -> [chan+1064] ->
# get_onlinezone -> KerberosZone.exit(zone)), and that byte was the constant
# --gs-battle-zone.  So the map -> zone lookup is the SERVER's job; nothing on
# the wire does it for us, and this table is that decode.
#
# WARNING: M0/M1 (--gs-battle-map, rec+24/+25) are NOT the map index and must not be
# set from it.  get_onlinezone packs them as exit_l(zonenum, map0, map1), i.e.
# the Zone object's own sub-map fields.  PROOF that they do not choose the
# arena: sec 4gr entered z201 (Jungle) and z208 (church) on two live runs, and
# BOTH carried M0,M1 = 0,0 -- one pair of map bytes, two different maps.  The
# zone byte is the whole selector.  M0/M1 stay at their flag value.
#
# THE MAPPING, measured -- not the `201 + index` that sec 4gr inferred.
# * The client's map roster is 28 records of {label msgid, help msgid, ordinal}
#   (0x00b1231c browser / 0x00b1aaa8 config in a current retail build;
#   0x00afc68c on the old JP rig -- WARNING: addresses are per-image, the roster was
#   re-found structurally in each).  Its third word is just index + 8 and names
#   no zone, so the client cannot tell us.
# * The title's own `data/zone/zonelist.txt` names every zone, and SE prefixed
#   the arenas "マルチ・" (multi-).  Matching the roster's JAPANESE labels
#   (group 28 of RETAIL lobby.bin, doc_patch_20060124_3 -- the English strings
#   are our own port and the two rosters disagree at 14/15) against those:
#
#     idx  roster label   zonelist                     zone  grade
#       0  ジャングル      201 マルチ・ジャングル         201  LIVE (sec 4ft)
#       2  カームの街      203 マルチ・カーム             203  name
#       3  荒野           204 マルチ・荒野               204  name
#       4  下水道         205 マルチ・下水道             205  name
#       7  教会           208 マルチ・カーム教会          208  LIVE (sec 4gr)
#       8  列車墓場       212 マルチ・列車墓場            212  name (exact)
#       9  神羅ビル       213 マルチ・神羅ビル跡          213  name
#      10  魔晄炉前       214 マルチ・魔晄炉前            214  name (exact)
#      12  DG2           216 マルチ・ディープグラウンド２  216  name
#      14  倉庫           209 マルチ・倉庫               209  name (exact)
#      15  ブリッジ       210 マルチ・ブリッジ            210  name (exact)
#      16  神羅屋敷       211 マルチ・神羅屋敷            211  name (exact)
#      20  巨大施設       230 マルチ・巨大施設            230  name (exact)
#      21  戦場跡        231 マルチ・戦場跡              231  name (exact)
#      22  渓谷          232 マルチ・渓谷                232  name (exact)
#      23  大断層        233 マルチ・大断層              233  name (exact)
#      24  砂漠          234 マルチ・砂漠                234  name (exact)
#      25  台地          235 マルチ・台地                235  name (exact)
#      26  残骸          236 マルチ・残骸                236  name (exact)
#      27  屋根          237 マルチ・屋根                237  name (exact)
#
# WARNING: NOT LINEAR.  `zone == 201 + idx` holds for 0..7 and then breaks: the
# roster lists 列車墓場 at 8 while z209 is 倉庫 (roster 14).  The `_qz - 201`
# in the command-41 answer is that same inference; it survives only because
# every --quest-zones default is <= 208.
#
# UNRESOLVED, 8 of 28, deliberately absent -- their labels match no マルチ
# zone, and a guess drops the player into someone else's arena or a stub:
#   1 DG, 5 研究所, 6 大演習場, 11 (SE's own KelStr hole), 13 テスト,
#   17/18/19 基地1/2/3.  Unclaimed arenas: 200, 202, 206, 207, 215, 239.
#   The measurement that would settle them: create a table on each, and read
#   which zone the client asks the patch server for (the patch server logs the fetch), or
#   read its gmap_str name off the loaded zone.
#
# 2026-09-23: 1, 5 and 6 ADDED by the roster ORDER. zonelist.txt runs 201..208
# in roster order (0 Jungle, 2 Kalm, 3 Wastelands, 4 Sewers and 7 Church are
# all decoded and 0/7 live), so the three holes in that run are 202 マルチ・
# ロビー (DG's lobby), 206 マルチ・ＷＲＯ (the lab), 207 マルチ・サバイバル
# (the training ground) -- all three ship full geometry. INFERRED from the run,
# not from a name match: confirm each on screen. Still absent: 11 (the hole),
# 13 テスト (its candidates 200 / 253 are not in the install) and 17/18/19
# 基地1/2/3 (no base zone ships; 215 アスール対策 and 223 lack bzd/gmap).
BT_MAP_ZONES_DEFAULT = ("0:201,1:202,2:203,3:204,4:205,5:206,6:207,7:208,"
                        "8:212,9:213,10:214,"
                        "12:216,14:209,15:210,16:211,20:230,21:231,22:232,"
                        "23:233,24:234,25:235,26:236,27:237")


def parse_map_zones(spec):
    """--battle-map-zones: `IDX:ZONE[,IDX:ZONE...]`, or off/none for an empty
    table.  Returns {roster map index: arena zone}."""
    s = (spec or "").strip().lower()
    if s in ("off", "none"):
        return {}
    if s in ("", "default", "auto"):
        s = BT_MAP_ZONES_DEFAULT
    out = {}
    for part in s.replace(" ", "").split(","):
        if not part:
            continue
        i, sep, z = part.partition(":")
        if not sep:
            raise SystemExit("--battle-map-zones wants IDX:ZONE, got %r" % part)
        i, z = int(i, 0), int(z, 0)
        if not 0 <= i < 64:
            raise SystemExit("--battle-map-zones map index %d is out of range "
                             "(0..63 -- the picker's own bit test)" % i)
        if not 0 < z < 256:
            raise SystemExit("--battle-map-zones zone %d is out of range "
                             "(1..255): kind 2 carries the zone in ONE byte "
                             "(rec+26), and 0 is get_onlinezone's exit(-1) = "
                             "the title" % z)
        out[i] = z
    return out


# WHICH PIECES AN ARENA LOADS ON ARRIVAL (seen live and in a savestate).
#
# The Wastelands drew only the skybox and walking did not bring the terrain
# in; the church's terrain streamed in only once the player walked around.  Slot-4 savestate in z204: m000/model.rfd resident
# (122/128 samples -- a 138-vertex shell spanning +-16,000 = the SKY), m002
# resident, m001 (1.27 MB, the whole terrain, and the piece our spawn stands
# in) ABSENT, 0/128 of its collision.  Kind 2's M0/M1 (rec+24/+25) reach
# get_onlinezone as exit_l(zone, map0, map1), the Zone's own sub-map pair --
# the arena twin of the lobby descriptor `index` that picks the preload piece
# (sec 4dn, live A/B), and SE's ev2045 respawn does Zone.load(201, 1, 3) = the
# Jungle's terrain pieces.  We sent 0,0 everywhere: the church's terrain is
# m002 (streams in on a walk), the Wastelands' is m001 (never does).
# Terrain piece per zone, measured from data/zone/zNNN/m0xx/model.rfd sizes.
# LIVE: z204 at 1,0 draws the Wastelands terrain (M0 IS the piece).
# z201 (Jungle) at 0,0 stayed blank until the player got control (seen live,
# mission 39); its terrain is m001 + m003..m005, and 1,3 is SE's own
# pair -- ev2045.battlefield's respawn does Zone.load(201, 1, 3). LIVE.
# z203 (Kalm) at 0,0 loaded only partially. Kalm spreads
# over m000..m005; the two pieces with the most model vertices within 300 of
# its spawn (-1016.1, 911.1) are m004 (2980) and m001 (802) -> 4,1; the rest
# stream in on movement. z205 (Sewers, unseen) by the same count: m003 (7946),
# m001 (3273) -> 3,1.
# 2026-09-23, every other decoded arena: the two pieces with the most MODEL
# vertices within 300 of its new --zone-spawns point (ZONE_SPAWNS_DEFAULT); a
# second piece under ~2% of the first is left at 0 (m000 loads anyway).
# 2026-09-24: z214 (Mako Reactor) at 1,0 drew textures on the WRONG SURFACES, and the
# software renderer did too. Its savestate: 34 of the 61 slots it uses were never
# uploaded and still held the previous zone's TEX0, the fence and mako_* among them.
# 0,0 was an A/B: the arena went BLACK (terrain piece never loaded), so the pair
# picks the terrain, not the textures. Back to 1,0; the texture fault is open.
ZONE_PIECES_DEFAULT = ("201:1,3;203:4,1;204:1,0;205:3,1;208:2,0;"
                       "202:4,3;206:1,0;207:6,0;209:1,0;210:3,0;211:1,6;"
                       "212:1,0;213:1,4;214:1,0;216:8,0;230:1,2;231:1,0;"
                       "232:1,0;233:1,0;234:1,0;235:1,0;236:1,0;237:1,0")

# The arena SPAWN per zone (kind 2 rec+0/+4/+8, --zone-spawns). 208/203/204/205
# are the sec 4gr.6 points, all visited live (Church "the spawn is good"; Kalm,
# Wastelands, Sewers 09-23). The rest (2026-09-23, never seen): the centre of
# the largest connected FLAT patch of each zone's collision mesh (mapid.rfd,
# up = -y, 40-unit cells, level +-1) whose floor is also VISIBLE (rendered
# model vertices within 8 of that height -- without that test 207/231/237/214
# landed on an invisible catch plane in the sky piece's collision), 2 units
# above the floor. The same picker without the visibility test reproduces the
# live Church point exactly (738.9, -102.0, 1427.0).
ZONE_SPAWNS_DEFAULT = (
    "208:738.9,-102,1427.0;203:-1016.1,-2,911.1;204:-629.7,-8,152.7;"
    "205:-620.9,398,-300.3;"
    "202:1.2,-2.5,-1266.2;206:1.2,-1.9,1.5;207:266.7,-2.0,-497.5;"
    "209:165.8,-2.0,57.9;210:-1625.0,37.2,167.2;211:18.3,81.0,-693.1;"
    "212:100.0,-1.9,0.1;213:-20.5,-1.9,-51.7;214:-459.1,-1.4,-861.1;"
    "216:-104.7,-2.0,574.8;230:474.2,138.0,1420.8;231:-1080.0,-2.0,686.6;"
    "232:-2815.1,602.2,511.5;233:-2723.3,-2.0,-1680.1;"
    "234:-743.7,-2.0,-1138.6;235:264.5,-2.0,-490.1;236:2130.0,-2.0,-1350.0;"
    "237:2264.7,-7.5,730.4")


def parse_zone_pieces(spec):
    """--zone-pieces: `ZONE:M0,M1[;ZONE:M0,M1...]`, or off/none.  Returns
    {arena zone: (map0, map1)} for kind 2's rec+24/+25."""
    s = (spec or "").strip().lower()
    if s in ("off", "none"):
        return {}
    out = {}
    for part in s.replace(" ", "").split(";"):
        if not part:
            continue
        z, sep, mm = part.partition(":")
        m = [int(x, 0) for x in mm.split(",") if x]
        if not sep or not 1 <= len(m) <= 2:
            raise SystemExit("--zone-pieces wants ZONE:M0,M1, got %r" % part)
        m = (m + [0])[:2]
        if not all(0 <= v < 256 for v in m):
            raise SystemExit("--zone-pieces %r: M0/M1 are one byte each" % part)
        out[int(z, 0)] = (m[0], m[1])
    return out


def battle_bmap(zone, zone_pieces, default=(0, 0)):
    """Kind 2's (M0, M1) for arena `zone`: its --zone-pieces entry, else the
    --gs-battle-map default."""
    return tuple(zone_pieces.get(zone, default))


# reasons battle_map_arena can refuse -- named so a test can assert on the
# DECISION and not on the wording of a log line.
ARENA_OK = "ok"
ARENA_NO_ZONE = "no-zone"        # the map has no decoded arena
ARENA_NO_SPAWN = "no-spawn"      # it has one, but nothing would stand on


def battle_map_arena(map_idx, map_zones, default_zone, zone_spawns=(),
                     needs_spawn=True):
    """sec 4hb: (arena zone, why) for a battletable whose record carries
    `map_idx` at BT_OFF_MAP.

    Returns the zone kind 2 should put at rec+26, or `default_zone` when we
    will not follow the map -- `why` is ARENA_OK / ARENA_NO_ZONE /
    ARENA_NO_SPAWN, so the caller decides the wording and a test decides
    nothing.  Pure on purpose: every branch here is reachable from
    doc_udp_test.py with hand-built arguments, including the known-bad ones."""
    z = map_zones.get(map_idx)
    if z is None:
        return default_zone, ARENA_NO_ZONE
    if needs_spawn and z != default_zone and z not in zone_spawns:
        return default_zone, ARENA_NO_SPAWN
    return z, ARENA_OK


def parse_map_mask(spec):
    """--lobby-map-mask: `all`, `none`, a 0x… / decimal mask, or a comma list
    of roster indices.  Returns an int."""
    s = (spec or "").strip().lower()
    if s in ("", "all", "auto"):
        return LOBBY_MAP_MASK_ALL
    if s in ("none", "off"):
        return 0
    if "," in s or s.isdigit() and len(s) <= 2:
        m = 0
        for part in s.split(","):
            part = part.strip()
            if not part:
                continue
            i = int(part, 0)
            if not 0 <= i < 64:
                raise SystemExit("--lobby-map-mask index %d is out of range "
                                 "(0..63)" % i)
            m |= 1 << i
        return m
    return int(s, 0)


def describe_map_mask(mask):
    """The names a mask admits -- so a startup line says what the picker will
    actually show, rather than printing a number nobody can read."""
    out = []
    for i, nm in enumerate(LOBBY_MAP_NAMES):
        if mask & (1 << i):
            out.append("%d:%s" % (i, nm))
    extra = mask >> len(LOBBY_MAP_NAMES)
    if extra:
        out.append("+%d bit(s) past the roster (the client stops at the "
                   "roster's terminator, so they do nothing)"
                   % bin(extra).count("1"))
    return out

# KEY: The getter SUBTRACTS 3.0 from Y (0x0058d2dc, `sub.s`, verified by decode --
# reading it as add.s inverts the whole thing).  So the descriptor's Y is three
# units ABOVE where the player ends up.  Confirmed three ways against measured
# emulog values: descriptors of -3.0 / 0.0 / -1.0 produced actors at -6.0 / -3.0
# / -4.0 in sec 4dd and sec 4df.  --lobby-spawn takes the WORLD position you want
# the player to stand at and this compensation is applied here, once.
SPAWN_Y_BIAS = 3.0

# The room spot sec 4dd measured 18 times as "the correct lobby spot", with the
# facing and index read out of doc_boomerang_slot07's own descriptor.
#
# WARNING: 2026-09-05 (audit): "room" IS THE BRIEFING ROOM, not the lobby.
# (1935.19, -0.052, -42.712) appears VERBATIM in `ev2046_sub.vl_brf2` -- the
# briefing-room script -- as one of sixteen seat positions ringed around
# (1896.8, -1.593).  Every savestate it was measured from was taken with
# selector 38 armed, i.e. with the player parked in that room.  With 38 off the
# zone script runs `vl_main` (the Visual Lobby) and this spot is "the middle of
# nowhere": walkable floor, wrong part of z217.
#
# The lobby's real areas are hard-coded in `vl_main` itself.  Right after it
# reads our descriptor it classifies the position (doc_jclass.py --name ev2046
# --code, bytecode 150..302) and hands the result to quest.handle_event:
#
#     region 0 (EAST wing):    430 < x < 1530   and  -600 < z <  560
#     region 1 (SOUTH wing):  -550 < x <  550   and -1560 < z < -430
#     region 2 (WEST wing):  -1550 < x < -400   and  -600 < z <  560
#     region 3: anywhere else  (the briefing-room spot lands HERE)
#
# and `mm_z217.gmap_exec` places the four map-screen anchors ID_PLACE_0..3 at
# (679.6, -3.4) / (1.7, -632.2) / (-679.8, -6.1) / (-0.9, 632.2) -- one per
# wing, inside those rectangles.  `quest.ev` (the east wing's opening event)
# stands the PLAYER actor at (900, 0, 145) facing +x, so that spot is floor by
# construction; the wing anchors are floor by intent.  Heading is derived from
# the facing vector (0x00507ee8 feeds dirX/dirZ to an atan2), not from `index`.
SPAWN_ROOM = (1935.19, 0.0, -42.712, -0.695, 0.0, 0.719, 11)
SPAWN_PRESETS = {
    "room":  SPAWN_ROOM,                                         # briefing seat
    # index: LIVE 2026-09-05 the east spawn landed exactly (emulog
    # copyMatrixFromActor p(900,0,145)) but the wing did not RENDER -- a void
    # with the interaction debug boxes -- until the player walked across a
    # boundary, at which point the engine streamed z217/m001 + m003. At spawn
    # it had loaded only m000/m013/m011, the same set as at the briefing seat,
    # where index was 11 and m011 IS the briefing room. So `index` is read
    # here as the piece to preload: 1 for the east wing. HYPOTHESIS under
    # test -- if the wing renders at spawn, it holds.
    "east":  (900.0, 0.0, 145.0, 1.0, 0.0, 0.0, 1),              # quest.ev's spot
    "east-anchor": (679.649, 0.0, -3.434, -1.0, 0.0, 0.0, 1),    # ID_PLACE_0
    "south": (1.729, 0.0, -632.189, 0.0, 0.0, 1.0, 11),          # ID_PLACE_1
    "west":  (-679.842, 0.0, -6.105, 1.0, 0.0, 0.0, 11),         # ID_PLACE_2
    "north": (-0.886, 0.0, 632.181, 0.0, 0.0, -1.0, 11),         # ID_PLACE_3
}

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
    if buf is None or len(buf) < BODY_OFF + 20:
        return None
    if buf[BODY_OFF + 1] != PEER_SELECTOR_REQ:
        return None
    return struct.unpack_from("<I", buf, BODY_OFF + 16)[0]


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


def build_gs_stats(entries=(), state=1, seq=0, ident=0):
    """Game-server message 27 -- a REWARD GRANT: (item id, quantity) pairs.

    WARNING: RETRACTED: this was first read as a stat/medal tally, on the strength of
    the Status screen's Medals page appearing right after we started sending it.
    It is not. Sending keys 16/17/18 with 4444/5555/6666 put THREE CHAT LINES on
    the account holder's screen --

        You obtain ??id?? x4444.
        You obtain ??id?? x5555.
        You obtain ??id?? x6666.

    -- which is msgid 0x9c29, `You obtain %s x%d.`, printed once per entry by the
    loop at 0x00ad93f8: `a3 = [array+8+8i]` (the ITEM ID) and `t1 =
    [array+12+8i]` (the QUANTITY), straight out of what this message writes. So
    the KEY is an ITEM ID and the AMOUNT is a quantity.

    WARNING: `??id??` is the string table's OTHER sentinel -- group 0 entry 6, the
    ITEM-name-by-id failure, distinct from `!!na!!` (group 0 entry 0). So 16, 17
    and 18 are not valid item ids. The valid id space is NOT decoded; item names
    live in their own table around 0x01fe4c00-0x01fe61ec, not in KelStr, and
    `--find` does not see them.

    WARNING: And the grant ANNOUNCES without DELIVERING: nothing appeared in the
    items screen. Either the ids have to be real, or the inventory add is a
    separate message.

    The rest below still holds -- the wire format, the destination, and the
    accumulation -- because those were measured rather than inferred.

    This is the only wire path found so far into the LOCAL profile record, the
    object `0x00bdd960` copies from and the Status screen renders. The user-list
    record cannot reach it; this can:

        msg 27 -> 0x00bc1458 -> 0x00bdeef8(userdata, entry)
                             -> 0x00be6b20(userdata + 304, entry)

    and `userdata + 304` IS that record.

    THE BODY, in docudp's body[] terms (record+20.. == wire+24.. == body[0]..):

        body[0..1]     u16  = 27
        body[12]       u8   COUNT, clamped to 6 by the handler
        body[13]       u8   STATE: bit 0 -> [array+0] = 1, bit 1 -> 2, else 0
        body[16+8i]    u32  KEY
        body[20+8i]    u16  AMOUNT
        (stride 8, i < COUNT)

    `0x00be6b20` keeps a tally at `record+868` with its count at `record+800`,
    up to 256 keys: a key already present has the amount ADDED to it, otherwise
    the pair is appended. So amounts ACCUMULATE across messages -- sending the
    same message twice doubles it.

    WARNING: The body must still be >= 13 bytes for the handler to run at all, and a
    COUNT of 0 skips the entry loop entirely while still writing `[array+0]` and
    `[array+4]`. That is what we shipped first, and the Status screen's Rank
    Points went from 0 to -1 -- our own empty tally, observed live.

    WARNING: The KEY SPACE IS NOT DECODED. Which key drives which row is exactly what a
    sweep has to find, and the amounts accumulate, so a sweep is not free.
    """
    n = min(len(entries), 6)
    body = bytearray(16 + 8 * max(n, 6))
    struct.pack_into("<H", body, 0, GS_ARM_MSG)
    body[12] = n
    body[13] = state & 0xFF
    for i, (key, amount) in enumerate(list(entries)[:6]):
        struct.pack_into("<I", body, 16 + 8 * i, key & 0xFFFFFFFF)
        struct.pack_into("<H", body, 20 + 8 * i, amount & 0xFFFF)
    return build_gs_message(GS_ARM_MSG, seq=seq, ident=ident,
                            body_extra=bytes(body[4:]))


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


# --- the GAME SERVER channel, inner type 130 (sec 4cq) ------------------------
GS_INNER_TYPE = 130
GS_MSG_MAX = 61
GS_ARM_MSG = 27           # the only message that sets [chan+204] bit 6
GS_ARM_MIN_BODY = 13      # 0x00bc1458 bails if [msg+18] < 13
GS_KEEPALIVE_MSG = 29     # its table entry IS the shared epilogue -- a true no-op

# --- the GAME SERVER request / answer ladder (sec 4ea) ------------------------
# [chan+2148] is a STATE, not a flag: 0 = closed, 1 = ready, 2 = a request is
# outstanding and [chan+2152] holds its type.  The client's senders (0x00bc5860
# and siblings) build a 32-byte buffer {u8 130, u8 state, u8 4, u32 handle@4,
# u32 0@8, u16 seq@16, u16 12@18, u16 TYPE@20, u16 session@22, u32 0@24,
# u32 arg@28} and 0x00bc03f8 frames it, so on the wire the body is
# {u16 type, u16 session, u32 0, u32 arg}.  The server->client stubs that put
# [chan+2148] back to 1 are the ANSWERS, type + 1:
#
#   31 -> 32   state/team set (arg byte -> [chan+222]); 32 also queues out 5
#   33 -> 34   (34 queues out 6)
#   36 -> 37
#   47 -> 48   leaveBriefingRoom (native 0x00531830 -> netclient bit 0x20000
#              -> 0x0058b6d0 -> sender 0x00bc6d08)
#   56 -> 57   57 also copies a TEAM LIST into [chan+2156]:
#              body[12] u16, body[14] u16 count (<= 8), body[16] u32, then
#              8-byte entries {u16, u16, u32} from body[20]
#   58 -> 59   59 also adds a userdata entry from [chan+1252]/[chan+1256]
#   60 -> 61   61 also stores body's [s5+8] into [obj+352]
#
# Fire-and-forget from the client: 1 = keepalive every 7 s (answer with our
# own 1, the [chan+224] stamp), 26 = the 1 Hz battle report, 44 = "setup
# received" (sent by the kind-4 handler itself), 30/38/45/53/54/62/64/100 unread.
#
# Server pushes ride message 35, the NOTIFY family: body[12..15] u32 KIND
# (0..54, table 0x00bf2c80), kind-specific payload from body[16] (kind 4 reads
# its record at body[20]).  Named kinds: 2 = battle SPAWN (floats), 3 = restart
# pos, 4 = battle SETUP (the rules record; the client replies with 53),
# 5 = battle START (facade bit 0x80: getBattleInitPos becomes readable),
# 22 = Extinct (entity gone), 27 = NPC control change, 31 = add chara,
# 51 = Reset Mission, 52 = ROUND_INTERVAL_END, 53 = NEW_ROUND_START,
# 54 = QUEST_PHASE.  All of this is emulator-read (doc_gs_battle_proof.py);
# none of it has been seen on a screen.
def load_mission_spawns(path=None):
    """2026-09-23: {zone: {controller id: {count, spawn [[x,y,z]..], ...}}}
    from doc_mission_spawns.json: the mission controllers' spawn nodes out of
    the arena files of patch 20060124_3. That is the game's level data and is
    not shipped here; put a table read out of your own copy beside this
    module. {} when absent (the mission NPCs then have no spawn points)."""
    import json
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "doc_mission_spawns.json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


MISSION_SPAWNS = load_mission_spawns()
GS_REVIVE_REQ = 43      # 2026-09-23: the client's ACK of a kind-9 kill notice (not an item)
GS_ITEM_USE_REQ = 21      # 2026-09-23: USE ITEM (item id at body+8) -> message 22
# 2026-09-24: MAGIC CAST. The cast 0x006b87d0 -> shot sender 0x00be9500 sees a
# magic flags word ((flags >> 3) & 7 = element) and calls 0x00bc7928: request
# 60 {u16 60, u16 session, u32 0, u32 arg = element | level << 16}, marked
# outstanding. The answer 61 (handler 0x00bc5358) clears the outstanding flag
# and, when body+4 (status) >= 0, stores body+8 as the self CURRENT MP (R+48 ->
# chara+36 each frame); the cast gate 0x006b7d70 needs chara+36 >= the spell's
# cost. Our old answer was the zero 61 = MP 0 after the first cast, and nothing
# else refills it (only kinds 2 / 51 / 44 / 34 write R+48). Emulated on the
# arena state: zeros -> 100 -> 0, body+8 = 70 -> 70 (an offline run of the client's own code (doc_magic_mp_proof)).
GS_MAGIC_REQ = 60
GS_MAGIC_ANS = 61
GS_REQ_ANSWERS = {31: 32, 33: 34, 36: 37, 47: 48, 56: 57, 58: 59, 60: 61,
                  # sec 4he: 38 -> 39 (arm 0x00bc5174: body[4] >= 0 posts
                  # facade 0x400, ev2045's reload-and-respawn path), 45 -> 46
                  # and 54 -> 55 (0x00bc5214: body[4] < 0 would KICK with an
                  # error; zero is the plain epilogue)
                  38: 39, 45: 46, 54: 55, 46: 47}
# request 46 = a character STATUS-BIT change (engine
# interface vt+68 / vt+76 -> builder 0x00bce5d8). The client marks a request
# outstanding ([chan+2136] = 2) and message 47 (handler 0x00bccd3c) is what sets
# it back to 1. Unanswered, every revive left the channel stuck and the player
# INVINCIBLE (kind 18 and 19 alike).
# sec 4he: the client's REAL request builders are 1, 21, 24, 25, 26, 30, 31,
# 33, 36, 38, 42, 43, 44, 45, 47, 53, 54, 56, 58, 60, 62, 64, 100.
# The "queue reply 4/5/6/9.." names an earlier reading gave 0x00bc31b0 were
# HUD EVENT numbers (it feeds the battle HUD 0x00ad9380, not the wire).
GS_REQ_NAMES = {1: "keepalive", 24: "1 Hz battle report (needs kind 3)",
                26: "req 26 (no caller)", 30: "KILL REPORT {killer, victim}",
                31: "team/state set", 33: "req 33", 36: "req 36",
                38: "P2P respawn / control request (39: body[4] >= 0)",
                42: "req 42", 43: "kill-notice ack (kind 9 arm)",
                44: "item-use counts (kind-4 reply, no answer)",
                45: "leave / exit (46)",
                47: "leaveBriefingRoom", 53: "ack of kind 36",
                54: "kelsvc vt+732 (55: body[4] < 0 = error kick)", 56: "req 56",
                58: "req 58 (item)", 60: "req 60",
                62: "NPC control SET", 64: "NPC control CLEAR", 100: "req 100"}
GS_NOTIFY_MSG = 35
GS_NOTIFY_NAMES = {2: "battle spawn", 3: "restart pos", 4: "battle SETUP",
                   5: "battle START", 22: "extinct", 27: "npc control",
                   31: "add chara", 51: "reset mission", 52: "round interval end",
                   53: "new round start", 54: "quest phase"}
GS_SETUP_LEN = 400        # kind 4 reads up to record+333; a zero record is the
                          # conservative "no rules, no npcs" (0x00bc1760)
GS_LEAVE_BRIEFING = 47
GS_READY_ROSTER_OFF = 132  # selector 38: 28-byte roster entries from body[132]
GS_READY_ROSTER_STRIDE = 28
GS_READY_SESSION_OFF = 36  # selector 38: u16 session id -> [chan+220]
GS_READY_COUNT_OFF = 40    # selector 38: u16 roster count (<= 32)
GS_READY_KIND_OFF = 6      # selector 38: u16; 2 -> [chan+204] = 0x800 + facade 0x4000


def gs_request_type(data, inner):
    """(message type, body) of an inbound type-130 datagram, or (None, None)."""
    body = request_body(data, inner)
    if body is None or len(body) < 2:
        return None, body
    return struct.unpack_from("<H", body, 0)[0], body


def build_gs_notify(kind, payload=b"", seq=0, ident=0, flags=0x01):
    """Message 35 carrying notify KIND at body[12..15] and `payload` from
    body[16].  The dispatcher 0x00bc3918 reads the kind as a u32 at
    datagram+36 (== body[12]) and jumps through 0x00bf2c80 (55 arms)."""
    extra = bytes(8) + struct.pack("<I", kind & 0xFFFFFFFF) + bytes(payload)
    return build_gs_message(GS_NOTIFY_MSG, seq=seq, body_extra=extra,
                            flags=flags, ident=ident)


def build_gs_team_list(entries=(), seq=0, ident=0, word12=0, word16=0):
    """Message 57: the answer to 56, plus the team list its stub copies into
    [chan+2156] -- body[12] u16, body[14] count (clamped to 8), body[16] u32,
    then 8-byte entries {u16 a, u16 b, u32 c} from body[20]."""
    ents = list(entries)[:8]
    extra = bytearray(16 + 8 * len(ents))
    struct.pack_into("<H", extra, 8, word12 & 0xFFFF)
    struct.pack_into("<H", extra, 10, len(ents))
    struct.pack_into("<I", extra, 12, word16 & 0xFFFFFFFF)
    for i, (a_, b_, c_) in enumerate(ents):
        struct.pack_into("<HHI", extra, 16 + 8 * i, a_ & 0xFFFF, b_ & 0xFFFF,
                         c_ & 0xFFFFFFFF)
    return build_gs_message(57, seq=seq, body_extra=bytes(extra), ident=ident)


GS_SPAWN_MAP_OFF = 24     # kind-2 record +24/+25 -> [chan+1092/1093] = map0/map1
GS_SPAWN_ZONE_OFF = 26    # kind-2 record +26 -> [chan+1064] = THE ARENA ZONE
GS_TEAM_NONE = 15         # request-31 args >= this are "no team" (255 = none)


def build_gs_spawn(x, y, z, rot=0.0, seq=0, ident=0, zone=0, bmap=(0, 0)):
    """Notify kind 2: the battle spawn.  0x00bc2800 reads floats at record
    +4/+8 (-> [chan+1072/1076]), +12/+16/+20 (-> [chan+1080..1088]) and bytes
    +24/+25/+26, record == body[20] (the same base kind 4 uses).  Which float
    is which axis is NOT read -- the proof only pins that they land.

    KEY: sec 4ft (static, 2026-09-13): byte +26 IS THE ARENA ZONE NUMBER. The
    arm does `sb rec[26] -> [chan+1064]` and `[chan+204] |= 4`, and the ONLY
    readers are the getters behind KerberosNetLobby.get_onlinezone():
    0x0058d7c8 returns [chan+1064] (zone), 0x0058d558 returns map0/map1 --
    [chan+1092/1093] = rec+24/+25, or once facade 0x80 (kind 5) is up the
    table-record copy [chan+1120/1121]. vl_main runs, after the distribution
    window: leaveBriefingRoom() -> get_onlinezone(false) -> KerberosZone.
    exit(zone), and get_onlinezone turns zone 0 into exit(-1) = THE TITLE.
    That is the sec 4ee/4el "OK -> title": we served zone 0. The only other
    writer of [chan+1064] is notify kind 36 (record +1), which we never send.

    KEY: sec 4ga (static + live PINE, 2026-09-13): the LAYOUT. The arm copies
    rec+0..23 to [chan+1068..1091]; getBattleInitPos = get_battle_pos_{x,y,z}_l
    -> 0x00507e00 -> vt+124 0x0058d308, which returns that block's +0/+4/+8 as
    the POSITION, and get_battle_rot_l (0x00507d90) = atan2(+12, +20), a
    FACING vector. We used to write x,y,z at +12..20 (the facing) and rot at
    +4 (the y). `rot` is in degrees -> facing (sin, 0, cos).
    WARNING: Once facade 0x80 (kind 5) is up the getter reads [chan+1096..] instead,
    a copy of the player's OWN record taken at kind-2 time (live: the
    briefing-room spot 2005.5, -10.5, -118.8) -- so kind 5 must arrive AFTER
    ev2045.battlefield has read the spawn (--gs-battle-go-after)."""
    rec = bytearray(32)
    struct.pack_into("<fff", rec, 0, x, y, z)
    _r = math.radians(rot)
    struct.pack_into("<fff", rec, 12, math.sin(_r), 0.0, math.cos(_r))
    rec[GS_SPAWN_MAP_OFF] = bmap[0] & 0xFF
    rec[GS_SPAWN_MAP_OFF + 1] = bmap[1] & 0xFF
    rec[GS_SPAWN_ZONE_OFF] = zone & 0xFF
    return build_gs_notify(2, bytes(4) + bytes(rec), seq=seq, ident=ident)


GS_DOWN_KIND = 25      # 2026-09-23: "down, respawn point" (retail 0x00bcbfa4)
GS_REVIVE_KIND = 13    # 2026-09-23: the respawn revive (retail 0x00bcbbc4)


def build_gs_down(x, y, z, rot=0.0, bmap=(0, 0), seq=0, ident=0, ammo=()):
    """Notify kind 25: a KO'd character is DOWN and will respawn here.

    Retail arm 0x00bcbfa4, read 2026-09-23 from doc_mission3001_slot06. For the
    receiver's OWN character (ident == [chan+0xd8]) it writes the respawn
    block -- payload[6]/[7] -> [chan+1092/1093] (map0/map1, the same bytes
    kind 2 carries), s16 payload[8..13] -> [chan+1068..1076] (position),
    s16 payload[14..19] -> [chan+1080..1088] (facing) -- then SETS the battle
    object's dead bits 0x2000 and 0x400 (0x00599700), and for every character
    pushes action code 25 (state word entry+0x56 := 2). Kind 13 revives only
    a character whose dead bits are BOTH set, so kind 25 must come first.

    2026-09-26: `ammo` = the RESPAWN REFILL, up to 3 (item, qty). For its own
    character the arm hands payload[20..43] (body[36..], `addiu a1, s1, 24`
    at 0x00bc4258) to 0x00be3200 -> 0x00be7de8: 3 x {u32 id, u16 0, u16 qty},
    a zero id ends it, and each qty is SET into the bag (R+868 entry +6, or
    appended); a change raises R+92 bit 0x200000, which rebuilds the arena
    inventory from the bag and reloads the gun (0x00bf0d70 -> 0x00bebd98).
    Proven by execution (doc_ammo_refill_proof). Our old 20-byte payload
    left it empty, so a death never gave ammo back."""
    _r = math.radians(rot)
    ammo = list(ammo)[:3]
    pay = bytearray(20 + (24 if ammo else 0))
    for i, (iid, qty) in enumerate(ammo):
        struct.pack_into("<IHH", pay, 20 + 8 * i, iid & 0xFFFFFFFF, 0,
                         min(qty, 0xFFFF))
    pay[6] = bmap[0] & 0xFF
    pay[7] = bmap[1] & 0xFF

    def clamp(v):
        return max(-32768, min(32767, int(round(v))))
    struct.pack_into("<hhh", pay, 8, clamp(x), clamp(y), clamp(z))
    struct.pack_into("<hhh", pay, 14, clamp(1000 * math.sin(_r)), 0,
                     clamp(1000 * math.cos(_r)))
    return build_gs_notify(GS_DOWN_KIND, bytes(pay), seq=seq, ident=ident)


def gs_real_ready(teams, members):
    """sec 4ft: (ready, why) for the REAL distribution of a table: at least two
    seated members, every one of them on a team, and both sides occupied."""
    members = [m for m in members if m]
    if len(members) < 2:
        return False, "%d seated member(s), need 2" % len(members)
    missing = [m for m in members if m not in teams]
    if missing:
        return False, "no team yet for %s" % ", ".join("0x%x" % m for m in missing)
    if len({teams[m] for m in members}) < 2:
        return False, "everyone is on team %d -- stand on OPPOSITE teams" \
            % teams[members[0]]
    return True, "all %d seated players are on a team, both sides occupied" \
        % len(members)


def gs_dist_due(g, settle):
    """sec 4fw: when a READY table's real distribution is due (ready_at +
    settle), or None if it is not ready or has already gone out.  Checked on
    the server's clock as well as on request 31: the briefing room sends 31
    only when a player clicks a team, so a settle that ends after the last
    click was never re-checked (live 09-13, table 4)."""
    if g.get("dist"):
        return None
    if g.get("ready_at") is None:
        # 2026-09-23: not ready yet -- wake for the auto-team deadline
        return g.get("auto_at")
    return g["ready_at"] + settle


def gs_auto_teams(teams, members):
    """(teams, assigned) with every seated member that never
    chose a team put on the SMALLER side (ties -> team 0), so a briefing whose
    countdown ran out still gets its distribution. Live: the
    joiner stood on a team space but its client never sent request 31, so
    gs_real_ready said 'no team yet' forever and the countdown ended in
    nothing. Pure: the caller decides when."""
    out = dict(teams)
    count = {0: 0, 1: 0}
    for m in members:
        if m in out:
            count[out[m]] = count.get(out[m], 0) + 1
    assigned = []
    for m in members:
        if m and m not in out:
            t = 0 if count[0] <= count[1] else 1
            out[m] = t
            count[t] += 1
            assigned.append(m)
    return out, assigned


def gs_real_distribution(teams, members):
    """sec 4ft: the kind-20 entries for a REAL table, in seat order: every
    seated member that has chosen a team, slot = its index in THIS LIST.

    Seen live (tables 31/32, "3 joined, only 2 got in-game"): the slot
    is NOT a per-team index. The arm 0x00bc23d8 swaps each id to battle
    roster [chan+2144] entry `slot` (0x00bc254c..0x00bc25b0, then writes the
    id there at 0x00bc2610) and stores the client's own index [chan+16] =
    the entry's LIST position (`sw s1, 16(s2)` at 0x00bc24b0 / 0x00bc2528).
    Both agree only when slot == list position. A per-team slot gave two
    players slot 0 in every two-team table, so the roster and the own index
    disagreed on who is player #N."""
    return [(cid, teams[cid], i) for i, cid in
            enumerate(c for c in members if c and c in teams)]


def bt_start_targets(store, ident, self_cid):
    """sec 4ft (LIVE 2026-09-13): (table key, the OTHER seated members) for a
    leader's Start. The command-3 request carries ident 0 (logged live:
    `ident=0x00000000`), so `table_of(0)` found nothing and the fan-out never
    ran -- fall back to the session's learned charid."""
    lead = ident or self_cid
    key = store.table_of(lead) if lead else None
    if key is None:
        return None, lead, []
    return key, lead, [m for m in store.members(key) if m and m != lead]


def gs_solo_distribution(teams, self_cid):
    """sec 4fv: the kind-20 entries for a SOLO leader's briefing room:
    the player first (team 0 if request 31 never told us one), then every
    other id we seated there (the --gs-fake-teammates bots), slot = index
    within the team.  The distribution is what opens vl_main's door to
    leaveBriefingRoom -> KerberosZone.exit(get_onlinezone(false)); a solo
    table never satisfies gs_real_ready, so without this it never fires."""
    t = dict(teams)
    t.setdefault(self_cid, 0)
    order = [self_cid] + [c for c in t if c != self_cid]
    return gs_real_distribution(t, order)


GS_KILL_EVENT = 9         # notify kind 9: team points + killer + victim
GS_KILL_REQ = 30          # request 30 {killer @body+8, victim @hdr+8, 0 = self}
GS_RESPAWN_KIND = 13      # notify 13: self respawn, HP = max
GS_RESTART_POS_KIND = 3   # notify 3: restart position + [chan+204] |= 0x20
GS_DAMAGE_GATE_KIND = 30  # notify 30: facade |= 0x30 -- the 113 receive gate
GS_PLAYER_LEFT_KIND = 8   # notify 8: a member left the battle
GS_TEAM_SLOTS = 4         # [chan+1340..1347]: four u16 team point slots


def build_gs_kill_event(points, killer, victim, last_one=False, seq9=0,
                        seq=0, ident=0):
    """Notify kind 9 (arm 0x00bc2010, sec 4he): the SCORE message. Record:
    +0..7 four u16 team points -> [chan+1340..1347] (what getCurrentTeamPoint
    and the HUD's 'Team Ifrit N  Team Shiva N' read), +8 u32 killer, +12 u32
    victim, +16 u8, +17 s8 (HUD event 19 when set), +18 bit 0 = 'one kill from
    the target' (HUD 11), +19 u8 sequence. The arm bumps the local kill /
    death counters by comparing killer / victim with the client's own id."""
    rec = bytearray(24)
    for i in range(GS_TEAM_SLOTS):
        struct.pack_into("<H", rec, 2 * i,
                         max(0, min(int(points[i] if i < len(points) else 0),
                                    0xFFFF)))
    struct.pack_into("<II", rec, 8, killer & 0xFFFFFFFF, victim & 0xFFFFFFFF)
    rec[18] = 1 if last_one else 0
    rec[19] = seq9 & 0xFF
    return build_gs_notify(GS_KILL_EVENT, bytes(4) + bytes(rec), seq=seq,
                           ident=ident)


def mission_npc_report(data):
    """2026-09-23: the 1 Hz report (request 24) read WITHOUT its header.
    [(npc id, hp), ...] or None. The controlling client lists every entity it
    controls: count u8 at datagram[87], then 12-byte entries from datagram+88
    {u32 id, u16 HP, s16 x, s16 y, s16 z} (builder 0x00bc8670 / snapshot
    0x00be1e30; measured live on a 184-byte report, 8 robot dogs at HP 100).
    Recognised by its LENGTH (88 + 12 n): the type word is enciphered on the
    longer reports and this rig's game-server key changes per boot, so the
    header is often unreadable while this part is plaintext."""
    if data is None or len(data) < 88 or data[1] != 4:
        return None
    n = data[87]
    if len(data) != 88 + 12 * n:
        return None
    return [struct.unpack_from("<IH", data, 88 + 12 * k) for k in range(n)]


def gs_kill_report(inner, body):
    """(killer, victim) of a game-server request 30 (sender 0x00bc5660,
    layout 0x0058a3c8, sec 4he): the KILLER is the body's u32 arg at body+8
    (wire+32); the VICTIM rides the inner header's second word, wire+20 =
    inner["u32_20"] (the wrapper 0x00bc57ec substitutes the sender's own id
    for 0, so it is never 0 on the wire). `body` is what gs_request_type()
    returns (wire+24..)."""
    if body is None or len(body) < 12 or inner is None:
        return None
    killer = struct.unpack_from("<I", body, 8)[0]
    victim = inner.get("u32_20", 0) or inner.get("u32_16", 0)
    return killer, victim


class BattleRules(object):
    """What the battletable RECORD says the battle is (sec 4he). Every field
    here used to be a flat command-line knob; the record the LEADER wrote on
    the config screen is the source now, with the knob as the fallback only
    where the record carries nothing."""
    __slots__ = ("mode", "kind", "time_limit", "kill_target", "respawn",
                 "maximum", "situation", "map_idx", "mission", "flags",
                 "random_teams", "briefing", "npc", "ko_limit", "friendly_fire",
                 "restrictions", "base_hp", "capsules")

    def __init__(self, mode="TBT", time_limit=180.0, kill_target=0,
                 respawn=4.0, maximum=0, situation=0, map_idx=0, mission=0,
                 flags=0, kind=0, random_teams=False, briefing=0.0, npc=False,
                 ko_limit=0, friendly_fire=False, restrictions=0, base_hp=0,
                 capsules=0):
        self.mode, self.kind, self.flags = mode, kind, flags
        self.time_limit = float(time_limit)      # seconds; 0 = no clock
        self.kill_target = int(kill_target)
        self.respawn = float(respawn)            # seconds; < 0 = never
        self.maximum, self.situation = int(maximum), int(situation)
        self.map_idx, self.mission = int(map_idx), int(mission)
        self.random_teams, self.briefing, self.npc = bool(random_teams), float(briefing), bool(npc)
        self.ko_limit = int(ko_limit)            # deaths that put a player out
        self.friendly_fire = bool(friendly_fire)
        self.restrictions, self.base_hp, self.capsules = int(restrictions), int(base_hp), int(capsules)

    def __repr__(self):
        return ("BattleRules(%s kind %d, %s, kill target %d, respawn %.0f s, "
                "KO limit %d, max %d, situation %d, map %d, mission %d%s%s%s)"
                % (self.mode, self.kind,
                   ("%.0f s" % self.time_limit) if self.time_limit else "no clock",
                   self.kill_target, self.respawn, self.ko_limit, self.maximum,
                   self.situation, self.map_idx, self.mission,
                   ", random teams" if self.random_teams else "",
                   ", NPCs" if self.npc else "",
                   ", restrictions 0x%02x" % self.restrictions
                   if self.restrictions else ""))


LEADER_TAG = "[L]"              # 2026-09-24: the Team Leader name tag (--leader-tag)


class BattleRoom(object):
    """ONE battle, keyed by its battletable (sec 4he, 2026-09-23).

    Before this every battle timer lived on the SESSION: two players who
    pressed OK seconds apart got two battle ends, the first player's reset
    dissolved the shared table under the second, and the result read the
    bot team map instead of the table's. The room owns the clock, the
    roster, the teams, the tally and the verdict; sessions only deliver.

    Score keeping follows the client (sec 4he): the VICTIM's client reports
    its own death as request 30 {killer, victim}; the server tallies and
    pushes notify kind 9 (four team point slots + killer + victim) to every
    member, which is the only thing that moves the HUD counters. Win / lose
    / draw is the server's verdict in the kind-4 record, never a client
    comparison."""
    __slots__ = ("key", "members", "teams", "rules", "kills", "deaths",
                 "points", "seq9", "arrived", "started", "end_at", "reset_at",
                 "result_sent", "dead_until", "last_death", "over", "why",
                 "mission", "leader", "opened", "left", "damage_seen", "tally",
                 "npc_kills", "npc_hp", "team_leaders", "leader_kills",
                 "first_killer", "finisher",
                 "tally_keys", "field", "holders", "cap_hold", "capsule_winner",
                 "base_hp", "go_at", "go_fired", "go_cap", "gens",
                 "quest_items", "coins", "base_down", "occupy", "occupier",
                 "base_spots", "carrier_kos", "last_ko", "carrier_drop", "last_pick",
                 "cap_last", "last_capsule")

    def __init__(self, key, members, teams, rules, leader=0, mission=None,
                 now=None):
        self.key = key
        self.members = [m for m in members if m]
        self.teams = dict(teams)
        self.rules = rules
        self.leader = leader
        self.mission = mission
        self.kills = {m: 0 for m in self.members}
        self.deaths = {m: 0 for m in self.members}
        self.points = [0] * GS_TEAM_SLOTS
        self.seq9 = 0
        self.arrived = set()        # members whose request 47 has landed
        self.left = set()           # members gone before the end
        self.started = None         # the FIRST 47
        self.end_at = None
        # 2026-09-26: ONE GO for the room. Each client starts its HUD clock
        # at its own kind 5, and every GO went out --gs-battle-go-after s
        # after THAT client's 47 while the room clock ran from the FIRST 47:
        # live table 31 (09-26, 300 s) GOed at +20.0 / +21.6 / +30.4 s and
        # ended 300 s after the first 47 -- "battles end ~30 s early".
        self.go_at = None           # the room's shared GO, pending
        self.go_fired = None        # when it went out: the clock starts here
        self.go_cap = None          # arrivals later than this GO on their own
        self.gens = None            # doc_field.Generators, from the shared GO
        self.quest_items = False    # doc_npcquests.mission_items placed once
        self.reset_at = None
        self.result_sent = set()
        self.dead_until = {}        # victim -> respawn due
        self.last_death = {}        # victim -> time of its last counted death
        self.over = False
        self.why = None
        self.opened = now
        self.damage_seen = 0
        self.tally = None           # doc_stats.record_battle, once, at the end
        self.tally_keys = {}        # member id -> its key in `tally`
        self.npc_kills = 0          # mission: request 30s whose victim is no member
        self.npc_hp = {}            # mission: NPC id -> last HP from the 1 Hz report
        # 2026-09-24: TEAM CAPSULE -- slot -> (item, pos) on the field, who
        # holds how many, the running hold (team, until), the decided team
        self.field = None
        self.holders = {}
        # 2026-09-26: member -> Chocobo Coins picked up (kind 11 +, own drop
        # -); paid 1000 each at the end (doc_stats.coin_gil) and cut from the
        # client's bag (kind 21, ident = itself) before its kind 4
        self.coins = {}
        self.cap_hold = None
        self.capsule_winner = None
        # 2026-09-26: the two TEAM CAPSULE medals (launch build, 60:[47] /
        # [48]). Capsule Seeker: "defeated the most mako capsule carriers and
        # made them drop" -> killer -> carriers KO'd; `last_ko` = victim ->
        # [killer, when, credited] and `carrier_drop` = dropper -> when, so a
        # carrier's 118 DROP and its request 30 pair up in EITHER order
        # within CARRIER_DROP_S, once. Last Capsule: "obtained the last mako
        # capsule" -> the member whose pick-up completed the hold that WON
        # (last_pick -> cap_last -> last_capsule; INFERRED reading).
        self.carrier_kos = {}
        self.last_ko = {}
        self.carrier_drop = {}      # member -> when it dropped a capsule unKO'd
        self.last_pick = None
        self.cap_last = None
        self.last_capsule = None
        self.base_hp = {}           # TEAM BASE: base index -> last reported HP
        # 2026-09-26: TEAM BASE = destroy + OCCUPY (Additional Manual, Jan
        # 2006). A base at HP 0 opens an occupation phase for the team that
        # destroyed it; a member standing on the spot long enough wins it.
        self.base_down = {}         # base index -> the team that must occupy it
        self.occupy = {}            # base index -> (occupier cid, since)
        self.occupier = None        # the member whose hold won the battle
        self.base_spots = None      # (team 0 base, team 1 base) world positions
        # 2026-09-24: TEAM LEADER (mode byte 5, "TLD"). SE's 28:205: "Two
        # teams compete to defeat one another's team leader. Defeating the
        # enemy leader earns points." The client keeps no leader (its
        # isCharacterTeamLeader native is a -1 stub), so the server picks one
        # per team and only a kill of an enemy LEADER scores.
        self.team_leaders = {}      # team -> the member leading it
        self.leader_kills = {m: 0 for m in self.members}
        if self.leader_mode():
            self.pick_leaders()
        # 2026-09-24: the two medals the kill ledger can name (group 60 [41]
        # First Attack "defeats the first enemy", [46] The Finisher "ends a
        # battle or mission") -- the member, or None
        self.first_killer = None
        self.finisher = None

    # ── roster ────────────────────────────────────────────────────────
    def leader_mode(self):
        return self.rules.mode == "TLD" and self.mission is None

    def pick_leaders(self):
        """Each team's leader: the table's own leader leads their team, every
        other team is led by its first seated member. Returns the leaders
        chosen by this call as {team: cid}."""
        new = {}
        for m in [self.leader] + self.members:
            if not m or m not in self.members or m in self.left:
                continue
            t = self.team_of(m)
            if t not in self.team_leaders:
                self.team_leaders[t] = new[t] = m
        return new

    def is_team_leader(self, cid):
        return cid in self.team_leaders.values()

    def team_of(self, cid):
        return self.teams.get(cid, 0)

    def individual(self):
        return self.rules.mode == "BT"

    def slot_of(self, cid):
        """The team point slot a kill by `cid` is credited to (team modes:
        the team, folded into the four HUD slots). In BT every player is its
        own score (kind 9 carries killer / victim points) and the
        slot is only used for the verdict: the player's index."""
        if self.individual():
            return self.members.index(cid) if cid in self.members else 0
        return min(max(self.team_of(cid), 0), GS_TEAM_SLOTS - 1)

    def eliminated(self, cid):
        """Out of the battle: TDM after one death; otherwise at the KO limit."""
        d = self.deaths.get(cid, 0)
        if self.rules.mode == "TDM":
            return d > 0
        return bool(self.rules.ko_limit) and d >= self.rules.ko_limit

    def alive(self):
        return [m for m in self.present() if not self.eliminated(m)]

    def arrive(self, cid, now, go_after=0.0, go_wait=0.0):
        """Request 47 from `cid`. Returns True for the room's first 47.

        go_after 0: the clock starts at the first 47 (no GO to wait for).
        go_after > 0: the room's GO is due go_after s after the LATEST
        arrival, but never later than go_after + go_wait s after the first;
        the clock starts when go() fires it. `joins_go(cid)` says whether
        `cid` rides that shared GO or (arriving after it) gets its own."""
        first = self.started is None
        self.arrived.add(cid)
        if first:
            self.started = now
            if go_after > 0:
                self.go_cap = now + go_after + max(0.0, go_wait)
        if go_after > 0:
            if first or self.joins_go(now, go_after):
                self.go_at = max(self.go_at or 0.0, now + go_after)
            return first
        if first:
            self._start_clock(now)
        return first

    def _start_clock(self, now):
        if self.rules.time_limit > 0:
            self.end_at = now + self.rules.time_limit
        else:
            self.end_at = None          # "Time Limit: None" -- the target ends it

    def joins_go(self, now, go_after):
        """True while an arrival at `now` can still ride the shared GO."""
        return (self.go_fired is None and self.go_cap is not None
                and (self.go_at is None or now < self.go_at)
                and now + go_after <= self.go_cap)

    def go_due(self, now):
        return (self.go_at is not None and self.go_fired is None
                and now >= self.go_at)

    def go(self):
        """The shared GO went out: the room clock starts AT it."""
        self.go_fired = self.go_at
        self.go_at = None
        self._start_clock(self.go_fired)

    def leave(self, cid):
        """`cid` left. Returns {team: new leader} when it led a team in a
        Team Leader battle (the next member of that team takes over)."""
        self.left.add(cid)
        self.arrived.discard(cid)
        self.dead_until.pop(cid, None)
        if self.leader_mode():
            for t, m in list(self.team_leaders.items()):
                if m == cid:
                    del self.team_leaders[t]
            return self.pick_leaders()
        return {}

    def present(self):
        return [m for m in self.members if m not in self.left]

    # ── the tally ─────────────────────────────────────────────────────
    def saw_damage(self, sender, entries, now):
        self.damage_seen += 1

    def kill(self, killer, victim, now, dedupe_s=1.0):
        """A request 30 from `victim`'s client (or from an observer). Returns
        the kind-9 record fields (points, killer, victim, last_one) or None
        when the report is a duplicate / not this room's. Ends the room when
        the kill target is reached."""
        if self.over:
            return None
        if victim not in self.kills:
            # 2026-09-23 (doc_missions): in a MISSION room a death report whose
            # victim is not a seated player can only be an enemy. Whether the
            # client ever sends one is UNPROVEN (its request-30 callers are the
            # character-table HP paths); count it if it does, and let a "kill"
            # mission end on its target.
            if self.mission is not None and killer in self.kills:
                self.npc_kills += 1
                self.kills[killer] += 1
                if self.first_killer is None:
                    self.first_killer = killer
                if doc_missions.npc_kill_ends(self.mission, self.npc_kills):
                    self.over, self.why = True, "%s: %d enemy kill(s)" % (
                        doc_missions.WHY_OBJECTIVE, self.npc_kills)
                    self.finisher = killer
            return None
        last = self.last_death.get(victim)
        if last is not None and now - last < dedupe_s:
            return None
        if victim in self.dead_until and now < self.dead_until[victim]:
            # the client resends an unacknowledged kill
            # report for seconds; while the victim is still down it is the
            # same death, not a second one.
            return None
        self.last_death[victim] = now
        self.deaths[victim] += 1
        if (self.mission is not None
                and doc_missions.ko_out(self.mission, self.deaths[victim])):
            self.over, self.why = True, "%s: %d KO(s)" % (
                doc_missions.WHY_KO, self.deaths[victim])
        credited = (killer in self.kills and killer != victim
                    and (self.individual()
                         or self.team_of(killer) != self.team_of(victim)))
        # 2026-09-24: in Team Leader only the enemy LEADER's death scores
        scored = credited and (not self.leader_mode()
                               or self.team_leaders.get(self.team_of(victim)) == victim)
        if credited:
            self.kills[killer] += 1
            if self.first_killer is None:
                self.first_killer = killer
            self.last_ko[victim] = [killer, now, False]
            dropped = self.carrier_drop.pop(victim, None)
            if (self.holders.get(victim, 0) > 0 or (
                    dropped is not None and now - dropped <= CARRIER_DROP_S)):
                self.credit_carrier_ko(victim)
            if scored and self.leader_mode():
                self.leader_kills[killer] = self.leader_kills.get(killer, 0) + 1
            if scored and not self.individual():
                s = self.slot_of(killer)
                self.points[s] = min(self.points[s] + 1, 0xFFFF)
        if self.rules.respawn >= 0 and not self.eliminated(victim):
            self.dead_until[victim] = now + self.rules.respawn
        else:
            self.dead_until.pop(victim, None)   # out: no respawn pending
        self.seq9 = (self.seq9 + 1) & 0xFF
        target = self.rules.kill_target
        score = (self.kills[killer] if self.individual()
                 else self.points[self.slot_of(killer)]) if scored else 0
        last_one = bool(target and scored and score == target - 1)
        if target and scored and score >= target:
            self.over, self.why = True, "kill target %d reached" % target
        if (self.rules.mode == "TDM" or self.rules.ko_limit) and not self.over:
            # Team Survival / KO Limit: a side with nobody left standing loses;
            # in individual play the last one standing wins
            if self.individual():
                if len(self.present()) >= 2 and len(self.alive()) <= 1:
                    self.over, self.why = True, "last one standing (KO limit)"
            else:
                sides = {self.team_of(m) for m in self.present()}
                up = {self.team_of(m) for m in self.alive()}
                if len(sides) >= 2 and len(up) < len(sides):
                    self.over, self.why = True, ("team wiped out (%s)" % (
                        "survival" if self.rules.mode == "TDM" else "KO limit"))
        if self.over and credited and self.finisher is None:
            # the kill that ENDED it (target reached / side wiped / last one
            # standing); a mission lost to a KO is ended by an enemy -- nobody
            self.finisher = killer
        if self.individual():
            # kind 9 in BT (arm 0x00bc1e10): +0 the KILLER's points, +2 the
            # VICTIM's points -- per player, not four team totals
            pts = [self.kills.get(killer, 0) if credited else 0,
                   self.kills.get(victim, 0), 0, 0]
        else:
            pts = list(self.points)
        return (pts, killer if credited else 0, victim, last_one)

    def credit_carrier_ko(self, victim, now=None, window=None):
        """Capsule Seeker: credit `victim`'s last KO to its killer once -- at
        the KO when it held a capsule, or (now given) when its capsule DROP
        lands within `window` s of that KO. Returns the killer or None."""
        lk = self.last_ko.get(victim)
        if lk is None or lk[2]:
            return None
        if now is not None and now - lk[1] > (CARRIER_DROP_S if window is None
                                              else window):
            return None
        lk[2] = True
        self.carrier_kos[lk[0]] = self.carrier_kos.get(lk[0], 0) + 1
        return lk[0]

    def npc_hp_update(self, entries, player, now):
        """2026-09-23: a mission's enemy deaths from the controlling client's
        1 Hz report (mission_npc_report). An NPC whose HP falls from > 0 to 0
        is a kill for `player`; returns the ids that died this report."""
        died = []
        for nid, hp in entries:
            prev = self.npc_hp.get(nid)
            self.npc_hp[nid] = hp
            if prev is not None and hp != prev:
                # 2026-09-23: the game's DAMAGE SCALE, measured -- no shipped
                # table gives player HP (the server always set it; ours is a
                # placeholder 100), so log every NPC HP change.
                print("  [missions] NPC 0x%x HP %d -> %d (%+d)"
                      % (nid, prev, hp, hp - prev), flush=True)
            if prev and hp == 0 and not self.over:
                self.kill(player, nid, now)
                died.append(nid)
        return died

    def respawns_due(self, now):
        out = [c for c, t in self.dead_until.items() if now >= t]
        for c in out:
            self.dead_until.pop(c, None)
        return out

    # ── the verdict ───────────────────────────────────────────────────
    def base_update(self, reports, occupy=False):
        """The controller's request-24 bases. Returns [(index, hp)] that
        CHANGED (base index i is team i's: kind 29 lists them in order). A
        base that falls from HP > 0 to 0:
          * occupy=False (the old rule): ends the room, won by the other team;
          * occupy=True (2026-09-26, the January manual: "destroy the enemy
            base and occupy it for a set time"): opens the OCCUPATION phase
            for the other team (base_down); base_occupy_tick() decides it."""
        changed = []
        for idx, hp, _mask in reports:
            prev = self.base_hp.get(idx)
            if prev == hp:
                continue
            self.base_hp[idx] = hp
            changed.append((idx, hp))
            if hp == 0 and prev and not self.over and idx in (0, 1):
                if occupy:
                    self.base_down.setdefault(idx, 1 - idx)
                    continue
                self.capsule_winner = 1 - idx
                self.over = True
                self.why = "team %d's base destroyed" % idx
        return changed

    def winner_slot(self):
        """The leading side: a team point slot, or in BT the leading member's
        index. None for a tie / no points. TDM: the side still standing."""
        if self.capsule_winner is not None:
            return self.capsule_winner
        if self.over and self.why and ("wiped" in self.why or "standing" in self.why):
            up = self.alive()
            if self.individual() and len(up) == 1:
                return self.members.index(up[0])
            sides = {self.team_of(m) for m in up}
            if not self.individual() and len(sides) == 1:
                return min(max(sides.pop(), 0), GS_TEAM_SLOTS - 1)
        if self.individual():
            best = max(self.kills.values()) if self.kills else 0
            if best <= 0:
                return None
            lead = [m for m in self.members if self.kills.get(m, 0) == best]
            return self.members.index(lead[0]) if len(lead) == 1 else None
        best = max(self.points)
        if best <= 0:
            return None
        lead = [i for i, p in enumerate(self.points) if p == best]
        return lead[0] if len(lead) == 1 else None

    def winner_cid(self):
        """BT: the winning player, or None."""
        w = self.winner_slot()
        return self.members[w] if (self.individual() and w is not None) else None

    def outcome(self, cid):
        """'w' / 'l' / 'd' for `cid` under the rules. A mission (Solo quest)
        is a win iff the room was ended by its objective, not the clock."""
        if self.mission is not None:
            # 2026-09-23: the mission's own victory / defeat lines (SE's text,
            # doc_missions.OBJECTIVES): KO limit loses, objective wins, and an
            # "as many as possible" mission wins when the clock ends it.
            return doc_missions.verdict(self.mission, self.over, self.why,
                                        self.deaths.get(cid, 0))
        w = self.winner_slot()
        if w is None:
            return "d"
        return "w" if self.slot_of(cid) == w else "l"

    def winner_team(self):
        w = self.winner_slot()
        if w is None:
            return None
        for m in self.members:
            if self.slot_of(m) == w:
                return self.team_of(m)
        return w

    def elapsed(self, now):
        t0 = self.go_fired if self.go_fired is not None else self.started
        return 0.0 if t0 is None else max(0.0, now - t0)

    def summary(self):
        return ("table %d %s: points %s, kills %s, deaths %s, %s"
                % (self.key, self.rules.mode, self.points,
                   {"0x%x" % k: v for k, v in self.kills.items()},
                   {"0x%x" % k: v for k, v in self.deaths.items()},
                   self.why or "running"))


def battle_rules_from_record(rec, default_length=180.0, default_kill=0,
                             default_respawn=4.0, time_unit=1.0):
    """The BattleRules the battletable RECORD asks for. Decoded fields:
    wire+0 flags, +26 mission, +34 situation, +108 window kind, +109 max,
    +110 mode, +111 respawn delay (HUD: record[+57]*1000 + 4000 ms), +113
    map, +116 time limit (HUD countdown = record[+64] * 1000, sec 4he; the
    unit is `time_unit` seconds per count -- see --bt-time-unit). The kill
    target and the rest come from BT_RULE_FIELDS once they are decoded; a
    field that is not decoded keeps the fallback the caller passes."""
    if rec is None or len(rec) < BT_REC_LEN:
        return BattleRules(time_limit=default_length, kill_target=default_kill,
                           respawn=default_respawn)
    flags = struct.unpack_from("<I", rec, BT_OFF_FLAGS)[0]
    mode_b = rec[BT_OFF_MODE]
    kind = rec[BT_OFF_UNK108]
    if flags & BT_FLAG_MISSION:
        mode = "MISSION"
    elif flags & BT_FLAG_INDIVIDUAL:
        mode = "BT"
    else:
        mode = BT_MODE_NAMES.get(mode_b, "TBT")
    kt = struct.unpack_from("<H", rec, BT_OFF_TARGET)[0] or default_kill
    ko = rec[BT_OFF_KO_LIMIT] if flags & BT_FLAG_KO_LIMIT else 0
    tl = struct.unpack_from("<I", rec, BT_OFF_TIME)[0]
    if tl and time_unit > 0:
        time_limit = tl * time_unit
    elif tl == 0 and (kt or ko) and time_unit > 0:
        time_limit = 0.0                # "Time Limit: None": the target ends it
    else:
        time_limit = default_length
    rs = rec[BT_OFF_PENALTY]
    respawn = float(rs) + 4.0 if rs else default_respawn
    if mode == "TDM":
        respawn = -1.0                  # Team Survival: no respawns (0x70c9)
    return BattleRules(mode=mode, time_limit=time_limit, kill_target=kt,
                       respawn=respawn, maximum=rec[BT_OFF_MAX],
                       situation=struct.unpack_from("<H", rec, BT_OFF_SITUATION)[0],
                       map_idx=rec[BT_OFF_MAP],
                       mission=struct.unpack_from("<H", rec, BT_OFF_MISSION)[0],
                       flags=flags, kind=kind,
                       random_teams=bool(flags & BT_FLAG_RANDOM_TEAMS),
                       briefing=float(rec[BT_OFF_BRIEFING]) * 60.0,
                       npc=bool(flags & BT_FLAG_NPC), ko_limit=ko,
                       friendly_fire=bool(flags & BT_FLAG_FRIENDLY_FIRE),
                       restrictions=rec[BT_OFF_RESTRICT],
                       base_hp=struct.unpack_from("<I", rec, BT_OFF_BASE_HP)[0],
                       capsules=rec[BT_OFF_CAPSULES])


#: 2026-09-26: the JOIN / RESERVE result for a joiner whose rank points are
#: outside the table's Min/Max RP. SE's code is NOT located: the client ships
#: the text (KelStr 26:124, 0x687c "Your current ranking points do not fall
#: within the requirements of this battletable.") but no code in the
#: slot-08 image loads that id as an immediate, so which result selects it
#: is unknown. -7 is OURS, a nonzero refusal in the same class as the
#: novice (-5) and unit (-6) gates: the JOIN arm treats any negative as a
#: failure and the client stays unreserved.
BT_REFUSE_RP = -7


def rp_allowed(rec, rp):
    """(ok, why): may a character holding `rp` rank points sit at the table
    whose record is `rec`? source: January 2006 player guide, multiplayer
    page: a table can cap rank points so that mostly beginners meet, and the
    limit is set in the table's own game rules. The record's Maximum RP (wire+60, flags 0x00080000) and Minimum
    RP (wire+64, flags 0x00100000), both inclusive (OURS: the client's
    labels "Above %d RP" / "Below %d RP" do not say)."""
    if rec is None or rp is None or len(rec) < BT_OFF_MIN_RP + 4:
        return True, "no limit"
    flags = struct.unpack_from("<I", rec, BT_OFF_FLAGS)[0]
    rp = int(rp)
    if flags & BT_FLAG_MAX_RP:
        mx = struct.unpack_from("<I", rec, BT_OFF_MAX_RP)[0]
        if rp > mx:
            return False, "%d RP > the table's maximum %d" % (rp, mx)
    if flags & BT_FLAG_MIN_RP:
        mn = struct.unpack_from("<I", rec, BT_OFF_MIN_RP)[0]
        if rp < mn:
            return False, "%d RP < the table's minimum %d" % (rp, mn)
    return True, "within the table's RP limits"


def record_password(rec):
    """The table password the CREATE record carries (flags bit 0, 8 bytes at
    wire+68, 4 chars used), or b"" -- sec 4he: JOIN-with-password (30) and
    RESERVE-with-password (153) compare against THIS; the store used to keep
    b"" for every created table, so every password check passed."""
    if rec is None or len(rec) < BT_OFF_PW_REC + 8:
        return b""
    if not struct.unpack_from("<I", rec, BT_OFF_FLAGS)[0] & BT_FLAG_PASSWORD:
        return b""
    return bytes(rec[BT_OFF_PW_REC:BT_OFF_PW_REC + 8]).rstrip(b"\x00")


def unit_teams(teams, members, unit_of):
    """sec 4he: a UNIT table (flags 0x01000000) is unit vs unit --
    SE's help text 0x70c5: the first two units to reserve own the two sides.
    The client never maps unit -> team (kind 20 applies whatever team byte we
    send), so this is the server's. `unit_of(cid)` -> unit id or 0. Members
    of the first two units seated get team 0 / 1; anyone else keeps the team
    request 31 gave them (or none)."""
    out = dict(teams)
    sides = []
    for m in members:
        u = unit_of(m) if m else 0
        if u and u not in sides and len(sides) < 2:
            sides.append(u)
    for m in members:
        u = unit_of(m) if m else 0
        if u in sides:
            out[m] = sides.index(u)
    return out


def build_gs_team_set(ident, team, slot=0, seq=0):
    """Notify kind 0 = Set Team ID: the entity is the message IDENT (record+4),
    the team is the u16 at body[16]; the arm 0x00bc39bc first looks the entity
    up in the client's battle roster [chan+2144] and bails if absent."""
    return build_gs_notify(0, struct.pack("<H", team & 0xFFFF) + bytes(2),
                           seq=seq, ident=ident)


def build_gs_team_leave(ident, seq=0):
    """Notify kind 1 = the entity (message IDENT) leaves its team: Set Team
    with no new team, so its row counts down. The answer to a leaveTeam (request 33)."""
    return build_gs_notify(1, bytes(4), seq=seq, ident=ident)


def build_gs_add_chara(ident, team, slot=0, seq=0, self_ident=0):
    """Notify kind 31 = add chara: record at body[20]: +0 u32 id, +16 u32,
    +20 u16, +22 byte = TEAM in the HIGH nibble (15 = none -> 0xff) and the
    roster SLOT in the LOW nibble, +23 bit0 -> 0x00bc35a8.  Own id is skipped
    by the arm (0x00bc4514).
    WARNING: the byte is TEAM high, SLOT low; packed the other way round,
    "team 1" writes roster slot 1 over the client's OWN entry. And the arm pre-sets the member's team
    before Set Team runs, so a kind 31 with a team never moves a count: send
    team=None here (0xF) and a kind 0 after it for the team."""
    rec = bytearray(48)
    struct.pack_into("<I", rec, 0, ident & 0xFFFFFFFF)
    t = 0xF if team is None else (team & 0xF)
    rec[22] = (t << 4) | (slot & 0xF)
    return build_gs_notify(31, bytes(4) + bytes(rec), seq=seq, ident=self_ident)


def build_gs_distribution(entries, seq=0, ident=0):
    """Notify kind 20 = the PLAYER DISTRIBUTION ("Player distribution has been
    determined"): u8 count at body[20] (<= 32), then 8-byte entries from
    body[24]: {u32 character id @0, u8 team @4, u8 slot @5}.  The arm
    0x00bc23d8 posts facade 0x1000, calls the team setter 0x00bd4218 for
    every id -- INCLUDING the client's own, which is how the own team and the
    HUD count get set (kinds 31/0 skip self) -- stores own team in [chan+222]
    and own index in [chan+16], and writes every id into the battle roster
    [chan+2144] at its slot.  Team numbering as the client sent in request 31
    (0 = Ifrit); 255 = none."""
    ents = list(entries)[:32]
    payload = bytearray(8 + 8 * len(ents))
    payload[4] = len(ents)
    for i, (cid, team, slot) in enumerate(ents):
        struct.pack_into("<I", payload, 8 + 8 * i, cid & 0xFFFFFFFF)
        payload[8 + 8 * i + 4] = team & 0xFF
        payload[8 + 8 * i + 5] = slot & 0xFF
    return build_gs_notify(20, bytes(payload), seq=seq, ident=ident)


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


def npc_controller_payload(ctrl_id, n=None):
    """2026-09-23: notify kind 28's payload naming NPC controller `ctrl_id`.
    The record rides body[20] (payload = 4 pad bytes + record); rec+3 = 3,
    u16 id at rec+12 -> [chan+1324] (sec 4gs add.1). The ids are the arena
    file's table 28 (bzd directory entry 28, 48-byte records, id at +4):
    read from the live mission savestate doc_mission3000_slot03_20260923 --
    z201 carries 1000..1023 (BT), 1100..1123 (TBT), 3000..3005 (missions),
    9000/9001, 9100..9103, i.e. the SITUATION numbering. We always sent id 0,
    which names no controller, so no mission enemy was ever created."""
    rec = bytearray(64)
    # Seen live (fences, no NPCs): the kind-28 arm (retail 0x00bcc128)
    # reads rec[2] = NPC SLOT COUNT (<= 64) and a 64-bit mask at rec+4
    # (0x00bcaf88: slots < count -> [chan+1304] present, mask bits ->
    # [chan+1316]); rec[3] bit0 copies the controller id at rec+12 ->
    # [chan+1324] (0x00bcaf70), bit1 skips the rec[0] 4-byte entry list
    # (0x00bcabd8). Count 0 loaded the controller's objects and no NPC.
    n = max(0, min(64, CONTROLLER_NPCS.get(ctrl_id, 16) if n is None else n))
    rec[2] = n
    struct.pack_into("<Q", rec, 4, (1 << n) - 1)
    rec[3] = 3
    struct.pack_into("<H", rec, 12, ctrl_id & 0xFFFF)
    return bytes(4) + bytes(rec)


#: NPC count per controller (arena bzd table 28, record +8), z201 as read from
#: doc_mission3000_slot03_20260923.p2s. Unlisted ids use 16.
CONTROLLER_NPCS = {3000: 10, 3001: 8, 3002: 4, 9001: 10,
                   9100: 4, 9101: 4, 9102: 16, 9103: 16}
# 2026-09-24 (static RE, retail + proto; not yet live):
# TEAM BASE battles. A base is an ARENA GIMMICK (bzd table 13, type 5), not a
# server object. It is (1) SUPPRESSED at zone load when the table record's
# Base Durability (wire+16) is 0 (retail 0x0066e440 -> zonemgr+688 bit 3),
# (2) created only when the situation's controller (bzd table 28) lists it --
# every 11xx team situation lists exactly its two bases -- and (3) bound to a
# TEAM by notify kind 29 (arm retail 0x00bcc1bc, fill 0x00bcad68, needs
# [chan+2148] == 1), read ONCE at zone setup (0x004ccd90). We sent kind 29
# with a zero record, so no base was ever bound ("I do not see one", live).
# Kind 29 record at body[20]: +1 count (<= 48), +2 bit0 = 0, 16-byte entries
# from +4 {u16 type (1 = team base), u16 team, u16 gimmick instance, ...}.
# Kind 33 (arm retail 0x00bcc2dc): body[16] = the table index, rec+0 = the
# CONTROLLER's chara id (that client owns the base HP and reports it in
# request 24), rec+4 = HP -> what the HUD shows.
#: arena zone -> the two base gimmick instances its 11xx situations list
#: (team 0's first -- INFERRED order); None = no base in that arena.
# LIVE (Jungle, player on team 0 = Ifrit): with (23, 26) the RED base
# (Ifrit's model) was named "Team Shiva's base" -- the order was backwards.
BASE_GIMMICKS = {201: (26, 23), 204: None}
# 2026-09-24 (static RE, table 14 + the 1100 controllers): every arena's base
# list is ordered [g069, g070] and team 0 (Ifrit) is g070 -- the SECOND entry,
# as Jungle proved live. Arenas whose 1100 controller lists NO base get None
# (Kalm used to bind gimmicks 0 / 1, which are not bases there).
BASE_GIMMICKS.update({z: None for z in (203, 205, 207, 208, 209, 210, 211,
                                        217, 231, 233)})
BASE_GIMMICKS_DEFAULT = (1, 0)

# 2026-09-24: TEAM START POINTS. The client never picks a spawn by team (kind 2
# first spawn, kind 25 respawn, both from the server: ev2045.battlefield
# getBattleInitPos / getBattleRestartPos), so each team's point is ours.
# z201 has two type-8 nodes (table 15) next to the bases -- used as-is. Other
# arenas: the team's OWN base (table 14, via the 1100 controller) moved
# TEAM_START_STEP toward the enemy base, at the base's height (INFERRED; not
# checked against the collision floor).
# THE POSITIONS ARE NOT IN THIS FILE. Both tables are the arenas' own level
# data (the base gimmicks' placement and the type-8 start nodes, read out of
# each zone's arena files), so they ship with nothing here: they are read from
# doc_arena_table.json beside this module when that file exists, shaped
#   {"base_positions": {"ZONE": [[x, y, z], [x, y, z]], ...},
#    "team_starts":    {"ZONE": [[x, y, z], [x, y, z]], ...}}
# (base_positions in (g069, g070) order; team_starts as (team 0, team 1)).
# Without it team_start() answers None (the arena spawn is used) and Team Base
# occupation has no spots.
#: zone -> (g069 base, g070 base) world positions
BASE_POSITIONS = {}
#: zone -> (team 0 start, team 1 start) taken straight from the arena data
TEAM_STARTS = {}
ARENA_TABLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "doc_arena_table.json")


def load_arena_table(path=ARENA_TABLE_PATH):
    """(base positions, team starts) from `path`; ({}, {}) when absent."""
    import json
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return {}, {}

    def pairs(d):
        out = {}
        for z, pts in (d or {}).items():
            try:
                a, b = pts
                out[int(z)] = (tuple(float(v) for v in a),
                               tuple(float(v) for v in b))
            except (TypeError, ValueError):
                continue
        return out
    return pairs(raw.get("base_positions")), pairs(raw.get("team_starts"))


BASE_POSITIONS, TEAM_STARTS = load_arena_table()
TEAM_START_STEP = 150.0


def team_start(zone, team):
    """Team `team`'s start point in arena `zone`, or None (no team data)."""
    if team not in (0, 1):
        return None
    if zone in TEAM_STARTS:
        return TEAM_STARTS[zone][team]
    bp = BASE_POSITIONS.get(zone)
    if bp is None:
        return None
    own, enemy = (bp[1], bp[0]) if team == 0 else (bp[0], bp[1])
    dx, dz = enemy[0] - own[0], enemy[2] - own[2]
    d = (dx * dx + dz * dz) ** 0.5 or 1.0
    step = min(TEAM_START_STEP, d / 3.0)
    return (own[0] + dx / d * step, own[1], own[2] + dz / d * step)
BASE_TYPE_TEAM = 1


def base_gimmicks(zone):
    """The (team 0, team 1) base gimmick instances for arena `zone`, or None."""
    return BASE_GIMMICKS.get(zone, BASE_GIMMICKS_DEFAULT)


def base_objects_payload(gimmicks, teams=(0, 1)):
    """Notify kind 29's payload: one type-1 (team base) entry per gimmick."""
    n = len(gimmicks)
    rec = bytearray(4 + 16 * n)
    rec[1] = n & 0xFF
    for i, (g, team) in enumerate(zip(gimmicks, teams)):
        struct.pack_into("<HHH", rec, 4 + 16 * i, BASE_TYPE_TEAM, team & 0xFFFF,
                         g & 0xFFFF)
    return bytes(4) + bytes(rec)


# LIVE: the controller's request 24 carries the bases, exactly the proto
# builder's layout: count at body+61, then 12-byte entries from body+64 {u32
# HP, u16 index, u16 0, u32 attacker mask}. Jungle: 2 entries, 8000 each; the
# one shot fell 8000 -> 7968 -> 7562 with mask 1 while being hit.
BASE_REPORT_COUNT_OFF, BASE_REPORT_OFF, BASE_REPORT_LEN = 61, 64, 12


def base_report(body):
    """[(index, hp, attacker mask)] from a request-24 body, or []."""
    if body is None or len(body) < BASE_REPORT_OFF:
        return []
    n = body[BASE_REPORT_COUNT_OFF]
    if not 0 < n <= 4 or len(body) < BASE_REPORT_OFF + BASE_REPORT_LEN * n:
        return []
    out = []
    for i in range(n):
        o = BASE_REPORT_OFF + BASE_REPORT_LEN * i
        hp, idx, _z, mask = struct.unpack_from("<IHHI", body, o)
        out.append((idx, hp, mask))
    return out


def base_hp_payload(index, controller, hp):
    """Notify kind 33's payload: table index `index`, its controller, its HP."""
    return (struct.pack("<I", index & 0xFFFFFFFF)
            + struct.pack("<II", controller & 0xFFFFFFFF,
                          max(0, int(hp)) & 0xFFFFFFFF))


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
            out.append((kind, build_gs_notify(kind, bytes.fromhex(hx), seq=seq,
                                              ident=ident)))
        elif kind == 4:
            out.append((kind, build_gs_notify(4, bytes(4) + bytes(GS_SETUP_LEN),
                                              seq=seq, ident=ident)))
        elif kind == 2 and spawn is not None:
            out.append((kind, build_gs_spawn(spawn[0], spawn[1], spawn[2],
                                             seq=seq, ident=ident, zone=zone,
                                             bmap=bmap)))
        else:
            out.append((kind, build_gs_notify(kind, seq=seq, ident=ident)))
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
    off = BODY_OFF
    # KEY: 2026-09-13: the roster lists the OTHER members only. 0x00bcb838 zeroes
    # the 32 x 32-byte roster at [chan+1260] (== [chan+2144], what kind 0's
    # lookup 0x00bc5ee0 searches), copies COUNT-1 entries from body[132] and
    # then writes [kelsvc+272] -- the client itself -- into slot COUNT-1. Self
    # first made the joiner's roster [self, self] (the other player never in
    # it), and every kind-0 team change for them bailed: counts stuck at 0.
    ids = [m for m in members if m and m != ident][:31]
    count = len(ids) + 1
    need = off + GS_READY_ROSTER_OFF + GS_READY_ROSTER_STRIDE * len(ids)
    if len(b) < need:
        b += bytes(need - len(b))
        struct.pack_into("<H", b, 2, len(b))
    if rec is not None:
        b[off + BATTLETABLE_REC_OFF:off + BATTLETABLE_REC_OFF + BT_REC_LEN] = \
            bytes(rec[:BT_REC_LEN]).ljust(BT_REC_LEN, b"\x00")
        gs_id = struct.unpack_from("<H", rec, BT_OFF_ID)[0]
    struct.pack_into("<H", b, off + GS_READY_KIND_OFF, kind & 0xFFFF)
    struct.pack_into("<H", b, off + GS_READY_SESSION_OFF, gs_id & 0xFFFF)
    struct.pack_into("<H", b, off + GS_READY_COUNT_OFF, count)
    for i, cid in enumerate(ids):
        struct.pack_into("<I", b, off + GS_READY_ROSTER_OFF
                         + GS_READY_ROSTER_STRIDE * i, cid & 0xFFFFFFFF)
    b[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    b[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(b))
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
    struct.pack_into("<I", r, BT_OFF_FLAGS,
                     (struct.unpack_from("<I", r, BT_OFF_FLAGS)[0] | flags)
                     & 0xFFFFFFFF)
    struct.pack_into("<H", r, BT_OFF_MISSION, quest & 0xFFFF)
    if situation:
        struct.pack_into("<H", r, BT_OFF_SITUATION, situation & 0xFFFF)
    return bytes(r)


def build_magic_answer(mp, seq=0, ident=0):
    """Message 61 for a request 60: body+4 status 0 (a negative one would deny
    the cast and leave MP alone), body+8 = the new current MP."""
    return build_gs_message(GS_MAGIC_ANS, seq=seq, ident=ident,
                            body_extra=struct.pack("<iI", 0, max(0, int(mp))))


def build_item_use_answer(item, seq=0, ident=0):
    """2026-09-26: message 22 for a request 21 -- body+8 = the item whose
    effect the unit named by `ident` plays (arm 0x00bc503c -> receiveUseItem,
    tools/doc_items.py). body+4 is not read."""
    return build_gs_message(22, seq=seq, ident=ident,
                            body_extra=bytes(4) + struct.pack("<I", item & 0xFFFFFFFF))


GS_MP_KIND = 44


def build_gs_mp_push(mp, full_hp=False, seq=0, ident=0):
    """Notify kind 44 (handler 0x00bc4924): the u32 at body[16] -- HIGH 16 bits
    = the new current MP (always written), low 16 nonzero = also HP to max
    (0x00bdf790, only while HP != 0). Emulated: {90 << 16} MP -> 90, HP kept."""
    return build_gs_notify(GS_MP_KIND,
                           struct.pack("<I", ((max(0, int(mp)) & 0xFFFF) << 16)
                                       | (1 if full_hp else 0)),
                           seq=seq, ident=ident)


def build_gs_message(mtype, seq=0, body_extra=b"", flags=0x01, ident=0,
                     mode_byte=0):
    """One application message on the GAME SERVER channel.

    The channel is 0x009f2b40, its receive handler is 0x00bc4e98, and it is the
    one the item/stat manager feeds from -- `init item number -1` is that
    manager finding the channel unconnected (sec 4cd). CER-48101 is the client
    asking to retry a handshake on it.

    THE FRAMING, measured with an offline run of the client's own code (doc_wire_record_map) rather than read:
    0x0058a0b0 scatters the datagram into a RECORD before 0x00581384 dispatches,
    and the scatter is

        record+16..17  <- wire +14..15   the seq checked against [chan+212]
        record+20..    <- wire +24..     the body, 1:1

    so the u16 message TYPE goes at **body[0]** and the sequence the channel's
    reliable window uses is the FRAMEWORK inner-header seq -- the same field
    every other message here already carries. WARNING: There is no second sequence
    inside the body; an earlier reading of mine put the type at wire+28 and it
    was wrong.

    Proven in an offline run of the client's own code (doc_gsreply_proof): with --gs-connect done first, all
    61 types are ACCEPTED by the client's own handler and all 18 with a real
    handler run. 43 of the 61 share a do-nothing epilogue, so a sweep is safe.

    WARNING: The BODY FORMAT of each message is NOT decoded. This sends the type and
    zeros. That is enough to ask "does any game-server traffic quiet CER-48101",
    which is a different question from "is the payload right".

    WARNING:KEY: CER-48101 IS A 40-SECOND GAME-SERVER TIMEOUT, AND SENDING IS PROBABLY
    NOT ENOUGH TO CLEAR IT (sec 4cq). The client says so itself, one line before
    the error in the emulog: `timeout gameserver 40006`. The check is 0x00bc10d4:

        if ([chan+12] < now_ms() - [chan+224]) -> timeout    ; [chan+12] == 40000

    so `[chan+224]` is a LAST-HEARD stamp, and 0x00bc4e98 refreshes it at
    0x00bc4f40 only after THREE gates:

        (flags & 0x08) == 0  &&  (flags & 0x01) != 0  &&  ([chan+204] & 0x40) != 0

    WARNING:WARNING: Measured offline after a full --gs-connect: **`[chan+204]` is 0**, so the
    third gate fails and NO flags value refreshes the stamp -- the message is
    accepted, dispatched, and the 40 s clock keeps running. That is sec 4cf's
    shape again: the arm accepts and the thing you wanted does not happen.
    0x00bc0260 (what selector 38 reaches) writes [chan+204] = 0 or 0x800, never
    0x40, and nothing in the overlay stores that bit with a literal.

    VERIFIED:KEY: SOLVED -- bit 6 is set by MESSAGE 27 WITH A BODY OF >= 13 BYTES.
    0x00bc1458 (message 27's handler) opens with

        if ([msg+18] < 13) return               ; [msg+18] is the BODY LENGTH
        if (([chan+204] & 0x40) == 0) {
            0x00bc4d90(chan, [msg+16]) ; [chan+204] |= 0x40   ; 0x00bc14bc
        }

    and it is the ONLY site in the whole binary that ORs 0x40 into that field.
    So the full recipe, each step measured in doc_gsreply_proof.py:

        1. --gs-connect            selector 104 + 38  -> endpoint + ready flag
        2. message 27, body >= 13  -> [chan+204] |= 0x40      ARMS the channel
        3. any message thereafter  -> [chan+224] = now_ms()   REFRESHES the stamp

    WARNING: The arming message itself does NOT refresh the stamp: 0x00bc4e98 tests bit
    6 BEFORE dispatching to the handler that sets it, so the first message always
    falls through. It takes two. And without step 2 no number of other messages
    ever refreshes it -- measured: message 42 twice leaves [chan+204] at 0.
    WARNING: A body of 4 (the type alone) fails the length gate silently.
    """
    body = bytearray(4 + len(body_extra))
    struct.pack_into("<H", body, 0, mtype & 0xFFFF)
    body[4:] = body_extra
    mid = bytearray(16)
    mid[0] = GS_INNER_TYPE
    mid[1] = flags & 0xFF
    struct.pack_into("<H", mid, 6, seq & 0xFFFF)
    struct.pack_into("<I", mid, 8, ident & 0xFFFFFFFF)
    pkt = bytearray([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", 0)
    pkt += struct.pack("<I", now_ms() & 0xFFFF)
    pkt += mid + body
    struct.pack_into("<H", pkt, 2, len(pkt))
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
    return bytes(pkt)


USER_SELECTOR_REQ = 10    # the client asking for the user list
USER_SELECTOR_ANS = 11    # request + 1, the arm 0x00bcc9c0 -> 0x00bc9bf0
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

USER_SELECTOR_REQS = (10, 18)


def user_list_wanted_id(data, inner):
    """The id a selector-18 user-list request is ASKING ABOUT, or None.

    sec 4cg, confirmed live: `[kelsvc+268]` is the id the client resolves names
    through, and it is written by our own selector-104 message (body[58..59] ->
    0x00bca9c0). Set it to 1 and the client comes straight back with

        body  07 12 00 00 01 00 00 00 | 00 00 00 00 01 00 00 00
              ^^ subchannel            ^^^^^^^^^^^^ body[12..13] = 1
                 ^^ SELECTOR 18                     = the id WE sent

    i.e. it is asking us to resolve exactly the id we handed it. Answering with
    the player's own uid instead -- which is what we did first -- serves a record
    the client never asked for, so the lookup still fails and the UI still
    renders `!!na!!`.

    WARNING: Only selector 18 is known to carry this. Selector 10's body has the same
    shape but has never been observed with a non-zero value there, so it is read
    but not assumed.
    """
    plain = inner["plain"] if inner is not None else None
    buf = plain if plain is not None else (data if data[1] != 1 else None)
    if buf is None or len(buf) < BODY_OFF + 14:
        return None
    return struct.unpack_from("<H", buf, BODY_OFF + 12)[0]


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
    pkt += struct.pack("<H", HDR_LEN + len(body))
    pkt += struct.pack("<I", now_ms() & 0xFFFF)
    pkt += mid + body
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
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
    pkt += struct.pack("<H", HDR_LEN + len(body))
    pkt += struct.pack("<I", now_ms() & 0xFFFF)
    pkt += mid + body
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
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


# --- the BATTLETABLE CONSOLE VERBS and their STORE (sec 4dz) ------------------
# Read off the lobby phase table (an offline run of the client's own code (doc_phaseflow)) joined with the
# arm map: every console verb is a request phase that sends ONE selector and
# parks [kelsvc+12]; the poll phase after it needs the answer's arm to put the
# state back to 2.  The verbs, by the KelStr group-39 line each phase prints:
#
#   phase 38  sel 24 -> 25  CREATE TABLE      request body[12..131] = the 120-byte
#                           record (0x00bd1688 packs it, key 0); arm 0x00bcb558
#                           (gate 10) reads the answer's record at body[12..131]:
#                           rec+24 -> [kelsvc+268] (the table id), rec+12/+20 ->
#                           the GAME SERVER ip/port via 0x00bc0320, rec+8 leader.
#   phase 36  sel 26 -> 27  TABLE CONFIG      body[12..13] = key; arm 0x00bcb740
#                           (gate 11) converts body[12..131] and copies rec+28
#                           member ids (u32, max 32) from body[132].
#   phase 40  sel 28 -> 29  ADJUST RULES      request carries the record like 24
#                           (0x00bd1808, key at rec+24); arm 0x00bcb7e0 (gate 12).
#   phase 42  sel 22 -> 23  PRE-RESERVE       36-byte, result -> [kelsvc+1064].
#   phase 44  sel 20 -> 21  JOIN (endpoint)   body[12..13] = key; 30 -> 31 is the
#                           same with the password at body[16..23].  On success
#                           phase 45 prints "You have reserved a spot at the
#                           battletable." and sets the phase to 0 -- the lobby
#                           machine ENDS there; what follows is server-driven
#                           (selector 38 / game-server msg 37 = battle ready).
#   phase 46  sel 155 -> 156  CANCEL          arm logs "Cancel %d", clears the
#                           reservation flag itself (0x00be33b0) when result >= 0.
#   phase 48  sel 151 -> 152  RESERVE BY ID   body[12..13] = key; the arm reads
#                           the answer's u16 at body[16] and hands it to
#                           0x00be3348 (sets the reserved flag + table id).
#             sel 153 -> 154  ...with password (body[16..23]); logs "Reserve With
#                           pass %d res %d".
#   phase 50  sel 125 -> 126  DISSOLVE        arm 0x00bcc240: peer lookup, then
#                           [kelsvc+266] = old id, [kelsvc+268] = 0xffff.
#   phase 52  sel 127 -> 128  INVITE          a1 = target character id; arm
#                           0x00bcd4a4 = state 2 + clear pending, nothing else.
#   phases 54/56 KICK / APPOINT LEADER ride the COMMAND channel (240 -> 241,
#                           commands 2 and 1, target id at body[16..19]).
#
# Everything below is proven against the client's own arms in the emulator
# (an offline run of the client's own code (doc_bt_verbs_proof)), NOT on hardware.  The record layout is the
# browser's (BT_OFF_*); rec+12..15 / rec+20..21 are the game-server endpoint
# the create arm hands to 0x00bc0320 (bytes in order / big-endian port, the
# same encoding build_world_answer uses at body[52..57]).
BT_REQ_CREATE = 24
BT_REQ_CONFIG = 26
BT_REQ_UPDATE = 28
BT_REQ_PREPARE = 22
BT_REQ_JOIN = 20
BT_REQ_JOIN_PW = 30
BT_REQ_RESERVE = 151
BT_REQ_RESERVE_PW = 153
BT_REQ_CANCEL = 155
BT_REQ_DISSOLVE = 125
# KEY: 2026-09-23 (retail build, doc_reservation_clear_proof.py): the push that
# actually CLEARS the client's reservation. Demux 0x00bd3978 case 110
# (0x00bd4494): record+4 == [kelsvc+272] -> 0x00be5d58 = R+756 (what
# getMyReservationTableId() returns) = 0xffff, R+0x2fa &= ~1 (the held bit),
# kelsvc+0x10c = 0xffff, and the reserved table's member list emptied. The
# selector-156 CLEAR sent since 09-13/09-22 touches none of that on this build
# (row 51) -- live it was sent twice and the "!!na!!" table stayed.
BT_RESERVATION_CLEAR_SEL = 110
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
#.
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
BT_REQ_INVITE = 127
BT_VERB_REQS = (BT_REQ_CREATE, BT_REQ_CONFIG, BT_REQ_UPDATE, BT_REQ_RESERVE,
                BT_REQ_RESERVE_PW, BT_REQ_CANCEL, BT_REQ_DISSOLVE, BT_REQ_INVITE)
BT_JOIN_REQS = (BT_REQ_JOIN, BT_REQ_JOIN_PW)
BT_OFF_GS_IP = 12          # u32, bytes in address order -> 0x00bc0320 a1
BT_OFF_GS_PORT = 20        # u16 big-endian              -> 0x00bc0320 a2


# ---- the address a client is handed, chosen per client ---------------------
# --lobby-ip / --frag3-servers / the game-server endpoint were ONE address for
# every player. A deployment can have players on several networks (a LAN, a
# VPN, the internet through a forwarding front end) and each can reach only
# one of the server's addresses. The core applies the same rule; it is kept
# local here so this service needs nothing from the core's code:
#
#   0. POL_ADVERTISE_PUBLIC, when set, for a peer with a GLOBAL address (a
#      front end that forwards with the source intact).
#   1. POL_ADVERTISE_LAN, when set, for an RFC1918 peer.
#   2. otherwise, configured address off the LAN and peer RFC1918: the local
#      address the kernel would use to reach that peer.
#   3. otherwise the configured address, exactly as before.
_RFC1918_NETS = tuple(_ipaddress.ip_network(n) for n in
                      ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))  # generic RFC1918 example; polcheck: allow


def _ip_or_none(text):
    try:
        a = _ipaddress.ip_address(text)
    except (ValueError, TypeError):
        return None
    return getattr(a, "ipv4_mapped", None) or a


def _is_rfc1918(a):
    return a is not None and any(a in n for n in _RFC1918_NETS)


def host_for(default, peer_ip):
    """The host to write into a packet for the client at `peer_ip`. Never
    raises; an empty/None `default` stays empty (the caller's "no address")."""
    peer = _ip_or_none(peer_ip)
    if not default or peer is None or peer.is_loopback:
        return default
    public_ip = (os.environ.get("POL_ADVERTISE_PUBLIC") or "").strip()
    if public_ip and peer.is_global:
        return public_ip
    if _is_rfc1918(peer):
        lan_ip = (os.environ.get("POL_ADVERTISE_LAN") or "").strip()
        if lan_ip:
            return lan_ip
        if not _is_rfc1918(_ip_or_none(default)):
            try:
                probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    probe.connect((str(peer), 9))
                    src = probe.getsockname()[0]
                finally:
                    probe.close()
            except OSError:
                return default
            if _is_rfc1918(_ip_or_none(src)):
                return src
    return default


def rec_for(rec, default_gs_ip, peer_ip):
    """A battle-table record as THIS recipient must see it. The store stamps one
    game-server address into every record (BattletableStore._stamp); a table can
    seat a LAN console and an internet player together, so the address is
    rewritten per recipient on the way out. Returns `rec` untouched when there
    is nothing to change."""
    if rec is None or not default_gs_ip:
        return rec
    ip = host_for(default_gs_ip, peer_ip)
    if ip == default_gs_ip or len(rec) < BT_OFF_GS_IP + 4:
        return rec
    out = bytearray(rec)
    out[BT_OFF_GS_IP:BT_OFF_GS_IP + 4] = bytes(int(x) for x in ip.split("."))
    return type(rec)(out) if isinstance(rec, bytes) else out
BT_REQ_REC_OFF = 12        # where 0x00bd1688 / 0x00bd1808 put the record
BT_MEMBERS_OFF = 132       # u32 member ids in a selector-27 answer (a3+156)
BT_MAX_MEMBERS = 32        # 0x00bcb740 clamps the count here
BT_PASSWORD_OFF = 16       # 8 bytes, requests 30 and 153 (0x00bcda28)
LOBBY_CMD_APPOINT = 1      # 0x00bd1c28, phase 56, "%s has been appointed leader"
LOBBY_CMD_KICK = 2         # 0x00bd1cf0, phase 54, "%s has been kicked"
LOBBY_CMD_RETURN = 4       # 0x00bd1fb8: RETURN TO LOBBY (its poll runs the full
                           # reset 0x00bd2a38, selector 39's arm). Live,
                           # a player quit the Wastelands arena with
                           # it and the room ran on for 600 s.
LOBBY_CMD_START = 3        # 0x00bd1db8 (kelsvc vt+604): netclient bit 0x40 =
                           # start_onlinebattle -> the LEADER's "start the
                           # battle" request (sec 4fm). Its 241 result arm is a
                           # no-op; the client then waits for BATTLE READY (38).
LOBBY_CMD_QUEST = 41       # 2026-09-13: FETCH QUEST DETAIL, sent when a Solo
                           # (story mode) quest is picked: phase 125, kelsvc
                           # vt+1428 0x00bd81b0, u16 quest id at request
                           # body[16] (live: 0x11 = quest 17). 241 arm 0x00bc99c4
                           # copies answer body[16..52] into mgr+11708 (unread).
LOBBY_CMD_QUEST_INFO = 29  # 2026-09-13 (static): the Solo detail screen's
                           # TITLE + description come from mgr+1068, filled by
                           # command 29's 241 arm 0x00bc9710: answer body[16]
                           # u16 = quest id (title 0xBBFF+id, desc 0xBFFF+id),
                           # body[20] fee, body[24]/[28] item id/count, body[37]
                           # participant limit. Request 0x00bd7008 (state
                           # machine 0x00ad5024). NEVER seen live (09-13).
QUEST_DETAIL_MAP_OFF = 52  # 2026-09-13 (static): command 41's 241 answer
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
    pkt += struct.pack("<H", HDR_LEN + len(body))
    pkt += struct.pack("<I", now_ms() & 0xFFFF)
    pkt += mid + bytes(body)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
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
    if buf is None or len(buf) < BODY_OFF + 12:
        return None
    return bytes(buf[BODY_OFF:])


class BattletableStore:
    """Every battletable the lobby knows about, keyed by the u16 at rec+24."""

    def __init__(self, records=(), gs_ip=None, gs_port=0, cur_min=0,
                 situation=0):
        self.tables = {}          # key -> dict(rec, members, leader, password)
        self.reservation = {}     # character id -> key
        self.next_key = 1
        self.gs_ip = gs_ip
        self.gs_port = gs_port
        # sec 4ex (2026-09-11): floor for the served CURRENT-participants field
        # (BT_OFF_CUR). The "Start Immediately" gate 0x00aa0d98 passes iff the
        # SERVED browser-list record has [config+2]=BT_OFF_CUR >= 2 (limit live)
        # OR flags bit 0x00010000 (Mission). A solo leader's table has 1 member
        # -> cur 1 -> 0x683b "victory not configured". cur_min=2 clamps the
        # SERVED cur to satisfy the gate (pairs with --gs-fake-teammates for the
        # real battle roster). Does not change reserve/seating logic.
        self.cur_min = cur_min
        # sec 4gc: the battle situation id stamped into a record that left
        # wire +34 at 0 (every client CREATE does) -> mdlResLoad's set.
        self.situation = situation
        # 2026-09-24: {quest: seconds} -- a MISSION record's time limit (the
        # HUD countdown the client reads off the served record), set by main()
        # from doc_missions.MISSION_TIME; `time_unit` = --bt-time-unit
        self.mission_time = {}
        self.time_unit = 1.0
        for r in records:
            self.add_record(r)

    # -- records -------------------------------------------------------------
    def _stamp(self, t):
        rec = t["rec"]
        # a MISSION table passes the start gate on its flag, so it needs no
        # cur_min clamp (a solo quest table read "2/0" with it).
        _floor = (0 if struct.unpack_from("<I", rec, BT_OFF_FLAGS)[0]
                  & BT_FLAG_MISSION else self.cur_min)
        struct.pack_into("<H", rec, BT_OFF_CUR,
                         max(len(t["members"]), _floor) & 0xFFFF)
        struct.pack_into("<I", rec, BT_OFF_LEADER, t["leader"] & 0xFFFFFFFF)
        # sec 4he: wire+30 bit 0 = "In Progress" (the row renderer prints
        # group 28 [80] instead of the count). Set for the life of the
        # table's BattleRoom, never before -- nothing on a live path set it.
        rec[BT_OFF_STATE] = ((rec[BT_OFF_STATE] & ~1)
                             | (1 if t.get("in_progress") else 0)) & 0xFF
        if (struct.unpack_from("<I", rec, BT_OFF_FLAGS)[0] & BT_FLAG_MISSION
                and self.mission_time and self.time_unit > 0):
            _q = struct.unpack_from("<H", rec, BT_OFF_MISSION)[0]
            if _q in self.mission_time:
                struct.pack_into("<I", rec, BT_OFF_TIME,
                                 int(round(self.mission_time[_q] / self.time_unit)))
        if self.situation and not struct.unpack_from("<H", rec,
                                                     BT_OFF_SITUATION)[0]:
            struct.pack_into("<H", rec, BT_OFF_SITUATION,
                             self.situation & 0xFFFF)
        if self.gs_ip:
            rec[BT_OFF_GS_IP:BT_OFF_GS_IP + 4] = bytes(
                int(x) for x in self.gs_ip.split("."))
            struct.pack_into(">H", rec, BT_OFF_GS_PORT, self.gs_port & 0xFFFF)
        return rec

    def add_record(self, rec, members=(), leader=None, password=b""):
        rec = bytearray(bytes(rec[:BT_REC_LEN]).ljust(BT_REC_LEN, b"\x00"))
        key = struct.unpack_from("<H", rec, BT_OFF_ID)[0]
        if key == 0 or key in self.tables:
            while self.next_key in self.tables or self.next_key == 0:
                self.next_key = (self.next_key + 1) & 0xFFFF
            key = self.next_key
            struct.pack_into("<H", rec, BT_OFF_ID, key)
        self.next_key = max(self.next_key, (key + 1) & 0xFFFF) or 1
        if leader is None:
            leader = struct.unpack_from("<I", rec, BT_OFF_LEADER)[0]
        t = dict(rec=rec, members=list(members), leader=leader,
                 password=bytes(password or b""), leader_cid=0,
                 in_progress=False)
        self.tables[key] = t
        self._stamp(t)
        return key

    def records(self):
        return [bytes(self._stamp(t)) for _, t in sorted(self.tables.items())]

    def get(self, key):
        return self.tables.get(key)

    def record(self, key):
        t = self.tables.get(key)
        return bytes(self._stamp(t)) if t else None

    def members(self, key):
        t = self.tables.get(key)
        return list(t["members"]) if t else []

    def table_of(self, ident):
        return self.reservation.get(ident)

    def in_progress(self, key):
        t = self.tables.get(key)
        return bool(t and t.get("in_progress"))

    def set_in_progress(self, key, flag):
        """sec 4he: a table whose BattleRoom is open is In Progress: the
        browser row says so and reserve() refuses new seats (-4)."""
        t = self.tables.get(key)
        if t is None:
            return False
        t["in_progress"] = bool(flag)
        self._stamp(t)
        return True

    def leader_cid(self, key):
        t = self.tables.get(key)
        return (t or {}).get("leader_cid") or 0

    def is_leader(self, key, ident, uid=0):
        """sec 4he: leader authority. The record's leader field is the
        creator's UID (the row resolves a name through the profile cache);
        the creator's CHARACTER id is kept beside it, so a member's own
        Dissolve / Kick / Appoint can be refused by either identity."""
        t = self.tables.get(key)
        if t is None:
            return False
        if not t.get("leader_cid") and not t["leader"]:
            return True                  # a table nobody owns (probe rows)
        if ident and t.get("leader_cid") == ident:
            return True
        return bool(uid and t["leader"] == uid)

    def vacate(self, ident):
        """A session that is GONE (reaped, or a fresh entrance under the same
        id): its seat goes with it. Same as CANCEL, without the answer."""
        return self.cancel(ident)

    # -- verbs ---------------------------------------------------------------
    def create(self, wire_rec, ident, leader_uid, password=b""):
        """Selector 24: the client's own record, keyed by us; the creator is
        its first member and its leader."""
        if self.reservation.get(ident) is not None:
            self.cancel(ident)
        key = self.add_record(wire_rec, members=[ident] if ident else [],
                              leader=leader_uid,
                              password=password or record_password(wire_rec))
        self.tables[key]["leader_cid"] = ident or 0
        if ident:
            self.reservation[ident] = key
        return key

    def update(self, key, wire_rec, ident=None):
        """Selector 28: take the client's rule fields, keep what we own."""
        t = self.tables.get(key)
        if t is None:
            return False
        new = bytearray(bytes(wire_rec[:BT_REC_LEN]).ljust(BT_REC_LEN, b"\x00"))
        keep = bytes(t["rec"])
        new[BT_OFF_LEADER:BT_OFF_LEADER + 4] = keep[BT_OFF_LEADER:BT_OFF_LEADER + 4]
        new[BT_OFF_GS_IP:BT_OFF_GS_IP + 4] = keep[BT_OFF_GS_IP:BT_OFF_GS_IP + 4]
        new[BT_OFF_GS_PORT:BT_OFF_GS_PORT + 2] = keep[BT_OFF_GS_PORT:BT_OFF_GS_PORT + 2]
        struct.pack_into("<H", new, BT_OFF_ID, key)
        t["rec"] = new
        t["password"] = record_password(new)
        self._stamp(t)
        return True

    def reserve(self, key, ident, password=None, rp=None):
        """Selectors 20/30/151/153: seat `ident` at `key`.  Returns
        (result, key): 0 = seated, -1 = no such table, -2 = wrong password,
        -3 = full, -4 = in progress (sec 4he: a battle is running on it; a
        late seat used to block the distribution for everyone inside),
        BT_REFUSE_RP = the joiner's rank points `rp` are outside the table's
        Min/Max RP (rp_allowed; None = not checked). A member already seated
        is never re-checked."""
        t = self.tables.get(key)
        if t is None:
            return -1, key
        if t.get("in_progress") and ident not in t["members"]:
            return -4, key
        if t["password"] and password is not None and \
                bytes(password).rstrip(b"\x00") != t["password"].rstrip(b"\x00"):
            return -2, key
        if (rp is not None and ident not in t["members"]
                and not rp_allowed(t["rec"], rp)[0]):
            return BT_REFUSE_RP, key
        mx = t["rec"][BT_OFF_MAX] or BT_MAX_MEMBERS
        if ident and ident not in t["members"]:
            if len(t["members"]) >= min(mx, BT_MAX_MEMBERS):
                return -3, key
            old = self.reservation.get(ident)
            if old is not None and old != key:
                self.cancel(ident)
            t["members"].append(ident)
        if ident:
            self.reservation[ident] = key
        self._stamp(t)
        return 0, key

    def cancel(self, ident):
        """Selector 155: leave whatever table `ident` is seated at."""
        key = self.reservation.pop(ident, None)
        t = self.tables.get(key) if key is not None else None
        if t is not None:
            if ident in t["members"]:
                t["members"].remove(ident)
            if not t["members"]:
                del self.tables[key]
            else:
                if t.get("leader_cid") == ident or t["leader"] == 0:
                    t["leader_cid"] = t["members"][0]
                self._stamp(t)
        return key

    def dissolve(self, key, ident=None, uid=0, force=False):
        """Selector 125: the LEADER tears the table down. With an ident that
        is not the leader's (and not `force`) nothing happens (sec 4he: a
        member's own Dissolve used to take the leader's table down)."""
        t = self.tables.get(key)
        if t is None:
            return False
        if ident and not force and not self.is_leader(key, ident, uid):
            return False
        t = self.tables.pop(key, None)
        for m in t["members"]:
            if self.reservation.get(m) == key:
                del self.reservation[m]
        return True

    def kick(self, key, target, ident=None, uid=0):
        t = self.tables.get(key)
        if t is None or target not in t["members"]:
            return False
        if ident and not self.is_leader(key, ident, uid):
            return False
        t["members"].remove(target)
        self.reservation.pop(target, None)
        self._stamp(t)
        return True

    def appoint(self, key, target, ident=None, uid=0):
        t = self.tables.get(key)
        if t is None or target not in t["members"]:
            return False
        if ident and not self.is_leader(key, ident, uid):
            return False
        t["leader_cid"] = target
        t["leader"] = target
        self._stamp(t)
        return True


def build_battletable_verb_answer(req, selector, rec, members=(), seq=0,
                                  subchannel=7, ptype=127, mode_byte=0,
                                  ident=None, result=0, pad_to=176,
                                  peer_ip=None, default_gs_ip=None):
    """A selector-25 / 27 / 29 answer: the 120-byte record at body[12..131]
    (rec+24 = the key, so the u32 at body[12] is the record's flags word, NOT a
    result -- these arms never read one), member ids from body[132].

    The record's rec+28 is BOTH the participant count the browser prints and
    the member-list count 0x00bcb740 copies from body[136] (clamped to 32), so
    it is rewritten here from the list we actually send -- a count over bytes
    we did not write is the sec 4bo wild-write class.
    """
    # WARNING:KEY: sec 4gv addendum (2026-09-23): THE RECORD IS A SECOND WRITER OF THE
    # CLIENT'S GAME-SERVER ENDPOINT, so it must be rewritten per recipient the
    # way the list and selector-38 paths already are. rec+12/+20 feed
    # 0x00bc0320(chan, ip, port), and 0x00bc0320 is the SOLE writer of
    # [chan+184..191] -- the same sockaddr selector 104's arm installs through
    # it (0x00bca938 tail) and the same one the client's keepalive sender reads
    # back at [chan+186]/[chan+188] (JP 0x00bc0c18 -> record +0x14c/+0x150).
    # BattletableStore._stamp writes the RAW --lobby-ip into every record, so
    # every verb answer served from here overwrote whatever 104 had just
    # declared. Only the LEADER runs these verbs, which is exactly why the
    # leader's game-server channel goes dead at a table where the joiner's
    # works.
    # WARNING: only a record that ALREADY carries an endpoint: the "table gone" answer
    # is a deliberately ALL-ZERO record (see BT_REQ_CONFIG below) and writing an
    # address into it would stop it being one.
    if (peer_ip and default_gs_ip and len(rec) >= BT_OFF_GS_IP + 4
            and any(rec[BT_OFF_GS_IP:BT_OFF_GS_IP + 4])):
        rec = rec_for(rec, default_gs_ip, peer_ip)
    mem = [int(m) & 0xFFFFFFFF for m in list(members)[:BT_MAX_MEMBERS]]
    body = bytearray(max(pad_to, BT_MEMBERS_OFF + 4 * len(mem)))
    body[0] = subchannel & 0xFF
    body[1] = selector & 0xFF
    struct.pack_into("<H", body, 4, 0)                 # failure flag clear
    R = BATTLETABLE_REC_OFF
    body[R:R + BT_REC_LEN] = bytes(rec[:BT_REC_LEN]).ljust(BT_REC_LEN, b"\x00")
    if result < 0:
        # a failure: no record to file. [kelsvc+24] (what the dispatcher takes
        # from body[12]) goes negative and the handlers bail on it.
        body[R:R + BT_REC_LEN] = bytes(BT_REC_LEN)
        struct.pack_into("<i", body, 12, result)
    struct.pack_into("<H", body, R + BT_OFF_CUR, len(mem))
    for i, m in enumerate(mem):
        struct.pack_into("<I", body, BT_MEMBERS_OFF + 4 * i, m)

    mid = bytearray(16)
    mid[0] = ptype & 0xFF
    struct.pack_into("<H", mid, 6, seq & 0xFFFF)
    if ident is None and req is not None and len(req) >= 20:
        ident = struct.unpack_from("<I", req, 16)[0]
    struct.pack_into("<I", mid, 8, (ident or 0) & 0xFFFFFFFF)

    pkt = bytearray([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", HDR_LEN + len(body))
    pkt += struct.pack("<I", now_ms() & 0xFFFF)
    pkt += mid + body
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
    return bytes(pkt)


def build_reserve_echo(req, key, seq=0, subchannel=7, ptype=127, pad_to=176,
                       ident=None):
    """sec 4fl (2026-09-12): the RESERVATION ECHO -- an unsolicited selector-152
    answer sent right AFTER a CREATE-ok (25) or a successful JOIN-ok (21).

    The "Start Immediately" status (0x00AA55A0 case 7, 0x00aa5834) refuses with
    0x683b ("Conditions for victory are not configured") when sub->[1118] ==
    0xffff.  sub->[1118] is recomputed (0x00AA19E8) from getVictoryCond
    0x00AD5F50 -> store method 0x00bd36d0 (key == [kelsvc+272] -> SELF path
    0x00bdd960) -> copier 0x00be67e0 over the SELF record R = [0x00bf4530]+304:
    returns u16 R+2970 iff (u32 R+684) & 0x0004, else 0xffff.  The ONLY
    reachable setter of that pair is 0x00be3348, called from the selector-152/
    154 arm (0x00bcd6b0): `if body[12] (s32) >= 0: R+2970 = u16 body[16];
    R+684 |= 4` (the ori at 0x00be3378 is in a branch DELAY SLOT).  The CREATE-
    ok processor (0x00bcb638) and the JOIN-ok processor (0x00bca9cc) both call
    the CLEAR 0x00be33b0 unconditionally, so the echo must trail the 25/21.

    A leader who CREATEs a table never sends 151 for it (live logs 09-12: only
    24/26/28), so without this echo they never hold a reservation on their own
    table and Start Immediately is refused; on 09-11 a tester only got past
    it by RESERVING by hand.  body[12..15] = 0 (success), body[16..17] = key --
    exactly what battletable_verb answers a real 151 with.  SE's text for this
    state is misleading; the field is the reservation, not a victory type."""
    return build_world_answer(req, selector=BT_REQ_RESERVE + 1, result=0,
                              cmd_arg=key, seq=seq, subchannel=subchannel,
                              ptype=ptype, pad_to=pad_to, ident=ident)


def battletable_verb(store, req, body, req_sel, ident, uid, seq=0,
                     subchannel=7, ptype=127, pad_to=176, probe=False,
                     quest=None, peer_ip=None, default_gs_ip=None, rp=None):
    """Answer one console verb out of the store.  Returns (packet, note) or
    (None, note) when the verb is not ours to answer (unreadable body).  A
    config request for a table we do not hold answers result -1; `probe` is
    kept for callers but no longer used here (it painted a phantom table)."""
    kw = dict(seq=seq, subchannel=subchannel, ptype=ptype, ident=ident)
    # kw goes to build_world_answer too, which takes neither of these -- only
    # the RECORD answers rewrite the endpoint.
    kwrec = dict(kw, peer_ip=peer_ip, default_gs_ip=default_gs_ip)
    key = struct.unpack_from("<H", body, 12)[0] if len(body) >= 14 else 0
    if req_sel == BT_REQ_CREATE:
        if len(body) < BT_REQ_REC_OFF + BT_REC_LEN:
            return None, "create request body is %d bytes, need %d" % (
                len(body), BT_REQ_REC_OFF + BT_REC_LEN)
        wire = bytearray(body[BT_REQ_REC_OFF:BT_REQ_REC_OFF + BT_REC_LEN])
        # sec 4fe (LIVE 2026-09-12): the create screen's only offered type sends
        # MODE 0, which is not a real battle mode -- the config screen then shows
        # "Settings: !!na!!" and "Map: !!na!!" and Start Immediately silently
        # does nothing (every WORKING table on the wire is mode 1; measured over
        # PINE: served tables mode=1 render, the created mode=0 table does not).
        # Coerce an invalid mode-0 create to mode 1 (Battle) so the table is a
        # real, startable table. map 0 is fine (Jungle; served jungle table is
        # map 0 too) -- the differentiator was the mode, not the map.
        _mode_fix = wire[BT_OFF_MODE] == 0
        if _mode_fix:
            wire[BT_OFF_MODE] = 1
        # 2026-09-13: the LEADER is the creator's CHARID. The list row resolves
        # a name from it; the entrance uid is one value shared by every machine
        # (0xa756a69a) or a per-machine one the OTHER client never learns, so
        # a uid leader read as the wrong player, then as no name at all.
        # 2026-09-13 (live + static): a SOLO table = list kind 4 at wire+108
        # (the client's list filter 0x00aa2fc8 shows a row only where record
        # +52 == the window's kind). Its create carried flags|0x8, mission 0,
        # max 0 -> the row read "TBT 2/0 | !!na!!". Stamp it a MISSION: flags
        # 0x00010000 (the "MS" mode label + the start gate 0x00aa0d98), wire+26
        # = the quest the creator picked (the row's 3rd column = 0xBBFF+id),
        # max 1 if 0. _stamp skips the cur_min clamp for mission tables.
        _solo = wire[BT_OFF_UNK108] == 4
        if _solo:
            _fl = struct.unpack_from("<I", wire, BT_OFF_FLAGS)[0]
            struct.pack_into("<I", wire, BT_OFF_FLAGS,
                             _fl | BT_FLAG_MISSION | 0x8)
            if quest:
                struct.pack_into("<H", wire, BT_OFF_MISSION, quest & 0xFFFF)
            if wire[BT_OFF_MAX] == 0:
                wire[BT_OFF_MAX] = 1
        key = store.create(bytes(wire), ident, ident or uid)
        return (build_battletable_verb_answer(
                    req, BT_REQ_CREATE + 1, store.record(key),
                    store.members(key), pad_to=pad_to, **kwrec),
                "CREATE -> table %d (map %d, mode %d%s, max %d)%s for 0x%08x" % (
                    key, wire[BT_OFF_MAP], wire[BT_OFF_MODE],
                    " [coerced 0->1]" if _mode_fix else "",
                    wire[BT_OFF_MAX],
                    (" SOLO -> MISSION, quest %s" % quest) if _solo else "",
                    ident or 0))
    if req_sel == BT_REQ_CONFIG:
        rec = store.record(key)
        if rec is None:
            # 2026-09-13: a table that is GONE (dissolved, or a stale row the
            # client still holds) gets an ALL-ZERO record (key 0 = no table,
            # no flags, 0 members), never the sec 4do sentinel probe -- the
            # probe's values rendered as a stranger's password table ("Below
            # 3,881,520 RP", 0 players, 0 minutes) after the player
            # dissolved their own table 3. NOT result=-1: body[12] is the
            # record's FLAGS word here and the 27 arm 0x00bcb740 never treats
            # the answer as a failure (doc_phantom_table_proof.py, emulated) --
            # -1 would set every flag, the password bit included. The real
            # cure is the reservation CLEAR sent after a DISSOLVE-ok (main).
            return (build_battletable_verb_answer(
                        req, BT_REQ_CONFIG + 1, bytes(BT_REC_LEN), (),
                        pad_to=pad_to, **kwrec),
                    "CONFIG of unknown table %d -> empty record (table gone)" % key)
        return (build_battletable_verb_answer(
                    req, BT_REQ_CONFIG + 1, rec, store.members(key),
                    pad_to=pad_to, **kwrec),
                "CONFIG table %d, %d member(s)" % (key, len(store.members(key))))
    if req_sel == BT_REQ_UPDATE:
        if len(body) < BT_REQ_REC_OFF + BT_REC_LEN:
            return None, "update request body is %d bytes" % len(body)
        wire = body[BT_REQ_REC_OFF:BT_REQ_REC_OFF + BT_REC_LEN]
        key = struct.unpack_from("<H", wire, BT_OFF_ID)[0] or \
            store.table_of(ident) or 0
        ok = store.update(key, wire, ident)
        rec = store.record(key) if ok else bytes(wire)
        return (build_battletable_verb_answer(
                    req, BT_REQ_UPDATE + 1, rec, store.members(key),
                    result=0 if ok else -1, pad_to=pad_to, **kwrec),
                "ADJUST RULES table %d%s" % (key, "" if ok else " (unknown)"))
    if req_sel in (BT_REQ_RESERVE, BT_REQ_RESERVE_PW):
        pw = (body[BT_PASSWORD_OFF:BT_PASSWORD_OFF + 8]
              if req_sel == BT_REQ_RESERVE_PW else None)
        res, key = store.reserve(key, ident, pw, rp=rp)
        return (build_world_answer(req, selector=req_sel + 1, result=res,
                                   cmd_arg=key, pad_to=pad_to, **kw),
                "RESERVE table %d -> %d%s" % (
                    key, res, " (with password)" if pw is not None else ""))
    if req_sel == BT_REQ_CANCEL:
        key = store.cancel(ident)
        return (build_world_answer(req, selector=req_sel + 1, result=0,
                                   pad_to=pad_to, **kw),
                "CANCEL -> left table %s" % key)
    if req_sel == BT_REQ_DISSOLVE:
        key = store.table_of(ident) or key
        ok = store.dissolve(key, ident, uid=uid or 0)
        return (build_world_answer(req, selector=req_sel + 1,
                                   result=0 if ok else -1, pad_to=pad_to, **kw),
                "DISSOLVE table %s -> %s" % (
                    key, "gone" if ok else
                    ("REFUSED, not the leader" if key in store.tables
                     else "unknown")))
    if req_sel == BT_REQ_INVITE:
        target = struct.unpack_from("<I", body, 12)[0] if len(body) >= 16 else 0
        return (build_world_answer(req, selector=req_sel + 1, result=0,
                                   pad_to=pad_to, **kw),
                "INVITE 0x%08x (acknowledged only)" % target)
    return None, "not a battletable verb"


def build_user_list_answer(req, uids, seq=0, subchannel=7, ptype=127,
                           mode_byte=0, ident=None, total=1, index=0,
                           records=None, name=None, fields=None,
                           answer_selector=USER_SELECTOR_ANS,
                           sweep_prefix="Slot"):
    """The selector-11 reply that PUTS PLAYERS IN THE USER LIST (sec 4bx).

    `user list 0 0` prints immediately before every CER-47117 -- after the roster
    loads and again on opening the map.  That printf is `0x00bc9bf0` in the kel
    overlay and the jump table reaches it from SELECTOR 11 (arm `0x00bcc9c0`).
    We have always ANSWERED selector 10 with 11 -- with build_world_answer's
    empty body -- so the client parsed a list of zero users every time.

    The handler, read at `0x00bc9bf0` (a3 is the RAW DATAGRAM, so a3+24 == BODY):

        s4 = body + 12,  s2 = s5 = body + 20

        body[12..13]  u16  RECORDS IN THIS MESSAGE
        body[16..17]  u16  TOTAL MESSAGES      -> [kelsvc+228]
        body[18..19]  u16  THIS MESSAGE INDEX  -> bit (index) in the u32 mask
                           array at [kelsvc+1068 + (index>>5)*4]
        body[20..]         records, stride 56, converted 56 -> 64 by 0x0058af08
                           into [kelsvc+1052] + [kelsvc+1060]*64, capacity
                           [kelsvc+1056]

        completion: [kelsvc+228] == [kelsvc+232]  (total == messages received)

    Rejections, all of which return -1 and none of which log:
      * index > total                        -> 0x00bc9ed0
      * a message index whose mask bit is ALREADY SET (a duplicate) -> 0x00bc9ed0

    WARNING: total == 0 is NOT an error: the handler skips the bookkeeping, stores
    nothing, prints `user list 0 0`, and its own completion test 0 == 0 passes.
    That is exactly what our empty body produced.

    KEY: sec 4ch: SELECTOR 11 AND SELECTOR 19 ARE NOT THE SAME DELIVERY.
    The arms differ in one argument -- 0x00bcc9c0 passes `t0 = 0`, 0x00bccb6c
    passes `t0 = 1` -- and inside 0x00bc9bf0 that argument picks the branch:

        t0 == 0   -> the 1024-capped path, stores NOTHING the profile UI reads
        t0 != 0   -> 0x00bd8690(a0 = [kelsvc+280], a1 = record), the 80-byte
                     PROFILE CACHE, which is what the Status/Profile window
                     resolves names out of

    So a user list delivered on 11 cannot fix `!!na!!` and one delivered on 19
    can.  The 19 path is additionally capped at `32 - (u8)[kelsvc+1084]` records
    per message and SKIPS THE WHOLE LOOP, silently, when that is <= 0; selector
    104's arm (0x00bcd26c) is one of the four sites that zero the counter, so
    --gs-connect already arms it.  It also DROPS any record whose +0 equals
    [kelsvc+272], i.e. the client's own id.

    The record's fields are decoded in build_peer_record above.
    """
    if records is None:
        # the 2026-09-05 audit (F): --user-list-sweep served 32 entries all called
        # `Quarry`, which is what the player saw. The sweep is a lever, not a
        # roster, so give each swept id a name that says which id it IS -- an
        # unreadable list is worse than an obviously-synthetic one.
        records = [build_peer_record(
            u, name=(name if u == uids[0] else "%s%d" % (sweep_prefix, u)),
            **(fields or {})) for u in uids]
    body = bytearray(20 + PEER_REC_LEN * len(records))
    body[0] = subchannel & 0xFF
    body[1] = answer_selector
    # body[4] bit 0 is the failure flag on the sibling rungs; keep it clear.
    struct.pack_into("<H", body, 4, 0)
    struct.pack_into("<H", body, 12, len(records))     # records in THIS message
    struct.pack_into("<H", body, 16, total & 0xFFFF)   # total messages
    struct.pack_into("<H", body, 18, index & 0xFFFF)   # this message's index
    for i, r in enumerate(records):
        o = 20 + PEER_REC_LEN * i
        body[o:o + PEER_REC_LEN] = r[:PEER_REC_LEN]

    mid = bytearray(16)
    mid[0] = ptype & 0xFF
    struct.pack_into("<H", mid, 6, seq & 0xFFFF)
    if ident is None and req is not None and len(req) >= 20:
        ident = struct.unpack_from("<I", req, 16)[0]
    struct.pack_into("<I", mid, 8, (ident or 0) & 0xFFFFFFFF)

    pkt = bytearray()
    pkt += bytes([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", HDR_LEN + len(body))
    pkt += struct.pack("<I", now_ms() & 0xFFFF)
    pkt += mid
    pkt += body
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
    return bytes(pkt)


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
        return struct.unpack_from("<I", data, BODY_OFF + ENTRANCE_UID_OFF)[0]
    if len(data) == 132 and data[1] == 1:
        return struct.unpack_from("<I", data, BODY_OFF + WORLD_DOOR_UID_OFF)[0]
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
    if len(data) < BODY_OFF + 4:
        return None
    return struct.unpack_from("<I", data, BODY_OFF)[0]


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
    if len(data) < BODY_OFF + 0x1C:
        return None
    uid = struct.unpack_from("<I", data, BODY_OFF)[0]
    x, y, z = struct.unpack_from("<fff", data, BODY_OFF + 4)
    dx, dy, dz = struct.unpack_from("<fff", data, BODY_OFF + 0x10)
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
    pkt += struct.pack("<H", HDR_LEN + len(body))
    pkt += struct.pack("<I", (now_ms() & 0xFFFF) if ms is None else (ms & 0xFFFFFFFF))
    pkt += mid
    pkt += body
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
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
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
    return bytes(pkt)


PEER_POS_LEN = BODY_OFF + 40   # a position datagram: header + the 40-byte pose


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
    return struct.unpack_from("<I", data, BODY_OFF)[0]


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

# 2026-09-24 (static RE on the retail client, not yet live): TEAM
# CAPSULE battles. The Mako Capsule is item 0x6B300000 (item-def +12 == 10,
# the "field item" class). The SERVER places it (notify kind 10, arm
# 0x00bcba04: record at body[20] {u32 id, u16 count, u16 slot < 128, u16,
# s16 x, y, z}, integer world units); touching one sends P2P 119 {+20 u32
# slot, +24 u32 1, +28 seq, +32.. f32 pos} and the client waits: kind 11
# (ident = the PICKER, same record) removes it from the field for everyone
# and bags it for the picker ("%s captures a mako capsule!"). A carrier's
# drop (KO) is P2P 118 {+20 u32 item, +24 u32 count, +28 seq, +32.. f32 pos}
# -- already out of its own bag; kind 21 (ident = the dropper) spawns it for
# the others, kind 10 for the dropper. Kind 46 = the scoreboard (body[20..47]
# 7 x u32 holder id, body[48..54] 7 x u8 count), kinds 47 / 48 = the hold
# countdown (10 s, index at body[16]) start / cancel. The client has no
# capsule win test: the server ends it (kind 4 via end_battle).
MAKO_CAPSULE = 0x6B300000
CAPSULE_HOLD_S = 10.0
CAPSULE_RING = 150.0          # OURS: no fixed capsule points found in bzd
CAPSULE_HOLDERS = 7
#: OURS: a carrier's DROP (P2P 118) this soon after its KO was caused by that
#: KO (Capsule Seeker; the drop and request 30 come from the victim's client in
#: no measured order)
CARRIER_DROP_S = 3.0


FIELD_QUIET = 2               # kind 10 body[16] == 2 skips the HUD notice


def field_item_payload(iid, slot, pos, count=1, head=0):
    """Kind 10 / 11 / 21's payload: body[16] u32 `head` (0 = the HUD notice,
    FIELD_QUIET = none; any nonzero value also clears whatever the game had
    in that slot first -- pickup RE 2026-09-26), then the 16-byte record."""
    x, y, z = (max(-32768, min(32767, int(round(v)))) for v in pos)
    return struct.pack("<I", head) + struct.pack("<IHHHhhh", iid & 0xFFFFFFFF, count & 0xFFFF,
                                  slot & 0xFFFF, 0, x, y, z)


def capsule_ring(center, n, radius=CAPSULE_RING):
    """`n` field positions on a ring around `center` (x, y, z)."""
    import math
    cx, cy, cz = center
    return [(cx + radius * math.cos(2 * math.pi * i / max(1, n)), cy,
             cz + radius * math.sin(2 * math.pi * i / max(1, n)))
            for i in range(n)]


def capsule_scoreboard_payload(holders):
    """Kind 46: up to 7 {holder id, count} pairs (holders = {cid: count})."""
    rows = [(c, n) for c, n in sorted(holders.items()) if n > 0][:CAPSULE_HOLDERS]
    ids = [c for c, _ in rows] + [0] * (CAPSULE_HOLDERS - len(rows))
    cnt = [n for _, n in rows] + [0] * (CAPSULE_HOLDERS - len(rows))
    return (bytes(4) + struct.pack("<7I", *[i & 0xFFFFFFFF for i in ids])
            + bytes(min(255, n) for n in cnt))


def p2p_pickup_slot(payload):
    return struct.unpack_from("<I", payload, 0)[0] if len(payload) >= 4 else None


def p2p_drop(payload):
    """(item, count, (x, y, z)) of a 118 payload, or None."""
    if len(payload) < 24:
        return None
    iid, count = struct.unpack_from("<II", payload, 0)
    return iid, count, struct.unpack_from("<fff", payload, 12)


# The capsule RULES, pure (the room holds the state; main() only sends).
# Each returns [(kind, payload, ident, to)] with to = "all" | "self" | "others"
# relative to the acting member, plus a log note.

# 2026-09-26: the field holds ANY item, not only capsules. A capsule entry is
# (id, pos); any other item is (id, pos, count). Every battle gets a field, so
# a player can drop ammo for a teammate (118) and anyone can pick it up (119)
# -- before this, a non-capsule 118 left the dropper's bag and went nowhere.
FIELD_SLOTS = 128               # the client's table [chan+1284] (slot < 128)


def capsule_pickup(room, cid, slot):
    field = room.field
    if field is None or room.over or slot not in field:
        return [], ("ignored (%s)" % ("no capsule field" if field is None else
                                      "battle over" if room.over else
                                      "slot %s empty -- taken" % slot))
    iid, pos, *_rest = field.pop(slot)
    if iid != MAKO_CAPSULE:
        # kind 11, ident = the picker: gone for everyone, bagged by the picker
        count = _rest[0] if _rest else 1
        return ([(11, field_item_payload(iid, slot, pos, count), cid, "all")],
                "PICKED UP slot %d: 0x%08x x%d" % (slot, iid, count))
    room.holders[cid] = room.holders.get(cid, 0) + 1
    room.last_pick = cid
    return ([(11, field_item_payload(iid, slot, pos), cid, "all")],
            "PICKED UP slot %d -> holds %d" % (slot, room.holders[cid]))


def capsule_drop(room, cid, iid, count, pos, now=None):
    field = room.field
    if field is None or room.over:
        return [], "ignored (%s)" % ("no capsule field" if field is None
                                     else "battle over")
    if iid != MAKO_CAPSULE:
        # the item already left the dropper's bag: place it, kind 10 to ALL
        # (ident = the dropper). Not kind 21 to the dropper: that arm cuts
        # the item from the bag a second time (pickup RE, 2026-09-26).
        slot = next((i for i in range(FIELD_SLOTS) if i not in field), None)
        if slot is None:
            return [], "ignored (field full: %d items)" % len(field)
        count = max(1, min(int(count), 0xFFFF))
        field[slot] = (iid, pos, count)
        return ([(10, field_item_payload(iid, slot, pos, count), cid, "all")],
                "DROPPED 0x%08x x%d -> slot %d" % (iid, count, slot))
    held = room.holders.get(cid, 0)
    now = time.time() if now is None else now
    seeker = room.credit_carrier_ko(cid, now) if held else None
    _lk = room.last_ko.get(cid)
    if held and (_lk is None or now - _lk[1] > CARRIER_DROP_S):
        room.carrier_drop[cid] = now        # its request 30 may come next
    count = max(1, min(int(count), held)) if held else max(1, int(count))
    room.holders[cid] = max(0, held - count)
    out = []
    for _ in range(count):
        slot = next((i for i in range(FIELD_SLOTS) if i not in field), None)
        if slot is None:
            break
        field[slot] = (iid, pos)
        pl = field_item_payload(iid, slot, pos)
        out.append((10, pl, cid, "self"))      # it left its bag already
        out.append((21, pl, cid, "others"))    # spawns it for everyone else
    return out, "DROPPED %d -> holds %d%s" % (
        count, room.holders[cid],
        " (KO'd by 0x%x: a carrier KO, Capsule Seeker)" % seeker
        if seeker is not None else "")


def capsule_hold(room, now):
    """The scoreboard, then the hold: a team holding every capsule starts the
    countdown (47); losing one cancels it (48)."""
    out = [(46, capsule_scoreboard_payload(room.holders), 0, "all")]
    n = room.rules.capsules
    per = {}
    for c, k in room.holders.items():
        per[room.team_of(c)] = per.get(room.team_of(c), 0) + k
    full = [tm for tm, k in per.items() if k >= n > 0]
    note = ""
    if full and room.cap_hold is None:
        room.cap_hold = (full[0], now + CAPSULE_HOLD_S)
        room.cap_last = room.last_pick
        out.append((47, struct.pack("<I", full[0] & 0xFFFFFFFF), 0, "all"))
        note = "team %d holds all %d -- %.0f s hold (47)" % (full[0], n, CAPSULE_HOLD_S)
    elif room.cap_hold is not None and room.cap_hold[0] not in full:
        out.append((48, struct.pack("<I", room.cap_hold[0] & 0xFFFFFFFF), 0, "all"))
        note = "team %d lost a capsule -- hold CANCELLED (48)" % room.cap_hold[0]
        room.cap_hold = None
        room.cap_last = None
    return out, note


def capsule_count(room):
    """How many capsules `room`'s field gets: a TEAM CAPSULE table's record
    count, a capsule MISSION's (doc_missions.capsule_setup), else 0."""
    if room is None:
        return 0
    if room.mission is not None:
        cs = doc_missions.capsule_setup(room.mission)
        return cs[0] if cs else 0
    if room.rules.mode == "TCP":
        return max(0, room.rules.capsules)
    return 0


def capsule_mission_check(room):
    """A capsule MISSION: the players (co-op, all of them together) hold its
    target -> the room is over with the objective. Returns a log note."""
    if room.mission is None or room.over:
        return ""
    held = sum(room.holders.values())
    if doc_missions.capsules_end(room.mission, held):
        room.over = True
        room.why = "%s: %d Mako Capsule(s) collected" % (
            doc_missions.WHY_OBJECTIVE, held)
        return "mission target reached (%d held)" % held
    return "mission: %d held" % held


def capsule_hold_done(room, now):
    """True (and the winner set) when a running hold has lasted."""
    if room.cap_hold is None or room.over or now < room.cap_hold[1]:
        return False
    room.capsule_winner = min(max(room.cap_hold[0], 0), GS_TEAM_SLOTS - 1)
    room.last_capsule = room.cap_last
    return True


# 2026-09-26: TEAM BASE OCCUPATION. SE's January Additional Manual: the team
# that destroys the enemy base and then holds it for a set time wins. After
# the base falls, holding it means standing where the base stood (source:
# April 2006 player blog, the DG Drone 1st exam). The radius and the time
# are OURS (no source prints them; the bzd base gimmick carries no trigger
# radius we have decoded). No client HUD for the hold was found: group 55 has
# only "%s's base has been destroyed!" and the result line "%s's Base
# Captured", and kinds 47/48 are the CAPSULE hold -- so the hold runs on the
# server alone and ends the room with the kind-4 verdict.
BASE_OCCUPY_RADIUS = 100.0      # OURS: horizontal (x/z) distance to the spot
BASE_OCCUPY_S = 10.0            # OURS: seconds of unbroken presence
BASE_POSE_FRESH_S = 2.0         # a 0x83 pose older than this is not "there"


def base_spots(zone):
    """(team 0 base, team 1 base) world positions for arena `zone`, or None.
    BASE_POSITIONS lists (g069, g070) and team 0 owns g070 (see team_start)."""
    bp = BASE_POSITIONS.get(zone)
    return None if bp is None else (bp[1], bp[0])


def base_occupy_tick(room, poses, now, radius=BASE_OCCUPY_RADIUS,
                     hold_s=BASE_OCCUPY_S, fresh_s=BASE_POSE_FRESH_S):
    """Run every destroyed base's occupation. `poses` = {cid: (x, y, z, t)}
    from the members' type-0x83 streams. A living, present member of the
    team that must occupy base i, with a fresh pose within `radius` (x/z) of
    base i's spot, holds it; the hold survives while ANY such member stays
    (the first one keeps the credit), and resets when none is left. `hold_s`
    of unbroken hold ends the room: that team wins, the holder is the
    occupier (the Assault medal). Returns log notes for the changes."""
    notes = []
    if room.over or not room.base_down or room.base_spots is None:
        return notes
    alive = set(room.present()) - set(room.dead_until)
    for idx, team in sorted(room.base_down.items()):
        spot = room.base_spots[idx] if idx < len(room.base_spots) else None
        if spot is None:
            continue
        inside = []
        for m in room.members:
            if m not in alive or room.team_of(m) != team:
                continue
            p = poses.get(m)
            if p is None or now - p[3] > fresh_s:
                continue
            d = ((p[0] - spot[0]) ** 2 + (p[2] - spot[2]) ** 2) ** 0.5
            if d <= radius:
                inside.append((d, m))
        cur = room.occupy.get(idx)
        if not inside:
            if cur is not None:
                room.occupy.pop(idx, None)
                notes.append("team %d's hold on base %d BROKEN after %.1f s "
                             "(nobody on the spot) -- reset"
                             % (team, idx, now - cur[1]))
            continue
        if cur is None:
            cur = room.occupy[idx] = (min(inside)[1], now)
            notes.append("team %d OCCUPYING base %d: 0x%x on the spot "
                         "(%.0f s to hold)" % (team, idx, cur[0], hold_s))
        elif cur[0] not in [m for _d, m in inside]:
            cur = room.occupy[idx] = (min(inside)[1], cur[1])
        if now - cur[1] >= hold_s:
            room.capsule_winner = min(max(team, 0), GS_TEAM_SLOTS - 1)
            room.occupier = cur[0]
            room.over = True
            room.why = ("team %d's base destroyed and occupied by 0x%x"
                        % (idx, cur[0]))
            notes.append("team %d HELD base %d for %.0f s -- WINS (occupier "
                         "0x%x)" % (team, idx, now - cur[1], cur[0]))
            break
    return notes


def p2p_battle_type(data, inner):
    """The P2P type of a battle-layer datagram, or None. Mode 3 or 4 on the
    wire, a decrypted inner header (mode 3 is the mode-2 cipher instance
    under another mode byte: dispatcher 0x00584230 maps both to 0x005842b8),
    inner flags bit 3, and a P2P type byte -- everything else on the channel
    is a game-server request or a pose report and stays on its own path."""
    if inner is None or len(data) < BODY_OFF + P2P_PAYLOAD_OFF:
        return None
    if data[1] not in (3, 4) or not (inner.get("flags", 0) & PEER_RELAY_FLAG):
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
    if data[1] not in (0, 3, 4) or len(inner["plain"]) < BODY_OFF + 4:
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
    if len(data) != BODY_OFF + 24 or data[1] != 4:
        return None
    if inner is not None and inner.get("plain") is not None:
        return None                 # readable: p2p_server_type()'s to name
    a_, b_, _n = struct.unpack_from("<III", data, BODY_OFF)
    pos = struct.unpack_from("<fff", data, BODY_OFF + 12)
    if not all(math.isfinite(v) and abs(v) < 100000.0 for v in pos):
        return None
    if a_ < FIELD_SLOTS and b_ == 1:
        return P2P_PICKUP
    if a_ >> 24 and 1 <= b_ <= 0xFFFF:
        return P2P_DROP
    return None


def p2p_record(plain):
    """(type, flags, sender, target, payload) of a decrypted P2P datagram."""
    b = plain[BODY_OFF:]
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
    rid = struct.unpack_from("<I", data, BODY_OFF)[0]
    pkt = bytearray(data)
    pkt[8:24] = bytes(16)
    pkt[8] = 0x83
    pkt[9] = PEER_RELAY_FLAG
    struct.pack_into("<I", pkt, 16, rid)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    ck = cksum(pkt)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", ck)
    return {"type": 0x83, "flags": PEER_RELAY_FLAG, "cksum": ck, "ack_seq": 0,
            "seq": 0, "u32_16": rid, "u32_20": 0, "is_data": False,
            "is_ack": False, "plain": bytes(pkt), "synth": True}


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
    pkt += struct.pack("<H", HDR_LEN + len(body))
    pkt += struct.pack("<I", now_ms() & 0xFFFF)
    pkt += mid
    pkt += body
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
    return bytes(pkt)


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
    if plain is not None and len(plain) > BODY_OFF + 1:
        sel = plain[BODY_OFF + 1]
    elif data[1] != 1 and len(data) > BODY_OFF + 1:
        sel = data[BODY_OFF + 1]
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


def build_srv_entry(ip="127.0.0.1", port=55040, id0=0, tail=0, area=1):
    """One 12-byte SERVER-LIST entry of a subtype-3 payload.

    MEASURED, the assembly loop at 0x00585dd0 (stride 12, bounded at 128 which
    is exactly the max phase 2 passes in [conn+0xDC]):

        [entry+0]  u16            -> conn+0x140 + idx*12   (raw)
        [entry+2]  u16 via ntohs  -> conn+0x142 + idx*12   (0x0058a928)
        [entry+4]  u32 via ntohl  -> conn+0x144 + idx*12   (0x0058a940)
        [entry+10] u16            -> conn+0x14A + idx*12   (raw)

    0x0058a928/0x0058a940 are byte swappers, so +2 is a PORT and +4 an IP, both
    in network order.  0x00586280 then copies that table into [conn+0xD8] --
    the caller buffer phase 2 handed down -- capped at min(count, [conn+0xDC]).

    KEY: `area` (entry+8) IS THE FIELD THAT MADE THE SELECT SERVER LIST EMPTY,
    diagnosed 2026-09-22 from a savestate taken on the screen. We left it 0 for
    the entire life of this service and 0 is never valid.

    The live screen is lobby screen id 0x0B (object at [0x00B135E8]); its
    populate `0x00AB4238` copies the area array and then FILTERS at 0x00AB4598:

        if (area[i].id != want) skip;     want = client area code, or 0xFFFF
                                          when the cursor is on "all areas"

    The client's own area code is `[0x001B5658]`, a LINK-TIME CONSTANT of the
    DoC executable -- measured **1**, and its only setter is referenced nowhere
    in the 32 MB image, so it never changes. The copy loop at 0x00591790 maps
    the wire record to what the filter reads:

        record +0   -> dst+4   name code
        record +8   -> dst+0   AREA ID   <- the filter compares THIS
        record +0xA -> dst+8   class (the select handler refuses >= 1000)

    Measured with area 0: `[screen+0x80]` (areas) = 1 but `[screen+0x84]`
    (rows built) = 0. 0 != 1, the one row is filtered out, the list is empty.
    Sending 1 puts the row on the default tab; 0xFFFF puts it on "all areas"
    and moves the cursor there, so 1 is the right default.
    """
    e = bytearray(12)
    struct.pack_into("<H", e, 0, id0 & 0xFFFF)
    struct.pack_into(">H", e, 2, port & 0xFFFF)          # network order
    o = [int(x) for x in ip.split(".")]
    e[4] = o[0]; e[5] = o[1]; e[6] = o[2]; e[7] = o[3]   # network order
    struct.pack_into("<H", e, 8, area & 0xFFFF)          # the AREA/tab id
    struct.pack_into("<H", e, 10, tail & 0xFFFF)
    return bytes(e)


def build_frag3(req, parts=1, index=0, payload=b"", mode="subtype", crypto="echo",
                body_len=56, mode_byte=0, do_cksum=True, ptype=128, flags=0):
    """A SUBTYPE-3 reply: the fragmented-response envelope.

    MEASURED, handler 0x00585d28 (reached only when [conn+0xD0] == 3, gate at
    0x00585fc4).  Its argument is the BODY, same as subtype-4's 0x00585ec8:

        v0 = lhu [body+4]      ; TOTAL number of parts; 0 -> handler returns at once
        a0 = lhu [body+6]      ; THIS part's index
        if (v0 < a0) return -1 ; index greater than total is rejected
        [conn+0xE0] |= 1 << index      ; bitmask of parts received
        [conn+0xE4]  = v0              ; total expected
        [conn+0xE8]  = 1               ; parts received
        a3 = body + 8                  ; -> the PAYLOAD

    and at 0x00585e84, once [conn+0xE8] == [conn+0xE4] (all parts in), it stamps
    [conn+0xF8] and moves the connection state on.  So a single-part response is
    parts=1, index=0, payload from body[8].

    build_reply() zeroes body[4..7], which is why a subtype-3 reply built with it
    is a no-op: total parts reads as 0.

    WARNING -- this must NEVER be sent to the entrance packets (body tail
    `00 02`).  Sending subtype 3 indiscriminately BROKE the handshake live
    (seen on a console): the connection transits state 3 on the healthy path, so a
    subtype-3 message arriving then is accepted at the wrong moment.  The caller
    targets it at the `00 01` lobby requests ONLY, which are never sent during
    the entrance -- a targeting guarantee, not a state-machine assumption.
    """
    if len(req) < HDR_LEN:
        return None
    body = bytearray(max(body_len, 8 + len(payload)))
    body[1] = 3
    # body[2..3] is the ENTRY COUNT of this fragment (0x00585dd0 reads it and
    # returns immediately when it is zero -- which is why an empty frag3 reply
    # registers the fragment but copies nothing).
    struct.pack_into("<H", body, 2, (len(payload) // 12) & 0xFFFF)
    struct.pack_into("<H", body, 4, parts & 0xFFFF)
    struct.pack_into("<H", body, 6, index & 0xFFFF)
    if payload:
        body[8:8 + len(payload)] = payload

    if crypto == "echo":
        mid = bytearray(req[8:24])
    else:
        mid = bytearray(16)

    # WARNING: The inner header's TYPE and FLAGS must be set explicitly, exactly as
    # build_reply does.  Echoing req[8:24] hands back the client's *encrypted*
    # header, and since we reply in mode 0 (no cipher) the client reads those
    # bytes as plaintext -- type and flags come out as garbage and the packet is
    # dropped UPSTREAM of the dispatcher.  Cost one live boot: 2 frag replies
    # sent, [conn+0xE4]/[0xE8] still 0 while the connection sat in state 3.
    mid[0] = ptype & 0xFF               # 128 = the type the client itself sends
    mid[1] = flags & 0xFF               # bit 3 clear => no ID lookup

    total = HDR_LEN + len(body)
    pkt = bytearray()
    pkt += bytes([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", total)
    pkt += struct.pack("<I", now_ms() & 0xFFFFFFFF)
    pkt += mid
    pkt += body
    if do_cksum:
        pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
        pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
    return bytes(pkt)


def build_reliable_ack(ack_seq):
    """A header-only MODE-0 ACK for the reliable-messaging framework.

    PROVEN OFFLINE (an offline run of the client's own code (doc_ack_proof), against the client's own code): the framework
    header handler 0x005810d0 dispatches on record[1] (flags); bit1 (0x02) = ACK,
    which walks the pending-send list (framework+0x248) and, for the node whose
    message seq (sub[+0x0a]) == the received ack-seq, UNLINKS it (count 1->0) and
    fires the send-completion -- stopping the retransmit.  A 24-byte mode-0 packet
    with pkt[9]=0x02 (flags) and pkt[12..13]=ack-seq, run through kel's real
    parser + handler against the live framework, cancels the pending seq-28 send.

    The reliable channel honours mode 0 (no cipher), same as the lobby channel.
    type (pkt[8]) is NOT checked; use 0xFF to match the client's own ACK template.
    """
    pkt = bytearray(HDR_LEN)                    # header-only, no body (msg[18]=0)
    pkt[0] = 0x04
    pkt[1] = 0x00                                # mode 0
    struct.pack_into("<H", pkt, 2, HDR_LEN)
    struct.pack_into("<I", pkt, 4, now_ms() & 0xFFFF)
    pkt[8] = 0xFF                                # inner type (0xFF = the ACK template's type)
    pkt[9] = 0x02                                # inner flags -> record[1] bit1 = ACK
    struct.pack_into("<H", pkt, 12, ack_seq & 0xFFFF)   # ack-seq, read at pkt+12 by 0x005810d0
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
    return bytes(pkt)


# --- sweep -----------------------------------------------------------------
# DoC sends a BURST of ~10 datagrams per connection attempt, then goes quiet.
# So one attempt = one candidate.  With the input-unlock pnach the tester can
# dismiss the error and retry immediately, which makes a whole table walkable in
# a single game session instead of one reboot per candidate.
#
# A new burst is detected by a gap in arrival times (BURST_GAP seconds).  The
# candidate in force is printed in a banner so the Nth error code the tester
# reports lines up with the Nth banner in this log.
#
# Ordered deliberately: the known-good baseline FIRST, so if it does not
# reproduce CER-48103 the run is untrustworthy and everything after it is noise.
BURST_GAP = 8.0
SWEEP = [
    (128, 4, "baseline -- known to reach CER-48103 (lobby phase)"),
    (128, 3, "same type, the OTHER ENT subtype"),
    (0,   4, "type 0 (s6=12)"),
    (1,   4, "type 1 (s6=8)"),
    (2,   4, "type 2 (generic arm)"),
    (3,   4, "type 3 (s6=40)"),
    (4,   4, "type 4"),
    (126, 4, "type 126 (s6=12)"),
    (254, 4, "type 254 (own arm)"),
    (255, 4, "type 255 (own arm)"),
]


def _week_start_arg(spec):
    try:
        doc_stats.parse_week_start(spec)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))
    return spec


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--mode", choices=["none", "echo", "subtype"], default="none",
                    help="what to send back (default: nothing, log only)")
    ap.add_argument("--subtype", type=int, default=4,
                    help="value for body[1]; 4 is accepted in state 5, 3 in state 3")
    ap.add_argument("--crypto", choices=["echo", "zero", "copyhdr"], default="echo",
                    help="what to put in the 16 unknown bytes at +8")
    ap.add_argument("--body-len", type=int, default=56,
                    help="body length; the client sends 56 (52 + 2 + 2)")
    ap.add_argument("--peer", default=None,
                    help="allowlist of source IPs to answer, comma/space separated "
                         "(default: answer whoever asks). sec 4fq: each IP gets "
                         "its OWN session, so two clients can share one match.")
    ap.add_argument("--type", type=int, default=128, dest="ptype",
                    help="packet+8, the message TYPE. 128 (0x80) is what the client "
                         "itself sends. Dispatch arms exist for 0,1,2,3,4,126,127,128,254,255.")
    ap.add_argument("--flags", type=int, default=0,
                    help="packet+9. bit 3 (0x08) makes the client look up an ID at "
                         "packet+16; leave clear unless you have a valid ID.")
    ap.add_argument("--mode-byte", type=int, default=0,
                    help="packet[1], the cipher selector. 0 = NO-OP (0x00584364), "
                         "1 = the mode the client itself uses. Default 0.")
    ap.add_argument("--no-cksum", action="store_true",
                    help="leave the checksum field zero -- the client will then REPORT "
                         "its own computed value, which validates our implementation")
    ap.add_argument("--lobby-ip", default="127.0.0.1",
                    help="address handed to the client in the subtype-4 body as the "
                         "LOBBY server (body+12). Empty string leaves the body zeroed.")
    ap.add_argument("--lobby-port", type=int, default=55040,
                    help="port for the same redirect (body+10)")
    ap.add_argument("--sweep", action="store_true",
                    help="step through the SWEEP table, one candidate per connection "
                         "burst, printing a banner so the Nth error code the tester "
                         "reports matches the Nth banner")
    ap.add_argument("--once", action="store_true",
                    help="send a reply to the first datagram only, then log-only")
    ap.add_argument("--save", default=None, help="directory to write datagrams into")
    ap.add_argument("--lobby-probe", choices=["off", "echo", "advance"], default="off",
                    help="how to answer the LOBBY packets (the 96-byte, type-129 shape) as "
                         "opposed to the 80-byte entrance. 'advance' (RECOMMENDED) sends the "
                         "mode-0 selector-2 reply PROVEN offline to flip the UDATA nest 1->2 "
                         "and the main connection 7->8: expect DoC to leave "
                         "CER-48103 and enter the Kerberos event stage. 'echo' bounces the "
                         "client's own 96-byte packet back (only elicits a CTRL-24, never "
                         "advances). The 80-byte entrance always gets the subtype-4 redirect. "
                         "Watch the emulog for the phase change, not this log.")
    ap.add_argument("--lobby-sustain-selector", type=int, default=8,
                    help="body[1] of the SUSTAIN reply, sent to every 96-byte type-129 "
                         "packet. 8 routes (via the inbound router's jump table, index "
                         "selector-4) to the state-6 handler 0x00587c10, which advances "
                         "the nest 6->2; it then self-advances 2->6, re-stamping the "
                         "liveness field the 10s watchdog watches. PROVEN offline against "
                         "a live state-6 savestate of the lobby (doc_state6_router.py). "
                         "0 disables (old selector-2-only behaviour).")
    ap.add_argument("--lobby-sel2-count", type=int, default=1,
                    help="if non-zero, ALSO send the selector-2 (1->2) advance reply to every "
                         "96-byte packet (in addition to the sustain reply). selector-2 is a "
                         "no-op at every state except state 1, so this is always safe and needs "
                         "no per-connection tracking. 0 disables selector-2 entirely.")
    ap.add_argument("--lobby-extra-selectors", default="",
                    help="comma-separated EXTRA response codes to send after the main "
                         "reply, e.g. 14.  THE LADDER (sec 4ao, each handler gated on a "
                         "specific nest state, so every one is a no-op unless the client "
                         "happens to be in its state -- VERIFIED offline against the "
                         "state-6 savestate: of 2,8,10,12,14,16,18,20,22,24 only 8 moves "
                         "a state-6 nest):\n"
                         "  code  state  handler     what it does\n"
                         "   8     6     0x00587c10  the CHARACTER LIST (see --lobby-chara-*)\n"
                         "  10     8     0x00587ee0  BARE ACK (sets state 2, no payload)\n"
                         "  12     7     0x00587e50  returns ONE record via [nest+0xE8]\n"
                         "  14     9     0x00587ef0  BARE ACK (sets state 2, no payload)\n"
                         "  16    10     0x00587e98  returns ONE record via [nest+0xE8]\n"
                         "  18/20/22/24  0x00587f00/f98/fa8/ff0\n"
                         "State 9 is the interesting one: its REQUEST 0x005888f8 packs a "
                         "character record into a type-13 message using the exact INVERSE "
                         "of the 0x0058ad30 list permute (buf+58 -> wire+85 ...), which is "
                         "what create-a-character looks like -- and it only wants code 14, "
                         "an empty ack.  CER-48104 is the charamake server timing out.\n"
                         "WARNING: each entry is one MORE datagram per inbound packet, and "
                         "flooding the client receive ring is what killed the ACK sweep "
                         "(sec 4ae: 5 extra -> 38 s, from a 75 s baseline).  Send ONE.")
    ap.add_argument("--extra-subtypes", default="",
                    help="FALSIFIED LIVE 2026-08-24 -- DO NOT USE without re-proving it. "
                         "Sending subtype 3 alongside 4 BROKE the entrance handshake: the "
                         "boot regressed from catch error = -47110(phase 3) to -1(phase 1), "
                         "never printed connected entrance server, and left [conn+0xD0] = -2 "
                         "with the nest never opened (state 0). The connection PASSES THROUGH "
                         "state 3 during the normal handshake, so a subtype-3 message arriving "
                         "then is accepted at the wrong moment and derails it. The argument "
                         "that each subtype is state-gated so both are safe was an ANALOGY to "
                         "the nest selectors -- those were verified as no-ops against a live "
                         "savestate; this never was. Verify offline before re-enabling. "
                         "comma-separated EXTRA subtypes to ALSO answer each non-lobby "
                         "(80-byte type-128) packet with, e.g. 3.  MEASURED (0x00585fc4): the "
                         "inbound dispatcher reads the subtype at [record+1] and accepts\n"
                         "  subtype 3  ONLY when [conn+0xD0] == 3  -> 0x00585d28\n"
                         "  subtype 4  ONLY when [conn+0xD0] == 5  -> 0x00585ec8\n"
                         "and IGNORES every other subtype outright.  The connection sits in "
                         "state 3/4 through the whole lobby phase (savestate: [main+0xD0]=3), "
                         "so the fixed subtype-4 redirect we have always sent is DISCARDED "
                         "there -- which is why the two 00 01 requests go unanswered and the "
                         "retry timer raises CER-48104.  Each subtype is state-gated inside "
                         "the client, so sending both is safe: the one that does not match "
                         "the current state is a no-op (same reasoning as the nest selectors).")
    ap.add_argument("--frag3", action="store_true",
                    help="answer the LOBBY requests (80-byte type-128 packets whose body "
                         "tail is 00 01) with a SUBTYPE-3 fragmented response: parts=1, "
                         "index=0, payload from body[8] (handler 0x00585d28). Those two "
                         "requests -- 00 01 33 c1 and 00 01 b3 44 -- are what currently go "
                         "unanswered until the retry timer raises CER-48104. The entrance "
                         "packets (tail 00 02) are NEVER touched, which is the difference "
                         "from --extra-subtypes (falsified, sec 4aw).")
    ap.add_argument("--frag3-servers", default="",
                    help="comma-separated ip:port entries to put in the subtype-3 "
                         "payload as 12-byte server-list records, e.g. "
                         "127.0.0.1:55040. Empty sends a fragment with ZERO entries, "
                         "which registers the fragment but copies nothing. Full form is "
                         "ip:port[:id[:tail[:area]]]; `area` defaults to --frag3-area.")
    ap.add_argument("--frag3-area", type=lambda v: int(v, 0), default=1,
                    help="entry+8, the AREA/tab id the Select Server screen filters "
                         "on (0x00AB4598). The client keeps its own area code in "
                         "[0x001B5658] -- a link-time constant, measured 1 -- and "
                         "DROPS every row whose area id is neither that nor 0xFFFF. "
                         "We sent 0 for the life of this service, which is why the "
                         "list was always empty. 1 = the default tab, 0xFFFF = the "
                         "'all areas' tab.")
    ap.add_argument("--no-chara-on-request", dest="chara_on_request",
                    action="store_false", default=True,
                    help="answer the client's selector-7 with the chara code-8 straight "
                         "away (the old behaviour) instead of holding it until the 00 01 "
                         "request. Holding is the default because answering early is "
                         "MEASURED to lose: savestate 15:41:32 shows [nest+8]=2 with the "
                         "armed high bit clear -- the code-8 arm's own signature, so it "
                         "WAS accepted -- while [nest+0xF4] stayed untouched and holds "
                         "byte-identical garbage across three boots. The client had not "
                         "pointed that field at the real buffer yet. Not answering parks "
                         "the nest at 6 (armed) and the watchdog budget [nest+4]=40000 is "
                         "~20 s, while the 00 01 request lands ~4 s later.")
    ap.add_argument("--frag3-hold-s", type=float, default=0.0,
                    help="INSTRUMENT, not a fix. RED FLAG: phase 3 only tolerates about "
                         "SIX SECONDS. Holding longer times the poll out -- [conn+0xD0] "
                         "goes negative and the boot dies with -47110(phase = 3) / "
                         "CER-48104. MEASURED twice (holds of 30 s and 20 s, boots 15:41 "
                         "and 15:53), and it kills the run BEFORE phase 4 ever reads the "
                         "buffer, so anything downstream of phase 3 goes untested. Keep "
                         "any hold under ~5 s. After the selector-7 chara burst, hold "
                         "back the frag3 answer to the 00 01 request for this many "
                         "seconds. That answer is what releases phase 3, so holding it "
                         "parks the client in the poll and leaves [nest+8] and "
                         "[nest+0xF4] readable for as long as you like. [nest+8]==2 means "
                         "our code-8 WAS accepted and the count is not where we think it "
                         "is; ==6 means it never reached the handler and the offline "
                         "harness -- which calls the parser and router directly and models "
                         "none of the socket path -- has been lying (the sec 4ax trap). "
                         "0 = off.")
    ap.add_argument("--chara-burst", type=int, default=6,
                    help="how many copies of the CHARA code-8 to send when the client "
                         "transmits SELECTOR 7 -- the 2->6 arm 0x005884d0, the only thing "
                         "that opens nest state 6 and therefore the only window in which "
                         "handler 0x00587c10 will write the character count. The first "
                         "acceptance drops the nest to 2, and boot 13:22 saw exactly ONE "
                         "selector-7 in the whole session, so a single reply that loses a "
                         "50 ms race costs the entire boot. A code-8 outside state 6 is a "
                         "proven no-op (an offline run of the client's own code (doc_code8_wire_proof) sweeps states "
                         "0..7), so the extra copies are free. 1 = old behaviour.")
    ap.add_argument("--chara-burst-ms", type=int, default=25,
                    help="spacing between the --chara-burst copies, in ms.")
    ap.add_argument("--no-nest-close-answer", dest="nest_close_answer",
                    action="store_false", default=True,
                    help="do NOT answer the nest's selector-3 CLOSE request with a "
                         "selector-4 reply. On by default, because phase 110 cannot "
                         "pass without it: phase 109 (main-conn vtable+36 = "
                         "0x00586910) calls the nest's vtable+220 = 0x00587a98, which "
                         "sends selector 3 and sets [nest+8] = 4; phase 110 polls "
                         "0x00587b40, which returns 1 only at [nest+8] == 0; and the "
                         "only writer of 0 from 4 is the classifier's selector-4 arm "
                         "0x00589690. PROVEN offline against a live nest -- "
                         "an offline run of the client's own code (doc_close_proof) -- including the control that "
                         "selector 4 is a strict no-op in states 0,1,2,3,5,6,7, so it "
                         "cannot derail anything earlier. (Unlike the subtype-3 case "
                         "of sec 4aw: state 4 is written ONLY by the close path, so it "
                         "is genuinely terminal, not transited on the healthy path.)")
    ap.add_argument("--nest-quiet-after-frag3", type=int, default=0,
                    help="after this many subtype-3 frag replies have been sent, STOP all "
                         "nest traffic (code-8 answers to 36-byte packets, the selector-2 and "
                         "selector-8 replies to 96-byte packets, and the keepalive). 0 = never. "
                         "WHY: phase 110 polls 0x00587b40, which returns 1 only when the NEST "
                         "state [nest+8] is ZERO -- it waits for the nest to CLOSE. Every code-8 "
                         "sets [nest+8]=2, so a chatty responder pins the nest open and phase 110 "
                         "times out with -47111 / CER-48103 (MEASURED, boot 12:30: reached phase "
                         "110, died 70 s later, cursor frozen). SUPERSEDED: silence is NOT the "
                         "answer -- the nest does not close on its own, it closes on an inbound "
                         "SELECTOR 4 (see --no-nest-close-answer). Keep this at 0. But the nest "
                         "replies are REQUIRED "
                         "earlier -- with them off from the start the client never issues the "
                         "00 01 list requests and dies at phase 1 (MEASURED, boot 12:35). So it is "
                         "a SEQUENCING problem: chatty until the list is answered, silent after. "
                         "The frag3 reply is the natural trigger -- phase 4 follows it within "
                         "milliseconds and phase 110 comes after that.")
    ap.add_argument("--frag3-server-id", type=lambda x: int(x, 0), default=0,
                    help="entry+0 of every server-list entry, the default when "
                         "--frag3-servers does not carry one. The Select Server "
                         "screen (KelStr group 29) has a NAME column and a "
                         "`Players Connected` column and we have only ever "
                         "written 0 here; a distinct value says which column "
                         "reads it (the 2026-09-05 audit J).")
    ap.add_argument("--frag3-server-tail", type=lambda x: int(x, 0), default=0,
                    help="entry+10 of every server-list entry -- the other "
                         "unidentified column. See --frag3-server-id.")
    ap.add_argument("--frag3-parts", type=int, default=1,
                    help="body[4..5], the TOTAL part count of the subtype-3 response.")
    ap.add_argument("--chara-store", default="",
                    help="path to a JSON per-account character store (sec 4dq). "
                         "When set, REGISTER and DELETE PERSIST -- created "
                         "characters stick across reconnects, deletes take, and "
                         "each account (keyed by its entrance uid) sees its OWN "
                         "roster instead of the seeded --lobby-chara-* Quarrys. "
                         "Empty = the old fixed seeding.")
    ap.add_argument("--account", default="",
                    help="key the --chara-store by THIS account (e.g. member:3) "
                         "instead of the entrance uid. The uid is PER SESSION -- "
                         "measured rotating 0xa756a69a -> 0xa455a599 inside one "
                         "process -- so keyed on it a player's roster split and "
                         "their characters vanished between sessions. Also the key "
                         "the lobby reads for the DoC content profile. Empty = the "
                         "old uid keying (the emulator, dev).")
    ap.add_argument("--accounts-db", default="",
                    help="sec 4ft: key the --chara-store PER CLIENT by the POL "
                         "member signed in at that client's address -- the login "
                         "service's `session` table in accounts.db, opened "
                         "READ-ONLY. Supersedes --account, which is ONE key for "
                         "every client: with two machines in --peer it filed both "
                         "players' characters into one roster (2026-09-13: the "
                         "Deck's delete removed the PC's). Fallbacks: the member "
                         "last resolved at that address (doc-ip-members.json "
                         "beside the store), then an addr:<ip> key -- never a "
                         "shared bucket. Empty = --account, as before.")
    ap.add_argument("--chara-id-base", type=lambda x: int(x, 0), default=0x1000,
                    help="sec 4dv: the base for the CHARACTER ID written at "
                         "wire+0 of each roster record. That u32 becomes "
                         "[kelsvc+272] at lobby phase 25 -- the id getMyCharaId() "
                         "returns, the key the name plate and the battletable "
                         "check look themselves up by, and the value the client "
                         "then stamps into record+4 of every message it sends. "
                         "We shipped 0 for every character ever created, which "
                         "is why the client looked itself up as id 0. 0 here "
                         "restores that old behaviour. Bits 30/31 are masked "
                         "off on purpose (sec 4bw peer-table side, sec 4ch "
                         "sign-extending cache key).")
    ap.add_argument("--bt-start-ready", action="store_true", default=False,
                    help="sec 4ex (2026-09-11): clamp the SERVED battletable "
                         "current-participants field (BT_OFF_CUR) to >= 2 so the "
                         "'Start Immediately' gate (0x00aa0d98: [config+2] >= 2 "
                         "OR FLAGS & 0x00010000) passes for a SOLO leader. Without "
                         "it a solo-created table serves cur=1 and the client "
                         "shows 0x683b 'Conditions for victory are not configured. "
                         "Battle cannot begin.' The gate reads the SERVER-served "
                         "browser-list record, not the player's menu edits, so "
                         "this is the only lever. Pairs with --gs-fake-teammates "
                         "for the actual battle roster. Cosmetic: the browser then "
                         "shows the table as 2/max.")
    ap.add_argument("--world-self-charaid", action="store_true", default=False,
                    help="sec 4ev (2026-09-11): on the world-door answer "
                         "(selector 2), OVERRIDE body[44..47] with the client's "
                         "CHARAID (seen_charid = [kelsvc+272], record+4 of its "
                         "requests) instead of echoing the UID from the session "
                         "token. mgr+304 [rec+52] (the battletable-data manager's "
                         "self record key) is set from body[44]; keying it by the "
                         "UID while getMyReservationTableId() looks up by charaid "
                         "-> a self-lookup MISS -> the getter returns an "
                         "uninitialised buffer value the 0x6835 'already reserved' "
                         "gate reads (sec 4eu). Charaid here makes the lookup HIT "
                         "a clean record -> 0xffff -> Create allowed. WARNING: "
                         "body[44] overlaps the echoed session token (token+16); "
                         "if the client re-validates the token this may disturb "
                         "world entry -- OFF by default, revert by dropping it.")
    ap.add_argument("--self-hp", type=int, default=100,
                    help="2026-09-13: the player's HP, written as a u32 at body[48..51] "
                         "of the world-door answer (selector 2) -- world-door "
                         "record+4, which setUserData 0x00be6580 copies into the "
                         "self record's CURRENT (R+44) and MAX (R+752) HP. We used "
                         "to echo the session token there: HP read -31166/-31166. "
                         "WARNING: 100 is a PLACEHOLDER until real per-character stats "
                         "are served. 0 = echo the token as before. With "
                         "--suit-hp on this is only the fallback for a login "
                         "whose suit is unknown.")
    ap.add_argument("--suit-hp", default="on", choices=("on", "off"),
                    help="2026-09-24: the world-door HP follows the EQUIPPED SUIT "
                         "(body[80]) through the retail durability table "
                         "(doc_gear.suit_hp: Sniper 210, Speed 240, Magic 250, "
                         "Soldier 270, Toughness 340; bgd.bin block +0x3fc). "
                         "off = --self-hp for everyone.")
    ap.add_argument("--shop", default="",
                    help="sec 4gk: path to the per-character wallet + bag JSON. "
                         "When set, the lobby's shop lists (64 stock, 141 recipes, "
                         "143 prices) are served, a 145 item transaction gets a "
                         "real 146 verdict (check gil, apply, persist), and the "
                         "world-door answer carries the character's gil (body[52]) "
                         "and bag (body[140]/[240+]). Empty = OFF: the old empty "
                         "answers, and the echoed token as gil.")
    ap.add_argument("--shop-stock", default="",
                    help="JSON stock/price override for --shop: {\"start_gil\": N, "
                         "\"stock\": [{\"id\": \"0x69320000\", \"price\": 50}, ...]}. "
                         "Empty = doc_shop.DEFAULT_STOCK (the 2006 retail guides' "
                         "prices, 2026-09-26).")
    ap.add_argument("--shop-start-gil", type=int, default=None,
                    help="gil a character's wallet starts with (default: the "
                         "--shop-stock file's start_gil, else %d)"
                         % doc_shop.START_GIL)
    ap.add_argument("--no-trade", dest="trade", action="store_false", default=True,
                    help="sec 4gk addendum 5: do NOT relay player-to-player trades "
                         "(41 invite / 43 offer / 47 confirm / 49 cancel -> pushes "
                         "42 / 44 / 50 / 48, wallets swapped on both confirms). "
                         "Trading is on whenever --shop is.")
    ap.add_argument("--issue-ammo", default="standard",
                    help="sec 4go (2026-09-13): bullets are INVENTORY ITEMS and "
                         "the magazine fills from them (0x004a5780), so an "
                         "empty bag = a gun that never fires. Tops the "
                         "world-door bag up to these every login, NOT "
                         "persisted, with or without --shop. 'standard' = 36 "
                         "handgun / 18 rifle / 60 MG (the standard "
                         "mission supplies), 'off', or 'ID:QTY,...'.")
    ap.add_argument("--issue-gear", default="standard",
                    choices=["standard", "off"],
                    help="2026-09-13: the Status window's Mask/Armor rows list the "
                         "bag's masks (0x6330xxxx) and suits (0x6331xxxx) and name "
                         "the EQUIPPED pair, which the world door carries at "
                         "body[76] (mask) / body[80] (suit). 'standard' issues DG "
                         "Soldier Mask M or F (by the selected character's "
                         "gender) + DG Soldier Suit into the bag and equips "
                         "them, every login, NOT persisted. 'off' = the old "
                         "blank rows (body[80] echoes the request).")
    ap.add_argument("--gear-store", default="auto",
                    help="2026-09-13: CHANGE MASK / CHANGE ARMOR (lobby commands "
                         "17 equip / 18 unequip, doc_gear.py) persisted per "
                         "character: answered with the new costume code at 241 "
                         "body[6] (the generic zero answer reset the look) and "
                         "served back on the world door. 'auto' = doc-gear.json "
                         "next to the --shop file (off without --shop), a path, "
                         "or 'off'.")
    ap.add_argument("--rankings", default="",
                    help="2026-09-13: path to the rankings JSON. When set, the "
                         "lobby's Ranking menu (137 Individual -> 138, 149 Unit "
                         "-> 150) is answered with real rows: every character "
                         "in the chara store, ranked on the file's values (0 "
                         "when absent). Empty = the old generic echo, which "
                         "put the page size (30) in the row count and drew 30 "
                         "empty rows. See tools/doc_rank.py.")
    ap.add_argument("--solo-quests", default="1-8,16-40",
                    help="2026-09-13: quest ids the Solo Battle (story mode) "
                         "list offers, answering selector 159 -> 160. Id N is "
                         "named by KelStr group 47 index N-1: 1-8 = the rank "
                         "exams, 9-15 = exams whose text says 'Not yet "
                         "implemented' (left out), 16-36 = named missions. "
                         "2026-09-23: the served (retail-rebased) table has 43 "
                         "rows; 39/40 = Beginner's Course I/II (jungle, real "
                         "briefing text, 300/500 gil). 37/38/41 (Train "
                         "Graveyard / Battlefield Ruins, zones 212/231: no floor "
                         "point yet) and 42/43 (briefing 'Not yet implemented.') "
                         "are left out. "
                         "With --mission-ledger the exams among these are "
                         "gated by the instructors. Empty = the old empty list.")
    ap.add_argument("--mission-npc-types",
                    default="3001:3,3,3,3,3,3,0,0;3004:1;4,0,5,6,7,8,9,10,11,12",
                    help="2026-09-23: kind-15 TYPE per mission NPC slot (cycled). "
                         "The controller record carries no type; live, types 1, 4 "
                         "and 52 spawned SOLID but INVISIBLE enemies at the "
                         "controller's spawn nodes. A SWEEP: each slot gets its own "
                         "type and the log names id -> type, so a live look pins "
                         "which value draws the mission's model. Empty = the "
                         "arena test types. 'SIT:t,t;SIT:t;default' sets them per "
                         "situation: live, every type drew situation 3000's "
                         "dog, which reads as type = INDEX into the situation's "
                         "loaded model list (bzd table 20: 3001 = e030 dog, w010, "
                         "w003, e102; 3004 = w003, e102) -- e102 = index 3 / 1.")
    ap.add_argument("--respawn-kind", type=int, default=13,
                    help="2026-09-23: notify kind pushed about a KO'd member when "
                         "the room's respawn delay elapses; kind 25 (dead bits + "
                         "respawn point) goes out with each counted death. 13 = "
                         "retail respawn: HP max and the state word back to 0. "
                         "18/19 revive the HP but leave state 1 (INVINCIBLE, live "
                         "09-23). 0 = never (down until the battle ends).")
    ap.add_argument("--phoenix-hp", type=int, default=0,
                    help="unused since 2026-09-23 (request 43 is the kill-notice "
                         "ack, not a Phoenix Down); kept so old command lines run.")
    ap.add_argument("--item-use-answer", default="item", choices=("item", "off"),
                    help="2026-09-23: answer game-server request 21 (USE ITEM, "
                         "item id at body+8 -- a Potion in battle) with message "
                         "22 {ident = the player, body+8 = the item id}. 'off' = "
                         "unanswered, as before (the client resends and nothing "
                         "happens).")
    ap.add_argument("--mp-model", default="ledger",
                    choices=("ledger", "full", "zero"),
                    help="2026-09-24: game-server request 60 (MAGIC CAST, arg = "
                         "element | level << 16) is answered with message 61 "
                         "{status 0, MP} and the client takes that MP. 'ledger' "
                         "(tools/doc_magic.py): 100 per battle, each cast charged "
                         "its cost once (resends recognised by their schedule), "
                         "Magic Suit x0.6, 0 on a Magic-restricted table. 'full' = "
                         "always 100 (unlimited casting). 'zero' = the old generic "
                         "answer (MP 0 after the first cast).")
    ap.add_argument("--mp-respawn", default="full", choices=("full", "keep"),
                    help="2026-09-24 (--mp-model ledger): on a KO respawn push "
                         "notify kind 44 with MP 100 ('full', OURS -- the client "
                         "never refills MP on a respawn by itself) or leave the "
                         "MP the player died with ('keep').")
    ap.add_argument("--base-occupy", default="on", choices=("on", "off"),
                    help="2026-09-26: TEAM BASE win = destroy + OCCUPY (the "
                         "January Additional Manual). 'on': a base at HP 0 "
                         "opens an occupation phase; a living member of the "
                         "destroying team standing within --base-occupy-radius "
                         "of the base spot (its type-0x83 pose) for "
                         "--base-occupy-s unbroken seconds wins, and gets the "
                         "Assault medal. 'off' = the old rule: HP 0 ends the "
                         "battle at once.")
    ap.add_argument("--base-occupy-radius", type=float,
                    default=BASE_OCCUPY_RADIUS,
                    help="OURS (2026-09-26): horizontal distance from the base "
                         "spot (BASE_POSITIONS) that counts as standing on it.")
    ap.add_argument("--base-occupy-s", type=float, default=BASE_OCCUPY_S,
                    help="OURS (2026-09-26): seconds the occupation must last "
                         "(the manual's 'a set time'; no source prints it).")
    ap.add_argument("--mp-points", default="off", choices=("on", "off"),
                    help="2026-09-26 (tools/doc_items.py): MP POINTS. 'on': a "
                         "battle that is not a mission gets notify kind 28 with "
                         "rec[2] = 64 and every mask bit set, so the client's "
                         "zone setup creates the situation's MP points (bzd "
                         "type-8 nodes; the zero record made none), and each "
                         "P2P 117 (touching one with MP below max) is credited "
                         "and pushed with kind 44. 'off' (the default since "
                         "2026-09-26) = the old zero kind 28, 117 ignored: the "
                         "January Additional Manual P.031 moved MP recovery "
                         "from Mako Points to the Ether item, MP full at the "
                         "battle start (a January 2006 player "
                         "blog also reports Mako Points gone). Missions still send their NPC-controller "
                         "28 either way.")
    ap.add_argument("--mp-point-amount", type=int,
                    default=doc_items.MP_POINT_AMOUNT,
                    help="OURS (2026-09-26): MP one MP-point credit adds (the "
                         "client leaves the amount to the server; retail's is "
                         "unknown).")
    ap.add_argument("--mp-point-every", type=float,
                    default=doc_items.MP_POINT_EVERY,
                    help="OURS (2026-09-26): seconds between credits from one MP "
                         "point to one player (the client sends a 117 every "
                         "frame it stands in range).")
    ap.add_argument("--item-use-broadcast", default="on", choices=("on", "off"),
                    help="2026-09-26: send message 22 (the item's effect) about a "
                         "use to every member of the room, not only the user -- "
                         "its arm looks the ident up in the teammate records too "
                         "(0x00bdfb20), so others play the effect on that unit. "
                         "'off' = the user only.")
    ap.add_argument("--mission-ledger", default="on", choices=("on", "off"),
                    help="2026-09-23: MISSION MODE per player (tools/doc_missions.py, "
                         "needs --stats). 'on': the instructors (lobby NPCs 7-10) "
                         "answer command 26 from the career -- no battle yet / "
                         "fewer than three / not enough rank points / the exam "
                         "AUTHORIZED, which adds it to the player's mission "
                         "ledger -- and selector 159 -> 160 lists that ledger's "
                         "exams plus --solo-quests minus every exam. 'off' = the "
                         "old static --solo-quests list for everyone and the "
                         "instructors' greeting.")
    ap.add_argument("--no-quest-mission", dest="quest_mission",
                    action="store_false", default=True,
                    help="2026-09-13: do NOT turn a Start that follows a Solo "
                         "quest pick (lobby command 41) into a MISSION battle. "
                         "By default the next BATTLE READY (38) after a pick "
                         "carries flags 0x00010000 and mission id = the quest "
                         "id; without it the quest plays as a team battle.")
    ap.add_argument("--quest-situations", default="",
                    help="with the quest mission: QUEST:SITUATION pairs "
                         "(e.g. 17:3001) for 38's situation id, the arena "
                         "resource set (3000+ = mission sets). Unlisted = keep "
                         "the table record's own situation. Mapping unknown.")
    ap.add_argument("--quest-zones",
                    default="5:208,16:208,31:208,20:201,30:201,32:201,"
                            "18:204,27:204,33:204,19:205,24:205,34:205,"
                            "23:203,35:203",
                    help="with the quest mission: QUEST:ZONE pairs for notify "
                         "kind 2's arena zone (rec+26) -- the ARENA; 38's map "
                         "index is list display only. Default = the place each "
                         "quest's own description names, matched to zonelist by "
                         "NAME (church 208, Kalm 203, wastelands 204, sewers "
                         "205, jungle 201) -- inferred, not SE data. Unlisted "
                         "quests keep --gs-battle-zone. Empty = all keep it.")
    ap.add_argument("--zone-spawns",
                    default=ZONE_SPAWNS_DEFAULT,
                    help="ZONE:x,y,z entries separated by ';' -- kind 2's spawn "
                         "position (record +0/+4/+8) when the arena is that "
                         "zone. Unlisted zones use --gs-battle-pos (a z201 "
                         "point: live 09-13 it put the player in the VOID of "
                         "z208, the church). Defaults: a floor point from each "
                         "zone's COLLISION mesh (m0xx/mapid.rfd, up = -y, "
                         "2 units above the floor) near its gmap.class map "
                         "centre -- no SE script sets a spawn in these online-"
                         "only zones. 205 has two floor levels (400/365).")
    ap.add_argument("--quest-pick-window", type=float, default=300.0,
                    help="seconds a quest pick stays armed for the next Start")
    ap.add_argument("--rankings-hide-zero", action="store_true",
                    help="with --rankings: list only characters with a nonzero "
                         "value in the asked-for category")
    ap.add_argument("--npc-este-accept", type=float,
                    default=doc_npcquests.ESTE_ACCEPT,
                    help="2026-09-24: the chance Este-D keeps a Dandelion and "
                         "gives the Gasmask (chance decides, per the "
                         "fan archive; no odds published and the player "
                         "guides call it rare -> default %(default)s, OURS). 1 = always, 0 = never.")
    ap.add_argument("--npc-hiren-wither", type=float,
                    default=doc_npcquests.HIREN_WITHER_DAY,
                    help="2026-09-26: Hiren's seed WITHERS when more than this "
                         "many --npc-quest-day days pass between two visits "
                         "while it grows (a January 2006 player blog: about "
                         "once per real day; the exact window is OURS). "
                         "0 = never withers.")
    ap.add_argument("--fuzzy-seed", choices=doc_npcquests.SEED_MODES,
                    default="field",
                    help="2026-09-26: where Hiren's Fuzzy Seed comes from. "
                         "field = ONE on Collector's Mind's field at SE's own "
                         "church generator node (z208 item set 7, the seed at "
                         "100 %%), the picker's server bag credited on the "
                         "pick-up (the fan archive: the seeds are found in "
                         "the Collector's Mind mission); clear = the "
                         "old OURS rule, one per clear; off = none.")
    ap.add_argument("--npc-quest-day", type=float, default=86400.0,
                    help="2026-09-24: seconds per DAY of Hiren's seed "
                         "(2026-09-26: bloom day 5 = the players' 120 h; "
                         "sprout day 2 / bud day 4 OURS). Lower it to test "
                         "the chain quickly.")
    ap.add_argument("--battle-drop-s", type=float, default=90.0,
                    help="2026-09-26: a member of a RUNNING battle whose client "
                         "has sent nothing for this many seconds dropped off "
                         "the line: it leaves the room and, per SE's January "
                         "Additional Manual, loses --leave-rp-penalty rank "
                         "points like a return to the lobby. Default = "
                         "--keepalive-idle-s's 90 (the window already used to "
                         "decide a peer left). 0 = off (a silent member stays "
                         "in the room until the session reaper).")
    ap.add_argument("--leave-rp-penalty", type=int,
                    default=doc_stats.LEAVE_RP_PENALTY,
                    help="2026-09-24: rank points taken from a player who "
                         "RETURNS TO LOBBY (command 4) out of a battle still "
                         "running -- the client's own warning 0x5c0d 'Leaving "
                         "a battle partway through will reduce your rank "
                         "points'. 2026-09-26: default 10, SE's PlayOnline "
                         "Additional Manual; 0 = off. Needs "
                         "--stats.")
    ap.add_argument("--weekly-medals", choices=("on", "off"), default="on",
                    help="2026-09-26: award the four WEEKLY medals (60:[35..38] "
                         "Weekly Rank Points / Defeats / Team Wins / Solo Wins "
                         "1st = medal ids 19..22) when the server clock crosses "
                         "a week boundary, and on startup for any ended week "
                         "not yet closed (the server was down over the "
                         "rollover). Each goes to the week's UNIQUE leader "
                         "with a count above zero; a tie awards nobody "
                         "(doc_stats.WEEKLY_MEDALS). The medal shows in the "
                         "winner's next world-door mask. The week's tallies "
                         "are kept either way; off = never closed. Needs "
                         "--stats.")
    ap.add_argument("--week-start", default=doc_stats.WEEK_START,
                    type=_week_start_arg,
                    help="2026-09-26: when a weekly-medal week starts, 'DAY "
                         "HH:MM +HH:MM' (default %(default)r = Monday "
                         "00:00 JST).")
    ap.add_argument("--test-clock-offset", type=float, default=0.0,
                    help=argparse.SUPPRESS)   # TEST ONLY: seconds added to the
                                              # career / weekly clock
    ap.add_argument("--chocobo-coins", choices=("on", "off"), default="on",
                    help="2026-09-26: pay every Chocobo Coin (0x67300001) a "
                         "player picked up in a battle or mission 1000 gil at "
                         "the end (9 at most, FFCheats) and cut them from its "
                         "bag (kind 21) before the result. off = coins stay "
                         "in the bag and pay nothing (the old behaviour).")
    ap.add_argument("--battle-capture", default="",
                    help="2026-09-24: append one JSON line per relayed P2P "
                         "battle datagram and per game-server request (not "
                         "keepalives) to this file -- type, sender, target, "
                         "table, the whole payload. For matching in-battle "
                         "events (heal, capsule, base, flag) to the messages "
                         "that carry them; the Base Attack medal (base "
                         "damage per attacker) still needs one. Empty = off.")
    ap.add_argument("--stats", default="",
                    help="2026-09-13: path to the CAREER store JSON "
                         "(tools/doc_stats.py). When set: the world door carries "
                         "the medal mask / rank points / rank (body[56]/[68]/"
                         "[131]), the Status window's 139 is answered with the "
                         "140 career record (W-L, per-mode results, medal "
                         "counts), the battle END's kind-4 carries the outcome "
                         "and the new rank-point / gil TOTALS (the old zero "
                         "record set both to 0 on screen), and every battle is "
                         "tallied into the store, the --rankings values and the "
                         "Viewer profile. Empty = the old behaviour.")
    ap.add_argument("--units", default="",
                    help="2026-09-13: path to the units JSON. When set, Unit "
                         "Management is answered for real: lobby commands 24 "
                         "(unit info), 13 (areas), 25 (my units), 8 (register), "
                         "12 (modify), 9 (delete), 10 (enlist), 11 (leave), and "
                         "the enlisted unit rides the world door (body[60]). "
                         "Registered units also appear in --rankings' Unit "
                         "Ranking. Empty = the sec 4dy zeroed answer ('you have "
                         "no units'). See tools/doc_unit.py.")
    ap.add_argument("--intro", default="on", choices=("on", "off"),
                    help="2026-09-23 (sec 4hc, tools/doc_novice.py): play the "
                         "retail NEW-PLAYER INTRO once per character -- push "
                         "selector 134 sub-kind 10 event 1 after the lobby spawn "
                         "(selector 13); the client exits to zone 240 (ev2100 "
                         "prologue) -> 241 -> 242 -> lobby and confirms with "
                         "command 27 id 1, which is recorded (career field "
                         "intro_seen) so it never plays again. Needs "
                         "--lobby-zone (sec 4hg addendum 4): the return from "
                         "zone 242 loads the zone in [mgr+0xd94], which the "
                         "world-door answer fills at body[42..43].")
    ap.add_argument("--intro-delay", type=float, default=2.0,
                    help="seconds after the selector-13 lobby spawn before the "
                         "intro push goes out (default 2.0)")
    ap.add_argument("--novice", default="on", choices=("on", "off"),
                    help="2026-09-23 (sec 4hc): the NOVICE ('Beginner') mark. A "
                         "character is a novice until --novice-kills career "
                         "kills or command 33 (the Cactuar 'Beginner's Machine'); "
                         "novices get world-door body[129] bit 0x40 and peer "
                         "FLAGS bit 0x40, graduation is pushed to every lobby "
                         "client as selector 134 sub-kind 11 and recorded "
                         "(career field novice_cleared).")
    ap.add_argument("--novice-kills", type=int,
                    default=doc_novice.KILLS_TO_GRADUATE,
                    help="career kills that remove the novice mark (SE: 20)")
    ap.add_argument("--novice-tables", default="enforce",
                    choices=("enforce", "open"),
                    help="Novice battletables (flags bit 0x04000000, which the "
                         "client sets itself when created from the Novice "
                         "menu): 'enforce' refuses a JOIN by a non-novice, as "
                         "SE's text says ('open only to novice players'); "
                         "'open' lets anyone in.")
    ap.add_argument("--leader-tag", default="on", choices=("on", "off"),
                    help="2026-09-24 (EXPERIMENT): in a Team Leader battle (mode "
                         "byte 5) rename each team's leader '%sName' in the other "
                         "members' peer tables (unsolicited selector-37 answer) "
                         "at the start, and restore it at the end. The client has "
                         "no leader display of its own." % "[L]")
    ap.add_argument("--rp-tables", default="enforce", choices=("enforce", "open"),
                    help="2026-09-26: a table's Minimum / Maximum RP (record "
                         "+64 / +60, flags 0x00100000 / 0x00080000): "
                         "'enforce' refuses a JOIN / RESERVE by a character "
                         "whose career rank points are outside them (the limits "
                         "are the table's game rules; refusal result %d, "
                         "OURS); 'open' ignores "
                         "them. Needs --stats." % BT_REFUSE_RP)
    ap.add_argument("--unit-tables", default="enforce", choices=("enforce", "open"),
                    help="2026-09-24: UNIT battletables (flags 0x01000000, needs "
                         "--units). 'enforce' = SE's 28:197: a JOIN is refused "
                         "(-6) unless the joiner's unit is one of the first two "
                         "units seated; 'open' lets anyone in. Either way the "
                         "sides are seated by unit and the result pays each unit "
                         "(doc_unit.record_battle).")
    ap.add_argument("--npc", default="on", choices=("on", "off"),
                    help="2026-09-13: answer the lobby NPC quest-event commands "
                         "(26 check -> the NPC's event id at 241 body[6], 27 done "
                         "and 39 clear -> clean acks). 'off' = the generic 241, "
                         "whose zero body[6] reads as event 0 (the lobby intro). "
                         "See tools/doc_npc.py.")
    ap.add_argument("--npc-events", default="",
                    help="overrides for command 26. TRIGGER:EVENT pins the "
                         "walk-up answer ('7:1180'); TRIGGER:B:EVENT pins one "
                         "follow-up, where B is the scene's sub-code ('4:2:305' "
                         "= what Argento says once the player accepts). Default: "
                         "each NPC's greeting id, else its table's first id, and "
                         "doc_npc.FOLLOWUP for a known (trigger, b); unknown "
                         "triggers are answered 0xffff")
    ap.add_argument("--npc-spawn", default="off", choices=("on", "off"),
                    help="2026-09-13 (static, not yet confirmed on a console): push the lobby "
                         "NPCs the way the game server did -- notify kind 15 'Add "
                         "Npc' with the 33 standing zone/z217/bzd.bin actors, "
                         "--npc-spawn-delay seconds after the client's in-world "
                         "stream starts. OFF by default: live-untested.")
    ap.add_argument("--npc-spawn-delay", type=float, default=10.0,
                    help="seconds after the in-world stream starts before the "
                         "NPC push (default 10: well after ev2046.main has picked "
                         "vl_main, which is what 38-at-entry used to derail)")
    ap.add_argument("--npc-spawn-ready", default="38", choices=("38", "none"),
                    help="how the game-server channel is made READY first. The "
                         "client drops every game-server message but type 29 "
                         "while [chan+2148] is 0, and only selector 38 sets it. "
                         "38 also posts facade 0x208 (the briefing-room flags) -- "
                         "read as harmless mid-lobby, NOT yet confirmed on a console. 'none' = "
                         "send kind 15 alone (dropped unless already ready)")
    ap.add_argument("--npc-spawn-type", default="idx",
                    choices=doc_npc_spawn.TYPE_MODES,
                    help="what goes in entry +8 (the NPC type; its model reader is "
                         "unread): idx = bzd record index (default), num = the "
                         "lnpc number, chr = the bzd type/model field")
    ap.add_argument("--npc-spawn-only", default="",
                    help="lnpc numbers to push, e.g. '4,31,32,33' (default: all)")
    ap.add_argument("--npc-spawn-hp", type=int, default=doc_npc_spawn.DEFAULT_HP,
                    help="entry +4, the NPC's HP")
    ap.add_argument("--npc-spawn-via", default="wu", choices=("wu", "kind15"),
                    help="sec 4gs addendum 5: 'wu' (default) = TYPE-125 world "
                         "updates with nibble-4 ids (0x4000_0000|lnpc, wire+4 = "
                         "bzd record index) -- the client registers them itself "
                         "(0x00bd2358) and builds the bzd chara; no game-server "
                         "channel, no selector 38. 'kind15' = the old notify-15 "
                         "push behind --npc-spawn-ready (38 = BRIEFING ROOM live)")
    ap.add_argument("--npc-spawn-name", default="bzd",
                    choices=doc_npc_spawn.NAME_MODES,
                    help="wire+6 of each NPC record, read by the lobby name plate "
                         "(0x00ace9e0) as a bzd TABLE-0 record index whose +154 "
                         "(the lnpc number) picks msgid 0xd3ff + n: bzd = the bzd "
                         "record index (default); msgid/index/none reproduce "
                         "the '!!na!!' plates seen live 09-13")
    ap.add_argument("--npc-spawn-every", type=float, default=5.0,
                    help="under --npc-spawn-via wu, resend the NPC world updates "
                         "this often while the lobby stream is live (s; 0 = once)")
    ap.add_argument("--npc-arena", default="off", choices=("on", "off"),
                    help="2026-09-13 (sec 4gs addendum 4): the kind-15 TEST where "
                         "the game-server channel is already open -- "
                         "--npc-arena-after s after the battle GO (--gs-battle-go), "
                         "push one NPC per --npc-arena-types value in a ring "
                         "around the arena spawn. Asks only: does kind 15 draw, "
                         "and which type draws what. No selector 38.")
    ap.add_argument("--npc-arena-after", type=float, default=5.0,
                    help="seconds after the battle GO before the arena ring")
    ap.add_argument("--npc-arena-types", default=doc_npc_spawn.ARENA_TYPES_DEFAULT,
                    help="entry +8 values, one NPC each, placed in this order "
                         "counter-clockwise from +x (default "
                         + doc_npc_spawn.ARENA_TYPES_DEFAULT + ")")
    ap.add_argument("--npc-arena-radius", type=float, default=150.0,
                    help="ring radius around the arena spawn, world units")
    ap.add_argument("--unit-fee", type=int, default=0,
                    help="with --units: gil charged to register or modify a unit "
                         "(answer body[6]; the client deducts it, and a --shop "
                         "wallet pays it too). SE's figure is not known; 0 = free.")
    ap.add_argument("--no-self-name", dest="self_name", action="store_false",
                    default=True,
                    help="2026-09-13: do NOT write the selected character's name "
                         "into body[112..127] of the world-door answer (character "
                         "record +68 -> self record R+704). Without it the own "
                         "table's owner and the own team entry read blank.")
    ap.add_argument("--chara-chrcode", type=lambda x: int(x, 0), default=None,
                    help="APPEARANCE EXPERIMENT (sec 4dr, 2026-09-10). Stamp this "
                         "64-bit 'chr code' into wire+0x10..0x17 (LE) of every "
                         "USED roster record (needs --chara-store). The o099 "
                         "costume builder 0x006ec748 reads a 64-bit word from "
                         "[actor+0x440]: bit32 = gender (0='m',1='f'), bit33 = "
                         "face-model flag, then a 6-bit cursor walks the six part "
                         "variants ((code>>34)&0xff and (code>>42)&0xff are two of "
                         "them). Whether the LIST record feeds that word is the one "
                         "unproven link -- so serve a KNOWN value, select the "
                         "character, enter, and read the emulog: `chr load request "
                         "[o099][0x%%08x]`, `chr resource loaded o099 [...]`, and "
                         "the `o099_f_NN` resource names. If they change, this field "
                         "IS the appearance and we can dress from --chara-store; if "
                         "not, the costume rides the user-data/JVM path (sec 4dt). "
                         "Suggested first value 0x0000302b00000000: bit32=1 "
                         "(female), bit33=1 (face flag), (>>34)&0xff=0x0a and "
                         "(>>42)&0xff=0x0c (two part variants) -- a male default "
                         "reads 0, so female is the clean single-bit discriminator. "
                         "None = off (record stays name+used).")
    ap.add_argument("--self-costume-probe", action="store_true",
                    help="APPEARANCE OFFSET PROBE (sec 4dr, 2026-09-11). Stamp "
                         "distinct u16 markers across body[96..112] of the "
                         "selector-2 and selector-13 world-answer replies (base "
                         "0xB000 for sel 2, 0xC000 for sel 13; marker at body[N] "
                         "= base|N). The self avatar's costume code X is stored "
                         "at [0x009f3f88] from a field of that reply; boot ONCE, "
                         "enter the lobby with a character, take a savestate and "
                         "read [0x009f3f88] -- e.g. 0xB068 means the selector-2 "
                         "reply, X at body+0x68 (body+104). That pins the exact "
                         "wire offset with no guessing on the entry path (the "
                         "window is past the session token and clear of the "
                         "body[140] SE-crash count). OFF by default; inert "
                         "diagnostic. Then --self-costume packs the real code "
                         "there. See the 2026-09-05 audit.")
    ap.add_argument("--self-costume", type=lambda x: int(x, 0), default=None,
                    help="DRESS THE LOBBY AVATAR (sec 4dr, offset LIVE-pinned "
                         "2026-09-11). Pack this 16-bit costume code into body+100 "
                         "of the selector-2 world-door reply -- the field the "
                         "client stores at [0x009f3f88] and the o099 builder "
                         "0x006ec748 dresses from (repacker 0x005a2598: gender = "
                         "bit6, faceFlag = NOT bit7, varA = faceFlag?(x>>10)&3:"
                         "(x>>6)&0x3c, varB = (x>>3)&7, varC = x&3). e.g. 0x0000 = "
                         "male all-default; 0x0040 = female. None = off (leave the "
                         "field as-is). WARNING: dresses the OWN lobby avatar only; the "
                         "character-select preview is a separate source. The "
                         "app92/app93 charamake nibbles -> this code mapping is "
                         "not yet located, so this is a RAW code for now; "
                         "--chara-store-driven auto-dressing is --self-costume-auto.")
    ap.add_argument("--self-costume-auto", action="store_true",
                    help="AUTO-DRESS the lobby avatar from --chara-store (sec 4dr). "
                         "On the selector-2 world-door reply, read the SELECTED "
                         "character id from the request (body+80, u32 -- MEASURED), "
                         "match it to the account's roster, and pack "
                         "doc_charastore.chr_code(that char) into body+100 so the "
                         "avatar wears the created face/armor/color. Needs "
                         "--chara-store. --self-costume (raw) overrides it. The "
                         "nibble->variant mapping is our own (SE's is lost) but "
                         "deterministic; refine chr_code if an element is on the "
                         "wrong slot. OFF by default.")
    ap.add_argument("--self-costume-file", default=None,
                    help="LIVE COSTUME CALIBRATION (sec 4dr). Path to a file whose "
                         "contents (a hex/int u16, e.g. 0x0402) are read FRESH on "
                         "every selector-2 reply and packed at body+100, overriding "
                         "--self-costume and --self-costume-auto. Lets the costume "
                         "code be changed with a plain file write and one lobby "
                         "re-entry -- no container recreate -- to map the creation "
                         "menu numbers onto the o099 part variants by eye. Empty or "
                         "missing file = fall through to auto/raw. Remove when done.")
    ap.add_argument("--lobby-chara-count", type=int, default=-1,
                    help="THE CHARACTER LIST.  If >=0, every code-8 (selector-8) reply "
                         "carries a character-select payload: body[17] = this count and, "
                         "if non-zero, that many 96-byte records from body[20].  The "
                         "state-6 handler 0x00587c10 copies them into the game buffer at "
                         "[nest+0xF4] (16 slots x 96 B + a 16-byte header -- the arithmetic "
                         "the emulog set chara data buffer 1552 confirms).  -1 = off, which "
                         "keeps the known-good sustain reply (body[17] forced to 0 = zero "
                         "characters, three blank rows).  MAX %d per message: the client "
                         "decodes into a 560-byte stack record and a sixth would overwrite "
                         "its saved return address." % CHARA_MAX_RECORDS)
    ap.add_argument("--lobby-chara-allow", type=int, default=-1,
                    help="body[16] -> buf[1], the byte NEXT to the count.  Believed to be "
                         "the slot allowance / create-character permission, but that is "
                         "INFERENCE: the UI that reads it lives in lobby.pex, never "
                         "disassembled.  NB it has never been zero -- the sustain reply "
                         "reuses the client token, whose byte 16 is 0x4c (76) in every "
                         "captured packet, and no create affordance has ever appeared. "
                         "-1 = leave the token byte alone.")
    ap.add_argument("--lobby-chara-name", default=None,
                    help="string written at wire+0x20 (24 B) -> buf+0x40 of each record. "
                         "Default BBBBBBn.")
    ap.add_argument("--lobby-chara-name-a", default=None,
                    help="string written at wire+0x44 (16 B) -> buf+0x00 of each record. "
                         "Default AAAAAAn.  BOTH blocks are wide enough to be the name and "
                         "we do not know which the UI draws -- send both, and whichever "
                         "renders on screen names the field.")
    ap.add_argument("--no-charamake-answer", dest="charamake_answer",
                    action="store_false", default=True,
                    help="do NOT answer the 232-byte REGISTER submission with a "
                         "selector-16. On by default: the submission parks the nest at "
                         "state 10 and phase 10's poll 0x00588cf8 spins while [nest+8] "
                         "== 10, which is the -47111(phase = 10) death. Code 16 is the "
                         "response gated on state 10 (handler 0x00587e98): it sets "
                         "[nest+8] = 2, after which the poll returns [nest+20] or 1 and "
                         "the phase advances.")
    ap.add_argument("--no-delete-answer", dest="delete_answer",
                    action="store_false", default=True,
                    help="do NOT answer the slot-DELETE request. DELETE sends a 40-byte "
                         "mode-2 message with body `05 11 00 00 <slot>` -- selector 17, "
                         "slot index at body[4] -- and the even code gated on the state it "
                         "parks in is 18 (0x00587f00), by the same request/response pairing "
                         "as the charamake's 16.")
    ap.add_argument("--no-world-answer", dest="world_answer",
                    action="store_false", default=True,
                    help="do NOT answer the type-0x7f GAME SERVER request. Selecting a "
                         "server sends a 132-byte mode-1 datagram whose INNER type is "
                         "127 (main is 128, the lobby nest 129) and phase 28 then polls "
                         "kelsvc vt+44 = 0x00bdb250 for [kelsvc+12] == 2. Nothing else "
                         "sets that field in time, so the 40 s receive watchdog "
                         "0x00589a58 stamps it -1 and the run dies -1(phase = 28) / "
                         "CER-48102. See --world-selector.")
    ap.add_argument("--world-len", type=int, default=0,
                    help="OPTIONAL exact-length filter on the game-server request; 0 (the "
                         "default) disables it and routes purely on the inner type, which is "
                         "what the client actually demuxes on. Phase 27's request is 132 "
                         "bytes, but phases 29 and 31 send their own sizes on the same "
                         "channel (sec 4bn), so a length filter answers phase 28 and nothing "
                         "after it. Set 132 to restore the old phase-28-only behaviour.")
    ap.add_argument("--gs-connect", action="store_true",
                    help="CONNECT THE GAME SERVER CHANNEL once the client is in "
                         "world, by sending selector 104 (writes the endpoint at "
                         "[0x009f2b40+184]) then selector 38 (sets the ready flag "
                         "[chan+2148] = 1). sec 4cd: the item/stat manager's count "
                         "getter is 0x0058e210 -> 0x00bc60d8, which reads that very "
                         "channel and bails unless [chan+2148] == 1 -- which is why "
                         "`init item number -1`, a flashing -1 HP bar and a nonsense "
                         "item count. Proven offline: the count goes -1 -> 0 once "
                         "both land. WARNING: sec 4bu called this channel a red herring; "
                         "true for the WORLD DOOR, false for the stat system.")
    ap.add_argument("--gs-stats", default="",
                    help="entries for the game-server STAT TALLY, as a comma "
                         "list of ITEM_ID:QUANTITY (at most 6 -- the handler "
                         "clamps COUNT to 6). Confirmed live: each entry prints "
                         "`You obtain %%s x%%d.` (msgid 0x9c29) in chat, from the "
                         "loop at 0x00ad93f8. WARNING: ids 16/17/18 resolved to "
                         "`??id??`, the item-name-by-id failure, so the valid id "
                         "space is unknown and item names are NOT in KelStr. "
                         "WARNING: AMOUNTS ACCUMULATE: 0x00be6b20 ADDS "
                         "to a key that is already present, so sending the same "
                         "message twice doubles it and a sweep leaves residue "
                         "on the character. WARNING: The KEY NUMBERING is not "
                         "decoded; the 24 medal names are group 60 entries "
                         "16..39, so both a 0-based medal index and the msgid "
                         "low byte are live candidates.")
    ap.add_argument("--gs-arm-state", type=int, default=1,
                    help="the STATE byte (body[13]) of the game-server arming "
                         "message 27. 0x00bc1548: bit 0 -> [array+0] = 1, bit 1 "
                         "-> 2, anything else -> 0. We shipped 0 first and the "
                         "Status screen's Rank Points went 0 -> -1, so 0 is "
                         "very likely 'no data'. 1 is the cheapest probe there "
                         "is -- it needs no knowledge of the key space and "
                         "leaves no accumulating residue, because COUNT stays 0.")
    ap.add_argument("--gs-keepalive-ms", type=int, default=15000,
                    help="hold the GAME SERVER channel open, which is what "
                         "CER-48101 actually is (sec 4cq). The client's own "
                         "emulog says `timeout gameserver 40006` one line before "
                         "the error: 0x00bc10d4 fires when now - [chan+224] "
                         "exceeds [chan+12] == 40000 ms. [chan+224] is a "
                         "LAST-HEARD stamp that only refreshes once the channel "
                         "is ARMED -- message %d with a body of at least %d "
                         "bytes, the only site in the binary that ORs 0x40 into "
                         "[chan+204]. So this sends the arming message once "
                         "after --gs-connect and then message %d every N ms. 0 "
                         "disables. WARNING: the arming message does not itself "
                         "refresh the stamp: 0x00bc4e98 tests the bit before "
                         "dispatching to the handler that sets it, so it takes "
                         "two." % (GS_ARM_MSG, GS_ARM_MIN_BODY, GS_KEEPALIVE_MSG))
    ap.add_argument("--gs-rearm-ms", type=int, default=0,
                    help="sec 4cx. Redo --gs-connect (selector 104 + 38) and "
                         "the arm every N ms, not just once per world session. "
                         "0 (the default) keeps the old behaviour. The client "
                         "RESETS the game-server channel at 0x00bc03b8 -- four "
                         "callers, one of them the plain interface close -- and "
                         "that zeroes [chan+2148], so the item/stat manager goes "
                         "back to `init item number -1` for the rest of the "
                         "session and nothing on the wire says so. Re-running the "
                         "two selectors recovers it (measured in "
                         "an offline run of the client's own code (doc_gsseq_proof)). WARNING: OFF by default "
                         "because the arm is message %d, a reward GRANT: run it "
                         "with --gs-stats EMPTY or every cycle grants again."
                         % GS_ARM_MSG)
    ap.add_argument("--gs-msg", default="",
                    help="after --gs-connect opens the game-server channel, "
                         "send these application messages on it -- a comma list "
                         "of type numbers, 1..61 (sec 4cq). The channel is where "
                         "the item/stat data lives and CER-48101 is the client "
                         "asking to retry a handshake on it. WARNING: PROBE: the body "
                         "format of each message is NOT decoded, so this sends "
                         "the type and zeros. It answers 'does any game-server "
                         "traffic quiet the retry', not 'is the payload right'. "
                         "Proven offline (doc_gsreply_proof.py): all 61 types "
                         "are accepted by the client's own handler and 43 of "
                         "them share a do-nothing epilogue, so a sweep is safe.")
    ap.add_argument("--no-gs-answer", dest="gs_answer", action="store_false",
                    default=True,
                    help="sec 4ea: do NOT answer the client's game-server "
                         "requests (31/33/36/47/56/58/60 -> type+1, keepalive "
                         "1 -> 1). Default on: every request the client makes "
                         "on the type-130 channel is answered by name.")
    ap.add_argument("--gs-battle-start", default=GS_BATTLE_START_DEFAULT,
                    help="sec 4ea/4fy: the notify kinds (message 35) pushed "
                         "after answering 47 (leaveBriefingRoom) with 48, once "
                         "per battle: KIND[:HEXPAYLOAD],... Default 2 alone "
                         "(the spawn + the arena zone); 5 and 53 follow as "
                         "--gs-battle-go (sec 4ga). WARNING: NOT 4: kind 4 is the RESULT -- its arm "
                         "0x00bc1760 sets facade 0x40, which ends ev2045's "
                         "battle loop at once (the live 09-13 instant win / "
                         "defeat); --gs-battle-length sends it at the end.")
    ap.add_argument("--gs-battle-length", type=float, default=180.0,
                    help="sec 4fy: seconds after the battle starts (request 47) "
                         "to END it: notify kind 4 (the RESULT, facade 0x40) "
                         "and then, --gs-battle-reset-after s later, selector "
                         "39 (the full battle reset 0x00bd2a38) so the client "
                         "returns to the LOBBY instead of hanging in br_main. "
                         "0 = never end.")
    ap.add_argument("--gs-battle-reset-after", type=float, default=8.0,
                    help="sec 4fy: seconds between the result (kind 4) and "
                         "selector 39, the time the result screen is shown.")
    ap.add_argument("--gs-battle-after-join", type=float, default=25.0,
                    help="sec 4ed: seconds after the last team join (request 31) "
                         "to push --gs-battle-start, because the briefing room "
                         "offers no 'ready' button -- the real server started "
                         "the table on a timer / head count. 0 = never; 47 "
                         "(leaveBriefingRoom) still triggers it immediately.")
    ap.add_argument("--gs-team-notify", dest="gs_team_notify",
                    action="store_true", default=False,
                    help="sec 4ee: push notify kind 20 (PLAYER DISTRIBUTION) "
                         "after a team join. OFF by default: the arm posts "
                         "facade 0x1000 UNCONDITIONALLY, which the briefing loop "
                         "reads as 'distribution determined' and FINALIZES the "
                         "teams with whoever is seated (1 in a solo test), then "
                         "tries to enter the arena, fails (ID_NO_USE), and exits "
                         "to the title. It is the match-start signal, not a "
                         "per-join update; there is no provisional form.")
    ap.add_argument("--gs-fake-teammates", type=int, default=0,
                    help="sec 4ei: after a team join (request 31), push notify "
                         "kind 31 (add chara) for this many BOT ids into the team "
                         "the client just joined -- NON-finalizing (no kind 20, "
                         "no facade 0x1000), so the team roster fills and the "
                         "count moves WITHOUT the ID_NO_USE kick. The client skips "
                         "its own id, so this is how a solo tester sees a "
                         "populated team; it also probes whether a populated team "
                         "unlocks the 'start' console action (the arena gate, sec "
                         "4eh). 0 = off.")
    ap.add_argument("--gs-fake-team-base", type=lambda x: int(x, 0),
                    default=0x9000,
                    help="base character id for --gs-fake-teammates bots "
                         "(bot k = base + k). Kept clear of real roster ids.")
    ap.add_argument("--gs-battle-zone", type=int, default=201,
                    help="sec 4ft: the ARENA ZONE number served in notify kind "
                         "2's record +26 -> [chan+1064], which vl_main reads "
                         "through get_onlinezone() after the distribution window "
                         "and hands to KerberosZone.exit(). 0 = the old zero "
                         "record, which get_onlinezone turns into exit(-1) = the "
                         "title (the sec 4ee/4el bounce). Default 201 = z201; "
                         "doc-proto-test.img carries z201..z237 with geometry "
                         "(sec 4fb). WARNING: A CONSTANT: which zone SE served for "
                         "which table map is not decoded (the map table "
                         "0x00afc68c holds only KelStr ids).")
    ap.add_argument("--gs-battle-map", default="0,0",
                    help="sec 4ft: map0,map1 for kind 2's record +24/+25 "
                         "(get_onlinezone's mapnum0/mapnum1 -> exit_l). 0,0 "
                         "unless proven otherwise. WARNING: sec 4hb: this is NOT the "
                         "battletable's map index -- z201 and z208 were both "
                         "entered live with 0,0, so the ZONE byte picks the "
                         "arena and these do not. Use --battle-map-zones.")
    ap.add_argument("--zone-pieces", default=ZONE_PIECES_DEFAULT,
                    help="2026-09-23: ZONE:M0,M1 entries separated by ';' -- "
                         "kind 2's rec+24/+25 (exit_l's map0/map1) for that "
                         "arena zone, overriding --gs-battle-map. Names the "
                         "zone's TERRAIN piece so it loads on arrival: with "
                         "0,0 z204 loaded only its sky (m000) and never its "
                         "ground (m001). off = --gs-battle-map everywhere. "
                         "Default %s." % ZONE_PIECES_DEFAULT)
    ap.add_argument("--battle-map-zones", default="",
                    help="sec 4hb: IDX:ZONE pairs mapping the battletable "
                         "record's MAP BYTE (BT_OFF_MAP -- what the config "
                         "screen's Map picker writes) to the arena zone kind 2 "
                         "serves at rec+26. Empty = the decoded default "
                         "(BT_MAP_ZONES_DEFAULT): the 20 of 28 roster entries "
                         "whose label matches a 'multi' (maruchi) arena in the title's "
                         "own data/zone/zonelist.txt. 'off' = none, i.e. every "
                         "table plays in --gs-battle-zone (the behaviour up to "
                         "2026-09-23, which is the bug: the map was chosen and "
                         "then discarded). WARNING: NOT linear -- 201+idx is right "
                         "only for 0..7.")
    ap.add_argument("--no-battle-map-zone", dest="battle_map_zone",
                    action="store_false", default=True,
                    help="sec 4hb: do NOT let a table's chosen map choose the "
                         "arena zone; serve --gs-battle-zone for every table. "
                         "A mission battle keeps --quest-zones either way.")
    # KEY: DEFAULT FLIPPED 2026-09-23 (design decision): serve the chosen map's zone even
    # with no floor point for it. The guard was the safer default while nothing
    # could pick a map, but it is self-defeating now -- a spawn point for z209
    # can only be surveyed from inside z209, and the guard is exactly what keeps
    # us out. Landing in the void is a recoverable, informative failure; never
    # entering the zone is not. Pass --battle-map-needs-spawn to restore it.
    ap.add_argument("--battle-map-needs-spawn", dest="battle_map_needs_spawn",
                    action="store_true", default=False,
                    help="sec 4hb: keep a table in --gs-battle-zone when no "
                         "--zone-spawns point exists for its map's arena zone. "
                         "OFF by default since 2026-09-23: we follow the map "
                         "regardless, because "
                         "kind 2's fallback spawn is a z201 point and sec 4gr "
                         "already landed a player in the VOID that way ('I am "
                         "in the church map! -- but in the VOID'). Pass it to "
                         "keep every player on a floor, at the cost of the "
                         "chosen map being ignored for 15 of the 20 arenas.")
    ap.add_argument("--gs-no-real-roster", dest="gs_real_roster",
                    action="store_false", default=True,
                    help="sec 4ft: do NOT feed the REAL table members into the "
                         "briefing. Default on, and a no-op unless the player's "
                         "battletable has 2+ seated members: each request 31 "
                         "then pushes notify kind 31 (add chara) for every other "
                         "member to every member (kind 0 on a team change), and "
                         "--gs-fake-teammates is skipped at that table.")
    ap.add_argument("--gs-no-real-distribution", dest="gs_real_dist",
                    action="store_false", default=True,
                    help="sec 4ft: do NOT push the kind-20 distribution over a "
                         "real 2+-member roster. Default on: once every seated "
                         "member is on a team and both sides are occupied for "
                         "--gs-real-dist-settle s, every member gets kind 20 -> "
                         "the 'Player distribution has been determined' window "
                         "-> leaveBriefingRoom (47) -> get_onlinezone -> the "
                         "arena (--gs-battle-zone).")
    ap.add_argument("--gs-real-dist-settle", type=float, default=5.0,
                    help="sec 4ft: seconds the real roster must stay ready "
                         "before the distribution goes out, so a player can "
                         "still change sides. Checked on each request 31, which "
                         "the briefing room re-sends every 1-4 s.")
    ap.add_argument("--no-gs-rearm-until-team", dest="gs_rearm_until_team",
                    action="store_false", default=True,
                    help="2026-09-23: do NOT re-send the message-27 arm on each "
                         "keepalive after a 38 until the client's first team "
                         "request (31/33). Default on: a client whose one 27 "
                         "was lost can keep alive but never send request 31.")
    ap.add_argument("--gs-auto-team-after", type=float, default=120.0,
                    help="2026-09-23: seconds after a 2+-member Start before a "
                         "seated member who never chose a team (no request 31) "
                         "is put on the smaller side, so the distribution still "
                         "goes out. The table record's Briefing Time (wire+111, "
                         "minutes) wins when set. Negative = never.")
    ap.add_argument("--gs-no-solo-distribution", dest="gs_solo_dist",
                    action="store_false", default=True,
                    help="sec 4fv: do NOT push the kind-20 distribution "
                         "to a SOLO leader. Default on: when the post-join "
                         "timer pushes --gs-battle-start (kind 2 carrying "
                         "--gs-battle-zone), a table with fewer than 2 seated "
                         "members also gets kind 20 over its own roster -> the "
                         "'Player distribution has been determined' window -> "
                         "OK -> leaveBriefingRoom (47) -> get_onlinezone -> "
                         "KerberosZone.exit(zone). A no-op at 2+ members, "
                         "where --gs-no-real-distribution's push owns it.")
    ap.add_argument("--bt-kill-target", type=int, default=0,
                    help="sec 4he: FALLBACK kill target (team points that end "
                         "the battle) for a table whose record carries none "
                         "decoded yet (BT_RULE_FIELDS). 0 = time limit only. "
                         "The record's own Conditions for Victory row wins "
                         "once its wire byte is measured.")
    ap.add_argument("--bt-respawn-s", type=float, default=4.0,
                    help="sec 4he: FALLBACK respawn delay when the record's "
                         "wire+111 is 0 (the client's own HUD delay is "
                         "record[+57]*1000 + 4000 ms). Negative = never.")
    ap.add_argument("--bt-time-unit", type=float, default=1.0,
                    help="sec 4he: seconds per count of the record's Time Limit "
                         "(wire+4 u32; the picker commit 0x00aac21c writes "
                         "minutes*60, so 1 = the record is already seconds). "
                         "0 = ignore the record, use --gs-battle-length.")
    ap.add_argument("--no-p2p-relay", dest="p2p_relay", action="store_false",
                    default=True,
                    help="sec 4he: do NOT relay the P2P battle layer (shots "
                         "112, damage 113, entity messages) between the "
                         "members of a table. Default relays; without it "
                         "nobody can be hit.")
    ap.add_argument("--bt-situation", type=int, default=1100,
                    help="sec 4gc: the battle SITUATION ID stamped into every "
                         "served battletable record whose wire +34 is 0 -> "
                         "[0x00bf4530]+100 -> getBattleSituationId -> ev2045 "
                         "mdlResLoad: 1000-1098 Res_bt1 (battle), 1100-1998 "
                         "Res_tbt1 (team battle, the default: the briefing has "
                         "two teams), 2000-2098 Res_fa1, 2100-2998 Res_tfa1, "
                         "3000+ missions. 0 = the old zero (no battle set "
                         "loads).")
    ap.add_argument("--bt-no-start-all", dest="bt_start_all",
                    action="store_false", default=True,
                    help="sec 4ft: when the LEADER's Start (lobby command 3) "
                         "pushes BATTLE READY, do NOT also push it to the other "
                         "seated members. Default on: only the leader sends "
                         "command 3, so without this a joiner never reaches the "
                         "briefing room (38 alone takes a reserved member there, "
                         "sec 4eo).")
    ap.add_argument("--gs-battle-pos", default="925.4,-12.3,-1271.7",
                    help="sec 4ga: x,y,z of the battle spawn (notify kind 2 "
                         "record +0/+4/+8 -> getBattleInitPos -> "
                         "btl_start_set's setpos). Default = the one z201 "
                         "point in the client's own ev2045 (battlefield's "
                         "respawn path, beside Zone.load(201,...)) -- a "
                         "CANDIDATE, not SE's per-team spawn. 0,0,0 = the old "
                         "void corner.")
    ap.add_argument("--gs-battle-rot", type=float, default=0.0,
                    help="sec 4ga: spawn facing in degrees -> kind 2 record "
                         "+12/+20 = (sin, cos), read by get_battle_rot_l.")
    ap.add_argument("--gs-battle-go", default=GS_BATTLE_GO_DEFAULT,
                    help="sec 4ga: the notify kinds sent --gs-battle-go-after "
                         "s after the battle starts (request 47): 5 = START "
                         "(facade 0x80, releases ev2045's waitlogin), 28/29/3/"
                         "30 = the zero-record arena handshake that opens the "
                         "DAMAGE gate (facade 0x20, sec 4he). (53 was dropped "
                         "2026-09-24: the retail client ignores kinds >= 49.) "
                         "Empty = never.")
    ap.add_argument("--gs-battle-go-after", type=float, default=20.0,
                    help="sec 4ga: seconds between request 47 and --gs-battle-"
                         "go. Kind 5 before ev2045 reads the spawn makes the "
                         "client spawn at its own last position (the void "
                         "corner); later only delays the start.")
    ap.add_argument("--no-field-items", dest="field_items",
                    action="store_false", default=True,
                    help="2026-09-26: do NOT run the arena's item generators "
                         "(doc_field: ammo / Potions / Ethers / ... placed with "
                         "kind 10 from the map's own generator points).")
    ap.add_argument("--field-respawn-s", type=float,
                    default=doc_field.RESPAWN_S,
                    help="seconds before an emptied item generator rolls again "
                         "(OURS: the map data carries no interval)")
    ap.add_argument("--no-respawn-ammo", dest="respawn_ammo",
                    action="store_false", default=True,
                    help="2026-09-26: send kind 25 (down) WITHOUT the respawn "
                         "refill list (the battle's BULLETS, each SET to "
                         "max(supplies ledger, battle-start count) in the "
                         "victim's bag; retail's 03-24 rule, "
                         "doc_missions.respawn_refill) -- the old empty "
                         "20-byte payload.")
    ap.add_argument("--no-mission-supplies", dest="mission_supplies",
                    action="store_false", default=True,
                    help="2026-09-26: do NOT top each player up to the battle's "
                         "supplies (doc_missions.SUPPLIES; the standard issue "
                         "for PvP) with message 27 at its request 47.")
    ap.add_argument("--battle-go-wait", type=float, default=20.0,
                    help="2026-09-26: a battle room sends ONE GO to every member, "
                         "--gs-battle-go-after s after the LATEST request 47, and "
                         "starts its clock at that GO (each client's HUD clock "
                         "starts at its kind 5). This caps how much a late 47 can "
                         "push the shared GO back past the first 47's; a member "
                         "later than that gets its own GO and a shorter battle.")
    ap.add_argument("--no-gs-ready-roster", dest="gs_ready_roster",
                    action="store_false", default=True,
                    help="sec 4ea: send selector 38 WITHOUT the session id / "
                         "roster (the old all-zero body).")
    ap.add_argument("--gs-ready-after", default="",
                    help="sec 4dx: send SELECTOR 38 -- the battle-READY flag -- "
                         "immediately after answering these answer-selectors. "
                         "Comma list; empty (the default) never sends it. "
                         "38's arm 0x00bccf04 -> 0x00bcb838 -> 0x00bc0260 is the "
                         "SOLE writer of [chan+2148] = 1, which is what makes "
                         "the client send its game-server hello and what opens "
                         "leaveBriefingRoom()'s door (sec 4di). "
                         "the 2026-09-05 audit missing #2 asked for exactly this knob: "
                         "38 is not a connect step, it is 'your battle instance "
                         "is ready', and sending it at WORLD ENTRY is what "
                         "produced the briefing-room slingshot -- a match "
                         "declared ready before anyone reserved one. "
                         "`21` is the honest trigger: selector 21 is the "
                         "phase-44 answer, i.e. the last rung of a COMPLETED "
                         "reservation (sec 4dw). "
                         "WARNING: if this re-opens the slingshot the answer is NOT "
                         "to drop 38 again -- that re-breaks the door -- it is "
                         "that the trigger is still too early.")
    ap.add_argument("--gs-connect-selectors", default="104",
                    help="which game-server connect selectors --gs-connect sends "
                         "(sec 4df). 104 writes the ENDPOINT, which the item/stat "
                         "manager needs; 38 sets the READY flag, which is what "
                         "sends the client to the briefing room on every world "
                         "entry. The default keeps both, i.e. the behaviour that "
                         "shipped; `104` alone tests whether the endpoint gives a "
                         "working avatar without claiming a match is ready.")
    ap.add_argument("--gs-connect-ip", default=None,
                    help="endpoint for --gs-connect (default: --lobby-ip).")
    ap.add_argument("--no-gs-start-endpoint", dest="gs_start_endpoint",
                    action="store_false", default=True,
                    help="sec 4gv: do NOT re-declare the game-server endpoint "
                         "(selector %d) immediately before the BATTLE READY "
                         "(selector %d) + message-%d re-arm pair at Start. "
                         "Default ON. The client's game-server receive handler "
                         "DROPS every datagram whose source does not equal the "
                         "endpoint selector %d last wrote into [chan+184..191], "
                         "before dispatch and before the sequence window -- and "
                         "that endpoint is written once per world session, at "
                         "--gs-connect. Any channel reset between the connect "
                         "and the Start (0x00bc03b8, sec 4cx) leaves it stale, "
                         "the re-arm is swallowed at the gate, [chan+204] bit 6 "
                         "is never set, [chan+224] is never refreshed and the "
                         "client paints CER-48101 40 s later. MEASURED live: "
                         "the peer whose connect->Start gap "
                         "was 2 m 10 s sent ZERO game-server hellos and its "
                         "[chan+212] was still 65528. Unlike --gs-rearm-ms this "
                         "sends selector %d ONLY (never message %d on its own), "
                         "so it grants nothing."
                         % (GS_ENDPOINT_SELECTOR, GS_READY_SELECTOR, GS_ARM_MSG,
                            GS_ENDPOINT_SELECTOR, GS_ENDPOINT_SELECTOR,
                            GS_ARM_MSG))
    ap.add_argument("--gs-connect-port", type=int, default=55040,
                    help="port for --gs-connect.")
    ap.add_argument("--gs-connect-id", type=int, default=0,
                    help="u16 written to body[58..59] of the selector-104 message, "
                         "which 0x00bca938 stores at [kelsvc+268] (sh r3, 268(r17) "
                         "at 0x00bca9c0). sec 4cf: that field is the id the client "
                         "resolves names through, and when it cannot the UI renders "
                         "`!!na!!` -- the whole Status page 2 is that one lookup "
                         "failing, not thirteen missing strings. It reads 65535 "
                         "before --gs-connect and 0 after (this default), and both "
                         "are evidently 'none'. sec 4bs also calls it the argument "
                         "of the follow-up kind-18 request -- and selector 18 DID "
                         "appear on the wire once the channel opened, so the loop "
                         "is: set an id here, the client asks about it on 18, we "
                         "answer 19 with a user list carrying that id and a name.")
    ap.add_argument("--kelsvc-keepalive-ms", type=int, default=15000,
                    help="send a type-127 no-op every N ms to refresh the "
                         "client's KELSVC receive watchdog. 0 disables. sec 4cc: "
                         "CER-48102 is that watchdog -- [conn+4] = 40000 ms "
                         "against [conn+32], i.e. [kelsvc+8] and [kelsvc+36]. The "
                         "existing --lobby-keepalive-ms feeds the type-129 nest, "
                         "NOT kelsvc, and we otherwise send type-127 only when the "
                         "client asks. So a player who is busy in menus or walking "
                         "around -- transmitting constantly, but not REQUESTING -- "
                         "gets 40 s of kelsvc silence from us and the watchdog "
                         "fires. Measured: the receive driver 0x005895b0 stamps "
                         "[conn+32] = now_ms() in its tail (0x005896ec) for EVERY "
                         "message it handles, whatever the selector.")
    ap.add_argument("--kelsvc-keepalive-selector", type=int, default=20,
                    help="selector for --kelsvc-keepalive-ms. MUST be one of the "
                         "194 that map to the shared no-op arm 0x00bcd788, so the "
                         "refresh costs nothing: verified offline that state "
                         "[kelsvc+12] and flags [kelsvc+28] are both unchanged "
                         "while [kelsvc+36] refreshes. WARNING: Do NOT point this at a "
                         "real arm -- see sec 4bz, where a state-setting fallback "
                         "silently reset the connection.")
    ap.add_argument("--pending-ack-after", default="13",
                    help="comma list of ANSWER selectors after which to also send "
                         "a bare selector-128 acknowledgement. Default 13. "
                         "sec 4ca: selector 13 releases phase 30 (it sets state 2 "
                         "and [kelsvc+1064]) but its arm 0x00bcca00 NEVER CLEARS "
                         "THE PENDING MARKER, bit 31 of [kelsvc+28] -- so the "
                         "client's own 10 s deadline in 0x00589af0 expires and it "
                         "paints CER-47117, every time, while resending the "
                         "request with exponential backoff. Selector 128's arm "
                         "0x00bcd4a4 is a bare ack: clear bit 31, set state 2, "
                         "nothing else. Empty string disables.")
    ap.add_argument("--pending-ack-selector", type=int, default=128,
                    help="the bare-acknowledgement selector for "
                         "--pending-ack-after (128 and 136 share arm 0x00bcd4a4).")
    ap.add_argument("--short-ladder", default="22",
                    help="comma-separated SELECTORS whose request is a 36-byte "
                         "datagram (12-byte body) and which we should still "
                         "answer. sec 4dv: selector 22 is the reserve's server "
                         "handoff -- phase 42 sends it, phase 43 blocks on the "
                         "selector-23 answer, and the old 40-byte length gate "
                         "dropped all seven of them in the 09-05 corpus, which "
                         "is the CER-47117 reservation stall. Keep 5 OUT of "
                         "this list: it is a driver arm and answering it moves "
                         "[kelsvc+12] (sec 4bz). Empty string disables.")
    ap.add_argument("--chat", choices=("on", "all", "off"), default="on",
                    help="2026-09-26: relay chat (world selector 255, kinds "
                         "0..9) with ident = the speaker, SCOPED as retail "
                         "(doc_chat): say = same lobby area, shout = + the "
                         "adjacent areas, entry = same battletable, team = "
                         "same team, tell = its target. ALL = every non-tell "
                         "line to every live player (the first relay); OFF = "
                         "the old drop.")
    ap.add_argument("--world-answer-unpairable", action="store_true",
                    help="ALSO answer request selectors that cannot be paired "
                         "(0, or >= 255) using --world-selector-next. OFF by "
                         "default since sec 4bz: that default is 2, and selector "
                         "2 is a DRIVER arm that sets [kelsvc+12] = 2, so "
                         "'answering' a selector-255 notification silently reset "
                         "the connection state out from under whatever request "
                         "was pending. 255 cannot pair anyway -- 256 is past the "
                         "end of the 252-entry jump table.")
    ap.add_argument("--world-selector-next", type=int, default=2,
                    help="answer SELECTOR for the rounds after the world door (phase 29 on). "
                         "WARNING: Briefly defaulted to 5 on the reasoning that the state [conn+8] sits "
                         "at 2 after the world door and 5 is the only arm live there. That was "
                         "WRONG: the state was read from a savestate taken during phase 27's "
                         "processing. Every client SEND resets it -- 0x00589924/0x0058992c does "
                         "`[conn+8] = 1` -- so phase 29's request leaves the state at 1 again and "
                         "selector 2 is right for every round. 2 is also the ONLY selector that "
                         "reaches 0x005894f0, which clears the pending-request marker at "
                         "[conn+24] (= kelsvc+28) that 0x00589af0 times out on after 10 s. Kept "
                         "as a flag so the four selectors the driver accepts (2/4/5/6) can be "
                         "swept without a rebuild.")
    ap.add_argument("--no-world-selector-pair", dest="world_selector_pair",
                    action="store_false", default=True,
                    help="do NOT derive the answer selector as `request selector + 1` "
                         "(sec 4bs); fall back to --world-selector / "
                         "--world-selector-next. The pairing is what finally answered "
                         "phase 30: the driver 0x005895b0 RETURNS body[1] and the demux "
                         "0x00bcc718 dispatches it through the jump table at 0x00bf3230 "
                         "(index = selector - 4), so phase 29's `07 0c ..` (selector 12) "
                         "wants selector 13 -- handler 0x00bca868, which is the only "
                         "code that sets BOTH [kelsvc+12] = 2 and [kelsvc+1064], the two "
                         "things phase 30's poll 0x00bd0888 requires. Selectors 2/4/5/6 "
                         "are the DRIVER's arms and none of them can do it. Turn this "
                         "off only to reproduce the pre-4bs behaviour.")
    ap.add_argument("--lobby-clock", default="play",
                    help="command 20's answer body[16] = the Status screen's PLAY "
                         "TIME in seconds (2026-09-13; sec 4dc called it the server "
                         "clock). 'play' (default) serves the selected character's "
                         "tracked play time (doc_playtime.py); 'unix' the old epoch "
                         "seconds (renders ~496,000 h); an INTEGER forces a value; "
                         "'off' echoes the request's stale bytes. The client asks "
                         "only while its slot is empty.")
    ap.add_argument("--play-time", default=None,
                    help="per-character play-time JSON for --lobby-clock play. "
                         "Default: doc-playtime.json next to --chara-store (memory "
                         "only without one); 'off' = memory only.")
    ap.add_argument("--lobby-cmd", default="echo",
                    help="selector 241 (Command Result) body[12]: 'echo' takes "
                         "the command id out of the client's own selector-240 "
                         "request (the default -- 0x00589c48 writes it at "
                         "request body[12] as a single byte), an INTEGER forces "
                         "one sub-type, 'off' restores the pre-fix behaviour of "
                         "sending --world-result there. WARNING: 'off' means the answer "
                         "bails at 0x00bc9274 every time, which is what shipped "
                         "until 2026-08-28.")
    ap.add_argument("--world-result", type=int, default=0,
                    help="body[12..15] of the world answer = `record+32`, the RESULT the "
                         "selector-13 handler reads first. It is copied verbatim into "
                         "[kelsvc+1064], and phase 30 fails if it is negative. 0 = ok. "
                         "Set a negative value to make the client report a server-side "
                         "refusal instead of hanging.")
    ap.add_argument("--world-gs-ip", default="",
                    help="GAME SERVER address to hand the client in body[52..55] of a "
                         "selector-21 answer (sec 4bs). 0x00bca938 passes it to "
                         "0x0058a970, which fills the sockaddr at [0x009f2b40 + 184] -- "
                         "the channel that has been 0.0.0.0:0 in every savestate, and "
                         "the reason its demux 0x00bc4e98 logs `[KEL NET GAME "
                         "SERVER]Drop packet bad packet` for anything that arrives. "
                         "Empty leaves body[52..] as the request left it (zeros).")
    ap.add_argument("--world-gs-port", type=int, default=55040,
                    help="GAME SERVER port, body[56..57] of a selector-21 answer, "
                         "written big-endian. Calibrated: with the IP in network-order "
                         "octets and the port big-endian the client stores exactly the "
                         "same 8 bytes it already holds for the live lobby endpoint.")
    ap.add_argument("--world-pad", type=int, default=176,
                    help="pad the world-door reply's BODY to this many bytes with zeros. "
                         "THIS IS THE SE-CRASH FIX (sec 4bo): the client reads a 32-bit array "
                         "count from body[140], and echoing the 132-byte request only supplies "
                         "body[0..107], so it read stale RAM (measured: 0, 1040, 2149, -1529, "
                         "15360) and a copy loop wrote count*8 bytes over the SE record-array "
                         "base. 176 covers body[140..143] with margin; 0 disables padding and "
                         "restores the old, crashing behaviour.")
    ap.add_argument("--lobby-map-mask", default="all",
                    help="WHICH MAPS THE BATTLETABLE MAP PICKER OFFERS (sec 4gv). A "
                         "64-bit bitmask over the client's own 28-entry map roster, "
                         "carried at body[72..79] of the SAME selector-13 answer the "
                         "spawn rides. The picker skips every roster entry whose bit is "
                         "clear, so the zero we shipped until now is exactly why that "
                         "list has rendered EMPTY since 2026-09-12 -- and why only the "
                         "Map row was affected: every other row on that screen builds "
                         "its options against an all-0xFF mask the client makes up "
                         "locally. 'all' (default) = every map except index 11, which "
                         "is a hole in SE's own string table and would show as "
                         "'!!na!!'. 'none' restores the old, empty behaviour. Also "
                         "accepts a mask (0x0ffff7ff) or a comma list of roster indices "
                         "(0,4,7). WARNING: The index space is the battletable record's map "
                         "byte (BT_OFF_MAP), so whatever you allow here is what a "
                         "created table can ask the game server to host.")
    ap.add_argument("--lobby-zone", type=int, default=217,
                    help="2026-09-23 (sec 4hg addendum 4): the zone number the "
                         "world-door answer (selector 2) carries at body[42..43] "
                         "-> [mgr+0xd94], the zone z217's lobby-entry fallback "
                         "loads when nothing is resident (every return from an "
                         "event zone). 217 = the lobby entry. 0 = the old "
                         "behaviour (the echoed token bytes = a junk zone = the "
                         "intro's black screen).")
    ap.add_argument("--lobby-spawn", default="",
                    help="WHERE THE PLAYER APPEARS IN THE LOBBY (sec 4dh). Empty = off, "
                         "which ships body[28..53] as zeros and is the p(0,0,0) spawn "
                         "outside the level that sec 4df measured. Accepts "
                         "'x,y,z[,dirx,diry,dirz[,index]]' or a preset: 'east' (the "
                         "Visual Lobby's east wing, where quest.ev stands the player), "
                         "'east-anchor'/'south'/'west'/'north' (the four map-screen "
                         "anchors of mm_z217, one per wing), or 'room' -- which is a "
                         "BRIEFING ROOM seat (ev2046_sub.vl_brf2), the spot sec 4dd "
                         "measured with selector 38 armed; in the Visual Lobby it is "
                         "the middle of nowhere (the 2026-09-05 audit). Rides "
                         "selector 13 -- the phase-30 "
                         "answer -- whose arm 0x00bca868 stores a 28-byte descriptor at "
                         "[0x009f3b80+3232]; the zone script reads it back through "
                         "KerberosNetLobby.getLobbyInitPos(). Y is given as the WORLD "
                         "position: the getter subtracts 3.0 and we add it back here.")
    ap.add_argument("--world-type", type=int, default=127,
                    help="inner type of the world-door reply. 127 routes the datagram to "
                         "kelsvc (0x009f3480), whose [kelsvc+16] == 7 bounds body[0] and "
                         "whose [kelsvc+12] is the field phase 28 polls.")
    ap.add_argument("--list-148", default="",
                    help="sec 4gt add.1 PROBE (2026-09-22), default OFF: answer the "
                         "selector-147 list request with a REAL selector-148 "
                         "list instead of the generic zero-length one. Either a "
                         "bare COUNT (\"8\" -> ids 1..8, record index i, "
                         "flags 0) or `id:rec:flags` triples "
                         "(`1:0:1,2:1:3`). body[15] = count, then 4 bytes per "
                         "entry {u16 id, u8 record index, u8 flags}; the "
                         "client's populator 0x00aae2d0 turns flags bit0 into "
                         "rec+26 (229 vs -1) and bit1 into rec+4 (0 vs 2), and "
                         "the builder 0x00aae890 draws idx[i] out of the "
                         "52-byte table at 0x00B89548. WARNING: A PROBE: the meaning "
                         "of the ids is UNKNOWN and it is NOT established that "
                         "this list feeds the battletable config rows. It "
                         "answers one question -- does a non-zero count put "
                         "rows on screen. Empty = the old behaviour.")
    ap.add_argument("--battletable-list", default="",
                    help="serve a real BATTLETABLE LIST on selector 16 -> 17 "
                         "(sec 4dv). Either a COUNT (\"3\") or "
                         "\"map:cur/max:comment;...\", e.g. "
                         "\"jungle:0/8:Come on in;church:2/16:Large-Scale\". "
                         "Maps: " + ", ".join(BT_MAPS) + ". The browser asks at "
                         "lobby phase 34 and parks the channel in state 15; the "
                         "accumulator 0x00bc9a70 keys each row on the record's "
                         "u16 at +24 and renders map / participants / comment / "
                         "leader name. Empty = the old empty-body answer.")
    ap.add_argument("--battletable-probe", action="store_true",
                    help="answer the selector-26 battletable request with a "
                         "selector-27 record whose every field is a distinct "
                         "sentinel (sec 4dn/4do). The config screen (Map / Max "
                         "Players / Time Limit / Point / Comment / Restrictions "
                         "/ NPC) currently renders !!na!! because we answer with "
                         "zeros; this names which record offset drives which "
                         "row. SHIPS MADE-UP VALUES -- a probe, not a table.")
    ap.add_argument("--no-battletable-verbs", dest="battletable_verbs",
                    action="store_false", default=True,
                    help="sec 4dz: do NOT serve the battletable console verbs "
                         "out of the store (create 24, config 26, adjust 28, "
                         "reserve 151/153, cancel 155, dissolve 125, invite "
                         "127, and the join 20/30 seating). With this set they "
                         "fall back to the generic zero-body answer.")
    ap.add_argument("--bt-no-onfly-reserve", action="store_true",
                    default=False,
                    help="sec 4eo/4ep (2026-09-11): do NOT create-on-the-fly "
                         "and seat the player for a JOIN whose table id is "
                         "UNKNOWN (the online battletable console "
                         "default-targets the uninitialised [manager+11808] "
                         "= 59600). Left on (the default), the sec-4ee "
                         "create-on-the-fly seats the player and the "
                         "generic selector-21 endpoint answer then sets the "
                         "client reserved flag [kelsvc+1092] bit 4, so the "
                         "player is PERPETUALLY reserved (prompt 0x6835) "
                         "and the Create option is hidden -- they can never "
                         "become a table leader. With this set the phantom "
                         "JOIN is NOT invented and is answered selector 21 "
                         "with result=-1 (no such table), so the phase-45 "
                         "success path never runs and the reserved flag "
                         "stays clear -- the player is free to CREATE. A "
                         "real listed table (--battletable-list) or a real "
                         "CREATE (selector 24) is unaffected.")
    ap.add_argument("--bt-no-start-ready", action="store_true",
                    default=False,
                    help="sec 4fm (2026-09-12): do NOT push BATTLE READY "
                         "(selector 38, roster per --no-gs-ready-roster) right "
                         "after answering a selector-240 request whose command "
                         "is 3 = START (0x00bd1db8, what Start Immediately's "
                         "zone flag 10 -> start_onlinebattle sends). Live "
                         "09-12: the leader's Start reached 0x00AA2218, the "
                         "client sent command 3, we echoed 241 and nothing "
                         "followed -- 38 was never sent because --gs-ready-"
                         "after is unset. Default ON; this is the off switch.")
    ap.add_argument("--bt-no-reserve-echo", action="store_true",
                    default=False,
                    help="sec 4fl (2026-09-12): do NOT send the unsolicited "
                         "selector-152 RESERVATION ECHO after a CREATE-ok (25) "
                         "or a successful JOIN-ok (21). The echo is what lets "
                         "the client's Start Immediately pass the 0x683b "
                         "status (it reads the self record R+2970 gated by "
                         "R+684 bit 4, set ONLY by the 152/154 arm); the "
                         "create flow never sends 151 for the leader's own "
                         "table. Default ON; this flag is the off switch.")
    ap.add_argument("--user-list-selector", type=int, default=0,
                    help="force the user-list ANSWER selector instead of "
                         "deriving it as request+1. 0 keeps the pairing. Set "
                         "19 to route every user list onto the rung that "
                         "actually reaches the profile cache: sec 4ch, "
                         "selectors 11 and 19 share the handler 0x00bc9bf0, "
                         "the [kelsvc+12] == 7 gate and the `user list N N` "
                         "log line, and differ only in the argument that picks "
                         "0x00bd8690 -> [kelsvc+280]. The demux dispatches on "
                         "the selector WE send, so this is legal; sec 4ci "
                         "measured 13 requests on 10 and one on 18, i.e. "
                         "almost all of it was landing on the wrong rung.")
    ap.add_argument("--user-list-sweep", type=int, default=0,
                    help="also serve ids 1..N in every user-list answer, on "
                         "top of the one asked for. The record is keyed on its "
                         "+0 and we do not yet know which id the Status window "
                         "resolves; a spread costs only bytes, because the "
                         "client keeps what it wants and the cache holds 32. "
                         "WARNING: a record whose +0 == [kelsvc+272] is dropped "
                         "silently, so id 0 can never be served this way.")
    ap.add_argument("--user-rank", type=int, default=None,
                    help="user record +54, the RANK, 1-BASED: 1 DGD-3, 2 "
                         "DGD-2, 3 DGD-1, 4 DGSC-3 ... 15 DGG-1, 16 TSV. It "
                         "indexes 0x00afd000, whose entry 0 duplicates entry 1, "
                         "and anything >= 17 also falls back to entry 0 -- so 0 "
                         "and 99 both render DGD-3 and NO value means 'no rank' "
                         "(sec 4ch). The label formatter 0x00ad7048 prints it "
                         "as the third field of its `%%s %%s %%s%%s`.")
    ap.add_argument("--user-zone", type=int, default=None,
                    help="user record +32, the SERVER/ZONE id -> profile +64. "
                         "0x00ad6f20 is `return [rec+64] != 0xffff`, so it "
                         "picks msgid 0x7806 'LBY' when the id is 0xffff and "
                         "0x7807 'RES' otherwise, and 0x00ad6188 forces 0xffff "
                         "when the id equals the one being labelled.")
    ap.add_argument("--user-flags", type=int, default=None,
                    help="user record +30 -> profile +62. Bit 1 adds the "
                         "'$m03' marker to the label and bit 4 adds '$m04' "
                         "(0x00ad7104/0x00ad711c). 0x00bd36d0 sets bit 3 "
                         "itself on the group path.")
    ap.add_argument("--user-costume", type=lambda x: int(x, 0), default=None,
                    help="user record +36 (u16), the REMOTE costume code -> "
                         "profile cache, which is where getUserData(id) reads "
                         "the o099 code for a peer whose id != [kelsvc+272] "
                         "(sec 4dr, converter 0x00bd8690). WITH --world-self-"
                         "charaid OFF the self avatar's uid is the ACCOUNT uid "
                         "(!= the charid in [kelsvc+272]), so the client dresses "
                         "ITSELF through this remote path -- serving the code "
                         "here dresses the lobby avatar WITHOUT the flag, so the "
                         "name plate (which needs uid != [kelsvc+272]) keeps "
                         "working. Same 16-bit code as --self-costume; repack() "
                         "expands it on the client (0x1012 = Lex).")
    ap.add_argument("--user-port", type=int, default=None,
                    help="user record +28, the peer's port -> profile +60, "
                         "byte-swapped the same way.")
    ap.add_argument("--user-rec-probe", action="store_true",
                    help="WARNING: A PROBE, NOT A FIX. Fill every still-unknown "
                         "field of the user record with a value that is "
                         "unmistakable on screen -- rank 16 (TSV), zone 3, "
                         "flags 0x12 (both markers), +4=111111, +8=222222, "
                         "+12=333333, +36=4444, +55=55 -- so ONE boot and one "
                         "screenshot say which Status row each field drives. "
                         "It ships deliberately wrong data; do not leave it on.")
    ap.add_argument("--user-list-name", default=None,
                    help="name to put at the user record's +38..53 "
                         "(16 bytes). Defaults to --lobby-chara-name. The "
                         "name plate only checks that byte 0 is alphanumeric "
                         "(0x006b0ed4), so this is what stops the per-frame "
                         "`Name plate error uid` spam -- if +38 is really the "
                         "name, which is what the live run tests.")
    ap.add_argument("--user-list", action="store_true",
                    help="answer the client's selector-10 USER LIST request with "
                         "a real one-entry selector-11 list (sec 4bx) instead of "
                         "build_world_answer's empty body. The single entry is "
                         "the client's OWN uid, learned off its in-game type-0x83 "
                         "broadcast (body[0..3]) -- it is failing to find ITSELF "
                         "(`Name plate error uid 0x%(uid)s` once per frame). OFF "
                         "by default: whether a non-empty list clears CER-47117 "
                         "is exactly what this is for testing."
                         .replace("%(uid)s", "a756a69a"))
    ap.add_argument("--world-update-ms", type=int, default=0,
                    help="send a type-125 WORLD UPDATE this often (ms) while the "
                         "client's type-0x83 position stream is live. 0 = off, the "
                         "default. Nothing has ever sent a type-125, so the world "
                         "has always contained exactly one entity -- the player. "
                         "WARNING: The two record scales (x0.1 position, x0.001 "
                         "orientation) are READ FROM DISASSEMBLY, never measured: "
                         "doc_eemu has no FPU. The live check is whether the peer "
                         "appears where this says it should.")
    ap.add_argument("--world-update-id", type=lambda v: int(v, 0), default=0x40000001,
                    help="entity id for the test peer. Bit 30 picks the table and "
                         "the 0x00bd2358 arm wants the TOP NIBBLE == 4, so the "
                         "default is 0x40000001. The client will not know it and "
                         "will ask selector 36 -- that is the designed pull.")
    ap.add_argument("--world-update-abs", default="",
                    help="absolute x,y,z for the type-125 record instead of an "
                         "offset from the player. With --world-update-id=0 (the "
                         "client's OWN uid) this asks whether a world update can "
                         "PLACE the player -- who otherwise spawns at the origin, "
                         "~1900 units from the level, with no floor and so no "
                         "ability to move (sec 4df).")
    ap.add_argument("--world-update-offset", type=float, default=3.0,
                    help="metres to offset the test peer from the player on X, so "
                         "it is next to them rather than inside them.")
    ap.add_argument("--peer-relay", choices=("off", "raw", "wu"), default="off",
                    help="sec 4fu: TWO CLIENTS SEE EACH OTHER. On every type-0x83 "
                         "position broadcast, put the sender in each OTHER "
                         "in-world client's world: a selector-37 peer record, a "
                         "type-125 spawn at its pose, and then 'raw' = the 0x83 "
                         "itself re-flagged as a peer datagram (flags|8, mode 0, "
                         "verbatim otherwise) for the unit's own update path, or "
                         "'wu' = one type-125 per 0x83 instead. OFF by default "
                         "until proven on two screens.")
    ap.add_argument("--peer-relay-spawn-ms", type=int, default=3000,
                    help="under --peer-relay raw, how often the type-125 (re)spawn "
                         "of each peer is repeated to each other client, so a unit "
                         "the receiver evicted or lost to a zone load comes back.")
    ap.add_argument("--peer-relay-push-s", type=float, default=30.0,
                    help="how often each peer's selector-37 record is re-pushed to "
                         "each other client (its peer table survives, but a "
                         "reconnect empties it).")
    ap.add_argument("--peer-relay-live-s", type=float, default=5.0,
                    help="a client counts as IN WORLD while its own 0x83 stream is "
                         "this fresh; only those are relayed to (the world channel "
                         "is shut everywhere else).")
    ap.add_argument("--peer-push", action="store_true",
                    help="sec 4dj. Send an UNSOLICITED selector-37 peer answer for every "
                         "id the user list carries, so [kelsvc+284] -- the PEER table -- "
                         "actually fills. This is a different table from the profile "
                         "cache [kelsvc+280] the user list feeds, and it is the one "
                         "getCharacterTableId reads (`lw a0, 284(a0)` on kelsvc). "
                         "MEASURED: with --user-list-sweep=32 the cache reached 32 rows "
                         "and the peer table stayed at 0, so every character lookup still "
                         "missed and still returned 0xffff4867 as the table id -- which is "
                         "the 'you already have a reservation' message. Safe to send "
                         "unsolicited: selector 37's arm 0x00bccee8 has no state gate.")
    ap.add_argument("--peer-answer", action="store_true",
                    help="answer the client's selector-36 CACHE MISS with a "
                         "selector-37 peer record (sec 4bw). The client emits "
                         "that request by itself whenever a type-125 world "
                         "update names an entity it does not know. OFF by "
                         "default: nothing sends type-125 yet, and the record we "
                         "would serve is all zeros past the id.")
    ap.add_argument("--world-selector", type=int, default=2,
                    help="body[1] of the world-door reply, the SELECTOR the shared driver "
                         "0x005895b0 dispatches on. 2 at state 1 (post sets state 1) is "
                         "the arm 0x00589660, which calls the sub-object's vt entry 6 = "
                         "0x00bc8aa0, whose FIRST act is 0x005894f0 -- and that sets "
                         "[kelsvc+12] = 2 iff body[4] bit 0 is clear. 5 and 6 also reach "
                         "the state = 2 assignment, but only from state 3.")
    ap.add_argument("--world-subchannel", type=int, default=-1,
                    help="body[0] of the world-door reply; <0 keeps the client's own (7). "
                         "The driver rejects body[0] > [kelsvc+16] == 7 -- a LOOSER bound "
                         "than the nest's 5, which is why the world request may be echoed "
                         "even though a 232/132-byte nest body may not.")
    ap.add_argument("--world-burst", type=int, default=4,
                    help="copies of the world-door answer. A selector outside its gating "
                         "state is a no-op, so repeats are free.")
    ap.add_argument("--charamake-len", type=int, default=232,
                    help="datagram length that identifies the REGISTER submission "
                         "(MEASURED: 232 bytes, mode 2).")
    ap.add_argument("--charamake-burst", type=int, default=4,
                    help="copies of the selector-16 answer. Like the code-8, a selector "
                         "outside its gating state is a no-op, so repeats are free.")
    ap.add_argument("--lobby-chara-used", action="store_true",
                    help="serve records the client renders as REAL characters: the name at "
                         "record+0 and the USED flag, bit 0 of record+58. Both MEASURED off "
                         "the consumer's own branch 0x00ad591c, which reads lbu 106(service "
                         "+ index*96), masks bit 0, and prints either '(not use)' or "
                         "'#%%d %%s' with the string at service+index*96+48 -- i.e. record+0 "
                         "once the +48 copy base is subtracted. Use --lobby-chara-name to "
                         "set the name.")
    ap.add_argument("--lobby-chara-probe", action="store_true",
                    help="THE USED-MARKER SEARCH. Serve four DIFFERENT all-zero records, "
                         "each with one candidate field set, and see which slot stops "
                         "printing '(not use)'. The slots are independent, so this tests "
                         "four hypotheses in one boot: id+0x00, flag+0x04, name+0x44, "
                         "name+0x20. Everything about the record layout is a hypothesis -- "
                         "arbitrary bytes reading as unused (sec 4bb) is the only measured "
                         "fact, so the marker is positive and lives in these 96 bytes.")
    ap.add_argument("--lobby-chara-blank", action="store_true",
                    help="make the --lobby-chara-count records ALL ZERO -- present but "
                         "empty slots -- instead of the populated AAAAAA/BBBBBB test "
                         "records. An empty roster is NOT count=0: char=0 gave four dead "
                         "Unregistered rows and a frozen cursor, while an accidental "
                         "char=145 walked 145 records of arbitrary RAM, reported every one "
                         "as '(not use)', and offered CREATE CHARACTER with a working "
                         "cursor. The client needs records to walk; blank ones are what "
                         "makes a slot selectable.")
    ap.add_argument("--lobby-chara-fill", type=int, default=1,
                    help="value stuffed into the record unknown small fields (default 1). "
                         "Use 0 to test whether a zeroed level/class renders as a blank row.")
    ap.add_argument("--reliable-ack-lo", type=int, default=-1,
                    help="if >=0, ALSO answer every reliable packet (36-B mode-2 / 96-B) with a "
                         "sweep of MODE-0 reliable ACKs for ack-seq in [lo,hi]. The framework "
                         "cancels the retransmit of the pending message whose seq matches (PROVEN "
                         "offline, sec 4ae). The client's seq is encrypted so we sweep; the measured "
                         "first-unacked seq was 28. -1 disables.")
    ap.add_argument("--reliable-ack-hi", type=int, default=90,
                    help="upper bound of the reliable-ACK sweep (see --reliable-ack-lo).")
    ap.add_argument("--reliable-ack-selectors", default="1,3,10,12,18,36,240",
                    help="type-127 request selectors to ACK IMMEDIATELY, whatever "
                         "--reliable-ack-ingame thinks (sec 4dd). Default 240, the "
                         "selectors we ANSWER -- the lobby command channel (240), "
                         "the user list (10/18), the ladder (1/12/3) and the peer "
                         "pull (36). Each arrives while the 2 Hz "
                         "stream is quiet, so the gated ACK lands ~7.7 s late, after "
                         "the client has already timed out and boomeranged back. "
                         "Empty string disables. NOT a return to "
                         "--reliable-ack-exact: this only covers messages we answer, "
                         "where the client is mid-transaction and keeps transmitting.")
    ap.add_argument("--reliable-ack-ingame", action="store_true",
                    help="ACK the client's reliable DATA, but ONLY while its "
                         "in-game type-0x83 position stream is live (within "
                         "--reliable-ack-idle seconds). This is the literal form "
                         "of the rule --reliable-ack-exact violated: never ACK "
                         "the last outstanding retransmit UNLESS SOMETHING ELSE "
                         "KEEPS THE GUEST TRANSMITTING. In the lobby nothing "
                         "does, so ACKing there silences the client and PCSX2 "
                         "unbinds its UDP port ~48 s later (CER-48104, sec 4bx). "
                         "In game the 2 Hz stream holds the mapping open by "
                         "itself, so ACKing is free -- and NOT acking there "
                         "leaves the client resending forever, which is what "
                         "produced the CER-48102 40 s watchdog on 08-27.")
    ap.add_argument("--reliable-ack-idle", type=float, default=5.0,
                    help="seconds since the last type-0x83 within which the "
                         "client counts as 'streaming' for --reliable-ack-ingame.")
    ap.add_argument("--reliable-ack-exact", action="store_true",
                    help="answer each reliable DATA packet with exactly ONE mode-0 ACK for the "
                         "seq read out of its DECRYPTED inner header (sec 4ai), sent AFTER the "
                         "advance replies. Supersedes --reliable-ack-lo/-hi: the sweep was only "
                         "ever a workaround for not being able to read the seq, and it flooded "
                         "the client's receive ring (151 ACKs -> 5 s, 5 ACKs -> 38 s; sec 4ae). "
                         "OFF by default -- the known-good config is a 75 s sustain with no ACK "
                         "at all, and this has NOT been proven live.")
    ap.add_argument("--keepalive-idle-s", type=float, default=90.0,
                    help="stop EVERY unsolicited send (lobby, kelsvc and game-server "
                         "keepalives) once nothing has arrived from the peer for this "
                         "many seconds; 0 = never stop. the 2026-09-05 audit (C): "
                         "the container had sent 7,080 selector-8 keepalives to a peer "
                         "that left two days earlier. Any packet from the peer re-arms.")
    ap.add_argument("--no-session-adopt", dest="session_adopt",
                    action="store_false", default=True,
                    help="sec 4gz: do NOT re-join a client that reappears on a new "
                         "source port to the session it was playing on. Sessions key "
                         "on (ip, port) so two consoles behind one household NAT stay "
                         "apart; adoption is the other half -- a router that re-binds "
                         "the mapping mid-session would otherwise hand the same player "
                         "a blank second session. Off = one session per PORT, full stop.")
    ap.add_argument("--session-adopt-idle", type=float, default=5.0,
                    help="sec 4gz: adopt a predecessor session only once it has been "
                         "silent this long. One client uses ONE socket (measured), so "
                         "two ports sending concurrently under one charid are two "
                         "players whose accounts resolved to the same character -- "
                         "merging those would be the collision, not the fix.")
    ap.add_argument("--session-idle-drop", type=float, default=900.0,
                    help="sec 4gz: forget a session after this many seconds of silence "
                         "(0 = never). With (ip, port) keys the registry grows with "
                         "every re-bound NAT mapping, and a stale entry lingers in the "
                         "connected count and the adoption scan.")
    ap.add_argument("--save-max", type=int, default=20000,
                    help="keep at most this many files in --save, deleting the oldest "
                         "(0 = unbounded). 39,743 had accumulated by 2026-09-05.")
    ap.add_argument("--lobby-keepalive-ms", type=int, default=0,
                    help="if >0, ALSO send the selector-8 advance reply UNSOLICITED every N ms to "
                         "the last peer, using the last 96-byte lobby packet as the template. "
                         "WHY (sec 4aj): the watchdog 0x00589af0 times out on "
                         "(now_ms - nest[+0x24]) > 10000 while armed, and nest[+0x24] is re-stamped "
                         "ONLY by the client's 2->6 self-advance, which only happens after our "
                         "selector-8 answers a state-6 window. Until now the ONLY thing generating "
                         "the inbound packets that made us reply was the client's own unACKed "
                         "retransmits -- so ACKing them silenced the client and the 10 s clock ran "
                         "out (LIVE: 5.1 s, twice). A responder that drives the advance loop on its "
                         "OWN clock does not depend on retransmits. PROVEN OFFLINE "
                         "(an offline run of the client's own code (doc_keepalive_proof)) that an unsolicited selector-8 is a "
                         "harmless no-op at state 2 and advances 6->2 at state 6. 0 disables. "
                         "\n"
                         "MEASURED WINDOW (sec 4al): 9001 < N < 40000. The client's own state-2 poll "
                         "fires only once 9001 ms have passed with NO accepted message from us "
                         "(gate 0x00589a58: elapsed = now - nest[+0x20]), and EVERY accepted message "
                         "re-stamps +0x20 -- so N=1000 makes the poll impossible and the client sits "
                         "mute (LIVE boot 8: 3 packets in 10 minutes). Above nest[+4]=40000 the gate "
                         "returns -1, the error arm. Prefer ~30000: a backstop that lets the client "
                         "poll at ~9 s and drive a real request/response cadence.")
    ap.add_argument("--lobby-keepalive-open-ms", type=int, default=1000,
                    help="keepalive interval during the OPENING window (see --lobby-keepalive-open-s). "
                         "The nest is ARMED with an already-stale nest[+0x24] at LOGIN -- MEASURED "
                         "(an offline run of the client's own code (doc_silence_proof)): from state 6 armed, the tick returns -2 at "
                         "+10.25 s, and the observed death is ~5 s because the liveness is ~5 s old "
                         "before LOGIN even happens. We cannot see when the nest reaches state 6, so "
                         "the opening has to keep trying. Once a selector-8 lands it goes 6->2 and "
                         "DISARMS, and from there the budget is 40 s, not 10.")
    ap.add_argument("--lobby-keepalive-open-s", type=float, default=15.0,
                    help="how long to hold the opening interval before dropping to the steady "
                         "--lobby-keepalive-ms. 0 disables the opening phase entirely.")
    ap.add_argument("--no-decrypt", action="store_true",
                    help="do not decrypt inbound inner headers for the log (decrypt costs ~12 ms "
                         "per packet and is otherwise read-only).")
    ap.add_argument("--lobby-selector", type=int, default=2,
                    help="body[1] of the 'advance' reply = the driver's selector at "
                         "[record+21]. 2 advances the nest at state 1 (default); other values "
                         "are for probing.")
    ap.add_argument("--lobby-seq", type=int, default=0,
                    help="inner-header seq (packet+14) of the 'advance' reply -> record+16. "
                         "Not gated by the advance; tunable in case the reliable layer cares.")
    ap.add_argument("--lobby-edit", default=None,
                    help="patch the echoed LOBBY reply before sending: comma-separated "
                         "OFF:HH byte writes (decimal offset, hex byte), e.g. '25:02' sets "
                         "body[1] (packet+25, the subtype the driver dispatches on) to 2. "
                         "The 16-byte field is NOT validated on receive (proven: echo is not "
                         "dropped), so editing the body is safe. Use to test the selector "
                         "hypothesis: nest object parks at state 1 and needs a selector-2 msg.")
    a = ap.parse_args()

    extra_selectors = [int(x) for x in a.lobby_extra_selectors.split(",") if x.strip()]
    if extra_selectors:
        print("[docudp] LADDER: also sending response code(s) %s after each reply -- "
              "each is a no-op unless the nest is in that code's state"
              % extra_selectors, flush=True)

    extra_subtypes = [int(x) for x in a.extra_subtypes.split(",") if x.strip()]
    if extra_subtypes:
        print("[docudp] EXTRA SUBTYPES: also answering each 80-byte packet with subtype(s) %s "
              "(subtype 3 is accepted only at conn state 3, subtype 4 only at state 5)"
              % extra_subtypes, flush=True)

    chara_kw = {}
    if a.lobby_chara_count >= 0:
        n = min(a.lobby_chara_count, CHARA_MAX_RECORDS)
        if n < a.lobby_chara_count:
            print("[docudp] WARNING: --lobby-chara-count %d clamped to %d (the client "
                  "record buffer is 560 bytes)" % (a.lobby_chara_count, n), flush=True)
        # AN EMPTY SLOT IS A PRESENT-BUT-BLANK RECORD, not a zero count.
        # MEASURED: boot 15:55's accidental char=145 made the client walk 145
        # records off the end of our packet into arbitrary RAM, print
        # "#N (not use)" for every one, and offer CREATE CHARACTER with a working
        # cursor.  Boot 16:61 sent a deliberate char=0 and got four dead
        # "Unregistered" rows and a FROZEN cursor -- nothing to put a cursor on.
        # Since essentially arbitrary bytes read as unused, an all-zero record is
        # the most likely canonical spelling of "empty slot".
        recs = ([build_used_record(i, a.lobby_chara_name) for i in range(n)]
                    if a.lobby_chara_used else
                [build_probe_record(i) for i in range(n)] if a.lobby_chara_probe else
                [bytes(96) for _ in range(n)] if a.lobby_chara_blank else
                [build_chara_record(
                    i,
                    name_b=(("%s%d" % (a.lobby_chara_name, i))
                            if a.lobby_chara_name and n > 1 else a.lobby_chara_name),
                    name_a=(("%s%d" % (a.lobby_chara_name_a, i))
                            if a.lobby_chara_name_a and n > 1 else a.lobby_chara_name_a),
                    fill=a.lobby_chara_fill)
                 for i in range(n)])
        chara_kw = dict(chara_count=n, chara_records=recs,
                        chara_allow=(a.lobby_chara_allow
                                     if a.lobby_chara_allow >= 0 else None))
        if a.lobby_chara_probe:
            print("[docudp] USED-MARKER PROBE: slot i -> %s"
                  % ", ".join("#%d %s" % (i, PROBE_SLOTS[i][0])
                              for i in range(min(n, len(PROBE_SLOTS)))), flush=True)
        print("[docudp] CHARA payload ON: count=%d allow=%s -- every selector-8 reply "
              "carries it, including the answer to the 36-byte mode-2 packets"
              % (n, ("0x%02x" % a.lobby_chara_allow) if a.lobby_chara_allow >= 0
                 else "(token byte, untouched)"), flush=True)

    # sec 4dq: PERSISTENT per-account characters. When --chara-store is set,
    # the seeded chara_kw above is replaced, per peer, by that account's own
    # stored roster: four slots, each a real created character or an empty slot
    # (so CREATE CHARACTER still appears). refresh_roster() rebuilds chara_kw in
    # place, so every existing code-8 send site picks it up unchanged.
    # sec 4ft: with --accounts-db the key is resolved PER CLIENT (_skey below),
    # so the store carries no fixed account -- and must not auto-adopt one.
    _store = (doc_charastore.CharaStore(
                  a.chara_store, account=(None if a.accounts_db else a.account))
              if a.chara_store else None)
    _resolver = (doc_charastore.AccountResolver(
                     a.accounts_db,
                     os.path.join(os.path.dirname(os.path.abspath(a.chara_store)),
                                  "doc-ip-members.json"), _store)
                 if (_store is not None and a.accounts_db) else None)
    if _store is not None:
        print("[docudp] chara store %s keyed by %s" % (
            a.chara_store,
            ("the POL MEMBER signed in at each client's address (%s, read-only; "
             "sec 4ft)" % a.accounts_db) if _resolver is not None
            else ("ACCOUNT %r" % _store.account) if _store.account
            else "the entrance uid (per SESSION -- rosters split when it "
                 "rotates; set --account)"), flush=True)

    def _skey(uid, sess=None):
        """sec 4ft: the store key for the client in hand. With --accounts-db it
        is that client's POL member, resolved once per entrance and cached on
        its Session; without it, the uid, which CharaStore keys by --account or
        by itself exactly as before. `sess` names another client's session
        (sec 4fx: the relay dresses a SENDER, not the packet in hand).

        WARNING: sec 4gz, STILL OPEN: the resolve is by ADDRESS. Sessions no longer
        collide behind one household NAT, but two POL members playing from one
        house still resolve through `resolve(ip)` -- and if that hands both the
        same member, both get the same roster and (member + slot) the same
        charid, at which point adopt_session's live-collision guard is the only
        thing keeping them apart. Fixing THAT means resolving the member from
        something in the datagram, not from where it came from."""
        _s = sess if sess is not None else current[0]
        if _resolver is None or _s is None:
            return uid
        if _s.account_key is None:
            _s.account_key = _resolver.resolve(_s.ip)
        return _s.account_key
    _roster_uid = [0]

    # sec 4gk: the shop -- stock, prices, and a wallet + bag per CHARACTER.
    _shop = (doc_shop.Shop(a.shop, stock_path=a.shop_stock,
                           start_gil=a.shop_start_gil) if a.shop else None)
    if _shop is not None:
        print("[docudp] SHOP ON: %s, %d stocked (PLACEHOLDER prices%s), start gil "
              "%d -- answers 64/66 buy/68 sell/141/143/145, gil+bag on the world door (sec 4gk)"
              % (a.shop, len(_shop.stock),
                 "" if not a.shop_stock else ", from %s" % a.shop_stock,
                 _shop.start_gil), flush=True)
    # sec 4go: bullets issued into every world-door bag (the magazine fills
    # from them; an empty bag was the gun that never fired).
    _ammo = doc_shop.parse_issue(a.issue_ammo)
    print("[docudp] AMMO %s -- topped up in the world-door bag every login, not "
          "persisted (sec 4go)" % (", ".join("0x%08x x%d" % (i, q) for i, q in _ammo)
                                   or "OFF"), flush=True)

    # 2026-09-13: Unit Management (doc_unit.py), keyed like the shop wallet.
    _units = (doc_unit.Units(a.units, fee=a.unit_fee, shop=_shop,
                             accounts_db=a.accounts_db) if a.units else None)
    if _units is not None:
        print("[docudp] UNITS ON: %s, %d unit(s), fee %d gil -- lobby commands "
              "24/13/25/8/12/9/10/11, enlisted unit at world-door body[60]"
              % (a.units, len(_units.data["units"]), _units.fee), flush=True)

    # 2026-09-13: CHANGE MASK / ARMOR (doc_gear.py), keyed like the shop wallet.
    # 'auto' puts doc-gear.json next to the shop file, so a deployment needs no compose
    # edit; without --shop there is no per-character identity to key it on.
    _gear_path = a.gear_store
    if _gear_path == "auto":
        _gear_path = (os.path.join(os.path.dirname(os.path.abspath(a.shop)),
                                   "doc-gear.json") if a.shop else "")
    elif _gear_path == "off":
        _gear_path = ""
    _gearstore = doc_gear.GearStore(_gear_path) if _gear_path else None
    print("[docudp] GEAR %s" % (
        ("ON: %s, %d character(s) -- lobby commands 17 equip / 18 unequip answered "
         "with the new costume at 241 body[6], served back on the world door"
         % (_gear_path, len(_gearstore.data))) if _gearstore is not None else
        "OFF -- mask/armor changes answered generically (costume reset), not stored"),
          flush=True)

    # 2026-09-13: LOBBY NPCs (doc_npc.py) -- commands 26/27/39.
    _npc_over = doc_npc.parse_overrides(a.npc_events)
    if a.npc == "on":
        print("[docudp] NPCs ON: command 26 -> the talked-to NPC's event id "
              "(%d NPC tables, %d scene follow-up(s) on (trigger, b), "
              "%d override(s)); 27/39 acked"
              % (len(doc_npc.NPC_EVENTS), len(doc_npc.FOLLOWUP), len(_npc_over)),
              flush=True)
    # sec 4gs addendum 3: the lobby NPC push. Per client ip, main-scope on
    # purpose (Session has __slots__): {"due", "ready_at", "done", "seen"}.
    _npc_spawn_only = doc_npc_spawn.parse_only(a.npc_spawn_only)
    _npc_spawn = {}
    # sec 4gs addendum 4: session -> when to push the arena ring (after GO).
    _npc_arena_due = {}
    # 2026-09-23: mission NPC replacement. sess -> {"types": {id: type},
    # "spawn": [[x,y,z]..], "next": next index, "due": [(time, type), ..]}
    _mnpc = {}
    # 2026-09-23 (sec 4hc): the intro push, keyed by session key (so the
    # adoption re-key below must list it). value = when to send; the send
    # records the key in _intro_sent so one session gets one push.
    _intro_due = {}
    _intro_sent = set()
    _npc_arena_types = doc_npc_spawn.parse_types(a.npc_arena_types)
    if a.npc_arena == "on":
        print("[docudp] NPC ARENA TEST ON: %d NPC(s) (types %s) in a %.0f-unit "
              "ring around the arena spawn, %.0f s after the battle GO"
              % (len(_npc_arena_types), a.npc_arena_types, a.npc_arena_radius,
                 a.npc_arena_after), flush=True)
    if a.npc_spawn == "on":
        print("[docudp] NPC SPAWN ON: via %s, %d NPC(s), type=%s, %.0f s after "
              "the in-world stream starts%s"
              % ("type-125 world update (nibble-4 ids)" if a.npc_spawn_via == "wu"
                 else "notify kind %d, ready=%s" % (doc_npc_spawn.KIND_ADD_NPC,
                                                    a.npc_spawn_ready),
                 len(doc_npc_spawn.select(_npc_spawn_only)), a.npc_spawn_type,
                 a.npc_spawn_delay,
                 (", resent every %.0f s" % a.npc_spawn_every)
                 if a.npc_spawn_via == "wu" and a.npc_spawn_every > 0 else ""),
              flush=True)

    # 2026-09-13: PLAY TIME (lobby command 20), per character, keyed like the
    # shop wallet. Accrues from each client's datagram gaps (doc_playtime.py).
    _pt_path = (a.play_time if a.play_time is not None
                else os.path.join(os.path.dirname(os.path.abspath(a.chara_store)),
                                  "doc-playtime.json") if a.chara_store else "")
    _playtime = doc_playtime.PlayTime("" if _pt_path == "off" else _pt_path)
    _pt_key = {}             # (client ip, charid) -> wallet key, resolved once
    if a.lobby_clock == "play":
        print("[docudp] PLAY TIME ON: %s, %d character(s) -- command 20 answers "
              "the selected character's seconds at body[16]"
              % (_playtime.path or "(memory only)", len(_playtime.data)),
              flush=True)

    def _rank_characters():
        """Every character in the chara store under a `member:N` key, as
        (wallet key, name, character id) -- the same key _wallet_key builds for
        the asker, so VIEW YOUR RANKING finds its own row. uid-keyed rosters
        (pre --accounts-db) and archived keys are left out."""
        if _store is None:
            return []
        out = []
        for key, chars in _store.data.items():
            if not (key.startswith("member:") and key[7:].isdigit()):
                continue
            for c in chars or ():
                cid = chara_id_for(a.chara_id_base, 0, key, c.get("slot", 0))
                if cid:
                    out.append(("%s/0x%08x" % (key, cid & 0x3FFFFFFF),
                                c.get("name", ""), cid))
        return out

    _rank = (doc_rank.Rankings(a.rankings, characters=_rank_characters,
                               show_zero=not a.rankings_hide_zero,
                               units=(_units.ranking_units if _units else None))
             if a.rankings else None)
    if _rank is not None:
        print("[docudp] RANKINGS ON: %s, %d character(s) in the chara store -- "
              "answers 137 -> 138 (Individual) and 149 -> 150 (Unit)"
              % (a.rankings, len(_rank_characters())), flush=True)

    # 2026-09-13: CAREERS (doc_stats.py). The Status screen, the battle result,
    # the Ranking menu's values and the Viewer profile all read this one store.
    _stats = doc_stats.Stats(a.stats) if a.stats else None
    _novice = (doc_novice.Novice(_stats, a.novice_kills)
               if (a.novice == "on" or a.intro == "on") else None)
    if _stats is not None:
        if _rank is not None:
            _stats.push_rankings(_rank)
        print("[docudp] STATS ON: %s, %d career(s) -- world door body[56]/[68]/"
              "[131], 139 -> 140 career record, kind-4 result totals"
              % (a.stats, len(_stats.data["chars"])), flush=True)
        # 2026-09-26: the WEEKLY medals (doc_stats.WEEKLY_MEDALS). The career
        # clock stamps every battle / leave into its week's tallies; a week
        # that ENDED while the server was down is closed right here.
        _stats.week_phase = doc_stats.parse_week_start(a.week_start)
        if a.test_clock_offset:
            _stats.clock = lambda: time.time() + a.test_clock_offset
            print("[docudp] TEST CLOCK: careers run %+.0f s off the wall clock"
                  % a.test_clock_offset, flush=True)
        print("[docudp] WEEKLY MEDALS %s: week starts %r, next close %s"
              % (a.weekly_medals.upper(), a.week_start,
                 _stats.next_week_close() or "none (no open week)"), flush=True)

    def weekly_close(why):
        """Close every ended, unclosed week (doc_stats.Stats.close_due)."""
        if _stats is None or a.weekly_medals != "on":
            return
        for _wk, _v in _stats.close_due():
            print("[docudp] WEEK CLOSED (%s): %d player(s)" % (why, _v["players"]),
                  flush=True)
            for _ln in _stats.week_lines(_wk, _v):
                print("[docudp]   %s" % _ln, flush=True)

    def weekly_deadline():
        """The wall-clock time the earliest open week ends, or None."""
        if _stats is None or a.weekly_medals != "on":
            return None
        _t = _stats.next_week_close()
        return None if _t is None else _t - a.test_clock_offset

    weekly_close("startup catch-up")

    def _bag_move(key, changes):
        """Apply [(item, +n/-n)] to `key`'s SERVER bag (doc_shop); returns a
        short description of what moved. A take never goes below zero."""
        if not changes or _shop is None:
            return ""
        w = _shop.wallet(key)
        done = []
        for iid, n in changes:
            k = "0x%08x" % iid
            have = int(w["bag"].get(k, 0))
            new_q = max(0, min(doc_shop.QTY_MAX, have + int(n)))
            if new_q:
                w["bag"][k] = new_q
            else:
                w["bag"].pop(k, None)
            done.append("%s %+d" % (_shop.name(iid), new_q - have))
        _shop.save()
        return ", ".join(done)

    def _wallet_key(uid, charid, sess=None):
        """The shop wallet key: the chara store's account key (per POL member
        with --accounts-db) plus the character id, so each character has its
        own gil and bag. `sess` = another client's session (a trade partner)."""
        acct = _skey(uid, sess) if (_resolver is not None or uid) else None
        if not isinstance(acct, str):
            if _store is not None and _store.account:
                acct = _store.account
            elif uid:
                acct = "0x%08x" % (uid & 0xFFFFFFFF)
            else:
                acct = "anon"
        charid &= 0x3FFFFFFF
        return ("%s/0x%08x" % (acct, charid)) if charid else acct

    def refresh_roster(uid):
        if _store is None:
            return
        slots = _store.roster(_skey(uid))
        # sec 4dv: each slot gets a REAL character id at wire+0. It has to be
        # stable across sessions (it keys the peer table and the profile cache)
        # and unique per character on the shard, so derive it from the account
        # uid and the slot rather than a counter nobody persists.
        recs = []
        for i in range(doc_charastore.MAX_SLOTS):
            if not slots[i]:
                # 2026-09-13: an EMPTY slot still names its own slot (wire+84,
                # used flag clear): the charamake answer's record updates the
                # list entry whose slot byte matches it (0x00587cf0), and an
                # all-zero record made every empty entry "slot 0".
                _er = bytearray(96)
                _er[84] = i & 0x7F
                recs.append(bytes(_er))
                continue
            # sec 4dv + 09-13: per MEMBER, not per entrance uid -- two members
            # share one uid (see chara_id_for)
            cid = chara_id_for(a.chara_id_base, uid, _skey(uid), i)
            recs.append(build_used_record(i, slots[i]["name"], slots[i],
                                          char_id=cid,
                                          chr_code=a.chara_chrcode))
            if cid:
                current[0].chara_ids[i] = cid
        current[0].chara_kw.clear()
        current[0].chara_kw.update(chara_count=doc_charastore.MAX_SLOTS,
                        chara_records=recs,
                        chara_allow=(a.lobby_chara_allow
                                     if a.lobby_chara_allow >= 0 else None))
        current[0].roster_uid[0] = uid
        names = ["%s(id 0x%x)" % (slots[i]["name"], current[0].chara_ids.get(i, 0))
                 if slots[i] else "(empty)"
                 for i in range(doc_charastore.MAX_SLOTS)]
        print("[chara] roster for 0x%08x [%s]: %s" % (uid, _skey(uid),
                                                     ", ".join(names)), flush=True)

    _chara_ids = {}       # slot -> the id we served, for logging

    def _player_name():
        # sec 4dr (2026-09-11): the name for the in-world PLAYER record -- the
        # user list (selector 11/19) and peer (37) records that drive the name
        # plate and the profile the game reads. It MUST be the selected
        # character's stored name, NOT --lobby-chara-name: that seed ("Quarry")
        # leaked into the name plate for months while the code-8 select list
        # correctly served the real name, so the character showed as Quarry in
        # world even though the roster said Lex. Resolve via seen_charid (the
        # selected [kelsvc+272]) against the account's roster; fall back to
        # --user-list-name (or empty) -- never the Quarry seed.
        if _store is not None and seen_uid[0]:
            _cid = seen_charid[0] & 0x3FFFFFFF
            _slots = _store.roster(_skey(seen_uid[0]))
            for _si in range(doc_charastore.MAX_SLOTS):
                if _slots[_si] and (current[0].chara_ids.get(_si) == _cid or not _cid):
                    return _slots[_si].get("name") or (a.user_list_name or "")
        return a.user_list_name or ""

    if _store is not None:
        chara_kw.clear()
        chara_kw.update(chara_count=doc_charastore.MAX_SLOTS,
                        chara_records=[bytes(96)] * doc_charastore.MAX_SLOTS,
                        chara_allow=(a.lobby_chara_allow
                                     if a.lobby_chara_allow >= 0 else None))
        print("[docudp] CHARA STORE ON: %s -- created characters persist per "
              "account (sec 4dq)" % a.chara_store, flush=True)

    # sec 4fq: each Session copies this default so two accounts never mix rosters
    default_chara_kw = dict(chara_kw)

    lobby_edits = []
    if a.lobby_edit:
        for pair in a.lobby_edit.split(","):
            off, hh = pair.split(":")
            lobby_edits.append((int(off), int(hh, 16)))

    def is_lobby(pkt):
        # Everything that is NOT the 80-byte type-128 entrance handshake is lobby
        # traffic: the 96-byte type-129 (body 05 01 ...) AND the 24-byte bodyless
        # control packet the client emits ~50 ms after we echo a 96-byte one.
        # The entrance still needs the subtype-4 redirect; everything else gets the
        # lobby probe.
        return len(pkt) != 80

    def _is_close_request(pkt):
        """Is this the nest's CLOSE request -- the message phase 109 sends?

        The builder 0x00589f38 writes the selector to body[1] (`sb a2, 1(t3)`,
        t3 = buf+20), and the close initiator 0x00587a98 passes a2 = 3.  The
        message is 12 bytes long ([buf+18] = 12), so it arrives as a 36-byte
        mode-2 datagram whose body is plaintext: `05 03 00 00 ...`.  Compare the
        2->6 arm 0x005884d0, which passes a2 = 7 -- the `05 07 ...` body we have
        been answering with a code-8 all along.
        """
        if not a.nest_close_answer:
            return False
        return len(pkt) >= BODY_OFF + 2 and pkt[BODY_OFF + 1] == 3

    if a.save:
        os.makedirs(a.save, exist_ok=True)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.bind, a.port))
    print("[docudp] listening on %s:%d  mode=%s subtype=%d crypto=%s modebyte=%d cksum=%s type=%d flags=%02x lobby=%s:%d"
          % (a.bind, a.port, a.mode, a.subtype, a.crypto, a.mode_byte, not a.no_cksum, a.ptype, a.flags, a.lobby_ip, a.lobby_port), flush=True)
    print("[docudp] watch the PCSX2 console for '[KEL NET ENT]Drop packet bad packet'"
          " -- that means it REACHED the handler", flush=True)

    n = 0
    answered = 0
    last_rx = 0.0            # sweep-mode debug clock (single-client only)
    sweep_i = -1

    class Session:
        """sec 4fq (2026-09-12): per-CLIENT connection state, keyed by source IP.
        The battletable STORE stays shared (one match), but the connect/nest/
        lobby handshake, the learned charaid, the game-server channel and every
        timer are per client -- two concurrent clients used to clobber a single
        global session (and CER-48104 on the second). The boxed [0] fields keep
        the existing `name[0]` access working after a per-iteration rebind."""
        __slots__ = ("chara_burst_at", "chara_pending", "frag3_pending",
                     "frag3_sent", "ka_src", "ka_template", "ka_next", "ka_sent",
                     "ka_first", "kel_ka_next", "gs_done", "gs_ka_src",
                     "gs_ka_next", "gs_seq", "gs_teams", "gs_join_deadline",
                     "gs_bots_sent", "gs_join_src", "gs_rearm_next", "last_pose",
                     "gs_rearm_pending",
                     "last_wu", "seen_uid", "seen_charid", "last_stream",
                     "last_peer_rx", "save_count", "chara_kw",
                     "chara_ids", "roster_uid", "gs_src", "src", "wire_cid",
                     "relay_pushed", "relay_wu", "ip", "key", "account_key",
                     "pos_id", "gs_battle_on",
                     "gs_battle_end", "gs_battle_reset", "gs_battle_go",
                     "suit_item")

        def __init__(self, ip=None, port=0):
            self.ip = ip                  # sec 4ft: the key's address
            self.key = (ip, port)         # sec 4gz: the registry key, (ip, port)
            self.account_key = None       # sec 4ft: resolved lazily by _skey
            self.chara_burst_at = None
            self.chara_pending = None
            self.frag3_pending = None
            self.frag3_sent = 0
            self.ka_src = None
            self.ka_template = None
            self.ka_next = None
            self.ka_sent = 0
            self.ka_first = None
            self.kel_ka_next = 0.0
            self.gs_done = [False]
            self.gs_ka_src = [None]
            self.gs_ka_next = [0.0]
            self.gs_seq = [0]
            self.gs_teams = {}
            self.suit_item = None     # 2026-09-24: the world-door suit (Magic Suit pays x0.6 MP)
            self.gs_join_deadline = [0.0]
            self.gs_bots_sent = [False]
            # 2026-09-23: re-send the message-27 arm on every keepalive until
            # this client's first team request (31/33) after a 38
            self.gs_rearm_pending = [False]
            self.gs_join_src = [None]
            self.gs_battle_on = [0.0]      # sec 4fy: request 47 answered once
            self.gs_battle_end = [0.0]     # sec 4fy: when to send the result
            self.gs_battle_reset = [0.0]   # sec 4fy: when to send selector 39
            self.gs_battle_go = [0.0]      # sec 4ga: when to send 5,53 (START)
            self.gs_rearm_next = [0.0]
            self.last_pose = [None]
            self.last_wu = [0.0]
            self.seen_uid = [0]
            self.seen_charid = [0]
            self.wire_cid = [0]        # sec 4gz: the charid its packets STAMP
                                       # at +16 -- identity for session keying
                                       # only; seen_charid stays the selected
                                       # character the ladder proved (sec 4dv)
            self.last_stream = [0.0]
            self.last_peer_rx = [0.0]
            self.save_count = [0]
            self.chara_kw = dict(default_chara_kw)
            self.chara_ids = {}
            self.roster_uid = [0]
            self.gs_src = [None]     # sec 4ft: this client's game-server
                                     # address once its channel is up (a GS
                                     # request since its last 38); None = not
                                     # in a briefing room, push nothing to it
            self.src = None             # sec 4fu: (ip, port) to relay peers to
            self.relay_pushed = {}      # sec 4fu: peer id -> last record push
            self.relay_wu = {}          # sec 4fu: peer id -> last type-125 spawn
            self.pos_id = [0]           # sec 4fu: the id its own 0x83s carry

    # sec 4gz (2026-09-21): (src IP, src PORT) -> Session, NOT the IP alone.
    # Two consoles behind ONE household NAT arrive on one address, so an
    # IP-keyed registry handed them a single Session: one seen_uid, one roster,
    # one set of gs_* timers, one peer table, and replies to whichever sent
    # last -- the pre-sec-4fq "second client dies at CER-48104" failure
    # rescoped to a house, and a public-server blocker.
    # MEASURED (doc_gunfire_emulog_20260913_1453.txt, a 12-minute session that
    # reached the game-server channel): the title uses exactly ONE UDP source
    # port for everything -- `Binding UDP fixed port 56138` once, to 55040,
    # with the lobby AND the game-server channel on it (the other binds in that
    # log are DNS, to port 53). The three captures on hand agree
    # (56138 only). So ka_src / gs_src / gs_ka_src / gs_join_src are snapshots
    # of the same endpoint, not evidence of several ports, and (ip, port) is one
    # key per client. A NAT mapping can still MOVE mid-session, so the charid
    # adoption below re-joins a client that reappears on a new port.
    sessions = {}            # (src IP, src port) -> Session

    # sec 4ha: PUBLISH THE POPULATION, ON A THREAD. Each session-carrying
    # service writes `<dir>/<service>-sessions-live.json` = {count, stamp}, so a
    # deploy script can defer a restart while someone is live and a status bot
    # can show the count (POL_DOC_LIVE_DIR, default /logs).
    # WARNING: NOT on the packet loop, which is where this started. The loop blocks
    # in select() while nobody is connected, so the marker was written once at
    # startup and never again and a reader saw it go stale after a few minutes.
    # A thread ticks whether or not anyone sends a packet, which is the whole
    # point of a liveness marker.
    # WARNING: /logs, NOT POL_DATA_DIR: /data is mounted READ-ONLY in this container,
    # so the write failed silently there. /logs is the writable mount, where
    # the rankings and chara store already live.
    def _publish_live_sessions():
        import time as _t
        while True:
            try:
                _lp = os.path.join(os.environ.get("POL_DOC_LIVE_DIR", "/logs"),
                                   "doc-sessions-live.json")
                _lt = "%s.tmp.%d" % (_lp, os.getpid())
                with open(_lt, "w") as _lf:
                    _lf.write('{"count": %d, "stamp": %f}'
                              % (len(sessions), _t.time()))
                os.replace(_lt, _lp)
            except Exception:
                pass                 # a status line is never worth an exception
            _t.sleep(10.0)

    import threading as _threading
    _threading.Thread(target=_publish_live_sessions, name="doc-live-sessions",
                      daemon=True).start()
    current = [None]         # sec 4fq: the session of the packet in hand
    players = {}             # sec 4fr: charid -> {name, uid}, SHARED so
                             # each client is served the OTHER players
    # sec 4ft: per-TABLE briefing state, SHARED by the seated clients:
    #   key -> {"teams": {charid: team}, "shown": {observer: {charid: team}},
    #           "ready_at": when the roster first read ready, "dist": sent,
    #           "why": the last readiness verdict printed}
    gs_tables = {}
    try:
        _gs_bmap = (tuple(int(x, 0) for x in a.gs_battle_map.split(",")
                          if x.strip()) + (0, 0))[:2]
    except ValueError:
        raise SystemExit("--gs-battle-map wants M0,M1, got %r" % a.gs_battle_map)
    _zone_pieces = parse_zone_pieces(a.zone_pieces)
    if _zone_pieces:
        print("[arena] kind-2 map0/map1 per zone (--zone-pieces): %s"
              % ", ".join("z%d=%d,%d" % (z, m[0], m[1])
                          for z, m in sorted(_zone_pieces.items())), flush=True)
    _gs_stat_list = []
    for _pair in (a.gs_stats or "").replace(" ", "").split(","):
        if _pair:
            _k2, _, _v2 = _pair.partition(":")
            _gs_stat_list.append((int(_k2, 0), int(_v2, 0)))

    def session_of(charid):
        """sec 4ft: the session whose client is `charid` (its record+4).

        sec 4gz: the MOST RECENTLY HEARD one. Normally there is only ever a
        single match -- a port move is folded away by adopt_session -- but when
        two live clients claim one charid (accounts that resolved to the same
        character) the reply belongs to whichever is actually sending, not to
        whichever the dict happens to list first.
        """
        if not charid:
            return None
        best = None
        for _ss in sessions.values():
            if _ss.seen_charid[0] != charid:
                continue
            if best is None or _ss.last_peer_rx[0] > best.last_peer_rx[0]:
                best = _ss
        return best

    # -- 2026-09-23 (sec 4hc): the new-player intro and the novice mark -------

    def _unit_of_cid(cid):
        """2026-09-24: the unit a seated character is enlisted in, or 0 (it
        needs the character's live session to build its wallet key)."""
        if _units is None or not cid:
            return 0
        us = session_of(cid)
        if us is None:
            return 0
        return _units.enlisted(_wallet_key(us.seen_uid[0], cid, us))
    def _novice_key(sess):
        """The career key of the character this session is playing, or None."""
        cid = sess.seen_charid[0] if sess is not None else 0
        if not cid:
            return None
        return _wallet_key(sess.seen_uid[0], cid, sess)

    def novice_cid(cid):
        """True when character `cid` still wears the novice mark (--novice on).
        Keyed through its live session first, else the career file."""
        if _novice is None or a.novice != "on" or not cid:
            return False
        key = _novice_key(session_of(cid))
        if key is None and _stats is not None:
            key = _stats.key_for_charid(cid)
        return key is not None and _novice.is_novice(key)

    def rp_of_cid(cid):
        """2026-09-26: character `cid`'s career rank points for a table's
        Min/Max RP (rp_allowed), or None = not checked (--rp-tables open,
        no --stats, no character). Keyed like novice_cid."""
        if _stats is None or a.rp_tables != "enforce" or not cid:
            return None
        key = _novice_key(session_of(cid))
        if key is None:
            key = _stats.key_for_charid(cid)
        if key is None:
            return 0                     # no career yet = a fresh 0 RP one
        return int(_stats.peek(key).get("rp", 0))

    def peer_flags(cid):
        """The peer record's FLAGS for character `cid`: --user-flags, plus bit
        0x40 while it is a novice. wire+30 lands on peer-table byte +0x2f, the
        byte selector 134 sub 11 clears (doc_novice_proof E)."""
        f = a.user_flags
        if novice_cid(cid):
            f = (f or 0) | doc_novice.NOVICE_BIT
        return f

    def send_push(sess, body, ident, what):
        """An unsolicited type-127 lobby message to one client."""
        if sess is None or sess.src is None:
            return False
        s.sendto(seal_world_body(None, body, seq=a.lobby_seq,
                                 ptype=a.world_type, ident=ident), sess.src)
        print("  [novice] SENT selector %d %s to %s:%d (ident 0x%08x)"
              % (doc_novice.SEL_PUSH, what, sess.src[0], sess.src[1],
                 ident & 0xFFFFFFFF), flush=True)
        return True

    def issue_supplies(sess, dst):
        """2026-09-26: message 27 (the reward grant, which ADDS to the bag and
        prints "You obtain %s x%d") with whatever tops this player up to the
        battle's supplies: the mission's Initial Supplies, the standard issue
        for PvP. The login top-up alone let ammo run dry over a session."""
        if not a.mission_supplies or sess.key not in _supply_bag:
            return
        quest = _mission_battle.get(sess.key)
        want = doc_missions.supplies(quest, _ammo or
                                     doc_missions.STANDARD_SUPPLIES)
        held = _supply_bag[sess.key]
        grant = doc_shop.supply_grant(held, want)
        if not grant:
            print("  [supplies] 0x%08x already holds %s's supplies"
                  % (sess.seen_charid[0], "quest %s" % quest if quest
                     else "a PvP battle"), flush=True)
            return
        s.sendto(build_gs_stats(grant, seq=next_gs_seq(sess),
                                ident=sess.seen_charid[0]), dst)
        for iid, q in grant:
            held[iid] = held.get(iid, 0) + q
        print("  [supplies] 0x%08x %s: SENT message 27 granting %s"
              % (sess.seen_charid[0], "quest %s" % quest if quest
                 else "PvP", ", ".join("0x%08x x%d" % g for g in grant)),
              flush=True)

    def relay_chat(sender, body):
        """2026-09-26: a selector-255 chat line to the players who must see
        it (doc_chat). Nothing is ANSWERED to the sender -- sec 4bz still holds."""
        if a.chat == "off":
            return 0
        now = time.time()
        live = {_ss.seen_charid[0] for _ss in list(sessions.values())
                if _ss.seen_charid[0] and not peer_idle(_ss, now)}
        p = doc_chat.parse(body)
        n = 0
        for cid in doc_chat.recipients(body, sender, live,
                                       chat_where if a.chat == "on" else None):
            ts = session_of(cid)
            dst = (ts.ka_src or ts.src) if ts is not None else None
            if dst is None:
                continue
            s.sendto(seal_world_body(None, doc_chat.relay_body(body),
                                     seq=a.lobby_seq, ptype=a.world_type,
                                     ident=sender), dst)
            n += 1
        if p is not None:
            print("  [chat] 0x%08x %s %r -> %d player(s)%s"
                  % (sender, "TELL 0x%08x" % p[1] if p[0] == doc_chat.KIND_TELL
                     else "%s (kind %d)" % (doc_chat.kind_name(p[0]), p[0]),
                     p[2], n, "" if a.chat == "on" else " [--chat=all]"),
                  flush=True)
        return n

    def chat_where(cid):
        """doc_chat.Where for `cid`: its lobby area off the last position it
        streamed (or the battle room it is fighting in), its battletable
        reservation, and its team (the room's, else the team it picked)."""
        room = battle_of(cid)
        if room is not None and (cid not in room.members or cid in room.left):
            room = None
        ts = session_of(cid)
        if room is not None:
            area = ("battle", room.key)
        else:
            area = doc_chat.lobby_area(ts.last_pose[0] if ts is not None
                                       else None)
        if room is not None:        # BT: every player is their own side
            team = None if room.individual() else room.team_of(cid)
        else:
            team = ts.gs_teams.get(cid) if ts is not None else None
        return doc_chat.Where(area, bt_store.table_of(cid),
                              room.key if room is not None else None, team)

    def broadcast_graduate(cid, why):
        """Selector 134 sub-kind 11 to every client in the world: the mark comes
        off `cid` on every peer table, and on its own self record."""
        body = doc_novice.graduate_push(
            subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7))
        n = 0
        now = time.time()
        for _ss in list(sessions.values()):
            if not _ss.seen_charid[0] or peer_idle(_ss, now):
                continue
            if send_push(_ss, body, cid, "sub 11 (novice mark OFF for 0x%08x)"
                         % cid):
                n += 1
        print("  [novice] 0x%08x GRADUATED (%s) -- mark-removed push to %d "
              "client(s)" % (cid, why, n), flush=True)

    # sec 4gz: ADOPTION -- what a session inherits from the port its client
    # moved off. Every name in Session.__slots__ has to appear in exactly one
    # of these five tuples; the audit below REFUSES TO START otherwise, because
    # a slot nobody classified is the class of bug that crash-loops every
    # client (Session has __slots__, so a typo is an AttributeError mid-session).
    _INHERIT_COPY = (        # carried over verbatim (boxed [0] or plain)
        "frag3_sent", "ka_sent", "ka_first", "gs_done",
        "gs_ka_next", "gs_join_deadline", "gs_bots_sent", "gs_rearm_next",
        "gs_rearm_pending", "gs_battle_on", "gs_battle_end", "gs_battle_reset", "gs_battle_go",
        "gs_seq", "last_pose", "last_wu", "seen_uid", "seen_charid", "wire_cid",
        "last_stream", "save_count", "roster_uid", "pos_id", "account_key",
        "chara_pending", "chara_burst_at", "suit_item")
    _INHERIT_DICT = (        # merged into the box we already hold
        "gs_teams", "chara_kw", "chara_ids", "relay_pushed", "relay_wu")
    _INHERIT_RETARGET = (    # an endpoint: kept as a FLAG, aimed at the new port
        "gs_src", "gs_ka_src", "gs_join_src")
    _INHERIT_SPECIAL = ("frag3_pending",     # a held reply: retargeted by hand
                        "ka_template")       # only if the new port has none yet
    _INHERIT_KEEP = (        # the new port's own truth -- never inherited
        "ip", "key", "src", "ka_src", "ka_next", "kel_ka_next", "last_peer_rx")
    _INHERIT_ALL = (_INHERIT_COPY + _INHERIT_DICT + _INHERIT_RETARGET
                    + _INHERIT_SPECIAL + _INHERIT_KEEP)
    _slot_set = set(Session.__slots__)
    _unclassified = sorted(_slot_set - set(_INHERIT_ALL))
    _phantom = sorted(set(_INHERIT_ALL) - _slot_set)
    _twice = sorted({n for n in _INHERIT_ALL if _INHERIT_ALL.count(n) > 1})
    if _unclassified or _phantom or _twice:
        raise SystemExit(
            "[docudp] sec 4gz session-inherit audit FAILED -- fix the tuples "
            "before this ships: unclassified slots %s, names that are not "
            "slots %s, names listed twice %s"
            % (_unclassified, _phantom, _twice))
    print("[docudp] sec 4gz: sessions key on (ip, port); inherit audit OK "
          "(%d/%d Session slots classified, adopt=%s idle>=%.1fs, "
          "reap idle>%s)"
          % (len(_INHERIT_ALL), len(Session.__slots__),
             "on" if a.session_adopt else "OFF", a.session_adopt_idle,
             ("%.0fs" % a.session_idle_drop) if a.session_idle_drop > 0
             else "never"), flush=True)

    def session_inherit(new, old):
        """Move `old`'s accumulated state into `new` (sec 4gz).

        Direction matters: the state comes TO the session in hand, so `sess`
        and every boxed per-client local the main loop rebound at the top of
        the iteration (`gs_done = sess.gs_done`, ...) stay valid -- the boxes
        are updated IN PLACE (`[:] =`), never replaced.
        """
        for _n in _INHERIT_COPY:
            _v = getattr(old, _n)
            if isinstance(_v, list):
                getattr(new, _n)[:] = _v
            else:
                setattr(new, _n, _v)
        for _n in _INHERIT_DICT:
            _d = getattr(new, _n)
            _d.clear()
            _d.update(getattr(old, _n))
        for _n in _INHERIT_RETARGET:
            # The channel was up on the old port; the client is on the new one.
            getattr(new, _n)[0] = (new.src if getattr(old, _n)[0] is not None
                                   else None)
        if new.ka_template is None:
            new.ka_template = old.ka_template
        if old.frag3_pending is not None:
            # A HELD character-list fragment. Its captured target is the dead
            # port, so it follows the client instead of being sent into the void.
            new.frag3_pending = (old.frag3_pending[0], new.src)
        # sec 4gz: the per-client state that lives OUTSIDE Session, because
        # Session has __slots__ -- re-key it from the dead port to this one.
        # WARNING: ANY new dict keyed by a session key belongs in this list; the NPC
        # one is measured (without it the moved client was sprayed with all 33
        # lobby NPCs a second time).
        for _tbl in (_npc_spawn, _quest_pick, _mission_battle, _intro_due):
            if old.key in _tbl:
                _tbl[new.key] = _tbl.pop(old.key)
        if old.key in _intro_sent:
            _intro_sent.add(new.key)
        for _ptk in [_k for _k in _pt_key if _k[0] == old.key]:
            _pt_key[(new.key, _ptk[1])] = _pt_key.pop(_ptk)

    _adopt_warned = {}

    def adopt_session(new, charid, now):
        """sec 4gz: one player, ONE session, even when its source port moves.

        A client's UDP mapping can be re-bound by its own router (SE's client
        idles the socket for ~20-48 s in the lobby, which is inside a domestic
        NAT's UDP timeout), and it then reappears on a new port with the same
        character id. Fold the predecessor's state into the session in hand and
        retire it.

        WARNING: REFUSED while the other session is still live: one client uses one
        socket (measured, see `sessions` above), so two concurrently-sending
        ports that claim one charid are TWO PLAYERS whose identity collapsed
        upstream (the chara store resolves its account key from the IP, so two
        members behind one NAT can be handed the same member and the same
        slot). Merging them would be the very collision this keying fixes.
        """
        if not a.session_adopt or not charid or len(sessions) < 2:
            return None
        for old in list(sessions.values()):
            if (old is new or old.ip != new.ip
                    or charid not in (old.wire_cid[0], old.seen_charid[0])):
                continue
            _idle = now - (old.last_peer_rx[0] or 0.0)
            if _idle < a.session_adopt_idle:
                if now - _adopt_warned.get(charid, 0.0) > 30.0:
                    _adopt_warned[charid] = now
                    print("[session] WARNING: %s:%d and %s:%d BOTH claim charid "
                          "0x%08x and both are live (%.1f s apart) -- NOT "
                          "merging: that is two players whose accounts "
                          "resolved to one character, not one moved port "
                          "(sec 4gz)"
                          % (old.key[0], old.key[1], new.key[0], new.key[1],
                             charid, _idle), flush=True)
                continue
            session_inherit(new, old)
            sessions.pop(old.key, None)
            print("[docudp] SESSION ADOPTED: charid 0x%08x moved from %s:%d "
                  "(idle %.1f s) to %s:%d -- state carried over (uid 0x%08x, "
                  "roster uid 0x%08x, %d chara ids, gs_seq %d, gs_done %s, "
                  "%d peer pushes, %d teams) -- %d client(s) now"
                  % (charid, old.key[0], old.key[1], _idle,
                     new.key[0], new.key[1], new.seen_uid[0],
                     new.roster_uid[0], len(new.chara_ids), new.gs_seq[0],
                     new.gs_done[0], len(new.relay_pushed), len(new.gs_teams),
                     len(sessions)), flush=True)
            return old
        return None

    def gs_table_state(key):
        return gs_tables.setdefault(key, {"teams": {}, "shown": {},
                                          "ready_at": None, "dist": False,
                                          "why": None, "auto_at": None})

    # sec 4gk addendum 5: player-to-player TRADE (doc_trade.py). The server is
    # a relay: offers go to the partner as 42/44, and when both have confirmed
    # the wallets are swapped and both clients get 50 (the client applies the
    # swap itself from the two stored offers) -- or 48 if the swap is refused.
    _trade = doc_trade.TradeBook() if (a.trade and _shop is not None) else None
    if _trade is not None:
        print("[docudp] TRADE ON: 41/43/47/49 relayed as 42/44/50/48 (sec 4gk)",
              flush=True)

    def trade_push(charid, body):
        ts = session_of(charid)
        dst = (ts.ka_src or ts.src) if ts is not None else None
        if dst is None:
            print("  [trade] 0x%08x has no live session -- push %d dropped"
                  % (charid, body[1]), flush=True)
            return False
        s.sendto(seal_world_body(None, body, seq=a.lobby_seq, ptype=a.world_type,
                                 ident=charid), dst)
        print("  [trade] SENT %d to 0x%08x at %s:%d" % (body[1], charid, dst[0], dst[1]),
              flush=True)
        return True

    def trade_swap(t):
        ok, note = True, "no wallets (--shop off)"
        if _shop is not None:
            sa, sb = session_of(t.a), session_of(t.b)
            ka = _wallet_key(sa.seen_uid[0] if sa else 0, t.a, sa)
            kb = _wallet_key(sb.seen_uid[0] if sb else 0, t.b, sb)
            ok, note = _shop.trade(ka, t.offers[t.a], kb, t.offers[t.b])
        print("  [trade] %s" % note, flush=True)
        for _c in (t.a, t.b):
            trade_push(_c, doc_trade.bare_body(doc_trade.DONE_PUSH if ok
                                               else doc_trade.CANCEL_PUSH))

    def synth_world_req(nbody=176):
        """A bare type-`--world-type` request to build an UNSOLICITED world
        answer on. build_world_answer echoes only body[16:], so a zero body
        means every field the client reads is one we wrote. This is the shape
        push_battle_ready's selector 38 has ridden live since sec 4ft."""
        req = bytearray(HDR_LEN + nbody)
        req[0] = 0x04
        struct.pack_into("<H", req, 2, len(req))
        req[8] = a.world_type & 0xFF
        return bytes(req)

    def send_gs_endpoint(dst, ident, req=None, why=""):
        """(RE-)DECLARE our game-server endpoint to the client at `dst`.

        sec 4gv. Selector 104 is the sole writer of [chan+184..191], the
        sockaddr the client's game-server receive handler compares EVERY
        datagram's source against before it dispatches anything. The endpoint
        is computed PER PEER through host_for(), exactly as the --gs-connect
        path does, so a LAN console gets the LAN address and an internet player
        gets POL_ADVERTISE_PUBLIC -- there is no global address here.

        WARNING: ORDER: 104 -> 38 -> the message-27 arm, which is the order the
        --gs-connect block has always used and the order --gs-rearm-ms replays.
        104 must come FIRST because it is what makes the other two deliverable
        at all; the arm must come LAST because 38's routine 0x00bc0260 zeroes
        [chan+204] (sec 4eb, CER-48101 live). Re-running 104 on a HEALTHY
        channel is harmless -- measured in an offline run of the client's own code (doc_gsseq_proof) and
        already relied on by --gs-rearm-ms (sec 4cx).

        Returns the endpoint string that went out, or None when there is
        nothing to declare (no --lobby-ip / --gs-connect-ip, or the builder
        refused the request)."""
        if dst is None:
            return None
        _ep = host_for(a.gs_connect_ip or a.lobby_ip, dst[0])
        if not _ep:
            return None
        _g = build_world_answer(
            req if req is not None else synth_world_req(),
            selector=GS_ENDPOINT_SELECTOR, seq=a.lobby_seq,
            subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
            inner_ip=None, ptype=a.world_type, pad_to=a.world_pad,
            # WARNING:KEY: sec 4dv: record+4, NOT 0 -- 104's arm 0x00bcd248 opens
            # `lw v1,4(s2); lw v0,272(s1); bne v1,v0,<drop>`, so the endpoint
            # message is dropped without a word unless this equals the charaid
            # the client holds at [kelsvc+272].
            ident=ident, gs_ip=_ep, gs_port=a.gs_connect_port,
            gs_id=a.gs_connect_id)
        if _g is None:
            return None
        s.sendto(_g, dst)
        print("  SENT GAME-SERVER ENDPOINT (selector %d) to %s:%d -> "
              "[chan+184..191] = %s:%d, id %d, ident 0x%08x%s"
              % (GS_ENDPOINT_SELECTOR, dst[0], dst[1], _ep, a.gs_connect_port,
                 a.gs_connect_id, ident or 0,
                 ("  [%s]" % why) if why else ""), flush=True)
        return _ep

    def push_battle_ready(msess, key):
        """sec 4ft: BATTLE READY (selector 38) + the message-27 re-arm to a
        seated member who did NOT send the Start -- the pair the leader's own
        command 3 gets. Only the leader sends command 3, and 38 alone takes a
        reserved member to the briefing room (sec 4eo). Built on a synthetic
        request, as the kelsvc keepalive is: 38's body from body[12] on is
        ours (the table record + the seat list)."""
        if msess.ka_src is None:
            return False
        _cid = msess.seen_charid[0]
        _rd = build_world_answer(
            synth_world_req(), selector=GS_READY_SELECTOR, seq=a.lobby_seq,
            subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
            inner_ip=None, ptype=a.world_type, pad_to=a.world_pad, ident=_cid)
        if _rd is None:
            return False
        if a.gs_ready_roster:
            _rd = gs_ready_roster(_rd, _cid, a.gs_connect_id,
                                  bt_store.members(key),
                                  rec=rec_for(bt_store.record(key),
                                              _gs_endpoint, msess.ka_src[0]))
        # WARNING:KEY: sec 4gv: the same re-declaration the leader gets, computed
        # PER PEER -- this member may be on the LAN while the leader is on the
        # internet, so host_for() is asked about THIS socket's address.
        if a.gs_connect and a.gs_start_endpoint:
            send_gs_endpoint(msess.ka_src, _cid, why="Start, start-all member")
        s.sendto(_rd, msess.ka_src)
        msess.gs_join_deadline[0] = 0.0
        msess.gs_bots_sent[0] = False
        msess.gs_battle_on[0] = 0.0      # sec 4fy: a new battle
        msess.gs_battle_end[0] = 0.0
        msess.gs_battle_reset[0] = 0.0
        msess.gs_battle_go[0] = 0.0
        msess.gs_src[0] = None
        s.sendto(build_gs_stats(_gs_stat_list, state=a.gs_arm_state,
                                seq=next_gs_seq(msess), ident=_cid),
                 msess.ka_src)
        msess.gs_ka_src[0] = msess.ka_src
        msess.gs_ka_next[0] = time.time() + a.gs_keepalive_ms / 1000.0
        msess.gs_rearm_pending[0] = a.gs_rearm_until_team
        print("  [start-all] SENT BATTLE READY (selector %d) + re-arm (message "
              "%d) to seated member 0x%08x at %s:%d, table %d (sec 4ft)"
              % (GS_READY_SELECTOR, GS_ARM_MSG, _cid, msess.ka_src[0],
                 msess.ka_src[1], key), flush=True)
        return True

    def push_lobby_npcs(msess, src):
        """sec 4gs addendum 3: announce the lobby NPCs (notify kind 15) to a
        client whose in-world stream is live -- once per in-world stretch. At
        +delay: selector 38 (the only writer of [chan+2148] = 1; the receive
        gate drops all but type 29 at 0) + the message-27 re-arm (38 zeroes
        [chan+204]); 2 s later, the kind-15 batches. Offline-proven up to the
        unit spawn (an offline run of the client's own code (doc_npc_spawn_proof)); the model is not."""
        now = time.time()
        _cid = msess.seen_charid[0]
        # Once per ENTRANCE (a new user id re-arms it), and never for a player
        # seated at a battletable: they are bound for the briefing room or an
        # arena, where a 38 of ours would cut across the battle flow.
        st = _npc_spawn.get(msess.key)
        if st is None or st["uid"] != msess.seen_uid[0]:
            st = _npc_spawn[msess.key] = {"due": now + a.npc_spawn_delay,
                                       "ready_at": 0.0, "done": False,
                                       "uid": msess.seen_uid[0]}
        if st["done"] or now < st["due"]:
            return
        if a.npc_spawn_via == "wu":
            # sec 4gs addendum 5: type-125 with nibble-4 ids -- the client
            # registers each NPC itself (0x00bd2358 -> kelsvc +288, rec+32 = 1)
            # and its online entity pump builds bzd record wire+4. Resent as
            # the NPCs' pose update; stops by itself once the lobby stream does.
            if now < st.get("next", 0.0):
                return
            _recs = doc_npc_spawn.wu_records(_npc_spawn_only,
                                             mode=a.npc_spawn_type,
                                             name=a.npc_spawn_name)
            for _i in range(0, len(_recs), doc_npc_spawn.PER_MSG):
                s.sendto(build_world_update(_recs[_i:_i + doc_npc_spawn.PER_MSG],
                                            seq=a.lobby_seq), src)
            _first = not st.get("next")
            if a.npc_spawn_every > 0:
                st["next"] = now + a.npc_spawn_every
            else:
                st["done"] = True
            if _first:
                print("  [npc-spawn] SENT type-125 world update(s): %d NPC(s), "
                      "ids 0x%08x.., wire+4 = %s -> %s:%d%s"
                      % (len(_recs), _recs[0]["id"] if _recs else 0,
                         a.npc_spawn_type, src[0], src[1],
                         (" (resending every %.0f s)" % a.npc_spawn_every)
                         if a.npc_spawn_every > 0 else ""), flush=True)
            return
        if _cid and bt_store.table_of(_cid):
            return
        if a.npc_spawn_ready == "38" and not st["ready_at"]:
            _req = bytearray(HDR_LEN + 176)
            _req[0] = 0x04
            struct.pack_into("<H", _req, 2, len(_req))
            _req[8] = a.world_type & 0xFF
            _rd = build_world_answer(
                bytes(_req), selector=GS_READY_SELECTOR, seq=a.lobby_seq,
                subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
                inner_ip=None, ptype=a.world_type, pad_to=a.world_pad,
                ident=_cid)
            if _rd is None:
                return
            s.sendto(gs_ready_roster(_rd, _cid, a.gs_connect_id, ()), src)
            s.sendto(build_gs_stats(_gs_stat_list, state=a.gs_arm_state,
                                    seq=next_gs_seq(msess), ident=_cid), src)
            msess.gs_ka_src[0] = src
            msess.gs_ka_next[0] = now + a.gs_keepalive_ms / 1000.0
            st["ready_at"] = now
            print("  [npc-spawn] SENT selector %d (channel READY) + re-arm "
                  "(message %d) to 0x%08x at %s:%d; kind %d follows in 2 s"
                  % (GS_READY_SELECTOR, GS_ARM_MSG, _cid, src[0], src[1],
                     doc_npc_spawn.KIND_ADD_NPC), flush=True)
            return
        if a.npc_spawn_ready == "38" and now - st["ready_at"] < 2.0:
            return
        _bodies = doc_npc_spawn.payloads(_npc_spawn_only, mode=a.npc_spawn_type,
                                         hp=a.npc_spawn_hp)
        for _b in _bodies:
            s.sendto(build_gs_notify(doc_npc_spawn.KIND_ADD_NPC, _b,
                                     seq=next_gs_seq(msess), ident=_cid), src)
        st["done"] = True
        print("  [npc-spawn] SENT notify kind %d 'Add Npc': %d NPC(s) in %d "
              "message(s), ids 0x%08x.., type=%s -> %s:%d"
              % (doc_npc_spawn.KIND_ADD_NPC,
                 sum(struct.unpack_from("<I", _b, 0)[0] for _b in _bodies),
                 len(_bodies), doc_npc_spawn.ID_BASE, a.npc_spawn_type,
                 src[0], src[1]), flush=True)

    def gs_sync_table(key):
        """sec 4ft: bring every seated member's briefing roster up to date
        (kind 31 add chara for each OTHER member with a team, kind 0 when a
        team changed) and, once the roster is ready and has settled, push the
        kind-20 distribution over it to every member. Idempotent; driven by
        request 31, which the briefing room re-sends every 1-4 s."""
        g = gs_table_state(key)
        members = [m for m in bt_store.members(key) if m]
        live = {}
        for m in members:
            ms = session_of(m)
            if ms is not None and ms.gs_src[0] is not None:
                live[m] = ms
        # 2026-09-23: the briefing countdown ran out and someone still has no
        # team -- seat them on the smaller side so the distribution can go out
        if (a.gs_real_dist and not g["dist"] and g.get("auto_at")
                and time.time() >= g["auto_at"]):
            if len(members) >= 2 and len(live) < len(members):
                # not everyone is in the briefing room yet: look again in 5 s
                # (the deadline is also the timer loop's wake-up, so it must
                # move or the loop spins)
                g["auto_at"] = time.time() + 5.0
            else:
                g["auto_at"] = None
                _auto, _assigned = gs_auto_teams(g["teams"], members)
                if len(members) >= 2 and _assigned:
                    g["teams"].update(_auto)
                    print("  [roster] table %d: briefing time is up -- "
                          "AUTO-TEAMED %s (they never sent request 31)"
                          % (key, ", ".join("0x%x -> team %d" % (m, _auto[m])
                                            for m in _assigned)), flush=True)
        for obs, ms in live.items():
            shown = g["shown"].setdefault(obs, {})
            # 2026-09-23: someone stepped off a space (request 33) -> kind 1,
            # or its row never counts down
            for cid in [c for c in shown if c not in g["teams"]]:
                s.sendto(build_gs_team_leave(cid, seq=next_gs_seq(ms)),
                         ms.gs_src[0])
                print("  [roster] SENT notify 1 (leave team) 0x%08x -> 0x%08x's "
                      "briefing" % (cid, obs), flush=True)
                del shown[cid]
            for cid in members:
                if cid not in g["teams"]:
                    continue
                team = g["teams"][cid]
                if cid == obs:
                    # 2026-09-13: the observer's OWN team change, to itself --
                    # kind 31 skips the own id by design, and without this
                    # the player's own team icon never changed on stepping
                    # into a team zone.
                    if shown.get(cid) != team:
                        s.sendto(build_gs_team_set(cid, team, seq=next_gs_seq(ms)),
                                 ms.gs_src[0])
                        print("  [roster] SENT notify 0 (set team) 0x%08x -> team "
                              "%d to ITSELF (own icon / counts)" % (cid, team),
                              flush=True)
                        shown[cid] = team
                    continue
                if cid not in shown:
                    # every seated
                    # member is already in this observer's roster from ITS 38
                    # (gs_ready_roster), filed with team 0xff, so a plain kind 0
                    # is a +1 on the row. The kind 31 we sent here could never
                    # move a count (and clobbered roster slots).
                    s.sendto(build_gs_team_set(cid, team, seq=next_gs_seq(ms)),
                             ms.gs_src[0])
                    print("  [roster] SENT notify 0 (set team) 0x%08x -> team %d "
                          "-> 0x%08x's briefing (first sight)" % (cid, team, obs),
                          flush=True)
                elif shown[cid] != team:
                    s.sendto(build_gs_team_set(cid, team, seq=next_gs_seq(ms)),
                             ms.gs_src[0])
                    print("  [roster] SENT notify 0 (set team) 0x%08x %d -> %d "
                          "-> 0x%08x's briefing (sec 4ft)"
                          % (cid, shown[cid], team, obs), flush=True)
                else:
                    continue
                shown[cid] = team
        if not a.gs_real_dist or g["dist"]:
            return
        # sec 4he: a UNIT table seats unit vs unit, whatever zone was clicked
        _rec_u = bt_store.record(key)
        if (_units is not None and _rec_u is not None
                and struct.unpack_from("<I", _rec_u, BT_OFF_FLAGS)[0] & BT_FLAG_UNIT):
            _ut = unit_teams(g["teams"], members, _unit_of_cid)
            if _ut != g["teams"]:
                print("  [roster] table %d is a UNIT table: sides by unit -> %s "
                      "(sec 4he)" % (key, {"0x%x" % k: v for k, v in _ut.items()}),
                      flush=True)
                g["teams"].update(_ut)
        ok, why = gs_real_ready(g["teams"], members)
        if ok and len(live) < len(members):
            ok, why = False, ("waiting for %d member(s) to reach the briefing "
                              "room" % (len(members) - len(live)))
        if why != g["why"]:
            g["why"] = why
            print("  [roster] table %d: %s" % (key, why), flush=True)
        now = time.time()
        if not ok:
            g["ready_at"] = None
            return
        if g["ready_at"] is None:
            g["ready_at"] = now
            print("  [roster] table %d READY -- the distribution goes out in "
                  "%.0f s unless someone changes side" % (key, a.gs_real_dist_settle),
                  flush=True)
        if now - g["ready_at"] < a.gs_real_dist_settle:
            return
        dist = gs_real_distribution(g["teams"], members)
        for obs, ms in live.items():
            s.sendto(build_gs_distribution(dist, seq=next_gs_seq(ms), ident=obs),
                     ms.gs_src[0])
        g["dist"] = True
        open_battle(key, members, g["teams"], now=now)
        print("  [roster] SENT notify 20 (PLAYER DISTRIBUTION) over the REAL "
              "roster %s to %d client(s). Watch: 'Player distribution has been "
              "determined' -> OK -> request 47 -> 48 + %s with kind 2 zone %d -> "
              "get_onlinezone -> KerberosZone.exit(z%d) (sec 4ft)"
              % (["0x%x:t%d:s%d" % e for e in dist], len(live),
                 a.gs_battle_start, a.gs_battle_zone, a.gs_battle_zone),
              flush=True)

    # ── sec 4he: BATTLE ROOMS, one per table ───────────────────────────
    battles = {}             # table key -> BattleRoom
    # 2026-09-26: MISSION SUPPLIES. session key -> {item: qty} the server
    # believes the player holds (world-door bag, minus each battle's request
    # 44, plus our grants); topped up to the mission's supplies at its 47.
    _supply_bag = {}
    _supply_44 = {}          # session key -> the battle (47 time) already counted
    _room_member_key = {}    # charid -> wallet key at its 47 (a member that
                             # leaves before the end has no session to ask)

    def battle_of(cid):
        if not cid:
            return None
        key = bt_store.table_of(cid)
        room = battles.get(key) if key is not None else None
        if room is None:
            for r in battles.values():
                # never a room whose TABLE is gone
                # -- the church battle "ARRIVED in table 1's room" (the
                # dissolved Wastelands table) and so never opened its own.
                if (cid in r.kills and cid not in r.left
                        and (r.key == -1 or r.key in bt_store.tables)):
                    return r
        return room

    def member_dst(cid):
        ms = session_of(cid)
        if ms is None:
            return None, None
        return ms, (ms.gs_src[0] or ms.ka_src or ms.src)

    def send_reservation_clear(cid, dst=None, why=""):
        """Selector 110 to `cid` on its WORLD channel: the push that empties
        the client's own reservation (BT_RESERVATION_CLEAR_SEL). Sent wherever
        a table disappears under a client that may still hold it."""
        if not cid:
            return False
        if dst is None:
            ms = session_of(cid)
            dst = (ms.ka_src or ms.src) if ms is not None else None
        if dst is None:
            return False
        _req = bytearray(HDR_LEN + 176)
        _req[0] = 0x04
        struct.pack_into("<H", _req, 2, len(_req))
        _req[8] = a.world_type & 0xFF
        _pk = build_world_answer(
            bytes(_req), selector=BT_RESERVATION_CLEAR_SEL, seq=a.lobby_seq,
            subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
            inner_ip=None, ptype=a.world_type, pad_to=a.world_pad, ident=cid)
        if _pk is None:
            return False
        s.sendto(_pk, dst)
        print("  SENT type-%d RESERVATION CLEAR (selector %d, ident 0x%08x) "
              "to %s:%d -- R+756 = 0xffff on the client%s"
              % (a.world_type, BT_RESERVATION_CLEAR_SEL, cid, dst[0], dst[1],
                 (" (%s)" % why) if why else ""), flush=True)
        return True

    def open_battle(key, members, teams, mission=None, now=None):
        """The distribution went out: from here the table is IN PROGRESS and
        the room owns the clock, the tally and the verdict. Rules come from
        the table RECORD (battle_rules_from_record) with the old knobs as
        the fallback for whatever the record does not carry."""
        now = now if now is not None else time.time()
        rec = bt_store.record(key) if key is not None else None
        rules = battle_rules_from_record(
            rec, default_length=a.gs_battle_length,
            default_kill=a.bt_kill_target, default_respawn=a.bt_respawn_s,
            time_unit=a.bt_time_unit)
        # RETAIL never sends command 41, so `mission` (from
        # _mission_battle) stayed None while the TABLE said Mission (flags
        # 0x10000, quest at wire+26 = rules.mission): the room was labelled
        # MISSION but no mission hook (scoring, NPC HP, killer fallback,
        # verdict) ever ran. Take the quest from the record.
        if mission is None and rules.mode == "MISSION" and rules.mission:
            mission = rules.mission
        if mission is not None:
            rules.mode = "MISSION"
            # 2026-09-24: the archive's time limit for this mission (the record
            # we serve carries the same number, so the HUD agrees)
            _mt = doc_missions.time_limit(mission)
            if _mt:
                rules.time_limit = float(_mt)
        room = BattleRoom(key if key is not None else -1, members, teams, rules,
                          leader=bt_store.leader_cid(key) if key is not None else 0,
                          mission=mission, now=now)
        battles[room.key] = room
        if key is not None:
            bt_store.set_in_progress(key, True)
        print("  [battle] ROOM OPENED for table %s: %d member(s) %s, teams %s, "
              "%r -- In Progress on the list, no new seats (sec 4he)"
              % (key, len(room.members),
                 ["0x%x" % m for m in room.members],
                 {"0x%x" % k: v for k, v in room.teams.items()}, rules),
              flush=True)
        if room.leader_mode():
            print("  [leader] TEAM LEADER battle, table %s: leaders %s -- only "
                  "an enemy leader's death scores (SE 28:205)"
                  % (key, {t: "0x%x" % m for t, m in room.team_leaders.items()}),
                  flush=True)
            tag_leaders(room, list(room.team_leaders.values()), True, "battle start")
        return room

    def close_battle(room, why="over"):
        battles.pop(room.key, None)
        if room.leader_mode():
            tag_leaders(room, list(room.team_leaders.values()), False, "battle over")
        if room.key in bt_store.tables:
            bt_store.set_in_progress(room.key, False)
            if bt_store.dissolve(room.key, force=True):
                gs_tables.pop(room.key, None)
                print("  [battle] table %d DISSOLVED after the battle (%s) -- "
                      "off the battle table list (sec 4gc/4he)"
                      % (room.key, why), flush=True)
                for m in room.members:
                    send_reservation_clear(m, why="table %d dissolved after "
                                           "the battle" % room.key)

    def _member_name(cid):
        n = (players.get(cid, {}).get("name") or relay_names.get(cid)
             or next((nm for _k, nm, _i in _rank_characters() if _i == cid), None))
        return n or "0x%08x" % cid

    def tag_leaders(room, cids, on=True, why=""):
        """2026-09-24 (TEAM LEADER, an experiment): the client draws no
        leader, so rename each leader "[L]Name" in the PEER table of every
        other member -- the same unsolicited selector-37 answer the lobby
        relay already re-pushes (0x00bd9090 overwrites the slot). on=False
        restores the plain name. Whether the battle's name display reads the
        peer table is what the live test shows."""
        if a.leader_tag != "on" or not cids:
            return
        sub = a.world_subchannel if a.world_subchannel >= 0 else 7
        for lc in cids:
            nm = _member_name(lc)
            shown = (LEADER_TAG + nm)[:15] if on else nm
            sent = 0
            for m in room.members:
                if m == lc:
                    continue
                # a peer answer is a WORLD-channel message (type 127),
                # like the reservation clear -- not the game-server channel
                ms = session_of(m)
                dst = (ms.ka_src or ms.src) if ms is not None else None
                if dst is None:
                    continue
                s.sendto(build_peer_answer(
                    None, lc, seq=a.lobby_seq, subchannel=sub,
                    ptype=a.world_type, ident=ms.seen_charid[0],
                    blob=build_peer_record(lc, name=shown, zone=a.user_zone,
                                           rank=a.user_rank, flags=peer_flags(lc),
                                           f36=player_look.get(lc))[4:]), dst)
                sent += 1
            print("  [leader] %s 0x%08x as %r -> %d member(s)%s"
                  % ("TAGGED" if on else "UNTAGGED", lc, shown, sent,
                     (" (%s)" % why) if why else ""), flush=True)

    def push_kill_event(room, fields):
        points, killer, victim, last_one = fields
        for m in room.present():
            ms, dst = member_dst(m)
            if dst is None:
                continue
            s.sendto(build_gs_kill_event(points, killer, victim, last_one,
                                         seq9=room.seq9, seq=next_gs_seq(ms),
                                         ident=m), dst)

    def push_down(room, victim):
        """Kind 25 about `victim` to every member. Retail death flow (read
        2026-09-23): kind 9 -> the client acks with request 43 and puts the
        victim in state 1; kind 25 sets the dead bits + respawn point, state
        2; kind 13 at the respawn deadline revives, state 0."""
        (_dp, _dbm) = _spawn_of.get(victim, (None, (0, 0)))
        if _dp is None:
            print("  [battle] DOWN 0x%x: no recorded spawn, respawn point "
                  "(0, 0, 0) map %s" % (victim, _dbm), flush=True)
            _dp = (0.0, 0.0, 0.0)
        # 2026-09-26: the respawn REFILL (kind 25 carries 3 entries and SETS
        # each quantity). Retail rule: BULLETS only, topped up to the
        # battle-start count; each row is max(supplies ledger, battle-start)
        # so a SET never cuts a count the ledger knows (doc_missions.
        # respawn_refill).
        _ammo25 = ()
        if a.respawn_ammo:
            _vs = session_of(victim)
            _want = doc_missions.supplies(
                _mission_battle.get(_vs.key) if _vs is not None else None,
                _ammo or doc_missions.STANDARD_SUPPLIES)
            _vheld = (_supply_bag.get(_vs.key) if _vs is not None else None)
            _ammo25 = doc_missions.respawn_refill(_want, _vheld)
            if _vheld is not None:
                _vheld.update(_ammo25)
        for m in room.present():
            ms, dst = member_dst(m)
            if dst is None:
                continue
            s.sendto(build_gs_down(_dp[0], _dp[1], _dp[2], bmap=_dbm,
                                   seq=next_gs_seq(ms), ident=victim,
                                   ammo=_ammo25), dst)
        print("  [battle] DOWN 0x%x: SENT notify kind %d to %d member(s), "
              "respawn at (%.0f, %.0f, %.0f) in %.0f s%s"
              % (victim, GS_DOWN_KIND, len(room.present()), _dp[0], _dp[1],
                 _dp[2], room.rules.respawn,
                 ", ammo refilled to %s" % ", ".join(
                     "0x%08x x%d" % e for e in _ammo25) if _ammo25 else ""),
              flush=True)

    def push_revive(room, victim):
        for m in room.present():
            ms, dst = member_dst(m)
            if dst is None:
                continue
            s.sendto(build_gs_notify(a.respawn_kind, struct.pack("<I", 0),
                                     seq=next_gs_seq(ms), ident=victim), dst)
        # 2026-09-24: no respawn kind touches MP on the client (only 2 / 51 /
        # 44 / 34 / message 61 write R+48), so a KO would keep whatever MP the
        # player died with. OURS (inferred retail): refill with kind 44.
        if a.mp_model == "ledger" and a.mp_respawn == "full" \
                and _magic.mp(victim) is not None:
            vs, vdst = member_dst(victim)
            if vdst is not None:
                _vmp = _magic.refill(victim)
                s.sendto(build_gs_mp_push(_vmp, seq=next_gs_seq(vs),
                                          ident=victim), vdst)
                print("  [magic] 0x%x respawned: MP -> %d (notify kind 44)"
                      % (victim, _vmp), flush=True)

    def end_battle(room, now, why=None):
        """Kind 4 (the RESULT, facade 0x40) to every member still in the
        room, with the room's verdict; selector 39 follows for each after
        --gs-battle-reset-after and the table is dissolved ONCE."""
        room.over = True
        room.why = room.why or why or "time limit"
        room.end_at = None
        room.reset_at = now + a.gs_battle_reset_after
        print("  [battle] END %s" % room.summary(), flush=True)
        for m in room.present():
            if m in room.result_sent:
                continue
            ms, dst = member_dst(m)
            if ms is None or dst is None:
                continue
            room.result_sent.add(m)
            _res_rec = bytes(GS_SETUP_LEN)
            _res_ok = False
            if _stats is not None:
                try:
                    _res_rec, _res_note = _battle_result(ms, room)
                    _res_ok = True
                    print("  [stats] " + _res_note, flush=True)
                except Exception as _rex:      # never let a tally kill the END
                    print("  [stats] RESULT tally FAILED (%r) -- sending the "
                          "zero record" % (_rex,), flush=True)
            _wc = room.winner_cid()
            if _wc is not None:
                # sec 4he (arm 0x00bc1ab8): in BT rec+29 is the
                # roster INDEX of the winner -> [chan+1384] -> "%s Wins by
                # Kill Count". The roster is selector 38's order for THIS
                # recipient: the others in seat order, itself last.
                _ro = [x for x in room.members if x != m][:31] + [m]
                _rr = bytearray(_res_rec)
                _rr[29] = _ro.index(_wc) if _wc in _ro else 0xFF
                _res_rec = bytes(_rr)
            # only when this result PAID them (a tally and a wallet)
            # (the carry cap is 9 -- item row +14 -- so no bag holds more)
            _held = (min(room.coins.pop(m, 0), doc_stats.COIN_CAP)
                     if a.chocobo_coins == "on" and _res_ok
                     and _shop is not None else 0)
            if _held > 0:
                # 2026-09-26: the coins were paid in this result's gil total
                # (doc_stats.coin_gil); cut them from the bag first. Kind 21
                # with ident = the recipient is the client's own "cut" arm
                # (0x00bc412c: ident == self -> 0x00bdef58 REMOVE {id, qty}
                # + event 9), the mirror of kind 11's add.
                s.sendto(build_gs_notify(21, field_item_payload(
                    doc_stats.COIN_ITEM, 0, (0.0, 0.0, 0.0), _held,
                    head=FIELD_QUIET), seq=next_gs_seq(ms), ident=m), dst)
                print("  [coins] SENT notify 21 to 0x%08x: CUT %d Chocobo "
                      "Coin(s) from the bag (paid %d gil)"
                      % (m, _held, doc_stats.coin_gil(_held)), flush=True)
            s.sendto(build_gs_notify(4, bytes(4) + _res_rec,
                                     seq=next_gs_seq(ms), ident=m), dst)
            ms.gs_battle_end[0] = 0.0
            ms.gs_battle_go[0] = 0.0
            print("  [battle] SENT notify 4 (the RESULT, facade 0x40) to 0x%08x "
                  "-- selector %d in %.0f s (sec 4fy)"
                  % (m, GS_BATTLE_OVER_SELECTOR, a.gs_battle_reset_after),
                  flush=True)

    def battle_reset(room):
        for m in list(room.members):
            if m in room.left:
                continue        # back in the lobby already: no reset for it
            ms = session_of(m)
            if ms is None or ms.ka_src is None:
                continue
            ms.gs_battle_on[0] = 0.0
            _req = bytearray(HDR_LEN + 176)
            _req[0] = 0x04
            struct.pack_into("<H", _req, 2, len(_req))
            _req[8] = a.world_type & 0xFF
            _bo = build_world_answer(
                bytes(_req), selector=GS_BATTLE_OVER_SELECTOR, seq=a.lobby_seq,
                subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
                inner_ip=None, ptype=a.world_type, pad_to=a.world_pad, ident=m)
            if _bo is not None:
                s.sendto(_bo, ms.ka_src)
                print("  [battle] SENT selector %d (battle over / reset, arm "
                      "0x00bcbd70) to 0x%08x at %s:%d (sec 4fy)"
                      % (GS_BATTLE_OVER_SELECTOR, m, ms.ka_src[0], ms.ka_src[1]),
                      flush=True)
        close_battle(room, room.why or "reset")

    def fire_battles(now):
        for room in list(battles.values()):
            if room.key != -1 and room.key not in bt_store.tables:
                # its table was dissolved (selector 125) or emptied (155)
                # under it: the room must not outlive it (live).
                battles.pop(room.key, None)
                print("  [battle] table %d is GONE -- its room CLOSED"
                      % room.key, flush=True)
                continue
            if room.go_due(now) and not room.over:
                room.go()
                print("  [battle] table %d shared GO: clock STARTED, %s"
                      % (room.key, ("ends in %.0f s" % (room.end_at - now))
                         if room.end_at else "no time limit"), flush=True)
            try:
                field_tick(room, now)
            except Exception:
                import traceback
                print("  [field] tick FAILED:\n%s" % traceback.format_exc(),
                      flush=True)
            if capsule_hold_done(room, now):
                end_battle(room, now, "team %d held all %d Mako Capsules for "
                           "%.0f s" % (room.cap_hold[0], room.rules.capsules,
                                       CAPSULE_HOLD_S))
            if room.base_down and not room.over:
                for _on in base_occupy_tick(room, _battle_pose, now,
                                            a.base_occupy_radius,
                                            a.base_occupy_s):
                    print("  [base] table %d: %s" % (room.key, _on), flush=True)
                if room.over:
                    end_battle(room, now)
            if room.end_at and now >= room.end_at and not room.over:
                end_battle(room, now, "time limit %.0f s" % room.rules.time_limit)
            if room.reset_at and now >= room.reset_at:
                room.reset_at = None
                battle_reset(room)
                continue
            # 2026-09-26: a member whose client has gone SILENT past
            # --battle-drop-s in a running room dropped off the line (the
            # client streams to the game server all battle): it leaves the
            # room and pays the manual's line-drop penalty (charge_line_drop)
            if not room.over and room.started and a.battle_drop_s > 0:
                for m in [x for x in room.present() if x in room.arrived]:
                    ms = session_of(m)
                    if (ms is not None and ms.last_peer_rx[0]
                            and now - ms.last_peer_rx[0] > a.battle_drop_s):
                        print("  [battle] 0x%08x silent %.0f s in table %d's "
                              "running room -- LINE DROPPED (--battle-drop-s %g)"
                              % (m, now - ms.last_peer_rx[0], room.key,
                                 a.battle_drop_s), flush=True)
                        vacate_seat(m, "line dropped")
            if not room.over and room.started and not room.present():
                end_battle(room, now, "everyone left")
            if not room.over and a.respawn_kind:
                # 2026-09-23: RESPAWN. BattleRoom.dead_until was set by every
                # counted death and never read, so a KO'd player stayed down
                # to the end (live, Beginner's Course II). Retail notify kinds
                # 13/18/19 revive through 0x00be6850 (HP := value if HP == 0,
                # 0 -> max); 19 also clears the dead flags 0x2400 and resets the
                # battle object (vt+220). ident = the revived character, body+16
                # u32 HP (0 = full).
                # Seen live and in a savestate: 18/19 revived the HP but never
                # touched the state word entry+0x56 that kind 9 set to 1, and
                # the damage path 0x00beec10 skips a character in state 1 or 2
                # -> INVINCIBLE. Kind 13 pushes action code 13 (state := 0)
                # after the kind-25 dead bits. Sent to every member so the
                # others see the revive too (arm 0x00be6ec0 for non-self).
                for _rc in room.respawns_due(now):
                    push_revive(room, _rc)
                    print("  [battle] RESPAWN 0x%x: SENT notify kind %d to "
                          "%d member(s)" % (_rc, a.respawn_kind,
                                            len(room.present())), flush=True)

    def battle_deadlines():
        out = []
        for room in battles.values():
            for t in (room.end_at, room.reset_at, room.go_at):
                if t:
                    out.append(t)
            if room.gens is not None and not room.over:
                if room.gens.next_due() is not None:
                    out.append(room.gens.next_due())
            elif room.go_fired is not None and not room.over:
                out.append(room.go_fired + 1.0)
            if room.base_down and not room.over:
                # 2026-09-26: an occupation phase is judged on the room tick
                out.append(time.time() + 0.25)
            if room.cap_hold is not None and not room.over:
                # 2026-09-26 (doc_base_e2e caplast): a capsule hold ends on
                # its own deadline -- without this a quiet room slept past it
                # until the next packet or the table's clock
                out.append(room.cap_hold[1])
            out.extend(room.dead_until.values())
            if a.battle_drop_s > 0 and room.started and not room.over:
                for m in room.present():
                    ms = session_of(m) if m in room.arrived else None
                    if ms is not None and ms.last_peer_rx[0]:
                        out.append(ms.last_peer_rx[0] + a.battle_drop_s)
        return out

    #: 2026-09-26: the vacate reasons that are a LINE DROP (the player's
    #: connection went away mid-battle), which the manual charges like a
    #: return to the lobby. Not "kicked" / "new entrance" (a different
    #: sign-in at the address) and never a normal or server-side end.
    LINE_DROP_WHYS = ("session reaped", "line dropped")

    def charge_line_drop(room, cid, why):
        """SE's January Additional Manual: returning to the lobby/title
        mid-battle, OR not being able to go
        on because of the line, costs 10 ranking points. Lobby command 4 has
        charged the first since 09-24; this is the second. Only a member that
        ARRIVED in a room still running (not over), not already gone (a
        member in room.left paid at its command 4 -- no double charge), and
        not a solo mission (quitting one is a failed mission, uncharged, the
        command-4 path's rule). Must run BEFORE room.leave()."""
        if (_stats is None or a.leave_rp_penalty <= 0 or room is None
                or room.over or room.mission is not None
                or cid not in room.arrived or cid in room.left):
            return None
        ms = session_of(cid)
        key = (_wallet_key(ms.seen_uid[0], cid, ms) if ms is not None
               else _room_member_key.get(cid))
        if key is None:
            return None
        summ = _stats.record_leave(
            key, a.leave_rp_penalty, room.rules.mode,
            time.time() - (room.started or time.time()), rid=cid)
        print("  [stats] [%s] LINE DROP out of a running battle (%s): %d rank "
              "points (--leave-rp-penalty %d)"
              % (key, why, summ["rp"], a.leave_rp_penalty), flush=True)
        return summ

    def vacate_seat(cid, why):
        """A player is gone: its seat, and its place in a running room."""
        if not cid:
            return
        room = battle_of(cid)
        if room is not None and cid not in room.left:
            if why in LINE_DROP_WHYS:
                charge_line_drop(room, cid, why)
            _was_leader = room.is_team_leader(cid)
            _nl = room.leave(cid)
            print("  [battle] 0x%08x LEFT table %d's room (%s)" % (cid, room.key, why),
                  flush=True)
            if _was_leader:
                tag_leaders(room, [cid], False, "left the battle")
            tag_leaders(room, list(_nl.values()), True, "took over as leader")
            for m in room.present():
                ms, dst = member_dst(m)
                if dst is not None:
                    s.sendto(build_gs_notify(GS_PLAYER_LEFT_KIND, bytes(4),
                                             seq=next_gs_seq(ms), ident=cid), dst)
        key = bt_store.vacate(cid)
        if key is not None:
            print("  [battletable] seat of 0x%08x at table %d VACATED (%s)"
                  % (cid, key, why), flush=True)

    _p2p_seen = {}           # (session key, P2P type) -> count, for the log
    _start_seen = {}         # session key -> time of its last command 3

    def battle_capture(what, **fields):
        """--battle-capture: one JSON line (bytes as hex). Never raises -- a
        capture that cannot write must not take a battle down."""
        if not a.battle_capture:
            return
        import json
        rec = {"t": round(time.time(), 3), "what": what}
        for k, v in fields.items():
            rec[k] = v.hex() if isinstance(v, (bytes, bytearray)) else v
        try:
            with open(a.battle_capture, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except (OSError, TypeError, ValueError) as ex:
            print("  [capture] write FAILED: %s" % ex, flush=True)

    def capsule_field(room, sess=None):
        """2026-09-24: a TEAM CAPSULE room's field, placed once (N = the
        record's capsule count, on a ring around the arena spawn), or None."""
        n = capsule_count(room)
        if n <= 0:
            return None
        if room.field is None:
            cid = room.members[0] if room.members else 0
            ms = session_of(cid)
            center = _battle_pos(ms.key if ms is not None else None, cid,
                                 per_team=False)
            room.field = {i: (MAKO_CAPSULE, pos) for i, pos in
                          enumerate(capsule_ring(center, n))}
            print("  [capsule] table %d: %d Mako Capsule(s) placed on a %.0f-unit "
                  "ring around %s" % (room.key, len(room.field), CAPSULE_RING,
                                      tuple(round(v, 1) for v in center)), flush=True)
        return room.field

    def field_tick(room, now):
        """2026-09-26: the arena's ITEM GENERATORS (doc_field). They start a
        second after the shared GO -- after each member's own GO has sent it
        the field (capsule_send_field) -- and a generator whose item is picked
        up rolls again --field-respawn-s later."""
        if (not a.field_items or room.over or room.started is None
                or (room.go_at is not None and room.go_fired is None)):
            return
        t0 = room.go_fired if room.go_fired is not None else room.started
        if now < t0 + 1.0:
            return
        field = battle_field(room)
        if room.gens is None:
            cid = next(iter(room.present()), 0)
            ms = session_of(cid)
            zone = _battle_zone(ms.key if ms is not None else None, cid)
            gens = doc_field.generators(zone, room.rules.situation)
            room.gens = doc_field.Generators(gens, now, a.field_respawn_s)
            print("  [field] table %d: zone %s situation %d -> %d item "
                  "generator(s), respawn %.0f s"
                  % (room.key, zone, room.rules.situation, len(gens),
                     a.field_respawn_s), flush=True)
        taken = set(field)

        def free_slot():
            i = next((k for k in range(FIELD_SLOTS) if k not in taken), None)
            if i is not None:
                taken.add(i)
            return i
        placed = room.gens.tick(now, free_slot)
        for _gi, slot, iid, qty, pos in placed:
            field[slot] = (iid, pos, qty)
        if not placed:
            return
        for m in room.present():
            ms, dst = member_dst(m)
            if dst is None:
                continue
            for _gi, slot, iid, qty, pos in placed:
                s.sendto(build_gs_notify(10, field_item_payload(
                    iid, slot, pos, qty, head=FIELD_QUIET),
                    seq=next_gs_seq(ms), ident=m), dst)
        print("  [field] table %d: SENT notify kind 10 x%d to %d member(s): %s"
              % (room.key, len(placed), len(room.present()),
                 ", ".join("0x%08x x%d@%d" % (i, q, sl)
                           for _g, sl, i, q, _p in placed[:6])
                 + (" ..." if len(placed) > 6 else "")), flush=True)

    def battle_field(room):
        """2026-09-26: every battle has a field -- the capsules when the table
        or mission has them, else an empty one for dropped items."""
        if room is None:
            return None
        if capsule_field(room) is None and room.field is None:
            room.field = {}
        if room.mission is not None and not room.quest_items:
            room.quest_items = True
            place_quest_items(room)
        return room.field

    def place_quest_items(room):
        """2026-09-26: a mission's QUEST items (doc_npcquests.mission_items:
        Collector's Mind's Fuzzy Seed) go on its field once, at SE's own
        generator node, before the GO sends the field."""
        if a.fuzzy_seed != "field":
            return
        cid = next(iter(room.members), 0)
        ms = session_of(cid)
        zone = _battle_zone(ms.key if ms is not None else None, cid)
        for iid, qty, pos in doc_npcquests.mission_items(
                room.mission, zone, room.rules.situation):
            slot = next((i for i in range(FIELD_SLOTS)
                         if i not in room.field), None)
            if slot is None:
                break
            room.field[slot] = (iid, pos, qty)
            print("  [npcquest] table %d: quest %d in zone %s -> 0x%08x x%d "
                  "on the field, slot %d at %s (SE's generator node)"
                  % (room.key, room.mission, zone, iid, qty, slot,
                     tuple(round(v, 1) for v in pos)), flush=True)

    def capsule_send_field(room, sess):
        """Kind 10 for every item on the field, to `sess` (its GO)."""
        field = battle_field(room)
        if not field or sess.gs_join_src[0] is None:
            return
        for slot, (iid, pos, *_c) in sorted(field.items()):
            s.sendto(build_gs_notify(10, field_item_payload(iid, slot, pos,
                                                            _c[0] if _c else 1),
                                     seq=next_gs_seq(sess),
                                     ident=sess.seen_charid[0]), sess.gs_join_src[0])
        print("  [capsule] SENT notify kind 10 x%d (the field) to 0x%08x"
              % (len(field), sess.seen_charid[0]), flush=True)

    def _mp_battle(room):
        """(ledger battle key, Magic restricted?) -- the key request 60 uses."""
        if room is None:
            return ("no room",), False
        return ((room.key, room.opened),
                doc_magic.magic_restricted(room.rules.flags,
                                           room.rules.restrictions))

    def push_mp(cid, mp, why):
        """Notify kind 44 {MP << 16} to `cid` (R+48 = the MP it casts from)."""
        ms, dst = member_dst(cid)
        if dst is None:
            print("  [magic] 0x%x: MP %d (%s) -- no channel to push kind 44 on"
                  % (cid, mp, why), flush=True)
            return False
        s.sendto(build_gs_mp_push(mp, seq=next_gs_seq(ms), ident=cid), dst)
        print("  [magic] 0x%x: MP -> %d (%s) -- SENT notify kind 44"
              % (cid, mp, why), flush=True)
        return True

    def mp_point(cid, body, via):
        """2026-09-26 (doc_items): a 117 -- `cid` stands at MP point N with MP
        below max. The client sends one per frame in range and changes nothing
        itself; credit the ledger (OURS: --mp-point-amount every
        --mp-point-every s per point) and push kind 44."""
        p = doc_items.parse_mp_point(body)
        room = battle_of(cid)
        _n = _mp_point_seen[cid] = _mp_point_seen.get(cid, 0) + 1
        loud = _n <= 3 or _n % 200 == 0
        if p is None or room is None or a.mp_points == "off":
            if loud:
                print("  [mp point] %s 117 from 0x%08x ignored: %s (#%d)"
                      % (via, cid, "short payload" if p is None else
                         "not in a battle" if room is None else "--mp-points off",
                         _n), flush=True)
            return
        _kind, point, _cnt = p
        if a.mp_model != "ledger":
            if loud:
                print("  [mp point] %s 117 from 0x%08x (point %d): --mp-model %s "
                      "keeps no MP to credit (#%d)" % (via, cid, point,
                                                        a.mp_model, _n), flush=True)
            return
        bkey, restricted = _mp_battle(room)
        amt = _mp_points.credit(cid, bkey, point, time.time())
        if not amt:
            if loud:
                print("  [mp point] %s 117 from 0x%08x (point %d, n %s): cooling "
                      "down (#%d)" % (via, cid, point, _cnt, _n), flush=True)
            return
        mp = _magic.credit(cid, bkey, amt, restricted)
        push_mp(cid, mp, "MP point %d +%d, %s" % (point, amt, via))

    def capsule_server(cid, ptype, body):
        """A reliable 119 pick-up / 118 drop addressed to the server."""
        if ptype == P2P_MP_POINT:
            return mp_point(cid, body, "reliable")
        room = battle_of(cid)
        if battle_field(room) is None:
            print("  [capsule] reliable %s from 0x%08x ignored: not in a battle"
                  % (P2P_NAMES.get(ptype), cid), flush=True)
            return
        if ptype == P2P_PICKUP:
            slot = p2p_pickup_slot(body)
            msgs, note = capsule_pickup(room, cid, slot)
            if len(body) >= 24:
                note += " (n %d, picker at %s)" % (
                    struct.unpack_from("<I", body, 8)[0],
                    tuple(round(v, 1) for v in struct.unpack_from("<fff", body, 12)))
        else:
            d = p2p_drop(body)
            msgs, note = (capsule_drop(room, cid, *d) if d is not None
                          else ([], "ignored (short 118)"))
        _capsule_after(room, cid, msgs, "reliable " + note)

    def _capsule_send(room, actor, msgs):
        for kind, payload, ident, to in msgs:
            for m in room.present():
                if (to == "self" and m != actor) or (to == "others" and m == actor):
                    continue
                ms, dst = member_dst(m)
                if dst is not None:
                    s.sendto(build_gs_notify(kind, payload, seq=next_gs_seq(ms),
                                             ident=ident), dst)

    def capsule_p2p(sender, inner, ptype):
        """Arbitrate a 119 pick-up / 118 drop (never relayed)."""
        _t, _f, _sid, _tgt, _payload = p2p_record(inner["plain"])
        cid = sender.seen_charid[0] or _sid
        if ptype == P2P_MP_POINT:
            return mp_point(cid, _payload, "p2p")
        room = battle_of(cid)
        if battle_field(room) is None:
            print("  [capsule] %s from 0x%08x ignored: not in a battle"
                  % (P2P_NAMES.get(ptype), cid), flush=True)
            return
        if ptype == P2P_PICKUP:
            msgs, note = capsule_pickup(room, cid, p2p_pickup_slot(_payload))
        else:
            d = p2p_drop(_payload)
            msgs, note = (capsule_drop(room, cid, *d) if d is not None
                          else ([], "ignored (short 118)"))
        _capsule_after(room, cid, msgs, note)

    def _capsule_after(room, cid, msgs, note):
        _capsule_send(room, cid, msgs)
        print("  [capsule] 0x%08x (team %d) %s" % (cid, room.team_of(cid), note),
              flush=True)
        for kind, payload, ident, _to in msgs:
            if kind == 11 and room.gens is not None:
                _gi = room.gens.picked(struct.unpack_from("<H", payload, 10)[0],
                                       time.time())
                if _gi is not None:
                    print("  [field] table %d: generator %d emptied -- rolls "
                          "again in %.0f s" % (room.key, _gi,
                                               room.gens.respawn_s), flush=True)
            # 2026-09-26: keep the supplies ledger honest about field items
            if kind not in (10, 11):
                continue
            _fi, _fn = struct.unpack_from("<IH", payload, 4)
            if _fi == doc_stats.COIN_ITEM:
                # Chocobo Coins: +n for the picker (kind 11), -n for a
                # dropper (kind 10 from its own 118) -- paid at the end
                room.coins[ident] = max(0, room.coins.get(ident, 0)
                                        + (_fn if kind == 11 else -_fn))
                print("  [coins] table %d: 0x%08x holds %d Chocobo Coin(s)"
                      % (room.key, ident, room.coins[ident]), flush=True)
            _fs = session_of(ident)
            if _fi in doc_npcquests.FIELD_QUEST_ITEMS:
                # a QUEST item (the Fuzzy Seed) is the SERVER bag's business:
                # Hiren checks that bag. kind 11 = picked up, 10 = dropped.
                _qk = (_wallet_key(_fs.seen_uid[0], ident, _fs)
                       if _fs is not None else _room_member_key.get(ident))
                if _qk:
                    print("  [npcquest] [%s] %s a quest item on the field: %s"
                          % (_qk, "PICKED UP" if kind == 11 else "DROPPED",
                             _bag_move(_qk, [(_fi, _fn if kind == 11
                                              else -_fn)])), flush=True)
            if (_fi in doc_missions.SUPPLY_ITEMS and _fs is not None
                    and _fs.key in _supply_bag):
                _held = _supply_bag[_fs.key]
                _held[_fi] = max(0, _held.get(_fi, 0)
                                 + (_fn if kind == 11 else -_fn))
        if capsule_count(room) <= 0:
            return                  # a plain field: no capsule rules to run
        if msgs and room.mission is not None:
            # a mission has no team hold and no scoreboard (46 is the Team
            # Capsule HUD); the count alone wins it
            mnote = capsule_mission_check(room)
            print("  [capsule] table %d: %s" % (room.key, mnote), flush=True)
            if room.over:
                end_battle(room, time.time())
        elif msgs:
            hmsgs, hnote = capsule_hold(room, time.time())
            _capsule_send(room, cid, hmsgs)
            if hnote:
                print("  [capsule] table %d: %s" % (room.key, hnote), flush=True)

    def relay_p2p_battle(sender, inner, ptype):
        """sec 4he: forward a shot / damage / entity datagram to the OTHER
        members of the sender's battle, re-stamped exactly like the 0x83 pose
        relay (mode 0, flags | 8, checksum recomputed, everything else
        verbatim -- the parser gate 0x00be20b0 wants the sender id at +16 to
        be a unit that exists and the source to be the game-server mirror,
        which we are). A 113 names its target at rec+8; everyone else drops
        it at 0x00be9860, so the whole room gets every packet and the
        receiver does the filtering the way it was built to."""
        plain = inner["plain"]
        _t, _f, _sid, _tgt, _payload = p2p_record(plain)
        cid = sender.seen_charid[0] or _sid
        room = battle_of(cid)
        peers = (room.members if room is not None
                 else [m for m in bt_store.members(bt_store.table_of(cid) or -1)
                       if m])
        out = build_peer_relay(plain)
        sent = 0
        for m in peers:
            if not m or m == cid:
                continue
            ms = session_of(m)
            dst = (ms.gs_src[0] or ms.ka_src or ms.src) if ms is not None else None
            if dst is None:
                continue
            s.sendto(out, dst)
            sent += 1
        k = (sender.key, ptype)
        _p2p_seen[k] = _p2p_seen.get(k, 0) + 1
        n = _p2p_seen[k]
        if n <= 3 or n % 100 == 0:
            extra = ""
            if ptype == P2P_DAMAGE:
                extra = " " + ", ".join(
                    "0x%x:%+d by 0x%x shot %d" % e
                    for e in p2p_damage_entries(_payload)[:4])
            print("  [p2p] %s (type %d, mode %d, %d B) from 0x%08x -> target %s "
                  "-> RELAYED to %d member(s) of %s (#%d)%s"
                  % (P2P_NAMES.get(ptype, "?"), ptype, plain[1], len(plain),
                     _sid, "all" if _tgt == -1 else "0x%x" % (_tgt & 0xFFFFFFFF),
                     sent, ("battle table %d" % room.key) if room is not None
                     else "its table", n, extra), flush=True)
        if room is not None and ptype == P2P_DAMAGE:
            room.saw_damage(cid, p2p_damage_entries(_payload), time.time())
        battle_capture("p2p", type=ptype, name=P2P_NAMES.get(ptype, "?"),
                       flags=_f, sender=cid, target=_tgt,
                       table=room.key if room is not None else None,
                       payload=_payload)
        return sent

    relay_names = {}         # sec 4fu: relayed peer id -> name (cache misses)
    player_look = {}         # sec 4fu (look): charid -> o099 look code, the
                             # peer record's +36 -> slot+40 -> unit+88

    def _player_look(sess):
        """sec 4fu (look): the o099 costume code (doc_charastore.chr_code) of
        `sess`'s SELECTED character, or None without a store / a match."""
        if _store is None or not sess.seen_uid[0]:
            return None
        _cid = sess.seen_charid[0] & 0x3FFFFFFF
        if not _cid:
            return None
        # sec 4fx: through the member key (sec 4ft). The raw uid reads the
        # old uid-keyed backup roster, i.e. somebody else's (or no) look.
        _slots = _store.roster(_skey(sess.seen_uid[0], sess))
        for _si in range(doc_charastore.MAX_SLOTS):
            if _slots[_si] and sess.chara_ids.get(_si) == _cid:
                return doc_charastore.chr_code(_slots[_si]) & 0xFFFF
        return None
    relay_log = {}           # sec 4fu: (peer id, dst ip) -> [count, since]

    def relay_peer_pose(sender, inner, pose):
        """sec 4fu (2026-09-13): put `sender` in every OTHER in-world client's
        world and move it there, the way the client itself is built to.

        DoC's world was peer-to-peer with the server as a directory (sec 4bw),
        and the client ALREADY takes a peer's datagrams relayed by the game
        server (0x00be20b0 marks such a unit |= 0x01000000). Per receiver, all
        off the sender's own 0x83:
          1. a selector-37 peer record keyed by the sender's id (packet[16..19],
             its charid) -- the spawn resolves it in [kelsvc+284]. Sent ALONE
             the first time, so a type-125 cannot overtake it into a cache miss
             (which --peer-answer would fill with a nameless record);
          2. a type-125 naming that id -> 0x00bd2108 SPAWNS the remote unit (a
             flagged 0x83 for an unknown id is dropped in the parser, so this
             comes first). Its pose fields are the sender's own 40-byte pose
             record, and its time word is the SENDER's ms, so it never runs
             ahead of the relayed 0x83s (the FE lesson: map, never invent);
          3. 'raw': the 0x83 itself, build_peer_relay() -- flags|8, mode 0,
             verbatim otherwise -- consumed by the unit's own update on the
             sender's cadence. 'wu': one type-125 per 0x83 instead.
        Only clients whose OWN 0x83 stream is fresh receive anything: the world
        channel is shut everywhere else (sec 4bu/4df).
        """
        plain = inner.get("plain") if inner is not None else None
        rid = (inner.get("u32_16") if inner is not None else 0) or pose[0]
        # bits 30/31 must stay clear: bit 30 is the silent peer table, bit 31
        # breaks the sign-extended key compare (sec 4bw/4ch)
        if (plain is None or len(plain) < BODY_OFF + 40 or not rid
                or rid & 0xC0000000):
            return
        now = datetime.datetime.now().timestamp()
        ms = struct.unpack_from("<I", plain, 4)[0]
        x, y, z, dx, dy, dz = pose[1:]
        b = BODY_OFF
        h28, h30 = struct.unpack_from("<HH", plain, b + 28)
        name = (players.get(sender.seen_charid[0], {}).get("name")
                or players.get(rid, {}).get("name") or "Player_%x" % rid)
        relay_names[rid] = name
        sender.pos_id[0] = rid
        # KEY: sec 4fu (look, 2026-09-13): THE REMOTE AVATAR'S LOOK IS UNIT+88.
        # The unit update 0x00be4850 (vt+28's first call) does `lhu a0, 88(unit);
        # sh a0, 38(pose)` -- it OVERWRITES pose-record +38, where the sender
        # puts its own costume code (live 0x83s end `12 10` = 0x1012), with the
        # unit's +88. unit+88 is set once, at spawn, from the peer lookup's +26
        # = peer slot+40 = OUR peer record's wire+36. We sent 0 there: both
        # screens drew the default avatar (live 09-13). Serve the sender's
        # stored character look; its 0x83's own +38 is the fallback.
        look = _player_look(sender)
        if look is None:
            look = struct.unpack_from("<H", plain, b + 38)[0]
        player_look[rid] = look
        raw = build_peer_relay(plain) if a.peer_relay == "raw" else None
        sub = a.world_subchannel if a.world_subchannel >= 0 else 7
        for other in list(sessions.values()):
            if other is sender or other.src is None:
                continue
            if now - other.last_stream[0] > a.peer_relay_live_s:
                continue
            dst = other.src
            first = rid not in other.relay_pushed
            if first or now - other.relay_pushed[rid] >= a.peer_relay_push_s:
                other.relay_pushed[rid] = now
                s.sendto(build_peer_answer(
                    None, rid, seq=a.lobby_seq, subchannel=sub,
                    ptype=a.world_type, ident=other.seen_charid[0],
                    blob=build_peer_record(rid, name=name, zone=a.user_zone,
                                           rank=a.user_rank,
                                           flags=peer_flags(rid),
                                           f36=look)[4:]), dst)
                print("  [peer-relay] PEER record 0x%08x (%s, look 0x%04x) -> "
                      "%s:%d%s"
                      % (rid, name, look, dst[0], dst[1],
                         " -- first sight; the spawn follows on the next 0x83"
                         if first else ""), flush=True)
                if first:
                    continue
            if raw is None or (now - other.relay_wu.get(rid, 0.0)
                               >= a.peer_relay_spawn_ms / 1000.0):
                if rid not in other.relay_wu:
                    print("  [peer-relay] SPAWN 0x%08x at (%.1f, %.1f, %.1f) -> "
                          "%s:%d (type 125, sender ms %d)"
                          % (rid, x, y, z, dst[0], dst[1], ms), flush=True)
                other.relay_wu[rid] = now
                s.sendto(build_world_update([dict(
                    id=rid, x=x, y=y, z=z, dx=dx, dy=dy, dz=dz,
                    h6=h28, h20=h30, b4=plain[b + 32], b5=plain[b + 35],
                    h22=ms & 0xFFFF)], seq=a.lobby_seq, ms=ms), dst)
            if raw is not None:
                s.sendto(raw, dst)
            st = relay_log.setdefault((rid, dst[0]), [0, now])
            st[0] += 1
            if now - st[1] >= 10.0:
                print("  [peer-relay] 0x%08x -> %s: %d position update(s) in "
                      "%.0f s (%s)" % (rid, dst[0], st[0], now - st[1],
                                       a.peer_relay), flush=True)
                st[0], st[1] = 0, now
    if a.lobby_keepalive_ms > 0:
        print("[docudp] lobby keepalive: selector-%d every %d ms once a 96-byte "
              "template has been seen" % (a.lobby_sustain_selector or a.lobby_selector,
                                          a.lobby_keepalive_ms), flush=True)
    _ack_selectors = set()
    for _t in (a.reliable_ack_selectors or "").replace(",", " ").split():
        _ack_selectors.add(int(_t, 0))
    _pending_ack_after = {int(x) for x in a.pending_ack_after.split(",")
                          if x.strip()}

    # --lobby-map-mask -> the module global every selector-13 answer reads.
    # Parsed loudly at startup for the same reason --lobby-spawn is: an empty
    # mask and a mask that failed to parse look identical on screen (an empty
    # map picker), and that is the bug we are fixing.
    global LOBBY_MAP_MASK, LOBBY_ZONE
    LOBBY_MAP_MASK = parse_map_mask(a.lobby_map_mask)
    LOBBY_ZONE = a.lobby_zone
    print("[docudp] LOBBY ZONE %d at world-door body[42..43] (sec 4hg addendum 4)"
          % LOBBY_ZONE, flush=True)
    if LOBBY_MAP_MASK:
        _names = describe_map_mask(LOBBY_MAP_MASK)
        print("[map] selector %d will carry map mask 0x%016x at body[%d..%d] "
              "-- %d map(s) in the battletable picker"
              % (WORLD_SPAWN_SELECTOR_ANS, LOBBY_MAP_MASK, LOBBY_MAP_MASK_OFF,
                 LOBBY_MAP_MASK_OFF + 7, len(_names)), flush=True)
        print("[map]   %s" % ", ".join(_names), flush=True)
    else:
        print("[map] --lobby-map-mask none: body[%d..%d] stays zero, so the "
              "battletable Map row builds an EMPTY list (the pre-fix "
              "behaviour, sec 4gv)" % (LOBBY_MAP_MASK_OFF,
                                       LOBBY_MAP_MASK_OFF + 7), flush=True)

    # --lobby-spawn -> (x, y, z, dirx, diry, dirz, index) or None. Parsed once,
    # loudly, at startup: a spawn that silently fails to parse is indistinguishable
    # from the zeros we are trying to stop sending.
    _spawn = None
    if a.lobby_spawn.strip():
        if a.lobby_spawn.strip().lower() in SPAWN_PRESETS:
            _spawn = SPAWN_PRESETS[a.lobby_spawn.strip().lower()]
        else:
            _f = [x for x in a.lobby_spawn.replace(",", " ").split() if x]
            if len(_f) not in (3, 6, 7):
                raise SystemExit("--lobby-spawn wants 3, 6 or 7 numbers (or one of %s), "
                                 "got %d: %r" % (sorted(SPAWN_PRESETS), len(_f),
                                                 a.lobby_spawn))
            _v = [float(x) for x in _f[:6]] + [0.0] * (6 - min(len(_f), 6))
            _spawn = tuple(_v[:6]) + (int(float(_f[6])) if len(_f) == 7 else 0,)
        print("[spawn] selector %d will carry world position (%.3f, %.3f, %.3f) "
              "facing (%.3f, %.3f, %.3f) index %d"
              % ((WORLD_SPAWN_SELECTOR_ANS,) + _spawn), flush=True)
        print("[spawn]   body[28..51] floats, body[52..53] index; descriptor Y is "
              "%.3f (+%.1f, the getter subtracts it back). Zeros here were the "
              "p(0,0,0) spawn -- sec 4dh."
              % (_spawn[1] + SPAWN_Y_BIAS, SPAWN_Y_BIAS), flush=True)
    # sec 4dw: one endpoint, used by both writers of the game-server sockaddr --
    # --gs-connect's selector 104 and the phase-44 selector-21 answer.
    _gs_endpoint = a.world_gs_ip or a.gs_connect_ip or a.lobby_ip
    _gs_ready_after = {int(x, 0) for x in
                       a.gs_ready_after.replace(" ", "").split(",") if x}
    # sec 4fq: --peer is now an allowlist (comma-separated IPs); empty = any.
    peer_allow = {x.strip() for x in (a.peer or "").replace(",", " ").split()
                  if x.strip()}
    short_ladder = {int(x, 0) for x in a.short_ladder.replace(" ", "").split(",")
                    if x}   # sec 4dv: 36-byte rungs we are allowed to answer
    # 2026-09-13: the two table verbs whose request carries NOTHING are 36-byte
    # datagrams too -- DISSOLVE 125 (phase 50) and CANCEL 155 (phase 46). With
    # only `--short-ladder=22` they fell to "log-only" before battletable_verb:
    # a live server on 09-13 had 0 dissolves / 0 cancels ever handled, and Lex's disband left
    # table 1 in the store (the Deck kept listing it). They name no key; the verb
    # resolves the requester's own table from its charid.
    if a.battletable_verbs:
        short_ladder |= {BT_REQ_DISSOLVE, BT_REQ_CANCEL}
    # 2026-09-13: selector 159 (phase 123, vt+1412 0x00bd8050, parks state 51)
    # is the SOLO BATTLE list -- solo = story mode, and 160's arm 0x00bcd74c ->
    # 0x00bcaba8 reads a QUEST-ID list ("Quest id %d"): rec+15 count, rec+16
    # u16[count]. It is a 36-byte request too, so it fell to "log-only" and the
    # player got CER-47117 on opening Solo. The generic zero-body 160 = count
    # 0 (an empty list), state 2, bit 31 clear -- the doc_bt_verbs_proof ladder
    # sweep. Real quest ids are not decoded yet; do not guess them in.
    short_ladder.add(QUEST_LIST_REQ)
    _solo_quests = parse_id_ranges(a.solo_quests)
    # 2026-09-23: MISSION MODE per player (tools/doc_missions.py). The career
    # store (--stats) holds each character's rank / rank points / battles and
    # the exams an instructor has "added to Missions"; 159 -> 160 lists them
    # and the instructors' command 26 answers come from that state.
    _ledger = a.mission_ledger == "on" and _stats is not None
    _magic = doc_magic.Ledger()   # 2026-09-24: per-character MP (--mp-model ledger)
    # 2026-09-26 (doc_items): MP points (117) and item use (21 -> 22)
    _mp_points = doc_items.MpPoints(a.mp_point_amount, a.mp_point_every)
    _mp_point_seen = {}   # charid -> 117 count (log throttle)
    _item_uses = doc_items.UseLedger()
    _spawn_of = {}        # charid -> ((x, y, z), bmap) of its kind-2 spawn
    _battle_pose = {}     # 2026-09-26: charid -> (x, y, z, t), its last 0x83
    if a.mission_ledger == "on" and _stats is None:
        print("[missions] LEDGER OFF: --mission-ledger=on needs --stats (no "
              "career store) -- static --solo-quests list, instructors greet",
              flush=True)
    elif _ledger:
        print("[missions] LEDGER ON: instructors %s grant the rank exams %s from "
              "the career (3 battles, then %s rank points); 159 -> 160 = the "
              "player's open exams + %d always-available mission(s) %s"
              % (sorted(doc_missions.INSTRUCTORS),
                 [q for q, _, _ in doc_missions.EXAMS.values()],
                 "/".join(str(n) for _, n, _ in list(doc_missions.EXAMS.values())[1:]),
                 len([q for q in _solo_quests if q not in doc_missions.EXAM_QUESTS]),
                 [q for q in _solo_quests if q not in doc_missions.EXAM_QUESTS]),
              flush=True)
    _list148 = parse_list148_spec(a.list_148)
    if _list148:
        print("[147-list] PROBE ON (sec 4gt add.1): selector %d -> %d, %d entr(ies) "
              "%s -- the generic answer is a ZERO-length list, which is what "
              "draws the blank unselectable rows. Values are NOT decoded; this "
              "only asks whether a non-zero count puts rows on screen."
              % (LIST148_REQ, LIST148_ANS, len(_list148),
                 ",".join("%d:%d:%d" % e for e in _list148)), flush=True)
    # session key (sec 4gz: (ip, port)) -> (quest id, time) from its last
    # command 41; consumed by the next Start. Main-scope on purpose: Session
    # has __slots__. NB keyed by the ADDRESS until 09-21, which two consoles in
    # one house share.
    _quest_pick = {}
    # session key (sec 4gz) -> quest id while its current battle is a MISSION
    # (set by a mission 38, dropped by any other 38): no fake teammates, solo
    # seating.
    _mission_battle = {}
    # 2026-09-24: doc_missions.MISSION_SETUP gives every set-up mission its
    # arena; --quest-zones pairs still override it.
    _quest_zone = dict(doc_missions.ARCHIVE_ZONES)
    _quest_zone.update({q: r[0] for q, r in doc_missions.MISSION_SETUP.items()})
    _quest_zone.update({int(q, 0): int(v, 0) for q, _, v in
                        (p.partition(":") for p in
                         a.quest_zones.replace(" ", "").split(",") if p)})

    _map_zone = parse_map_zones(a.battle_map_zones)
    # the inverse, for the command-41 answer's map label. First index wins, so
    # a hand-written table that points two maps at one zone stays single-valued.
    _zone_map = {}
    for _mi, _mz in sorted(_map_zone.items()):
        _zone_map.setdefault(_mz, _mi)

    def _map_name(m):
        return LOBBY_MAP_NAMES[m] if 0 <= m < len(LOBBY_MAP_NAMES) else "?"

    def _table_arena(cid):
        """sec 4hb: (arena zone, note) for the MAP the client's own battletable
        record holds, or (None, note) when it has no table, no decoded zone for
        that map, or no spawn in that zone.  `note` is None when there is simply
        nothing to say (no table at all); otherwise it is the log line."""
        if not a.battle_map_zone or not cid:
            return None, None
        k = bt_store.table_of(cid)
        if k is None:
            return None, None
        rec = bt_store.record(k)
        if not rec or len(rec) <= BT_OFF_MAP:
            return None, None
        m = rec[BT_OFF_MAP]
        z, why = battle_map_arena(m, _map_zone, a.gs_battle_zone,
                                  zone_spawns=_zone_spawn,
                                  needs_spawn=a.battle_map_needs_spawn)
        if why == ARENA_NO_ZONE:
            return None, ("table %d picked map %d (%s), which has NO decoded "
                          "arena zone -- staying in zone %d. sec 4hb: 8 of the "
                          "28 roster labels match no arena in zonelist.txt, and "
                          "a guess lands in someone else's map or a stub"
                          % (k, m, _map_name(m), a.gs_battle_zone))
        if why == ARENA_NO_SPAWN:
            return None, ("table %d picked map %d (%s) = arena zone %d, but no "
                          "--zone-spawns point exists for z%d -- staying in "
                          "zone %d rather than spawning in the VOID (sec 4gr). "
                          "pass --battle-map-needs-spawn to keep this guard"
                          % (k, m, _map_name(m), _map_zone[m], _map_zone[m],
                             a.gs_battle_zone))
        return z, ("table %d map %d (%s) -> ARENA ZONE %d (sec 4hb)"
                   % (k, m, _map_name(m), z))

    def _battle_zone_note(key, cid=None):
        """(zone, note) -- the whole precedence in one place, so the log line
        and the byte on the wire can never disagree."""
        q = _mission_battle.get(key) if key else None
        if q is None and cid:
            # Accept Mission -> a mission TABLE never sends
            # command 41, so _mission_battle stayed empty and Collector's Mind
            # (quest 16, Church) opened in the table map's Jungle. The table
            # record itself names the quest (flags 0x10000, wire+26).
            q = _record_quest(cid)
        if q is not None:
            _qz = _quest_zone.get(q, a.gs_battle_zone)
            return _qz, ("quest %d is a MISSION -> arena zone %d "
                         "(--quest-zones; the table's map does not apply)"
                         % (q, _qz))
        z, note = _table_arena(cid)
        return (a.gs_battle_zone if z is None else z), note

    def _battle_zone(key, cid=None):
        """Kind 2's arena zone for the client keyed `key` (sec 4gz: its
        (ip, port), not its address -- a household NAT shares the address):
        its quest's zone while its battle is a mission (--quest-zones), else
        the zone its BATTLETABLE'S CHOSEN MAP is played in (sec 4hb, needs
        `cid`), else --gs-battle-zone."""
        return _battle_zone_note(key, cid)[0]

    def _battle_result(sess, room=None):
        """2026-09-13: (kind-4 RESULT record, log note) for this client, and
        the career tally it reports (doc_stats.py).

        The server has NO combat data yet: the client's 1 Hz report (message
        24) needs a kind 3 we never send, and request 44 is item-use counts. So
        a PvP battle is judged a DRAW, and a mission that ran to our timer is a
        FAILURE -- its own defeat text is "Exceed Time Limit". Kind 4 carries
        NEW TOTALS for rank points (+8) and gil (+16); the zero record we used
        to send set both to 0 on screen."""
        cid = sess.seen_charid[0]
        # 2026-09-26: THIS client's account. Without `sess` the key came from
        # current[0] -- whoever sent the last packet -- and end_battle runs off
        # the room clock or another member's request 30, so with --accounts-db
        # every other member missed its tally row and got the all-zero record:
        # a LOSS, 0 rank points, 0 gil on screen (live tables 30-32, 09-26).
        key = _wallet_key(sess.seen_uid[0], cid, sess)
        quest = _mission_battle.get(sess.key)
        if room is not None:
            # sec 4he: the ROOM's tally, computed ONCE for every member
            # (kills / KOs / team / winner from the kind-9 ledger) and read
            # back per member here.
            if room.tally is None:
                rows = []
                for m in room.members:
                    ms = session_of(m)
                    # a member whose session is gone keeps the key it had at
                    # its 47 -- the fallback would file its battle under
                    # current[0]'s account (2026-09-26)
                    mk = (_wallet_key(ms.seen_uid[0], m, ms) if ms is not None
                          else _room_member_key.get(m)
                          or _wallet_key(0, m, None))
                    rows.append({"key": mk, "id": m,
                                 "name": next((n for k, n, _i in
                                               _rank_characters() if k == mk),
                                              None),
                                 "team": (room.team_of(m) if room.rules.mode
                                          != "BT" else m),
                                 "kills": room.kills.get(m, 0),
                                 "kos": room.deaths.get(m, 0),
                                 "first_kill": m == room.first_killer,
                                 "finisher": m == room.finisher,
                                 # 2026-09-26: Assault "captures his enemy's
                                 # base and brings his team victory" = the
                                 # OCCUPIER, not the destroyer
                                 "base_capture": m == room.occupier,
                                 # 2026-09-26: the launch medals' inputs
                                 # (doc_stats.MODE_MEDALS): standing at the
                                 # end (Survivor), capsule carriers KO'd
                                 # (Capsule Seeker), the winning hold's last
                                 # capsule, enemy leaders KO'd (Leader Slayer)
                                 "survived": (m not in room.left
                                              and not room.eliminated(m)),
                                 "carrier_kos": room.carrier_kos.get(m, 0),
                                 "last_capsule": m == room.last_capsule,
                                 "leader_kills": room.leader_kills.get(m, 0),
                                 "left": m in room.left,
                                 "coins": (room.coins.get(m, 0)
                                           if a.chocobo_coins == "on" else 0)})
                if a.leave_rp_penalty > 0:
                    # 2026-09-24: a player who left partway already paid the
                    # --leave-rp-penalty; the end tally must not score them too
                    rows = [r for r in rows if r["id"] not in room.left]
                if room.mission is not None:
                    mode = "MISSION"
                    winner = 0 if room.outcome(room.members[0]) == "w" else None
                    for r in rows:
                        r["team"] = 0
                else:
                    mode = room.rules.mode if room.rules.mode in ("BT", "TBT", "FA") \
                        else "TBT"
                    w = room.winner_slot()
                    if w is None:
                        winner = None
                    elif mode == "BT":
                        winner = next((m for m in room.members
                                       if room.slot_of(m) == w), None)
                    else:
                        winner = room.winner_team()
                # variant: the table's own mode -- the tally files TDM / TBS /
                # TCP / ... under TBT, but Star of Victory is "TBT mode" only
                room.tally = _stats.record_battle(
                    mode, rows, winner, room.elapsed(time.time()),
                    quest=room.mission, variant=room.rules.mode)
                room.tally_keys = {r["id"]: r["key"] for r in rows}
                # 2026-09-24: a UNIT battle also settles the two units --
                # each gets its members' rank points and a W/D/L (doc_unit)
                if (_units is not None and room.mission is None
                        and room.rules.flags & BT_FLAG_UNIT):
                    _usides = {}
                    for r in rows:
                        _u = _units.enlisted(r["key"])
                        _t = room.tally.get(r["key"])
                        if not _u or _t is None:
                            continue
                        _o, _p = _usides.get(_u, (_t["outcome"], 0))
                        _usides[_u] = (_o, _p + int(_t.get("rp", 0)))
                    _ures = _units.record_battle(
                        [(u, o, p) for u, (o, p) in _usides.items()])
                    print("  [units] UNIT BATTLE table %d settled: %s" % (
                        room.key, ", ".join("%s %s +%d pts (now %d)" % (
                            h, o.upper(), p, tot)
                            for h, (o, p, tot) in _ures.items()) or "no units"),
                        flush=True)
            summ = room.tally.get(key)
            mode = room.rules.mode
            if summ is None:
                raise KeyError("0x%x has no row in table %d's tally" % (cid, room.key))
        else:
            if quest is not None:
                mode, winner = "MISSION", 1          # the player is team 0
            else:
                mode = "TBT" if len(set(sess.gs_teams.values())) >= 2 else "BT"
                winner = None
            name = next((n for k, n, _i in _rank_characters() if k == key), None)
            summ = _stats.record_battle(
                mode, [{"key": key, "name": name, "id": cid,
                        "team": 0 if quest is not None
                        else sess.gs_teams.get(cid, 0)}],
                winner, a.gs_battle_length, quest=quest)[key]
        c = _stats.career(key)
        # 2026-09-23 (sec 4hc): SE's rule -- the novice mark comes off at 20
        # kills. The ceremony plays on lobby re-entry because vl_main saved
        # "novice at departure" in event flag 5 (quest_scr003.ev(9998)).
        if (_novice is not None and a.novice == "on"
                and _novice.graduate_by_kills(key)):
            broadcast_graduate(cid, "%d career kills" % c.get("kills", 0))
        gil = 0
        if _shop is not None:
            w = _shop.wallet(key)
            if summ["gil"]:
                w["gil"] = min(w["gil"] + summ["gil"], doc_shop.GIL_MAX)
                _shop.save()
            gil = w["gil"]
            # 2026-09-26: the Soldier Mask is EARNED by clearing the DG Drone
            # 2nd exam (doc_gear.settle_soldier_mask: into the bag at the
            # next world door, once there is room)
            if (summ.get("quest") == doc_gear.SOLDIER_MASK_EXAM
                    and summ.get("outcome") == "w"
                    and doc_gear.owe_soldier_mask(w)):
                _shop.save()
                print("  [gear] [%s] cleared the Drone 2nd exam: Soldier Mask "
                      "OWED (in the bag from the next world door)" % key,
                      flush=True)
            # 2026-09-24: Collector's Mind is where the Fuzzy Seeds come from
            # (Lifestream fan archive) -- Hiren grows them (doc_npcquests)
            if (a.fuzzy_seed == "clear"
                    and summ.get("quest") == doc_npcquests.COLLECTORS_MIND
                    and summ.get("outcome") == "w"):
                print("  [npcquest] [%s] cleared Collector's Mind: %s"
                      % (key, _bag_move(key, [(doc_npcquests.FUZZY_SEED,
                                               doc_npcquests.SEEDS_PER_CLEAR)])),
                      flush=True)
        if _rank is not None:
            _stats.push_rankings(_rank)
        # 2026-09-24: the Results board -- every player's kills / KOs / rank
        # points and who won each medal, in THIS client's roster order
        holders, columns = None, None
        if room is not None:
            holders, columns = doc_stats.result_board(
                cid, room.members,
                {m: room.tally.get(k) for m, k in room.tally_keys.items()})
        rec = doc_stats.result_record(summ["outcome"], c["rp"], gil,
                                      doc_stats.medal_mask(c), c["rank"],
                                      score=summ["rp"], holders=holders,
                                      columns=columns)
        return rec, ("RESULT [%s] %s %s%s: +%d rank points, +%d gil, medals %s -> %s"
                     % (key, mode, {"w": "WIN", "l": "LOSS", "d": "DRAW"}.get(
                         summ["outcome"], summ["outcome"]),
                        (" (%d kills / %d KOs)" % (summ.get("kills", 0),
                                                   summ.get("kos", 0)))
                        if room is not None else "", summ["rp"],
                        summ["gil"], [doc_stats.MEDALS[m] for m in summ["medals"]]
                        or "none", _stats.summary_line(key)))

    _zone_spawn = {}
    for _zs in (a.zone_spawns or "").replace(" ", "").split(";"):
        if _zs:
            _zk, _, _zv = _zs.partition(":")
            _zone_spawn[int(_zk, 0)] = tuple(float(x) for x in
                                              _zv.split(","))[:3]

    def _spawn_team(key, cid):
        """2026-09-24: `cid`'s team when its battle is a TEAM battle (not a
        mission, not individual), else None."""
        if not cid:
            return None
        room = battle_of(cid)
        if room is not None:
            if room.mission is not None or room.individual():
                return None
            return room.team_of(cid)
        tk = bt_store.table_of(cid)
        rec = bt_store.record(tk) if tk is not None else None
        if not rec or len(rec) <= BT_OFF_MODE:
            return None
        if struct.unpack_from("<I", rec, BT_OFF_FLAGS)[0] & BT_FLAG_MISSION:
            return None
        if BT_MODE_NAMES.get(rec[BT_OFF_MODE], "TBT") == "BT":
            return None
        ms = session_of(cid)
        return ms.gs_teams.get(cid, 0) if ms is not None else 0

    def _battle_pos(key, cid=None, per_team=True):
        """Kind 2's spawn for the client keyed `key` (sec 4gz): its arena
        zone's entry in --zone-spawns, else --gs-battle-pos.  Takes `cid` for
        the same reason _battle_zone does -- a table's map moves the zone, and
        the spawn has to move with it (sec 4gr.6: a z201 point is the VOID in
        z208). 2026-09-24: in a team battle, the player's TEAM start point
        (team_start) when the arena has one; per_team=False = the zone's."""
        z = _battle_zone(key, cid)
        if per_team:
            tm = _spawn_team(key, cid)
            ts = team_start(z, tm) if tm is not None else None
            if ts is not None:
                print("  [arena] 0x%08x spawns at team %d's start %s (zone %d)"
                      % (cid, tm, tuple(round(v, 1) for v in ts), z), flush=True)
                return ts
        if z in _zone_spawn:
            return _zone_spawn[z]
        try:
            return tuple(float(x) for x in a.gs_battle_pos.split(","))[:3]
        except ValueError:
            return (0.0, 0.0, 0.0)
    def _mission_quest(sess):
        """2026-09-23: the quest id of `sess`'s Mission-flagged table, or 0."""
        cid = sess.seen_charid[0] if sess is not None else 0
        tk = bt_store.table_of(cid) if cid else None
        rec = bt_store.record(tk) if tk is not None else None
        if not rec or len(rec) <= BT_OFF_MISSION + 1:
            return 0
        if not struct.unpack_from("<I", rec, BT_OFF_FLAGS)[0] & BT_FLAG_MISSION:
            return 0
        return struct.unpack_from("<H", rec, BT_OFF_MISSION)[0]

    def _record_quest(cid):
        """The mission quest id of `cid`'s battle table, or None when the
        table is not a mission (flags 0x10000, u16 at wire+26)."""
        tk = bt_store.table_of(cid) if cid else None
        rec = bt_store.record(tk) if tk is not None else None
        if not rec or len(rec) <= BT_OFF_MISSION + 1:
            return None
        if not struct.unpack_from("<I", rec, BT_OFF_FLAGS)[0] & BT_FLAG_MISSION:
            return None
        return struct.unpack_from("<H", rec, BT_OFF_MISSION)[0] or None

    def _mission_ctrl(sess):
        """2026-09-23: the NPC controller id for `sess`'s battle -- its
        table's mission quest mapped through --quest-situations -- or 0."""
        cid = sess.seen_charid[0] if sess is not None else 0
        tk = bt_store.table_of(cid) if cid else None
        rec = bt_store.record(tk) if tk is not None else None
        if not rec or len(rec) <= BT_OFF_MISSION + 1:
            return 0
        if not struct.unpack_from("<I", rec, BT_OFF_FLAGS)[0] & BT_FLAG_MISSION:
            return 0
        return _quest_sit.get(struct.unpack_from("<H", rec, BT_OFF_MISSION)[0], 0)

    _r24_next = {}

    def _base_setup(sess):
        """2026-09-24: (gimmicks, hp, controller) when `sess`'s battle is a
        TEAM BASE table (mode byte 3) with a Base Durability and its arena
        has bases, else None."""
        cid = sess.seen_charid[0] if sess is not None else 0
        tk = bt_store.table_of(cid) if cid else None
        rec = bt_store.record(tk) if tk is not None else None
        if not rec or len(rec) <= BT_OFF_MODE:
            return None
        if rec[BT_OFF_MODE] != 3:
            return None
        hp = struct.unpack_from("<I", rec, BT_OFF_BASE_HP)[0]
        if not hp:
            return None
        g = base_gimmicks(_battle_zone(sess.key, cid))
        if not g:
            return None
        ctrl = bt_store.leader_cid(tk) or cid
        return g, hp, ctrl

    def base_report_in(room, bs, reports, zone=None):
        """The CONTROLLER's base HP: forward changes (kind 33) to the other
        members' HUDs. A base that falls opens its OCCUPATION phase
        (--base-occupy, base_occupy_tick in fire_battles); with no spot for
        the arena, or --base-occupy off, it ends the room at once."""
        if room.base_spots is None and zone is not None:
            room.base_spots = base_spots(zone)
        _occ = a.base_occupy == "on" and room.base_spots is not None
        _was_down = set(room.base_down)
        changed = room.base_update(reports, occupy=_occ)
        for _bi in sorted(set(room.base_down) - _was_down):
            print("  [base] table %d: base %d (team %d) DESTROYED -- team %d "
                  "must occupy it: stand within %.0f of %s for %.0f s"
                  % (room.key, _bi, _bi, room.base_down[_bi],
                     a.base_occupy_radius,
                     tuple(round(v, 1) for v in room.base_spots[_bi]),
                     a.base_occupy_s), flush=True)
        if a.base_occupy == "on" and room.base_spots is None and changed:
            print("  [base] table %d: no base spot for zone %s -- a destroyed "
                  "base ends the battle at once (the old rule)"
                  % (room.key, zone), flush=True)
        for idx, hp in changed:
            for m in room.present():
                if m == bs[2]:
                    continue            # the controller owns the HP already
                ms, dst = member_dst(m)
                if dst is not None:
                    s.sendto(build_gs_notify(33, base_hp_payload(idx, bs[2], hp),
                                             seq=next_gs_seq(ms), ident=m), dst)
            print("  [base] table %d: base %d (team %d) HP %d" % (room.key, idx,
                                                              idx, hp), flush=True)
        if changed and room.over and room.why.endswith("base destroyed"):
            end_battle(room, time.time())

    def _send_base_objects(sess, dst, why):
        bs = _base_setup(sess)
        if bs is None or dst is None:
            return
        s.sendto(build_gs_notify(29, base_objects_payload(bs[0]),
                                 seq=next_gs_seq(sess), ident=sess.seen_charid[0]),
                 dst)
        print("  [base] SENT notify kind 29: bases %s (team 0, team 1), %s"
              % (list(bs[0]), why), flush=True)

    # 2026-09-24: situation per mission from doc_missions.MISSION_SETUP,
    # --quest-situations pairs override.
    _quest_sit = {q: r[1] for q, r in doc_missions.MISSION_SETUP.items()}
    _quest_sit.update({int(q, 0): int(v, 0) for q, _, v in
                       (p.partition(":") for p in
                        a.quest_situations.replace(" ", "").split(",") if p)})
    bt_store = BattletableStore(
        parse_battletable_spec(a.battletable_list,
                               name=a.user_list_name or a.lobby_chara_name),
        gs_ip=_gs_endpoint, gs_port=(a.world_gs_port or a.gs_connect_port),
        cur_min=(2 if a.bt_start_ready else 0),
        situation=a.bt_situation)
    bt_store.mission_time = dict(doc_missions.MISSION_TIME)
    bt_store.time_unit = a.bt_time_unit
    bt_tables = bt_store.records()
    if bt_tables:
        print("[battletable] serving %d table(s) on selector %d -> %d"
              % (len(bt_tables), BATTLETABLE_LIST_REQ, BATTLETABLE_LIST_ANS),
              flush=True)
    if a.battletable_verbs:
        print("[battletable] console verbs ON (sec 4dz): %s"
              % ", ".join("%d->%d %s" % (r, r + 1, selector_name(r))
                          for r in BT_VERB_REQS), flush=True)
        print("[battletable] reservation ECHO (sec 4fl): %s -- selector 152 "
              "after CREATE-ok/JOIN-ok so the leader holds a reservation on "
              "their own table (the 0x683b Start gate)"
              % ("OFF (--bt-no-reserve-echo)" if a.bt_no_reserve_echo
                 else "ON"), flush=True)
        print("[battletable] START -> BATTLE READY (sec 4fm): %s -- selector 38 "
              "right after the 241 answer to lobby command 3 (the leader's "
              "start_onlinebattle request)"
              % ("OFF (--bt-no-start-ready)" if a.bt_no_start_ready
                 else "ON"), flush=True)
        print("[gs] post-join battle start: ARM-ONCE per BATTLE READY (sec 4fn), "
              "%.0f s after the FIRST request 31; fake teammates pushed once"
              % a.gs_battle_after_join, flush=True)
    print("[gs] sec 4ft: kind 2 serves arena zone %d map %s (0 = the old title "
          "bounce); start-all %s; real roster %s; real distribution %s "
          "(settle %.0f s)"
          % (a.gs_battle_zone, _gs_bmap, "ON" if a.bt_start_all else "OFF",
             "ON" if a.gs_real_roster else "OFF",
             "ON" if a.gs_real_dist else "OFF", a.gs_real_dist_settle),
          flush=True)
    if not a.battle_map_zone or not _map_zone:
        print("[gs] sec 4hb: the table's CHOSEN MAP is IGNORED -- every table "
              "plays in zone %d whatever its Map row says (%s). This is the "
              "2026-09-23 'always the Jungle' bug; drop --no-battle-map-zone / "
              "--battle-map-zones=off to fix it."
              % (a.gs_battle_zone,
                 "--no-battle-map-zone" if not a.battle_map_zone
                 else "--battle-map-zones is empty"), flush=True)
    else:
        _ready = sorted(z for z in set(_map_zone.values())
                        if z == a.gs_battle_zone or z in _zone_spawn)
        _nospawn = sorted(set(_map_zone.values()) - set(_ready))
        print("[gs] sec 4hb: the table's MAP picks the arena zone -- %d of the "
              "%d roster maps decoded: %s"
              % (len(_map_zone), len(LOBBY_MAP_NAMES),
                 ", ".join("%d(%s)->z%d" % (i, _map_name(i), z)
                           for i, z in sorted(_map_zone.items()))), flush=True)
        print("[gs] sec 4hb: zones with a spawn (playable now): %s%s"
              % (", ".join("z%d" % z for z in _ready) or "NONE",
                 ("; NO --zone-spawns point for %s -- those maps %s"
                  % (", ".join("z%d" % z for z in _nospawn),
                     "stay in zone %d" % a.gs_battle_zone
                     if a.battle_map_needs_spawn
                     else "WILL be served anyway (default since 2026-09-23, "
                          "--battle-map-needs-spawn restores the guard): "
                          "expect the VOID until each floor is surveyed"))
                 if _nospawn else ""), flush=True)
        _undecoded = [i for i in range(len(LOBBY_MAP_NAMES))
                      if i not in _map_zone and i not in LOBBY_MAP_HOLES]
        if _undecoded:
            print("[gs] sec 4hb: NO zone decoded for map %s -- a table on one "
                  "of those stays in zone %d"
                  % (", ".join("%d(%s)" % (i, _map_name(i))
                               for i in _undecoded), a.gs_battle_zone),
                  flush=True)
    print("[gs] sec 4fv: solo distribution %s -- kind 20 after the "
          "post-join battle pushes when the table has < 2 seated members"
          % ("ON" if a.gs_solo_dist else "OFF (--gs-no-solo-distribution)"),
          flush=True)

    def next_gs_seq(sess):
        """The sequence for the next type-130 packet -- and it MUST move.

        WARNING:KEY: sec 4cx. The game-server channel runs a sequence WINDOW that every
        other channel here lets us ignore, and `--lobby-seq` defaults to 0 and
        never advances, so every reliable message we have ever sent it after the
        first was thrown away. In `0x00bc4e98`, past the three gates that stamp
        `[chan+224]`:

            delta = (seq - [chan+212]) & 0xffff
            if delta > 0xf800 and (flags & 1):  0x00bc4dd8(chan, seq) < 0 -> DROP
            if (u32)(delta - 1) >= 10000                                 -> DROP
            ...accept, and [chan+212] = seq

        so an accepted sequence needs **1 <= delta <= 10000**. Repeat one and
        `delta - 1` is 0xffffffff: the client prints

            [KEL NET GAME SRV] Drop resend packet 130 0

        which is exactly what the live emulog shows once every 15.05 s -- our
        own `--gs-keepalive-ms=15000`, dropped every single time.

        WARNING: It is a SILENT failure everywhere else: `[chan+224]` is stamped at
        0x00bc4f40 BEFORE the window runs, so CER-48101's 40 s timeout stays
        quiet while nothing is ever dispatched. That is why the grants appeared
        to work -- `build_gs_stats` IS message 27, the arming message, and an
        arm lands only because bit 6 of `[chan+204]` is still clear and takes
        the `beql` at 0x00bc4f30 straight past the window. One grant per world
        session, every repeat dropped.

        WARNING: And why `doc_gsreply_proof.py` said the channel was fine: it builds
        with **flags=0x00**, and an unreliable packet skips the window at
        0x00bc4f20. We ship flags=0x01. Measured, all of it, by running the
        client's own handler in `an offline run of the client's own code (doc_gsseq_proof)`.

        A plain monotone u16 is correct in every case, with no reset: the ARM
        message always bypasses the window (the channel reset at 0x00bc03b8
        clears `[chan+204]`, and 0x00bc4ff0 then stores our seq into
        `[chan+212]`), so it re-synchronises the window to whatever value this
        counter has reached. `0x00bc03b8` does NOT clear `[chan+212]`, so a
        counter that never restarts also survives a reset with delta 1.
        """
        sess.gs_seq[0] = (sess.gs_seq[0] + 1) & 0xFFFF
        return sess.gs_seq[0]


    def players_connected(exclude=None, now=None):
        """sec 4fz: how many DoC clients are ON the server -- sessions heard
        from inside --keepalive-idle-s, the same window peer_idle() uses to
        decide a peer has LEFT. sec 4gz: one per CLIENT (sessions key by
        (ip, port)), so two consoles in one house now count as two; a session
        left behind by a moved port stops counting as soon as it falls out of
        that window, and is reaped by --session-idle-drop.
        `exclude` is the client asking: at Select Server it has not joined yet,
        so the column shows the OTHER players, the way a server list does."""
        now = now or datetime.datetime.now().timestamp()
        win = a.keepalive_idle_s if a.keepalive_idle_s > 0 else 90.0
        return sum(1 for _ss in sessions.values()
                   if _ss is not exclude and _ss.last_peer_rx[0]
                   and now - _ss.last_peer_rx[0] <= win)

    def peer_idle(sess, now):
        """the 2026-09-05 audit (C): no unsolicited sends to a peer that left."""
        return (a.keepalive_idle_s > 0 and sess.last_peer_rx[0] > 0
                and (now - sess.last_peer_rx[0]) > a.keepalive_idle_s)

    def fire_keepalives(sess, now):
        """Every timer-driven send, due or not -- called from BOTH the select
        timeout and after each inbound datagram.

        WARNING: the 2026-09-05 audit (B): the kelsvc and game-server keepalives
        used to sit after the blocking recvfrom, so they only ever ran when the
        client had just spoken -- 161 and 160 sends against 7,080 lobby
        keepalives over the same two days.  The client's 2 Hz stream goes quiet
        in menus, which is exactly where the 40 s kelsvc receive watchdog
        (CER-48102, sec 4cc) then had nothing refreshing it.  Now the loop
        selects on the earliest of all three deadlines and fires whatever is
        due, whether or not the client is transmitting.
        """

        if peer_idle(sess, now):
            return
        # 2026-09-23 (sec 4hc): the queued new-player intro push.
        _idue = _intro_due.get(sess.key)
        if _idue and now >= _idue:
            _intro_due.pop(sess.key, None)
            _intro_sent.add(sess.key)
            send_push(sess, doc_novice.intro_push(
                subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7)),
                sess.seen_charid[0], "sub 10 event 1 (the new-player intro)")
        # Drive the advance loop on OUR clock, not on the client's retransmits.
        if (a.lobby_keepalive_ms > 0 and sess.ka_template is not None and sess.ka_src is not None
                and not (a.nest_quiet_after_frag3 > 0
                         and sess.frag3_sent >= a.nest_quiet_after_frag3)
                and now >= (sess.ka_next or 0.0)):
            # Opening: beat fast until the nest is disarmed (we cannot observe that, so
            # we just keep trying for --lobby-keepalive-open-s). Steady: a gap wide
            # enough for the client's own 9001 ms poll gate to open (sec 4al/4am).
            opening = (a.lobby_keepalive_open_s > 0 and sess.ka_first is not None
                       and (now - sess.ka_first) < a.lobby_keepalive_open_s)
            ka_interval = (a.lobby_keepalive_open_ms if opening else a.lobby_keepalive_ms) / 1000.0
            sess.ka_next = now + ka_interval
            ka = build_lobby_advance(
                sess.ka_template,
                selector=a.lobby_sustain_selector or a.lobby_selector,
                seq=a.lobby_seq,
                inner_ip=host_for(a.lobby_ip, sess.ka_src[0]),
                empty_records=True, **sess.chara_kw)
            s.sendto(bytes(ka), sess.ka_src)
            sess.ka_sent += 1
            # The ladder extras ride the KEEPALIVE, not just the inbound path.
            # MEASURED (doc-rx-boot10-duty): a boot is only three packets --
            # entrance(80) -> lobby(96) -> mode-2(36) in 0.13 s -- and then the
            # client goes SILENT while it loads the zone and draws character
            # select.  The charamake timeout (CER-48104) fires in that silence.
            # An extra code sent only on inbound would therefore fire three times
            # at the start, when the nest is nowhere near state 9, and never once
            # during the phase we are trying to answer.
            for sel in extra_selectors:
                ex = build_lobby_advance(
                    sess.ka_template, selector=sel, seq=a.lobby_seq,
                    inner_ip=host_for(a.lobby_ip, sess.ka_src[0]),
                    empty_records=True)
                if ex is not None:
                    s.sendto(ex, sess.ka_src)
            kts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print("[%s] KEEPALIVE #%d (%s, %dms) -- unsolicited selector-%d%s to %s:%d"
                  % (kts, sess.ka_sent, "opening" if opening else "steady",
                     int(ka_interval * 1000),
                     a.lobby_sustain_selector or a.lobby_selector,
                     ("+ladder%s" % extra_selectors) if extra_selectors else "",
                     sess.ka_src[0], sess.ka_src[1]), flush=True)
        # KEY: sec 4cc: refresh the client's KELSVC receive watchdog. Its budget
        # is [conn+4] = 40000 ms against [conn+32], and the ONLY thing that
        # refreshes [conn+32] is a message reaching the driver 0x005895b0, which
        # stamps it in its tail for any selector. We send type-127 solely in
        # answer to requests, so an active player who simply is not REQUESTING
        # sees 40 s of silence on that channel -> CER-48102. A no-op selector
        # costs nothing: state and flags measured unchanged.
        if (a.kelsvc_keepalive_ms > 0 and sess.ka_src is not None
                and now >= sess.kel_ka_next):
            sess.kel_ka_next = now + a.kelsvc_keepalive_ms / 1000.0
            _kreq = bytearray(HDR_LEN + 176)
            _kreq[0] = 0x04
            struct.pack_into("<H", _kreq, 2, len(_kreq))
            _kreq[8] = a.world_type & 0xFF
            _kk = build_world_answer(
                bytes(_kreq), selector=a.kelsvc_keepalive_selector, seq=a.lobby_seq,
                subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
                # sec 4dv: same reason as the game-server connect -- an arm
                # that reads record+4 compares it with [kelsvc+272], so send
                # the id the client told us it is using, not a constant 0.
                inner_ip=None, ptype=a.world_type, pad_to=a.world_pad,
                ident=sess.seen_charid[0])
            if _kk is not None:
                s.sendto(_kk, sess.ka_src)
                print("  KELSVC KEEPALIVE (type-%d selector %d no-op) -> %s:%d "
                      "-- refreshes [conn+32], sec 4cc"
                      % (a.world_type, a.kelsvc_keepalive_selector,
                         sess.ka_src[0], sess.ka_src[1]), flush=True)
        # sec 4cq: the GAME SERVER channel's own 40 s deadline. Once the arm
        # above has set [chan+204] bit 6, ANY accepted message refreshes
        # [chan+224] -- 0x00bc4e98 stamps it before it dispatches, so the type
        # does not matter. Message 29's table entry IS the shared epilogue, so
        # it is the cheapest no-op the channel has.
        # sec 4fw (live 09-13): the distribution's settle was only re-checked
        # on request 31 -- READY at 02:03:19.9, the last click's 31 at :22.7,
        # none after, so kind 20 never went out and both players sat in the
        # briefing room. Re-check it on the server's clock.
        if a.gs_real_dist and sess.seen_charid[0]:
            _rk = bt_store.table_of(sess.seen_charid[0])
            _due = (gs_dist_due(gs_table_state(_rk), a.gs_real_dist_settle)
                    if _rk is not None else None)
            if _due is not None and now >= _due:
                try:
                    gs_sync_table(_rk)
                except Exception:
                    import traceback
                    print("  [roster] gs_sync_table (timer) FAILED:\n%s"
                          % traceback.format_exc(), flush=True)
        # sec 4ga: GO. Kind 5 (START) sets facade 0x80, which makes
        # getBattleInitPos return the player's OWN record instead of our kind-2
        # spawn -- so it (and 53) wait until ev2045.battlefield has read the
        # spawn and parked in waitlogin, which waits for exactly this bit.
        if (sess.gs_battle_go[0] and now >= sess.gs_battle_go[0]
                and sess.gs_join_src[0] is not None):
            sess.gs_battle_go[0] = 0.0
            _gspec = a.gs_battle_go
            _mctl = _mission_ctrl(sess)
            if _mctl:
                _gspec = ",".join(
                    ("28:" + npc_controller_payload(_mctl).hex())
                    if part.strip() == "28" else part
                    for part in (_gspec or "").split(","))
                print("  [missions] GO burst: kind 28 names NPC controller %d"
                      % _mctl, flush=True)
            elif a.mp_points == "on":
                # 2026-09-26 (doc_items): the same MP-point record the spawn
                # carried; a zero 28 here would re-send count 0
                _gspec = ",".join(
                    ("28:" + doc_items.mp_points_record().hex())
                    if part.strip() == "28" else part
                    for part in (_gspec or "").split(","))
            _bs = _base_setup(sess)
            if _bs is not None:
                # the gate burst's kind 29 must carry the SAME bases: a zero
                # record would empty the object table the HUD reads HP from
                _gspec = ",".join(
                    ("29:" + base_objects_payload(_bs[0]).hex())
                    if part.strip() == "29" else part
                    for part in (_gspec or "").split(","))
            for _k, _np in gs_battle_sequence(_gspec,
                                              seq_fn=lambda: next_gs_seq(sess),
                                              ident=sess.seen_charid[0]):
                s.sendto(_np, sess.gs_join_src[0])
                time.sleep(0.05)
                print("  [battle] GO: SENT notify kind %d (%s), %.1f s after "
                      "its 47 (sec 4ga)" % (_k, GS_NOTIFY_NAMES.get(_k, "?"),
                                            now - (sess.gs_battle_on[0] or now)),
                      flush=True)
            try:
                capsule_send_field(battle_of(sess.seen_charid[0]), sess)
            except Exception:
                import traceback
                print("  [capsule] field FAILED:\n%s" % traceback.format_exc(),
                      flush=True)
            if _bs is not None:
                for _bi in range(len(_bs[0])):
                    s.sendto(build_gs_notify(33, base_hp_payload(_bi, _bs[2], _bs[1]),
                                             seq=next_gs_seq(sess),
                                             ident=sess.seen_charid[0]),
                             sess.gs_join_src[0])
                print("  [base] SENT notify kind 33 x%d: HP %d, controller 0x%08x"
                      % (len(_bs[0]), _bs[1], _bs[2]), flush=True)
            if (a.npc_arena == "on" and _npc_arena_types) or _mission_ctrl(sess):
                _npc_arena_due[sess] = now + a.npc_arena_after
        # sec 4gs addendum 4: the arena kind-15 test ring.
        _nad = _npc_arena_due.get(sess)
        if _nad and now >= _nad and sess.gs_join_src[0] is not None:
            _npc_arena_due.pop(sess, None)
            _ctr = _battle_pos(sess.key, sess.seen_charid[0], per_team=False)
            _rb = None
            _mctl2 = _mission_ctrl(sess)
            _mz = _battle_zone(sess.key, sess.seen_charid[0]) if _mctl2 else None
            _msp = (MISSION_SPAWNS.get(str(_mz), {}).get(str(_mctl2))
                    if _mctl2 else None)
            if _mctl2 and not (_msp and _msp.get("count") and _msp.get("spawn")):
                # 2026-09-23: the situation picks the MODELS (live: every type
                # value drew situation 3000's one enemy model, the dog), but
                # some mission controllers carry no spawn nodes (z201 3003..
                # 3005). Place the NPCs at the nearest mission controller that
                # has them.
                _zc = MISSION_SPAWNS.get(str(_mz), {})
                _alt = sorted((abs(int(k) - _mctl2), k) for k, v in _zc.items()
                              if 3000 <= int(k) < 4000 and v.get("count")
                              and v.get("spawn"))
                if _alt:
                    _msp = _zc[_alt[0][1]]
                    print("  [missions] controller %d has no spawn nodes in zone "
                          "%s -> placing at controller %s's" % (_mctl2, _mz,
                                                               _alt[0][1]),
                          flush=True)
            if _msp and _msp.get("count") and _msp.get("spawn"):
                # 2026-09-23: the mission's own NPCs -- the controller's spawn
                # count at its own spawn nodes (arena bzd tables 28/29/15). The
                # enemy TYPE is not in the controller record yet, so the test
                # types are cycled and each id's type is logged: whichever
                # draws a DG soldier is the one to pin.
                # SIT:t,t,..;SIT:t,.. per situation, or one bare list for all
                _mtspec = {}
                for _part in (a.mission_npc_types or "").split(";"):
                    _k, _sep, _v = _part.strip().partition(":")
                    if _sep and _k.lower().startswith("q"):
                        _mtspec[("q", int(_k[1:], 0))] = doc_npc_spawn.parse_types(_v)
                    elif _sep:
                        _mtspec[int(_k, 0)] = doc_npc_spawn.parse_types(_v)
                    elif _k:
                        _mtspec[None] = doc_npc_spawn.parse_types(_k)
                _mquest = _mission_quest(sess)
                _msu = doc_missions.mission_setup(_mquest)
                if _msu and ("q", _mquest) not in _mtspec:
                    _mtspec[("q", _mquest)] = _msu[2]
                _mexact = _mtspec.get(("q", _mquest)) or _mtspec.get(_mctl2)
                _mtypes = (_mexact or _mtspec.get(None)
                           or _npc_arena_types or doc_npc_spawn.parse_types(
                               doc_npc_spawn.ARENA_TYPES_DEFAULT))
                _ments = [doc_npc_spawn.entry(
                    doc_npc_spawn.ARENA_ID_BASE + _i, _mtypes[_i % len(_mtypes)],
                    tuple(_p), (0.0, 0.0, 1.0), a.npc_spawn_hp)
                    for _i, _p in enumerate(_msp["spawn"][:(
                        min(_msp["count"], len(_mexact)) if _mexact
                        else _msp["count"])])]
                _rb = [struct.pack("<I", len(_ments[_j:_j + 8]))
                       + b"".join(_ments[_j:_j + 8])
                       for _j in range(0, len(_ments), 8)]
                _nmis = len(_ments)
                _mnpc[sess] = {
                    "types": {doc_npc_spawn.ARENA_ID_BASE + _i:
                              _mtypes[_i % len(_mtypes)] for _i in range(_nmis)},
                    "spawn": list(_msp["spawn"]), "next": _nmis, "due": []}
                print("  [missions] zone %s controller %d: %d NPC(s) at the "
                      "controller's spawn nodes, types by id: %s"
                      % (_mz, _mctl2, _nmis, ", ".join(
                          "0x%x=t%d" % (doc_npc_spawn.ARENA_ID_BASE + _i,
                                        _mtypes[_i % len(_mtypes)])
                          for _i in range(_nmis))), flush=True)
            if _rb is None:
                if not (a.npc_arena == "on" and _npc_arena_types):
                    _rb = []
                else:
                    _rb = doc_npc_spawn.ring_payloads(_ctr, _npc_arena_types,
                                                      radius=a.npc_arena_radius,
                                                      hp=a.npc_spawn_hp)
                _nmis = len(_npc_arena_types) if _rb else 0
            for _b in _rb:
                s.sendto(build_gs_notify(doc_npc_spawn.KIND_ADD_NPC, _b,
                                         seq=next_gs_seq(sess),
                                         ident=sess.seen_charid[0]),
                         sess.gs_join_src[0])
                time.sleep(0.05)
            if _rb and not _msp:
                print("  [npc-arena] SENT notify kind %d 'Add Npc': %d NPC(s), types "
                      "%s counter-clockwise from +x, radius %.0f around (%.1f, %.1f, "
                      "%.1f), ids 0x%08x.. -> %s:%d"
                      % (doc_npc_spawn.KIND_ADD_NPC, len(_npc_arena_types),
                         a.npc_arena_types, a.npc_arena_radius, _ctr[0], _ctr[1],
                         _ctr[2], doc_npc_spawn.ARENA_ID_BASE,
                         sess.gs_join_src[0][0], sess.gs_join_src[0][1]),
                      flush=True)
            # Seen live (slot 7): the Add-Npc entries DO land in the
            # char table (8 x HP 100, flags 0x40050211) but never render: an
            # NPC entry gets an actor only from movement updates, and nobody
            # controls these. Notify kind 27 (retail arm 0x00bcc084) hands an
            # entity to a controller: body[16] u32 entity id, body[20] u32 new
            # controller's char id (== ours -> take over, 0x00be7bc8(.., 1)),
            # body[24] u32 mask (0 -> 0x7fffff). In a MISSION battle, give
            # every arena NPC to the player so its client simulates them.
            if _mission_ctrl(sess) and _nmis:
                _me = sess.seen_charid[0]
                for _i in range(_nmis):
                    s.sendto(build_gs_notify(
                        27, struct.pack("<III", doc_npc_spawn.ARENA_ID_BASE + _i,
                                        _me, 0),
                        seq=next_gs_seq(sess), ident=_me), sess.gs_join_src[0])
                    time.sleep(0.02)
                print("  [missions] SENT notify kind 27 x%d: NPC control of "
                      "0x%08x.. -> 0x%08x (the player)"
                      % (_nmis, doc_npc_spawn.ARENA_ID_BASE, _me),
                      flush=True)
        # 2026-09-23: REPLACE dead mission NPCs. The situation's resource set
        # loads a fixed number of each model (bzd table 20: 3001 = e030 x1, w010,
        # w003, e102 x2) -- a third soldier draws nothing (live: six requested,
        # invisible). So spawn what the set holds and put a fresh one of the
        # same type on the next spawn node a few seconds after each death, until
        # the objective ends the room.
        _mn = _mnpc.get(sess)
        if _mn and _mn["due"] and sess.gs_join_src[0] is not None:
            _room_r = battle_of(sess.seen_charid[0])
            if _room_r is None or _room_r.over:
                _mnpc.pop(sess, None)
            else:
                for _due, _typ in [d for d in _mn["due"] if now >= d[0]]:
                    _mn["due"].remove((_due, _typ))
                    _nid = doc_npc_spawn.ARENA_ID_BASE + _mn["next"]
                    _pos = _mn["spawn"][_mn["next"] % len(_mn["spawn"])]
                    _mn["next"] += 1
                    _mn["types"][_nid] = _typ
                    _me = sess.seen_charid[0]
                    s.sendto(build_gs_notify(
                        doc_npc_spawn.KIND_ADD_NPC,
                        struct.pack("<I", 1) + doc_npc_spawn.entry(
                            _nid, _typ, tuple(_pos), (0.0, 0.0, 1.0),
                            a.npc_spawn_hp),
                        seq=next_gs_seq(sess), ident=_me), sess.gs_join_src[0])
                    s.sendto(build_gs_notify(
                        27, struct.pack("<III", _nid, _me, 0),
                        seq=next_gs_seq(sess), ident=_me), sess.gs_join_src[0])
                    print("  [missions] REPLACEMENT NPC 0x%x type %d at %s -> "
                          "control 0x%x" % (_nid, _typ, _pos, _me), flush=True)
        # sec 4fy: the battle END. Kind 4 is the RESULT (its arm 0x00bc1760
        # sets facade 0x40, which ends ev2045's battle loop -> act_win/lose ->
        # the result windows), and selector 39's arm 0x00bcbd70 is the full
        # battle reset 0x00bd2a38 (facade 0x80/0x08/0x200/0x40 off) -- without
        # it ev2045 exit(217)s with 0x80 still set, main() picks br_main, and
        # the client hangs black in vl_brf2 (live 09-13, br_main stage 2).
        if (sess.gs_battle_end[0] and now >= sess.gs_battle_end[0]
                and sess.gs_join_src[0] is not None):
            # sec 4he: a battle with a ROOM ends on the room's clock
            # (fire_battles); this per-session end is the roomless fallback.
            sess.gs_battle_end[0] = 0.0
            _res_rec = bytes(GS_SETUP_LEN)
            if _stats is not None and sess.seen_charid[0]:
                try:
                    _res_rec, _res_note = _battle_result(sess)
                    print("  [stats] " + _res_note, flush=True)
                except Exception as _rex:      # never let a tally kill the END
                    print("  [stats] RESULT tally FAILED (%r) -- sending the "
                          "zero record" % (_rex,), flush=True)
            s.sendto(build_gs_notify(4, bytes(4) + _res_rec,
                                     seq=next_gs_seq(sess),
                                     ident=sess.seen_charid[0]),
                     sess.gs_join_src[0])
            sess.gs_battle_reset[0] = now + a.gs_battle_reset_after
            print("  [battle] SENT notify 4 (the RESULT, facade 0x40) -- "
                  "selector %d in %.0f s (sec 4fy)"
                  % (GS_BATTLE_OVER_SELECTOR, a.gs_battle_reset_after), flush=True)
        if sess.gs_battle_reset[0] and now >= sess.gs_battle_reset[0]:
            sess.gs_battle_reset[0] = 0.0
            sess.gs_battle_on[0] = 0.0
            if sess.ka_src is not None:
                _req = bytearray(HDR_LEN + 176)
                _req[0] = 0x04
                struct.pack_into("<H", _req, 2, len(_req))
                _req[8] = a.world_type & 0xFF
                _bo = build_world_answer(
                    bytes(_req), selector=GS_BATTLE_OVER_SELECTOR,
                    seq=a.lobby_seq,
                    subchannel=(a.world_subchannel if a.world_subchannel >= 0
                                else 7),
                    inner_ip=None, ptype=a.world_type, pad_to=a.world_pad,
                    ident=sess.seen_charid[0])
                if _bo is not None:
                    s.sendto(_bo, sess.ka_src)
                    print("  [battle] SENT selector %d (battle over / reset, "
                          "arm 0x00bcbd70) to %s:%d -- expect the lobby, not "
                          "br_main (sec 4fy)" % (GS_BATTLE_OVER_SELECTOR,
                                                 sess.ka_src[0], sess.ka_src[1]),
                          flush=True)
            # sec 4gc (live 09-13): finished games stayed in the battle table
            # list -- the table outlived its battle. Dissolve it here (the
            # second member's reset finds it gone), and drop its roster /
            # distribution state so a re-created key starts clean.
            _dk = (bt_store.table_of(sess.seen_charid[0])
                   if sess.seen_charid[0] else None)
            _dmem = bt_store.members(_dk) if _dk is not None else []
            if _dk is not None and bt_store.dissolve(_dk):
                gs_tables.pop(_dk, None)
                print("  [battle] table %d DISSOLVED after the battle -- off "
                      "the battle table list (sec 4gc)" % _dk, flush=True)
                for m in _dmem:
                    send_reservation_clear(m, why="table %d dissolved after "
                                           "the battle" % _dk)
        if sess.gs_join_deadline[0] and time.time() >= sess.gs_join_deadline[0]:
            sess.gs_join_deadline[0] = 0.0
            _bkey = sess.key if sess.gs_join_src[0] else None
            _bcid = sess.seen_charid[0] if sess.gs_join_src[0] else None
            _bpos = _battle_pos(_bkey, _bcid)
            _bzone, _bnote = _battle_zone_note(_bkey, _bcid)
            if _bnote:
                print("  [arena] " + _bnote, flush=True)
            if _bcid:
                # kind 25 (push_down) repeats this spawn and its M0/M1
                _spawn_of[_bcid] = (_bpos, battle_bmap(_bzone, _zone_pieces,
                                                       _gs_bmap))
            for _k, _np in gs_battle_sequence(a.gs_battle_start, spawn=_bpos,
                                              seq_fn=lambda: next_gs_seq(sess),
                                              ident=sess.seen_charid[0],
                                              zone=_bzone,
                                              bmap=battle_bmap(_bzone,
                                                               _zone_pieces,
                                                               _gs_bmap)):
                s.sendto(_np, sess.gs_join_src[0])
                time.sleep(0.05)
                print("  SENT notify kind %d (%s) on the post-join timer -- sec 4ed"
                      % (_k, GS_NOTIFY_NAMES.get(_k, "?")), flush=True)
            _send_base_objects(sess, sess.gs_join_src[0],
                               "with the spawn (post-join timer)")
            _mctl = _mission_ctrl(sess)
            if _mctl:
                s.sendto(build_gs_notify(28, npc_controller_payload(_mctl),
                                         seq=next_gs_seq(sess),
                                         ident=sess.seen_charid[0]),
                         sess.gs_join_src[0])
                print("  [missions] SENT notify kind 28 naming NPC controller %d "
                      "(the mission's situation) with the spawn" % _mctl, flush=True)
            elif a.mp_points == "on":
                # 2026-09-26 (doc_items): kind 28's count + mask are what the
                # zone setup's "magic supply" step (0x00bf1370) reads to create
                # the situation's MP points -- ONCE, so with the spawn, like
                # the mission's controller record and the bases' kind 29
                s.sendto(build_gs_notify(28, doc_items.mp_points_record(),
                                         seq=next_gs_seq(sess),
                                         ident=sess.seen_charid[0]),
                         sess.gs_join_src[0])
                print("  [mp point] SENT notify kind 28 (MP points: count 64, "
                      "all enabled) with the spawn", flush=True)
            # sec 4fv: a solo leader never satisfies gs_real_ready, so the
            # distribution -- the only door vl_main has to get_onlinezone --
            # never opened. Push it AFTER kind 2 (which sets [chan+204] & 4 and
            # the zone byte get_onlinezone polls for).
            _self = sess.seen_charid[0] or 0
            _tk = bt_store.table_of(_self) if _self else None
            _seated = [m for m in bt_store.members(_tk) if m] if _tk else []
            if a.gs_solo_dist and _self and len(_seated) < 2:
                _dist = gs_solo_distribution(sess.gs_teams, _self)
                s.sendto(build_gs_distribution(_dist, seq=next_gs_seq(sess),
                                               ident=_self),
                         sess.gs_join_src[0])
                if battle_of(_self) is None:
                    open_battle(_tk, [_self], {_self: sess.gs_teams.get(_self, 0)},
                                mission=_mission_battle.get(sess.key), now=now)
                print("  [solo] SENT notify 20 (PLAYER DISTRIBUTION) over %s "
                      "(table %s, %d seated). Watch: 'Player distribution has "
                      "been determined' -> OK -> request 47 -> get_onlinezone "
                      "-> KerberosZone.exit(z%d) (sec 4fv)"
                      % (["0x%x:t%d:s%d" % e for e in _dist], _tk, len(_seated),
                         _bzone),
                      flush=True)
        if (a.gs_keepalive_ms > 0 and sess.gs_ka_src[0] is not None
                and now >= sess.gs_ka_next[0]):
            sess.gs_ka_next[0] = now + a.gs_keepalive_ms / 1000.0
            s.sendto(build_gs_message(GS_KEEPALIVE_MSG, seq=next_gs_seq(sess),
                                      body_extra=bytes(64)), sess.gs_ka_src[0])
            print("  GAME-SERVER KEEPALIVE (message %d no-op) -> %s:%d -- "
                  "refreshes [chan+224], sec 4cq"
                  % (GS_KEEPALIVE_MSG, sess.gs_ka_src[0][0], sess.gs_ka_src[0][1]),
                  flush=True)

    def next_deadline(now):
        """The earliest timer across ALL sessions, or None to block (sec 4fq)."""
        due = []
        for sess in sessions.values():
            if peer_idle(sess, now):
                continue
            if (a.lobby_keepalive_ms > 0 and sess.ka_template is not None
                    and sess.ka_src is not None
                    and not (a.nest_quiet_after_frag3 > 0
                             and sess.frag3_sent >= a.nest_quiet_after_frag3)):
                due.append(sess.ka_next or 0.0)
            if a.kelsvc_keepalive_ms > 0 and sess.ka_src is not None:
                due.append(sess.kel_ka_next)
            if a.gs_keepalive_ms > 0 and sess.gs_ka_src[0] is not None:
                due.append(sess.gs_ka_next[0])
            if sess.frag3_pending is not None and sess.chara_burst_at is not None:
                due.append(sess.chara_burst_at + a.frag3_hold_s)
            if sess.gs_join_deadline[0]:
                due.append(sess.gs_join_deadline[0])
            for _bt in (sess.gs_battle_end[0], sess.gs_battle_reset[0],
                        sess.gs_battle_go[0]):
                if _bt:
                    due.append(_bt)            # sec 4fy: result / selector 39
            if _npc_arena_due.get(sess):
                due.append(_npc_arena_due[sess])   # sec 4gs addendum 4
            if _intro_due.get(sess.key):
                due.append(_intro_due[sess.key])   # sec 4hc: the intro push
            if a.gs_real_dist and sess.seen_charid[0]:
                _rk = bt_store.table_of(sess.seen_charid[0])
                if _rk is not None:
                    _due = gs_dist_due(gs_table_state(_rk), a.gs_real_dist_settle)
                    if _due is not None:
                        due.append(_due)   # sec 4fw: wake for the settle
        due.extend(battle_deadlines())             # sec 4he: room clocks
        _wd = weekly_deadline()                    # the weekly medals' rollover
        if _wd is not None:
            due.append(_wd)
        return min(due) if due else None

    while True:
        # sec 4fq: HELD FRAG3 + timers for EVERY client session, on our clock.
        _now = datetime.datetime.now().timestamp()
        for _sess in list(sessions.values()):
            if (_sess.frag3_pending is not None
                    and _sess.chara_burst_at is not None):
                held = _now - _sess.chara_burst_at
                if held >= a.frag3_hold_s:
                    fr_h, fsrc = _sess.frag3_pending
                    _sess.frag3_pending = None
                    s.sendto(fr_h, fsrc)
                    _sess.frag3_sent += 1
                    print("[%s]   SENT the HELD frag3 reply #%d after %.1f s to %s:%d"
                          % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
                             _sess.frag3_sent, held, fsrc[0], fsrc[1]), flush=True)
        # sec 4gz: REAP long-dead sessions. Keyed by (ip, port) the registry
        # grows with every re-bound NAT mapping, not just with every address,
        # so on a public server it has to be bounded -- and a stale entry would
        # otherwise sit in `players_connected` and in the adoption scan for the
        # life of the process. Nothing in flight is dropped: a session holding a
        # held frag3 or a pending chara reply is left alone.
        if a.session_idle_drop > 0:
            for _sk, _sess in list(sessions.items()):
                if (_sess.frag3_pending is None and _sess.chara_pending is None
                        and _sess.last_peer_rx[0]
                        and _now - _sess.last_peer_rx[0] > a.session_idle_drop):
                    sessions.pop(_sk, None)
                    print("[docudp] session %s:%d REAPED -- idle %.0f s, "
                          "%d client(s) now"
                          % (_sk[0], _sk[1], _now - _sess.last_peer_rx[0],
                             len(sessions)), flush=True)
                    if session_of(_sess.seen_charid[0]) is None:
                        vacate_seat(_sess.seen_charid[0], "session reaped")
        try:
            fire_battles(_now)                     # sec 4he: room clocks
        except Exception:
            import traceback
            print("  [battle] fire_battles FAILED:\n%s" % traceback.format_exc(),
                  flush=True)
        _wd = weekly_deadline()
        if _wd is not None and _now >= _wd:
            try:
                weekly_close("week rollover")
            except Exception:
                import traceback
                print("  [stats] weekly close FAILED:\n%s"
                      % traceback.format_exc(), flush=True)
        _dl = next_deadline(_now)
        if _dl is not None:
            if not select.select([s], [], [], max(0.0, _dl - _now))[0]:
                _t = datetime.datetime.now().timestamp()
                for _sess in list(sessions.values()):
                    fire_keepalives(_sess, _t)
                continue
        data, src = s.recvfrom(65535)
        # The addresses THIS sender can reach (host_for): every reply below that
        # carries one uses these, not a.lobby_ip / _gs_endpoint directly.
        _lip = host_for(a.lobby_ip, src[0])
        _gsip = host_for(_gs_endpoint, src[0])
        _bt_echo_key = None  # sec 4fl: JOIN-ok reservation echo target
        n += 1
        # sec 4fq: --peer is an ALLOWLIST now. A source not on it gets no session
        # and moves no state (the old single-global session let the 2nd client
        # clobber the 1st and die at CER-48104).
        if peer_allow and src[0] not in peer_allow:
            ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print("\n[%s] RECV #%d from %s:%d  %d bytes -- (ignoring: not in "
                  "--peer %s)" % (ts, n, src[0], src[1], len(data),
                                  sorted(peer_allow)), flush=True)
            continue
        # sec 4fq: bind (or create) THIS client's session, then rebind the boxed
        # per-client state so every existing name[0] access below is per client.
        # sec 4gz: (ip, PORT). One client = one UDP socket (measured, see the
        # `sessions` comment), and a NAT has to give two consoles in one house
        # two different external ports, so this is one session per console.
        sess = sessions.get(src)
        if sess is None:
            sess = sessions[src] = Session(src[0], src[1])
            print("[docudp] NEW CLIENT SESSION %s:%d -- %d client(s) now"
                  % (src[0], src[1], len(sessions)), flush=True)
        current[0] = sess
        sess.src = src
        gs_done = sess.gs_done
        gs_ka_src = sess.gs_ka_src
        gs_ka_next = sess.gs_ka_next
        gs_seq = sess.gs_seq
        gs_teams = sess.gs_teams
        gs_join_deadline = sess.gs_join_deadline
        gs_bots_sent = sess.gs_bots_sent
        gs_join_src = sess.gs_join_src
        gs_rearm_next = sess.gs_rearm_next
        last_pose = sess.last_pose
        last_wu = sess.last_wu
        seen_uid = sess.seen_uid
        seen_charid = sess.seen_charid
        last_stream = sess.last_stream
        last_peer_rx = sess.last_peer_rx
        save_count = sess.save_count
        sess.last_peer_rx[0] = datetime.datetime.now().timestamp()
        if len(data) == 96:
            sess.ka_template = data
            if sess.ka_first is None:
                sess.ka_first = datetime.datetime.now().timestamp()
        if sess.ka_src != src:
            sess.ka_src = src
        # NB: do NOT push ka_next out on inbound traffic (sec 4an).
        now = datetime.datetime.now().timestamp()
        fire_keepalives(sess, now)
        # 2026-09-13: PLAY TIME accrues while a selected character is online.
        if seen_charid[0]:
            _ptk = _pt_key.get((sess.key, seen_charid[0]))
            if _ptk is None:
                _ptk = _pt_key[(sess.key, seen_charid[0])] = _wallet_key(
                    seen_uid[0], seen_charid[0])
            _playtime.touch(sess.key, _ptk, now)
        # sec 4cx: THE CHANNEL CAN BE RESET UNDER US, AND WE NEVER NOTICE.
        # 0x00bc03b8 zeroes [chan+2148] (ready), [chan+204] (the arm bits) and
        # a dozen more fields, and it has four callers -- selector 39's arm
        # 0x00bccf20, the interface close at 0x0058c8c4, 0x00bd2ab0 and
        # 0x00bd75e8. `--gs-connect` only re-fires on a phase-27 round, so a
        # reset inside one world session leaves the item/stat manager reading
        # `[APP NET CLIENT] init item number -1` for the rest of it, exactly as
        # the 08-27 emulog shows: -1, then 0 once we connect, then -1 again at
        # the next zone entry with no reconnect in between.
        # Measured: re-running selector 104 + 38 on a reset channel takes it
        # straight back to ready=1, and on a HEALTHY channel it is harmless --
        # WARNING: except that it CLEARS [chan+204], so the arm must follow it, which
        # is exactly the order the gs_done block already sends them in.
        # WARNING: OFF by default: message 27 is a reward GRANT, and even an empty one
        # writes [array+0]/[array+4]. Arm this only for an experiment, and only
        # with --gs-stats empty.
        if a.gs_rearm_ms > 0 and gs_done[0] and now >= gs_rearm_next[0]:
            gs_rearm_next[0] = now + a.gs_rearm_ms / 1000.0
            gs_done[0] = False
            print("  GAME-SERVER RE-ARM due -- next in-game packet redoes "
                  "selector 104 + 38 + the arm (sec 4cx)", flush=True)
        if a.sweep and (now - last_rx) > BURST_GAP:
            sweep_i += 1
            if sweep_i < len(SWEEP):
                a.ptype, a.subtype, why = SWEEP[sweep_i]
                print("", flush=True)
                print("=" * 72, flush=True)
                print("SWEEP %d/%d -- type=%d subtype=%d   (%s)"
                      % (sweep_i + 1, len(SWEEP), a.ptype, a.subtype, why), flush=True)
                print("=" * 72, flush=True)
            else:
                print("", flush=True)
                print("[docudp] SWEEP EXHAUSTED -- holding at the last candidate",
                      flush=True)
        last_rx = now
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print("\n[%s] RECV #%d from %s:%d  %d bytes" % (ts, n, src[0], src[1], len(data)),
              flush=True)
        inner = None if a.no_decrypt else describe_inner(data)
        if inner is not None:
            print("  INNER (decrypted) type=0x%02x flags=0x%02x SEQ=%d ack-seq=%d%s%s"
                  % (inner["type"], inner["flags"], inner["seq"], inner["ack_seq"],
                     "  DATA" if inner["is_data"] else "",
                     "  ACK" if inner["is_ack"] else ""), flush=True)
        elif _KELCRYPT and not a.no_decrypt and len(data) >= 24:
            print("  INNER (decrypted) -- REJECTED by its own checksum "
                  "(unexpected mode/key?)", flush=True)
        print(describe(data), flush=True)
        print(hexdump(data), flush=True)
        if a.save:
            fn = os.path.join(a.save, "rx-%03d-%s.bin" % (n, ts.replace(":", "")))
            open(fn, "wb").write(data)
            save_count[0] += 1
            if a.save_max > 0 and save_count[0] % 500 == 1:
                try:
                    _fs = sorted((os.path.getmtime(os.path.join(a.save, f)),
                                  os.path.join(a.save, f))
                                 for f in os.listdir(a.save) if f.startswith("rx-"))
                    for _, _old in _fs[:max(0, len(_fs) - a.save_max)]:
                        os.remove(_old)
                except OSError as e:
                    print("  (save prune failed: %s)" % e, flush=True)

        if a.once and answered:
            continue

        extra_reply = None
        chara_burst_now = False

        # THE WORLD DOOR -- the type-0x7f GAME SERVER answer.
        #
        # Selecting a server at the character list sends a 132-byte mode-1 datagram
        # whose inner type is 127 (main = 128, lobby nest = 129).  Phase 27
        # (0x00ad3ef0) builds it in connectServer 0x00bce620 and prints "called
        # connectServer()."; phase 28 (0x00ad3f68) then calls kelsvc vt+44 =
        # 0x00bdb250 and advances ONLY on [kelsvc+12] == 2 exactly (`bne s0, 2`).
        #
        # Nothing we have ever sent lands on that channel, so the field is left at
        # the state 0x00589890 posted -- 1 -- and the 40 s receive watchdog runs out:
        # getIdle 0x00589a58 compares now - [kelsvc+32] against [kelsvc+8] == 40000,
        # and past it does `[kelsvc+12] = -1; return -1`.  The tick 0x00bcee70 sees
        # -1, takes its `s6 != -2` arm, calls 0x00589dc0(sub, 0xffff441a) -- that
        # constant IS -48102 -- and prints "[KEL LOBBY] lobby connection timeout."
        # That is exactly the observed `catch error = -1(phase = 28)` + CER-48102.
        #
        # The reply is the SAME recipe that already advances the nest, on a different
        # object with looser constants.  Driver 0x005895b0 is shared:
        #
        #     [record+20] body[0]  subchannel, must be <= [kelsvc+16] == 7  (nest: 5)
        #     [record+21] body[1]  SELECTOR -- 2 at state 1 -> arm 0x00589660
        #                          -> sub vt entry 6 = 0x00bc8aa0 (the kel overlay)
        #     [record+24] body[4]  bit 0 MUST be clear
        #
        # 0x00bc8aa0's first act is `0x005894f0(kelsvc+4, sockaddr, record)`, the same
        # m5 that advances the nest: it clears bit 31 of [kelsvc+28] and, iff
        # u16[record+24] & 1 == 0, does `[kelsvc+12] = 2`.  Otherwise it reports
        # -u16[record+26] as an error.  So body[4] carries the ECHOED command with bit
        # 0 doubling as the failure flag, and body[6..7] is the error code.
        #
        # WARNING: The request is MODE 1 and its first 16 body bytes are CIPHERTEXT, so
        # only body[16..] -- which carries the session token, plaintext -- may be
        # echoed.  build_world_answer synthesises body[0..15].  Echoing them put
        # body[0] = 216 on the wire and the driver rejected it at its first gate;
        # see that function's docstring and sec 4bj.
        # ROUTE ON THE INNER TYPE, NOT THE LENGTH.  Phase 28 is not the only round:
        # phases 29 and 31 send again on this same channel, both gated on
        # [kelsvc+12] == 2 and both answered by driving it back to 2 -- the same
        # selector-2 recipe (sec 4bn).  Their requests are NOT 132 bytes:
        # 0x00bd0688 zeroes a 532-byte buffer, writes the u16 arg at buf+32 and
        # adds 4 to the u16 length at buf+18, so each round is its own size.
        # Keying on len == 132 answered phase 28 and nothing after it.
        #
        # WARNING: data[8] IS NOT THE INNER TYPE ON A MODE-1 PACKET.  sec 4bj: mode 1
        # enciphers 32 bytes from offset 8, so pkt[8] is CIPHERTEXT -- the phase-27
        # request reads `type@8=125` on the wire while its decrypted type is 0x7f.
        # Routing on the raw byte therefore silently stopped answering the world
        # door: one boot, zero WORLD-DOOR lines, CER-48102 at the 40 s watchdog.
        # `inner` above is already the DECRYPTED header (describe_inner ->
        # doc_kelcrypt.header, self-checked by its own checksum), so use its type
        # and fall back to the raw byte only for the plaintext modes.
        # >= not >: phase 29's request is EXACTLY 40 bytes (BODY_OFF + 16), a
        # 16-byte body `07 0c 00 00 01 00 00 00 ...`, and `>` excluded it by one
        # byte -- we ACKed it and never answered, so phase 30 polled an empty
        # queue for 9 s and died -47117.  36-byte polls stay excluded.
        # KEY: sec 4fu (briefing, live 09-13): a PEER position datagram whose
        # header we cannot decrypt (the Deck's mode-4 0x83s in the briefing
        # room) -- recognised by its body carrying this client's OWN id, and
        # given the header the client meant, so it reaches the stream/relay
        # path below instead of being read as "GS request <charid & 0xffff>".
        if (inner is None and a.peer_relay != "off"
                and peer_pos_id(data) in {i for i in (seen_charid[0],
                                                      sess.pos_id[0]) if i}):
            inner = synth_peer_inner(data)
            print("  INNER (synthesised) type=0x83 flags=0x08 -- a PEER position "
                  "datagram, id 0x%08x from its body (sec 4fu)"
                  % inner["u32_16"], flush=True)
        _itype = (inner["type"] if inner is not None
                  else (data[8] if len(data) > 8 else -1))
        # sec 4gz: THE CLIENT MAY HAVE MOVED PORT. Before a single field is
        # touched, fold in the session this charid was last playing on (its
        # router re-bound the mapping while the lobby socket idled). Done here,
        # ahead of every state read below, so nothing is written to a session
        # that is about to inherit -- and by copying INTO `sess`, so the boxed
        # locals rebound at the top of this iteration stay the right boxes.
        _pkt_cid = packet_charid(data, inner, _itype, a.world_type)
        if _pkt_cid:
            adopt_session(sess, _pkt_cid, now)
            # WARNING: NOT seen_charid: that is the ladder's own belief (sec 4dv) and
            # every reply, wallet key and table lookup keys on it. This is the
            # identity the WIRE carries, used for session keying and nothing
            # else -- so a client that has only ever streamed position (its
            # charid is in +16, but no type-127 round has landed) can still be
            # re-joined to its own session after a port move.
            sess.wire_cid[0] = _pkt_cid
        # the 2026-09-05 audit 2026-09-05 (A): a NEW SESSION starts at the entrance.
        # Learn the uid there (and again at the world door), and drop every
        # per-session belief the previous player left behind -- the stale uid
        # was measured live on 09-05 (a second account served the first one's
        # uid for its first two user lists) and the same guard answered a
        # fresh container's first user list with the empty body.
        _ue = early_uid(data)
        # sec 4ea: THE GAME-SERVER LADDER. A type-130 datagram from the client
        # is a request whose u16 type sits at body[0]; the answer is type + 1
        # (GS_REQ_ANSWERS) and it is what puts [chan+2148] back to 1 so the
        # next request can go out. 47 = leaveBriefingRoom is where stage 4
        # begins: after 48 we push --gs-battle-start.
        _gs_answered = False
        # sec 4eb (live 09-11): the client's game-server requests are MODE 4
        # datagrams -- header enciphered with the third cipher instance we do
        # not hold, body PLAINTEXT. describe_inner rejects them, so the inner
        # type is unreadable; the mode byte alone names the channel.
        # sec 4fu: a mode-4 type-0x83 is a PEER POSITION, not a GS request
        # sec 4he: the P2P BATTLE LAYER (shots, damage, entity messages) is
        # addressed to us and must be RELAYED, never parsed as a GS request.
        _p2pk = p2p_battle_type(data, inner)
        _srvk = None if _p2pk is not None else p2p_server_type(data, inner)
        _srvb = bytes(inner["plain"][BODY_OFF:]) if _srvk is not None else None
        if _p2pk is None and _srvk is None:
            _srvk = p2p_server_type_mode4(data, inner)
            _srvb = bytes(data[BODY_OFF:])   # mode 4: the body is plaintext
        if _srvk is not None:
            try:
                capsule_server(seen_charid[0], _srvk, _srvb)
            except Exception:
                import traceback
                print("  [capsule] FAILED:\n%s" % traceback.format_exc(),
                      flush=True)
            _gs_answered = True     # the reliable ACK stops the 500 ms resend
        if _p2pk in P2P_SERVER_TYPES:
            try:
                capsule_p2p(sess, inner, _p2pk)
            except Exception:
                import traceback
                print("  [capsule] FAILED:\n%s" % traceback.format_exc(),
                      flush=True)
            _p2pk = None
        if _p2pk is not None and a.p2p_relay:
            try:
                relay_p2p_battle(sess, inner, _p2pk)
            except Exception:
                import traceback
                print("  [p2p] relay FAILED:\n%s" % traceback.format_exc(),
                      flush=True)
        _gs_mode4 = (len(data) >= BODY_OFF + 2 and data[1] == 4
                     and _itype != 0x83 and _p2pk is None and _srvk is None)
        if (a.gs_answer and len(data) >= BODY_OFF + 2
                and (_gs_mode4 or (_itype == GS_INNER_TYPE and inner is not None
                                   and inner["is_data"]))):
            _gmt, _gbody = gs_request_type(data, inner)
            # 2026-09-24: in a TEAM BASE battle the controller reports base HP
            # in request 24 (proto builder 0x00bc06d0: up to 4 x {u32 HP, u16
            # index, u16 0, u32 attacker mask}, count at body+61 -- retail
            # layout not re-derived). Dump it (every 5 s) until it is decoded.
            if _gmt == 24 and _gbody is not None:
                _bs24 = _base_setup(sess)
                _br24 = battle_of(seen_charid[0])
                if (_bs24 is not None and _br24 is not None
                        and seen_charid[0] == _bs24[2]):
                    try:
                        base_report_in(_br24, _bs24, base_report(_gbody),
                                       zone=_battle_zone(sess.key,
                                                         seen_charid[0]))
                    except Exception:
                        import traceback
                        print("  [base] report FAILED:" + chr(10) + "%s"
                              % traceback.format_exc(), flush=True)
            if (_gmt == 44 and _gbody is not None
                    and sess.key in _supply_bag
                    and _supply_44.get(sess.key) != sess.gs_battle_on[0]):
                # the kind-4 reply is resent (0.5/1/2 s); count one per battle
                _supply_44[sess.key] = sess.gs_battle_on[0]
                _fired = doc_shop.fired_counts(_gbody)
                _held = _supply_bag[sess.key]
                for _fi, _fn in _fired.items():
                    _held[_fi] = max(0, _held.get(_fi, 0) - _fn)
                print("  [supplies] 0x%08x fired %s this battle -> holds %s"
                      % (seen_charid[0], ", ".join("0x%08x x%d" % f for f in
                                                   sorted(_fired.items()))
                         or "nothing",
                         ", ".join("0x%08x x%d" % h for h in
                                   sorted(_held.items()))), flush=True)
            _gname = GS_REQ_NAMES.get(_gmt, "?")
            if _gmt != 1:
                # the raw datagram too: request 24's header is often enciphered
                _bcr = battle_of(seen_charid[0])
                battle_capture("gs", type=_gmt, name=_gname,
                               sender=seen_charid[0],
                               table=_bcr.key if _bcr is not None else None,
                               body=_gbody or b"", raw=data)
            # 2026-09-23: a mission's enemy HP rides the 1 Hz report in the
            # clear even when the header is not readable (mission_npc_report).
            _npcs = mission_npc_report(data)
            if _npcs:
                _rmn = battle_of(seen_charid[0])
                if _rmn is not None and _rmn.mission is not None:
                    _me24 = seen_charid[0] or (_rmn.members[0] if _rmn.members else 0)
                    _died = _rmn.npc_hp_update(_npcs, _me24, time.time())
                    if _died:
                        print("  [missions] enemy down (1 Hz report): %s -> %d "
                              "enemy kill(s) for 0x%x%s"
                              % (["0x%x" % d for d in _died], _rmn.npc_kills,
                                 _me24, "; " + _rmn.why if _rmn.over else ""),
                              flush=True)
                        _mn = _mnpc.get(sess)
                        if _mn is not None and not _rmn.over:
                            for _d in _died:
                                _mn["due"].append((time.time() + 5.0,
                                                   _mn["types"].get(_d, 0)))
                        if _rmn.over:
                            end_battle(_rmn, time.time())
            _gs_was_up = sess.gs_src[0] is not None
            sess.gs_src[0] = src     # sec 4ft: its channel is up -- pushable
            # 2026-09-23: a member whose channel comes up AFTER the others
            # picked their teams never heard about them (sync ran only on
            # someone's 31). Catch it up now.
            if (not _gs_was_up and a.gs_real_roster and seen_charid[0]):
                _uk = bt_store.table_of(seen_charid[0])
                if (_uk is not None and _uk in gs_tables
                        and len([m for m in bt_store.members(_uk) if m]) >= 2):
                    try:
                        gs_sync_table(_uk)
                    except Exception:
                        import traceback
                        print("  [roster] gs_sync_table (channel up) FAILED:\n%s"
                              % traceback.format_exc(), flush=True)
            _garg = (struct.unpack_from("<I", _gbody, 8)[0]
                     if _gbody is not None and len(_gbody) >= 12 else None)
            if _gmt == 1:
                s.sendto(build_gs_message(1, seq=next_gs_seq(sess),
                                          ident=seen_charid[0]), src)
                _gs_answered = True
                print("  GS request 1 (keepalive) -> SENT 1 (the [chan+224] "
                      "stamp)", flush=True)
                if sess.gs_rearm_pending[0]:
                    # the team-join
                    # builder sends request 31 only while [chan+204] & 0x40 is
                    # set, and ONLY message 27 sets it. Keepalives flow without
                    # it, so a lost / early 27 leaves a client that can never
                    # join a team (it sends nothing but request 1). Arm again until its first 31/33 proves it is armed.
                    # WARNING: EMPTY on purpose: message 27 is also a reward GRANT
                    # (--gs-stats), and this one repeats every 7 s
                    s.sendto(build_gs_stats([], state=a.gs_arm_state,
                                            seq=next_gs_seq(sess),
                                            ident=seen_charid[0]), src)
                    print("  SENT GAME-SERVER RE-ARM (message %d) on the "
                          "keepalive -- no team request from 0x%08x since its "
                          "38 yet" % (GS_ARM_MSG, seen_charid[0] or 0),
                          flush=True)
            elif _gmt == GS_KILL_REQ:
                # sec 4he: the VICTIM's client reports its own death. Tally,
                # then kind 9 to everyone -- the only thing that moves the
                # team points [chan+1340..] and the kill / death counters.
                _gs_answered = True
                _kr = gs_kill_report(inner, _gbody)
                _room30 = battle_of(seen_charid[0])
                _kdd = 1.0
                if (_kr is None and _room30 is not None
                        and _room30.mission is not None
                        and _gbody is not None and len(_gbody) >= 12):
                    # 2026-09-23: header unreadable (per-boot game-server key),
                    # but the KILLER at body+8 is plaintext. In a mission an
                    # NPC killer means the player died; the player's own kills
                    # arrive through the 1 Hz report instead. The client
                    # resends an unacknowledged report, so dedupe over 5 s.
                    _kkil = struct.unpack_from("<I", _gbody, 8)[0]
                    if _kkil and _kkil not in _room30.kills and seen_charid[0]:
                        _kr, _kdd = (_kkil, seen_charid[0]), 10.0
                if (_kr is None and not (_gbody is not None and len(_gbody) >= 12
                        and struct.unpack_from("<I", _gbody, 8)[0]
                        == (seen_charid[0] or -1))):
                    # the fallback was skipped with the room
                    # open -- say exactly which condition failed.
                    print("  GS request 30 fallback skipped: me=0x%x room=%s "
                          "mission=%s body=%s kills=%s"
                          % (seen_charid[0] or 0,
                             None if _room30 is None else _room30.key,
                             None if _room30 is None else _room30.mission,
                             _gbody.hex() if _gbody else None,
                             None if _room30 is None else
                             ["0x%x" % k for k in _room30.kills]), flush=True)
                if _kr is None or _room30 is None:
                    print("  GS request 30 (KILL REPORT) %s -- %s"
                          % ("0x%x killed 0x%x" % _kr if _kr else "unreadable",
                             "no room for 0x%08x" % (seen_charid[0] or 0)
                             if _kr else "dropped"), flush=True)
                else:
                    _was_over30 = _room30.over
                    _kf = _room30.kill(_kr[0], _kr[1], time.time(), dedupe_s=_kdd)
                    if _kf is None:
                        print("  GS request 30 (KILL REPORT) 0x%x killed 0x%x -- "
                              "duplicate / not a member, ignored" % _kr,
                              flush=True)
                        # 2026-09-26: a MISSION enemy kill (victim not a
                        # member) returns None but can complete a "kill"
                        # objective -- the room was marked over and never
                        # ended (found by doc_launch_e2e's exam clear)
                        if _room30.over and not _was_over30:
                            end_battle(_room30, time.time())
                    else:
                        push_kill_event(_room30, _kf)
                        if (a.respawn_kind and not _room30.over
                                and _kr[1] in _room30.dead_until):
                            push_down(_room30, _kr[1])
                        print("  GS request 30 (KILL REPORT) 0x%x killed 0x%x -> "
                              "SENT notify 9 to %d member(s): points %s%s%s"
                              % (_kr[0], _kr[1], len(_room30.present()),
                                 _kf[0], " (one from the target)" if _kf[3]
                                 else "", "; " + _room30.why if _room30.over
                                 else ""), flush=True)
                        if _room30.over:
                            end_battle(_room30, time.time())
            elif _gmt == GS_REVIVE_REQ:
                # RETRACTED 2026-09-23: request 43 is NOT a Phoenix Down. Its
                # only builder caller is 0x00bc9be8, called first thing by the
                # kind-9 arm 0x00bc9e70: every client ACKS every kill notice
                # with it. Answering it with a revive gave every death an
                # instant "Phoenix Down" (live: revived with the Phoenix Down
                # animation without using one). The message table 0x00bf0070
                # has no handler for 44, so nothing is sent.
                _gs_answered = True
                print("  GS request 43 (ack of the kill notice) from 0x%x -- "
                      "no answer" % (seen_charid[0] or 0), flush=True)
            elif _gmt == GS_ITEM_USE_REQ and a.item_use_answer != "off":
                # a Potion in battle sent request 21 and the
                # client kept resending it. Request 21 = {u16 21, u16 session,
                # u32 0, u32 ITEM} (builder 0x00bc53f0, arena state); there is
                # no target -- an item is used on oneself.
                # 2026-09-26 (doc_items, emulated): message 22 IS THE EFFECT.
                # Its arm stores body+8 for the unit named by the ident (self
                # or a teammate record) and the next tick runs "receiveUseItem"
                # -> the item's effect script: Potion 301 HEAL 150 -> the
                # client's own R+44 (lasts, no push needed); Ether 334 MP +50
                # on the LOCAL chara only (R+48 overwrites it every frame), so
                # the server pushes kind 44. The CLIENT took the item out of
                # its bag when it sent the request (0x00be6c08), so every NEW
                # use is answered -- live, three uses (seqs 3147,
                # 3151, 3152 in 0.3 s) got ONE answer under the old 10 s
                # window. A resend = the same transport seq, or (header
                # unreadable) the same item on the reliable resend schedule.
                _gs_answered = True
                _itm = (struct.unpack_from("<I", _gbody, 8)[0]
                        if _gbody is not None and len(_gbody) >= 12 else 0)
                _me21 = seen_charid[0] or 0
                _now21 = time.time()
                _seq21 = (inner.get("seq") if inner is not None
                          and inner.get("is_data") else None)
                _new21, _why21 = _item_uses.use(_me21, _itm, _now21, seq=_seq21)
                if not _new21:
                    print("  GS request 21 (USE ITEM 0x%08x) from 0x%08x: %s -- "
                          "answered already" % (_itm, _me21, _why21), flush=True)
                else:
                    _room21 = battle_of(_me21) if _me21 else None
                    _to21 = [_me21]
                    if _room21 is not None and a.item_use_broadcast == "on":
                        _to21 += [m for m in _room21.present() if m != _me21]
                    _sent21 = 0
                    for _m21 in _to21:
                        if _m21 == _me21:
                            _ms21, _dst21 = sess, src
                        else:
                            _ms21, _dst21 = member_dst(_m21)
                        if _dst21 is None:
                            continue
                        s.sendto(build_item_use_answer(
                            _itm, seq=next_gs_seq(_ms21), ident=_me21), _dst21)
                        _sent21 += 1
                    _bag21 = ""
                    if sess.key in _supply_bag and _itm in _supply_bag[sess.key]:
                        _h21 = _supply_bag[sess.key]
                        _h21[_itm] = max(0, _h21[_itm] - 1)
                        _bag21 = "; supplies 0x%08x -> x%d" % (_itm, _h21[_itm])
                    print("  GS request 21 (USE ITEM 0x%08x) from 0x%08x (%s) -> "
                          "SENT message 22 {ident = 0x%08x, body+8 = item} to %d "
                          "member(s)%s%s"
                          % (_itm, _me21, _why21, _me21, _sent21,
                             " (HP +%d on the client)" % doc_items.ITEM_HP[_itm]
                             if _itm in doc_items.ITEM_HP else "", _bag21),
                          flush=True)
                    if (_itm in doc_items.ITEM_MP and a.mp_model == "ledger"
                            and _me21):
                        _bk21, _rs21 = _mp_battle(_room21)
                        push_mp(_me21, _magic.credit(
                            _me21, _bk21, doc_items.ITEM_MP[_itm], _rs21),
                            "item 0x%08x +%d" % (_itm, doc_items.ITEM_MP[_itm]))
            elif _gmt == GS_MAGIC_REQ and a.mp_model != "zero":
                # one Fire cast = request 60 arg
                # 0x10001, resent at +0.6/+1.6/+3.6/+7.6 s, each answered with
                # the ZERO 61 -> MP 0 for the rest of the battle ("cast once,
                # then couldn't"). build_magic_answer has the client side;
                # doc_magic.Ledger prices the cast (element / level from the
                # arg, Magic Suit x0.6) and charges each cast ONCE -- a
                # same-spell copy on the resend schedule is answered with the
                # same MP. Every copy is answered: a lost 61 would otherwise
                # leave the client's request slot outstanding.
                _gs_answered = True
                _mcid = seen_charid[0] or 0
                _mroom = battle_of(_mcid) if _mcid else None
                _mnote = "full MP"
                _mmp = doc_magic.MP_MAX
                if a.mp_model == "ledger":
                    _mbk = ((_mroom.key, _mroom.opened) if _mroom is not None
                            else ("no room",))
                    _mres = (_mroom is not None and doc_magic.magic_restricted(
                        _mroom.rules.flags, _mroom.rules.restrictions))
                    _mmp, _mcost, _mnote = _magic.cast(
                        _mcid, _mbk, _garg or 0, time.time(),
                        suit=getattr(sess, "suit_item", None), restricted=_mres)
                s.sendto(build_magic_answer(_mmp, seq=next_gs_seq(sess),
                                            ident=_mcid), src)
                print("  GS request 60 (MAGIC CAST, element %d level %d) from "
                      "0x%x -> SENT 61 {status 0, MP %d} -- %s"
                      % ((_garg or 0) & 0xFFFF, ((_garg or 0) >> 16) & 0xFFFF,
                         _mcid, _mmp, _mnote), flush=True)
                if (_garg or 0) & 0xFFFF == 4:
                    # 2026-09-26 (doc_mp_heal_proof, emulated): a Cure's HEAL
                    # is the caster's type-113 entry with NEGATIVE damage,
                    # which we relay; the healed client applies it to its own
                    # R+44 (0x00be99d8 -> 0x00bdf7f0), the HP store itself,
                    # and the caster applies its own entries locally. Nothing
                    # to push.
                    print("  [magic] Cure/Bind: the heal rides the caster's "
                          "113 (relayed); each target applies it to its own "
                          "HP", flush=True)
            elif _gmt in GS_REQ_ANSWERS:
                _gans = GS_REQ_ANSWERS[_gmt]
                if _gans == 57:
                    _gp = build_gs_team_list(
                        [(0, 0, seen_charid[0])], seq=next_gs_seq(sess),
                        ident=seen_charid[0])
                else:
                    _gp = build_gs_message(_gans, seq=next_gs_seq(sess),
                                           ident=seen_charid[0])
                s.sendto(_gp, src)
                _gs_answered = True
                print("  GS request %d (%s, arg %s) -> SENT %d  [the stub sets "
                      "[chan+2148] = 1 again]"
                      % (_gmt, _gname, "0x%x" % _garg if _garg is not None else "-",
                         _gans), flush=True)
                # sec 4fn (live 2026-09-12): the briefing room re-sends
                # request 31 every 1-4 s (22:04:24.4, :25.4, :27.4, :31.4 ...),
                # so pushing the bots on EVERY 31 churned the team space and
                # the join timer below never fired. Push once per 38.
                # sec 4ft: a table with 2+ REAL seated members gets the real
                # roster (gs_sync_table below) instead of bots.
                if _gmt in (31, 33):
                    sess.gs_rearm_pending[0] = False   # it is armed
                _real_key = None
                if _gmt in (31, 33) and a.gs_real_roster and seen_charid[0]:
                    _tk31 = bt_store.table_of(seen_charid[0])
                    _mem31 = ([m for m in bt_store.members(_tk31) if m]
                              if _tk31 is not None else [])
                    if seen_charid[0] in _mem31 and len(_mem31) >= 2:
                        _real_key = _tk31
                if (_gmt == 31 and _real_key is None
                        and (a.gs_fake_teammates > 0 or a.gs_team_notify)
                        and not gs_bots_sent[0]):
                    gs_bots_sent[0] = True
                    # sec 4ek: the player got the "battle ready, hit OK" prompt
                    # only when the DISTRIBUTION (kind 20, facade 0x1000) fired --
                    # but with a 1-member team it bounced to ID_NO_USE -> title.
                    # Now: populate BOTH teams with bots (kind 31, slot=0, one
                    # clean team each, no count churn), THEN finalize over that
                    # full both-teams roster. A valid roster is the natural
                    # reason the client would proceed into the battle instead of
                    # the "cannot proceed" window.
                    _team = (_garg or 0) & 0xFF
                    gs_teams[seen_charid[0]] = _team
                    _roster = [(seen_charid[0], _team)]
                    _mq = _mission_battle.get(sess.key)
                    if _mq is not None:
                        print("  [quest] MISSION battle (quest %d): no fake "
                              "teammates -- the player is seated alone; arena "
                              "zone %d" % (_mq, _battle_zone(sess.key,
                                                            seen_charid[0])),
                              flush=True)
                    if a.gs_fake_teammates > 0 and _mq is None:
                        for _t in (0, 1):
                            for _k in range(1, a.gs_fake_teammates + 1):
                                _bot = (a.gs_fake_team_base + _t * 0x100 + _k) \
                                    & 0xFFFFFFFF
                                if _bot == seen_charid[0]:
                                    continue
                                gs_teams[_bot] = _t
                                s.sendto(build_gs_add_chara(
                                    _bot, _t, slot=0, seq=next_gs_seq(sess),
                                    self_ident=seen_charid[0]), src)
                                _roster.append((_bot, _t))
                        print("  SENT %d FAKE TEAMMATE(s) PER TEAM (notify 31) -- "
                              "both teams populated, %d total incl. self (sec 4ek)"
                              % (a.gs_fake_teammates, len(_roster)), flush=True)
                    if a.gs_team_notify:
                        _dist = [(cid, tm, i)
                                 for i, (cid, tm) in enumerate(_roster)]
                        s.sendto(build_gs_distribution(
                            _dist, seq=next_gs_seq(sess), ident=seen_charid[0]), src)
                        print("  SENT notify 20 (PLAYER DISTRIBUTION, FINALIZE) "
                              "over a %d-member both-teams roster -- posts facade "
                              "0x1000. Watch: does the client ENTER THE ARENA now, "
                              "or still ID_NO_USE -> title? (sec 4ek)"
                              % len(_roster), flush=True)
                if (_real_key is None and _gmt in (31, 33) and seen_charid[0]
                        and a.gs_real_roster):
                    # a SOLO table never reaches gs_sync_table, so its player got
                    # a bare 32 and the Ready row stayed 0 until the kind-20
                    # distribution. Kind 0 to itself is the +1;
                    # kind 1 takes it back off on 33. The client
                    # re-sends 31 every 0.5-4 s; a repeat Set Team to the same
                    # team is dec+inc = no change.
                    _me = seen_charid[0]
                    _st = (_garg or 0) & 0xFF if _gmt == 31 else GS_TEAM_NONE
                    if _st < GS_TEAM_NONE:
                        s.sendto(build_gs_team_set(_me, _st, seq=next_gs_seq(sess)),
                                 src)
                        print("  [roster] solo: SENT notify 0 (set team) 0x%08x "
                              "-> team %d to ITSELF" % (_me, _st), flush=True)
                    else:
                        s.sendto(build_gs_team_leave(_me, seq=next_gs_seq(sess)),
                                 src)
                        print("  [roster] solo: SENT notify 1 (leave team) "
                              "0x%08x to ITSELF" % _me, flush=True)
                if _real_key is not None:
                    _g31 = gs_table_state(_real_key)
                    # request 33 = leaveTeam (the player stepped OFF a space)
                    _t31 = (_garg or 0) & 0xFF if _gmt == 31 else GS_TEAM_NONE
                    _me = seen_charid[0]
                    if _t31 < GS_TEAM_NONE:
                        if _g31["teams"].get(_me) != _t31:
                            print("  [roster] 0x%08x is on team %d at table %d "
                                  "(%d seated, real roster, sec 4ft)"
                                  % (_me, _t31, _real_key,
                                     len(bt_store.members(_real_key))),
                                  flush=True)
                        _g31["teams"][_me] = _t31
                    elif _g31["teams"].pop(_me, None) is not None:
                        print("  [roster] 0x%08x left its team (arg 0x%x) at "
                              "table %d" % (_me, _t31, _real_key), flush=True)
                    try:
                        gs_sync_table(_real_key)
                    except Exception:   # a shared-table bug must not take
                        import traceback  # docudp down for BOTH clients
                        print("  [roster] gs_sync_table FAILED:\n%s"
                              % traceback.format_exc(), flush=True)
                if _gmt == 31 and a.gs_battle_after_join > 0:
                    gs_join_src[0] = src
                    if not gs_join_deadline[0]:
                        # sec 4fn: arm ONCE per 38 -- the repeated 31s used to
                        # push the deadline out forever.
                        gs_join_deadline[0] = time.time() + a.gs_battle_after_join
                        print("  [gs] battle start armed for %.0f s after this "
                              "join (arm-once, sec 4fn)"
                              % a.gs_battle_after_join, flush=True)
                    else:
                        print("  [gs] repeat join -- battle start already armed, "
                              "%.0f s left"
                              % max(0.0, gs_join_deadline[0] - time.time()),
                              flush=True)
                if (_gmt == GS_LEAVE_BRIEFING and a.gs_battle_start
                        and sess.gs_battle_on[0]):
                    # sec 4fy (live 09-13): the client RETRANSMITS 47 (0.5/1/2/4
                    # s) and every copy re-pushed the whole start burst. The
                    # copies get their 48 (above) and nothing else.
                    print("  [battle] request 47 again -- 48 only, this battle "
                          "already started (sec 4fy)", flush=True)
                elif _gmt == GS_LEAVE_BRIEFING and a.gs_battle_start:
                    sess.gs_battle_on[0] = time.time()
                    issue_supplies(sess, src)
                    if a.gs_battle_go:
                        sess.gs_battle_go[0] = time.time() + a.gs_battle_go_after
                    _room47 = battle_of(seen_charid[0])
                    if _room47 is not None:
                        # sec 4he: the ROOM owns the end, and (2026-09-26) the
                        # START: every member that lands its 47 in time gets ONE
                        # shared GO, and the room clock starts at that GO -- the
                        # moment each client starts its own HUD clock.
                        _gafter = a.gs_battle_go_after if a.gs_battle_go else 0.0
                        _tnow = time.time()
                        _shared = (_gafter > 0
                                   and (_room47.started is None
                                        or _room47.joins_go(_tnow, _gafter)))
                        _room_member_key[seen_charid[0]] = _wallet_key(
                            seen_uid[0], seen_charid[0], sess)
                        _first47 = _room47.arrive(seen_charid[0], _tnow,
                                                  go_after=_gafter,
                                                  go_wait=a.battle_go_wait)
                        if _shared:
                            for _gm in _room47.arrived:
                                _gms, _ = member_dst(_gm)
                                if _gms is not None and _gms.gs_battle_go[0]:
                                    _gms.gs_battle_go[0] = _room47.go_at
                            sess.gs_battle_go[0] = _room47.go_at
                            print("  [battle] table %d: 0x%08x rides the room's "
                                  "shared GO in %.1f s (%d arrived)"
                                  % (_room47.key, seen_charid[0],
                                     _room47.go_at - _tnow,
                                     len(_room47.arrived)), flush=True)
                        elif _gafter > 0:
                            print("  [battle] table %d: 0x%08x arrived after the "
                                  "room's GO window -- its own GO in %.0f s"
                                  % (_room47.key, seen_charid[0], _gafter),
                                  flush=True)
                        if _first47:
                            print("  [battle] table %d clock %s by 0x%08x: "
                                  "%s, kill target %d, KO limit %d, %d member(s) "
                                  "(sec 4he)"
                                  % (_room47.key,
                                     "ARMED (starts at the shared GO)"
                                     if _shared else "STARTED", seen_charid[0],
                                     ("%.0f s (the table's Time Limit)"
                                      % _room47.rules.time_limit)
                                     if _room47.rules.time_limit else
                                     "no time limit (the target ends it)",
                                     _room47.rules.kill_target,
                                     _room47.rules.ko_limit,
                                     len(_room47.members)), flush=True)
                        else:
                            print("  [battle] 0x%08x ARRIVED in table %d's room "
                                  "(%s)"
                                  % (seen_charid[0], _room47.key,
                                     ("%.0f s left" % max(0.0, _room47.end_at
                                                         - time.time()))
                                     if _room47.end_at else
                                     "clock not started yet" if _room47.go_at
                                     else "no time limit"), flush=True)
                    elif a.gs_battle_length > 0:
                        sess.gs_battle_end[0] = time.time() + a.gs_battle_length
                        print("  [battle] started (no room) -- the result (kind 4) "
                              "goes out in %.0f s, then selector 39 (sec 4fy)"
                              % a.gs_battle_length, flush=True)
                    _bpos = _battle_pos(sess.key, seen_charid[0])
                    _bzone, _bnote = _battle_zone_note(sess.key,
                                                       seen_charid[0])
                    if _bnote:
                        print("  [arena] " + _bnote, flush=True)
                    for _k, _np in gs_battle_sequence(
                            a.gs_battle_start, spawn=_bpos,
                            seq_fn=lambda: next_gs_seq(sess), ident=seen_charid[0],
                            zone=_bzone,
                            bmap=battle_bmap(_bzone, _zone_pieces, _gs_bmap)):
                        s.sendto(_np, src)
                        time.sleep(0.05)
                        print("  SENT notify kind %d (%s) -- message %d, %d "
                              "bytes. STAGE 4: watch the emulog for "
                              "KEL_NET_GAMESERVER_NOTIFY_* and a zone load"
                              % (_k, GS_NOTIFY_NAMES.get(_k, "?"),
                                 GS_NOTIFY_MSG, len(_np)), flush=True)
                    _send_base_objects(sess, src, "with the spawn (request 47)")
            elif _gmt is not None:
                print("  GS request %d (%s, arg %s) -- no answer defined; "
                      "fire-and-forget or unread"
                      % (_gmt, _gname,
                         "0x%x" % _garg if _garg is not None else "-"),
                      flush=True)
        if _ue and _ue != seen_uid[0]:
            print("  [uid] client's own user id = 0x%08x (from the %s, was 0x%08x) "
                  "-- per-session state reset"
                  % (_ue, "entrance" if len(data) == 80 else "world door",
                     seen_uid[0]), flush=True)
            # sec 4he: a new sign-in under this session leaves whatever
            # table its previous character was seated at.
            vacate_seat(seen_charid[0], "new entrance")
            seen_uid[0] = _ue
            last_pose[0] = None
            last_stream[0] = 0.0
            gs_done[0] = False
            # sec 4ft: a new entrance follows a new POL sign-in, which may be a
            # different member at this address -- resolve the key again.
            sess.account_key = None
            refresh_roster(_ue)
            # sec 4fu: its peer table and remote units went with it -- re-push
            for _o in sessions.values():
                _o.relay_pushed.pop(seen_charid[0], None)
                _o.relay_wu.pop(seen_charid[0], None)
            sess.relay_pushed.clear()
            sess.relay_wu.clear()
        # Learn the player's own uid off the in-game position stream (sec 4bx).
        _u = ingame_uid(data, inner)
        if _u:
            # The in-game stream is also the ONLY thing that keeps PCSX2's UDP
            # mapping open from the guest side, so its timestamp is what decides
            # whether ACKing is safe (sec 4bx).
            last_stream[0] = datetime.datetime.now().timestamp()
            _pose = ingame_pose(data, inner)
            if _pose is not None:
                last_pose[0] = _pose[1:]
                # 2026-09-26: the pose TEAM BASE occupation reads
                _pk = seen_charid[0] or _pose[0]
                if _pk:
                    _battle_pose[_pk] = (_pose[1], _pose[2], _pose[3],
                                         last_stream[0])
                if a.peer_relay != "off":
                    relay_peer_pose(sess, inner, _pose)
            # KEY: sec 4de: THE WORLD HAS NEVER HAD ANYTHING IN IT. Nothing has ever
            # sent a type-125, so every session has been a lobby containing exactly
            # one entity -- which is what "waiting for teams to fill up" looks like
            # from the inside. Put one peer in it, standing next to the player.
            # WARNING: The client will NOT know this id and will print `Cache miss` and
            # ask selector 36 (sec 4bw). That is the designed pull, not a fault --
            # --peer-answer answers it.
            if a.world_update_ms > 0 and last_pose[0] is not None:
                _nowt = datetime.datetime.now().timestamp()
                if (_nowt - last_wu[0]) * 1000.0 >= a.world_update_ms:
                    last_wu[0] = _nowt
                    _x, _y, _z, _dx, _dy, _dz = last_pose[0]
                    # sec 4df: --world-update-id=0 means the CLIENT ITSELF, and
                    # --world-update-abs an absolute position instead of an offset
                    # from wherever it currently is. Together they ask the one
                    # question left: the client spawns at the ORIGIN, ~1900 units
                    # from the level, with no floor under it -- so it cannot move.
                    # Nothing we send has ever told it where to stand. Does a
                    # type-125 naming its OWN uid at a real position move it?
                    _wid = a.world_update_id or seen_uid[0]
                    if a.world_update_abs:
                        _ax, _ay, _az = [float(t) for t in
                                         a.world_update_abs.replace(",", " ").split()]
                    else:
                        _ax, _ay, _az = _x + a.world_update_offset, _y, _z
                    wu = build_world_update([dict(
                        id=_wid, x=_ax, y=_ay, z=_az,
                        dx=_dx, dy=_dy, dz=_dz)],
                        seq=a.lobby_seq)
                    s.sendto(wu, src)
                    print("  SENT type-125 WORLD UPDATE: entity 0x%08x at "
                          "(%.1f, %.1f, %.1f)%s"
                          % (_wid, _ax, _ay, _az,
                             "  [SELF -- trying to place the player]"
                             if _wid == seen_uid[0] else ""), flush=True)
            # KEY: sec 4cd: the in-game stream is the first solid proof the client is
            # in world, so it is the right moment to open the GAME SERVER channel.
            # Both selectors are UNGATED (doc_armmap.py), which is what makes this
            # possible at all -- selector 21, the endpoint writer sec 4bs found,
            # needs [kelsvc+12] == 8 and can never run in world. Selector 104
            # reaches the SAME writer 0x00bca938 with no gate.
            if a.gs_connect and not gs_done[0]:
                gs_done[0] = True
                _ep = host_for(a.gs_connect_ip or a.lobby_ip, src[0])
                # KEY: sec 4df: THESE TWO ARE DIFFERENT THINGS AND WERE WELDED
                # TOGETHER. 104 writes the game-server ENDPOINT -- that is what
                # the item/stat manager needs, and without it the HP bar and item
                # count render garbage (sec 4cd) and the avatar does not appear to
                # be controllable. 38 sets the READY FLAG, i.e. "your match server
                # is up", and sec 4cd records that enabling this pair is exactly
                # what first put the account holder in the briefing room, with the
                # team-assignment prompt, on every world entry.
                #
                # So the pair traded one fault for the other: WITH it, a working
                # character in the wrong room; WITHOUT it, the right area and a
                # character that will not move. --gs-connect-selectors=104 asks
                # the question neither setting could: does the endpoint alone give
                # a working avatar without claiming a match is ready?
                _gs_sels = [int(t, 0) for t in
                            a.gs_connect_selectors.replace(",", " ").split()]
                for _sel in _gs_sels:
                    if _sel == GS_ENDPOINT_SELECTOR:
                        # sec 4gv: ONE builder for every 104 this server sends,
                        # so the world-entry declaration and the Start
                        # re-declaration cannot drift apart.
                        send_gs_endpoint(src, seen_charid[0], req=data,
                                         why="world entry")
                        continue
                    _g = build_world_answer(
                        data, selector=_sel, seq=a.lobby_seq,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7),
                        inner_ip=None, ptype=a.world_type, pad_to=a.world_pad,
                        # WARNING:KEY: sec 4dv: NOT 0 -- record+4. Selector 104's arm
                        # 0x00bcd248 OPENS with
                        #     lw v1, 4(s2); lw v0, 272(s1); bne v1, v0, <drop>
                        # so the endpoint message is dropped without a word
                        # unless record+4 equals [kelsvc+272]. Hardcoding 0 was
                        # correct only for as long as [kelsvc+272] was 0, which
                        # is to say only until the roster carried a real
                        # character id -- at which point the game-server channel
                        # would have gone quiet again and looked like a
                        # regression in something else entirely.
                        ident=seen_charid[0])
                    if _g is not None:
                        s.sendto(_g, src)
                print("  SENT GAME-SERVER CONNECT: selectors %s (104 = endpoint "
                      "%s:%d, id %d -> [kelsvc+268]; 38 = the READY flag, which is "
                      "what sends the client to the briefing room -- sec 4cd/4df)"
                      % (",".join(str(x) for x in _gs_sels), _ep,
                         a.gs_connect_port, a.gs_connect_id), flush=True)
                # sec 4cq: ARM the channel. Message 27 with a body of at
                # least 13 bytes is the only thing in the binary that sets
                # [chan+204] bit 6, and without that bit the last-heard stamp
                # CER-48101's 40 s timeout reads is never refreshed.
                if a.gs_keepalive_ms > 0:
                    _st = []
                    for _pair in a.gs_stats.replace(" ", "").split(","):
                        if not _pair:
                            continue
                        _k, _, _v = _pair.partition(":")
                        _st.append((int(_k, 0), int(_v, 0)))
                    s.sendto(build_gs_stats(_st, state=a.gs_arm_state,
                                            seq=next_gs_seq(sess)), src)
                    gs_ka_src[0] = src
                    gs_ka_next[0] = time.time() + a.gs_keepalive_ms / 1000.0
                    print("  SENT GAME-SERVER ARM: message %d, COUNT=%d "
                          "STATE=%d%s -> [chan+204] |= 0x40 -- sec 4cq"
                          % (GS_ARM_MSG, min(len(_st), 6), a.gs_arm_state,
                             ("  " + " ".join("%d:%d" % t for t in _st[:6]))
                             if _st else ""), flush=True)
                _mts = [int(x) for x in a.gs_msg.replace(" ", "").split(",")
                        if x] if a.gs_msg else []
                for _mt in _mts:
                    if not 1 <= _mt <= GS_MSG_MAX:
                        print("  gs-msg %d out of range 1..%d, skipped"
                              % (_mt, GS_MSG_MAX), flush=True)
                        continue
                    s.sendto(build_gs_message(_mt, seq=next_gs_seq(sess)), src)
                    print("  SENT GAME-SERVER MESSAGE type %d (inner 130, body[0]"
                          " = the type, body zeros) -- sec 4cq" % _mt, flush=True)
            # sec 4gs addendum 3: the lobby NPCs (doc_npc_spawn.py), off by default.
            if a.npc_spawn == "on":
                push_lobby_npcs(sess, src)
        # sec 4dr FIX (2026-09-11): a CHARAID must never be taken as the account
        # uid. The comment below ("the 64-byte stream carries only the account
        # uid") is REFUTED live: with --world-self-charaid the self-record id
        # ([kelsvc+272]) IS the charaid, so the client also streams its position
        # keyed by the charaid -- doc-rx holds 64-byte type-0x83 packets with
        # body[0] = 0x0002aa68 (Lex's id) mixed in with the real 0xa756a69a stream.
        # ingame_uid read that charaid as the account uid, seen_uid flipped to
        # 0x0002aa68, refresh_roster(0x0002aa68) rebuilt an EMPTY roster, and BOTH
        # the name plate and the auto-costume lookup (which key on seen_uid) came
        # back empty -- the avatar fell to the default look and the name went
        # blank. Reject any _u we have served as a character id, or that equals
        # the selected charaid [kelsvc+272].
        _u_is_charid = bool(_u) and (_u in sess.chara_ids.values()
                                     or _u == (seen_charid[0] & 0x3FFFFFFF))
        if _u and not _u_is_charid and _u != seen_uid[0]:
            seen_uid[0] = _u
            print("  [uid] client's own user id = 0x%08x (from its type-0x83)"
                  % _u, flush=True)
        # sec 4dr follow-up (2026-09-10): the per-account roster is otherwise
        # loaded into chara_kw ONLY on a fresh 80/132-byte entrance (early_uid).
        # This box recreates the `doc` container every few minutes (stale-check),
        # so a client that reconnects and resumes on the in-game type-0x83 stream
        # WITHOUT sending a new entrance is served the process's initial 4-empty
        # roster -- an existing account's characters vanish until a full back-out
        # and re-enter.  The in-game account uid rides the 64-byte stream too
        # (0xa455a599 / 0xa756a69a); refresh_roster keys the store by that uid,
        # so (re)loading here is safe and idempotent.  Guarded on _roster_uid so a
        # session whose entrance already loaded the roster does not refresh every
        # position packet -- and on _u_is_charid so the charaid stream (see above)
        # never rebuilds the roster against an empty account.
        if (_store is not None and _u and not _u_is_charid
                and sess.roster_uid[0] != _u):
            refresh_roster(_u)

        # KEY: sec 4dv: THE LENGTH GATE WAS DROPPING A WHOLE RUNG.  `>= BODY_OFF
        # + 16` (40 bytes) is right for every rung that carries an argument, and
        # WRONG for the ones that carry none: selector 22 -- the server handoff
        # phase 42 sends and phase 43 blocks on -- is a 36-byte datagram with a
        # 12-byte body, and it arrived SEVEN times in the 09-05 reserve corpus
        # and was answered zero times.  Nothing cleared bit 31 of [kelsvc+28],
        # so the client's own 10 s deadline (0x00589af0) expired and painted
        # CER-47117 at phase 43 -- the reservation stall, exactly.
        # WARNING: The other 36-byte type-7 traffic is the selector-5 driver poll (2099
        # of them in that corpus).  5 + 1 = 6 is a DRIVER arm whose whole job is
        # to move [kelsvc+12], so answering it is the sec 4bz self-harm again.
        # Hence an explicit ALLOWLIST rather than a lower bound.
        _short = len(data) < BODY_OFF + 16
        _short_ok = (_short and len(data) >= BODY_OFF + 12
                     and data[1] != 1 and len(data) > BODY_OFF + 1
                     and (data[BODY_OFF + 1] in short_ladder
                          # sec 4gk: trade CONFIRM 47 / CANCEL 49 are 36-byte
                          or (_trade is not None
                              and data[BODY_OFF + 1] in doc_trade.SHORT_REQS)))
        if (a.world_answer and (not _short or _short_ok)
                and _itype == a.world_type
                # Seen live (CER-48102): a MODE-4 (game-server) datagram
                # whose header did not decrypt has no trustworthy type -- a
                # 136-byte 1 Hz NPC report read as 0x7f, was answered as lobby
                # "selector 73", and its garbage ident became the session's
                # character id. Game-server traffic never takes this path.
                and not (len(data) > 1 and data[1] == 4 and inner is None)
                and (a.world_len <= 0 or len(data) == a.world_len)):
            # KEY: THE ANSWER SELECTOR IS THE REQUEST'S SELECTOR + 1 (sec 4bs).
            # The driver 0x005895b0 RETURNS body[1] and the demux 0x00bcc718
            # dispatches on it through a 252-entry jump table at 0x00bf3230
            # (index = selector - 4).  The client's own outgoing header builder
            # 0x00bdb190 writes the selector at body[1], so every round names its
            # own answer:
            #   phase 27  request sel 1  -> answer 2   driver arm, state 1 -> 2
            #   phase 29  request sel 12 -> answer 13  0x00bca868: state = 2 AND
            #                                         [kelsvc+1064] = body[12..15];
            #                                         this is what releases phase 30
            #   phase 31  request sel 3  -> answer 4   0x00bc8ee0, the disconnect
            #                                         phase 32 waits for (state 0)
            # Selector 2 was NOT wrong for phase 27 and IS wrong for everything
            # after it -- three sessions of selector sweeps at phase 30 failed
            # because 2/4/5/6 are the DRIVER's arms and 13 is a TABLE arm.
            #
            # Read the selector out of the DECRYPTED body when we have it: mode 1
            # enciphers 32 bytes from offset 8, i.e. body[0..15] (sec 4bj), and
            # doc_kelcrypt.header hands back the whole plaintext packet, so even
            # phase 27's `07 01 ...` is readable.
            # WARNING: FALL BACK TO THE RAW BYTE FOR EVERY MODE BUT 1, exactly as the
            # pre-4bs code did.  header() returns None whenever the cipher blob is
            # missing (log-only builds) or the self-check fails, and phase 29 is
            # MODE 2 with a plaintext body -- so requiring the decrypt here would
            # silently drop phase 29 back to selector 2, which is the failure this
            # whole change exists to fix, and it would look like nothing happened.
            _plain = inner["plain"] if inner is not None else None
            _req_sel, _ident = world_reply_fields(data, inner)
            # KEY: sec 4dv: record+4 IS [kelsvc+272]. 0x00bdb190 stamps it into
            # every outgoing message, so the client tells us its own character
            # id on every request -- no probe needed. Learn it and stop guessing
            # 0 downstream.
            if _ident:
                if _ident != seen_charid[0]:
                    print("  [charid] the client's own [kelsvc+272] = 0x%08x "
                          "(record+4) -- getMyCharaId() now answers, sec 4dv"
                          % _ident, flush=True)
                seen_charid[0] = _ident
                # register the NAME now, not at the first
                # user-list request. The relay's peer records read `players`,
                # and until that request they went out as "Player_41050" --
                # which the other client keeps for good (first sight wins).
                _known = players.get(_ident, {}).get("name") or ""
                if not _known or _known.startswith("Player_"):
                    _pn = _player_name()
                    if _pn:
                        players[_ident] = {"name": _pn, "uid": seen_uid[0],
                                           "look": _player_look(sess)}
            _unpairable = False
            if a.world_selector_pair and _req_sel is not None and 0 < _req_sel < 255:
                _sel = _req_sel + 1
            elif _req_sel in (None, 1):
                _sel = a.world_selector
            else:
                # WARNING: THE 255 TRAP (sec 4bz). The pairing bound is `< 255`, so a
                # selector-255 request falls through to --world-selector-next,
                # which DEFAULTS TO 2 -- and selector 2 is a DRIVER arm
                # (0x00589660 -> 0x00bc8aa0 -> 0x005894f0) whose whole job is to
                # set [kelsvc+12] = 2.  So every unpairable notification we
                # "answered" was silently RESETTING THE CONNECTION STATE.  If the
                # client was sitting in state 7 waiting for its user list, that
                # knocks it out of the only state selector 11's arm will run in,
                # its pending request can never be cleared, and 10 s later it
                # paints CER-47117 (sec 4by).  The client sent selector 255 four
                # times on 08-27 and we did this four times.
                #
                # 255 cannot pair anyway: 255+1 = 256 is past the end of the
                # 252-entry table.  So the honest answer is NO answer -- the
                # datagram still gets its reliable ACK, which is what it is owed.
                _unpairable = True
                _sel = a.world_selector_next
            # Arms that read `[record+4]` compare it with `[kelsvc+272]` and drop
            # the message without a word on a mismatch, so echo it.  WARNING: sec 4bw
            # measured that this is PER-ARM, not a shared gate: 0x00bcaa70
            # (selector 37) never looks at it and inserts regardless.  Echoing
            # stays right; "every arm gates" was too strong.  The selector-2 rung
            # keeps the lobby-IP value it was proven live with; that arm is in
            # the driver and never reads the field.
            if _sel == 2:
                _ident = None
            # KEY: sec 4ce: RE-ARM the game-server connect. Selector 1 is phase 27,
            # the world door -- i.e. a NEW world session. Without this the connect
            # is one-shot per CONTAINER, so only the first session after a restart
            # gets its item/stat channel and every reconnect silently reverts to
            # the old behaviour. Reported live: first attempt reached a new room,
            # the second went back to the confined one.
            if _req_sel == 1:
                # sec 4dv: the world door is a NEW session, so the learned
                # character id must not carry over -- the same stale-across-
                # sessions class as `seen_uid` (the 2026-09-05 audit defect A). It is
                # relearned from the very next type-127 round (selector 12),
                # which is long before anything that needs it.
                if seen_charid[0]:
                    seen_charid[0] = 0
            if _req_sel == 1 and gs_done[0]:
                gs_done[0] = False
                print("  [gs] world door seen -- re-arming the game-server connect",
                      flush=True)
            # KEY: SELECTOR 36 IS NOT A LADDER RUNG -- it is the client asking who an
            # entity is (sec 4bw), and its answer's body[12] is a PEER RECORD
            # where build_world_answer would put its `result` word.  Answering it
            # with the generic builder inserts an entity whose id is the result
            # code.  Off by default: we never send a type-125, so the client never
            # cache-misses, and we have no entity data to serve yet.
            # KEY: SELECTOR 10 IS THE USER LIST REQUEST (sec 4bx). We have always
            # answered it with selector 11 -- and an EMPTY body, which the client
            # parses as a list of zero users, prints `user list 0 0`, and then
            # CER-47117. Serve the player's own uid instead; it is the entity it
            # is failing to find a name plate for.
            _bt_body = request_body(data, inner) if a.battletable_verbs else None
            # sec 4ep (2026-09-11): true when this JOIN targets an UNKNOWN
            # table and --bt-no-onfly-reserve is on -- the selector-21
            # endpoint answer below must then FAIL (result=-1) so the client
            # does NOT set [kelsvc+1092] bit 4 for a phantom reservation.
            _bt_phantom_join = False
            _bt_join_result = -1
            if a.battletable_verbs and _req_sel in BT_JOIN_REQS and _bt_body:
                # sec 4dz: the JOIN rung names the table at body[12..13]; seat
                # the character before the endpoint answer below goes out.
                _jkey = struct.unpack_from("<H", _bt_body, 12)[0]
                _jpw = (_bt_body[BT_PASSWORD_OFF:BT_PASSWORD_OFF + 8]
                        if _req_sel == BT_REQ_JOIN_PW else None)
                _jt = bt_store.tables.get(_jkey)
                if (a.novice == "on" and a.novice_tables == "enforce"
                        and _jt is not None
                        and struct.unpack_from("<I", _jt["rec"], BT_OFF_FLAGS)[0]
                        & BT_FLAG_NOVICE
                        and not novice_cid(_ident or seen_charid[0] or 0)):
                    # sec 4hc: "a mode open only to novice players" (28:198/199)
                    _jres = -5
                elif (_units is not None and a.unit_tables == "enforce"
                        and _jt is not None
                        and struct.unpack_from("<I", _jt["rec"], BT_OFF_FLAGS)[0]
                        & BT_FLAG_UNIT
                        and (_ident or 0) not in _jt["members"]
                        and not doc_unit.join_allowed(
                            _jt["members"], _unit_of_cid,
                            _ident or seen_charid[0] or 0)[0]):
                    # 2026-09-24: SE's 28:197 -- "you cannot make a
                    # reservation unless you belong to one of the first two
                    # units to reserve"
                    print("  [units] JOIN table %d refused: %s" % (
                        _jkey, doc_unit.join_allowed(
                            _jt["members"], _unit_of_cid,
                            _ident or seen_charid[0] or 0)[1]), flush=True)
                    _jres = -6
                else:
                    _jres, _jkey = bt_store.reserve(
                        _jkey, _ident or 0, _jpw,
                        rp=rp_of_cid(_ident or seen_charid[0] or 0))
                if _jres == -1 and _jkey and a.bt_no_onfly_reserve:
                    # sec 4eo/4ep (2026-09-11): the console default-targets
                    # the uninitialised [manager+11808] (59600) the moment
                    # the player signs in. Creating that table on the fly
                    # (sec 4ee) and answering the JOIN with the selector-21
                    # success endpoint sets the reserved flag [kelsvc+1092]
                    # bit 4 -- so the player is stuck "reserved" (prompt
                    # 0x6835) and the Create/Start-Immediately path is hidden.
                    # Do NOT invent the table; leave _jres = -1 and mark the
                    # join phantom so _result is forced to -1 below (the same
                    # "no such table" result the RESERVE arm returns), which
                    # keeps the phase-45 success path -- and the reserved
                    # flag -- from ever running. The player stays
                    # UNRESERVED and free to CREATE their own table and
                    # become its leader.
                    _bt_phantom_join = True
                    print("  [battletable] table %d UNKNOWN -- NOT creating on "
                          "the fly (sec 4eo, --bt-no-onfly-reserve); answering "
                          "JOIN selector 21 with result=-1 so the client stays "
                          "UNRESERVED and can CREATE" % _jkey, flush=True)
                elif _jres == -1 and _jkey:
                    # sec 4ee: the console reserves whatever [manager+11808]
                    # holds (59600 in every live boot where no table was
                    # picked from the browser). An unknown id used to leave
                    # the character unseated, so 38 carried no record and the
                    # briefing room had nobody in it. Make the table exist.
                    bt_store.add_record(build_battletable_record(
                        table_id=_jkey, leader=seen_uid[0], cur=0, maximum=8,
                        map_idx=0, mode=1, comment="Table %d" % _jkey))
                    _jres, _jkey = bt_store.reserve(
                        _jkey, _ident or 0, _jpw,
                        rp=rp_of_cid(_ident or seen_charid[0] or 0))
                    print("  [battletable] table %d did not exist -- CREATED it "
                          "on the fly (sec 4ee)" % _jkey, flush=True)
                if _jres == 0 and _jkey:
                    _bt_echo_key = _jkey  # sec 4fl: echo 152 after the 21
                elif _jres < 0:
                    # sec 4he: a REFUSED join (password / full / in progress)
                    # used to get the generic success 21, so the client sat
                    # "reserved" at a table the store never seated it at.
                    _bt_phantom_join = True
                    _bt_join_result = _jres
                print("  [battletable] JOIN table %d by 0x%08x -> %d (%s)"
                      % (_jkey, _ident or 0, _jres,
                         {0: "seated", -1: "no such table", -2: "wrong password",
                          -3: "full", -4: "IN PROGRESS",
                          -5: "NOVICES ONLY (--novice-tables enforce)",
                          BT_REFUSE_RP: "RP LIMIT: %s (--rp-tables enforce)"
                              % (rp_allowed(_jt["rec"] if _jt else None,
                                            rp_of_cid(_ident or seen_charid[0]
                                                      or 0))[1]),
                          -6: "UNIT: not one of the first two units "
                              "(--unit-tables enforce)"}.get(_jres, "?")),
                      flush=True)
            bt_tables = bt_store.records()
            if bt_tables and _req_sel == BATTLETABLE_LIST_REQ:
                # sec 4dv: the browser's list. Answering it with
                # build_world_answer's empty body is a well-formed list of ZERO
                # tables -- the handler's own completion test 0 == 0 passes, so
                # the screen is simply empty and nothing looks wrong.
                bl = build_battletable_list(
                    data, [rec_for(_r, _gs_endpoint, src[0])
                           for _r in bt_tables], seq=a.lobby_seq,
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7),
                    ptype=a.world_type, ident=_ident)
                s.sendto(bl, src)
                print("  SENT type-%d BATTLETABLE LIST (selector %d -> %d) "
                      "%d table(s), stride %d -- the arm needs [kelsvc+12] == 15,"
                      " which phase 34's own request parks it in"
                      % (a.world_type, BATTLETABLE_LIST_REQ,
                         BATTLETABLE_LIST_ANS, len(bt_tables), BT_REC_LEN),
                      flush=True)
                _served_list = True
            elif (a.battletable_verbs and _req_sel in BT_VERB_REQS
                    and _bt_body is not None):
                # 2026-09-13: EVERY config goes through the store -- an unknown
                # key now answers result -1 there instead of reaching the
                # sentinel probe below (the phantom password table).
                _vp, _vnote = battletable_verb(
                    bt_store, data, _bt_body, _req_sel, _ident or 0,
                    seen_uid[0], seq=a.lobby_seq,
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7),
                    ptype=a.world_type, pad_to=a.world_pad,
                    probe=a.battletable_probe,
                    quest=((_quest_pick.get(sess.key) or (None,))[0]
                           if a.quest_mission else None),
                    # sec 4gv addendum: the record carries the game-server
                    # endpoint and the client installs it, so it is rewritten
                    # per recipient exactly as the list and 38 paths do.
                    peer_ip=src[0], default_gs_ip=_gs_endpoint,
                    rp=rp_of_cid(_ident or seen_charid[0] or 0))
                if _vp is not None:
                    s.sendto(_vp, src)
                    print("  SENT type-%d %s (selector %d -> %d): %s  [store: "
                          "%d table(s), %d seated]"
                          % (a.world_type, selector_name(_req_sel), _req_sel,
                             _req_sel + 1, _vnote, len(bt_store.tables),
                             len(bt_store.reservation)), flush=True)
                    # sec 4fl: the leader never sends 151 for their own table;
                    # echo the reservation AFTER the 25 (0x00bcb638 clears it
                    # on the way in) so R+2970/R+684 bit 4 hold the new key.
                    _ck = (bt_store.table_of(_ident or 0)
                           if _req_sel == BT_REQ_CREATE else None)
                    if _ck and not a.bt_no_reserve_echo:
                        s.sendto(build_reserve_echo(
                            data, _ck, seq=a.lobby_seq,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7),
                            ptype=a.world_type, pad_to=a.world_pad,
                            ident=_ident), src)
                        print("  SENT type-%d RESERVATION ECHO (selector 152, "
                              "unsolicited) for table %d after the CREATE-ok "
                              "(sec 4fl)" % (a.world_type, _ck), flush=True)
                    # 2026-09-13: the mirror of that echo. After a DISSOLVE-ok
                    # the leader still held the reservation the echo gave them
                    # (R+2970 / R+684 bit 4), so "Reserved Table" pointed at a
                    # dead key and asked CONFIG for it (live table 1,
                    # 16:55 table 3). The CANCEL-ok arm ("Cancel %d", kel
                    # 0x00bcd6c0) calls the clear 0x00be33b0 when body[12]
                    # >= 0; the clear is a no-op if bit 4 is already off.
                    if (_req_sel == BT_REQ_DISSOLVE and " -> gone" in _vnote
                            and not a.bt_no_reserve_echo):
                        s.sendto(build_world_answer(
                            data, selector=BT_REQ_CANCEL + 1, result=0,
                            seq=a.lobby_seq,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7),
                            ptype=a.world_type, pad_to=a.world_pad,
                            ident=_ident), src)
                        print("  SENT type-%d RESERVATION CLEAR (selector 156, "
                              "unsolicited) after the DISSOLVE-ok" % a.world_type,
                              flush=True)
                        send_reservation_clear(_ident or seen_charid[0], dst=src,
                                               why="after the DISSOLVE-ok")
                    # 2026-09-22: the SAME orphan, without a dissolve. The
                    # store is in MEMORY, so every responder restart drops every
                    # table while the client keeps the reservation the echo above
                    # gave it (R+2970 / R+684 bit 4 -- nothing in the lobby
                    # re-clears them, sec 4fl). The client then opens Battle
                    # Entry holding a dead key: the extra "Confirm Reserved
                    # Battletable" row appears, CONFIG asks for a table we do not
                    # have, and our all-zero answer renders as a junk table
                    # (!!na!!, Max 0, Time Limit 35931752 min -- savestates 06/07,
                    # live table 4114 with [store: 0 table(s), 0 seated]).
                    # Leaving re-enters it because the reservation is still set.
                    # Clear it on the way out, exactly as the DISSOLVE-ok does.
                    if (_req_sel == BT_REQ_CONFIG and "table gone" in _vnote
                            and not a.bt_no_reserve_echo):
                        s.sendto(build_world_answer(
                            data, selector=BT_REQ_CANCEL + 1, result=0,
                            seq=a.lobby_seq,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7),
                            ptype=a.world_type, pad_to=a.world_pad,
                            ident=_ident), src)
                        print("  SENT type-%d RESERVATION CLEAR (selector 156, "
                              "unsolicited) -- CONFIG named a table the store "
                              "does not have, so the client's reservation is an "
                              "orphan" % a.world_type, flush=True)
                        # ...and the one that WORKS on this build (the 156
                        # above left the "!!na!!" table up, live)
                        send_reservation_clear(_ident or seen_charid[0], dst=src,
                                               why="CONFIG of a table the store "
                                               "does not have")
                else:
                    print("  [battletable] %s (selector %d): %s -- falling back "
                          "to the generic answer"
                          % (selector_name(_req_sel), _req_sel, _vnote),
                          flush=True)
                _served_list = _vp is not None
            elif _stats is not None and _req_sel == doc_stats.CAREER_REQ:
                # 2026-09-13: the Status window's CAREER RECORD, asked EVERY
                # time it opens (139 -> 140, arm 0x00bcd4e0, state 44 -> 2).
                # The generic echo put the request's own bytes into the W/L and
                # medal counts. The asked-for charid (0 = self) is read at
                # body[12]; the raw bytes are logged until a live one settles it.
                _crq = request_body(data, inner) or b""
                _cwant = (struct.unpack_from("<I", _crq, 12)[0]
                          if len(_crq) >= 16 else 0)
                _cself = _ident or seen_charid[0]
                _ckey = (_stats.key_for_charid(_cwant)
                         if _cwant and (_cwant & 0x3FFFFFFF) != (_cself & 0x3FFFFFFF)
                         else _wallet_key(seen_uid[0], _cself))
                _cc = _stats.peek(_ckey) if _ckey else doc_stats.new_career()
                s.sendto(seal_world_body(
                    data, doc_stats.career_body(
                        _cc, subchannel=(a.world_subchannel
                                         if a.world_subchannel >= 0 else 7)),
                    seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                print("  SENT type-%d CAREER RECORD (selector 139 -> 140) [%s]: "
                      "%s  [req body[12..27] = %s]"
                      % (a.world_type, _ckey, _stats.summary_line(_ckey)
                         if _ckey and _ckey in _stats.data["chars"]
                         else "no career yet", _crq[12:28].hex(" ")), flush=True)
                _served_list = True
            elif _shop is not None and _req_sel in doc_shop.SHOP_REQS:
                # sec 4gk: the shop lists and the 145 -> 146 item transaction.
                _swk = _wallet_key(seen_uid[0], _ident or seen_charid[0])
                _sbody, _snote = _shop.body_for(
                    _req_sel, request_body(data, inner), _swk,
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7))
                if _sbody is not None:
                    s.sendto(seal_world_body(data, _sbody, seq=a.lobby_seq,
                                             ptype=a.world_type, ident=_ident),
                             src)
                print("  %s type-%d SHOP selector %d -> %d [%s]: %s"
                      % ("SENT" if _sbody is not None else "NOT SENT (generic "
                         "answer instead)", a.world_type, _req_sel, _req_sel + 1,
                         _swk, _snote), flush=True)
                _served_list = _sbody is not None
            elif _rank is not None and _req_sel in doc_rank.RANK_REQS:
                # 2026-09-13: the Ranking menu (doc_rank.py). The generic echo
                # put the request's page size in the answer's row count.
                _rwk = _wallet_key(seen_uid[0], _ident or seen_charid[0])
                _rbody, _rnote = _rank.body_for(
                    _req_sel, request_body(data, inner), _rwk,
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7))
                if _rbody is not None:
                    s.sendto(seal_world_body(data, _rbody, seq=a.lobby_seq,
                                             ptype=a.world_type, ident=_ident),
                             src)
                print("  %s type-%d RANKING selector %d -> %d [%s]: %s"
                      % ("SENT" if _rbody is not None else "NOT SENT (generic "
                         "answer instead)", a.world_type, _req_sel, _req_sel + 1,
                         _rwk, _rnote), flush=True)
                _served_list = _rbody is not None
            elif (_req_sel == LIST148_REQ and not _list148
                  and (_ledger or _solo_quests)):
                # 2026-09-23 LIVE: on the RETAIL build "Accept Mission" sends
                # selector 147, not 159 (live log: a player in Accept
                # Mission, zero 159s, 147 with capacity 256 at body[16]). The
                # 148 answer feeds the mission window's populator 0x00aae2d0:
                # {u16 quest id -> name KelStr 0xBBFF+id, u8 RANK (0-based;
                # 0x00aae950 maps it onto the "Mission: DG <class>" tab table
                # 0x00b12158 = thresholds 0/3/6/9/12/15), u8 flags (bit0 ->
                # rec+26 229 else -1, bit1 -> rec+4 0 else 2; left 0)}.
                _mids = _solo_quests
                _mnote = a.solo_quests
                if _ledger:
                    _mkey = _wallet_key(seen_uid[0], _ident or seen_charid[0])
                    _mc = _stats.peek(_mkey)
                    _mids = doc_missions.mission_list(_mc, _solo_quests)
                    _mnote = "[%s] ledger %s" % (_mkey, _mc.get("quests_open") or [])
                # flags bit1 -> row state rec+4 = 0 (selectable); without it the
                # populator writes 2 and every row drew GREYED (live
                # 2026-09-23). The ledger already hides what is not earned, so
                # every listed mission is takeable.
                _ment = [(q, doc_missions.list_rank(q), MISSION_ROW_OPEN)
                         for q in _mids]
                s.sendto(seal_world_body(
                    data, build_list148_body(
                        _ment,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7)),
                    seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                print("  SENT type-%d MISSION LIST (selector 147 -> 148, retail "
                      "Accept Mission): %d mission(s) %s -- %s"
                      % (a.world_type, len(_ment), _mids, _mnote), flush=True)
                _served_list = True
            elif _req_sel == LIST148_REQ and _list148:
                # sec 4gt add.1 probe. The generic answer here is a well-formed list
                # of ZERO entries, which is exactly what draws the blank,
                # unselectable rows (memory
                # doc-server-list-is-gated-on-state-10, corrected 2026-09-22).
                s.sendto(seal_world_body(
                    data, build_list148_body(
                        _list148,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7)),
                    seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                print("  SENT type-%d 147 LIST PROBE (selector %d -> %d): "
                      "%d entr(ies) %s -- PROBE, values are not decoded"
                      % (a.world_type, LIST148_REQ, LIST148_ANS,
                         len(_list148),
                         ",".join("%d:%d:%d" % e for e in _list148)),
                      flush=True)
                _served_list = True
            elif _req_sel == QUEST_LIST_REQ and (_solo_quests or _ledger):
                # 2026-09-13: Solo Battle = story mode; list the quest ids
                # (build_quest_list_body). Empty --solo-quests = the generic
                # zero-body answer (an empty list).
                # 2026-09-23: with the MISSION LEDGER the list is PER PLAYER
                # (doc_missions.mission_list): the exams an instructor has
                # authorized for this character, then --solo-quests minus every
                # exam. peek() so a lookup never creates a career.
                _qids, _qnote = _solo_quests, a.solo_quests
                if _ledger:
                    _qkey = _wallet_key(seen_uid[0], _ident or seen_charid[0])
                    _qc = _stats.peek(_qkey)
                    _qids = doc_missions.mission_list(_qc, _solo_quests)
                    _qnote = ("[%s] ledger %s, rank %d, %d rp, %d battle(s)"
                              % (_qkey, _qc.get("quests_open") or [],
                                 _qc.get("rank", 1), _qc.get("rp", 0),
                                 _qc.get("battles", 0)))
                s.sendto(seal_world_body(
                    data, build_quest_list_body(
                        _qids,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7)),
                    seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                print("  SENT type-%d %s (selector 159 -> 160): "
                      "%d quest(s) %s -- %s"
                      % (a.world_type,
                         "MISSION LIST" if _ledger else "SOLO QUEST LIST",
                         len(_qids), _qids, _qnote), flush=True)
                _served_list = True
            elif _trade is not None and _req_sel in doc_trade.TRADE_REQS:
                # sec 4gk addendum 5: TRADE. Never the generic answer: a
                # generic 42 back to the INVITER runs its own "invited"
                # handler (flag 0x400, partner = our result word 0).
                _tme = _ident or seen_charid[0]
                _tacts, _tnote = _trade.request(_req_sel, _tme,
                                                request_body(data, inner))
                print("  [trade] request %d from 0x%08x: %s"
                      % (_req_sel, _tme, _tnote), flush=True)
                for _ta in _tacts:
                    if _ta[0] == "ack":
                        s.sendto(seal_world_body(
                            data, doc_trade.bare_body(doc_trade.ACK_ANS),
                            seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                    elif _ta[0] == "push":
                        trade_push(_ta[1], _ta[2])
                    elif _ta[0] == "swap":
                        trade_swap(_ta[1])
                _served_list = True
            elif a.battletable_probe and _req_sel == 26:
                bt = build_battletable_probe(
                    data, seq=a.lobby_seq,
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7),
                    ptype=a.world_type, ident=_ident)
                s.sendto(bt, src)
                print("  SENT type-%d BATTLETABLE PROBE (selector 26 -> 27) -- "
                      "sentinels in every field; read the config screen (sec 4do)"
                      % a.world_type, flush=True)
                _served_list = True
            elif (a.user_list and _req_sel in USER_SELECTOR_REQS
                    and seen_uid[0]):
                # KEY: sec 4cg: serve the id the client ASKED FOR, not our own uid.
                _want = user_list_wanted_id(data, inner)
                # 0xffff is "none" too: --gs-connect-id=65535 (at no table)
                _ids = ([_want] if (_want not in (None, 0, 0xFFFF))
                        else [seen_uid[0]])
                # sec 4fr: register THIS player and fold in every OTHER player
                # so two clients see each other (and resolve each other's name).
                if seen_charid[0]:
                    players[seen_charid[0]] = {
                        "name": _player_name() or ("Player_%x" % seen_charid[0]),
                        "uid": seen_uid[0],
                        "look": _player_look(sess)}      # sec 4fx
                _other_ids = [c for c in players
                              if c and c != seen_charid[0]]
                _ids = _ids + [c for c in _other_ids if c not in _ids]
                # 2026-09-13: THIS player's own CHARID, named, right after the
                # self record. That record is keyed by the ASKED id (the uid),
                # but a table's leader (b2d40362) and the kind-20 distribution
                # name members by CHARID -- the one id a client could not
                # resolve on its own screen: own table ownerless, own team
                # empty after "Player distribution has been determined".
                if seen_charid[0] and seen_charid[0] not in _ids:
                    _ids = _ids[:1] + [seen_charid[0]] + _ids[1:]
                # KEY: sec 4ci: the FIRST live session with a decoded record
                # measured 13 x (10 -> 11) and exactly ONE (18 -> 19). Only 19
                # reaches the profile cache the UI reads (sec 4ch), so all the
                # frequent traffic was landing on the rung that discards it.
                # --user-list-selector forces the answer rung regardless of what
                # was asked; both arms take the same handler and the same
                # [kelsvc+12] == 7 gate, and the demux dispatches on the selector
                # WE send, not the one the client sent.
                _ans = a.user_list_selector or (_req_sel + 1)
                # WARNING: and the id is the other half. The record is keyed on its
                # +0, and 0x00bd8528 binary-searches it with a SIGN-EXTENDING
                # `lw` against a 64-bit compare -- so a uid with bit 31 set
                # (0xa756a69a is one) stores fine and may never be found. Rather
                # than guess which id the UI resolves, serve a SPREAD: the asked
                # id plus 1..N. The cache holds 32 and the client drops the ones
                # it does not want, so the sweep costs nothing but bytes.
                _sweep_ids = []
                if a.user_list_sweep:
                    _sweep_ids = [i for i in range(1, a.user_list_sweep + 1)
                                  if i not in _ids]
                    _ids = _ids + _sweep_ids
                # KEY: sec 4fx (2026-09-13): f36 (wire+36) is the o099 LOOK, and
                # --user-costume stamped Lex's 0x1012 on EVERY record -- this
                # player's own and the other player's alike -- so everyone wore
                # Lex. Each record now carries its own player's SELECTED
                # character: this client's for the first (self) record, the
                # shared registry's for another player. --user-costume is only
                # the fallback for ids with no known look (the sweep).
                def _ul_fields(_uid):
                    _f = dict(_user_rec_fields(a) or {})
                    if _uid in (_ids[0], seen_charid[0]):
                        _lk = _player_look(sess)
                    else:
                        _lk = players.get(_uid, {}).get("look")
                        if _lk is None:
                            _lk = player_look.get(_uid)
                    if _lk is not None:
                        _f["f36"] = _lk & 0xFFFF
                    return _f
                _ul_recs = [build_peer_record(
                    _uid, name=(players.get(_uid, {}).get("name")
                                or (_player_name() if _uid == _ids[0]
                                    else "Slot%d" % _uid)),
                    **_ul_fields(_uid)) for _uid in _ids]
                ul = build_user_list_answer(
                    data, _ids, seq=a.lobby_seq,
                    name=_player_name(), records=_ul_recs,
                    fields=_user_rec_fields(a),
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7),
                    ptype=a.world_type, ident=_ident,
                    answer_selector=_ans)
                s.sendto(ul, src)
                print("  SENT type-%d USER LIST (selector %d -> %d) total=1 "
                      "index=0 records=%d uid=0x%08x%s"
                      % (a.world_type, _req_sel, _ans, len(_ids), _ids[0],
                         "  (+%d swept)" % (len(_ids) - 1) if len(_ids) > 1
                         else ""), flush=True)
                # KEY: sec 4dj: THE USER LIST AND THE PEER TABLE ARE DIFFERENT
                # TABLES, and the battletable check reads the one we never fill.
                # Measured in doc_reserve_slot06 with --user-list-sweep=32 live:
                #     CACHE [kelsvc+280] count = 32   <- the sweep landed here
                #     PEER  [kelsvc+284] count =  0   <- and this stayed empty
                # getCharacterTableId does `lw a0, 284(a0)` on kelsvc, i.e. the
                # PEER table, so its lookup still missed and still returned
                # 0xffff4867 as the "table id". The cache is the Status/Profile
                # rung; the peer table is selector 37's.
                #
                # Nothing ever fills the peer table unsolicited (sec 4bw: it is a
                # PULL -- the client asks with selector 36 on a type-125 cache
                # miss, and it has never once asked). But selector 37's arm
                # 0x00bccee8 has NO state gate, so an unsolicited answer simply
                # runs and inserts. Push one per swept id, right here, where the
                # client has just proved it is in the right state and `_ident` is
                # known good.
                if a.peer_push:
                    # KEY:KEY: ID 0 IS THE ONE THAT MATTERS, and no sweep produces it.
                    # getMyCharaId() is `lw v0, 272(a0)` on kelsvc (0x00bdb2b0),
                    # i.e. [kelsvc+272] -- which is 0 in every savestate we hold,
                    # because the code that sets it has never been reached (sec
                    # 4ch). So the client looks ITSELF up by id 0, while
                    # --user-list-sweep serves 1..N. Proven in doc_eemu against
                    # doc_reserve_slot06:
                    #     before            getCharacterTableId(0) = -47001
                    #     after pushing 7   getCharacterTableId(0) = -47001
                    #     after pushing 0   getCharacterTableId(0) = 0
                    # 0 = "no battletable", which is the whole point.
                    # sec 4dv: id 0 was only ever right BECAUSE [kelsvc+272]
                    # was 0. Now that the roster carries a real id, push the id
                    # the client itself is using -- record+4 of its own
                    # messages -- and fall back to 0 for the old behaviour.
                    _self = seen_charid[0]
                    # 2026-09-13: never the sweep ids. The peer table IS what
                    # Player Search searches (0x00bda970, name prefix), and
                    # they went in under the ASKER's name: 32 "Lex" rows.
                    _push_ids = doc_playtime.peer_push_ids(_self, players, _ids,
                                                           _sweep_ids)
                    for _pid in _push_ids:
                        _pnm = (players.get(_pid, {}).get("name")
                                or _player_name())
                        pp = build_peer_answer(
                            data, _pid, seq=a.lobby_seq,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7),
                            ptype=a.world_type, ident=_ident,
                            blob=build_peer_record(
                                _pid, name=_pnm,
                                zone=a.user_zone, rank=a.user_rank,
                                flags=peer_flags(_pid),
                                # sec 4fu (look): another player's look, so
                                # a zero record cannot win the peer table
                                f36=(player_look.get(_pid)
                                     if _pid != _self else None))[4:])
                            # sec 4et (2026-09-11): [4:] DROPS the redundant
                            # leading id. build_peer_answer re-embeds `blob` at
                            # record+4 (it prepends ent_id itself), so passing a
                            # FULL build_peer_record shifted every field +4 --
                            # the zone (wire+32, which getCharacterTableId reads
                            # at peer slot+42) landed at wire+36/slot+40 instead,
                            # leaving slot+42 = 0 = "table 0" = the false
                            # "already reserved". Dropping the id aligns zone ->
                            # wire+32 -> slot+42 = --user-zone (0xffff = none).
                            # Verified on the live build's 0x00bd9090 (slot 6).
                        s.sendto(pp, src)
                    print("  SENT %d unsolicited PEER answers (selector %d), ids "
                          "%d..%d INCLUDING 0x%08x -- that is what "
                          "getMyCharaId() returns ([kelsvc+272], read off the "
                          "client's own record+4), and it is the id the "
                          "battletable check looks up (sec 4dj/4dv)"
                          % (len(_push_ids), PEER_SELECTOR_ANS,
                             min(_push_ids), max(_push_ids), _self), flush=True)
                _served_list = True
            else:
                _served_list = False
            _miss = peer_miss_id(data, inner)
            if a.peer_answer and _miss is not None:
                # sec 4fu: a miss on a RELAYED peer gets that peer's record
                _rn = relay_names.get(_miss)
                pr = build_peer_answer(data, _miss, seq=a.lobby_seq,
                                       subchannel=(a.world_subchannel
                                                   if a.world_subchannel >= 0 else 7),
                                       ptype=a.world_type, ident=_ident,
                                       blob=(build_peer_record(
                                           _miss, name=_rn, zone=a.user_zone,
                                           rank=a.user_rank,
                                           flags=peer_flags(_miss),
                                           f36=player_look.get(_miss))[4:]
                                             if _rn else None))
                s.sendto(pr, src)
                print("  SENT type-%d PEER answer (selector %d -> %d) for entity "
                      "0x%08x  [%s]"
                      % (a.world_type, PEER_SELECTOR_REQ, PEER_SELECTOR_ANS,
                         _miss, ("relayed peer %s" % _rn) if _rn
                         else "zero record"), flush=True)
            # NO `continue` -- the rest of the loop still owes this datagram its
            # ACK, which is exactly the omission that cost the phase-29 round in
            # sec 4bt ("we ACKed it and never answered" is the mirror of it).
            if _req_sel == doc_chat.SEL_CHAT:
                relay_chat(_ident or seen_charid[0], request_body(data, inner))
            if _unpairable and not a.world_answer_unpairable:
                print("  (selector %s is UNPAIRABLE -- NOT answering; sending it "
                      "--world-selector-next=%d would reset [kelsvc+12], sec 4bz)"
                      % (_req_sel, a.world_selector_next), flush=True)
            # KEY: SELECTOR 241's body[12] IS THE COMMAND ID, not a result word.
            # build_world_answer packs `result` there, it defaults to 0, and the
            # handler's window is [3, 41] -- so every "Command Result" we have
            # ever sent bailed at 0x00bc9274 before it selected anything.  Echo
            # the id the client itself put at request body[12] (lobby_cmd_id).
            # WARNING: ONE OFFSET, TWO MEANINGS: on selector 13 body[12] really is the
            # result and must stay 0, so this override is keyed on the ANSWER
            # rung and nothing else.
            _result = a.world_result
            # sec 4ep (2026-09-11): a phantom/unknown JOIN (see the JOIN
            # block above) must fail so the client never sets [kelsvc+1092]
            # bit 4. The generic ladder answers selector 20/30 with 21/31
            # (a GS_ENDPOINT_SELECTORS rung), whose body[12..15] result the
            # phase-44 JOIN arm reads: 0/positive = success (reserved), a
            # negative = "no such table". Override it to -1 here.
            if _bt_phantom_join:
                _result = _bt_join_result
            _cmd = None
            _cmd_arg = None
            if _sel == LOBBY_CMD_SELECTOR_ANS and a.lobby_cmd != "off":
                _cmd = (lobby_cmd_id(data, inner) if a.lobby_cmd == "echo"
                        else int(a.lobby_cmd, 0))
                if _cmd is not None:
                    _result = _cmd
                    if _cmd == LOBBY_CMD_QUEST:
                        _qb = request_body(data, inner)
                        _qid = (struct.unpack_from("<H", _qb, 16)[0]
                                if _qb is not None and len(_qb) >= 18 else 0)
                        if _qid:
                            _quest_pick[sess.key] = (_qid, time.time())
                            print("  [quest] %s picked Solo quest %d (command "
                                  "41) -- the next Start plays it as a MISSION%s"
                                  % (src[0], _qid, "" if a.quest_mission
                                     else " (OFF: --no-quest-mission)"),
                                  flush=True)
                    # 2026-09-23 (sec 4hc): command 33 = clearNovicePlayerFlag
                    # (the Cactuar Beginner's Machine). Answer with the 241 whose
                    # sub-33 arm clears the local mark (doc_novice_proof C), then
                    # record it and tell every client (selector 134 sub 11).
                    if _cmd == doc_novice.CMD_GRADUATE and _novice is not None:
                        _gcid = (_ident or seen_charid[0] or 0)
                        s.sendto(seal_world_body(data, doc_npc.answer_body(
                            _cmd, subchannel=(a.world_subchannel
                                              if a.world_subchannel >= 0 else 7)),
                            seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                        _served_list = True
                        _gk = _novice_key(sess)
                        if _gk is not None and _novice.graduate(_gk, "machine"):
                            broadcast_graduate(_gcid, "Beginner's Machine, command 33")
                        else:
                            print("  [novice] command 33 from [%s]: already "
                                  "graduated, answered only" % _gk, flush=True)
                    # command 27 id 1 = the intro chain finished (ev2046.main).
                    if (_cmd == doc_novice.CMD_EVENT_DONE and _novice is not None
                            and doc_novice.event_done_id(request_body(data, inner))
                            == doc_novice.EV_INTRO):
                        _ik = _novice_key(sess)
                        if _ik is not None and _novice.mark_intro_seen(_ik):
                            print("  [intro] [%s] finished the new-player intro "
                                  "(command 27 id 1) -- recorded, it will not "
                                  "play again" % _ik, flush=True)
                        # sec 4hg addendum 3: no notify here. Kind 39 was
                        # tried (after command 27, and 8 s into the intro):
                        # the client drops every game-server message but
                        # the keepalive until obj+0x858 (a battle join) is
                        # set, and the crash is the zone loader, not the
                        # facade standby.
                    if _cmd == LOBBY_CMD_PLAYTIME:
                        if a.lobby_clock == "play":
                            _cmd_arg = _playtime.answer(_wallet_key(
                                seen_uid[0], _ident or seen_charid[0]))
                        else:
                            _cmd_arg = lobby_clock_value(a.lobby_clock)
                    # sec 4dz: KICK (2) and APPOINT LEADER (1) are lobby
                    # commands whose 12-byte argument opens with the target's
                    # character id (0x00bd1cf0 / 0x00bd1c28 pass &target as a3
                    # to the 0x00589c48 builder, which copies it to body[16]).
                    if (a.battletable_verbs and _cmd in (LOBBY_CMD_KICK,
                                                         LOBBY_CMD_APPOINT)
                            and _bt_body is not None and len(_bt_body) >= 20):
                        _tgt = struct.unpack_from("<I", _bt_body, 16)[0]
                        _tkey = bt_store.table_of(_ident or 0)
                        _ok = (bt_store.kick if _cmd == LOBBY_CMD_KICK
                               else bt_store.appoint)(_tkey, _tgt, _ident,
                                                      uid=seen_uid[0])
                        print("  [battletable] command %d %s 0x%08x at table %s "
                              "-> %s" % (_cmd, "KICK" if _cmd == LOBBY_CMD_KICK
                                         else "APPOINT", _tgt, _tkey,
                                         "ok" if _ok else
                                         "REFUSED (not a member, or not the "
                                         "leader -- sec 4he)"),
                              flush=True)
                        if _ok and _cmd == LOBBY_CMD_KICK:
                            vacate_seat(_tgt, "kicked")
                    # 2026-09-13: UNIT MANAGEMENT (doc_unit.py). The panel's
                    # commands get a real 241 instead of the sec 4dy zeroes:
                    # lists for 24/13/25, a verdict for 8/12/9/10/11 (fee or
                    # SE's refusal code in the header, body[4]/body[6]).
                    if _units is not None and _cmd in doc_unit.UNIT_CMDS:
                        _uk = _wallet_key(seen_uid[0], _ident or seen_charid[0])
                        _ub, _un = _units.body_for(
                            _cmd, request_body(data, inner), _uk,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7))
                        if _ub is not None:
                            s.sendto(seal_world_body(data, _ub, seq=a.lobby_seq,
                                                     ptype=a.world_type,
                                                     ident=_ident), src)
                            _served_list = True
                        print("  %s type-%d UNIT selector %d -> %d [%s]: %s"
                              % ("SENT" if _ub is not None else "NOT SENT (generic "
                                 "answer instead)", a.world_type,
                                 LOBBY_CMD_SELECTOR_REQ, LOBBY_CMD_SELECTOR_ANS,
                                 _uk, _un), flush=True)
                    # 2026-09-24: UNIT VERSUS INFO (command 34, doc_unit). The
                    # unit table's window asks for the two sides; the Start
                    # gate 0x00aa12c8 counts the nonzero unit ids in this
                    # answer and refuses (0x683b) below two. The sides are the
                    # first two units seated -- the same rule JOIN enforces.
                    if _units is not None and _cmd == doc_unit.CMD_VERSUS:
                        _vreq = request_body(data, inner)
                        _vtid = (struct.unpack_from("<H", _vreq, 16)[0]
                                 if _vreq is not None and len(_vreq) >= 18
                                 else bt_store.table_of(_ident or 0) or 0)
                        _vt = bt_store.tables.get(_vtid)
                        _vmem = list(_vt["members"]) if _vt is not None else []
                        _vuo = {m: _unit_of_cid(m) for m in _vmem}
                        _vsides = [(u, (_units.unit(u) or {}).get("name")
                                    or "Unit %X" % (u & 0xFFFFFFFF),
                                    sum(1 for m in _vmem if _vuo[m] == u))
                                   for u in doc_unit.unit_sides(_vmem, _vuo.get)]
                        s.sendto(seal_world_body(
                            data, doc_unit.versus_body(
                                _vtid, _vsides,
                                subchannel=(a.world_subchannel
                                            if a.world_subchannel >= 0 else 7)),
                            seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                        _served_list = True
                        print("  [units] SENT UNIT VERSUS (command 34) for table %d: "
                              "%s -> Start %s" % (
                                  _vtid, " vs ".join("%s %r x%d" % (
                                      doc_unit.hexid(u), n, c) for u, n, c in _vsides)
                                  or "no units seated",
                                  "OPEN (2 units)" if len(_vsides) >= 2 else
                                  "REFUSED client-side (0x683b) until a 2nd unit "
                                  "joins"), flush=True)
                    # 2026-09-13: CHANGE MASK / ARMOR (doc_gear.py). Command 17
                    # EQUIP(slot, item) / 18 UNEQUIP(slot): the 241 arm stores
                    # body[6] VERBATIM as the costume code (R+728), so the
                    # generic zero answer reset the character's look. Answer
                    # with the new code and remember (mask, suit, costume).
                    if _gearstore is not None and _cmd in doc_gear.GEAR_CMDS:
                        _gcid = (_ident or seen_charid[0] or 0) & 0x3FFFFFFF
                        _gk = _wallet_key(seen_uid[0], _gcid)
                        _gbase = None
                        if _store is not None and seen_uid[0]:
                            _gr = _store.roster(_skey(seen_uid[0]))
                            for _gi in range(doc_charastore.MAX_SLOTS):
                                if sess.chara_ids.get(_gi) == _gcid and _gr[_gi]:
                                    _gbase = doc_charastore.chr_code(_gr[_gi])
                                    break
                        _gb, _gn = _gearstore.body_for(
                            _cmd, request_body(data, inner), _gk, _gbase,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7))
                        if _gb is not None:
                            s.sendto(seal_world_body(data, _gb, seq=a.lobby_seq,
                                                     ptype=a.world_type,
                                                     ident=_ident), src)
                            _served_list = True
                        print("  %s type-%d GEAR selector %d -> %d: %s"
                              % ("SENT" if _gb is not None else "NOT SENT (generic "
                                 "answer instead)", a.world_type,
                                 LOBBY_CMD_SELECTOR_REQ, LOBBY_CMD_SELECTOR_ANS,
                                 _gn), flush=True)
                    # 2026-09-13: LOBBY NPCs (doc_npc.py). Command 26 is Java
                    # checkQuestEvent(trigger, 0): the answer's body[6] is the
                    # event the client plays (quest_scr003 NPC scene); 27 =
                    # scene done, 39 = clear. Every request is logged raw -- the
                    # trigger == NPC number reading is not yet confirmed on a console.
                    if a.npc == "on" and _cmd in doc_npc.NPC_CMDS:
                        # 2026-09-23: the INSTRUCTORS (NPCs 7-10) answer from
                        # the career when the mission ledger is on: no battle
                        # yet / fewer than three / not enough rank points / the
                        # exam authorized -- which "adds it to Missions" here,
                        # on the answer, exactly as the dialogue says. An
                        # admin --npc-events override for that trigger still
                        # wins; only the b == 0 walk-up is judged.
                        _npc_use = _npc_over
                        _nq = doc_npc.parse_request(request_body(data, inner))
                        if (_ledger and _cmd == doc_npc.CMD_CHECK and _nq
                                and _nq["b"] == 0
                                and _nq["trigger"] in doc_missions.INSTRUCTORS
                                and _nq["trigger"] not in _npc_over):
                            _mkey = _wallet_key(seen_uid[0],
                                                _ident or seen_charid[0])
                            _mc = _stats.peek(_mkey)
                            _mev, _mgrant, _mwhy = doc_missions.instructor_event(
                                _nq["trigger"], _mc)
                            if _mgrant is not None:
                                _mc = _stats.career(_mkey)
                                if doc_missions.grant(_mc, _mgrant):
                                    _stats.save()
                            _npc_use = dict(_npc_over)
                            _npc_use[_nq["trigger"]] = _mev
                            print("  [missions] instructor NPC %d for [%s]: rank %d, "
                                  "%d rp, %d battle(s), open %s -> event %d (%s)"
                                  % (_nq["trigger"], _mkey, _mc.get("rank", 1),
                                     _mc.get("rp", 0), _mc.get("battles", 0),
                                     _mc.get("quests_open") or [], _mev, _mwhy),
                                  flush=True)
                        # 2026-09-24: ARGENTO (lnpc 4) answers from the career
                        # too: first meeting 302 / asks again 304 / the chain
                        # 305 / chain complete 300; the accept arm's (4, 2)
                        # records the rank held (doc_missions.argento_event).
                        # An exact --npc-events 4:B:E (or 4:E for the walk-up)
                        # still wins.
                        if (_ledger and _cmd == doc_npc.CMD_CHECK and _nq
                                and _nq["trigger"] == doc_missions.ARGENTO
                                and (_nq["trigger"], _nq["b"]) not in _npc_over
                                and (_nq["b"] or _nq["trigger"] not in _npc_over)):
                            _akey = _wallet_key(seen_uid[0],
                                                _ident or seen_charid[0])
                            _ac = _stats.peek(_akey)
                            _aev, _ast, _awhy = doc_missions.argento_event(
                                _ac, _nq["b"])
                            if _ast is not None:
                                _ac = _stats.career(_akey)
                                _ac[doc_missions.ARGENTO_KEY] = _ast
                                _stats.save()
                            _npc_use = dict(_npc_over)
                            _npc_use[(_nq["trigger"], _nq["b"])] = _aev
                            print("  [missions] Argento for [%s] (b %d): rank %d, "
                                  "state %s -> event %d (%s)"
                                  % (_akey, _nq["b"], _ac.get("rank", 1),
                                     _ac.get(doc_missions.ARGENTO_KEY) or {},
                                     _aev, _awhy), flush=True)
                        # 2026-09-24: the ITEM QUESTS -- Soar (26, broken items
                        # by wins), Este-D (29, Dandelion -> Gasmask at random),
                        # Hiren (36, grows a Fuzzy Seed over 7 days) answer
                        # from the career + the server bag (doc_npcquests).
                        if (_ledger and _shop is not None
                                and _cmd == doc_npc.CMD_CHECK and _nq
                                and _nq["b"] == 0
                                and _nq["trigger"] in doc_npcquests.NPCS
                                and _nq["trigger"] not in _npc_over):
                            _qkey = _wallet_key(seen_uid[0],
                                                _ident or seen_charid[0])
                            _qc = _stats.career(_qkey)
                            _qbag = {int(k, 16): v for k, v in
                                     _shop.wallet(_qkey)["bag"].items()}
                            _qev, _qst, _qmv, _qwhy = doc_npcquests.decide(
                                _nq["trigger"], _qc, _qbag,
                                day=a.npc_quest_day,
                                accept=a.npc_este_accept,
                                wither=a.npc_hiren_wither)
                            doc_npcquests.apply(_qc, _nq["trigger"], _qst)
                            _stats.save()
                            _qmoved = _bag_move(_qkey, _qmv)
                            _npc_use = dict(_npc_use)
                            _npc_use[_nq["trigger"]] = _qev
                            print("  [npcquest] NPC %d for [%s]: %s -> event %d%s"
                                  % (_nq["trigger"], _qkey, _qwhy, _qev,
                                     (" (bag %s)" % _qmoved) if _qmoved else ""),
                                  flush=True)
                        # ...and the scene reporting itself DONE (command 27)
                        # is where the gifts / trades happen
                        if (_ledger and _shop is not None
                                and _cmd == doc_novice.CMD_EVENT_DONE):
                            _qdone = doc_novice.event_done_id(
                                request_body(data, inner))
                            _qkey = _wallet_key(seen_uid[0],
                                                _ident or seen_charid[0])
                            _qc = _stats.career(_qkey)
                            _qr = doc_npcquests.on_done(_qdone, _qc)
                            if _qr is not None:
                                _qn, _qst, _qmv, _qwhy = _qr
                                doc_npcquests.apply(_qc, _qn, _qst)
                                _stats.save()
                                _qmoved = _bag_move(_qkey, _qmv)
                                print("  [npcquest] NPC %d scene %d DONE for [%s]: "
                                      "%s%s" % (_qn, _qdone, _qkey, _qwhy,
                                                (" (bag %s)" % _qmoved)
                                                if _qmoved else ""), flush=True)
                        _nb, _nn = doc_npc.body_for(
                            _cmd, request_body(data, inner), _npc_use,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7))
                        if _nb is not None:
                            s.sendto(seal_world_body(data, _nb, seq=a.lobby_seq,
                                                     ptype=a.world_type,
                                                     ident=_ident), src)
                            _served_list = True
                        print("  [npc] %s command %d (%s): %s"
                              % ("SENT 241" if _nb is not None else "NOT SENT",
                                 _cmd, doc_npc.CMD_NAMES.get(_cmd, "?"), _nn),
                              flush=True)
            # sec 4dr AUTO-DRESS (2026-09-11): on the selector-2 world-door reply,
            # dress the lobby avatar from the SELECTED character's stored look.
            # The world-door request names the chosen character at body+80 (u32
            # char id, MEASURED: Lex 0x0002a664 sits there); match it to the
            # account's roster, turn its charamake nibbles into the costume code
            # (doc_charastore.chr_code) and hand it to build_world_answer, which
            # writes it at the pinned body+100. --self-costume (raw) still wins.
            _self_cost = a.self_costume
            if a.self_costume_file and _sel == 2:
                # sec 4dr live calibration: read the code FRESH each time so it
                # can be changed with a file write + one lobby re-entry, no
                # recreate. Overrides --self-costume and --self-costume-auto.
                try:
                    with open(a.self_costume_file) as _scf:
                        _sct = _scf.read().strip()
                    if _sct:
                        _self_cost = int(_sct, 0) & 0xFFFF
                except (OSError, ValueError):
                    pass
            if (_self_cost is None and a.self_costume_auto and _store is not None
                    and _sel == 2 and seen_uid[0]
                    and len(data) >= BODY_OFF + 84):
                _sel_cid = struct.unpack_from(
                    "<I", data, BODY_OFF + 80)[0] & 0x3FFFFFFF
                _sl_roster = _store.roster(_skey(seen_uid[0]))
                for _si in range(doc_charastore.MAX_SLOTS):
                    if sess.chara_ids.get(_si) == _sel_cid and _sl_roster[_si]:
                        _self_cost = doc_charastore.chr_code(_sl_roster[_si])
                        print("  [self-costume] dressing selected char id 0x%08x "
                              "(slot %d, %s) -> code 0x%04x at body+100"
                              % (_sel_cid, _si, _sl_roster[_si].get("name", "?"),
                                 _self_cost), flush=True)
                        break
            # sec 4ew (2026-09-11): the self-record id (mgr+304 [+52]) is set
            # ONCE, from the state-1 selector-2 world-door answer's body[44]
            # (RE: 0x00bc8aa0 setMySelfRecord, key = datagram+68 = body[44]).
            # The charaid isn't yet learnable from record+4 at that first
            # message -- but the selector-2 REQUEST already carries the SELECTED
            # character id at body[80] (the same id the self-costume path reads),
            # which IS [kelsvc+272]. Read it straight from the request so the
            # override lands on the FIRST message, unconditionally.
            # 2026-09-13: the SELECTED character's name for the self record
            # (world-door body[112..127]); same selection as self-costume-auto.
            _self_name = None
            if (a.self_name and _store is not None and _sel == 2 and seen_uid[0]
                    and len(data) >= BODY_OFF + 84):
                _nc = struct.unpack_from("<I", data, BODY_OFF + 80)[0] & 0x3FFFFFFF
                _nr = _store.roster(_skey(seen_uid[0]))
                for _si in range(doc_charastore.MAX_SLOTS):
                    if sess.chara_ids.get(_si) == _nc and _nr[_si]:
                        _self_name = _nr[_si].get("name") or None
                        break
                if _self_name:
                    print("  [self-name] selector 2: self record name <- %r at "
                          "answer body[112..127] (char 0x%08x)" % (_self_name, _nc),
                          flush=True)
            # LEARN the character id here. The world door
            # clears seen_charid (sec 4dv) and it came back only from a later
            # request's record+4 -- but lobby commands (selector 240: units,
            # Start) carry ident 0, so a player who went straight to Unit
            # Management was keyed as the bare account ("member:15"), saw 0
            # units, and every Create was refused as "already a unit".
            if _sel == 2 and len(data) >= BODY_OFF + 84:
                _wdc = struct.unpack_from("<I", data, BODY_OFF + 80)[0] & 0x3FFFFFFF
                if _wdc and not seen_charid[0]:
                    seen_charid[0] = _wdc
                    print("  [charid] 0x%08x from the world-door request "
                          "body[80] (the selected character)" % _wdc, flush=True)
            _world_self_id = None
            if (a.world_self_charaid and _sel == 2
                    and len(data) >= BODY_OFF + 84):
                _wsi = struct.unpack_from("<I", data, BODY_OFF + 80)[0] & 0x3FFFFFFF
                if _wsi:
                    _world_self_id = _wsi
                    print("  [world-self-charaid] selector 2: self-record id <- "
                          "0x%08x (selected charaid, req body[80]) at answer "
                          "body[44]; keys mgr+304 by charaid (sec 4ew)"
                          % _wsi, flush=True)
            # sec 4gk: the selected character's gil and bag on the world door.
            # The request names the character at body[80] -- the same id every
            # later request carries at record+4, which keys its 145s.
            _shop_gil = _shop_bag = None
            if _shop is not None and _sel == 2:
                _lc = (struct.unpack_from("<I", data, BODY_OFF + 80)[0]
                       if len(data) >= BODY_OFF + 84 else 0)
                _lk = _wallet_key(seen_uid[0], _lc)
                _shop_gil, _shop_bag = _shop.login_fields(_lk)
                print("  [shop] selector 2 [%s]: gil %d at body[52], bag %d "
                      "item(s) at body[140]/[240+]: %s"
                      % (_lk, _shop_gil, len(_shop_bag),
                         ", ".join("%s x%d" % (_shop.name(i), q)
                                   for i, q in _shop_bag) or "(empty)"),
                      flush=True)
            # sec 4go: top the bag up with the issued bullets -- without them
            # every magazine stays 0 (0x004a5780) and the gun never fires.
            if _ammo and _sel == 2:
                _shop_bag = doc_shop.issue_items(_shop_bag, _ammo)
                print("  [ammo] selector 2: bag now %s (issued, not persisted; "
                      "sec 4go)" % ", ".join("0x%08x x%d" % (i, q)
                                             for i, q in _shop_bag), flush=True)
            if _sel == 2 and a.mission_supplies:
                _supply_bag[sess.key] = {
                    i: q for i, q in (_shop_bag or ())
                    if i in doc_missions.SUPPLY_ITEMS}
            # 2026-09-13: the starter MASK + SUIT, in the bag and equipped at
            # body[76]/[80] (doc_shop.starter_gear). The mask follows the
            # selected character's gender: chr_code bit 6, 1 = female (the
            # repacker 0x005a2598 reads it there).
            _gear_login = None
            if a.issue_gear == "standard" and _sel == 2:
                _gc = (struct.unpack_from("<I", data, BODY_OFF + 80)[0]
                       & 0x3FFFFFFF if len(data) >= BODY_OFF + 84 else 0)
                _female, _armor = False, 0
                if _store is not None and seen_uid[0]:
                    _gr = _store.roster(_skey(seen_uid[0]))
                    for _gi in range(doc_charastore.MAX_SLOTS):
                        if sess.chara_ids.get(_gi) == _gc and _gr[_gi]:
                            _code = doc_charastore.chr_code(_gr[_gi])
                            _female = bool(_code & 0x40)
                            _armor = doc_gear.armor_of(_code)
                            break
                # the suit follows the creation ARMOR pick (chr_code bits 3-5)
                _gear_login = doc_gear.starter_gear(_female, _armor)
                # 2026-09-26: the Soldier Mask is EARNED (Drone 2nd exam), not
                # issued -- worn only when the persisted bag holds one (a
                # character made before the rule keeps its own). Without a
                # shop there is no bag to hold it: the old issue stands.
                _mask_note = "issued (no --shop)"
                if _shop is not None:
                    _mw = _shop.wallet(_wallet_key(seen_uid[0], _gc))
                    _mheld, _mnotes = doc_gear.settle_soldier_mask(
                        _mw, _female, doc_shop.BAG_MAX)
                    if _mnotes:
                        _shop.save()
                    _gear_login = (_mheld if _mheld is not None
                                   else doc_gear.NO_ITEM, _gear_login[1])
                    _mask_note = ("held" if _mheld is not None
                                  else "none (earned on the Drone 2nd exam)")
                    if _mnotes:
                        _mask_note += "; " + "; ".join(_mnotes)
                _shop_bag = doc_shop.issue_items(
                    _shop_bag, [(i, 1) for i in _gear_login
                                if i != doc_gear.NO_ITEM])
                print("  [gear] selector 2 (char 0x%08x, %s): mask 0x%08x at "
                      "body[76] [%s], suit 0x%08x at body[80], in the bag"
                      % (_gc, "F" if _female else "M", _gear_login[0],
                         _mask_note, _gear_login[1]), flush=True)
            # 2026-09-13: the character's OWN mask/suit/costume once it has
            # changed them (doc_gear.GearStore, lobby commands 17/18). The
            # starter pair stays in the bag; --self-costume(-file) still win.
            if _gearstore is not None and _sel == 2:
                _gcl = (struct.unpack_from("<I", data, BODY_OFF + 80)[0]
                        if len(data) >= BODY_OFF + 84 else 0)
                _glk = _wallet_key(seen_uid[0], _gcl)
                if _gearstore.get(_glk) is not None:
                    _gm, _gsu, _gco = _gearstore.login(_glk, _gear_login, _self_cost)
                    _gear_login = (_gm, _gsu)
                    if (a.self_costume is None and not a.self_costume_file
                            and _gco is not None):
                        _self_cost = _gco
                    print("  [gear-store] selector 2 [%s]: mask 0x%08x, suit 0x%08x, "
                          "costume %s (the character's own changes)"
                          % (_glk, _gm, _gsu, "0x%04x" % _self_cost
                             if _self_cost is not None else "unset"), flush=True)
            # 2026-09-24: the HP follows the suit served at body[80] -- the
            # retail server's durability lookup (doc_gear.suit_hp).
            _hp_login = a.self_hp if (a.self_hp and _sel == 2) else None
            if _sel == 2 and _gear_login is not None:
                sess.suit_item = _gear_login[1]
            if a.suit_hp == "on" and _sel == 2 and _gear_login is not None:
                _shp = doc_gear.suit_hp(_gear_login[1])
                if _shp is not None:
                    _hp_login = _shp
                print("  [hp] selector 2: suit 0x%08x -> HP %s at body[48]%s"
                      % (_gear_login[1], _hp_login,
                         "" if _shp is not None else " (unknown suit, --self-hp)"),
                      flush=True)
            # 2026-09-13: the selected character's enlisted unit (or 0) on the
            # world door, keyed like its shop wallet (doc_unit.py).
            _unit_login = None
            if _units is not None and _sel == 2:
                _uc = (struct.unpack_from("<I", data, BODY_OFF + 80)[0]
                       if len(data) >= BODY_OFF + 84 else 0)
                _ulk = _wallet_key(seen_uid[0], _uc)
                _unit_login = _units.enlisted(_ulk)
                print("  [units] selector 2 [%s]: enlisted unit 0x%x at "
                      "body[60..67] (R+720)" % (_ulk, _unit_login), flush=True)
            # 2026-09-13: the selected character's career (doc_stats.py), keyed
            # like its shop wallet -- medal mask, rank points and rank.
            _career_login = None
            if _stats is not None and _sel == 2:
                _cc = (struct.unpack_from("<I", data, BODY_OFF + 80)[0]
                       if len(data) >= BODY_OFF + 84 else 0)
                _clk = _wallet_key(seen_uid[0], _cc)
                _career_login = _stats.peek(_clk)
                print("  [stats] selector 2 [%s]: rank %d, %d rank points, medal "
                      "mask 0x%06x at body[131]/[68]/[56]"
                      % (_clk, doc_stats.clamp_rank(_career_login["rank"]),
                         _career_login["rp"], doc_stats.medal_mask(_career_login)),
                      flush=True)
            # 2026-09-23 (sec 4hc): the selected character's NOVICE mark.
            _novice_login = False
            if (_novice is not None and a.novice == "on" and _sel == 2
                    and len(data) >= BODY_OFF + 84):
                _nvc = struct.unpack_from("<I", data, BODY_OFF + 80)[0]
                _nvk = _wallet_key(seen_uid[0], _nvc)
                _novice_login = _novice.is_novice(_nvk)
                print("  [novice] selector 2 [%s]: %s (body[129] bit 0x40 %s)"
                      % (_nvk, "NOVICE" if _novice_login else "graduated",
                         "SET" if _novice_login else "clear"), flush=True)
            wr = None if (_served_list or (_unpairable
                                           and not a.world_answer_unpairable)
                          or (a.peer_answer and _miss is not None)) else build_world_answer(
                data, selector=_sel, seq=a.lobby_seq,
                subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
                inner_ip=_lip, ptype=a.world_type, pad_to=a.world_pad,
                ident=_ident, result=_result, cmd_arg=_cmd_arg,
                # WARNING:KEY: sec 4dw: ONLY on the endpoint rungs, and NEVER empty.
                # WARNING: Two reasons this is keyed on the selector rather than just
                # passed through:
                #   * body[52..55] is the GAME SERVER IP on selector 21 and the
                #     SPAWN INDEX on selector 13 -- the same collision sec 4dh
                #     already had to guard once;
                #   * --world-gs-ip has always defaulted to "", which made the
                #     answer an all-zero endpoint rather than no endpoint. A
                #     rung nobody had ever reached, so nobody noticed.
                # The default is the --gs-connect endpoint, so the two paths
                # that write the same sockaddr cannot disagree.
                gs_ip=(_gsip if _sel in GS_ENDPOINT_SELECTORS else None),
                gs_port=(a.world_gs_port or a.gs_connect_port),
                gs_id=a.gs_connect_id,
                spawn=_spawn, self_probe=a.self_costume_probe,
                self_costume=_self_cost,
                self_id=_world_self_id,
                self_hp=_hp_login,
                self_name=_self_name,
                self_gil=_shop_gil, self_bag=_shop_bag,
                self_unit=_unit_login,
                self_career=_career_login,
                self_gear=_gear_login,
                self_novice=_novice_login)
            if wr is not None:
                # 2026-09-23 (sec 4hc): the lobby spawn is the client entering
                # the lobby -- queue the intro push for a character that has
                # never confirmed it (command 27 id 1), once per session.
                if (_sel == WORLD_SPAWN_SELECTOR_ANS and a.intro == "on"
                        and _novice is not None and seen_charid[0]
                        and sess.key not in _intro_sent
                        and sess.key not in _intro_due):
                    _ik = _novice_key(sess)
                    if _ik is not None and not _novice.intro_seen(_ik):
                        _intro_due[sess.key] = time.time() + a.intro_delay
                        print("  [intro] [%s] has not seen the new-player intro "
                              "-- pushing it in %.1f s (selector 134 sub 10 event 1)"
                              % (_ik, a.intro_delay), flush=True)
                if _spawn is not None and _sel == WORLD_SPAWN_SELECTOR_ANS:
                    print("  [spawn] selector %d carrying (%.1f, %.1f, %.1f) index %d "
                          "at body[28..53]. The oracle is the emulog's own "
                          "copyMatrixFromActor() line, NOT this one -- it prints the "
                          "actor's matrix and its Y is ours minus 3.0."
                          % ((WORLD_SPAWN_SELECTOR_ANS, _spawn[0], _spawn[1],
                              _spawn[2], _spawn[6])), flush=True)
                if _cmd_arg is not None:
                    print("  [cmd] command %d is PLAY TIME -- serving %d s "
                          "at body[16]. The client caches it with a local tick and "
                          "extrapolates; it asks ONLY while [kelsvc+256] == 0, so "
                          "the proof is that command 20 STOPS."
                          % (LOBBY_CMD_CLOCK, _cmd_arg), flush=True)
                if _cmd is not None:
                    print("  [cmd] selector %d -> %d carrying COMMAND %d "
                          "(was 0, which could never dispatch; sec 4cy). Watch "
                          "the emulog: an arm that RUNS is the proof."
                          % (LOBBY_CMD_SELECTOR_REQ, LOBBY_CMD_SELECTOR_ANS,
                             _cmd), flush=True)
                if _cmd == LOBBY_CMD_RETURN and seen_charid[0]:
                    # a player who ARRIVED in a running room and returns to the
                    # lobby has left it; fire_battles ends an empty room and
                    # close_battle dissolves its table (live: the quit
                    # Wastelands table stayed listed, its room ran on).
                    _rr = battle_of(seen_charid[0])
                    if (_rr is not None and not _rr.over
                            and seen_charid[0] in _rr.arrived
                            and _rr.mission is not None
                            and len(_rr.present()) <= 1):
                        # quitting a solo MISSION showed the
                        # client's own result screen with the WIN bits left by
                        # the previous battle ([chan+1388] is written only by
                        # kind 4). End it as a quit instead: kind 4 carries the
                        # mission verdict (a LOSS -- no objective), the tally
                        # records a failed mission, selector 39 resets as after
                        # any battle.
                        print("  [battle] 0x%08x QUIT solo mission table %d "
                              "(command 4) -- ending it with its verdict"
                              % (seen_charid[0], _rr.key), flush=True)
                        end_battle(_rr, time.time(), "player quit the mission")
                    elif (_rr is not None and not _rr.over
                            and seen_charid[0] in _rr.arrived):
                        _was_ldr = _rr.is_team_leader(seen_charid[0])
                        _nl = _rr.leave(seen_charid[0])
                        if _was_ldr:
                            tag_leaders(_rr, [seen_charid[0]], False,
                                        "returned to the lobby")
                        tag_leaders(_rr, list(_nl.values()), True,
                                    "took over as leader")
                        print("  [battle] 0x%08x RETURNED TO LOBBY (command 4) "
                              "-- LEFT table %d's room, %d still in it"
                              % (seen_charid[0], _rr.key, len(_rr.present())),
                              flush=True)
                        # the client's own warning (0x5c0d): leaving partway
                        # reduces rank points. Amount unknown -> flag, 0 = off.
                        if _stats is not None and a.leave_rp_penalty > 0:
                            _lk = _wallet_key(seen_uid[0], seen_charid[0], sess)
                            _ls = _stats.record_leave(
                                _lk, a.leave_rp_penalty, _rr.rules.mode,
                                time.time() - (_rr.started or time.time()),
                                rid=seen_charid[0])
                            print("  [stats] [%s] LEFT a running battle: %d rank "
                                  "points (--leave-rp-penalty %d)"
                                  % (_lk, _ls["rp"], a.leave_rp_penalty),
                                  flush=True)
                # 2026-09-13: the quest-detail answer names the quest's MAP --
                # the Solo screen label read "Jungle" (entry 0) for every quest.
                # Index = the arena zone's own roster index, from the same
                # --quest-zones.  WARNING: 2026-09-23: this used to be `zone - 201`,
                # "the list parallels zones 201..212 by index; inferred". Sec
                # 4hb MEASURED that parallel and it holds only for 201..208 --
                # z209 is 倉庫 (roster 14), not roster 8. _zone_map is the
                # measured inverse; the old arithmetic survives as the fallback
                # for a hand-set --quest-zones outside the decoded table, and is
                # now capped where it was actually right.
                if (_cmd == LOBBY_CMD_QUEST and a.quest_mission
                        and len(wr) > BODY_OFF + QUEST_DETAIL_MAP_OFF):
                    _qp41 = _quest_pick.get(sess.key)
                    if _qp41:
                        _qz = _quest_zone.get(_qp41[0], a.gs_battle_zone)
                        _qmap = _zone_map.get(
                            _qz, _qz - 201 if 201 <= _qz <= 208 else 0)
                        _wb = bytearray(wr)
                        _wb[BODY_OFF + QUEST_DETAIL_MAP_OFF] = _qmap & 0xFF
                        _wb[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
                        _wb[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(_wb))
                        wr = bytes(_wb)
                        print("  [quest] command 41 answer: quest %d -> map "
                              "index %d (zone %d) at body[%d]"
                              % (_qp41[0], _qmap, _qz, QUEST_DETAIL_MAP_OFF),
                              flush=True)
                if (_cmd == LOBBY_CMD_QUEST_INFO and a.quest_mission
                        and len(wr) > BODY_OFF + 38):
                    _qb29 = request_body(data, inner)
                    _qp29 = _quest_pick.get(sess.key)
                    _q29 = (_qp29[0] if _qp29 else
                            (struct.unpack_from("<H", _qb29, 16)[0]
                             if _qb29 is not None and len(_qb29) >= 18 else 0))
                    if _q29:
                        _wb = bytearray(wr)
                        struct.pack_into("<H", _wb, BODY_OFF + 16, _q29)
                        _wb[BODY_OFF + 37] = doc_missions.players(_q29)
                        _wb[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
                        _wb[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(_wb))
                        wr = bytes(_wb)
                    print("  [quest] command 29 (quest info) answered with quest "
                          "%d at body[16], limit %d at body[37] (doc_missions."
                          "players)" % (_q29, doc_missions.players(_q29)),
                          flush=True)
                for _i in range(max(1, a.world_burst)):
                    s.sendto(wr, src)
                    time.sleep(a.chara_burst_ms / 1000.0)
                # req body[1] is the client's own selector and body[4] its command;
                # both are CIPHERTEXT on the 132-byte phase-27 request (mode 1, sec
                # 4bj) but are worth printing for every round -- this log line is how
                # phases 29 and 31 get identified on the wire.
                # KEY: sec 4ca: some answer arms do their job WITHOUT clearing the
                # pending marker. Selector 13 is the one that bites: it releases
                # phase 30 (state 2 + [kelsvc+1064]) and the client reaches the
                # game, but bit 31 of [kelsvc+28] stays set, so 10 s later the
                # deadline in 0x00589af0 returns -2 -> CER-47117. Follow it with
                # the bare ack (selector 128, arm 0x00bcd4a4: clear bit 31, set
                # state 2, nothing else). Proven offline against a savestate
                # captured WITH the bit set: 13 alone leaves pending=1, 13 then
                # 128 leaves pending=0 with state and [+1064] unchanged.
                # KEY: sec 4dx: THE BATTLE-READY FLAG, ON A REAL TRIGGER.
                # Selector 38 was disarmed at world entry because it dragged the
                # player into the briefing room with no match behind it (sec
                # 4df/4di). It was never wrong -- it was early. Selector 21 is
                # the phase-44 answer, the last rung of a reservation that
                # actually completed (sec 4dw), which is the first moment in
                # this protocol where "your battle instance is ready" is a true
                # statement.
                # sec 4fm (live 2026-09-12): the trigger that is TRUE for a
                # solo leader. Start Immediately -> 0x00AA2218 -> zone flag 10
                # -> start_onlinebattle -> netclient bit 0x40 -> kelsvc vt+604
                # 0x00bd1db8 = lobby COMMAND 3 (seen on the wire at 21:48:10,
                # body[12]=03, 100 s after the CREATE). Its 241 arm is a no-op;
                # what the client waits for next is 38 -> [chan+2148] = 1 ->
                # its game-server hello (--gs-connect answers that ladder).
                _start_now = (_cmd == LOBBY_CMD_START
                              and not a.bt_no_start_ready)
                if _start_now:
                    # sec 4he: command 3 is RETRANSMITTED like every reliable
                    # request; a second copy re-ran the whole Start (38 again,
                    # timers zeroed, the chosen teams wiped). One per 10 s.
                    _ls = _start_seen.get(sess.key, 0.0)
                    _start_seen[sess.key] = time.time()
                    if time.time() - _ls < 10.0:
                        _start_now = False
                        print("  [cmd] command 3 (START) again %.1f s after the "
                              "last -- a retransmit, 241 only (sec 4he)"
                              % (time.time() - _ls), flush=True)
                if _start_now:
                    print("  [cmd] command %d is START (start_onlinebattle) -- "
                          "pushing BATTLE READY (selector %d) behind the 241 "
                          "(sec 4fm)" % (LOBBY_CMD_START, GS_READY_SELECTOR),
                          flush=True)
                if _sel in _gs_ready_after or _start_now:
                    # WARNING:KEY: sec 4gv (2026-09-23): RE-DECLARE THE ENDPOINT FIRST.
                    # Selector 38 rides the LOBBY channel and always lands; the
                    # message-27 re-arm four statements below rides the GAME
                    # SERVER channel, whose receive handler drops anything whose
                    # source != [chan+184..191]. That sockaddr was written once,
                    # at --gs-connect, and any channel reset since has wiped it.
                    # Live (table 2): the peer
                    # with a 2 m 10 s connect->Start gap sent 0 game-server
                    # hellos and its [chan+212] was still the uninitialised
                    # 65528 -- not one of our datagrams was ever accepted.
                    # ORDER: 104 FIRST (it is what makes the next two
                    # deliverable), then 38, then the arm LAST -- 38's
                    # 0x00bc0260 zeroes [chan+204] (sec 4eb). Re-running 104 on
                    # a healthy channel is measured harmless (sec 4cx).
                    if a.gs_connect and a.gs_start_endpoint:
                        send_gs_endpoint(src, seen_charid[0],
                                         why="Start, leader")
                    _rd = build_world_answer(
                        data, selector=GS_READY_SELECTOR, seq=a.lobby_seq,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7),
                        inner_ip=None, ptype=a.world_type, pad_to=a.world_pad,
                        ident=_ident)
                    if _rd is not None and a.gs_ready_roster:
                        # 2026-09-13: the leader's command 3 carries ident 0
                        # (26c502ee), so by ident the table was never found and
                        # the leader's own roster went out EMPTY (count 0 -- the
                        # all-zero [chan+2144] in its briefing savestate). Fall
                        # back to the session's charid, as start-all does.
                        _me38 = _ident or seen_charid[0] or 0
                        _tk = bt_store.table_of(_me38)
                        _rec38 = bt_store.record(_tk) if _tk else None
                        # 2026-09-13: a Start right after a Solo quest pick is
                        # that quest -> cut 38's record as a MISSION (one use).
                        _qp = _quest_pick.pop(sess.key, None) if _start_now else None
                        if (_qp and a.quest_mission
                                and time.time() - _qp[1] <= a.quest_pick_window):
                            if _rec38 is None:
                                _rec38 = bytes(build_battletable_record(
                                    table_id=a.gs_connect_id & 0xFFFF,
                                    leader=seen_uid[0], cur=1, maximum=1))
                                if bt_store.situation:
                                    _rec38 = bytearray(_rec38)
                                    struct.pack_into("<H", _rec38,
                                                     BT_OFF_SITUATION,
                                                     bt_store.situation)
                            _rec38 = quest_mission_record(
                                _rec38, _qp[0], flags=BT_FLAG_MISSION,
                                situation=_quest_sit.get(_qp[0], 0))
                            # live 09-13: the quest RAN ("1-player MS", sentry
                            # robots) but our team scaffolding took the count
                            # 1 -> 5. A mission seats the player alone: drop
                            # the session's old team map (bots from an earlier
                            # battle linger there) and mark it for the 31 path.
                            _mission_battle[sess.key] = _qp[0]
                            sess.gs_teams.clear()
                            print("  [quest] START after Solo quest %d -> 38 as "
                                  "a MISSION (flags |0x%08x, mission %d, "
                                  "situation %d, table %s)"
                                  % (_qp[0], BT_FLAG_MISSION, _qp[0],
                                     struct.unpack_from("<H", _rec38,
                                                        BT_OFF_SITUATION)[0],
                                     _tk), flush=True)
                        else:
                            _mission_battle.pop(sess.key, None)
                        # RETAIL picks a mission with command
                        # 29 and CREATEs a mission table itself, so the quest-pick
                        # branch above never runs and the table's own situation
                        # (1100, the PvP set) went out -- no enemies. A mission's
                        # enemies load only from a 3000+ set (mdlResLoad), so any
                        # mission-flagged record gets its quest's --quest-situations.
                        if _rec38 is not None and len(_rec38) > BT_OFF_SITUATION + 1:
                            _mfl = struct.unpack_from("<I", _rec38, BT_OFF_FLAGS)[0]
                            _mq = struct.unpack_from("<H", _rec38, BT_OFF_MISSION)[0]
                            if (_mfl & BT_FLAG_MISSION) and _mq in _quest_sit:
                                _rec38 = bytearray(_rec38)
                                struct.pack_into("<H", _rec38, BT_OFF_SITUATION,
                                                 _quest_sit[_mq])
                                _rec38 = bytes(_rec38)
                                print("  [quest] mission table %s, quest %d -> 38 "
                                      "situation %d (--quest-situations)"
                                      % (_tk, _mq, _quest_sit[_mq]), flush=True)
                        _rd = gs_ready_roster(
                            _rd, _me38, a.gs_connect_id,
                            bt_store.members(_tk) if _tk else (),
                            rec=rec_for(_rec38, _gs_endpoint, src[0]))
                    if _rd is not None:
                        s.sendto(_rd, src)
                        # sec 4fn: a fresh briefing room -> the once-per-38 state
                        # (bot push, join timer) starts over.
                        gs_join_deadline[0] = 0.0
                        gs_bots_sent[0] = False
                        sess.gs_battle_on[0] = 0.0     # sec 4fy: a new battle
                        sess.gs_battle_end[0] = 0.0
                        sess.gs_battle_reset[0] = 0.0
                        sess.gs_battle_go[0] = 0.0
                        print("  SENT type-%d BATTLE READY (selector %d) after "
                              "answer selector %d -- the sole writer of "
                              "[chan+2148] = 1. Watch for the client's first "
                              "type-0x82 (its game-server hello) and for "
                              "br_main / the team prompt (sec 4dx)"
                              % (a.world_type, GS_READY_SELECTOR, _sel),
                              flush=True)
                        # sec 4eb (live 09-11): 38's routine 0x00bc0260 does
                        # `[chan+204] = 0`, which DROPS the armed bit message 27
                        # set at world entry. Unarmed, the receive preamble never
                        # refreshes [chan+224], and 40 s after 38 the client
                        # printed `timeout gameserver 40007` -> CER-48101. Send
                        # the arm again right behind 38.
                        _st2 = []
                        for _pair in (a.gs_stats or "").replace(" ", "").split(","):
                            if not _pair:
                                continue
                            _k2, _, _v2 = _pair.partition(":")
                            _st2.append((int(_k2, 0), int(_v2, 0)))
                        s.sendto(build_gs_stats(_st2, state=a.gs_arm_state,
                                                seq=next_gs_seq(sess),
                                                ident=_ident or 0), src)
                        gs_ka_src[0] = src
                        gs_ka_next[0] = time.time() + a.gs_keepalive_ms / 1000.0
                        sess.gs_rearm_pending[0] = a.gs_rearm_until_team
                        print("  SENT GAME-SERVER RE-ARM (message %d) behind selector "
                              "38 -- 0x00bc0260 zeroed [chan+204], so the arm bit "
                              "was gone and no packet refreshed the 40 s stamp "
                              "(CER-48101 live 09-11, sec 4eb)" % GS_ARM_MSG,
                              flush=True)
                        sess.gs_src[0] = None    # sec 4ft: a new briefing room
                        # sec 4ft: only the LEADER sends command 3, so fan the
                        # same 38 + re-arm out to every other seated member --
                        # otherwise a joiner never leaves the lobby.
                        if _start_now and a.bt_start_all:
                            _sk, _lead, _others = bt_start_targets(
                                bt_store, _ident, seen_charid[0])
                            if _sk is None:
                                print("  [start-all] leader 0x%08x is not seated "
                                      "at any table -- nobody to fan 38 out to"
                                      % (_lead or 0), flush=True)
                            else:
                                gs_tables.pop(_sk, None)
                                # 2026-09-23: the briefing countdown's end =
                                # the record's Briefing Time, else the knob
                                _brec = bt_store.record(_sk)
                                _bsec = (float(_brec[BT_OFF_BRIEFING]) * 60.0
                                         if _brec and len(_brec) > BT_OFF_BRIEFING
                                         else 0.0) or a.gs_auto_team_after
                                if a.gs_auto_team_after >= 0:
                                    gs_table_state(_sk)["auto_at"] = (
                                        time.time() + _bsec + 2.0)
                                    print("  [start-all] table %d: anyone "
                                          "without a team is auto-teamed in "
                                          "%.0f s (end of the briefing)"
                                          % (_sk, _bsec + 2.0), flush=True)
                                print("  [start-all] leader 0x%08x START at table "
                                      "%d -> other seated: %s"
                                      % (_lead, _sk, ["0x%x" % m for m in _others]),
                                      flush=True)
                                for _m in _others:
                                    _ms = session_of(_m)
                                    if _ms is None or _ms is sess:
                                        print("  [start-all] seated member "
                                              "0x%08x has no live session -- "
                                              "it stays in the lobby" % _m,
                                              flush=True)
                                        continue
                                    try:
                                        push_battle_ready(_ms, _sk)
                                    except Exception:
                                        import traceback
                                        print("  [start-all] push to 0x%08x "
                                              "FAILED:\n%s"
                                              % (_m, traceback.format_exc()),
                                              flush=True)
                if _sel in _pending_ack_after:
                    pa = build_world_answer(
                        data, selector=a.pending_ack_selector, seq=a.lobby_seq,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7),
                        inner_ip=_lip, ptype=a.world_type,
                        pad_to=a.world_pad, ident=_ident)
                    if pa is not None:
                        s.sendto(pa, src)
                        print("  SENT type-%d bare ACK (selector %d) after answer "
                              "selector %d -- clears the pending marker, sec 4ca"
                              % (a.world_type, a.pending_ack_selector, _sel),
                              flush=True)
                print("  SENT type-%d WORLD answer x%d (req selector %s -> answer "
                      "selector %d, body[0]=%d, ident=%s) <- req len=%d mode=%d "
                      "reqbody[0..7]=%s%s"
                      % (a.world_type, max(1, a.world_burst),
                         _req_sel, _sel,
                         wr[BODY_OFF] if len(wr) > BODY_OFF else -1,
                         "0x%08x" % _ident if _ident is not None else "lobby-ip",
                         len(data), data[1],
                         (_plain if _plain is not None else data)
                         [BODY_OFF:BODY_OFF + 8].hex(" "),
                         "  [decrypted]" if _plain is not None else ""), flush=True)

        # THE DELETE ANSWER.  Pressing DELETE on a slot sends a 40-byte mode-2
        # message whose body is `05 11 00 00 <slot> ...` -- selector 17, an odd
        # (request) selector, with the slot index at body[4].  Same shape as the
        # charamake: the request parks the nest at a state and the server owes the
        # paired even code.  Per the sec 4ao ladder the code gated on state 11 is
        # 18 (handler 0x00587f00).
        if (a.delete_answer and sess.ka_template is not None
                and len(data) >= BODY_OFF + 2 and data[BODY_OFF + 1] == 17):
            dl = build_lobby_advance(sess.ka_template, selector=18, seq=a.lobby_seq,
                                     inner_ip=_lip, empty_records=True)
            if dl is not None:
                for _i in range(max(1, a.charamake_burst)):
                    s.sendto(dl, src)
                    time.sleep(a.chara_burst_ms / 1000.0)
                print("  SENT selector-18 DELETE ACK x%d (slot %d, state 11 -> ..)"
                      % (max(1, a.charamake_burst), data[BODY_OFF + 4]
                         if len(data) > BODY_OFF + 4 else -1), flush=True)
            if _store is not None and seen_uid[0] and len(data) > BODY_OFF + 4:
                _slot = data[BODY_OFF + 4]
                if _store.delete(_skey(seen_uid[0]), _slot):
                    refresh_roster(seen_uid[0])
                    print("  [chara] DELETED slot %d for 0x%08x, PERSISTED"
                          % (_slot, seen_uid[0]), flush=True)

        # THE CHARAMAKE ANSWER.  REGISTER sends a 232-byte mode-2 message (sec 4bc:
        # name at wire+104, appearance nibbles at wire+92/93/127) and parks the nest
        # at STATE 10.  Phase 10's poll 0x00588cf8 spins while [nest+8] == 10, so the
        # client sits there until we move it -- that is the -47111(phase = 10) death.
        # The response code gated on state 10 is 16, whose handler 0x00587e98 is
        # blunt: optionally copy a record via [nest+0xE8], then [nest+8] = 2. Once it
        # is 2 the poll returns [nest+20] or 1 -- positive -- and phase 10 advances.
        #
        # Built from the 96-byte TEMPLATE, never from the request: the 232-byte body
        # starts 0xb9, and the classifier 0x005895b0 rejects anything whose body[0]
        # exceeds [nest+12] == 5, so a reply echoing that body would never be read.
        if (a.charamake_answer and sess.ka_template is not None
                and len(data) == a.charamake_len):
            # 2026-09-13: store FIRST, so the answer can carry the new
            # character's record and the select list updates in place
            # (build_charamake_answer). Without a store: the old empty ACK.
            _new_rec = None
            if _store is not None and seen_uid[0]:
                _c = doc_charastore.parse_register(data)
                if _c is not None and _c.get("name"):
                    _slot = _store.add(_skey(seen_uid[0]), _c)
                    refresh_roster(seen_uid[0])
                    print("  [chara] REGISTERED '%s' (voice %d, gender %d) -> "
                          "slot %s for 0x%08x, PERSISTED" %
                          (_c["name"], _c["voice"], _c["gender"], _slot,
                           seen_uid[0]), flush=True)
                    if isinstance(_slot, int) and 0 <= _slot < doc_charastore.MAX_SLOTS:
                        _new_rec = build_used_record(
                            _slot, _c["name"], _c,
                            char_id=chara_id_for(a.chara_id_base, seen_uid[0],
                                                 _skey(seen_uid[0]), _slot),
                            chr_code=a.chara_chrcode)
            if _new_rec is not None:
                cm = build_charamake_answer(sess.ka_template, data, _new_rec,
                                            seq=a.lobby_seq, inner_ip=_lip)
            else:
                cm = build_lobby_advance(sess.ka_template, selector=16,
                                         seq=a.lobby_seq, inner_ip=_lip,
                                         empty_records=True)
            if cm is not None:
                for _i in range(max(1, a.charamake_burst)):
                    s.sendto(cm, src)
                    time.sleep(a.chara_burst_ms / 1000.0)
                print("  SENT selector-16 CHARAMAKE ACK x%d (state 10 -> 2, releases "
                      "phase 10)%s" % (max(1, a.charamake_burst),
                                       " CARRYING the new record (slot %d)" % _new_rec[84]
                                       if _new_rec is not None else ""), flush=True)
        if (a.nest_quiet_after_frag3 > 0 and sess.frag3_sent >= a.nest_quiet_after_frag3
                and is_lobby(data) and not _is_close_request(data)):
            # Phase 110 waits for [nest+8] == 0.  Going quiet was the WRONG read of
            # that (the nest does not close on its own -- it closes on an inbound
            # selector 4, see _is_close_request), so the close request is answered
            # even here.  See --nest-quiet-after-frag3.
            reply = None
            print("  (nest QUIET after %d frag3 -- not answering, so [nest+8] can "
                  "reach 0 for phase 110)" % sess.frag3_sent, flush=True)
        elif a.lobby_probe != "off" and is_lobby(data):
            # The lobby (type-129) sub-connection ignores the type-128 redirect;
            # answer it on its own terms.
            if a.lobby_probe == "advance" and _is_close_request(data):
                # THE NEST CLOSE.  Phase 109 calls the nest's vtable+220
                # (0x00587a98), which builds a message with selector 3 and hands it
                # to 0x005899d0 -> [nest+8] = 4.  Phase 110 then polls 0x00587b40,
                # which returns 1 only when [nest+8] == 0.  The ONLY thing that
                # clears state 4 is an inbound SELECTOR 4 (classifier 0x005895b0 arm
                # 0x00589690), after which the router's code-4 arm 0x005880f8 runs
                # the reset 0x005894a8.  PROVEN offline end to end, on kel's own code
                # against a live nest: an offline run of the client's own code (doc_close_proof).
                #
                # Answering the selector-3 request with anything else (our code-8,
                # or silence) leaves the nest at 4 forever and phase 110 never
                # advances -- that is CER-48103, sec 4ay.
                reply = build_lobby_advance(
                    data, selector=4, seq=a.lobby_seq, inner_ip=_lip,
                    empty_records=True)
                note = "CLOSE ack sel=4 (answers the client selector-3 close request)"
            elif a.lobby_probe == "advance":
                # Only the 96-byte type-129 packets carry the body the nest driver
                # dispatches on.  Two selectors drive the connection forward:
                #   selector 2  -> m5 advances the nest 1->2  (first handshake step)
                #   selector 8  -> state-6 handler 0x00587c10 advances 6->2, which
                #                  self-advances 2->6 and RE-STAMPS the liveness the
                #                  10s watchdog watches -> defeats CER-48103 AND pulls
                #                  the next user-data chunk.  (PROVEN offline against a
                #                  live state-6 savestate: doc_state6_router.py.)
                # State-1 and state-6 requests are byte-identical on the wire, so we
                # can't read the state.  Send BOTH replies to EVERY 96-B packet:
                #   selector 2 advances 1->2 and is a no-op at every other state (the
                #     driver gates m5 on nest[8]==1), and selector 8 advances 6->2 and
                #     is a no-op before state 6.  Neither interferes with the other.
                # NB: do NOT gate selector-2 on a per-run counter -- the responder is a
                # long-lived process, so a lifetime counter skips selector-2 on the 2nd
                # boot and the nest never leaves state 1 (MEASURED: state-1 savestates,
                # 14 s disconnect).  --lobby-sel2-count 0 disables selector-2 entirely.
                if len(data) == 96:
                    if a.lobby_sustain_selector:
                        reply = build_lobby_advance(
                            data, selector=a.lobby_sustain_selector,
                            seq=a.lobby_seq, inner_ip=_lip, empty_records=True,
                            **sess.chara_kw)
                        if a.lobby_sel2_count != 0:
                            extra_reply = build_lobby_advance(
                                data, selector=a.lobby_selector,
                                seq=a.lobby_seq, inner_ip=_lip)
                    else:
                        reply = build_lobby_advance(data, selector=a.lobby_selector,
                                                    seq=a.lobby_seq, inner_ip=_lip)
                    note = ("advance sel=%d" % (a.lobby_sustain_selector or a.lobby_selector)
                            + (" +sel2" if extra_reply else ""))
                elif sess.chara_kw and len(data) == 36 and data[BODY_OFF + 1] == 7:
                    # THE ONE STATE-6 WINDOW.  0x005884d0 (the 2->6 arm) is the only
                    # thing that puts the nest in state 6, and it does so at the moment
                    # it TRANSMITS selector 7 -- this packet.  The code-8 handler
                    # 0x00587c10 is gated on [nest+8]==6 and drops the nest to 2 on the
                    # first acceptance, so there is exactly one chance per window, and
                    # the client may never open another: boot 13:22 saw ONE selector-7
                    # in the whole session, and char stayed 0 even though all 17 of our
                    # code-8s carried body[16..17] = 10 01.
                    # A code-8 at any other state is a PROVEN no-op (the state sweep in
                    # an offline run of the client's own code (doc_code8_wire_proof)), so repeating it costs nothing.
                    reply = build_lobby_advance(
                        data, selector=(a.lobby_sustain_selector or 8),
                        seq=a.lobby_seq, inner_ip=_lip, **sess.chara_kw)
                    if a.chara_on_request:
                        # MEASURED (savestate 15:41:32, inside the held window):
                        # [nest+8]=2 with the armed HIGH bit CLEAR is the code-8
                        # arm's own signature -- it clears that bit only after its
                        # state==6 check and then the handler sets 2. So the code-8
                        # WAS accepted. But [nest+0xF4] was untouched, and holds
                        # byte-identical garbage across three boots: the client had
                        # not yet pointed that field at the real buffer, so our count
                        # landed somewhere else and the one window was spent.
                        # Leaving selector-7 UNANSWERED parks the nest at 6 (armed),
                        # and the watchdog budget is [nest+4]=40000 ~ 20 s while the
                        # 00 01 request lands ~4 s later.  Answer then instead.
                        sess.chara_pending = reply
                        reply = None
                        note = ('CHARA code-8 HELD for the 00 01 request '
                                '(nest parked at 6)')
                    else:
                        note = ('CHARA code-8 to the SELECTOR-7 window (count=%d, '
                                'burst=%d)'
                                % (sess.chara_kw.get('chara_count', 0), a.chara_burst))
                        chara_burst_now = True
                elif data[1] == 4:
                    # sec 4eb: a MODE-4 datagram is the game-server channel (the
                    # client's 36-byte keepalive `01 00 ..` every 7 s). It was
                    # answered above by name; the 424-byte nest roster this arm
                    # used to send it is what the emulog logged as bad packets.
                    reply = None
                    note = "mode-4 game-server datagram, answered by the GS ladder"
                elif len(data) == 36 and data[BODY_OFF] == 7:
                    # the 2026-09-05 audit (D): body[0] == 7 is the KELSVC
                    # subchannel, not the nest (5).  In world the client sends a
                    # 36-byte unreliable `07 05 ...` every ~4 s (624 in two
                    # sessions) and the arm below answered every one with a
                    # 424-byte type-129 roster the closed nest ignores.  Selector 5
                    # is a DRIVER arm (0x005895b0 handles 2/4/5/6 itself) that has
                    # never been read; log it and leave it alone.
                    reply = None
                    note = ("log-only (KELSVC subchannel 7, selector %d, 36-byte "
                            "poll -- no nest roster here; the arm is unread)"
                            % data[BODY_OFF + 1])
                elif sess.chara_kw and len(data) == 36:
                    # THE CHARACTER-SELECT EXPERIMENT (an earlier run).  In the
                    # mode-2 phase the client stops sending 96-byte packets, so the
                    # selector-8 reply above never fires and the code-8 handler never
                    # runs -- which is exactly the phase the character-select screen
                    # sits in.  Answer the 36-byte mode-2 packet on its own terms: a
                    # MODE-0 code-8 whose body we build from the client own (its body
                    # is plaintext: 05 07 00 00 01 ... = subchannel 5, selector 7),
                    # padded out to the 20-byte chara header.  Mode 0 is a verified
                    # no-op on the client decrypt path, so no cipher is needed here.
                    reply = build_lobby_advance(
                        data, selector=(a.lobby_sustain_selector or 8),
                        seq=a.lobby_seq, inner_ip=_lip, **sess.chara_kw)
                    note = ("CHARA code-8 to 36-B mode-2 (count=%d)"
                            % sess.chara_kw.get("chara_count", 0))
                else:
                    reply = None
                    note = "log-only (not a 96-byte type-129)"
            else:  # echo
                reply = bytearray(data)
                note = "echo"
                if len(data) == 96:
                    for off, val in lobby_edits:
                        if off < len(reply):
                            reply[off] = val
                            note = "edit [%d]=%02x" % (off, val)
                reply = bytes(reply)
            print("  (lobby packet -> probe=%s %s)" % (a.lobby_probe, note), flush=True)
        else:
            reply = build_reply(data, a.mode, a.subtype, a.crypto, a.body_len,
                                a.mode_byte, not a.no_cksum, a.ptype, a.flags,
                                _lip, a.lobby_port)
        # Reliable-ACK sweep: cancel the framework's retransmit of its pending
        # message (sec 4ae).  The client's seq is encrypted, so sweep [lo,hi].
        if a.reliable_ack_lo >= 0 and a.lobby_probe != "off" and is_lobby(data):
            nack = 0
            for seq in range(a.reliable_ack_lo, a.reliable_ack_hi + 1):
                s.sendto(build_reliable_ack(seq), src)
                nack += 1
            print("  SENT %d reliable ACKs (seq %d..%d) to %s:%d"
                  % (nack, a.reliable_ack_lo, a.reliable_ack_hi, src[0], src[1]), flush=True)

        if extra_reply is not None:
            s.sendto(extra_reply, src)
            print("  SENT %d bytes (selector-2 pre-advance) to %s:%d"
                  % (len(extra_reply), src[0], src[1]), flush=True)
            print(hexdump(extra_reply, indent="    2 "), flush=True)
        if reply is not None and chara_burst_now and a.chara_burst > 1:
            # Fire the extra copies first, so the whole burst sits as close to the
            # client own transmit as possible.
            for _i in range(a.chara_burst - 1):
                s.sendto(reply, src)
                time.sleep(a.chara_burst_ms / 1000.0)
            print('  SENT %d extra CHARA code-8 copies (%d ms apart) to cover the '
                  'state-6 window' % (a.chara_burst - 1, a.chara_burst_ms), flush=True)
            sess.chara_burst_at = datetime.datetime.now().timestamp()
            if a.frag3_hold_s > 0:
                print('  >>> SAVESTATE WINDOW OPEN for %.0f s -- the frag3 answer is '
                      'held, the client is parked in phase 3' % a.frag3_hold_s,
                      flush=True)
        if reply is not None:
            s.sendto(reply, src)
            answered += 1
            print("  SENT %d bytes back to %s:%d" % (len(reply), src[0], src[1]), flush=True)
            print(describe(reply), flush=True)
            # sec 4fl: a successful JOIN was answered with the selector-21
            # endpoint above; 0x00bca9cc clears the reservation on the way in,
            # so the 152 echo must FOLLOW it.
            if _bt_echo_key is not None and not a.bt_no_reserve_echo:
                s.sendto(build_reserve_echo(
                    data, _bt_echo_key, seq=a.lobby_seq,
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7),
                    ptype=a.world_type, pad_to=a.world_pad, ident=_ident), src)
                print("  SENT RESERVATION ECHO (selector 152, unsolicited) for "
                      "table %d after the JOIN-ok (sec 4fl)" % _bt_echo_key,
                      flush=True)
            print(hexdump(reply, indent="    > "), flush=True)

        # THE LOBBY REQUEST ANSWER.  Only for 80-byte type-128 packets whose body
        # tail is `00 01` -- the two requests (33 c1 / b3 44) that go unanswered
        # today.  The entrance (tail `00 02`) is deliberately excluded: sending
        # subtype 3 to it broke the handshake live (sec 4aw).
        if (sess.chara_pending is not None and len(data) == 80
                and data[76:78] == b"\x00\x01"):
            # Phase 2 has now issued the request, so [nest+0xF4] points where the
            # list is actually read from.  Send the held code-8 BEFORE the frag3
            # answer, because the frag3 answer is what releases phase 3 -> phase 4.
            for _i in range(max(1, a.chara_burst)):
                s.sendto(sess.chara_pending, src)
                time.sleep(a.chara_burst_ms / 1000.0)
            print("  SENT the HELD CHARA code-8 x%d on the 00 01 request -- "
                  "AFTER phase 2 set the buffer" % max(1, a.chara_burst), flush=True)
            sess.chara_pending = None
            sess.chara_burst_at = datetime.datetime.now().timestamp()
            if a.frag3_hold_s > 0:
                print("  >>> SAVESTATE WINDOW OPEN for %.0f s -- the frag3 answer is "
                      "held, the client is parked in phase 3" % a.frag3_hold_s,
                      flush=True)

        if a.frag3 and len(data) == 80 and data[76:78] == b"\x00\x01":
            # the 2026-09-05 audit (J): the Select Server screen has a NAME column
            # and a `Players Connected` column (KelStr group 29) and we have
            # always written id 0 / tail 0 into both. --frag3-servers now takes
            # an optional `:id:tail` so one boot can name which field is which
            # without a code change.  ip:port[:id[:tail]]
            entries = b""
            # KEY: sec 4fz (2026-09-13): PLAYERS CONNECTED is entry+10. Render loop 0x00aaed9c prints row+0xF0 with %d (entry+10 via copy 0x005862d0 -> list builder 0x00aae890); >= 1000 = 'server is full'. entry+0 = server id (the name), entry+8 = the tab.
            # We served 0 forever. An explicit :id:tail in --frag3-servers
            # still wins.
            _online = players_connected(exclude=sess)
            print("  [server list] %d other player(s) connected -> entry+10"
                  % _online, flush=True)
            for x in a.frag3_servers.split(","):
                x = x.strip()
                if not x:
                    continue
                f = x.split(":")
                entries += build_srv_entry(
                    host_for(f[0], src[0]), int(f[1]),
                    id0=int(f[2], 0) if len(f) > 2 and f[2] else a.frag3_server_id,
                    tail=(int(f[3], 0) if len(f) > 3 and f[3]
                          else _online),                      # sec 4fz
                    area=(int(f[4], 0) if len(f) > 4 and f[4]
                          else a.frag3_area))
            fr = build_frag3(data, parts=a.frag3_parts, index=0, payload=entries,
                             crypto=a.crypto, body_len=a.body_len,
                             mode_byte=a.mode_byte, do_cksum=not a.no_cksum)
            held_now = (a.frag3_hold_s > 0 and sess.chara_burst_at is not None
                        and (datetime.datetime.now().timestamp() - sess.chara_burst_at)
                        < a.frag3_hold_s)
            if fr is not None and held_now:
                sess.frag3_pending = (fr, src)
                print('  (frag3 HELD -- savestate window, %.1f s left)'
                      % (a.frag3_hold_s - (datetime.datetime.now().timestamp()
                                           - sess.chara_burst_at)), flush=True)
            elif fr is not None:
                s.sendto(fr, src)
                sess.frag3_sent += 1
                print("  SENT %d bytes (SUBTYPE-3 frag reply #%d, parts=%d idx=0) to %s:%d"
                      % (len(fr), sess.frag3_sent, a.frag3_parts, src[0], src[1]), flush=True)
                print(hexdump(fr, indent="    3 "), flush=True)

        # Extra SUBTYPES for the non-lobby (80-byte, type-128) packets.  The client
        # gates each subtype on the connection state (0x00585fc4), so the wrong one
        # is discarded for free and we do not have to observe the state to pick.
        if extra_subtypes and not is_lobby(data):
            for st in extra_subtypes:
                ex = build_reply(data, a.mode, st, a.crypto, a.body_len,
                                 a.mode_byte, not a.no_cksum, a.ptype, a.flags,
                                 _lip, a.lobby_port)
                if ex is not None:
                    s.sendto(ex, src)
                    print("  SENT %d bytes (extra subtype %d) to %s:%d"
                          % (len(ex), st, src[0], src[1]), flush=True)

        # The ladder extras, after the advance replies and before the ACK.  Each is
        # state-gated inside the client (sec 4ao), so a code for a state the nest is
        # not in costs a datagram and does nothing -- which is why this is a LIST the
        # user keeps short, not a sweep.
        if extra_selectors and a.lobby_probe == "advance" and is_lobby(data):
            for sel in extra_selectors:
                ex = build_lobby_advance(
                    data, selector=sel, seq=a.lobby_seq, inner_ip=_lip,
                    empty_records=True)
                if ex is not None:
                    s.sendto(ex, src)
                    print("  SENT %d bytes (ladder response code %d) to %s:%d"
                          % (len(ex), sel, src[0], src[1]), flush=True)

        # ONE exact ACK, last -- so it never competes with the advance replies for
        # a slot in the client's small receive ring (that is what killed the sweep).
        # NB this must sit OUTSIDE the `reply is not None` arm: the 36-byte mode-2
        # packets are exactly the channel we have no advance reply for (sec 4af),
        # and they are the ones whose retransmit we are trying to cancel.
        # WARNING: THE ACK IS A TRADE, NOT A SETTING (sec 4bx). ACK always and the
        # client goes quiet in the lobby -> PCSX2 unbinds its UDP port after ~48 s
        # of GUEST-transmit idle -> our packets vanish -> CER-48104. ACK never and
        # the client resends forever, its reliable queue never drains, and it can
        # end up hearing nothing from us for 40 s -> CER-48102. Both were measured
        # live on 08-27, in that order. The rule that resolves it is the
        # own wording: never ACK unless SOMETHING ELSE keeps the guest
        # transmitting -- and in game its 2 Hz position stream is exactly that.
        _streaming = (a.reliable_ack_ingame and last_stream[0]
                      and (datetime.datetime.now().timestamp() - last_stream[0])
                      <= a.reliable_ack_idle)
        # KEY: sec 4dd: THE GATE ABOVE IS PURELY TEMPORAL -- it has no idea WHAT it is
        # refusing to ACK, and that is what boomerangs the account holder out of the
        # lobby.  Measured live 2026-08-27 03:25:48Z:
        #
        #   03:25:48.934  SEQ=2922 flags=0x01 DATA   <- the lobby-entry command
        #   03:25:49.455  SEQ=2922  retransmit
        #   03:25:50.485  SEQ=2922  retransmit
        #   03:25:52.505  SEQ=2922  retransmit
        #   03:25:56.509  SEQ=2922  retransmit -> the client gives up
        #   03:25:56.610  SENT 1 reliable ACK for seq 2922    <- 7.68 s LATE
        #
        # The 2 Hz position stream is quiet during exactly the transition the
        # client is trying to make, so `--reliable-ack-ingame` holds the ACK until
        # after the transition has already failed, and then sends it.
        #
        # WARNING: THIS DOES NOT REOPEN THE sec 4by TRADE. That trade is about ACKing
        # while the client is IDLE: the ACK silences it, PCSX2 unbinds the guest
        # UDP port after ~48 s of GUEST-transmit idle, and everything we send
        # vanishes (CER-48104). A selector-240 request is the opposite situation --
        # the client is mid-transaction and will keep transmitting whatever we do.
        # So this is an exception for MESSAGES WE ARE ALREADY ANSWERING, not a
        # return to `--reliable-ack-exact`.
        _urgent = False
        if _ack_selectors and inner is not None and inner["is_data"] \
                and inner["type"] == a.world_type:
            _s, _ = world_reply_fields(data, inner)
            _urgent = _s in _ack_selectors
        if _gs_answered:
            _urgent = True
        if (a.reliable_ack_exact or _streaming or _urgent) \
                and inner is not None and inner["is_data"]:
            s.sendto(build_reliable_ack(inner["seq"]), src)
            print("  SENT 1 reliable ACK for seq %d to %s:%d%s"
                  % (inner["seq"], src[0], src[1],
                     "  [urgent: a selector we answer -- not gated on the 2 Hz "
                     "stream, sec 4dd]" if _urgent and not _streaming else ""),
                  flush=True)


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        print("\n[docudp] stopped")
