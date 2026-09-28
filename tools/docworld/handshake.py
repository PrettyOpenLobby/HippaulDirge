"""The entrance: the subtype-3 server list and the type-129 reply that advances the lobby nest."""
import struct
from . import charrecords, framing



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
    if len(req) < framing.BODY_OFF:
        return None
    body = bytearray(req[framing.BODY_OFF:])
    if len(body) < 5:
        body += bytes(5 - len(body))
    if chara_count is not None and len(body) < charrecords.CHARA_REC_OFF:
        # The 36-byte mode-2 packets carry only a 12-byte body; a code-8 chara
        # reply needs at least the 20-byte header (count at body[17], records
        # from body[20]).  Pad rather than refuse -- subchannel/selector/flag all
        # sit in the first 5 bytes and are preserved.
        body += bytes(charrecords.CHARA_REC_OFF - len(body))
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
            recs = [charrecords.build_chara_record(i) for i in range(n)]
        n = min(n, len(recs) if recs else n, charrecords.CHARA_MAX_RECORDS)
        body[13] = n & 0xFF
        if n:
            body = body[:charrecords.CHARA_REC_OFF] + bytearray(b"".join(recs[:n]))

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

    total = framing.HDR_LEN + len(body)
    pkt = bytearray()
    pkt += bytes([0x04, mode_byte & 0xFF])    # mode 0 = no cipher
    pkt += struct.pack("<H", total)
    pkt += struct.pack("<I", framing.now_ms() & 0xFFFF)
    pkt += mid
    pkt += body
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(pkt))
    return bytes(pkt)


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
    if len(req) < framing.HDR_LEN:
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

    total = framing.HDR_LEN + len(body)
    pkt = bytearray()
    pkt += bytes([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", total)
    pkt += struct.pack("<I", framing.now_ms() & 0xFFFFFFFF)
    pkt += mid
    pkt += body
    if do_cksum:
        pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
        pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(pkt))
    return bytes(pkt)
