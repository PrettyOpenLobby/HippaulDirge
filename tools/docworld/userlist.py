"""The lobby user list (selectors 10/11 and 18/19)."""
import struct
from . import framing, peerrecords



USER_SELECTOR_REQ = 10    # the client asking for the user list
USER_SELECTOR_ANS = 11    # request + 1, the arm 0x00bcc9c0 -> 0x00bc9bf0

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
    if buf is None or len(buf) < framing.BODY_OFF + 14:
        return None
    return struct.unpack_from("<H", buf, framing.BODY_OFF + 12)[0]


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
        records = [peerrecords.build_peer_record(
            u, name=(name if u == uids[0] else "%s%d" % (sweep_prefix, u)),
            **(fields or {})) for u in uids]
    body = bytearray(20 + peerrecords.PEER_REC_LEN * len(records))
    body[0] = subchannel & 0xFF
    body[1] = answer_selector
    # body[4] bit 0 is the failure flag on the sibling rungs; keep it clear.
    struct.pack_into("<H", body, 4, 0)
    struct.pack_into("<H", body, 12, len(records))     # records in THIS message
    struct.pack_into("<H", body, 16, total & 0xFFFF)   # total messages
    struct.pack_into("<H", body, 18, index & 0xFFFF)   # this message's index
    for i, r in enumerate(records):
        o = 20 + peerrecords.PEER_REC_LEN * i
        body[o:o + peerrecords.PEER_REC_LEN] = r[:peerrecords.PEER_REC_LEN]

    mid = bytearray(16)
    mid[0] = ptype & 0xFF
    struct.pack_into("<H", mid, 6, seq & 0xFFFF)
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
