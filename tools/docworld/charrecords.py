"""The character roster: character ids, the 96-byte wire record and the CHARAMAKE answer."""
import struct
from . import framing, handshake



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
    head = bytearray(template[framing.BODY_OFF:framing.BODY_OFF + 12]).ljust(12, b"\x00")
    tail = bytearray(reg_pkt[framing.BODY_OFF + 108:]) if len(reg_pkt) > framing.BODY_OFF + 108 else bytearray()
    body = head + bytearray(record[:96]).ljust(96, b"\x00") + tail
    if len(body) < 176:
        body += bytes(176 - len(body))
    return handshake.build_lobby_advance(bytes(template[:framing.BODY_OFF]) + bytes(body),
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
    # slot 0: the Deck picked "Test" and reported Fox's 0x2aa68 (live 09-12).
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
    # select screen with Fox in row 0).
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
