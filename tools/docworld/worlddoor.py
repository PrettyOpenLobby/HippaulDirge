"""The world-door answer (selector 1 -> 2 and the type-0x7f bodies built on it)."""
import struct
import doc_novice
import doc_stats
import doc_shop
import doc_unit
from . import arenamaps, framing, lobbycmd



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
    if len(req) < framing.BODY_OFF + 12:
        return None
    body = bytearray(req[framing.BODY_OFF:])
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
    if selector == lobbycmd.LOBBY_CMD_SELECTOR_ANS and len(body) >= 28:
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
    if spawn is not None and selector == arenamaps.WORLD_SPAWN_SELECTOR_ANS and len(body) >= 54:
        sx, sy, sz, dx, dy, dz, sidx = spawn
        struct.pack_into("<f", body, arenamaps.SPAWN_OFF_X, sx)
        struct.pack_into("<f", body, arenamaps.SPAWN_OFF_Y, sy + arenamaps.SPAWN_Y_BIAS)
        struct.pack_into("<f", body, arenamaps.SPAWN_OFF_Z, sz)
        struct.pack_into("<f", body, arenamaps.SPAWN_OFF_DIR_X, dx)
        struct.pack_into("<f", body, arenamaps.SPAWN_OFF_DIR_Y, dy)
        struct.pack_into("<f", body, arenamaps.SPAWN_OFF_DIR_Z, dz)
        # TWO byte stores, not a halfword: 0x00bca8a4/0x00bca89c do `lbu`/`lhu>>8`
        # and the arm writes them to the descriptor's +24 and +25 separately.
        body[arenamaps.SPAWN_OFF_INDEX] = sidx & 0xFF
        body[arenamaps.SPAWN_OFF_INDEX + 1] = (sidx >> 8) & 0xFF

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
    if (selector == arenamaps.WORLD_SPAWN_SELECTOR_ANS
            and len(body) >= arenamaps.LOBBY_MAP_MASK_OFF + 8):
        if arenamaps.LOBBY_MAP_MASK:
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
            struct.pack_into("<II", body, arenamaps.LOBBY_MAP_MASK_OFF,
                             arenamaps.LOBBY_MAP_MASK & 0xFFFFFFFF,
                             (arenamaps.LOBBY_MAP_MASK >> 32) & 0xFFFFFFFF)

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
    if selector == 2 and arenamaps.LOBBY_ZONE and len(body) >= arenamaps.LOBBY_ZONE_OFF + 2:
        struct.pack_into("<H", body, arenamaps.LOBBY_ZONE_OFF, arenamaps.LOBBY_ZONE & 0xFFFF)

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
    if self_probe and selector in (2, arenamaps.WORLD_SPAWN_SELECTOR_ANS) and len(body) >= 114:
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
    pkt += struct.pack("<H", framing.HDR_LEN + len(body))
    pkt += struct.pack("<I", framing.now_ms() & 0xFFFF)
    pkt += mid
    pkt += body
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
    pkt[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(pkt))
    return bytes(pkt)
