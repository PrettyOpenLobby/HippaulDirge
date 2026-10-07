"""Lobby commands (selector 240/241): command ids, the clock, and the table and quest command numbers."""
import time
from . import framing



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
    if buf is None or len(buf) < framing.BODY_OFF + 13:
        return None
    if buf[framing.BODY_OFF + 1] != LOBBY_CMD_SELECTOR_REQ:
        return None
    return buf[framing.BODY_OFF + 12]
LOBBY_CMD_APPOINT = 1      # 0x00bd1c28, phase 56, "%s has been appointed leader"
LOBBY_CMD_KICK = 2         # 0x00bd1cf0, phase 54, "%s has been kicked"
LOBBY_CMD_RETURN = 4       # 0x00bd1fb8: RETURN TO LOBBY (its poll runs the full
                           # reset 0x00bd2a38, selector 39's arm). Live,
                           # a player quit the Wastelands arena with
                           # it and the room ran on for 600 s.
# 2026-10-01 (retail lobby, re-visibility/rt_vis_proof.py): the Status
# window's Public / Anonymous row. The client sets / clears its own bit 0x04
# (setSelfFlags 0x00be5e60 / clearSelfFlags 0x00be5ec0) as it sends; the 241
# arm for both is the no-op 0x00bd0ff4. The setting itself is ours to keep.
LOBBY_CMD_ANONYMOUS = 6
LOBBY_CMD_PUBLIC = 7
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
