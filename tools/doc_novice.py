#!/usr/bin/env python3
"""Dirge of Cerberus: the NEW-PLAYER INTRO and the NOVICE ("Beginner") mark.

Read off the RETAIL client (SLPM-66271, CRC 139D8DF9) on 2026-09-23; the full
trace is the protocol notes sec 4hc, and every byte this module
sends is run through the client's own parser + demux by
an offline run of the client's own code (doc_novice_proof).

THE INTRO
---------
Retail `quest.handle_event` event 1 fades out, calls standbyForEvent() (local,
sends nothing) and KerberosZone.exit(240). Zone 240 runs ev2100 (the
"Deepground, a secret facility beneath Midgar" prologue), which exits to 241
(ev2110), which exits to 242 (ev2120, "Welcome... a newcomer?... that is a
Restrictor... get your orders from the instructor by the ranking board"),
which exits back to the lobby 217. There ev2046.main sees event flag 4 and
sends reportQuestEventDone(1) = LOBBY COMMAND 27 with u32 1 at body[16]: the
"intro seen" confirmation. SE's patch 20060124_3 ships all three scenes and
zones 240-242, and P2U-0010 serves them.

The client plays a quest event only once one of two setters has run:
  * the 241 sub-26 arm (the answer to lobby command 26, needs a pending request)
  * SELECTOR 134, SUB-KIND 10 -- ungated, so the server can PUSH it:
        body[1] = 134, body[12..15] = 10, body[16..17] = event id (u16)
    The 84-byte "quest data" at body[20..] is copied only for a long record;
    ours is short, so it is left alone.
quest.handle_event polls every 30 ms in the lobby loop, so it plays at once.

THE NOVICE MARK
---------------
  * KerberosNetLobby.isNovicePlayer() = bit 0x40 of the self record's byte
    R+0x2fa, filled by the world-door converter from wire+85 = selector-2
    reply BODY[129]. Bit 0x01 of the same byte is "reservation held", so the
    mark is OR-ed in, never stored over it.
  * Graduation: clearNovicePlayerFlag() = LOBBY COMMAND 33 (no argument); the
    241 sub-33 arm clears the local bit. The Cactuar "Beginner's Machine"
    (lobby NPC 39, event 101) sends it after its confirm.
  * SELECTOR 134, SUB-KIND 11 clears 0x40 for the character named by the
    packet ident on every peer table and, when it is the receiver, on self --
    the server's "mark removed" broadcast.
  * SE's rule, from its site and the NPC text: the mark comes off at 20 kills
    or at the machine, and it cannot be put back.
    Checked against SE's January Additional Manual: it says the mark goes
    once kills EXCEED 20 (i.e. 21). The client's own briefer text
    (ID_BT_SETU_SH_A_01, sentaku11_01) says AT 20, and the C / D briefers say
    about 20. The two conflict; the client wins, so the
    bar stays at 20 (KILLS_TO_GRADUATE; --novice-kills 21 = the manual).
  * The graduation ceremony (quest_scr003.ev(9998)) plays on lobby re-entry
    when the player left for a battle as a novice and is no longer one.

Persistence rides the career store (doc_stats.Stats), fields `intro_seen` and
`novice_cleared`; without --stats a process-lifetime dict stands in.
"""
import struct

SEL_PUSH = 134
SUB_QUEST_EVENT = 10
SUB_NOVICE_CLEAR = 11
EV_INTRO = 1

CMD_GRADUATE = 33          # clearNovicePlayerFlag()
CMD_EVENT_DONE = 27        # reportQuestEventDone(id), id at body[16]

DOOR_NOVICE_OFF = 129      # selector-2 body[129] = wire+85 -> R+0x2fa
NOVICE_BIT = 0x40

KILLS_TO_GRADUATE = 20
PUSH_LEN = 20


def push_body(sub, value=0, subchannel=7):
    """A selector-134 push: sub-kind at body[12], a u16 at body[16]."""
    b = bytearray(PUSH_LEN)
    b[0] = subchannel & 0xFF
    b[1] = SEL_PUSH
    struct.pack_into("<I", b, 12, sub & 0xFFFFFFFF)
    struct.pack_into("<H", b, 16, value & 0xFFFF)
    return bytes(b)


def intro_push(subchannel=7):
    return push_body(SUB_QUEST_EVENT, EV_INTRO, subchannel)


def graduate_push(subchannel=7):
    return push_body(SUB_NOVICE_CLEAR, 0, subchannel)


def apply_door(body, novice):
    """OR the novice mark into a selector-2 world-door body (padded if short)."""
    if not novice:
        return body
    b = bytearray(body)
    if len(b) <= DOOR_NOVICE_OFF:
        b += bytes(DOOR_NOVICE_OFF + 1 - len(b))
    b[DOOR_NOVICE_OFF] |= NOVICE_BIT
    return bytes(b)


def event_done_id(req_body):
    """The u32 id of a command-27 request, or None."""
    if req_body is None or len(req_body) < 20:
        return None
    return struct.unpack_from("<I", req_body, 16)[0]


class Novice:
    """Per-character intro / novice state, keyed like the career store."""

    def __init__(self, stats=None, kills_to_graduate=KILLS_TO_GRADUATE):
        self.stats = stats
        self.kills_to_graduate = kills_to_graduate
        self._mem = {}

    def _rec(self, key):
        if self.stats is not None:
            return self.stats.career(key)
        return self._mem.setdefault(key, {"kills": 0})

    def _peek(self, key):
        if self.stats is not None:
            return self.stats.peek(key) or {}
        return self._mem.get(key, {})

    def _save(self):
        if self.stats is not None:
            self.stats.save()

    def is_novice(self, key):
        c = self._peek(key)
        if c.get("novice_cleared"):
            return False
        return int(c.get("kills", 0)) < self.kills_to_graduate

    def intro_seen(self, key):
        return bool(self._peek(key).get("intro_seen"))

    def mark_intro_seen(self, key):
        c = self._rec(key)
        if c.get("intro_seen"):
            return False
        c["intro_seen"] = True
        self._save()
        return True

    def graduate(self, key, why):
        """Clear the mark for good. True only on the transition."""
        c = self._rec(key)
        if c.get("novice_cleared"):
            return False
        c["novice_cleared"] = why
        self._save()
        return True

    def graduate_by_kills(self, key):
        """After a battle: graduate if the career kill total reached the bar."""
        c = self._peek(key)
        if c.get("novice_cleared"):
            return False
        if int(c.get("kills", 0)) < self.kills_to_graduate:
            return False
        return self.graduate(key, "kills")


def _selftest():
    fails = []

    def check(cond, what):
        print("  %s  %s" % ("PASS" if cond else "**FAIL**", what))
        if not cond:
            fails.append(what)

    b = intro_push()
    check(b[1] == 134 and struct.unpack_from("<I", b, 12)[0] == 10
          and struct.unpack_from("<H", b, 16)[0] == 1, "intro push = 134 / sub 10 / event 1")
    b = graduate_push()
    check(b[1] == 134 and struct.unpack_from("<I", b, 12)[0] == 11, "graduate push = 134 / sub 11")
    door = bytes(140)
    door = bytearray(door)
    door[129] = 0x01
    check(apply_door(bytes(door), True)[129] == 0x41, "novice mark OR-ed, reservation bit kept")
    check(apply_door(bytes(door), False)[129] == 0x01, "non-novice door untouched")
    check(len(apply_door(bytes(100), True)) == 130, "short door padded to reach body[129]")
    n = Novice()
    check(n.is_novice("a") and not n.intro_seen("a"), "fresh character: novice, intro unseen")
    check(n.mark_intro_seen("a") and not n.mark_intro_seen("a"), "intro seen once")
    n._rec("a")["kills"] = 19
    check(not n.graduate_by_kills("a") and n.is_novice("a"), "19 kills: still a novice")
    n._rec("a")["kills"] = 20
    check(n.graduate_by_kills("a") and not n.is_novice("a"), "20 kills: graduated")
    check(not n.graduate("a", "machine"), "graduation happens once")
    check(not n.is_novice("a"), "mark cannot be restored")
    check(event_done_id(bytes(16) + struct.pack("<I", 1)) == 1, "command 27 id read at body[16]")
    return fails


if __name__ == "__main__":
    import sys
    sys.exit(1 if _selftest() else 0)
