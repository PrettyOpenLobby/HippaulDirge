#!/usr/bin/env python3
"""Dirge of Cerberus player-to-player TRADE -- the server side of the retail flow.

2026-10-08: decoded end to end on the RETAIL client (SLPM-66271, savestate
of the retail lobby; every arm run offline on the retail client). The 09-13 reading (prototype) had the right
offer layout and the right 42/44 relay, and three things wrong: the answer
to 41 (46 -> the inviter never opened its trade), 47 / 49 swapped (every
trade cancelled at the final click) and a two-sided confirm the client
never sends. A = the inviter, B = the invitee.

  41 INVITE   A: trade window (mode 0) OK -> "Request a trade with %s?" Yes
              -> kelsvc vt+692 0x00bd9c18. Refused locally while [kelsvc+28]
              & 0x400 (a trade open); stores the partner at [kelsvc+276],
              records A's OWN offer, PARKS [kelsvc+12] = 16 (10 s deadline).
  45 OPENED   answer to 41, arm 0x00bd41d4: gate 16 -> state 2, clears the
              pending bit 31, and SETS 0x400 -- the inviter's trade is open.
              (46 there, as served until today, only releases the park:
              A's 44 / 48 / 50 arms then all drop, needing 0x400.)
  42 INVITED  push to B, arm 0x00bd41b8 -> 0x00bd2dc8 (ungated): sets 0x400,
              partner = body[12], stores the offer (count R+2958, gil
              R+2964, rows R+3056..); the lobby lists Accept / Refuse Trade
              in the player menu ("%s wishes to trade with you.").
  240 cmd 23  B: Accept Trade -> lobby command 23 (vt+1084 0x00bdd128) -- sent
              only while [kelsvc+256] == 0 (it is a copy of the play-time
              sender, gate included), so it is often never on the wire. Its
              241 answer is the shared no-op; nothing may depend on it.
  134 sub 7   push to A (ident = B): "%s is entering terms." (lobby notice
              kind 14 -> 0x00ad55f0, inviter's window). INFERRED, not seen
              from SE's server: the arm and its dialog exist and nothing
              else sends them; served when command 23 arrives.
  43 OFFER    B: approves the terms (dialog 58 "Do you approve of the current
              terms?" Yes) -> vt+708 0x00bd9d48, B's counter-offer; parks 16.
  46 ACK      answer to 43, arm 0x00bd4244: gate 16 -> state 2.
  44 UPDATE   push to A, arm 0x00bd425c: needs 0x400 and body[12] == the
              stored partner; A's window goes to mode 2.
  49 APPROVE  A (mode 2): OK -> dialog 58 Yes -> vt+732 0x00bd9ef0, header
              only. The ONLY final confirm: B's approval is its 43.
  50 DONE     push to both, arm 0x00bd4284: the CLIENT applies the swap
              itself (0x00bebe48) from its own last 41/43 and the partner's
              last 42/44 ("Trade completed!"); the body is not read. A short
              stack makes it refuse part-way, so 50 goes out only after the
              server's own all-or-nothing swap (doc_shop.Shop.trade).
  47 CANCEL   either side: "Cancel trade?" Yes, or Refuse Trade -> vt+724
              0x00bd9e50, header only.
  48 CANCELLED push, arm 0x00bd4210: needs 0x400; clears it and R+92 0x800.
              The lobby shows "Trade cancelled." only when the header ident
              is NOT the receiver (notice kind 12); ident == receiver is the
              silent reset (kind 16). So the partner gets ident = canceller,
              and the canceller ident = itself (its 0x400 must clear, or its
              next 41 is refused locally).

41/43 body: [12] u32 partner charid, [16] u32 GIL, [20] u16 count (<= 10; the
window offers 4 rows), [24+8i] {u32 id, u16 0, u16 qty}. 47/49: header only
(36-byte datagrams).
"""
import struct

INVITE_REQ, INVITE_PUSH = 41, 42
OFFER_REQ, OFFER_PUSH = 43, 44
OPEN_ANS = 45            # the answer to 41 (sets the inviter's trade-open bit)
ACK_ANS = 46             # the answer to 43
CANCEL_REQ, CANCEL_PUSH = 47, 48
APPROVE_REQ, DONE_PUSH = 49, 50
TRADE_REQS = (INVITE_REQ, OFFER_REQ, CANCEL_REQ, APPROVE_REQ)
SHORT_REQS = (CANCEL_REQ, APPROVE_REQ)      # 36-byte, header-only
# legacy names (doc_udp_test, older proofs)
CONFIRM_REQ = APPROVE_REQ
MAX_ITEMS = 10
#: lobby command 23 = the invitee's "Accept Trade" (240 -> 241)
ACCEPT_CMD = 23
#: selector-134 sub-kind 7 = "%s is entering terms." to the inviter
ENTERING_TERMS_SUB = 7
PUSH_SEL = 134


def parse_offer(body):
    """(partner, gil, [(id, qty)]) from a 41/43 body, or None."""
    if body is None or len(body) < 24:
        return None
    partner, gil, n = struct.unpack_from("<IIH", body, 12)
    if n > MAX_ITEMS or len(body) < 24 + 8 * n:
        return None
    items = []
    for i in range(n):
        iid, _, qty = struct.unpack_from("<IHH", body, 24 + 8 * i)
        items.append((iid, qty))
    return partner, gil, items


def offer_body(selector, partner, gil, items, subchannel=7):
    """A 42/44 push: body[12] = the SENDER's charid (the receiver's partner)."""
    items = list(items)[:MAX_ITEMS]
    body = bytearray(24 + 8 * len(items))
    body[0] = subchannel & 0xFF
    body[1] = selector & 0xFF
    struct.pack_into("<IIH", body, 12, partner & 0xFFFFFFFF, gil & 0xFFFFFFFF, len(items))
    for i, (iid, qty) in enumerate(items):
        struct.pack_into("<IHH", body, 24 + 8 * i, iid & 0xFFFFFFFF, 0, qty & 0xFFFF)
    return bytes(body)


def bare_body(selector, subchannel=7):
    """45 / 46 / 48 / 50: no fields are read past the header."""
    body = bytearray(24)
    body[0] = subchannel & 0xFF
    body[1] = selector & 0xFF
    return bytes(body)


def entering_terms_body(subchannel=7):
    """Selector 134 sub 7 (arm 0x00bd45e4 -> 0x00bd18d8, case 0x00bd1a70)."""
    b = bytearray(20)
    b[0] = subchannel & 0xFF
    b[1] = PUSH_SEL
    struct.pack_into("<I", b, 12, ENTERING_TERMS_SUB)
    return bytes(b)


class Trade:
    __slots__ = ("a", "b", "offers", "countered")

    def __init__(self, a, b):
        self.a, self.b = a, b          # a = the inviter, b = the invitee
        self.offers = {a: (0, []), b: (0, [])}
        self.countered = False         # B's 43 has arrived

    def other(self, who):
        return self.b if who == self.a else self.a


class TradeBook:
    """Open trades, keyed by BOTH charids. Actions returned to the caller:
        ("answer", selector)             answer the request with that selector
        ("push", charid, body, ident)    an unsolicited push, header ident
        ("swap", trade)                  A approved B's terms: swap the server
                                         wallets, then 50 to both (48 to both
                                         if the swap is refused)
    """

    def __init__(self):
        self.by = {}

    def _close(self, t):
        self.by.pop(t.a, None)
        self.by.pop(t.b, None)

    @staticmethod
    def cancel_pushes(t, by):
        """48 to both sides: the partner hears it (ident = `by`), the
        canceller's own is the silent reset (ident = itself)."""
        return [("push", w, bare_body(CANCEL_PUSH), by) for w in (t.a, t.b)]

    def request(self, sel, sender, body, online=None):
        """(actions, note) for one trade request from `sender` (its charid).
        `online(charid)` says whether a partner can be reached (None = yes)."""
        if sel == INVITE_REQ:
            p = parse_offer(body)
            if p is None:
                return ([("answer", OPEN_ANS),
                         ("push", sender, bare_body(CANCEL_PUSH), sender)],
                        "INVITE unreadable -> opened and cancelled")
            partner, gil, items = p
            acts = [("answer", OPEN_ANS)]
            if (not partner or partner == sender
                    or (online is not None and not online(partner))):
                # retail opens on 45 and has no refusal code; the inviter's
                # "Waiting..." is closed by the partner-voiced 48
                return (acts + [("push", sender, bare_body(CANCEL_PUSH), partner)],
                        "INVITE 0x%08x -> 0x%08x: partner not reachable -> cancelled"
                        % (sender, partner))
            busy = self.by.get(partner)
            if busy is not None and sender not in (busy.a, busy.b):
                return (acts + [("push", sender, bare_body(CANCEL_PUSH), partner)],
                        "INVITE 0x%08x -> 0x%08x: partner is trading with 0x%08x "
                        "-> cancelled" % (sender, partner, busy.other(partner)))
            cur = self.by.get(sender)
            for old in {id(o): o for o in (cur, busy) if o is not None}.values():
                # the sender's own stale trade (its client had closed it, or
                # it would have refused the 41): tell the one left in it
                self._close(old)
                for who in (old.a, old.b):
                    if who != sender:
                        acts.append(("push", who, bare_body(CANCEL_PUSH), sender))
            t = Trade(sender, partner)
            t.offers[sender] = (gil, items)
            self.by[sender] = self.by[partner] = t
            return (acts + [("push", partner,
                             offer_body(INVITE_PUSH, sender, gil, items), sender)],
                    "INVITE 0x%08x -> 0x%08x: %d gil, %s" % (sender, partner, gil, items))
        t = self.by.get(sender)
        if t is None:
            acts = [("answer", ACK_ANS)] if sel == OFFER_REQ else []
            return (acts + [("push", sender, bare_body(CANCEL_PUSH), sender)],
                    "request %d from 0x%08x with no open trade -> reset" % (sel, sender))
        other = t.other(sender)
        if sel == OFFER_REQ:
            p = parse_offer(body)
            if p is None:
                return [("answer", ACK_ANS)], "OFFER unreadable"
            _, gil, items = p
            t.offers[sender] = (gil, items)
            if sender == t.b:
                t.countered = True
            return ([("answer", ACK_ANS),
                     ("push", other, offer_body(OFFER_PUSH, sender, gil, items), sender)],
                    "OFFER 0x%08x -> 0x%08x: %d gil, %s%s"
                    % (sender, other, gil, items,
                       " (the invitee approves; waiting for the inviter's 49)"
                       if sender == t.b else ""))
        if sel == APPROVE_REQ:
            if sender != t.a or not t.countered:
                return [], ("APPROVE from 0x%08x ignored: only the inviter approves, "
                            "after the invitee's terms (%s)"
                            % (sender, "countered" if t.countered else "no terms yet"))
            self._close(t)
            return [("swap", t)], "APPROVED by 0x%08x: 0x%08x <-> 0x%08x" % (sender, t.a, t.b)
        if sel == CANCEL_REQ:
            self._close(t)
            return self.cancel_pushes(t, sender), "CANCEL by 0x%08x" % sender
        return [], "not a trade request"

    def accept(self, sender):
        """Lobby command 23 (the invitee's Accept Trade): (actions, note)."""
        t = self.by.get(sender)
        if t is None or sender != t.b:
            return [], "command 23 from 0x%08x: no invitation open" % sender
        return ([("push", t.a, entering_terms_body(), sender)],
                "ACCEPT by 0x%08x -> 0x%08x is told the terms are being entered"
                % (sender, t.a))


if __name__ == "__main__":
    import sys
    PC, DECK = 0x0004103C, 0x00041018
    CANCEL = bare_body(CANCEL_PUSH)
    # the LIVE 12:33:26 request 41: PC -> Deck, 5 gil, no items
    live41 = bytes.fromhex("0729000001000000000000001810040005000000000000000000")[:24]
    assert parse_offer(live41) == (DECK, 5, []), parse_offer(live41)
    tb = TradeBook()
    acts, note = tb.request(INVITE_REQ, PC, live41)
    assert acts[0] == ("answer", OPEN_ANS), acts
    assert acts[1][:2] == ("push", DECK) and acts[1][3] == PC, acts
    assert acts[1][2][1] == INVITE_PUSH and parse_offer(acts[1][2]) == (PC, 5, []), note
    # the Deck accepts (command 23): the PC hears "entering terms"
    acts, _ = tb.accept(DECK)
    assert acts == [("push", PC, entering_terms_body(), DECK)], acts
    assert tb.accept(PC)[0] == [], "the inviter's own 23 is not an accept"
    # an early 49 from the inviter (no terms yet) is ignored; the invitee's 49 too
    assert tb.request(APPROVE_REQ, PC, None)[0] == []
    # the Deck approves with its terms: 1 Potion
    off = offer_body(OFFER_REQ, PC, 0, [(0x69320000, 1)])
    acts, _ = tb.request(OFFER_REQ, DECK, off)
    assert acts[0] == ("answer", ACK_ANS) and acts[1][1] == PC and acts[1][3] == DECK
    assert parse_offer(acts[1][2]) == (DECK, 0, [(0x69320000, 1)])
    assert tb.request(APPROVE_REQ, DECK, None)[0] == [], "the invitee never sends 49"
    acts, _ = tb.request(APPROVE_REQ, PC, None)
    assert acts[0][0] == "swap" and acts[0][1].offers == {PC: (5, []), DECK: (0, [(0x69320000, 1)])}
    assert PC not in tb.by and DECK not in tb.by
    # cancel: the partner hears it (ident = canceller), the canceller resets silently
    tb.request(INVITE_REQ, PC, live41)
    acts, _ = tb.request(CANCEL_REQ, DECK, None)
    assert sorted(acts) == sorted([("push", PC, CANCEL, DECK), ("push", DECK, CANCEL, DECK)]), acts
    # TWIN of the 09-13 reading: 47 is the CANCEL, not a confirm -- no swap
    assert not any(a[0] == "swap" for a in acts)
    # a request with no trade resets the sender only
    assert tb.request(APPROVE_REQ, PC, None)[0] == [("push", PC, CANCEL, PC)]
    # an unreachable partner: opened (45) and cancelled in the partner's voice
    acts, note = tb.request(INVITE_REQ, PC, live41, online=lambda c: False)
    assert acts == [("answer", OPEN_ANS), ("push", PC, CANCEL, DECK)], acts
    # a partner busy with a THIRD player: refused, the third trade untouched
    THIRD = 0x00050000
    tb.request(INVITE_REQ, THIRD, offer_body(INVITE_REQ, DECK, 1, [])[:24])
    acts, note = tb.request(INVITE_REQ, PC, live41)
    assert acts == [("answer", OPEN_ANS), ("push", PC, CANCEL, DECK)], acts
    assert tb.by[DECK].a == THIRD
    print("doc_trade self-test PASS")
    sys.exit(0)
