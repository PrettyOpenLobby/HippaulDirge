#!/usr/bin/env python3
"""Dirge of Cerberus player-to-player TRADE -- the server relay (sec 4gk addendum 5).

Captured live 2026-09-13 12:33:26Z: the PC (member:15) sent request 41 to the
Deck's character; we answered the generic empty 42 and nothing reached the Deck.
Every number below is read from the client (doc_inworld_slot03):

  41 INVITE   op 7 -> kelsvc vt+692 0x00bd2f58 -> writer 0x00bcdcf0. Refused
              locally while a trade is open ([kelsvc+28] & 0x400). Stores the
              partner at [kelsvc+276], records its OWN offer (0x00bded58), then
              PARKS [kelsvc+12] = 16.
  43 OFFER    op 8 -> vt+708 0x00bd3088 -> writer 0x00bcdda8, partner =
              [kelsvc+276]. Needs a trade open; records its own offer; parks 16.
              41/43 body: [12] partner charid, [16] u32 GIL, [20] u16 count
              (<= 10), [24+8i] {u32 id, u16, u16 qty}.
  46 ACK      arm 0x00bccff4, gate 16 -> the shared bare ack (0x00bcd4a8): the
              "offer delivered" answer to the parked sender of 41/43.
  42 INVITED  push, ungated, 0x00bcbb60: sets [kelsvc+28] |= 0x400, partner =
              body[12], and the partner's offer -> 0x00be6920 (count R+2958,
              entries R+3052.., gil R+2964). "%s wishes to trade with you."
  44 UPDATE   push, ungated, 0x00bcbc20: same, but only if body[12] == the stored
              partner.
  47 CONFIRM  vt+724 0x00bd3190 -> 0x00bcde60: header-only (a 36-byte datagram),
              only while a trade is open.
  49 CANCEL   vt+732 0x00bd3230 -> 0x00bcdea0: header-only, same gate.
  48 CANCELLED push, ungated, 0x00bcbce0 -> 0x00be6af0: clears R+92 bit 0x800.
  50 DONE     push, ungated, 0x00bcbd28 -> 0x00be6978: the CLIENT applies the
              swap itself from the two stored offers ("Trade completed!").

So the server relays offers, and when BOTH sides have confirmed the current
offers it swaps the two wallets (doc_shop.Shop.trade) and pushes 50 to both.
Which button sends 47 vs 49 is inferred from the strings (OK "to complete the
trade" / CANCEL) -- not yet seen live.
"""
import struct

INVITE_REQ, INVITE_PUSH = 41, 42
OFFER_REQ, OFFER_PUSH = 43, 44
ACK_ANS = 46
CONFIRM_REQ, CANCEL_PUSH = 47, 48
CANCEL_REQ, DONE_PUSH = 49, 50
TRADE_REQS = (INVITE_REQ, OFFER_REQ, CONFIRM_REQ, CANCEL_REQ)
SHORT_REQS = (CONFIRM_REQ, CANCEL_REQ)      # 36-byte, header-only
MAX_ITEMS = 10


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
    """46 / 48 / 50: no fields are read past the header."""
    body = bytearray(24)
    body[0] = subchannel & 0xFF
    body[1] = selector & 0xFF
    return bytes(body)


class Trade:
    __slots__ = ("a", "b", "offers", "confirmed")

    def __init__(self, a, b):
        self.a, self.b = a, b
        self.offers = {a: (0, []), b: (0, [])}
        self.confirmed = set()

    def other(self, who):
        return self.b if who == self.a else self.a


class TradeBook:
    """Open trades, keyed by BOTH charids. Actions returned to the caller:
        ("ack", charid)                  answer 46 to the parked sender
        ("push", charid, body)           a 42/44/48/50 to that client
        ("swap", trade)                  both confirmed: swap wallets, then
                                         the caller sends 50 (or 48 on failure)
    """

    def __init__(self):
        self.by = {}

    def _close(self, t):
        self.by.pop(t.a, None)
        self.by.pop(t.b, None)

    def request(self, sel, sender, body):
        """(actions, note) for one trade request from `sender` (its charid)."""
        if sel == INVITE_REQ:
            p = parse_offer(body)
            if p is None:
                return [("ack", sender)], "INVITE unreadable"
            partner, gil, items = p
            for old in (self.by.get(sender), self.by.get(partner)):
                if old is not None:          # a stale trade on either side
                    self._close(old)
            t = Trade(sender, partner)
            t.offers[sender] = (gil, items)
            self.by[sender] = self.by[partner] = t
            return ([("ack", sender),
                     ("push", partner, offer_body(INVITE_PUSH, sender, gil, items))],
                    "INVITE 0x%08x -> 0x%08x: %d gil, %s" % (sender, partner, gil, items))
        t = self.by.get(sender)
        if t is None:
            acts = [("ack", sender)] if sel == OFFER_REQ else []
            return acts + [("push", sender, bare_body(CANCEL_PUSH))], \
                "request %d from 0x%08x with no open trade -> cancel" % (sel, sender)
        other = t.other(sender)
        if sel == OFFER_REQ:
            p = parse_offer(body)
            if p is None:
                return [("ack", sender)], "OFFER unreadable"
            _, gil, items = p
            t.offers[sender] = (gil, items)
            t.confirmed.clear()              # any change voids both confirmations
            return ([("ack", sender),
                     ("push", other, offer_body(OFFER_PUSH, sender, gil, items))],
                    "OFFER 0x%08x -> 0x%08x: %d gil, %s" % (sender, other, gil, items))
        if sel == CONFIRM_REQ:
            t.confirmed.add(sender)
            if t.confirmed >= {t.a, t.b}:
                self._close(t)
                return [("swap", t)], "BOTH CONFIRMED 0x%08x <-> 0x%08x" % (t.a, t.b)
            return [], "CONFIRM 0x%08x (waiting for 0x%08x)" % (sender, other)
        if sel == CANCEL_REQ:
            self._close(t)
            return ([("push", t.a, bare_body(CANCEL_PUSH)),
                     ("push", t.b, bare_body(CANCEL_PUSH))],
                    "CANCEL by 0x%08x" % sender)
        return [], "not a trade request"


if __name__ == "__main__":
    import sys
    PC, DECK = 0x0004103C, 0x00041018
    # the LIVE 12:33:26 request 41: PC -> Deck, 5 gil, no items
    live41 = bytes.fromhex("0729000001000000000000001810040005000000000000000000")[:24]
    assert parse_offer(live41) == (DECK, 5, []), parse_offer(live41)
    tb = TradeBook()
    acts, note = tb.request(INVITE_REQ, PC, live41)
    assert acts[0] == ("ack", PC) and acts[1][0] == "push" and acts[1][1] == DECK, acts
    push = acts[1][2]
    assert push[1] == INVITE_PUSH and parse_offer(push) == (PC, 5, []), note
    # the Deck answers with an offer: 1 Potion
    off = offer_body(OFFER_REQ, PC, 0, [(0x69320000, 1)])
    acts, _ = tb.request(OFFER_REQ, DECK, off)
    assert acts[1][1] == PC and parse_offer(acts[1][2]) == (DECK, 0, [(0x69320000, 1)])
    assert tb.request(CONFIRM_REQ, PC, None)[0] == []
    acts, _ = tb.request(CONFIRM_REQ, DECK, None)
    assert acts[0][0] == "swap" and acts[0][1].offers == {PC: (5, []), DECK: (0, [(0x69320000, 1)])}
    assert PC not in tb.by and DECK not in tb.by
    # a changed offer voids a confirmation
    tb.request(INVITE_REQ, PC, live41)
    tb.request(CONFIRM_REQ, DECK, None)
    tb.request(OFFER_REQ, PC, offer_body(OFFER_REQ, DECK, 9, []))
    assert tb.request(CONFIRM_REQ, PC, None)[0] == [], "Deck's confirm was voided"
    # cancel reaches both
    acts, _ = tb.request(CANCEL_REQ, DECK, None)
    assert sorted(a[1] for a in acts) == sorted([PC, DECK]) and all(a[2][1] == CANCEL_PUSH for a in acts)
    # a confirm with no trade cancels the sender only
    acts, _ = tb.request(CONFIRM_REQ, PC, None)
    assert acts == [("push", PC, bare_body(CANCEL_PUSH))]
    print("doc_trade self-test PASS")
    sys.exit(0)
