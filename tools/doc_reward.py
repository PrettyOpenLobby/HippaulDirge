#!/usr/bin/env python3
"""Dirge of Cerberus QUEST REWARD notice -- the 68-byte block the lobby PRINTS.

the protocol notes sec 4hh item 4 (retail EE image of doc_retail_lobby_20260923,
static): selector 134 sub 10 (the quest-event push, doc_novice) carries an
optional 68-byte block at body[20..87]. The arm 0x00bd1be8 copies it to the
lobby service object +0x4D8..0x51B -- ONLY when the parsed record's u16 +0x12
is >= 0x58, and the parser (0x00595f08) sets that to the BODY LENGTH (measured
2026-09-24, an offline run of the client's own code (doc_reward_proof); sec 4hh called it "the inner header
u16 at packet+22", which has no effect) -- sets obj+0x444 |= 0x8000 and
queues a notice; the
per-frame 0x00bd5db0 hands it to lobby_rel 0x00af1d18 (event 0x11), which
prints group-39 system lines:

    +0x00 u32  gil                 0x9C64 "%d gil obtained!" (not when +0x40 bit0)
    +0x04 u32  24-bit medal mask   per bit i: title 0xF010+i, 0x9C65 "%s obtained!"
    +0x08 u32  rank points         0x9C66 "%d rank point(s) obtained!"
    +0x0C u32  new rank (low byte, printed when the word != 0; 1..16 like the
               career's rank -> 0x6C09 + rank - 1)  0x9C67 "You are promoted to %s."
    +0x10 x3   {u32 item, u16 flags, u16 count}   0x9C68 "You obtain %s x%d!";
               flags bit0 = went to stock -> 0x9C6A "Inventory full..."
    +0x28..3F  three more item slots (copied, never printed)
    +0x40 u32  bit0 = wallet full  0x9C6B "Wallet full..."

Every 134/10 before 2026-09-24 was 20 bytes long, so no reward block ever
reached a client. This module builds the 88-byte form; docudp decides when.
The printing is the client's; the SERVER still has to credit what it prints
(doc_stats / doc_shop), exactly as for any other reward.
"""
import struct

import doc_novice

BLOCK_LEN = 68
DATA_OFF = 20                 # body offset of the block (body[20..87])
LEN_GATE = 0x58               # BODY length the sub-10 arm requires
ITEM_SLOTS = 3                # printed slots (+0x10, +0x18, +0x20)
ITEM_OFF = 0x10
ITEM_STOCK_FLAG = 0x0001      # "went to stock" (inventory full)


def reward_block(gil=0, medals=0, rp=0, rank=0, items=(), wallet_full=False):
    """The 68-byte block. `items` = [(item_id, count[, flags])] (max 3 print);
    `rank` = the career rank 1..16 to announce (0 = no promotion line)."""
    b = bytearray(BLOCK_LEN)
    struct.pack_into("<I", b, 0x00, max(0, int(gil)) & 0xFFFFFFFF)
    struct.pack_into("<I", b, 0x04, int(medals) & 0x00FFFFFF)
    struct.pack_into("<I", b, 0x08, max(0, int(rp)) & 0xFFFFFFFF)
    struct.pack_into("<I", b, 0x0C, int(rank) & 0xFF)
    items = list(items)[:ITEM_SLOTS]
    for i, it in enumerate(items):
        iid, count = int(it[0]), int(it[1])
        flags = int(it[2]) if len(it) > 2 else 0
        # the dispatcher reads the LOW u16 as flags, the HIGH u16 as count
        struct.pack_into("<IHH", b, ITEM_OFF + 8 * i, iid & 0xFFFFFFFF,
                         flags & 0xFFFF, max(0, count) & 0xFFFF)
    struct.pack_into("<I", b, 0x40, 1 if wallet_full else 0)
    return bytes(b)


def reward_push_body(event_id, block, subchannel=7):
    """Selector 134 sub 10 (quest event `event_id`) carrying `block` at
    body[20..87]. 0xffff = an event id no NPC table matches, so the push
    prints the reward and plays no scene."""
    b = bytearray(doc_novice.push_body(doc_novice.SUB_QUEST_EVENT, event_id,
                                       subchannel)).ljust(DATA_OFF, b"\x00")
    b = b[:DATA_OFF] + bytes(block[:BLOCK_LEN]).ljust(BLOCK_LEN, b"\x00")
    return bytes(b)


NO_SCENE = 0xFFFF


def _selftest():
    blk = reward_block(gil=1000, medals=1 << 2, rp=35, rank=4,
                       items=[(0x6D300000, 1), (0x69320000, 2, 1)])
    assert len(blk) == BLOCK_LEN
    assert struct.unpack_from("<IIII", blk, 0) == (1000, 4, 35, 4)
    assert struct.unpack_from("<IHH", blk, 0x10) == (0x6D300000, 0, 1)
    assert struct.unpack_from("<IHH", blk, 0x18) == (0x69320000, 1, 2)
    assert struct.unpack_from("<I", blk, 0x40)[0] == 0
    body = reward_push_body(NO_SCENE, blk)
    assert len(body) == DATA_OFF + BLOCK_LEN == 88
    assert body[1] == doc_novice.SEL_PUSH
    assert struct.unpack_from("<I", body, 12)[0] == doc_novice.SUB_QUEST_EVENT
    assert struct.unpack_from("<H", body, 16)[0] == NO_SCENE
    assert body[DATA_OFF:] == blk
    print("doc_reward self-test PASS")


if __name__ == "__main__":
    _selftest()
