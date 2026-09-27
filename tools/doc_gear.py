#!/usr/bin/env python3
"""Dirge of Cerberus MASK + ARMOR -- the equipped gear on the world door (2026-09-13).

The Status window's `Mask :` and `Armor :` rows were blank for every character.
They are not free text: they name the EQUIPPED item out of the player's own bag.

WHAT IS MEASURED (static, doc_eastloaded_slot09; the client's own lookups run
in doc_eemu):

  * Masks and suits are INVENTORY ITEMS. Item names via 0x0058f4a0(id); the
    ids read off the client's own item table:
      0x6330000N  0 DG Soldier Mask M, 1 DG Soldier Mask F, 2 SOLDIER Mask,
                  3 Gasmask, 4 Gutlet Facemask, 5 Shield Visor, 6 Devilhead,
                  7 Demonhead, 8 Diablohead, 9 Capsule Searcher, ...
      0x633100NN  the NAMED suits sit every 20 ids: 0x00 DG Soldier Suit,
                  0x14 Sniper Suit, 0x28 Speed Suit, 0x3C Magic Suit,
                  0x50 Armored Suit; every id between is a placeholder name
                  ("Suit 1" .. "Suit 99").
    Item-property record (0x0049acb8, 24 bytes): +12 = TYPE (7 mask, 8 suit),
    +16 = the LOOK index (measured off the client's own item records): a suit's
    armor look = id // 20 for all 100 suits (blocks of 20), a mask's model =
    MASK_MODEL below.
  * The Status window's builder 0x00aca248 copies the bag into its list and
    counts type 7 / type 8; the value filler 0x00aca828 prints the name of
    list[equipped index] (window+1801 mask / +1800 armor), blank when -1.
  * The EQUIPPED pair rides the selector-2 world door: setUserData copies
    body[76..99] to R+768..791 and getEquipItems hands the actor word 0
    (body[76]) as the MASK and word 1 (body[80]) as the SUIT (0x004aa430),
    each only if that id is also in the bag (measured against the client's own
    equip routine).
  * KEY: THE EQUIPPED GEAR DRESSES THE MODEL (doc_armorlook_measure.py, ALL
    PASS): every 0x004aa430 equip re-dresses through 0x006b1038, which starts
    from the costume (actor+552) and, with a suit equipped, REPLACES the armor
    bits with the suit's +16 (`c = (c & 0xffc7) | look << 3`); with a mask
    equipped it sets bit 7 + the mask model (`(c & 0xf0ff) | model << 8 | 0x80`),
    otherwise clears bit 7. So the costume's armor/mask bits only show when
    nothing is equipped; placeholder "Suit 2" (look 0) rendered every character
    in the DEFAULT armor, and the DG mask hides the created face.

  * The creation value R (charamake app92 | app93 << 8, doc_charastore.chr_code)
    stores each pick 0-BASED: color bits 0-1, ARMOR bits 3-5, gender bit 6,
    face bits 12-13. MEASURED 09-13 with a test character "Deb" made as Face
    Type 2 / Armor Type 4 / Color Camouflage -> R = 0x1019 = face 1, armor 3,
    color 1. The creation repacker 0x005a2598 accepts armor < 5.

THE ARMOR PICK -> SUIT ITEM: armor field t -> suit 0x63310000 + 20*t, the named
suit whose look is t (MEASURED via +16). Confirmed in a live session 09-13: "Lex" (app92
18 -> armor 2) was made with the SPEED SUIT (0x63310028). WARNING: The first version
mapped t -> 0x6331000t, which equipped the placeholder "Suit 2" (look 0).

WHAT IS INFERRED:
  * Retail issued starting gear (creation's "initial mask type" / "initial
    armor type", KelStr 35:24/25). The creation screen offers NO mask pick
    (checked in a live session, 09-13), so the mask is the standard DG Soldier Mask M or F by
    gender (chr_code bit 6, 1 = female).
    WARNING: 2026-09-26, SOURCED against that: the SUIT is issued at creation, the
    MASK is not. The Soldier Mask is EARNED on the DG Drone 2nd exam:
    "入手方法：DGドローン 2nd class 昇格時に入手" (dcff7-online blog, ameblo
    entry-10008498561, 2006-01-29); "DGドローン2nd昇進試験クリア後、試験教官から
    入手可能 ... 捨てることができない" (dc.jpn.org wiki ソルジャーマスク, Wayback
    20060828080401); "※クリア後にソルジャーマスク入手可能" (ameblo
    entry-10008424977, 2006-04-03 exam page). And the 03-24 update fixed
    "アイテム所持数がいっぱいだった場合にソルジャーマスクが取得できない不具合"
    (ameblo entry-10010936385): with a full bag the mask was not received.
    So a new character starts with NO mask: body[76] = NO_ITEM, which the
    client handles like an unequipped mask (getEquipItems equips word 0 only
    when that id is in the bag; the re-dress then clears costume bit 7 and
    the created FACE shows, as after Change Mask -> remove). KelStr 35:3 /
    35:24 ("Select Mask Type", "initial mask type") are unused strings: the
    Jan creation screen has no mask row. settle_soldier_mask() below keeps
    the mask for every character that was issued one before this rule
    (a wallet without MASK_RULE_MARK) and delivers an earned one. OURS: a
    mask owed while the bag is full stays owed until there is room (the
    post-03-24 behaviour, not January's bug), and a held Soldier Mask is
    worn at login unless the character's own Change Mask choice says
    otherwise (GearStore); the exam instructor's hand-over scene is not
    served, the mask arrives at the next world door.

CHANGE MASK / CHANGE ARMOR (2026-09-13; measured offline by running the
client's senders and its 241 arms, ALL PASS). Both are LOBBY COMMANDS on
selector 240 -> 241:
  * cmd 17 EQUIP (sender 0x00bd4f38): request body[16] = slot (0 mask, 1 suit),
    body[20] = item id, body[24..27] stale stack. The sender saves slot/item
    to [kelsvc+1056/1060] and changes nothing else.
  * cmd 18 UNEQUIP (sender 0x00bd5048): body[16] = slot as ONE byte (the rest
    stale). The Status screen only ever sends slot 0 -- armor cannot be removed
    (KelStr 60:78).
  * The 241 arms apply the change ONLY on our answer. [kelsvc+24] = u16 body[6]
    (negated when body[4] bit 0 is set, which makes both arms bail = refusal).
    Arm 17 (0x00bc92c8 -> 0x00be7470): R+768+4*slot = the SAVED item, and the
    costume word R+728 (u16) = body[6] VERBATIM. Arm 18 (0x00bc92f4 ->
    0x00be7440): the slot = 0xFFFFFFFF, costume bit 7 cleared.
    WARNING: The generic answer (body[6] = 0) therefore reset the costume to 0.
  * Costume bits (repacker 0x005a2598): 0-1 color, 3-5 armor (< 5), 6 gender,
    7 MASK WORN, 8-11 mask model (< 14, used when bit 7 is set), 12-13 face
    (shown when bit 7 is clear). equip_costume applies the same +16 edit the
    client's re-dress does, so body[6] agrees with what the model shows.
  GearStore keeps (mask, suit, costume) per character and docudp serves them
  back on the world door (body[76]/[80] + the costume window at body+100).
  Refusal CODE: SE's number for "cannot equip" is not located; REFUSE = 1 only
  has to be nonzero so the arm bails.
"""
import json
import os
import struct
import tempfile

import doc_unit

MASK_DG_M, MASK_DG_F = 0x63300000, 0x63300001
SUIT_DG = 0x63310000
SUIT_STEP = 20                                # suit look = id // 20 (item def +16)
SUIT_COUNT = 100                              # 0x63310000..0x63310063
ARMOR_TYPES = 5                               # repacker 0x005a2598: armor < 5
LOGIN_MASK_OFF, LOGIN_SUIT_OFF = 76, 80      # world-door body -> R+768 / R+772

#: mask item index -> model (item def +16, MEASURED doc_armorlook_defs.py)
MASK_MODEL = (0, 1, 2, 3, 4, 5, 6, 6, 6, 7, 8, 9, 10, 10, 10, 11, 12, 13, 13, 13,
              3, 0, 0, 0)

CMD_EQUIP, CMD_UNEQUIP = 17, 18
GEAR_CMDS = (CMD_EQUIP, CMD_UNEQUIP)
CMD_NAMES = {CMD_EQUIP: "EQUIP", CMD_UNEQUIP: "UNEQUIP"}
SLOT_MASK, SLOT_SUIT = 0, 1
SLOT_NAMES = ("mask", "suit")
REQ_SLOT, REQ_ITEM = 16, 20                   # 240 request body
MASK_CAT, SUIT_CAT = 0x6330, 0x6331
NO_ITEM = 0xFFFFFFFF                          # what arm 18 writes into the slot
MASK_WORN = 0x0080                            # costume bit 7
MASK_MODEL_BITS = 0x0F00                      # costume bits 8-11
ARMOR_BITS = 0x0038                           # costume bits 3-5
REFUSE = 1                                    # nonzero -> [kelsvc+24] < 0 -> bail


def armor_of(code):
    """The 0-based armor pick out of a chr_code value (bits 3-5)."""
    return (code >> 3) & 7


def suit_for_armor(armor):
    """The named suit item for an armor pick (0 DG Soldier .. 4 Armored)."""
    armor = armor if 0 <= armor < ARMOR_TYPES else 0
    return SUIT_DG | (armor * SUIT_STEP)


def armor_for_suit(item):
    """The armor look a suit dresses the model in (its def +16), or None."""
    if (item >> 16) & 0xFFFF != SUIT_CAT or (item & 0xFFFF) >= SUIT_COUNT:
        return None
    return (item & 0xFFFF) // SUIT_STEP


#: 2026-09-24: THE PLAYER'S HP comes from the equipped SUIT. Retail
#: data/bgd/bgd.bin (patch 20060124_3) section 4, a 1140-byte block the client
#: holds at [[0x005e66e8]+0x14], is a run of 8-entry u16 grade tables; a suit's
#: item record +16 is its class, then one 4-bit grade per stat, low nibble
#: first. Client code reads the melee (+0x40c, 0x004a8448), mobility
#: (+0x41c/+0x42c, 0x00699348), shooting (+0x43c) and magic (+0x45c) tables by
#: their nibbles; NOTHING in the client reads +0x3fc, the table keyed by the
#: first nibble (durability) -- the server sent the result as world-door HP.
#: So this is the retail server's lookup, by the table order the client proves.
#: Grade 7 (360) is unused by every real suit.
SUIT_HP_TABLE = (210, 240, 250, 270, 340, 100, 200, 360)   # block +0x3fc
#: suit index -> durability grade (bgd item +17 & 0xf). Soldier 3, Sniper 0,
#: Speed 1 (and its variant 0x29), Magic 2, Toughness 4. The other 94 items
#: of the category are unnamed placeholders ("服N") with filler grades past
#: the table; they take their class's named suit.
SUIT_DURABILITY = {0x00: 3, 0x14: 0, 0x28: 1, 0x29: 1, 0x3C: 2, 0x50: 4}


def suit_hp(item):
    """The max HP a suit gives (retail bgd durability table), or None."""
    look = armor_for_suit(item)
    if look is None:
        return None
    n = item & 0xFFFF
    grade = SUIT_DURABILITY.get(n, SUIT_DURABILITY[look * SUIT_STEP])
    return SUIT_HP_TABLE[grade]


def mask_model(item):
    """The model a mask dresses the model in (its def +16), or None."""
    n = item & 0xFFFF
    if (item >> 16) & 0xFFFF != MASK_CAT or n >= len(MASK_MODEL):
        return None
    return MASK_MODEL[n]


def starter_gear(female=False, armor=0):
    """(mask id, suit id) of the old issue (mask + suit at every login).
    Since 2026-09-26 only the SUIT is issued; see settle_soldier_mask."""
    return (MASK_DG_F if female else MASK_DG_M), suit_for_armor(armor)


SOLDIER_MASKS = (MASK_DG_M, MASK_DG_F)
#: the exam that earns it: quest 1 = DG Drone 2nd (doc_stats.EXAM_PROMOTIONS
#: 1 -> rank 2, doc_missions.EXAMS[1])
SOLDIER_MASK_EXAM = 1
#: shop-wallet fields (doc_shop.Shop writes MASK_RULE_MARK on every NEW wallet)
MASK_RULE_MARK = "smask"      # the earned-mask rule applies to this wallet
MASK_DUE = "smask_due"        # a Soldier Mask is owed (earned / legacy)


def soldier_mask(female=False):
    return MASK_DG_F if female else MASK_DG_M


def _held_masks(bag, female=False):
    order = (soldier_mask(female), soldier_mask(not female))
    return [m for m in order if bag.get("0x%08x" % m, 0) > 0]


def owe_soldier_mask(wallet):
    """The Drone 2nd exam was cleared: owe the mask unless one is held or
    already owed. True when this call created the debt."""
    if _held_masks(wallet.get("bag") or {}) or wallet.get(MASK_DUE):
        return False
    wallet[MASK_DUE] = 1
    return True


def settle_soldier_mask(wallet, female=False, bag_max=50):
    """At login: (Soldier Mask to wear or None, [notes]); mutates `wallet`
    (a doc_shop wallet dict). A wallet made before the rule (no
    MASK_RULE_MARK) belongs to a character that was ISSUED the mask at
    creation, so it keeps it: it is owed once and put in the persisted bag.
    An owed mask goes into the bag when there is room for a new stack."""
    bag = wallet.setdefault("bag", {})
    notes = []
    if not wallet.get(MASK_RULE_MARK):
        wallet[MASK_RULE_MARK] = 1
        if not _held_masks(bag, female):
            wallet[MASK_DUE] = 1
        notes.append("made before the earned-mask rule: keeps its Soldier Mask")
    held = _held_masks(bag, female)
    if wallet.get(MASK_DUE):
        if held:
            wallet.pop(MASK_DUE, None)
        elif len([v for v in bag.values() if v > 0]) < bag_max:
            bag["0x%08x" % soldier_mask(female)] = 1
            wallet.pop(MASK_DUE, None)
            held = _held_masks(bag, female)
            notes.append("Soldier Mask 0x%08x put in the bag" % held[0])
        else:
            notes.append("Soldier Mask OWED, bag full (%d) -- stays owed" % bag_max)
    return (held[0] if held else None), notes


def slot_accepts(slot, item):
    """Does `item` belong in `slot` (masks in 0, suits in 1)?"""
    cat = (item >> 16) & 0xFFFF
    return (slot == SLOT_MASK and cat == MASK_CAT) or (slot == SLOT_SUIT and cat == SUIT_CAT)


def equip_costume(code, slot, item):
    """The costume code after equipping `item` in `slot` -- what the 241
    answer's body[6] must carry (arm 17 stores it verbatim at R+728). The same
    edit the client's re-dress 0x006b1038 makes with the item's def +16."""
    code &= 0xFFFF
    if slot == SLOT_MASK:
        m = mask_model(item)
        if m is not None:
            return (code & ~MASK_MODEL_BITS) | MASK_WORN | (m << 8)
    if slot == SLOT_SUIT:
        t = armor_for_suit(item)
        if t is not None:
            return (code & ~ARMOR_BITS) | (t << 3)
    return code


def unequip_costume(code):
    """Arm 18's own edit: the mask-worn bit cleared."""
    return code & 0xFFFF & ~MASK_WORN


def parse_request(cmd, req_body):
    """(slot, item) from a 17/18 request body; item is None for 18."""
    if len(req_body) <= REQ_SLOT:
        return None
    slot = req_body[REQ_SLOT]
    if cmd == CMD_EQUIP:
        if len(req_body) < REQ_ITEM + 4:
            return None
        return slot, struct.unpack_from("<I", req_body, REQ_ITEM)[0]
    return slot, None


class GearStore:
    """{key: {"mask": id, "suit": id, "costume": code}} in one JSON file,
    rewritten whole on change (doc_shop's shape). The key is docudp's wallet
    key `member:N/0x<charid>`, so gear follows the same character as its bag."""

    def __init__(self, path):
        self.path = path
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {}

    def save(self):
        d = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".gear-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=1, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass

    def get(self, key):
        """The stored record for `key`, or None."""
        self.load()
        r = self.data.get(key)
        return dict(r) if isinstance(r, dict) else None

    def login(self, key, starter=None, costume=None):
        """(mask, suit, costume) to serve at login: the stored values, falling
        back to the starter pair / creation costume for anything never set."""
        r = self.get(key) or {}
        s = starter or (NO_ITEM, NO_ITEM)
        mask = r.get("mask", s[0])
        suit = r.get("suit", s[1])
        cost = r.get("costume", costume)
        return (s[0] if mask is None else mask), (s[1] if suit is None else suit), cost

    def body_for(self, cmd, req_body, key, base_costume, subchannel=7):
        """(241 body, note) for one Change mask / Change armor command, or
        (None, why). `base_costume` = the character's creation code, used only
        until a costume has been stored."""
        if cmd not in GEAR_CMDS:
            return None, "not a gear command"
        req = parse_request(cmd, req_body)
        tag = "%s (cmd %d)" % (CMD_NAMES[cmd], cmd)
        if req is None:
            return None, "%s: 240 body unreadable" % tag
        slot, item = req
        rec = self.get(key) or {}
        cur = rec.get("costume", base_costume)

        def refuse(why):
            return (doc_unit.answer_head(cmd, subchannel, fail=REFUSE),
                    "%s REFUSED: %s" % (tag, why))

        if cur is None:
            # answering without a known costume would put a made-up look in R+728
            return refuse("no costume known for %s (no stored record, no roster "
                          "entry) -- refused rather than reset the look" % key)
        if cmd == CMD_EQUIP:
            if slot not in (SLOT_MASK, SLOT_SUIT) or not slot_accepts(slot, item):
                return refuse("slot %d cannot hold 0x%08x" % (slot, item))
            new = equip_costume(cur, slot, item)
            rec[SLOT_NAMES[slot]] = item
            what = "%s 0x%08x" % (SLOT_NAMES[slot], item)
        else:
            if slot != SLOT_MASK:
                return refuse("slot %d cannot be emptied (only the mask; KelStr 60:78)"
                              % slot)
            new = unequip_costume(cur)
            rec["mask"] = NO_ITEM
            what = "mask removed"
        rec["costume"] = new
        self.data[key] = rec
        self.save()
        return (doc_unit.answer_head(cmd, subchannel, value=new),
                "%s [%s]: %s, costume 0x%04x -> 0x%04x at body[6] (stored)"
                % (tag, key, what, cur & 0xFFFF, new))


if __name__ == "__main__":
    assert starter_gear(False) == (0x63300000, 0x63310000)
    assert starter_gear(True) == (0x63300001, 0x63310000)
    # live session 09-13: Lex (app92 18 -> armor 2) was made with the SPEED SUIT
    assert armor_of(18) == 2 and starter_gear(False, 2) == (0x63300000, 0x63310028)
    assert armor_of(0x1019) == 3 and starter_gear(False, 3)[1] == 0x6331003C   # Magic Suit
    assert starter_gear(False, 4)[1] == 0x63310050                             # Armored Suit
    assert starter_gear(False, 7)[1] == SUIT_DG          # out of range -> DG suit
    assert [armor_for_suit(suit_for_armor(t)) for t in range(5)] == [0, 1, 2, 3, 4]
    # item def +16 (doc_armorlook_defs.py): suit look = id // 20, all 100 suits
    assert armor_for_suit(0x63310002) == 0 and armor_for_suit(0x63310029) == 2
    assert armor_for_suit(0x63310063) == 4 and armor_for_suit(0x63310064) is None
    assert mask_model(0x63300001) == 1 and mask_model(0x63300009) == 7
    assert mask_model(0x6330000E) == 10 and mask_model(0x63300018) is None
    # costume math = the client's re-dress 0x006b1038
    assert equip_costume(0x1019, SLOT_MASK, 0x63300009) == 0x1799   # Capsule Searcher = model 7
    assert equip_costume(0x1799, SLOT_MASK, 0x63300002) == 0x1299
    assert equip_costume(0x1019, SLOT_SUIT, 0x63310050) == 0x1021   # Armored -> armor 4
    assert equip_costume(0x1019, SLOT_SUIT, 0x63310014) == 0x1009   # Sniper -> armor 1
    assert equip_costume(0x1019, SLOT_SUIT, 0x63310004) == 0x1001   # "Suit 4" = look 0
    assert equip_costume(0x1012, SLOT_SUIT, 0x63310028) == 0x1012   # Lex + Speed Suit
    assert equip_costume(0x1012, SLOT_MASK, 0x63300000) == 0x1092   # measured: mask worn
    assert equip_costume(0x1019, SLOT_MASK, 0x63310000) == 0x1019   # wrong category
    assert unequip_costume(0x19B9) == 0x1939
    assert parse_request(CMD_EQUIP, bytes(16) + b"\x00\x00\x00\x00\x00\x00\x30\x63") == (0, 0x63300000)
    # 2026-09-26: the Soldier Mask is EARNED (Drone 2nd exam), not issued
    w = {"gil": 3000, "bag": {}, MASK_RULE_MARK: 1}            # a new character
    assert settle_soldier_mask(w, False) == (None, []) and w["bag"] == {}
    assert owe_soldier_mask(w) and not owe_soldier_mask(w)      # owed once
    m, n = settle_soldier_mask(w, True)
    assert m == MASK_DG_F and w["bag"] == {"0x63300001": 1} and MASK_DUE not in w, n
    assert not owe_soldier_mask(w), "TWIN: a held mask is never owed again"
    assert settle_soldier_mask(w, True)[0] == MASK_DG_F and len(w["bag"]) == 1
    old = {"gil": 10, "bag": {"0x6f300000": 1}}                # before the rule
    assert settle_soldier_mask(old, False)[0] == MASK_DG_M, "legacy keeps it"
    assert old["bag"]["0x63300000"] == 1 and old[MASK_RULE_MARK] == 1
    assert settle_soldier_mask(old, False)[0] == MASK_DG_M and len(old["bag"]) == 2
    full = {"bag": {"0x%08x" % i: 1 for i in range(50)}, MASK_RULE_MARK: 1,
            MASK_DUE: 1}
    m, n = settle_soldier_mask(full, False, 50)
    assert m is None and full[MASK_DUE] == 1 and "bag full" in n[0], n
    del full["bag"]["0x00000000"]
    assert settle_soldier_mask(full, False, 50)[0] == MASK_DG_M and MASK_DUE not in full
    # 2026-09-24: suit HP = the retail durability table
    assert [suit_hp(suit_for_armor(t)) for t in range(5)] == [270, 210, 240, 250, 340]
    assert suit_hp(0x63310029) == 240 and suit_hp(0x63310004) == 270   # placeholder -> class
    assert suit_hp(0x63300000) is None and suit_hp(NO_ITEM) is None      # a mask / empty slot
    # and re-derived from the game's own data/bgd/bgd.bin (patch 20060124_3)
    # when POL_DOC_BGD names a copy read out of your own install, so the
    # constants above cannot drift from the game data (the twin: a wrong table
    # offset reads the float/-1 words before it and fails)
    _bgd = os.environ.get("POL_DOC_BGD") or ""
    if _bgd and os.path.exists(_bgd):
        _b = open(_bgd, "rb").read()
        # directory at +36: {offset, count, stride, 0} per section; 4 = the block
        _blk = struct.unpack_from("<I", _b, 36 + 16 * 4)[0]
        assert _blk == 12004
        assert struct.unpack_from("<8H", _b, _blk + 0x3FC) == SUIT_HP_TABLE
        assert struct.unpack_from("<8H", _b, _blk + 0x3F8) != SUIT_HP_TABLE
        for _i in range(474):
            _r = _b[260 + 24 * _i:284 + 24 * _i]
            _id = struct.unpack_from("<I", _r)[0]
            if _id >> 16 == SUIT_CAT and (_id & 0xFFFF) in SUIT_DURABILITY:
                assert _r[17] & 0xF == SUIT_DURABILITY[_id & 0xFFFF], hex(_id)
        print("doc_gear: suit HP table matches retail bgd.bin")
    print("doc_gear self-test PASS")
