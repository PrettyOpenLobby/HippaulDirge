#!/usr/bin/env python3
"""Dirge of Cerberus lobby ITEM QUESTS: DGD Soar, Este-D, DGSC Hiren (2026-09-24),
plus DGC Sturm's per-rank lines (see sturm()).

Our Jan-24 client ships all three scenes (quest_scr003 ev_n26 / ev_n29 /
ev_n36, retail lobby savestate) but docudp served each one fixed line. The
branches, their text (the client's NPC dialogue table) and the Lifestream NPC
fan archive (source for each NPC's quest, summarised below):

DGD Soar (lnpc 26), by WIN count; he hands the player broken items whether
they want them or not (source: Lifestream fan archive):
    1534 VICT_01_30     under 30 wins: "go and train"
    1533 VICT_30_150    30+: forces a Broken Handgun on you   (reports done)
    1532 VICT_HAND      after the handgun, under 150: "come back with victories"
    1531 VICT_BALERU_150  150+: forces a Broken Barrel on you (reports done)
    1530 VICT_BALERU_GET  both given

Este-D (lnpc 29): hand her a Dandelion and chance decides whether she throws
it away or keeps it, and keeping it gives a Gasmask (source: Lifestream fan
archive).
    201 FST        first meeting (no report -> met on serve)
    202 HANA_NASHI no flower
    203 HANA_HAZURE the flower is snatched and THROWN AWAY (no report -> on serve)
    204 HANA_ATARI  the flower is taken, a Gasmask given       (reports done)
    205 MASK_AF     after the mask

DGSC Hiren (lnpc 36): Fuzzy Seeds found in the Collector's Mind mission can be
handed to her, and she grows one into a Dandelion over a few real-time days
(source: Lifestream fan archive). Her own lines
stage it: sprouted (_03), bud (_05), bloomed "this past week" (_07):
    1541 HAJIME        first meeting                          (reports done)
    1556 TN_NASHI      no seed (first time)
    1540 TN_ARI        takes the Fuzzy Seed, starts growing   (reports done)
    1539 TN_AZUKE      growing, days 0-2
    1538 TN_AZUKE_03   sprouted, day 2+ (OURS)                (reports done)
    1552 TN_AZUKE_03B  ...seen
    1537 TN_AZUKE_05   bud, day 4+ (OURS)                     (reports done)
    1551 TN_AZUKE_05B  ...seen
    1536 TN_AZUKE_07   bloomed, day 5+ (= 120 h, players' sources): gives
                       the Dandelion                          (reports done)
    later seeds: 1542 HANA_OK_TNN (no seed) / 1559 HANA_OK_TNA (takes it,
    reports done), growing 1553 TNK_AZUKE2, 1558 TNK_AZUKE_03, 1557
    TNK_AZUKE_05 (no reports -> stage on serve), bloom 1561 TN_HANA2 (no
    report -> the flower on serve).
    WITHERING: unless the player looks in on it about once per real day,
    the seed withers and the flower is lost (source: January 2006 player
    blog). Hiren's own lines ask the player to visit often. The retail ev_n36 (retail
    savestate slot 08, doc_jdis) has the scenes, none reports done except
    1554:
    1535 HANA_KARE     "I let it wither..." (first time)       no report
    1550 HANA_KARE2    "I let it wither again..."              no report
    1555 TNK_NASHI     after a withered seed: no seed          no report
    1554 TNK_AZUKE     after a withered seed: takes a new one  (reports done)
    Rule (OURS in its exact shape): a seed withers when more than
    HIREN_WITHER_DAY (1 day, docudp --npc-hiren-wither) passed between two
    walk-ups to her while it grew; the time after the bloom does not count
    (a bloomed flower waits). The withered seed is gone, the chain resets to
    "bring a seed" (1555 / 1554); the growth after it follows the cycle as
    before. A seed planted before this rule starts its clock at the next
    walk-up (no instant wither on deploy).
NOT served: the standby lines (Y), 1549.

OURS (flagged): Este-D's odds (none published; the sources call it rare ->
ESTE_ACCEPT, 0.2);
Hiren's sprout / bud days (her bloom at 5 days = 120 h is the players'); the win
count = BT + TBT + FA wins. Items move in the SERVER bag (doc_shop); the
client's inventory shows them from the next world door. The retail scenes
send nothing about items: ev_n29's only native call is one
reportQuestEventDone (in the 204 branch), no bag check, no item transaction
(retail lobby savestate, doc_jdis 2026-09-26) -- so the server alone decides
who holds the flower.

WHERE THE FUZZY SEED COMES FROM (docudp --fuzzy-seed): the Lifestream fan
archive's mission and NPC pages both say the seeds are found in the Collector's
Mind mission. SE's
own church data agrees (an offline run of the client's own code (doc_item_generators) over the
retail 20060124_3 z208 bzd -> doc_item_generators.json): item set 7 is the
Fuzzy Seed ALONE at weight 100, set 8 the seed at 25, and one set-7 node sits
in five of the Church's mission situations (3000 and 3002 at (1159, -242,
1374), 3003, 3004, 3005); no other zone's data names a quest item. So the seed
is a FIELD item, as the player guides say too: picked up on the church's
2nd floor in Collector's Mind or another church map (source: 2006 player
guide (FFCheats) and a 2006 player wiki, quest pages). mission_items() places it once per run of any mission whose
situation has SE's 100 % node, and for Collector's Mind always (situation
3000's node when the room's own situation has none -- which situation SE ran
quest 16 in is not decoded: OURS); docudp credits the picker's server bag on
the pick-up and debits it on a drop. Whether (1159, -242, 1374) is the "2nd
floor" is not checked on a screen. doc_field never rolls it
(a 100 % generator would respawn it every RESPAWN_S). The old "one seed per
clear" (SEEDS_PER_CLEAR) stays as --fuzzy-seed clear.

NOT BUILT -- no retail scene, text or item exists in this client (checked
2026-09-26):
  * Ljungbery (Plain Earrings, a March 2006 event quest): lnpc 5
    is PARKED in SE's retail bzd and quest_scr003.ev has no table for it.
  * DGSC Jingi (lnpc 43, two April 2006 event quests) and DGG Iruka (lnpc
    42, a Phantasmask event quest): the retail ev_n43 / ev_n42 play only ID_AREA_D / ID_AREA_C
    flavor lines (the Mako bather, Area 3's lost souls), two ids each, no
    reportQuestEventDone. The Phantasmask item exists (0x6330000F), nothing
    hands it out.
  * Energetic Bonus Ticket / Cerulean Bullet / Plain Earrings / the book: the
    retail item table has only placeholders "QI21".."QI26", "QI29".."QI34" in
    the quest-item category 0x6430, and their missions (Sahagin / Cactus Dance
    Apr 20, The Blue Roar Apr 7) are not in the retail mission table (group 47
    holds 43 quests; 43 "Desert test mission" is SE's unfinished stand-in).
  * The Crimson / Verdant TICKETS (0x64300013 / 0x64300014, both in the item
    table): FFCheats' mission pages pay them for 22 Steel Wall / 29 Double
    Attack / 30 Forest of Grudge and charge 5 Crimson for 36 / 3 Verdant for
    27. Those pages carry the BETA text (Double Attack's objective as in
    the Dec 2005 base lobby.bin's 48:28, and the pages say they describe
    the beta); the Jan build rewrote 48:28 and its reward texts name rank points
    (51:21 / 51:29 "+50", 51:35 "+35", 51:26 / 51:28 "by performance"), and
    the Lifestream archive lists no ticket for them. A ticket gate would lock
    27 / 36 for good, so it stays out.
  * Este-D giving a gasmask anyway after many rejections (player wiki) and
    West-D's tune-up kits for a seed + 50 battles (FFCheats): ev_n29 has no
    branch for either (200..206 only) and the item table has no loose mask.
  * Soar's FFCheats chain (Phantasmask at 50 TBT wins, SC Frame Kit at 200
    TBT + 10 BT wins; handgun at 50 battles): the Jan ev_n26 has only the
    handgun / barrel branches, keyed VICT_01_30 / VICT_30_150 / BALERU_150,
    so the 30 / 150 thresholds are the client's own.
"""
import random
import time

SOAR, ESTE, HIREN, STURM = 26, 29, 36, 11
NPCS = (SOAR, ESTE, HIREN, STURM)

# item ids, from the client's own item table
FUZZY_SEED = 0x6430001B
DANDELION = 0x6430001C
GASMASK = 0x63300003
BROKEN_HANDGUN = 0x6F300009
BROKEN_BARREL = 0x6F310009

COLLECTORS_MIND = 16          # the mission the seeds come from
SEEDS_PER_CLEAR = 1           # OURS (--fuzzy-seed clear): the archive gives no count
SEED_MODES = ("field", "clear", "off")

# quest -> (zone, quest item, the situation whose node to use when the room's
# own situation has none). The item is placed where SE's generator for it
# stands, at weight 100 only (set 8's 25 % node is in no situation).
MISSION_ITEMS = {COLLECTORS_MIND: (208, FUZZY_SEED, 3000)}
#: quest items that live on a mission's field: a pick-up / drop moves them in
#: the SERVER bag too (docudp), and no item generator rolls them (doc_field)
FIELD_QUEST_ITEMS = frozenset(it for _z, it, _s in MISSION_ITEMS.values())
#: 2026-09-26: LOW. No rate is published, but every player source says she
#: mostly throws it away and the Gasmask is rare (source: 2006 player wiki,
#: quest and Gasmask pages; player guide (FFCheats), item list). The figure itself is OURS (--npc-este-accept; it was 0.5).
ESTE_ACCEPT = 0.2
DAY = 86400.0
#: 2026-09-26: the BLOOM is sourced: 120 hours, i.e. 5 days, of daily visits
#: (source: player guide (FFCheats) and a 2006 player wiki, quest pages).
#: Hiren's own mention of a week (TN_AZUKE_07_10) is flavor, and the _03 / _05 / _07 key suffixes are stage
#: names, not days (a 7-day reading contradicts both players' sources). The
#: sprout and bud days are OURS, spread before the bloom. It was 3 / 5 / 7.
HIREN_SPROUT_DAY, HIREN_BUD_DAY, HIREN_BLOOM_DAY = 2.0, 4.0, 5.0
#: 2026-09-26: about once per real day (source: January 2006 player blog); the exact
#: window is OURS (docudp --npc-hiren-wither, 0 = never withers)
HIREN_WITHER_DAY = 1.0
KEY = "npcq"                  # career field

SOAR_WINS_HANDGUN, SOAR_WINS_BARREL = 30, 150


def _state(career, npc):
    return (career or {}).get(KEY, {}).get(str(npc), {})


def wins(career):
    c = career or {}
    return sum(int((c.get(m) or {}).get("w", 0)) for m in ("bt", "tbt", "fa"))


# --- decisions: (event, state_changes, bag_changes, why) -------------------
# bag_changes = [(item, +n / -n)], applied by the caller to the server bag

def soar(career):
    st = _state(career, SOAR)
    w = wins(career)
    if not st.get("handgun"):
        if w < SOAR_WINS_HANDGUN:
            return 1534, {}, [], "%d win(s) < %d" % (w, SOAR_WINS_HANDGUN)
        return 1533, {}, [], "%d wins: the Broken Handgun (on done)" % w
    if not st.get("barrel"):
        if w < SOAR_WINS_BARREL:
            return 1532, {}, [], "%d win(s) < %d" % (w, SOAR_WINS_BARREL)
        return 1531, {}, [], "%d wins: the Broken Barrel (on done)" % w
    return 1530, {}, [], "both broken items given"


def este(career, has_flower, rnd=random.random, accept=ESTE_ACCEPT):
    st = _state(career, ESTE)
    if st.get("mask"):
        return 205, {}, [], "gasmask already given"
    if not st.get("met"):
        return 201, {"met": 1}, [], "first meeting"
    if not has_flower:
        return 202, {}, [], "no Dandelion in the bag"
    if rnd() < accept:
        return 204, {}, [], "she LIKES the flower (flower -> gasmask on done)"
    return 203, {}, [(DANDELION, -1)], "she throws the flower away"


def hiren(career, has_seed, now=None, day=DAY, wither=HIREN_WITHER_DAY):
    ev, chg, bag, why = _hiren(career, has_seed, now, day, wither)
    return ev, chg, bag, why


def _hiren(career, has_seed, now, day, wither):
    st = _state(career, HIREN)
    now = time.time() if now is None else now
    cycle = int(st.get("cycle", 0))
    if not st.get("met"):
        return 1541, {}, [], "first meeting"
    at = st.get("seed_at")
    if at is None:
        if st.get("withered"):
            if not has_seed:
                return 1555, {}, [], "no Fuzzy Seed (the last one withered)"
            return 1554, {}, [], "takes a Fuzzy Seed after a withered one (on done)"
        if not has_seed:
            return (1556 if cycle == 0 else 1542), {}, [], "no Fuzzy Seed in the bag"
        return ((1540 if cycle == 0 else 1559), {}, [],
                "takes the Fuzzy Seed (on done)")
    days = (now - float(at)) / float(day)
    stage = int(st.get("stage", 0))
    first = cycle == 0
    if wither and wither > 0:
        seen = st.get("seen_at")
        last = now if seen is None else float(seen)
        bloom_t = float(at) + HIREN_BLOOM_DAY * float(day)
        gap = (min(now, bloom_t) - last) / float(day)
        if gap > wither:
            kare = int(st.get("kare", 0))
            return ((1535 if kare == 0 else 1550),
                    {"seed_at": None, "stage": 0, "seen_at": None,
                     "kare": kare + 1, "withered": 1}, [],
                    "WITHERED: %.2f day(s) between visits > %.2f" % (gap, wither))
    ev, chg, bag, why = _hiren_grow(st, days, stage, first, cycle)
    if st.get("seed_at") is not None and "seed_at" not in chg:
        chg = dict(chg, seen_at=now)          # she saw you: the clock restarts
    return ev, chg, bag, why


def _hiren_grow(st, days, stage, first, cycle):
    if days >= HIREN_BLOOM_DAY:
        if first:
            return 1536, {}, [], "day %.1f: BLOOMED (Dandelion on done)" % days
        return (1561, {"seed_at": None, "stage": 0, "cycle": cycle + 1},
                [(DANDELION, 1)], "day %.1f: bloomed again (Dandelion)" % days)
    if days >= HIREN_BUD_DAY:
        if stage < 5:
            if first:
                return 1537, {}, [], "day %.1f: the bud" % days
            return 1557, {"stage": 5}, [], "day %.1f: the bud" % days
        return (1551 if first else 1553), {}, [], "day %.1f: bud seen" % days
    if days >= HIREN_SPROUT_DAY:
        if stage < 3:
            if first:
                return 1538, {}, [], "day %.1f: sprouted" % days
            return 1558, {"stage": 3}, [], "day %.1f: sprouted" % days
        return (1552 if first else 1553), {}, [], "day %.1f: sprout seen" % days
    return (1539 if first else 1553), {}, [], "day %.1f: growing" % days


# DGC Sturm (lnpc 11, the battle-system briefer): one line set per RANK held
# (ev_n11 tableswitch 1130..1230); the fan archive notes he says more with
# each promotion. Rank 1 keeps the tutorial 1131 we always served; 2..9
# = 1220 DR2 .. 1227 TR1. At Trooper 1st the instructor story plays once, in
# order: 1228 TR1_KAF ("Congratulations on making Trooper 1st ... that
# instructor has me concerned"), 1229 TR1_KOUHAI ("he went a little too far"),
# then 1227. 1130 / 1230 are the standby lines (not served, as for the rest).
STURM_TUTORIAL = 1131
STURM_RANK = {2: 1220, 3: 1221, 4: 1222, 5: 1223, 6: 1224, 7: 1225, 8: 1226,
              9: 1227}
STURM_TR1_STORY = (1228, 1229)


def sturm(career):
    rank = int((career or {}).get("rank", 1) or 1)
    if rank < 2:
        return STURM_TUTORIAL, {}, [], "rank %d: the tutorial" % rank
    if rank >= 9:
        told = int(_state(career, STURM).get("tr1_story", 0))
        if told < len(STURM_TR1_STORY):
            return (STURM_TR1_STORY[told], {"tr1_story": told + 1}, [],
                    "Trooper 1st: the instructor story, part %d" % (told + 1))
        return STURM_RANK[9], {}, [], "rank %d: the Trooper 1st line" % rank
    return STURM_RANK[rank], {}, [], "rank %d line" % rank


def mission_items(quest, zone, situation=0, table=None):
    """[(item, qty, (x, y, z))] -- the quest items a mission run finds on its
    field: SE's own generator nodes for a FIELD quest item (weight 100) in
    the room's `situation` of `zone` (any mission: the player wiki names
    Collector's Mind and other church maps), else, for a MISSION_ITEMS quest in its zone,
    the fallback situation's. [] when neither applies or there is no data."""
    if table is None:
        import doc_field
        table = doc_field.load()

    def nodes(z, sit):
        sets, sits = table.get(int(z or 0), ({}, {}))
        return [(item, max(1, int(qty)), pos)
                for pos, st in sits.get(int(sit or 0), ())
                for item, qty, weight in sets.get(st, ())
                if item in FIELD_QUEST_ITEMS and weight >= 100]
    own = nodes(zone, situation)
    if own:
        return own
    spec = MISSION_ITEMS.get(quest)
    if spec is None or int(zone or 0) != spec[0]:
        return []
    return [n for n in nodes(spec[0], spec[2]) if n[0] == spec[1]]


def decide(npc, career, bag, now=None, rnd=random.random, day=DAY,
           accept=ESTE_ACCEPT, wither=HIREN_WITHER_DAY):
    """(event, state_changes, bag_changes, why) for a walk-up to `npc`;
    `bag` = {item_id: qty} (the server's)."""
    bag = bag or {}
    if npc == SOAR:
        return soar(career)
    if npc == ESTE:
        return este(career, bag.get(DANDELION, 0) > 0, rnd, accept)
    if npc == HIREN:
        return hiren(career, bag.get(FUZZY_SEED, 0) > 0, now, day, wither)
    if npc == STURM:
        return sturm(career)
    return None


def on_done(event, career, now=None):
    """(npc, state_changes, bag_changes, why) for command 27 `event` (the
    scene reported itself done), or None when that event does nothing."""
    now = time.time() if now is None else now
    hs = _state(career, HIREN)
    cyc = int(hs.get("cycle", 0))
    # a done report can arrive twice (a retransmit, a replayed scene): every
    # gift / take is guarded by the state it creates
    if event == 1533 and _state(career, SOAR).get("handgun"):
        return None
    if event == 1531 and _state(career, SOAR).get("barrel"):
        return None
    if event == 204 and _state(career, ESTE).get("mask"):
        return None
    if event in (1540, 1559, 1554) and hs.get("seed_at") is not None:
        return None
    if event == 1536 and hs.get("seed_at") is None:
        return None
    if event == 1533:
        return SOAR, {"handgun": 1}, [(BROKEN_HANDGUN, 1)], "Broken Handgun given"
    if event == 1531:
        return SOAR, {"barrel": 1}, [(BROKEN_BARREL, 1)], "Broken Barrel given"
    if event == 204:
        return ESTE, {"mask": 1}, [(DANDELION, -1), (GASMASK, 1)], "flower -> Gasmask"
    if event == 1541:
        return HIREN, {"met": 1}, [], "met"
    if event in (1540, 1559, 1554):
        return (HIREN, {"seed_at": now, "stage": 0, "seen_at": now,
                        "withered": None}, [(FUZZY_SEED, -1)],
                "Fuzzy Seed entrusted (cycle %d%s)"
                % (cyc, ", after a withered one" if event == 1554 else ""))
    if event == 1538:
        return HIREN, {"stage": 3}, [], "sprout seen"
    if event == 1537:
        return HIREN, {"stage": 5}, [], "bud seen"
    if event == 1536:
        return (HIREN, {"seed_at": None, "stage": 0, "cycle": cyc + 1},
                [(DANDELION, 1)], "bloomed: Dandelion given")
    return None


def apply(career, npc, changes):
    """Merge `changes` into the career's npcq state for `npc`."""
    if not changes:
        return
    q = career.setdefault(KEY, {}).setdefault(str(npc), {})
    for k, v in changes.items():
        if v is None:
            q.pop(k, None)
        else:
            q[k] = v


def _selftest():
    fails = []

    def check(c, what):
        if not c:
            fails.append(what)
        print("  %s %s" % ("ok  " if c else "FAIL", what))

    c = {"bt": {"w": 10}, "tbt": {"w": 15}}
    check(soar(c)[0] == 1534, "Soar: 25 wins -> 'go and train'")
    c["tbt"]["w"] = 20
    check(soar(c)[0] == 1533, "Soar: 30 wins -> the Broken Handgun scene")
    n, st, bag, _ = on_done(1533, c)
    apply(c, n, st)
    check(bag == [(BROKEN_HANDGUN, 1)] and soar(c)[0] == 1532,
          "Soar: done gives the handgun once, then 'come back with victories'")
    c["fa"] = {"w": 120}
    check(soar(c)[0] == 1531, "Soar: 150 wins -> the Broken Barrel scene")
    apply(c, *on_done(1531, c)[:2])
    check(soar(c)[0] == 1530, "Soar: both given -> the closing lines")

    e = {}
    ev, st, _, _ = este(e, True)
    check(ev == 201, "Este-D: first meeting first, even holding a flower")
    apply(e, ESTE, st)
    check(este(e, False)[0] == 202, "Este-D: no Dandelion")
    ev, st, bag, _ = este(e, True, rnd=lambda: 0.9)
    check(ev == 203 and bag == [(DANDELION, -1)], "Este-D: bad luck -> thrown away")
    ev, st, bag, _ = este(e, True, rnd=lambda: 0.1)
    check(ev == 204 and bag == [], "Este-D: good luck -> 204, nothing moved yet")
    n, st, bag, _ = on_done(204, e)
    apply(e, n, st)
    check(bag == [(DANDELION, -1), (GASMASK, 1)] and este(e, True)[0] == 205,
          "Este-D: done trades the flower for the Gasmask, then 205 for good")

    def hiren0(*a):
        # the growth ladder alone (no withering: these visits are days apart)
        return hiren(*a, wither=0)

    h, t0 = {}, 1000.0
    check(hiren0(h, True, t0)[0] == 1541, "Hiren: first meeting")
    apply(h, *on_done(1541, h)[:2])
    check(hiren0(h, False, t0)[0] == 1556, "Hiren: no seed")
    check(hiren0(h, True, t0)[0] == 1540, "Hiren: a seed -> TN_ARI")
    n, st, bag, _ = on_done(1540, h, now=t0)
    apply(h, n, st)
    check(bag == [(FUZZY_SEED, -1)], "Hiren: done takes the seed")
    check(hiren0(h, False, t0 + 1 * DAY)[0] == 1539, "Hiren: day 1 growing")
    check(hiren0(h, False, t0 + 1.9 * DAY)[0] == 1539,
          "Hiren: TWIN day 1.9 still growing")
    check(hiren0(h, False, t0 + 2.2 * DAY)[0] == 1538, "Hiren: day 2 sprouted")
    apply(h, *on_done(1538, h)[:2])
    check(hiren0(h, False, t0 + 3 * DAY)[0] == 1552, "Hiren: sprout seen")
    check(hiren0(h, False, t0 + 4.2 * DAY)[0] == 1537, "Hiren: day 4 bud")
    apply(h, *on_done(1537, h)[:2])
    check(hiren0(h, False, t0 + 4.9 * DAY)[0] == 1551,
          "Hiren: bud seen; TWIN day 4.9 is not yet the bloom")
    check(hiren0(h, False, t0 + 5.0 * DAY)[0] == 1536,
          "Hiren: day 5 (120 h) bloomed")
    n, st, bag, _ = on_done(1536, h)
    apply(h, n, st)
    check(bag == [(DANDELION, 1)] and hiren0(h, False, t0 + 8 * DAY)[0] == 1542,
          "Hiren: done gives the Dandelion; after it, 'no seed' is HANA_OK_TNN")
    check(hiren0(h, True, t0 + 8 * DAY)[0] == 1559, "Hiren: another seed -> 1559")
    apply(h, *on_done(1559, h, now=t0 + 8 * DAY)[:2])
    ev, st, bag, _ = hiren0(h, False, t0 + 15.5 * DAY)
    check(ev == 1561 and bag == [(DANDELION, 1)],
          "Hiren: the second flower blooms on serve (1561 has no done report)")
    # 2026-09-26: WITHERING -- a visit gap over a day kills the seed
    w, t0 = {}, 5000.0
    apply(w, *on_done(1541, w)[:2])
    apply(w, *on_done(1540, w, now=t0)[:2])
    ev, st, _b, _w = hiren(w, False, t0 + 0.9 * DAY)
    check(ev == 1539 and st.get("seen_at") == t0 + 0.9 * DAY,
          "wither: a visit inside a day -> still growing, the clock restarts")
    apply(w, HIREN, st)
    ev, st, _b, _w = hiren(w, False, t0 + 1.8 * DAY)
    check(ev == 1539, "wither: TWIN 1.8 days after planting, 0.9 after the last "
          "visit -> alive (the clock runs from the last VISIT)")
    apply(w, HIREN, st)
    ev, st, _b, why = hiren(w, False, t0 + 2.9 * DAY)
    check(ev == 1535 and st.get("seed_at", 1) is None and st.get("withered") == 1,
          "wither: 1.1 days unvisited -> 1535 HANA_KARE, the seed is gone (%s)" % why)
    apply(w, HIREN, st)
    check(hiren(w, False, t0 + 3 * DAY)[0] == 1555,
          "wither: afterwards, no seed -> 1555 TNK_NASHI")
    check(hiren(w, True, t0 + 3 * DAY)[0] == 1554,
          "wither: afterwards, a seed -> 1554 TNK_AZUKE")
    n, st, bag, _ = on_done(1554, w, now=t0 + 3 * DAY)
    apply(w, n, st)
    check(bag == [(FUZZY_SEED, -1)] and "withered" not in _state(w, HIREN)
          and on_done(1554, w) is None,
          "wither: 1554 done takes the new seed once; the chain restarts")
    check(hiren(w, False, t0 + 3.5 * DAY)[0] == 1539,
          "wither: the new seed grows (first cycle lines, no flower yet)")
    ev, st, _b, _w = hiren(w, False, t0 + 5 * DAY)
    check(ev == 1550, "wither: a second withering -> 1550 HANA_KARE2 ('again')")
    b2, t1 = {}, 9000.0
    apply(b2, *on_done(1541, b2)[:2])
    apply(b2, *on_done(1540, b2, now=t1)[:2])
    for d in (0.9, 1.8, 2.7, 3.6, 4.5):
        apply(b2, HIREN, hiren(b2, False, t1 + d * DAY)[1])
    check(hiren(b2, False, t1 + 9 * DAY)[0] == 1536,
          "wither: visited daily to day 4.5, the bloom at day 5 WAITS (no wither "
          "counted after the bloom)")
    lg = {KEY: {str(HIREN): {"met": 1, "seed_at": t1, "stage": 0}}}
    ev, st, _b, _w = hiren(lg, False, t1 + 3 * DAY)
    check(ev == 1538 and st.get("seen_at") == t1 + 3 * DAY,
          "wither: a seed planted before the rule (no seen_at) starts its clock "
          "now, no instant wither")
    check(hiren(lg, False, t1 + 3 * DAY, wither=0)[0] == 1538
          and hiren({KEY: {str(HIREN): {"met": 1, "seed_at": t1, "seen_at": t1}}},
                    False, t1 + 3 * DAY, wither=0)[0] == 1538,
          "wither: --npc-hiren-wither 0 = never withers")
    check(sturm({"rank": 1})[0] == 1131 and sturm({})[0] == 1131,
          "Sturm: rank 1 (or none) -> the tutorial 1131")
    check([sturm({"rank": r})[0] for r in range(2, 9)] == list(range(1220, 1227)),
          "Sturm: ranks 2..8 -> 1220..1226")
    st9 = {"rank": 9}
    seq = []
    for _ in range(4):
        ev, chg, _b, _w = sturm(st9)
        apply(st9, STURM, chg)
        seq.append(ev)
    check(seq == [1228, 1229, 1227, 1227],
          "Sturm: Trooper 1st -> the instructor story once (1228, 1229), then 1227")
    s2 = {}
    apply(s2, *on_done(1533, s2)[:2])
    check(on_done(1533, s2) is None, "a repeated done gives no second handgun")
    apply(s2, ESTE, {"mask": 1})
    check(on_done(204, s2) is None, "...nor a second gasmask")
    check(on_done(1536, {}) is None, "a bloom report with nothing growing is ignored")
    check(decide(99, {}, {}) is None and on_done(12345, {}) is None,
          "other NPCs / events are not ours")

    # the Fuzzy Seed on Collector's Mind's field, at SE's generator node
    tab = {208: ({7: [(FUZZY_SEED, 1, 100)], 8: [(FUZZY_SEED, 1, 25)],
                  13: [(0x62300000, 9, 28)]},
                 {3000: [((1.0, 2.0, 3.0), 7), ((5.0, 5.0, 5.0), 13)],
                  3003: [((9.0, 9.0, 9.0), 7)],
                  3007: [((4.0, 4.0, 4.0), 8)]})}
    check(mission_items(COLLECTORS_MIND, 208, 0, tab)
          == [(FUZZY_SEED, 1, (1.0, 2.0, 3.0))],
          "seed: quest 16 in the Church, no situation -> situation 3000's node")
    check(mission_items(COLLECTORS_MIND, 208, 3003, tab)
          == [(FUZZY_SEED, 1, (9.0, 9.0, 9.0))],
          "seed: a situation with its own node uses it")
    check(mission_items(COLLECTORS_MIND, 208, 3007, tab)
          == [(FUZZY_SEED, 1, (1.0, 2.0, 3.0))],
          "TWIN: a 25 % node is not a placement (falls back to 3000's)")
    check(mission_items(COLLECTORS_MIND, 201, 0, tab) == []
          and mission_items(1, 208, 0, tab) == [],
          "TWIN: another arena, or another quest with no node -> no seed")
    check(mission_items(7, 208, 3003, tab) == [(FUZZY_SEED, 1, (9.0, 9.0, 9.0))]
          and mission_items(7, 208, 3007, tab) == [],
          "seed: ANY church mission whose situation has SE's 100 % node gets "
          "it ('Collector's Mind and other church maps'); a 25 % node does not")
    import doc_field
    if doc_field.load():
        real = mission_items(COLLECTORS_MIND, 208)
        check(len(real) == 1 and real[0][:2] == (FUZZY_SEED, 1)
              and [round(v) for v in real[0][2]] == [1159, -242, 1374],
              "seed: the retail z208 data -> one seed at (1159, -242, 1374)")
    else:
        print("  SKIP no doc_item_generators.json: the seed placement check "
              "against the arena data needs your own table")
    check(not doc_field.usable(FUZZY_SEED),
          "the item generators never roll a field quest item")
    print("doc_npcquests self-test %s" % ("PASS" if not fails else "FAIL %s" % fails))
    return not fails


if __name__ == "__main__":
    import sys
    sys.exit(0 if _selftest() else 1)
