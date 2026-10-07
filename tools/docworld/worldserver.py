"""main(): the socket, the per-session state and the event loop that answers every datagram, and the --sweep table."""
import datetime
import math
import os
import random
import select
import socket
import struct
import time
import docdb
import doc_charastore
import doc_playtime
import doc_npc
import doc_novice
import doc_missions
import doc_drops
import doc_field
import doc_npc_spawn
import doc_npcquests
import doc_rank
import doc_stats
import doc_shop
import doc_trade
import doc_chat
import doc_unit
import doc_gear
import doc_magic
import doc_items
from .deps import _KELCRYPT, doc_kelcrypt
from . import advertise, arenadata, arenamaps, battleroom, briefingroom, charrecords, cli, fielditems, framing, gamemsg, handshake, lobbycmd, p2pbattle, peerrecords, questlist, tablerecords, tableverbs, teamdist, userlist, worldchannel, worlddoor, worldpose



# --- sweep -----------------------------------------------------------------
# DoC sends a BURST of ~10 datagrams per connection attempt, then goes quiet.
# So one attempt = one candidate.  With the input-unlock pnach the tester can
# dismiss the error and retry immediately, which makes a whole table walkable in
# a single game session instead of one reboot per candidate.
#
# A new burst is detected by a gap in arrival times (BURST_GAP seconds).  The
# candidate in force is printed in a banner so the Nth error code the tester
# reports lines up with the Nth banner in this log.
#
# Ordered deliberately: the known-good baseline FIRST, so if it does not
# reproduce CER-48103 the run is untrustworthy and everything after it is noise.
BURST_GAP = 8.0
# 2026-09-28: the spawn ring radius per seat (world units, ~10 cm each)
SEAT_SPREAD = 15.0
SWEEP = [
    (128, 4, "baseline -- known to reach CER-48103 (lobby phase)"),
    (128, 3, "same type, the OTHER ENT subtype"),
    (0,   4, "type 0 (s6=12)"),
    (1,   4, "type 1 (s6=8)"),
    (2,   4, "type 2 (generic arm)"),
    (3,   4, "type 3 (s6=40)"),
    (4,   4, "type 4"),
    (126, 4, "type 126 (s6=12)"),
    (254, 4, "type 254 (own arm)"),
    (255, 4, "type 255 (own arm)"),
]


def main():
    ap = cli.build_parser()
    a = ap.parse_args()

    extra_selectors = [int(x) for x in a.lobby_extra_selectors.split(",") if x.strip()]
    if extra_selectors:
        print("[docudp] LADDER: also sending response code(s) %s after each reply -- "
              "each is a no-op unless the nest is in that code's state"
              % extra_selectors, flush=True)

    extra_subtypes = [int(x) for x in a.extra_subtypes.split(",") if x.strip()]
    if extra_subtypes:
        print("[docudp] EXTRA SUBTYPES: also answering each 80-byte packet with subtype(s) %s "
              "(subtype 3 is accepted only at conn state 3, subtype 4 only at state 5)"
              % extra_subtypes, flush=True)

    chara_kw = {}
    if a.lobby_chara_count >= 0:
        n = min(a.lobby_chara_count, charrecords.CHARA_MAX_RECORDS)
        if n < a.lobby_chara_count:
            print("[docudp] WARNING: --lobby-chara-count %d clamped to %d (the client "
                  "record buffer is 560 bytes)" % (a.lobby_chara_count, n), flush=True)
        # AN EMPTY SLOT IS A PRESENT-BUT-BLANK RECORD, not a zero count.
        # MEASURED: boot 15:55's accidental char=145 made the client walk 145
        # records off the end of our packet into arbitrary RAM, print
        # "#N (not use)" for every one, and offer CREATE CHARACTER with a working
        # cursor.  Boot 16:61 sent a deliberate char=0 and got four dead
        # "Unregistered" rows and a FROZEN cursor -- nothing to put a cursor on.
        # Since essentially arbitrary bytes read as unused, an all-zero record is
        # the most likely canonical spelling of "empty slot".
        recs = ([charrecords.build_used_record(i, a.lobby_chara_name) for i in range(n)]
                    if a.lobby_chara_used else
                [charrecords.build_probe_record(i) for i in range(n)] if a.lobby_chara_probe else
                [bytes(96) for _ in range(n)] if a.lobby_chara_blank else
                [charrecords.build_chara_record(
                    i,
                    name_b=(("%s%d" % (a.lobby_chara_name, i))
                            if a.lobby_chara_name and n > 1 else a.lobby_chara_name),
                    name_a=(("%s%d" % (a.lobby_chara_name_a, i))
                            if a.lobby_chara_name_a and n > 1 else a.lobby_chara_name_a),
                    fill=a.lobby_chara_fill)
                 for i in range(n)])
        chara_kw = dict(chara_count=n, chara_records=recs,
                        chara_allow=(a.lobby_chara_allow
                                     if a.lobby_chara_allow >= 0 else None))
        if a.lobby_chara_probe:
            print("[docudp] USED-MARKER PROBE: slot i -> %s"
                  % ", ".join("#%d %s" % (i, charrecords.PROBE_SLOTS[i][0])
                              for i in range(min(n, len(charrecords.PROBE_SLOTS)))), flush=True)
        print("[docudp] CHARA payload ON: count=%d allow=%s -- every selector-8 reply "
              "carries it, including the answer to the 36-byte mode-2 packets"
              % (n, ("0x%02x" % a.lobby_chara_allow) if a.lobby_chara_allow >= 0
                 else "(token byte, untouched)"), flush=True)

    # The stores live in the stack's PostgreSQL database (docdb.py): each flag
    # below is on or off, and a flag still given the path of its old JSON file
    # is on, with that file left unread (cli.store_on says how to import it).
    _chara_on = cli.store_on(a.chara_store, "--chara-store", "characters")
    _shop_on = cli.store_on(a.shop, "--shop", "shop")
    _units_on = cli.store_on(a.units, "--units", "units")
    _rank_on = cli.store_on(a.rankings, "--rankings", "rankings")
    _stats_on = cli.store_on(a.stats, "--stats", "stats")
    _members = cli.members_on(a)
    if (_chara_on or _shop_on or _units_on or _rank_on or _stats_on
            or _members):
        print("[docudp] database %s" % docdb.where(), flush=True)
        docdb.migrate_at_start("docudp")

    # sec 4dq: PERSISTENT per-account characters. When --chara-store is on,
    # the seeded chara_kw above is replaced, per peer, by that account's own
    # stored roster: four slots, each a real created character or an empty slot
    # (so CREATE CHARACTER still appears). refresh_roster() rebuilds chara_kw in
    # place, so every existing code-8 send site picks it up unchanged.
    # sec 4ft: with --pol-members the key is resolved PER CLIENT (_skey below),
    # so the store carries no fixed account -- and must not auto-adopt one.
    _store = (doc_charastore.CharaStore(
                  docdb.store("characters"),
                  account=(None if _members else a.account))
              if _chara_on else None)
    _resolver = (doc_charastore.AccountResolver(docdb.store("ip_members"), _store)
                 if (_store is not None and _members) else None)
    if _store is not None:
        print("[docudp] CHARA IDS: %d character(s) own a POL Content ID; new "
              "characters get one: %s (--chara-id-source %s)"
              % (_store.content_ids_held(), "yes" if a.chara_id_source == "content"
                 else "no", a.chara_id_source), flush=True)
        print("[docudp] chara store (doc_character) keyed by %s" % (
            ("the POL MEMBER signed in at each client's address (the core's "
             "session table, read-only; sec 4ft)") if _resolver is not None
            else ("ACCOUNT %r" % _store.account) if _store.account
            else "the entrance uid (per SESSION -- rosters split when it "
                 "rotates; set --account)"), flush=True)

    def _skey(uid, sess=None):
        """sec 4ft: the store key for the client in hand. With --pol-members it
        is that client's POL member, resolved once per entrance and cached on
        its Session; without it, the uid, which CharaStore keys by --account or
        by itself exactly as before. `sess` names another client's session
        (sec 4fx: the relay dresses a SENDER, not the packet in hand).

        WARNING: sec 4gz, STILL OPEN: the resolve is by ADDRESS. Sessions no longer
        collide behind one household NAT, but two POL members playing from one
        house still resolve through `resolve(ip)` -- and if that hands both the
        same member, both get the same roster and (member + slot) the same
        charid, at which point adopt_session's live-collision guard is the only
        thing keeping them apart. Fixing THAT means resolving the member from
        something in the datagram, not from where it came from."""
        _s = sess if sess is not None else current[0]
        if _resolver is None or _s is None:
            return uid
        if _s.account_key is None:
            _s.account_key = _resolver.resolve(_s.ip)
        return _s.account_key
    _roster_uid = [0]

    # sec 4gk: the shop -- stock, prices, and a wallet + bag per CHARACTER.
    _shop = (doc_shop.Shop(docdb.store("shop"), stock_path=a.shop_stock,
                           start_gil=a.shop_start_gil) if _shop_on else None)
    if _shop is not None:
        print("[docudp] SHOP ON: %d wallet(s), %d stocked (PLACEHOLDER prices%s), start gil "
              "%d -- answers 64/66 buy/68 sell/141/143/145, gil+bag on the world door (sec 4gk)"
              % (len(_shop.data), len(_shop.stock),
                 "" if not a.shop_stock else ", from %s" % a.shop_stock,
                 _shop.start_gil), flush=True)
    # sec 4go: bullets issued into every world-door bag (the magazine fills
    # from them; an empty bag was the gun that never fired).
    _ammo = doc_shop.parse_issue(a.issue_ammo)
    print("[docudp] AMMO %s -- topped up in the world-door bag every login, not "
          "persisted (sec 4go)" % (", ".join("0x%08x x%d" % (i, q) for i, q in _ammo)
                                   or "OFF"), flush=True)

    # 2026-09-13: Unit Management (doc_unit.py), keyed like the shop wallet.
    _units = (doc_unit.Units(docdb.store("units"), fee=a.unit_fee, shop=_shop,
                             groups=_members) if _units_on else None)
    if _units is not None:
        print("[docudp] UNITS ON: %d unit(s), fee %d gil -- lobby commands "
              "24/13/25/8/12/9/10/11, enlisted unit at world-door body[60]"
              % (len(_units.data["units"]), _units.fee), flush=True)

    # 2026-09-13: CHANGE MASK / ARMOR (doc_gear.py), keyed like the shop wallet.
    # 'auto' is on whenever --shop is, so a deployment needs no compose edit;
    # without --shop there is no per-character identity to key it on.
    _gear_on = (_shop_on if a.gear_store == "auto"
                else cli.store_on(a.gear_store, "--gear-store", "gear"))
    _gearstore = doc_gear.GearStore(docdb.store("gear")) if _gear_on else None
    print("[docudp] GEAR %s" % (
        ("ON: %d character(s) -- lobby commands 17 equip / 18 unequip answered "
         "with the new costume at 241 body[6], served back on the world door"
         % len(_gearstore.data)) if _gearstore is not None else
        "OFF -- mask/armor changes answered generically (costume reset), not stored"),
          flush=True)

    # 2026-09-13: LOBBY NPCs (doc_npc.py) -- commands 26/27/39.
    _npc_over = doc_npc.parse_overrides(a.npc_events)
    if a.npc == "on":
        print("[docudp] NPCs ON: command 26 -> the talked-to NPC's event id "
              "(%d NPC tables, %d scene follow-up(s) on (trigger, b), "
              "%d override(s)); 27/39 acked"
              % (len(doc_npc.NPC_EVENTS), len(doc_npc.FOLLOWUP), len(_npc_over)),
              flush=True)
    # sec 4gs addendum 3: the lobby NPC push. Per client ip, main-scope on
    # purpose (Session has __slots__): {"due", "ready_at", "done", "seen"}.
    _npc_spawn_only = doc_npc_spawn.parse_only(a.npc_spawn_only)
    _npc_spawn = {}
    # sec 4gs addendum 4: session -> when to push the arena ring (after GO).
    _npc_arena_due = {}
    # 2026-09-23: mission NPC replacement. sess -> {"types": {id: type},
    # "spawn": [[x,y,z]..], "next": next index, "due": [(time, type), ..]}
    _mnpc = {}
    # 2026-10-05: ONE enemy set per MISSION ROOM (room key -> the same dict
    # every member's _mnpc entry points at), plus "ctrl" = the one console
    # that controls them, "csess" = its session, "rb" = the Add Npc batches,
    # "n" = how many, "dead" = ids gone. Before this each member got its own
    # copy of the same ids and was told it controlled them (live 10-05: three
    # consoles, HP 100 -> 60 -> 100 from two controllers of one Dual Horn).
    _room_mnpc = {}
    # 2026-09-23 (sec 4hc): the intro push, keyed by session key (so the
    # adoption re-key below must list it). value = when to send; the send
    # records the key in _intro_sent so one session gets one push.
    _intro_due = {}
    _intro_sent = set()
    # 2026-10-01 (--bt-fill-start): table key -> when a table that has just
    # filled goes to the briefing room (begin_briefing), set by the JOIN.
    _fill_start = {}
    # 2026-10-03 (--rematch-after): table key -> when its next round's
    # briefing starts; (--join-queue): table key -> {charid: queued at}
    _rematch = {}
    # 2026-10-05: a rematch's BATTLE READY waits for each player to be BACK IN
    # THE LOBBY (live table 8: a 38 sent at a fixed 39 + 15 s landed while one
    # console was still on its result screens -> black screen, keepalives
    # still flowing). In the lobby the console streams poses but sends no
    # game-server request (keepalive 1 runs from 38 until the lobby).
    _last_gs_req = {}      # charid -> time of its last game-server request
    _last_pose_rx = {}     # charid -> time of its last 0x83 pose
    _rematch_since = {}    # table -> when its battle-over reset went out
    _rematch_logged = {}   # table -> the last whole second its wait was logged
    REMATCH_QUIET_S = 8.0   # OURS: > the 7 s keepalive period
    REMATCH_LOBBY_CAP_S = 60.0  # OURS: then a player not back gives up the seat
    # 2026-10-05 (live 17:53Z): of the 4-message GO burst the console acked
    # only one and never left the loading screen -- waitlogin needs ALL of
    # 28/29/3/30 (facade 0x20) since GO stopped sending kind 5, and nothing
    # resent them. A console that sends no request 24 (the arena's 1 Hz
    # report) within GO_RESEND_S of its GO gets the burst again.
    _last_gs24 = {}        # charid -> time of its last request 24
    _go_resend = {}        # session -> [due, burst spec, tries left, GO time]
    GO_RESEND_S = 3.0
    GO_RESEND_TRIES = 2
    _join_queue = {}
    # 2026-10-01: character id -> the battle STATUS word its client last
    # reported (request 46); notify kind 43 echoes it to the room.
    _status = {}
    _npc_arena_types = doc_npc_spawn.parse_types(a.npc_arena_types)
    if a.npc_arena == "on":
        print("[docudp] NPC ARENA TEST ON: %d NPC(s) (types %s) in a %.0f-unit "
              "ring around the arena spawn, %.0f s after the battle GO"
              % (len(_npc_arena_types), a.npc_arena_types, a.npc_arena_radius,
                 a.npc_arena_after), flush=True)
    if a.npc_spawn == "on":
        print("[docudp] NPC SPAWN ON: via %s, %d NPC(s), type=%s, %.0f s after "
              "the in-world stream starts%s"
              % ("type-125 world update (nibble-4 ids)" if a.npc_spawn_via == "wu"
                 else "notify kind %d, ready=%s" % (doc_npc_spawn.KIND_ADD_NPC,
                                                    a.npc_spawn_ready),
                 len(doc_npc_spawn.select(_npc_spawn_only)), a.npc_spawn_type,
                 a.npc_spawn_delay,
                 (", resent every %.0f s" % a.npc_spawn_every)
                 if a.npc_spawn_via == "wu" and a.npc_spawn_every > 0 else ""),
              flush=True)

    # 2026-09-13: PLAY TIME (lobby command 20), per character, keyed like the
    # shop wallet. Accrues from each client's datagram gaps (doc_playtime.py).
    # Stored with --chara-store unless --play-time says otherwise.
    _pt_on = (_chara_on if a.play_time is None
              else cli.store_on(a.play_time, "--play-time", "playtime"))
    _playtime = doc_playtime.PlayTime(docdb.store("playtime") if _pt_on else None)
    _pt_key = {}             # (client ip, charid) -> wallet key, resolved once
    if a.lobby_clock == "play":
        print("[docudp] PLAY TIME ON: %s, %d character(s) -- command 20 answers "
              "the selected character's seconds at body[16]"
              % ("doc_playtime" if _playtime.store is not None else "(memory only)",
                 len(_playtime.data)),
              flush=True)

    def _rank_characters():
        """Every character in the chara store under a `member:N` key, as
        (wallet key, name, character id) -- the same key _wallet_key builds for
        the asker, so VIEW YOUR RANKING finds its own row. uid-keyed rosters
        (pre --pol-members) and archived keys are left out."""
        if _store is None:
            return []
        out = []
        for key, chars in _store.data.items():
            if not (key.startswith("member:") and key[7:].isdigit()):
                continue
            for c in chars or ():
                cid = charrecords.chara_id_of(a.chara_id_base, 0, key, c.get("slot", 0), c)
                if cid:
                    out.append(("%s/0x%08x" % (key, cid & 0x3FFFFFFF),
                                c.get("name", ""), cid))
        return out

    _rank = (doc_rank.Rankings(docdb.store("rankings"), characters=_rank_characters,
                               show_zero=not a.rankings_hide_zero,
                               units=(_units.ranking_units if _units else None))
             if _rank_on else None)
    if _rank is not None:
        print("[docudp] RANKINGS ON: %d character(s) in the chara store -- "
              "answers 137 -> 138 (Individual) and 149 -> 150 (Unit)"
              % len(_rank_characters()), flush=True)

    # 2026-09-13: CAREERS (doc_stats.py). The Status screen, the battle result,
    # the Ranking menu's values and the Viewer profile all read this one store.
    _stats = doc_stats.Stats(docdb.store("stats")) if _stats_on else None
    _novice = (doc_novice.Novice(_stats, a.novice_kills)
               if (a.novice == "on" or a.intro == "on") else None)
    if _stats is not None:
        if _rank is not None:
            _stats.push_rankings(_rank)
        print("[docudp] STATS ON: %d career(s) -- world door body[56]/[68]/"
              "[131], 139 -> 140 career record, kind-4 result totals"
              % len(_stats.data["chars"]), flush=True)
        # 2026-09-26: the WEEKLY medals (doc_stats.WEEKLY_MEDALS). The career
        # clock stamps every battle / leave into its week's tallies; a week
        # that ENDED while the server was down is closed right here.
        _stats.week_phase = doc_stats.parse_week_start(a.week_start)
        if a.test_clock_offset:
            _stats.clock = lambda: time.time() + a.test_clock_offset
            print("[docudp] TEST CLOCK: careers run %+.0f s off the wall clock"
                  % a.test_clock_offset, flush=True)
        print("[docudp] WEEKLY MEDALS %s: week starts %r, next close %s"
              % (a.weekly_medals.upper(), a.week_start,
                 _stats.next_week_close() or "none (no open week)"), flush=True)

    def weekly_close(why):
        """Close every ended, unclosed week (doc_stats.Stats.close_due)."""
        if _stats is None or a.weekly_medals != "on":
            return
        for _wk, _v in _stats.close_due():
            print("[docudp] WEEK CLOSED (%s): %d player(s)" % (why, _v["players"]),
                  flush=True)
            for _ln in _stats.week_lines(_wk, _v):
                print("[docudp]   %s" % _ln, flush=True)

    def weekly_deadline():
        """The wall-clock time the earliest open week ends, or None."""
        if _stats is None or a.weekly_medals != "on":
            return None
        _t = _stats.next_week_close()
        return None if _t is None else _t - a.test_clock_offset

    weekly_close("startup catch-up")

    def _bag_move(key, changes):
        """Apply [(item, +n/-n)] to `key`'s SERVER bag (doc_shop); returns a
        short description of what moved. A take never goes below zero."""
        if not changes or _shop is None:
            return ""
        w = _shop.wallet(key)
        done = []
        for iid, n in changes:
            k = "0x%08x" % iid
            have = int(w["bag"].get(k, 0))
            new_q = max(0, min(doc_shop.QTY_MAX, have + int(n)))
            if new_q:
                w["bag"][k] = new_q
            else:
                w["bag"].pop(k, None)
            done.append("%s %+d" % (_shop.name(iid), new_q - have))
        _shop.save()
        return ", ".join(done)

    def _wallet_key(uid, charid, sess=None):
        """The shop wallet key: the chara store's account key (per POL member
        with --pol-members) plus the character id, so each character has its
        own gil and bag. `sess` = another client's session (a trade partner)."""
        acct = _skey(uid, sess) if (_resolver is not None or uid) else None
        if not isinstance(acct, str):
            if _store is not None and _store.account:
                acct = _store.account
            elif uid:
                acct = "0x%08x" % (uid & 0xFFFFFFFF)
            else:
                acct = "anon"
        charid &= 0x3FFFFFFF
        return ("%s/0x%08x" % (acct, charid)) if charid else acct

    def refresh_roster(uid):
        if _store is None:
            return
        slots = _store.roster(_skey(uid))
        # sec 4dv: each slot gets a REAL character id at wire+0. It has to be
        # stable across sessions (it keys the peer table and the profile cache)
        # and unique per character on the shard, so derive it from the account
        # uid and the slot rather than a counter nobody persists.
        recs = []
        for i in range(doc_charastore.MAX_SLOTS):
            if not slots[i]:
                # 2026-09-13: an EMPTY slot still names its own slot (wire+84,
                # used flag clear): the charamake answer's record updates the
                # list entry whose slot byte matches it (0x00587cf0), and an
                # all-zero record made every empty entry "slot 0".
                _er = bytearray(96)
                _er[84] = i & 0x7F
                recs.append(bytes(_er))
                continue
            # sec 4dv + 09-13: per MEMBER, not per entrance uid -- two members
            # share one uid (see chara_id_for)
            cid = charrecords.chara_id_of(a.chara_id_base, uid, _skey(uid), i, slots[i])
            recs.append(charrecords.build_used_record(i, slots[i]["name"], slots[i],
                                          char_id=cid,
                                          chr_code=a.chara_chrcode))
            if cid:
                current[0].chara_ids[i] = cid
        current[0].chara_kw.clear()
        current[0].chara_kw.update(chara_count=doc_charastore.MAX_SLOTS,
                        chara_records=recs,
                        chara_allow=(a.lobby_chara_allow
                                     if a.lobby_chara_allow >= 0 else None))
        current[0].roster_uid[0] = uid
        names = ["%s(id 0x%x)" % (slots[i]["name"], current[0].chara_ids.get(i, 0))
                 if slots[i] else "(empty)"
                 for i in range(doc_charastore.MAX_SLOTS)]
        print("[chara] roster for 0x%08x [%s]: %s" % (uid, _skey(uid),
                                                     ", ".join(names)), flush=True)

    _chara_ids = {}       # slot -> the id we served, for logging
    def _world_door_charid(data, sess):
        """2026-10-05: the SELECTED character for a world-door (selector 2)
        request: request body[80], or -- when the console sent 0 there (live
        10-05, Itachi reconnecting after a doc restart) -- the character the
        session already knows, or the account's ONLY character. 0 = unknown.
        A 0 keyed every per-character store (career, gil, bag, gear, unit,
        novice) as the bare account: the world door then served rank 1 / 0 RP
        / no medals, and the client took that as its own career."""
        cid = (struct.unpack_from("<I", data, framing.BODY_OFF + 80)[0] & 0x3FFFFFFF
               if len(data) >= framing.BODY_OFF + 84 else 0)
        if cid:
            return cid
        if sess.seen_charid[0]:
            return sess.seen_charid[0] & 0x3FFFFFFF
        if _store is not None and sess.seen_uid[0]:
            slots = _store.roster(_skey(sess.seen_uid[0], sess))
            used = [i for i in range(doc_charastore.MAX_SLOTS) if slots[i]]
            if len(used) == 1 and sess.chara_ids.get(used[0]):
                cid = sess.chara_ids[used[0]] & 0x3FFFFFFF
                print("  [charid] world door sent no character (body[80] = 0) -> "
                      "the account's only character 0x%08x" % cid, flush=True)
                return cid
        print("  [charid] world door sent no character (body[80] = 0) and none "
              "can be inferred -- per-character stores key on the bare account",
              flush=True)
        return 0


    def _player_name():
        # sec 4dr (2026-09-11): the name for the in-world PLAYER record -- the
        # user list (selector 11/19) and peer (37) records that drive the name
        # plate and the profile the game reads. It MUST be the selected
        # character's stored name, NOT --lobby-chara-name: that seed ("Quarry")
        # leaked into the name plate for months while the code-8 select list
        # correctly served the real name, so the character showed as Quarry in
        # world even though the roster said Lex. Resolve via seen_charid (the
        # selected [kelsvc+272]) against the account's roster; fall back to
        # --user-list-name (or empty) -- never the Quarry seed.
        if _store is not None and seen_uid[0]:
            _cid = seen_charid[0] & 0x3FFFFFFF
            _slots = _store.roster(_skey(seen_uid[0]))
            for _si in range(doc_charastore.MAX_SLOTS):
                if _slots[_si] and (current[0].chara_ids.get(_si) == _cid or not _cid):
                    return _slots[_si].get("name") or (a.user_list_name or "")
        return a.user_list_name or ""

    if _store is not None:
        chara_kw.clear()
        chara_kw.update(chara_count=doc_charastore.MAX_SLOTS,
                        chara_records=[bytes(96)] * doc_charastore.MAX_SLOTS,
                        chara_allow=(a.lobby_chara_allow
                                     if a.lobby_chara_allow >= 0 else None))
        print("[docudp] CHARA STORE ON: doc_character -- created characters "
              "persist per account (sec 4dq)", flush=True)

    # sec 4fq: each Session copies this default so two accounts never mix rosters
    default_chara_kw = dict(chara_kw)

    lobby_edits = []
    if a.lobby_edit:
        for pair in a.lobby_edit.split(","):
            off, hh = pair.split(":")
            lobby_edits.append((int(off), int(hh, 16)))

    def is_lobby(pkt):
        # Everything that is NOT the 80-byte type-128 entrance handshake is lobby
        # traffic: the 96-byte type-129 (body 05 01 ...) AND the 24-byte bodyless
        # control packet the client emits ~50 ms after we echo a 96-byte one.
        # The entrance still needs the subtype-4 redirect; everything else gets the
        # lobby probe.
        return len(pkt) != 80

    def _is_close_request(pkt):
        """Is this the nest's CLOSE request -- the message phase 109 sends?

        The builder 0x00589f38 writes the selector to body[1] (`sb a2, 1(t3)`,
        t3 = buf+20), and the close initiator 0x00587a98 passes a2 = 3.  The
        message is 12 bytes long ([buf+18] = 12), so it arrives as a 36-byte
        mode-2 datagram whose body is plaintext: `05 03 00 00 ...`.  Compare the
        2->6 arm 0x005884d0, which passes a2 = 7 -- the `05 07 ...` body we have
        been answering with a code-8 all along.
        """
        if not a.nest_close_answer:
            return False
        return len(pkt) >= framing.BODY_OFF + 2 and pkt[framing.BODY_OFF + 1] == 3

    if a.save:
        os.makedirs(a.save, exist_ok=True)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.bind, a.port))
    print("[docudp] listening on %s:%d  mode=%s subtype=%d crypto=%s modebyte=%d cksum=%s type=%d flags=%02x lobby=%s:%d"
          % (a.bind, a.port, a.mode, a.subtype, a.crypto, a.mode_byte, not a.no_cksum, a.ptype, a.flags, a.lobby_ip, a.lobby_port), flush=True)
    print("[docudp] watch the PCSX2 console for '[KEL NET ENT]Drop packet bad packet'"
          " -- that means it REACHED the handler", flush=True)

    n = 0
    answered = 0
    last_rx = 0.0            # sweep-mode debug clock (single-client only)
    sweep_i = -1

    class Session:
        """sec 4fq (2026-09-12): per-CLIENT connection state, keyed by source IP.
        The battletable STORE stays shared (one match), but the connect/nest/
        lobby handshake, the learned charaid, the game-server channel and every
        timer are per client -- two concurrent clients used to clobber a single
        global session (and CER-48104 on the second). The boxed [0] fields keep
        the existing `name[0]` access working after a per-iteration rebind."""
        __slots__ = ("chara_burst_at", "chara_pending", "frag3_pending",
                     "frag3_sent", "ka_src", "ka_template", "ka_next", "ka_sent",
                     "ka_first", "kel_ka_next", "gs_done", "gs_ka_src",
                     "gs_ka_next", "gs_seq", "gs_teams", "gs_join_deadline",
                     "gs_bots_sent", "gs_join_src", "gs_rearm_next", "last_pose",
                     "gs_rearm_pending",
                     "last_wu", "seen_uid", "seen_charid", "last_stream",
                     "last_peer_rx", "save_count", "chara_kw",
                     "chara_ids", "roster_uid", "gs_src", "src", "wire_cid",
                     "relay_pushed", "relay_wu", "ip", "key", "account_key",
                     "pos_id", "gs_battle_on",
                     "gs_battle_end", "gs_battle_reset", "gs_battle_go",
                     "suit_item")

        def __init__(self, ip=None, port=0):
            self.ip = ip                  # sec 4ft: the key's address
            self.key = (ip, port)         # sec 4gz: the registry key, (ip, port)
            self.account_key = None       # sec 4ft: resolved lazily by _skey
            self.chara_burst_at = None
            self.chara_pending = None
            self.frag3_pending = None
            self.frag3_sent = 0
            self.ka_src = None
            self.ka_template = None
            self.ka_next = None
            self.ka_sent = 0
            self.ka_first = None
            self.kel_ka_next = 0.0
            self.gs_done = [False]
            self.gs_ka_src = [None]
            self.gs_ka_next = [0.0]
            self.gs_seq = [0]
            self.gs_teams = {}
            self.suit_item = None     # 2026-09-24: the world-door suit (Magic Suit pays x0.6 MP)
            self.gs_join_deadline = [0.0]
            self.gs_bots_sent = [False]
            # 2026-09-23: re-send the message-27 arm on every keepalive until
            # this client's first team request (31/33) after a 38
            self.gs_rearm_pending = [False]
            self.gs_join_src = [None]
            self.gs_battle_on = [0.0]      # sec 4fy: request 47 answered once
            self.gs_battle_end = [0.0]     # sec 4fy: when to send the result
            self.gs_battle_reset = [0.0]   # sec 4fy: when to send selector 39
            self.gs_battle_go = [0.0]      # sec 4ga: when to send 5,53 (START)
            self.gs_rearm_next = [0.0]
            self.last_pose = [None]
            self.last_wu = [0.0]
            self.seen_uid = [0]
            self.seen_charid = [0]
            self.wire_cid = [0]        # sec 4gz: the charid its packets STAMP
                                       # at +16 -- identity for session keying
                                       # only; seen_charid stays the selected
                                       # character the ladder proved (sec 4dv)
            self.last_stream = [0.0]
            self.last_peer_rx = [0.0]
            self.save_count = [0]
            self.chara_kw = dict(default_chara_kw)
            self.chara_ids = {}
            self.roster_uid = [0]
            self.gs_src = [None]     # sec 4ft: this client's game-server
                                     # address once its channel is up (a GS
                                     # request since its last 38); None = not
                                     # in a briefing room, push nothing to it
            self.src = None             # sec 4fu: (ip, port) to relay peers to
            self.relay_pushed = {}      # sec 4fu: peer id -> last record push
            self.relay_wu = {}          # sec 4fu: peer id -> last type-125 spawn
            self.pos_id = [0]           # sec 4fu: the id its own 0x83s carry

    # sec 4gz (2026-09-21): (src IP, src PORT) -> Session, NOT the IP alone.
    # Two consoles behind ONE household NAT arrive on one address, so an
    # IP-keyed registry handed them a single Session: one seen_uid, one roster,
    # one set of gs_* timers, one peer table, and replies to whichever sent
    # last -- the pre-sec-4fq "second client dies at CER-48104" failure
    # rescoped to a house, and a public-server blocker.
    # MEASURED (doc_gunfire_emulog_20260913_1453.txt, a 12-minute session that
    # reached the game-server channel): the title uses exactly ONE UDP source
    # port for everything -- `Binding UDP fixed port 56138` once, to 55040,
    # with the lobby AND the game-server channel on it (the other binds in that
    # log are DNS, to port 53). The three captures on hand agree
    # (56138 only). So ka_src / gs_src / gs_ka_src / gs_join_src are snapshots
    # of the same endpoint, not evidence of several ports, and (ip, port) is one
    # key per client. A NAT mapping can still MOVE mid-session, so the charid
    # adoption below re-joins a client that reappears on a new port.
    sessions = {}            # (src IP, src port) -> Session
    # 2026-10-05: LEADER KEYS. A table leader's mode-4 game-server datagrams
    # are keyed [0, P, 0, 0] / IV [0, P - 0x5B0, 0, 0], P the address of one
    # heap object that MOVES per session (doc_kelcrypt.LEADER_KEYED): live
    # 10-05 a tester's console sent 1,594 unreadable headers (P 0x003B5B10) and the
    # IV-only learner could never find it. A background search of the window
    # learns a new P from one datagram; the pairs persist across restarts.
    _lk_path = (os.environ.get("POL_DOC_LEADER_KEYS_FILE")
                or ("/logs/doc-leader-keys.json" if os.path.isdir("/logs") else ""))
    if _lk_path and _KELCRYPT:
        doc_kelcrypt.load_leader_keys(_lk_path)
        print("[kelcrypt] %d leader key pair(s) known (%s)"
              % (len(doc_kelcrypt.LEADER_KEYED), _lk_path), flush=True)
    _lk_job = {"thread": None, "next": 0.0, "tried": {}, "buf": {}}

    def leader_key_search(pkt, hint, src):
        """Run doc_kelcrypt.find_leader_key off the main loop (one at a time,
        a minute between tries for one hint)."""
        import threading
        # the console's recent unreadable datagrams: the IV is solved from
        # several (doc_kelcrypt.solve_iv_mitm), the key from this one's id
        buf = _lk_job["buf"].setdefault(src, [])
        buf.append(bytes(pkt))
        del buf[:-16]
        if len(_lk_job["buf"]) > 64:
            _lk_job["buf"].pop(next(iter(_lk_job["buf"])))
        t = _lk_job["thread"]
        if t is not None and t.is_alive():
            return
        now_ = time.time()
        if now_ < _lk_job["next"] or now_ - _lk_job["tried"].get(hint, 0.0) < 10.0:
            return
        _lk_job["tried"][hint] = now_
        _lk_job["next"] = now_ + 2.0
        pkts = [bytes(pkt)] + [d for d in buf[:-1]]

        def work():
            t0 = time.time()
            r = doc_kelcrypt.find_leader_key(pkts, hint)
            if r is None:
                print("  [kelcrypt] no leader key in the window for %s:%d (id 0x%08x, "
                      "%.0f s)" % (src[0], src[1], hint, time.time() - t0), flush=True)
                return
            if doc_kelcrypt.add_leader_key(*r) and _lk_path:
                doc_kelcrypt.save_leader_keys(_lk_path)
            print("  [kelcrypt] LEARNED a leader KEY P=0x%08x IV X=0x%08x from %s:%d "
                  "(id 0x%08x, %.1f s) -- its mode-4 headers decrypt from here"
                  % (r[0], r[1], src[0], src[1], hint, time.time() - t0), flush=True)
        th = threading.Thread(target=work, name="leader-key", daemon=True)
        _lk_job["thread"] = th
        th.start()

    # sec 4ha: PUBLISH THE POPULATION, ON A THREAD. Each session-carrying
    # service publishes {count, stamp} through the core's live_sessions.py
    # (`live:<service>` in the core's Valkey), so a deploy script can defer a
    # restart while someone is live and a status bot can show the count. This
    # service is "doc": `python live_sessions.py count doc`. It used to be
    # doc-sessions-live.json on the logs volume.
    # WARNING: NOT on the packet loop, which is where this started. The loop blocks
    # in select() while nobody is connected, so the marker was written once at
    # startup and never again and a reader saw it go stale after a few minutes.
    # start_heartbeat's thread ticks whether or not anyone sends a packet, which
    # is the whole point of a liveness marker.
    # live_sessions.py is the core's module: the image is built FROM the
    # OpenLobby image, and in a checkout it sits beside polcore, which docdb
    # (imported above) has put on sys.path. A copy is never added here.
    try:
        import live_sessions as _live_sessions
        _live_sessions.start_heartbeat("doc", lambda: len(sessions))
    except Exception as _e:                           # noqa: BLE001
        print("[live] WARN live-session heartbeat not started (%r)" % (_e,),
              flush=True)
    current = [None]         # sec 4fq: the session of the packet in hand
    players = {}             # sec 4fr: charid -> {name, uid}, SHARED so
                             # each client is served the OTHER players
    # sec 4ft: per-TABLE briefing state, SHARED by the seated clients:
    #   key -> {"teams": {charid: team}, "shown": {observer: {charid: team}},
    #           "ready_at": when the roster first read ready, "dist": sent,
    #           "why": the last readiness verdict printed}
    gs_tables = {}
    try:
        _gs_bmap = (tuple(int(x, 0) for x in a.gs_battle_map.split(",")
                          if x.strip()) + (0, 0))[:2]
    except ValueError:
        raise SystemExit("--gs-battle-map wants M0,M1, got %r" % a.gs_battle_map)
    _zone_pieces = arenamaps.parse_zone_pieces(a.zone_pieces)
    if _zone_pieces:
        print("[arena] kind-2 map0/map1 per zone (--zone-pieces): %s"
              % ", ".join("z%d=%d,%d" % (z, m[0], m[1])
                          for z, m in sorted(_zone_pieces.items())), flush=True)
    _gs_stat_list = []
    for _pair in (a.gs_stats or "").replace(" ", "").split(","):
        if _pair:
            _k2, _, _v2 = _pair.partition(":")
            _gs_stat_list.append((int(_k2, 0), int(_v2, 0)))

    def session_of(charid):
        """sec 4ft: the session whose client is `charid` (its record+4).

        sec 4gz: the MOST RECENTLY HEARD one. Normally there is only ever a
        single match -- a port move is folded away by adopt_session -- but when
        two live clients claim one charid (accounts that resolved to the same
        character) the reply belongs to whichever is actually sending, not to
        whichever the dict happens to list first.
        """
        if not charid:
            return None
        best = None
        for _ss in sessions.values():
            if _ss.seen_charid[0] != charid:
                continue
            if best is None or _ss.last_peer_rx[0] > best.last_peer_rx[0]:
                best = _ss
        return best

    # -- 2026-09-23 (sec 4hc): the new-player intro and the novice mark -------

    def _unit_of_cid(cid):
        """2026-09-24: the unit a seated character is enlisted in, or 0 (it
        needs the character's live session to build its wallet key)."""
        if _units is None or not cid:
            return 0
        us = session_of(cid)
        if us is None:
            return 0
        return _units.enlisted(_wallet_key(us.seen_uid[0], cid, us))
    def _novice_key(sess):
        """The career key of the character this session is playing, or None."""
        cid = sess.seen_charid[0] if sess is not None else 0
        if not cid:
            return None
        return _wallet_key(sess.seen_uid[0], cid, sess)

    def novice_cid(cid):
        """True when character `cid` still wears the novice mark (--novice on).
        Keyed through its live session first, else the career file."""
        if _novice is None or a.novice != "on" or not cid:
            return False
        key = _novice_key(session_of(cid))
        if key is None and _stats is not None:
            key = _stats.key_for_charid(cid)
        return key is not None and _novice.is_novice(key)

    def rp_of_cid(cid):
        """2026-09-26: character `cid`'s career rank points for a table's
        Min/Max RP (rp_allowed), or None = not checked (--rp-tables open,
        no --stats, no character). Keyed like novice_cid."""
        if _stats is None or a.rp_tables != "enforce" or not cid:
            return None
        key = _novice_key(session_of(cid))
        if key is None:
            key = _stats.key_for_charid(cid)
        if key is None:
            return 0                     # no career yet = a fresh 0 RP one
        return int(_stats.peek(key).get("rp", 0))

    def rank_of_cid(cid):
        """2026-10-01: character `cid`'s career RANK for the peer / user record
        (+54, 1-based like the career's, doc_stats.RANK_CODES). Manual p.27:
        the pick menu shows each player's own rank; the global --user-rank
        (unset on prod = 0 = "DGD-3") made every other player a DG Drone 3rd.
        --user-rank still wins when it is set (a probe)."""
        if a.user_rank is not None or _stats is None or not cid:
            return a.user_rank
        key = _novice_key(session_of(cid))
        if key is None:
            key = _stats.key_for_charid(cid)
        if key is None:
            return doc_stats.RANK_MIN
        return doc_stats.clamp_rank(_stats.peek(key).get("rank",
                                                         doc_stats.RANK_MIN))

    def private_cid(cid):
        """2026-10-01: character `cid` set its record to Anonymous (lobby
        command 6; manual p.36 公開設定)."""
        if _stats is None or not cid:
            return False
        key = _novice_key(session_of(cid))
        if key is None:
            key = _stats.key_for_charid(cid)
        return _stats.is_private(key)

    def peer_flags(cid):
        """The peer record's FLAGS for character `cid`: --user-flags, plus bit
        0x40 while it is a novice. wire+30 lands on peer-table byte +0x2f, the
        byte selector 134 sub 11 clears (doc_novice_proof E)."""
        f = a.user_flags
        if novice_cid(cid):
            f = (f or 0) | doc_novice.NOVICE_BIT
        if private_cid(cid):
            f = (f or 0) | doc_stats.PRIVATE_BIT     # 2026-10-01: Anonymous
        return f

    def send_push(sess, body, ident, what):
        """An unsolicited type-127 lobby message to one client."""
        if sess is None or sess.src is None:
            return False
        s.sendto(worldchannel.seal_world_body(None, body, seq=a.lobby_seq,
                                 ptype=a.world_type, ident=ident), sess.src)
        print("  [novice] SENT selector %d %s to %s:%d (ident 0x%08x)"
              % (doc_novice.SEL_PUSH, what, sess.src[0], sess.src[1],
                 ident & 0xFFFFFFFF), flush=True)
        return True

    def issue_supplies(sess, dst):
        """2026-09-26: message 27 (the reward grant, which ADDS to the bag and
        prints "You obtain %s x%d") with whatever tops this player up to the
        battle's supplies: the mission's Initial Supplies, the standard issue
        for PvP. The login top-up alone let ammo run dry over a session."""
        if not a.mission_supplies:
            return
        if sess.key not in _supply_bag:
            # 2026-10-05 (live): the ledger is seeded only by the world door
            # (selector 2), so after a doc restart a player still logged in
            # got NO supplies at all (Beginner II without its Bomb Fragments,
            # Dual Horn without the top-up). Seed it from the stored bag; the
            # issued bullets are not stored, so this can grant a little extra.
            cid = sess.seen_charid[0]
            held0 = {}
            if _shop is not None and cid:
                _g, _b = _shop.login_fields(_wallet_key(sess.seen_uid[0], cid, sess))
                held0 = {i: q for i, q in (_b or ())
                         if i in doc_missions.SUPPLY_ITEMS}
            _supply_bag[sess.key] = held0
            print("  [supplies] 0x%08x: no world door since the restart -- "
                  "ledger seeded from the stored bag (%d supply row(s))"
                  % (cid or 0, len(held0)), flush=True)
        quest = _mission_battle.get(sess.key)
        want = doc_missions.supplies(quest, _ammo or
                                     doc_missions.STANDARD_SUPPLIES)
        held = _supply_bag[sess.key]
        grant = doc_shop.supply_grant(held, want)
        if not grant:
            print("  [supplies] 0x%08x already holds %s's supplies"
                  % (sess.seen_charid[0], "quest %s" % quest if quest
                     else "a PvP battle"), flush=True)
            return
        s.sendto(gamemsg.build_gs_stats(grant, seq=next_gs_seq(sess),
                                ident=sess.seen_charid[0]), dst)
        for iid, q in grant:
            held[iid] = held.get(iid, 0) + q
        print("  [supplies] 0x%08x %s: SENT message 27 granting %s"
              % (sess.seen_charid[0], "quest %s" % quest if quest
                 else "PvP", ", ".join("0x%08x x%d" % g for g in grant)),
              flush=True)

    def relay_chat(sender, body):
        """2026-09-26: a selector-255 chat line to the players who must see
        it (doc_chat). Nothing is ANSWERED to the sender -- sec 4bz still holds."""
        if a.chat == "off":
            return 0
        now = time.time()
        live = {_ss.seen_charid[0] for _ss in list(sessions.values())
                if _ss.seen_charid[0] and not peer_idle(_ss, now)}
        p = doc_chat.parse(body)
        n = 0
        for cid in doc_chat.recipients(body, sender, live,
                                       chat_where if a.chat == "on" else None):
            ts = session_of(cid)
            dst = (ts.ka_src or ts.src) if ts is not None else None
            if dst is None:
                continue
            s.sendto(worldchannel.seal_world_body(None, doc_chat.relay_body(body),
                                     seq=a.lobby_seq, ptype=a.world_type,
                                     ident=sender), dst)
            n += 1
        if p is not None:
            print("  [chat] 0x%08x %s %r -> %d player(s)%s"
                  % (sender, "TELL 0x%08x" % p[1] if p[0] == doc_chat.KIND_TELL
                     else "%s (kind %d)" % (doc_chat.kind_name(p[0]), p[0]),
                     p[2], n, "" if a.chat == "on" else " [--chat=all]"),
                  flush=True)
        return n

    def chat_where(cid):
        """doc_chat.Where for `cid`: its lobby area off the last position it
        streamed (or the battle room it is fighting in), its battletable
        reservation, and its team (the room's, else the team it picked)."""
        room = battle_of(cid)
        if room is not None and (cid not in room.members or cid in room.left):
            room = None
        ts = session_of(cid)
        if room is not None:
            area = ("battle", room.key)
        else:
            area = doc_chat.lobby_area(ts.last_pose[0] if ts is not None
                                       else None)
        if room is not None:        # BT: every player is their own side
            team = None if room.individual() else room.team_of(cid)
        else:
            team = ts.gs_teams.get(cid) if ts is not None else None
        _pose = ts.last_pose[0] if ts is not None else None
        return doc_chat.Where(area, bt_store.table_of(cid),
                              room.key if room is not None else None, team,
                              (_pose[0], _pose[2]) if _pose else None)

    def broadcast_graduate(cid, why):
        """Selector 134 sub-kind 11 to every client in the world: the mark comes
        off `cid` on every peer table, and on its own self record."""
        body = doc_novice.graduate_push(
            subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7))
        n = 0
        now = time.time()
        for _ss in list(sessions.values()):
            if not _ss.seen_charid[0] or peer_idle(_ss, now):
                continue
            if send_push(_ss, body, cid, "sub 11 (novice mark OFF for 0x%08x)"
                         % cid):
                n += 1
        print("  [novice] 0x%08x GRADUATED (%s) -- mark-removed push to %d "
              "client(s)" % (cid, why, n), flush=True)

    # sec 4gz: ADOPTION -- what a session inherits from the port its client
    # moved off. Every name in Session.__slots__ has to appear in exactly one
    # of these five tuples; the audit below REFUSES TO START otherwise, because
    # a slot nobody classified is the class of bug that crash-loops every
    # client (Session has __slots__, so a typo is an AttributeError mid-session).
    _INHERIT_COPY = (        # carried over verbatim (boxed [0] or plain)
        "frag3_sent", "ka_sent", "ka_first", "gs_done",
        "gs_ka_next", "gs_join_deadline", "gs_bots_sent", "gs_rearm_next",
        "gs_rearm_pending", "gs_battle_on", "gs_battle_end", "gs_battle_reset", "gs_battle_go",
        "gs_seq", "last_pose", "last_wu", "seen_uid", "seen_charid", "wire_cid",
        "last_stream", "save_count", "roster_uid", "pos_id", "account_key",
        "chara_pending", "chara_burst_at", "suit_item")
    _INHERIT_DICT = (        # merged into the box we already hold
        "gs_teams", "chara_kw", "chara_ids", "relay_pushed", "relay_wu")
    _INHERIT_RETARGET = (    # an endpoint: kept as a FLAG, aimed at the new port
        "gs_src", "gs_ka_src", "gs_join_src")
    _INHERIT_SPECIAL = ("frag3_pending",     # a held reply: retargeted by hand
                        "ka_template")       # only if the new port has none yet
    _INHERIT_KEEP = (        # the new port's own truth -- never inherited
        "ip", "key", "src", "ka_src", "ka_next", "kel_ka_next", "last_peer_rx")
    _INHERIT_ALL = (_INHERIT_COPY + _INHERIT_DICT + _INHERIT_RETARGET
                    + _INHERIT_SPECIAL + _INHERIT_KEEP)
    _slot_set = set(Session.__slots__)
    _unclassified = sorted(_slot_set - set(_INHERIT_ALL))
    _phantom = sorted(set(_INHERIT_ALL) - _slot_set)
    _twice = sorted({n for n in _INHERIT_ALL if _INHERIT_ALL.count(n) > 1})
    if _unclassified or _phantom or _twice:
        raise SystemExit(
            "[docudp] sec 4gz session-inherit audit FAILED -- fix the tuples "
            "before this ships: unclassified slots %s, names that are not "
            "slots %s, names listed twice %s"
            % (_unclassified, _phantom, _twice))
    print("[docudp] sec 4gz: sessions key on (ip, port); inherit audit OK "
          "(%d/%d Session slots classified, adopt=%s idle>=%.1fs, "
          "reap idle>%s)"
          % (len(_INHERIT_ALL), len(Session.__slots__),
             "on" if a.session_adopt else "OFF", a.session_adopt_idle,
             ("%.0fs" % a.session_idle_drop) if a.session_idle_drop > 0
             else "never"), flush=True)

    def session_inherit(new, old):
        """Move `old`'s accumulated state into `new` (sec 4gz).

        Direction matters: the state comes TO the session in hand, so `sess`
        and every boxed per-client local the main loop rebound at the top of
        the iteration (`gs_done = sess.gs_done`, ...) stay valid -- the boxes
        are updated IN PLACE (`[:] =`), never replaced.
        """
        for _n in _INHERIT_COPY:
            _v = getattr(old, _n)
            if isinstance(_v, list):
                getattr(new, _n)[:] = _v
            else:
                setattr(new, _n, _v)
        for _n in _INHERIT_DICT:
            _d = getattr(new, _n)
            _d.clear()
            _d.update(getattr(old, _n))
        for _n in _INHERIT_RETARGET:
            # The channel was up on the old port; the client is on the new one.
            getattr(new, _n)[0] = (new.src if getattr(old, _n)[0] is not None
                                   else None)
        if new.ka_template is None:
            new.ka_template = old.ka_template
        if old.frag3_pending is not None:
            # A HELD character-list fragment. Its captured target is the dead
            # port, so it follows the client instead of being sent into the void.
            new.frag3_pending = (old.frag3_pending[0], new.src)
        # sec 4gz: the per-client state that lives OUTSIDE Session, because
        # Session has __slots__ -- re-key it from the dead port to this one.
        # WARNING: ANY new dict keyed by a session key belongs in this list; the NPC
        # one is measured (without it the moved client was sprayed with all 33
        # lobby NPCs a second time).
        for _tbl in (_npc_spawn, _quest_pick, _mission_battle, _intro_due):
            if old.key in _tbl:
                _tbl[new.key] = _tbl.pop(old.key)
        if old.key in _intro_sent:
            _intro_sent.add(new.key)
        for _ptk in [_k for _k in _pt_key if _k[0] == old.key]:
            _pt_key[(new.key, _ptk[1])] = _pt_key.pop(_ptk)

    _adopt_warned = {}

    def adopt_session(new, charid, now):
        """sec 4gz: one player, ONE session, even when its source port moves.

        A client's UDP mapping can be re-bound by its own router (SE's client
        idles the socket for ~20-48 s in the lobby, which is inside a domestic
        NAT's UDP timeout), and it then reappears on a new port with the same
        character id. Fold the predecessor's state into the session in hand and
        retire it.

        WARNING: REFUSED while the other session is still live: one client uses one
        socket (measured, see `sessions` above), so two concurrently-sending
        ports that claim one charid are TWO PLAYERS whose identity collapsed
        upstream (the chara store resolves its account key from the IP, so two
        members behind one NAT can be handed the same member and the same
        slot). Merging them would be the very collision this keying fixes.
        """
        if not a.session_adopt or not charid or len(sessions) < 2:
            return None
        for old in list(sessions.values()):
            if (old is new or old.ip != new.ip
                    or charid not in (old.wire_cid[0], old.seen_charid[0])):
                continue
            _idle = now - (old.last_peer_rx[0] or 0.0)
            if _idle < a.session_adopt_idle:
                if now - _adopt_warned.get(charid, 0.0) > 30.0:
                    _adopt_warned[charid] = now
                    print("[session] WARNING: %s:%d and %s:%d BOTH claim charid "
                          "0x%08x and both are live (%.1f s apart) -- NOT "
                          "merging: that is two players whose accounts "
                          "resolved to one character, not one moved port "
                          "(sec 4gz)"
                          % (old.key[0], old.key[1], new.key[0], new.key[1],
                             charid, _idle), flush=True)
                continue
            session_inherit(new, old)
            sessions.pop(old.key, None)
            print("[docudp] SESSION ADOPTED: charid 0x%08x moved from %s:%d "
                  "(idle %.1f s) to %s:%d -- state carried over (uid 0x%08x, "
                  "roster uid 0x%08x, %d chara ids, gs_seq %d, gs_done %s, "
                  "%d peer pushes, %d teams) -- %d client(s) now"
                  % (charid, old.key[0], old.key[1], _idle,
                     new.key[0], new.key[1], new.seen_uid[0],
                     new.roster_uid[0], len(new.chara_ids), new.gs_seq[0],
                     new.gs_done[0], len(new.relay_pushed), len(new.gs_teams),
                     len(sessions)), flush=True)
            return old
        return None

    def gs_table_state(key):
        return gs_tables.setdefault(key, {"teams": {}, "shown": {},
                                          "ready_at": None, "dist": False,
                                          "why": None, "auto_at": None,
                                          "brief_end": None})

    def _briefing_running(key):
        """2026-09-29: the leader pressed Start at `key` and its room has not
        opened yet (the room's own In Progress bit takes over then). Lapses a
        minute past the briefing's end, so an abandoned briefing never locks
        the table."""
        st = gs_tables.get(key)
        t0 = st.get("started") if st else None
        if not t0:
            return False
        return time.time() < (st.get("brief_end") or t0 + 120.0) + 60.0

    # sec 4gk addendum 5: player-to-player TRADE (doc_trade.py). The server is
    # a relay: offers go to the partner as 42/44, and when both have confirmed
    # the wallets are swapped and both clients get 50 (the client applies the
    # swap itself from the two stored offers) -- or 48 if the swap is refused.
    _trade = doc_trade.TradeBook() if (a.trade and _shop is not None) else None
    if _trade is not None:
        print("[docudp] TRADE ON: 41/43/47/49 relayed as 42/44/50/48 (sec 4gk)",
              flush=True)

    def trade_push(charid, body):
        ts = session_of(charid)
        dst = (ts.ka_src or ts.src) if ts is not None else None
        if dst is None:
            print("  [trade] 0x%08x has no live session -- push %d dropped"
                  % (charid, body[1]), flush=True)
            return False
        s.sendto(worldchannel.seal_world_body(None, body, seq=a.lobby_seq, ptype=a.world_type,
                                 ident=charid), dst)
        print("  [trade] SENT %d to 0x%08x at %s:%d" % (body[1], charid, dst[0], dst[1]),
              flush=True)
        return True

    def trade_swap(t):
        ok, note = True, "no wallets (--shop off)"
        if _shop is not None:
            sa, sb = session_of(t.a), session_of(t.b)
            ka = _wallet_key(sa.seen_uid[0] if sa else 0, t.a, sa)
            kb = _wallet_key(sb.seen_uid[0] if sb else 0, t.b, sb)
            ok, note = _shop.trade(ka, t.offers[t.a], kb, t.offers[t.b])
        print("  [trade] %s" % note, flush=True)
        for _c in (t.a, t.b):
            trade_push(_c, doc_trade.bare_body(doc_trade.DONE_PUSH if ok
                                               else doc_trade.CANCEL_PUSH))

    def synth_world_req(nbody=176):
        """A bare type-`--world-type` request to build an UNSOLICITED world
        answer on. build_world_answer echoes only body[16:], so a zero body
        means every field the client reads is one we wrote. This is the shape
        push_battle_ready's selector 38 has ridden live since sec 4ft."""
        req = bytearray(framing.HDR_LEN + nbody)
        req[0] = 0x04
        struct.pack_into("<H", req, 2, len(req))
        req[8] = a.world_type & 0xFF
        return bytes(req)

    def send_gs_endpoint(dst, ident, req=None, why=""):
        """(RE-)DECLARE our game-server endpoint to the client at `dst`.

        sec 4gv. Selector 104 is the sole writer of [chan+184..191], the
        sockaddr the client's game-server receive handler compares EVERY
        datagram's source against before it dispatches anything. The endpoint
        is computed PER PEER through host_for(), exactly as the --gs-connect
        path does, so a LAN console gets the LAN address and an internet player
        gets POL_ADVERTISE_PUBLIC -- there is no global address here.

        WARNING: ORDER: 104 -> 38 -> the message-27 arm, which is the order the
        --gs-connect block has always used and the order --gs-rearm-ms replays.
        104 must come FIRST because it is what makes the other two deliverable
        at all; the arm must come LAST because 38's routine 0x00bc0260 zeroes
        [chan+204] (sec 4eb, CER-48101 live). Re-running 104 on a HEALTHY
        channel is harmless -- measured in an offline run of the client's own code (doc_gsseq_proof) and
        already relied on by --gs-rearm-ms (sec 4cx).

        Returns the endpoint string that went out, or None when there is
        nothing to declare (no --lobby-ip / --gs-connect-ip, or the builder
        refused the request)."""
        if dst is None:
            return None
        _ep = advertise.host_for(a.gs_connect_ip or a.lobby_ip, dst[0])
        if not _ep:
            return None
        _g = worlddoor.build_world_answer(
            req if req is not None else synth_world_req(),
            selector=worldchannel.GS_ENDPOINT_SELECTOR, seq=a.lobby_seq,
            subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
            inner_ip=None, ptype=a.world_type, pad_to=a.world_pad,
            # WARNING:KEY: sec 4dv: record+4, NOT 0 -- 104's arm 0x00bcd248 opens
            # `lw v1,4(s2); lw v0,272(s1); bne v1,v0,<drop>`, so the endpoint
            # message is dropped without a word unless this equals the charaid
            # the client holds at [kelsvc+272].
            ident=ident, gs_ip=_ep, gs_port=a.gs_connect_port,
            gs_id=a.gs_connect_id)
        if _g is None:
            return None
        s.sendto(_g, dst)
        print("  SENT GAME-SERVER ENDPOINT (selector %d) to %s:%d -> "
              "[chan+184..191] = %s:%d, id %d, ident 0x%08x%s"
              % (worldchannel.GS_ENDPOINT_SELECTOR, dst[0], dst[1], _ep, a.gs_connect_port,
                 a.gs_connect_id, ident or 0,
                 ("  [%s]" % why) if why else ""), flush=True)
        return _ep

    def push_member_peers(me, dst, members, why=""):
        """2026-10-05: every other table member's selector-37 peer record
        (with our relay address, peer_addr) to `me` at `dst`, right before its
        selector 38. MEASURED offline (retail 38 handler 0x00bd2ab0 on savestate
        RAM): the briefing room creates a unit ONLY for a roster member already
        in the console's peer table ([kelsvc+0x11c]) -- the lookup 0x00bde418
        fails for any other id and that player has no unit all battle. The
        lobby relay pushes records only for players who streamed nearby."""
        if dst is None or a.peer_record_addr != "relay":
            return 0
        sub = a.world_subchannel if a.world_subchannel >= 0 else 7
        n = 0
        for m in members:
            if not m or m == me:
                continue
            s.sendto(peerrecords.build_peer_answer(
                None, m, seq=a.lobby_seq, subchannel=sub, ptype=a.world_type,
                ident=me,
                blob=peerrecords.build_peer_record(
                    m, name=_member_name(m), zone=a.user_zone, rank=rank_of_cid(m),
                    flags=peer_flags(m), f36=player_look.get(m),
                    **peer_addr(m, dst[0], me))[4:]), dst)
            n += 1
        if n:
            print("  [peer] SENT %d member peer record(s) to 0x%08x before its "
                  "selector 38%s" % (n, me, (" (" + why + ")") if why else ""),
                  flush=True)
        return n

    def _rec_flags(rec):
        """2026-10-06: a table record's flags word (wire+0), 0 without one --
        logged with every 38: the client's BT ally test keys on its 0x200."""
        if rec is None or len(rec) < tablerecords.BT_OFF_FLAGS + 4:
            return 0
        return struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0]

    def push_battle_ready(msess, key):
        """sec 4ft: BATTLE READY (selector 38) + the message-27 re-arm to a
        seated member who did NOT send the Start -- the pair the leader's own
        command 3 gets. Only the leader sends command 3, and 38 alone takes a
        reserved member to the briefing room (sec 4eo). Built on a synthetic
        request, as the kelsvc keepalive is: 38's body from body[12] on is
        ours (the table record + the seat list)."""
        if msess.ka_src is None:
            return False
        _cid = msess.seen_charid[0]
        _rd = worlddoor.build_world_answer(
            synth_world_req(), selector=worldchannel.GS_READY_SELECTOR, seq=a.lobby_seq,
            subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
            inner_ip=None, ptype=a.world_type, pad_to=a.world_pad, ident=_cid)
        if _rd is None:
            return False
        if a.gs_ready_roster:
            _rd = briefingroom.gs_ready_roster(_rd, _cid, a.gs_connect_id,
                                  bt_store.members(key),
                                  rec=advertise.rec_for(bt_store.record(key),
                                              _gs_endpoint, msess.ka_src[0]),
                                  addr=battle_addr(msess.ka_src[0]))
        # WARNING:KEY: sec 4gv: the same re-declaration the leader gets, computed
        # PER PEER -- this member may be on the LAN while the leader is on the
        # internet, so host_for() is asked about THIS socket's address.
        if a.gs_connect and a.gs_start_endpoint:
            send_gs_endpoint(msess.ka_src, _cid, why="Start, start-all member")
        push_member_peers(_cid, msess.ka_src, bt_store.members(key), why="member")
        s.sendto(_rd, msess.ka_src)
        msess.gs_join_deadline[0] = 0.0
        msess.gs_bots_sent[0] = False
        msess.gs_battle_on[0] = 0.0      # sec 4fy: a new battle
        msess.gs_battle_end[0] = 0.0
        msess.gs_battle_reset[0] = 0.0
        msess.gs_battle_go[0] = 0.0
        msess.gs_src[0] = None
        s.sendto(gamemsg.build_gs_stats(_gs_stat_list, state=a.gs_arm_state,
                                seq=next_gs_seq(msess), ident=_cid),
                 msess.ka_src)
        msess.gs_ka_src[0] = msess.ka_src
        msess.gs_ka_next[0] = time.time() + a.gs_keepalive_ms / 1000.0
        msess.gs_rearm_pending[0] = a.gs_rearm_until_team
        print("  [start-all] SENT BATTLE READY (selector %d) + re-arm (message "
              "%d) to seated member 0x%08x at %s:%d, table %d, record flags "
              "0x%08x (sec 4ft; 0x200 = individual)"
              % (worldchannel.GS_READY_SELECTOR, gamemsg.GS_ARM_MSG, _cid, msess.ka_src[0],
                 msess.ka_src[1], key, _rec_flags(bt_store.record(key))), flush=True)
        return True

    def begin_briefing(_sk, _lead, _others, skip_sess=None):
        """The table `_sk` goes to the briefing room: from here it takes no new
        seats, its countdown and auto-team timer start, and every member in
        `_others` gets BATTLE READY (push_battle_ready). Two callers: the
        leader's Start (sec 4ft, the leader's own 38 is sent by the command-3
        path itself, so the leader is not in `_others`), and a table that has
        just FILLED (2026-10-01, manual p.29: "when the table fills, or the
        leader starts it, everyone reserved jumps to the briefing room"),
        where nobody sent command 3 and so everyone is in `_others`."""
        gs_tables.pop(_sk, None)
        # 2026-09-29: from here the table takes no new
        # seats (see the JOIN's -4 below)
        gs_table_state(_sk)["started"] = time.time()
        # 2026-09-23: the briefing countdown's end =
        # the record's Briefing Time, else the knob
        _brec = bt_store.record(_sk)
        _rsec = (float(_brec[tablerecords.BT_OFF_BRIEFING])
                 * a.gs_briefing_minute
                 if _brec and len(_brec) > tablerecords.BT_OFF_BRIEFING
                 else 0.0)
        # 2026-09-28: a SOLO table has nobody to wait
        # for, so it keeps the old start (the post-join
        # timer). Holding it for a 5:00 Briefing Time
        # read as "stuck in briefing" (Beginner's Course
        # I/II, live 09-28: three tries, left at ~4:20).
        if len(bt_store.members(_sk)) <= 1:
            _rsec = 0.0
        _bsec = _rsec or a.gs_auto_team_after
        # 2026-09-24: the client counts wire+111 minutes
        # down from this 38 (lobby 0x00ada55c) and
        # does nothing at zero -- the start is ours, at
        # the zero it shows. 0 = None: no countdown drawn.
        if _rsec and a.gs_briefing_clock:
            gs_table_state(_sk)["brief_end"] = (
                time.time() + _rsec + 1.0)
            print("  [start-all] table %d: briefing "
                  "countdown %.0f s -- the battle "
                  "starts when it reaches 0"
                  % (_sk, _rsec), flush=True)
        if a.gs_auto_team_after >= 0:
            gs_table_state(_sk)["auto_at"] = (
                gs_table_state(_sk)["brief_end"]
                or time.time() + _bsec + 2.0)
            print("  [start-all] table %d: anyone "
                  "without a team is auto-teamed (and "
                  "a one-sided table rebalanced) in "
                  "%.0f s (end of the briefing)"
                  % (_sk, gs_table_state(_sk)["auto_at"]
                     - time.time()), flush=True)
        print("  [start-all] leader 0x%08x START at table "
              "%d -> other seated: %s"
              % (_lead or 0, _sk, ["0x%x" % m for m in _others]),
              flush=True)
        for _m in _others:
            _ms = session_of(_m)
            if _ms is None or _ms is skip_sess:
                print("  [start-all] seated member "
                      "0x%08x has no live session -- "
                      "it stays in the lobby" % _m,
                      flush=True)
                continue
            try:
                push_battle_ready(_ms, _sk)
            except Exception:
                import traceback
                print("  [start-all] push to 0x%08x "
                      "FAILED:\n%s"
                      % (_m, traceback.format_exc()),
                      flush=True)

    def push_lobby_npcs(msess, src):
        """sec 4gs addendum 3: announce the lobby NPCs (notify kind 15) to a
        client whose in-world stream is live -- once per in-world stretch. At
        +delay: selector 38 (the only writer of [chan+2148] = 1; the receive
        gate drops all but type 29 at 0) + the message-27 re-arm (38 zeroes
        [chan+204]); 2 s later, the kind-15 batches. Offline-proven up to the
        unit spawn (an offline run of the client's own code (doc_npc_spawn_proof)); the model is not."""
        now = time.time()
        _cid = msess.seen_charid[0]
        # Once per ENTRANCE (a new user id re-arms it), and never for a player
        # seated at a battletable: they are bound for the briefing room or an
        # arena, where a 38 of ours would cut across the battle flow.
        st = _npc_spawn.get(msess.key)
        if st is None or st["uid"] != msess.seen_uid[0]:
            st = _npc_spawn[msess.key] = {"due": now + a.npc_spawn_delay,
                                       "ready_at": 0.0, "done": False,
                                       "uid": msess.seen_uid[0]}
        if st["done"] or now < st["due"]:
            return
        if a.npc_spawn_via == "wu":
            # sec 4gs addendum 5: type-125 with nibble-4 ids -- the client
            # registers each NPC itself (0x00bd2358 -> kelsvc +288, rec+32 = 1)
            # and its online entity pump builds bzd record wire+4. Resent as
            # the NPCs' pose update; stops by itself once the lobby stream does.
            if now < st.get("next", 0.0):
                return
            _recs = doc_npc_spawn.wu_records(_npc_spawn_only,
                                             mode=a.npc_spawn_type,
                                             name=a.npc_spawn_name)
            for _i in range(0, len(_recs), doc_npc_spawn.PER_MSG):
                s.sendto(worldpose.build_world_update(_recs[_i:_i + doc_npc_spawn.PER_MSG],
                                            seq=a.lobby_seq), src)
            _first = not st.get("next")
            if a.npc_spawn_every > 0:
                st["next"] = now + a.npc_spawn_every
            else:
                st["done"] = True
            if _first:
                print("  [npc-spawn] SENT type-125 world update(s): %d NPC(s), "
                      "ids 0x%08x.., wire+4 = %s -> %s:%d%s"
                      % (len(_recs), _recs[0]["id"] if _recs else 0,
                         a.npc_spawn_type, src[0], src[1],
                         (" (resending every %.0f s)" % a.npc_spawn_every)
                         if a.npc_spawn_every > 0 else ""), flush=True)
            return
        if _cid and bt_store.table_of(_cid):
            return
        if a.npc_spawn_ready == "38" and not st["ready_at"]:
            _req = bytearray(framing.HDR_LEN + 176)
            _req[0] = 0x04
            struct.pack_into("<H", _req, 2, len(_req))
            _req[8] = a.world_type & 0xFF
            _rd = worlddoor.build_world_answer(
                bytes(_req), selector=worldchannel.GS_READY_SELECTOR, seq=a.lobby_seq,
                subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
                inner_ip=None, ptype=a.world_type, pad_to=a.world_pad,
                ident=_cid)
            if _rd is None:
                return
            s.sendto(briefingroom.gs_ready_roster(_rd, _cid, a.gs_connect_id, ()), src)
            s.sendto(gamemsg.build_gs_stats(_gs_stat_list, state=a.gs_arm_state,
                                    seq=next_gs_seq(msess), ident=_cid), src)
            msess.gs_ka_src[0] = src
            msess.gs_ka_next[0] = now + a.gs_keepalive_ms / 1000.0
            st["ready_at"] = now
            print("  [npc-spawn] SENT selector %d (channel READY) + re-arm "
                  "(message %d) to 0x%08x at %s:%d; kind %d follows in 2 s"
                  % (worldchannel.GS_READY_SELECTOR, gamemsg.GS_ARM_MSG, _cid, src[0], src[1],
                     doc_npc_spawn.KIND_ADD_NPC), flush=True)
            return
        if a.npc_spawn_ready == "38" and now - st["ready_at"] < 2.0:
            return
        _bodies = doc_npc_spawn.payloads(_npc_spawn_only, mode=a.npc_spawn_type,
                                         hp=a.npc_spawn_hp)
        for _b in _bodies:
            s.sendto(gamemsg.build_gs_notify(doc_npc_spawn.KIND_ADD_NPC, _b,
                                     seq=next_gs_seq(msess), ident=_cid), src)
        st["done"] = True
        print("  [npc-spawn] SENT notify kind %d 'Add Npc': %d NPC(s) in %d "
              "message(s), ids 0x%08x.., type=%s -> %s:%d"
              % (doc_npc_spawn.KIND_ADD_NPC,
                 sum(struct.unpack_from("<I", _b, 0)[0] for _b in _bodies),
                 len(_bodies), doc_npc_spawn.ID_BASE, a.npc_spawn_type,
                 src[0], src[1]), flush=True)

    def gs_sync_table(key):
        """sec 4ft: bring every seated member's briefing roster up to date
        (kind 31 add chara for each OTHER member with a team, kind 0 when a
        team changed) and, once the roster is ready and has settled, push the
        kind-20 distribution over it to every member. Idempotent; driven by
        request 31, which the briefing room re-sends every 1-4 s."""
        g = gs_table_state(key)
        members = [m for m in bt_store.members(key) if m]
        live = {}
        for m in members:
            ms = session_of(m)
            if ms is not None and ms.gs_src[0] is not None:
                live[m] = ms
        # 2026-09-29: a MISSION table is co-op (one side is fine), and a table
        # FULL to its player limit need not wait out the countdown
        _rec_t = bt_store.record(key)
        _coop = bool(_rec_t is not None and len(_rec_t) > tablerecords.BT_OFF_FLAGS + 3
                     and struct.unpack_from("<I", _rec_t, tablerecords.BT_OFF_FLAGS)[0]
                     & tablerecords.BT_FLAG_MISSION)
        # 2026-10-06 (live, 3- and 4-player BT): every BT briefing sends request
        # 31 with 0, the "one side" rebalance then split them 2/1 and the pairs
        # saw each other as allies. The client skips the team compare when the
        # 38's flags carry 0x200 (getter 0x00BDA390, proven offline, scratchpad
        # re-bt/), so on those consoles it did not; defence in depth: an
        # individual table has no sides -- no rebalance, no both-sides rule,
        # and each member's team is its seat (distinct; kind 31 holds 0..14).
        _ind = bool(_rec_t is not None and len(_rec_t) > tablerecords.BT_OFF_FLAGS + 3
                    and struct.unpack_from("<I", _rec_t, tablerecords.BT_OFF_FLAGS)[0]
                    & tablerecords.BT_FLAG_INDIVIDUAL)
        if _ind:
            _coop = True
            for _si, _sm in enumerate(members):
                if _sm in g["teams"]:
                    g["teams"][_sm] = min(_si, 14)
        _full = bool(_rec_t is not None and len(_rec_t) > tablerecords.BT_OFF_MAX
                     and _rec_t[tablerecords.BT_OFF_MAX]
                     and len(members) >= _rec_t[tablerecords.BT_OFF_MAX])
        # 2026-10-01, manual p.30: "when every member is ready, or the time
        # limit runs out" -- for every mode (--briefing-start ready). `full`
        # is the 09-29 rule: PvP waits for a full table or the countdown.
        g["early"] = (a.briefing_start == "ready") or _coop or _full
        # 2026-09-23: the briefing countdown ran out and someone still has no
        # team -- seat them on the smaller side so the distribution can go out
        if (a.gs_real_dist and not g["dist"] and g.get("auto_at")
                and time.time() >= g["auto_at"]):
            if len(members) == 1 and a.gs_solo_dist:
                # 2026-09-24: a SOLO player who never stepped on a team space
                # sent no request 31, so the post-join timer (the only solo
                # start) was never armed and the countdown ended in nothing
                g["auto_at"] = None
                _ms1 = live.get(members[0])
                if (_ms1 is not None and not _ms1.gs_join_deadline[0]
                        and battle_of(members[0]) is None):
                    _ms1.gs_join_src[0] = _ms1.gs_src[0]
                    _ms1.gs_join_deadline[0] = time.time()
                    print("  [roster] table %d: briefing time is up -- SOLO "
                          "0x%x never chose a team, starting on team 0"
                          % (key, members[0]), flush=True)
            elif len(members) >= 2 and len(live) < len(members):
                # not everyone is in the briefing room yet: look again in 5 s
                # (the deadline is also the timer loop's wake-up, so it must
                # move or the loop spins)
                g["auto_at"] = time.time() + 5.0
            else:
                g["auto_at"] = None
                _auto, _assigned = teamdist.gs_auto_teams(g["teams"], members)
                if len(members) >= 2 and _assigned:
                    g["teams"].update(_auto)
                    print("  [roster] table %d: briefing time is up -- "
                          "AUTO-TEAMED %s (they never sent request 31)"
                          % (key, ", ".join("0x%x -> team %d" % (m, _auto[m])
                                            for m in _assigned)), flush=True)
                    # 2026-10-03 (live, table 7): request 31 is also what sets
                    # gs_join_src, and the GO burst (kind 5 START) only goes to
                    # a session that has one -- so an auto-teamed player loaded
                    # the arena and never started. Same move as the SOLO branch.
                    for _m in _assigned:
                        _msa = live.get(_m)
                        if _msa is not None:
                            _msa.gs_join_src[0] = _msa.gs_src[0]
                if len(members) >= 2 and a.gs_rebalance and not _coop:
                    _rb, _moved = teamdist.gs_rebalance_teams(g["teams"], members)
                    if _moved:
                        g["teams"].update(_rb)
                        print("  [roster] table %d: briefing time is up and "
                              "everyone is on ONE side -- REBALANCED %s"
                              % (key, ", ".join("0x%x -> team %d" % (m, _rb[m])
                                                for m in _moved)), flush=True)
        if _ind:
            # the auto-team above may have seated a latecomer on 0 / 1
            for _si, _sm in enumerate(members):
                if _sm in g["teams"]:
                    g["teams"][_sm] = min(_si, 14)
        for obs, ms in live.items():
            shown = g["shown"].setdefault(obs, {})
            # 2026-09-23: someone stepped off a space (request 33) -> kind 1,
            # or its row never counts down
            for cid in [c for c in shown if c not in g["teams"]]:
                s.sendto(gamemsg.build_gs_team_leave(cid, seq=next_gs_seq(ms)),
                         ms.gs_src[0])
                print("  [roster] SENT notify 1 (leave team) 0x%08x -> 0x%08x's "
                      "briefing" % (cid, obs), flush=True)
                del shown[cid]
            for cid in members:
                if cid not in g["teams"]:
                    continue
                team = g["teams"][cid]
                if cid == obs:
                    # 2026-09-13: the observer's OWN team change, to itself --
                    # kind 31 skips the own id by design, and without this
                    # the player's own team icon never changed on stepping
                    # into a team zone.
                    if shown.get(cid) != team:
                        s.sendto(gamemsg.build_gs_team_set(cid, team, seq=next_gs_seq(ms)),
                                 ms.gs_src[0])
                        print("  [roster] SENT notify 0 (set team) 0x%08x -> team "
                              "%d to ITSELF (own icon / counts)" % (cid, team),
                              flush=True)
                        shown[cid] = team
                    continue
                if cid not in shown:
                    # every seated
                    # member is already in this observer's roster from ITS 38
                    # (gs_ready_roster), filed with team 0xff, so a plain kind 0
                    # is a +1 on the row. The kind 31 we sent here could never
                    # move a count (and clobbered roster slots).
                    s.sendto(gamemsg.build_gs_team_set(cid, team, seq=next_gs_seq(ms)),
                             ms.gs_src[0])
                    print("  [roster] SENT notify 0 (set team) 0x%08x -> team %d "
                          "-> 0x%08x's briefing (first sight)" % (cid, team, obs),
                          flush=True)
                elif shown[cid] != team:
                    s.sendto(gamemsg.build_gs_team_set(cid, team, seq=next_gs_seq(ms)),
                             ms.gs_src[0])
                    print("  [roster] SENT notify 0 (set team) 0x%08x %d -> %d "
                          "-> 0x%08x's briefing (sec 4ft)"
                          % (cid, shown[cid], team, obs), flush=True)
                else:
                    continue
                shown[cid] = team
        if not a.gs_real_dist or g["dist"]:
            return
        # sec 4he: a UNIT table seats unit vs unit, whatever zone was clicked
        _rec_u = bt_store.record(key)
        if (_units is not None and _rec_u is not None
                and struct.unpack_from("<I", _rec_u, tablerecords.BT_OFF_FLAGS)[0] & tablerecords.BT_FLAG_UNIT):
            _ut = battleroom.unit_teams(g["teams"], members, _unit_of_cid)
            if _ut != g["teams"]:
                print("  [roster] table %d is a UNIT table: sides by unit -> %s "
                      "(sec 4he)" % (key, {"0x%x" % k: v for k, v in _ut.items()}),
                      flush=True)
                g["teams"].update(_ut)
        ok, why = teamdist.gs_real_ready(g["teams"], members, coop=_coop)
        if ok and len(live) < len(members):
            ok, why = False, ("waiting for %d member(s) to reach the briefing "
                              "room" % (len(members) - len(live)))
        if why != g["why"]:
            g["why"] = why
            print("  [roster] table %d: %s" % (key, why), flush=True)
        now = time.time()
        if not ok:
            g["ready_at"] = None
            return
        if g["ready_at"] is None:
            g["ready_at"] = now
            _due = teamdist.gs_dist_due(g, a.gs_real_dist_settle)
            print("  [roster] table %d READY -- the distribution goes out in "
                  "%.0f s%s unless someone changes side"
                  % (key, _due - now, " (the end of the briefing countdown)"
                     if _due > now + a.gs_real_dist_settle else ""), flush=True)
        if now < teamdist.gs_dist_due(g, a.gs_real_dist_settle):
            return
        dist = teamdist.gs_real_distribution(g["teams"], members)
        if a.gs_add_chara_before_dist == "on":
            # 2026-10-03 (live: in TEAM battles only the leader's hits
            # landed): a client keeps a remote's TEAM only in its profile
            # cache entry ([kelsvc+0x118], team +0x3c), and kind 0 / kind 20
            # store it only when that entry exists. Nothing created one in
            # battle, so every remote resolved to team 0xff -- a client whose
            # own team was also 0xff took them all for teammates
            # (0x00bd36d0 -> 0x006b0aa0 side 0) and never sent a 113. Kind
            # 31 (add chara) creates the entry WITH its team. Sent here, after
            # the briefing counts are final (a 31 with a team never moves a
            # count), with the distribution's own slots.
            for obs, ms in live.items():
                for cid, tm, slot in dist:
                    if cid == obs:
                        continue
                    s.sendto(gamemsg.build_gs_add_chara(
                        cid, tm, slot=slot, seq=next_gs_seq(ms), self_ident=obs,
                        addr=battle_addr(ms.gs_src[0][0])),
                        ms.gs_src[0])
            print("  [roster] SENT notify 31 (add chara, with team) for every "
                  "other member to %d client(s) before the distribution -- "
                  "each remote's team in the client's profile cache"
                  % len(live), flush=True)
        for obs, ms in live.items():
            s.sendto(gamemsg.build_gs_distribution(dist, seq=next_gs_seq(ms), ident=obs),
                     ms.gs_src[0])
        g["dist"] = True
        open_battle(key, members, g["teams"], now=now)
        print("  [roster] SENT notify 20 (PLAYER DISTRIBUTION) over the REAL "
              "roster %s to %d client(s). Watch: 'Player distribution has been "
              "determined' -> OK -> request 47 -> 48 + %s with kind 2 zone %d -> "
              "get_onlinezone -> KerberosZone.exit(z%d) (sec 4ft)"
              % (["0x%x:t%d:s%d" % e for e in dist], len(live),
                 a.gs_battle_start, a.gs_battle_zone, a.gs_battle_zone),
              flush=True)

    # ── sec 4he: BATTLE ROOMS, one per table ───────────────────────────
    battles = {}             # table key -> BattleRoom
    # 2026-09-26: MISSION SUPPLIES. session key -> {item: qty} the server
    # believes the player holds (world-door bag, minus each battle's request
    # 44, plus our grants); topped up to the mission's supplies at its 47.
    _supply_bag = {}
    _supply_44 = {}          # session key -> the battle (47 time) already counted
    _room_member_key = {}    # charid -> wallet key at its 47 (a member that
                             # leaves before the end has no session to ask)

    def battle_of(cid):
        if not cid:
            return None
        key = bt_store.table_of(cid)
        room = battles.get(key) if key is not None else None
        if room is None:
            for r in battles.values():
                # never a room whose TABLE is gone
                # -- the church battle "ARRIVED in table 1's room" (the
                # dissolved Wastelands table) and so never opened its own.
                if (cid in r.kills and cid not in r.left
                        and (r.key == -1 or r.key in bt_store.tables)):
                    return r
        return room

    def mission_npc_send(cid, kind, payload):
        """2026-10-05: one game-server notify to mission member `cid` on its
        battle channel (gs_join_src), for the room's shared enemy set."""
        ms = session_of(cid)
        if ms is None or ms.gs_join_src[0] is None:
            return False
        s.sendto(gamemsg.build_gs_notify(kind, payload, seq=next_gs_seq(ms),
                                         ident=cid), ms.gs_join_src[0])
        return True

    def member_dst(cid):
        ms = session_of(cid)
        if ms is None:
            return None, None
        return ms, (ms.gs_src[0] or ms.ka_src or ms.src)

    def send_reservation_clear(cid, dst=None, why=""):
        """Selector 110 to `cid` on its WORLD channel: the push that empties
        the client's own reservation (BT_RESERVATION_CLEAR_SEL). Sent wherever
        a table disappears under a client that may still hold it."""
        if not cid:
            return False
        if dst is None:
            ms = session_of(cid)
            dst = (ms.ka_src or ms.src) if ms is not None else None
        if dst is None:
            return False
        _req = bytearray(framing.HDR_LEN + 176)
        _req[0] = 0x04
        struct.pack_into("<H", _req, 2, len(_req))
        _req[8] = a.world_type & 0xFF
        _pk = worlddoor.build_world_answer(
            bytes(_req), selector=tableverbs.BT_RESERVATION_CLEAR_SEL, seq=a.lobby_seq,
            subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
            inner_ip=None, ptype=a.world_type, pad_to=a.world_pad, ident=cid)
        if _pk is None:
            return False
        s.sendto(_pk, dst)
        print("  SENT type-%d RESERVATION CLEAR (selector %d, ident 0x%08x) "
              "to %s:%d -- R+756 = 0xffff on the client%s"
              % (a.world_type, tableverbs.BT_RESERVATION_CLEAR_SEL, cid, dst[0], dst[1],
                 (" (%s)" % why) if why else ""), flush=True)
        return True

    def open_battle(key, members, teams, mission=None, now=None):
        """The distribution went out: from here the table is IN PROGRESS and
        the room owns the clock, the tally and the verdict. Rules come from
        the table RECORD (battle_rules_from_record) with the old knobs as
        the fallback for whatever the record does not carry."""
        now = now if now is not None else time.time()
        rec = bt_store.record(key) if key is not None else None
        rules = battleroom.battle_rules_from_record(
            rec, default_length=a.gs_battle_length,
            default_kill=a.bt_kill_target, default_respawn=a.bt_respawn_s,
            time_unit=a.bt_time_unit)
        # RETAIL never sends command 41, so `mission` (from
        # _mission_battle) stayed None while the TABLE said Mission (flags
        # 0x10000, quest at wire+26 = rules.mission): the room was labelled
        # MISSION but no mission hook (scoring, NPC HP, killer fallback,
        # verdict) ever ran. Take the quest from the record.
        if mission is None and rules.mode == "MISSION" and rules.mission:
            mission = rules.mission
        if mission is not None:
            rules.mode = "MISSION"
            # 2026-09-24: the archive's time limit for this mission (the record
            # we serve carries the same number, so the HUD agrees)
            _mt = doc_missions.time_limit(mission)
            if _mt:
                rules.time_limit = float(_mt)
            # 2026-10-03: the stored record keeps --bt-situation 1100; only
            # the 38 the client gets carries the quest's situation (sec 4ft
            # rewrite), so a mission room placed the PvP item generators
            if _quest_sit.get(mission):
                rules.situation = _quest_sit[mission]
        room = battleroom.BattleRoom(key if key is not None else -1, members, teams, rules,
                          leader=bt_store.leader_cid(key) if key is not None else 0,
                          mission=mission, now=now)
        battles[room.key] = room
        if key is not None:
            bt_store.set_in_progress(key, True)
        print("  [battle] ROOM OPENED for table %s: %d member(s) %s, teams %s, "
              "%r -- In Progress on the list, no new seats (sec 4he)"
              % (key, len(room.members),
                 ["0x%x" % m for m in room.members],
                 {"0x%x" % k: v for k, v in room.teams.items()}, rules),
              flush=True)
        if room.leader_mode():
            print("  [leader] TEAM LEADER battle, table %s: leaders %s -- only "
                  "an enemy leader's death scores (SE 28:205)"
                  % (key, {t: "0x%x" % m for t, m in room.team_leaders.items()}),
                  flush=True)
            tag_leaders(room, list(room.team_leaders.values()), True, "battle start")
        return room

    def queued_for(key, now=None):
        """The live queue of `key`: expired entries dropped."""
        now = time.time() if now is None else now
        q = _join_queue.get(key) or {}
        for c in [c for c, t0 in q.items() if now - t0 > a.join_queue_ttl]:
            del q[c]
        return list(q)

    def unqueue(cid, why=""):
        for k in list(_join_queue):
            if _join_queue[k].pop(cid, None) is not None:
                print("  [queue] 0x%08x left table %d's queue (%s)"
                      % (cid, k, why), flush=True)
            if not _join_queue[k]:
                del _join_queue[k]

    def queue_join(key, cid):
        """2026-10-03 (--join-queue): a JOIN refused because `key`'s briefing
        or battle runs. Kept OUT of the table's members (a late seat counted
        by the running room was the 09-29 bug), seated at the next round."""
        t = bt_store.tables.get(key)
        if a.join_queue != "on" or not cid or t is None or cid in t["members"]:
            return False
        unqueue(cid, "queued elsewhere")
        mx = min(t["rec"][tablerecords.BT_OFF_MAX] or tableverbs.BT_MAX_MEMBERS,
                 tableverbs.BT_MAX_MEMBERS)
        if len(t["members"]) + len(queued_for(key)) >= mx:
            print("  [queue] table %d is FULL with its queue -- 0x%08x not "
                  "queued" % (key, cid), flush=True)
            return False
        _join_queue.setdefault(key, {})[cid] = time.time()
        print("  [queue] 0x%08x QUEUED for table %d's next round (%d waiting)"
              % (cid, key, len(_join_queue[key])), flush=True)
        return True

    def keep_for_rematch(room, why):
        """2026-10-03, manual p.33: the table outlives its battle. Whoever
        took command 4 out of the battle, or has no session, gives up the
        seat; the others (and the queue) go back to the briefing room in
        --rematch-after s. False when there is nobody to play again."""
        key = room.key
        if a.rematch_after < 0 or room.mission is not None or key == -1:
            return False
        rec = bt_store.record(key)
        if rec is None or (struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0]
                           & tablerecords.BT_FLAG_MISSION):
            return False
        stay = [m for m in bt_store.members(key)
                if m and m not in room.left and session_of(m) is not None]
        if len(stay) + len(queued_for(key)) < 2:
            return False
        for m in [m for m in bt_store.members(key) if m not in stay]:
            bt_store.cancel(m)
            send_reservation_clear(m, why="left table %d before its next round"
                                   % key)
        bt_store.set_in_progress(key, False)
        gs_tables.pop(key, None)
        _rematch[key] = time.time() + a.rematch_after
        _rematch_since[key] = time.time()
        print("  [rematch] table %d KEPT after the battle (%s): %d seated, %d "
              "queued -- back to the briefing room in %.0f s (manual p.33)"
              % (key, why, len(stay), len(queued_for(key)), a.rematch_after),
              flush=True)
        return True

    def start_rematch(key):
        if key not in bt_store.tables:
            _join_queue.pop(key, None)
            return
        if _briefing_running(key) or bt_store.in_progress(key):
            print("  [rematch] table %d already started -- nothing to do" % key,
                  flush=True)
            return
        for q in queued_for(key):
            qs = session_of(q)
            if (qs is None or qs.ka_src is None or bt_store.table_of(q) is not None
                    or battle_of(q) is not None):
                print("  [queue] 0x%08x skipped for table %d (gone, seated "
                      "elsewhere or in a battle)" % (q, key), flush=True)
                continue
            res, _k = bt_store.reserve(key, q, None)
            print("  [queue] 0x%08x SEATED at table %d for the next round -> %d"
                  % (q, key, res), flush=True)
        _join_queue.pop(key, None)
        members = [m for m in bt_store.members(key) if m]
        if len(members) < 2:
            print("  [rematch] table %d has %d player(s) -- it stays open in "
                  "the lobby" % (key, len(members)), flush=True)
            return
        # 39 may have cleared the client's own reservation (R+2970/R+684 bit
        # 4, sec 4fl); re-echo it before the 38, as after a CREATE/JOIN
        if not a.bt_no_reserve_echo:
            for m in members:
                ms = session_of(m)
                if ms is not None and ms.ka_src is not None:
                    s.sendto(tableverbs.build_reserve_echo(
                        synth_world_req(), key, seq=a.lobby_seq,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7),
                        ptype=a.world_type, pad_to=a.world_pad, ident=m),
                        ms.ka_src)
        print("  [rematch] table %d: %d player(s) back to the briefing room"
              % (key, len(members)), flush=True)
        begin_briefing(key, bt_store.leader_cid(key), members)

    def close_battle(room, why="over", rematch=False):
        battles.pop(room.key, None)
        if room.leader_mode():
            tag_leaders(room, list(room.team_leaders.values()), False, "battle over")
        if rematch and room.key in bt_store.tables and keep_for_rematch(room, why):
            return
        if room.key in bt_store.tables:
            bt_store.set_in_progress(room.key, False)
            # the queue was refused (-4), so it holds no reservation to clear
            _join_queue.pop(room.key, None)
            if bt_store.dissolve(room.key, force=True):
                gs_tables.pop(room.key, None)
                print("  [battle] table %d DISSOLVED after the battle (%s) -- "
                      "off the battle table list (sec 4gc/4he)"
                      % (room.key, why), flush=True)
                for m in room.members:
                    send_reservation_clear(m, why="table %d dissolved after "
                                           "the battle" % room.key)

    def _member_name(cid):
        n = (players.get(cid, {}).get("name") or relay_names.get(cid)
             or next((nm for _k, nm, _i in _rank_characters() if _i == cid), None))
        return n or "0x%08x" % cid

    def tag_leaders(room, cids, on=True, why=""):
        """2026-09-24 (TEAM LEADER, an experiment): the client draws no
        leader, so rename each leader "[L]Name" in the PEER table of every
        other member -- the same unsolicited selector-37 answer the lobby
        relay already re-pushes (0x00bd9090 overwrites the slot). on=False
        restores the plain name. Whether the battle's name display reads the
        peer table is what the live test shows."""
        if a.leader_tag != "on" or not cids:
            return
        sub = a.world_subchannel if a.world_subchannel >= 0 else 7
        for lc in cids:
            nm = _member_name(lc)
            shown = (battleroom.LEADER_TAG + nm)[:15] if on else nm
            sent = 0
            for m in room.members:
                if m == lc:
                    continue
                # a peer answer is a WORLD-channel message (type 127),
                # like the reservation clear -- not the game-server channel
                ms = session_of(m)
                dst = (ms.ka_src or ms.src) if ms is not None else None
                if dst is None:
                    continue
                s.sendto(peerrecords.build_peer_answer(
                    None, lc, seq=a.lobby_seq, subchannel=sub,
                    ptype=a.world_type, ident=ms.seen_charid[0],
                    blob=peerrecords.build_peer_record(lc, name=shown, zone=a.user_zone,
                                           rank=rank_of_cid(lc), flags=peer_flags(lc),
                                           f36=player_look.get(lc),
                                           **peer_addr(lc, dst[0], m))[4:]), dst)
                sent += 1
            print("  [leader] %s 0x%08x as %r -> %d member(s)%s"
                  % ("TAGGED" if on else "UNTAGGED", lc, shown, sent,
                     (" (%s)" % why) if why else ""), flush=True)

    def push_kill_event(room, fields):
        points, killer, victim, last_one = fields
        for m in room.present():
            ms, dst = member_dst(m)
            if dst is None:
                continue
            s.sendto(gamemsg.build_gs_kill_event(points, killer, victim, last_one,
                                         seq9=room.seq9, seq=next_gs_seq(ms),
                                         ident=m), dst)

    def push_down(room, victim):
        """Kind 25 about `victim` to every member. Retail death flow (read
        2026-09-23): kind 9 -> the client acks with request 43 and puts the
        victim in state 1; kind 25 sets the dead bits + respawn point, state
        2; kind 13 at the respawn deadline revives, state 0."""
        (_dp, _dbm) = _spawn_of.get(victim, (None, (0, 0)))
        if _dp is None:
            print("  [battle] DOWN 0x%x: no recorded spawn, respawn point "
                  "(0, 0, 0) map %s" % (victim, _dbm), flush=True)
            _dp = (0.0, 0.0, 0.0)
        elif a.respawn_random:
            # 2026-10-01, manual p.33: a KO'd character "revives at a random
            # position (in team battles, a random position of its own team)".
            # The arena data has no list of respawn nodes, so the pool is the
            # points this battle already put players on (each one's first
            # spawn, on the floor by construction): the victim's team's in a
            # team battle, everyone's in BT.
            _pool = [_spawn_of[m][0] for m in room.members
                     if m in _spawn_of and _spawn_of[m][0] is not None
                     and (room.individual() or room.team_of(m) == room.team_of(victim))]
            if _pool:
                _dp = random.choice(_pool)
        # 2026-10-01: RERAISE (manual p.32, "revive from KO with full HP").
        # The client never revives itself -- at HP 0 it reports the death
        # (request 30) whatever its status -- so the server does: the victim
        # comes back where it fell, at once (kind 25 at its last position,
        # kind 13 on the next tick), and the spent Reraise is echoed off
        # (kind 43). Only kinds seen working live (re-battle option B); kind 9
        # followed by kind 19 without a 13 leaves the victim untouchable.
        _rr = _status.get(victim, 0)
        if a.status_echo and _rr & gamemsg.STATUS_RERAISE:
            # 2026-10-05 (live, Iron Curtain): only a FRESH arena pose. The
            # session's last_pose can be a LOBBY position (a console whose
            # arena pose stream we cannot read), which revived the player in
            # the void at (1089, 0, 202); without one, the battle spawn.
            _vp0 = _battle_pose.get(victim)
            if _vp0 is not None and time.time() - _vp0[3] < 5.0:
                _dp = (float(_vp0[0]), float(_vp0[1]), float(_vp0[2]))
            room.dead_until[victim] = time.time()
            _status[victim] = _rr & ~gamemsg.STATUS_RERAISE & 0xFFFFFFFF
            for m in room.present():
                ms, dst = member_dst(m)
                if dst is not None:
                    s.sendto(gamemsg.build_gs_notify(
                        gamemsg.GS_KIND_STATUS, struct.pack("<I", _status[victim]),
                        seq=next_gs_seq(ms), ident=victim), dst)
            print("  [battle] RERAISE 0x%x: revives where it fell (%.0f, %.0f, "
                  "%.0f), no penalty time; status -> 0x%08x"
                  % ((victim,) + tuple(_dp) + (_status[victim],)), flush=True)
        # 2026-09-26: the respawn REFILL (kind 25 carries 3 entries and SETS
        # each quantity). Retail rule: BULLETS only, topped up to the
        # battle-start count; each row is max(supplies ledger, battle-start)
        # so a SET never cuts a count the ledger knows (doc_missions.
        # respawn_refill).
        # 2026-10-06: the pieces AT the respawn point (random pool, Reraise),
        # not the first spawn's -- else the respawn lands on unloaded ground
        _dbm = arenamaps.spawn_bmap(_spawn_zone.get(victim), _dp, _dbm)
        _ammo25 = ()
        if a.respawn_ammo:
            _vs = session_of(victim)
            _want = doc_missions.supplies(
                _mission_battle.get(_vs.key) if _vs is not None else None,
                _ammo or doc_missions.STANDARD_SUPPLIES)
            _vheld = (_supply_bag.get(_vs.key) if _vs is not None else None)
            _ammo25 = doc_missions.respawn_refill(_want, _vheld)
            if _vheld is not None:
                _vheld.update(_ammo25)
        for m in room.present():
            ms, dst = member_dst(m)
            if dst is None:
                continue
            s.sendto(gamemsg.build_gs_down(_dp[0], _dp[1], _dp[2], bmap=_dbm,
                                   seq=next_gs_seq(ms), ident=victim,
                                   ammo=_ammo25), dst)
        print("  [battle] DOWN 0x%x: SENT notify kind %d to %d member(s), "
              "respawn at (%.0f, %.0f, %.0f) pieces %s in %.0f s%s"
              % (victim, gamemsg.GS_DOWN_KIND, len(room.present()), _dp[0], _dp[1],
                 _dp[2], tuple(_dbm), room.rules.respawn,
                 ", ammo refilled to %s" % ", ".join(
                     "0x%08x x%d" % e for e in _ammo25) if _ammo25 else ""),
              flush=True)

    def push_revive(room, victim):
        for m in room.present():
            ms, dst = member_dst(m)
            if dst is None:
                continue
            s.sendto(gamemsg.build_gs_notify(a.respawn_kind, struct.pack("<I", 0),
                                     seq=next_gs_seq(ms), ident=victim), dst)
        # 2026-09-24: no respawn kind touches MP on the client (only 2 / 51 /
        # 44 / 34 / message 61 write R+48), so a KO would keep whatever MP the
        # player died with. OURS (inferred retail): refill with kind 44.
        if a.mp_model == "ledger" and a.mp_respawn == "full" \
                and _magic.mp(victim) is not None:
            vs, vdst = member_dst(victim)
            if vdst is not None:
                _vmp = _magic.refill(victim)
                s.sendto(gamemsg.build_gs_mp_push(_vmp, seq=next_gs_seq(vs),
                                          ident=victim), vdst)
                print("  [magic] 0x%x respawned: MP -> %d (notify kind 44)"
                      % (victim, _vmp), flush=True)

    _MODE_INDEX = {"BT": 0, "TBT": 1, "TDM": 2, "TBS": 3, "TCP": 4, "TLD": 5,
                   "TFL": 6}

    def result_inputs(room, m):
        """2026-10-01: member `m`'s inputs to SE's rank-point formula
        (doc_stats.results_rp) and to the kind-4 record that shows them: the
        mode index (the table's mode byte), teammate KOs, kill streak, player
        count, base HP and the mode block's team rows. A row OURS can't fill
        (damage dealt to a base, capsule hold time, flags) stays 0."""
        mi = _MODE_INDEX.get(room.rules.mode, 1)
        team = room.team_of(m)
        mates = [x for x in room.members if room.team_of(x) == team]
        foes = [x for x in room.members if room.team_of(x) != team]
        blk = {}
        if mi == 1:
            blk["team_kills"] = sum(room.kills.get(x, 0) for x in mates)
        elif mi == 2:
            blk["survivors"] = sum(1 for x in mates if x not in room.left
                                   and not room.eliminated(x))
        elif mi == 3:
            own = room.base_hp.get(team)
            enemy = room.base_hp.get(1 - team) if team in (0, 1) else None
            blk["own_base_hp"] = own or 0
            blk["enemy_base_left"] = (room.rules.base_hp if enemy is None
                                      else enemy)
            blk["base_attack"] = int(m == room.occupier)
            blk["base_flags"] = 4 if own else 0
        elif mi == 4:
            blk["carriers_killed"] = room.carrier_kos.get(m, 0)
            blk["capsule_obtained"] = int(room.holders.get(m, 0) > 0)
            blk["capsules_end"] = sum(room.holders.get(x, 0) for x in mates)
        elif mi == 5:
            blk["leaders_killed"] = room.leader_kills.get(m, 0)
            blk["leader_points_earned"] = sum(room.leader_kills.get(x, 0)
                                              for x in mates)
            blk["leader_points_lost"] = sum(room.leader_kills.get(x, 0)
                                            for x in foes)
        return {"mode_idx": mi, "team_kos": room.team_kos.get(m, 0),
                "streak": room.streaks.get(m, 0),
                "players": len(room.members),
                "base_hp": room.rules.base_hp, "block": blk}

    def end_battle(room, now, why=None):
        """Kind 4 (the RESULT, facade 0x40) to every member still in the
        room, with the room's verdict; selector 39 follows for each after
        --gs-battle-reset-after and the table is dissolved ONCE."""
        room.over = True
        room.why = room.why or why or "time limit"
        room.end_at = None
        # 2026-10-01 (--post-battle-briefing): the manual's "back to the
        # briefing room, then the transporter to the lobby" (p.33). Kind 4
        # already takes the client to br_main (ev2046, facade 0x80 kept); the
        # transporter sends lobby command 4 and the client resets itself.
        # Selector 39 is then only the fallback for whoever never leaves.
        room.reset_at = now + (a.post_battle_briefing if a.post_battle_briefing > 0
                               else a.gs_battle_reset_after)
        print("  [battle] END %s" % room.summary(), flush=True)
        for m in room.present():
            if m in room.result_sent:
                continue
            ms, dst = member_dst(m)
            if ms is None or dst is None:
                continue
            room.result_sent.add(m)
            _res_rec = bytes(gamemsg.GS_SETUP_LEN)
            _res_ok = False
            if _stats is not None:
                try:
                    _res_rec, _res_note = _battle_result(ms, room)
                    _res_ok = True
                    print("  [stats] " + _res_note, flush=True)
                except Exception as _rex:      # never let a tally kill the END
                    print("  [stats] RESULT tally FAILED (%r) -- sending the "
                          "zero record" % (_rex,), flush=True)
            _wc = room.winner_cid()
            if _wc is not None:
                # sec 4he (arm 0x00bc1ab8): in BT rec+29 is the
                # roster INDEX of the winner -> [chan+1384] -> "%s Wins by
                # Kill Count". The roster is selector 38's order for THIS
                # recipient: the others in seat order, itself last.
                _ro = [x for x in room.members if x != m][:31] + [m]
                _rr = bytearray(_res_rec)
                _rr[29] = _ro.index(_wc) if _wc in _ro else 0xFF
                _res_rec = bytes(_rr)
            # only when this result PAID them (a tally and a wallet)
            # (the carry cap is 9 -- item row +14 -- so no bag holds more)
            _held = (min(room.coins.pop(m, 0), doc_stats.COIN_CAP)
                     if a.chocobo_coins == "on" and _res_ok
                     and _shop is not None else 0)
            if _held > 0:
                # 2026-09-26: the coins were paid in this result's gil total
                # (doc_stats.coin_gil); cut them from the bag first. Kind 21
                # with ident = the recipient is the client's own "cut" arm
                # (0x00bc412c: ident == self -> 0x00bdef58 REMOVE {id, qty}
                # + event 9), the mirror of kind 11's add.
                s.sendto(gamemsg.build_gs_notify(21, fielditems.field_item_payload(
                    doc_stats.COIN_ITEM, 0, (0.0, 0.0, 0.0), _held,
                    head=fielditems.FIELD_QUIET), seq=next_gs_seq(ms), ident=m), dst)
                print("  [coins] SENT notify 21 to 0x%08x: CUT %d Chocobo "
                      "Coin(s) from the bag (paid %d gil)"
                      % (m, _held, doc_stats.coin_gil(_held)), flush=True)
            # 2026-09-28 (Dirge report): Mako Capsules picked up in the match
            # stayed in the bag after it -- the kind 11 of each pick-up put
            # them there and nothing took them out. The same kind-21 cut as
            # the coins; `holders` is left alone (the tally read it above).
            _caps = room.holders.get(m, 0)
            if _caps > 0:
                s.sendto(gamemsg.build_gs_notify(21, fielditems.field_item_payload(
                    fielditems.MAKO_CAPSULE, 0, (0.0, 0.0, 0.0), _caps,
                    head=fielditems.FIELD_QUIET), seq=next_gs_seq(ms), ident=m), dst)
                print("  [capsule] SENT notify 21 to 0x%08x: CUT %d Mako "
                      "Capsule(s) from the bag at the battle's end" % (m, _caps),
                      flush=True)
            # 2026-10-01, manual p.33: consumables picked up on the field stay
            # behind. Only the net still held (a used Potion sends no request,
            # so this may cut one the player drank: the client's REMOVE stops
            # at what the bag holds).
            for _ci, _cq in sorted(room.field_picks.pop(m, {}).items()):
                if _cq <= 0:
                    continue
                s.sendto(gamemsg.build_gs_notify(21, fielditems.field_item_payload(
                    _ci, 0, (0.0, 0.0, 0.0), _cq,
                    head=fielditems.FIELD_QUIET), seq=next_gs_seq(ms), ident=m), dst)
                if ms.key in _supply_bag and _ci in _supply_bag[ms.key]:
                    _supply_bag[ms.key][_ci] = max(0, _supply_bag[ms.key][_ci] - _cq)
                print("  [field] SENT notify 21 to 0x%08x: CUT %d x 0x%08x "
                      "picked up on the field (manual p.33)" % (m, _cq, _ci),
                      flush=True)
            s.sendto(gamemsg.build_gs_notify(4, bytes(4) + _res_rec,
                                     seq=next_gs_seq(ms), ident=m), dst)
            ms.gs_battle_end[0] = 0.0
            ms.gs_battle_go[0] = 0.0
            print("  [battle] SENT notify 4 (the RESULT, facade 0x40) to 0x%08x "
                  "-- selector %d in %.0f s (sec 4fy)"
                  % (m, briefingroom.GS_BATTLE_OVER_SELECTOR, a.gs_battle_reset_after),
                  flush=True)

    def battle_reset(room):
        for m in list(room.members):
            if m in room.left:
                continue        # back in the lobby already: no reset for it
            ms = session_of(m)
            if ms is None or ms.ka_src is None:
                continue
            ms.gs_battle_on[0] = 0.0
            _req = bytearray(framing.HDR_LEN + 176)
            _req[0] = 0x04
            struct.pack_into("<H", _req, 2, len(_req))
            _req[8] = a.world_type & 0xFF
            _bo = worlddoor.build_world_answer(
                bytes(_req), selector=briefingroom.GS_BATTLE_OVER_SELECTOR, seq=a.lobby_seq,
                subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
                inner_ip=None, ptype=a.world_type, pad_to=a.world_pad, ident=m)
            if _bo is not None:
                s.sendto(_bo, ms.ka_src)
                print("  [battle] SENT selector %d (battle over / reset, arm "
                      "0x00bcbd70) to 0x%08x at %s:%d (sec 4fy)"
                      % (briefingroom.GS_BATTLE_OVER_SELECTOR, m, ms.ka_src[0], ms.ka_src[1]),
                      flush=True)
        close_battle(room, room.why or "reset", rematch=True)

    def fire_battles(now):
        for room in list(battles.values()):
            if room.key != -1 and room.key not in bt_store.tables:
                # its table was dissolved (selector 125) or emptied (155)
                # under it: the room must not outlive it (live).
                battles.pop(room.key, None)
                print("  [battle] table %d is GONE -- its room CLOSED"
                      % room.key, flush=True)
                continue
            if room.go_due(now) and not room.over:
                room.go()
                print("  [battle] table %d shared GO: clock STARTED, %s"
                      % (room.key, ("ends in %.0f s" % (room.end_at - now))
                         if room.end_at else "no time limit"), flush=True)
            try:
                field_tick(room, now)
            except Exception:
                import traceback
                print("  [field] tick FAILED:\n%s" % traceback.format_exc(),
                      flush=True)
            if fielditems.capsule_hold_done(room, now):
                end_battle(room, now, "team %d held all %d Mako Capsules for "
                           "%.0f s" % (room.cap_hold[0], room.rules.capsules,
                                       fielditems.CAPSULE_HOLD_S))
            if room.base_down and not room.over:
                for _on in arenadata.base_occupy_tick(room, _battle_pose, now,
                                            a.base_occupy_radius,
                                            a.base_occupy_s):
                    print("  [base] table %d: %s" % (room.key, _on), flush=True)
                if room.over:
                    end_battle(room, now)
            if room.end_at and now >= room.end_at and not room.over:
                end_battle(room, now, "time limit %.0f s" % room.rules.time_limit)
            if room.reset_at and now >= room.reset_at:
                room.reset_at = None
                battle_reset(room)
                continue
            # 2026-09-26: a member whose client has gone SILENT past
            # --battle-drop-s in a running room dropped off the line (the
            # client streams to the game server all battle): it leaves the
            # room and pays the manual's line-drop penalty (charge_line_drop)
            if not room.over and room.started and a.battle_drop_s > 0:
                for m in [x for x in room.present() if x in room.arrived]:
                    ms = session_of(m)
                    if (ms is not None and ms.last_peer_rx[0]
                            and now - ms.last_peer_rx[0] > a.battle_drop_s):
                        print("  [battle] 0x%08x silent %.0f s in table %d's "
                              "running room -- LINE DROPPED (--battle-drop-s %g)"
                              % (m, now - ms.last_peer_rx[0], room.key,
                                 a.battle_drop_s), flush=True)
                        vacate_seat(m, "line dropped")
            if not room.over and room.started and not room.present():
                end_battle(room, now, "everyone left")
            if not room.over and a.respawn_kind:
                # 2026-09-23: RESPAWN. BattleRoom.dead_until was set by every
                # counted death and never read, so a KO'd player stayed down
                # to the end (live, Beginner's Course II). Retail notify kinds
                # 13/18/19 revive through 0x00be6850 (HP := value if HP == 0,
                # 0 -> max); 19 also clears the dead flags 0x2400 and resets the
                # battle object (vt+220). ident = the revived character, body+16
                # u32 HP (0 = full).
                # Seen live and in a savestate: 18/19 revived the HP but never
                # touched the state word entry+0x56 that kind 9 set to 1, and
                # the damage path 0x00beec10 skips a character in state 1 or 2
                # -> INVINCIBLE. Kind 13 pushes action code 13 (state := 0)
                # after the kind-25 dead bits. Sent to every member so the
                # others see the revive too (arm 0x00be6ec0 for non-self).
                for _rc in room.respawns_due(now):
                    push_revive(room, _rc)
                    print("  [battle] RESPAWN 0x%x: SENT notify kind %d to "
                          "%d member(s)" % (_rc, a.respawn_kind,
                                            len(room.present())), flush=True)

    def battle_deadlines():
        out = []
        for room in battles.values():
            for t in (room.end_at, room.reset_at, room.go_at):
                if t:
                    out.append(t)
            if room.gens is not None and not room.over:
                if room.gens.next_due() is not None:
                    out.append(room.gens.next_due())
            elif room.go_fired is not None and not room.over:
                out.append(room.go_fired + 1.0)
            if room.base_down and not room.over:
                # 2026-09-26: an occupation phase is judged on the room tick
                out.append(time.time() + 0.25)
            if room.cap_hold is not None and not room.over:
                # 2026-09-26 (doc_base_e2e caplast): a capsule hold ends on
                # its own deadline -- without this a quiet room slept past it
                # until the next packet or the table's clock
                out.append(room.cap_hold[1])
            out.extend(room.dead_until.values())
            if a.battle_drop_s > 0 and room.started and not room.over:
                for m in room.present():
                    ms = session_of(m) if m in room.arrived else None
                    if ms is not None and ms.last_peer_rx[0]:
                        out.append(ms.last_peer_rx[0] + a.battle_drop_s)
        return out

    #: 2026-09-26: the vacate reasons that are a LINE DROP (the player's
    #: connection went away mid-battle), which the manual charges like a
    #: return to the lobby. Not "kicked" / "new entrance" (a different
    #: sign-in at the address) and never a normal or server-side end.
    LINE_DROP_WHYS = ("session reaped", "line dropped")

    def charge_line_drop(room, cid, why):
        """SE's January Additional Manual: returning to the lobby/title
        mid-battle, OR not being able to go
        on because of the line, costs 10 ranking points. Lobby command 4 has
        charged the first since 09-24; this is the second. Only a member that
        ARRIVED in a room still running (not over), not already gone (a
        member in room.left paid at its command 4 -- no double charge), and
        not a solo mission (quitting one is a failed mission, uncharged, the
        command-4 path's rule). Must run BEFORE room.leave()."""
        if (_stats is None or a.leave_rp_penalty <= 0 or room is None
                or room.over or room.mission is not None
                or cid not in room.arrived or cid in room.left):
            return None
        ms = session_of(cid)
        key = (_wallet_key(ms.seen_uid[0], cid, ms) if ms is not None
               else _room_member_key.get(cid))
        if key is None:
            return None
        summ = _stats.record_leave(
            key, a.leave_rp_penalty, room.rules.mode,
            time.time() - (room.started or time.time()), rid=cid)
        print("  [stats] [%s] LINE DROP out of a running battle (%s): %d rank "
              "points (--leave-rp-penalty %d)"
              % (key, why, summ["rp"], a.leave_rp_penalty), flush=True)
        return summ

    def vacate_seat(cid, why):
        """A player is gone: its seat, and its place in a running room."""
        if not cid:
            return
        unqueue(cid, why)
        room = battle_of(cid)
        if room is not None and cid not in room.left:
            if why in LINE_DROP_WHYS:
                charge_line_drop(room, cid, why)
            _was_leader = room.is_team_leader(cid)
            _nl = room.leave(cid)
            print("  [battle] 0x%08x LEFT table %d's room (%s)" % (cid, room.key, why),
                  flush=True)
            if _was_leader:
                tag_leaders(room, [cid], False, "left the battle")
            tag_leaders(room, list(_nl.values()), True, "took over as leader")
            for m in room.present():
                ms, dst = member_dst(m)
                if dst is not None:
                    s.sendto(gamemsg.build_gs_notify(gamemsg.GS_PLAYER_LEFT_KIND, bytes(4),
                                             seq=next_gs_seq(ms), ident=cid), dst)
        key = bt_store.vacate(cid)
        if key is not None:
            print("  [battletable] seat of 0x%08x at table %d VACATED (%s)"
                  % (cid, key, why), flush=True)

    _p2p_seen = {}           # (session key, P2P type) -> count, for the log
    _start_seen = {}         # session key -> time of its last command 3

    def battle_capture(what, **fields):
        """--battle-capture: one JSON line (bytes as hex). Never raises -- a
        capture that cannot write must not take a battle down."""
        if not a.battle_capture:
            return
        import json
        rec = {"t": round(time.time(), 3), "what": what}
        for k, v in fields.items():
            rec[k] = v.hex() if isinstance(v, (bytes, bytearray)) else v
        try:
            with open(a.battle_capture, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except (OSError, TypeError, ValueError) as ex:
            print("  [capture] write FAILED: %s" % ex, flush=True)

    def capsule_field(room, sess=None):
        """2026-09-24: a TEAM CAPSULE room's field, placed once (N = the
        record's capsule count, on a ring around the arena spawn), or None."""
        n = fielditems.capsule_count(room)
        if n <= 0:
            return None
        if room.field is None:
            cid = room.members[0] if room.members else 0
            ms = session_of(cid)
            center = _battle_pos(ms.key if ms is not None else None, cid,
                                 per_team=False)
            # 2026-10-05: a mission's capsules go on SE's own capsule spots --
            # its situation's item generators that hold Mako Capsules (live:
            # the ring put one inside a box) -- nearest the start first; the
            # ring only when the situation has too few
            spots = []
            _cz = _battle_zone(ms.key if ms is not None else None, cid)
            if room.mission is not None:
                spots = doc_field.capsule_spots(_cz, room.rules.situation)
            else:
                # 2026-10-06 (live, Jungle TCP): a Team Capsule table used the
                # ring too (capsules in a circle, some in a wall). Its own
                # situation's capsule generators, else its 9xxx twin's
                # (Jungle 1100 has 10; most arenas carry theirs on 9100/9101)
                for _cs in (room.rules.situation,) + doc_field.pvp_twins(room.rules.situation):
                    spots = doc_field.capsule_spots(_cz, _cs)
                    if len(spots) >= n:
                        break
            if len(spots) >= n:
                pts = (arenadata.mission_spawn_order(spots, center, a.mission_spawn_near)[:n]
                       if room.mission is not None
                       # PvP: nearest one member's start would favour its team
                       else random.sample(spots, n))
                room.field = {i: (fielditems.MAKO_CAPSULE, tuple(p))
                              for i, p in enumerate(pts)}
                print("  [capsule] table %d: %d Mako Capsule(s) on situation %d's "
                      "capsule generators (%d spot(s))"
                      % (room.key, len(room.field), room.rules.situation, len(spots)),
                      flush=True)
            else:
                room.field = {i: (fielditems.MAKO_CAPSULE, pos) for i, pos in
                              enumerate(fielditems.capsule_ring(center, n))}
                print("  [capsule] table %d: %d Mako Capsule(s) placed on a %.0f-unit "
                      "ring around %s" % (room.key, len(room.field), fielditems.CAPSULE_RING,
                                          tuple(round(v, 1) for v in center)), flush=True)
        return room.field

    def field_tick(room, now):
        """2026-09-26: the arena's ITEM GENERATORS (doc_field). They start a
        second after the shared GO -- after each member's own GO has sent it
        the field (capsule_send_field) -- and a generator whose item is picked
        up rolls again --field-respawn-s later."""
        if (not a.field_items or room.over or room.started is None
                or (room.go_at is not None and room.go_fired is None)):
            return
        t0 = room.go_fired if room.go_fired is not None else room.started
        if now < t0 + 1.0:
            return
        field = battle_field(room)
        if room.gens is None:
            cid = next(iter(room.present()), 0)
            ms = session_of(cid)
            zone = _battle_zone(ms.key if ms is not None else None, cid)
            gens = doc_field.generators(zone, room.rules.situation)
            room.gens = doc_field.Generators(gens, now, a.field_respawn_s)
            print("  [field] table %d: zone %s situation %d -> %d item "
                  "generator(s), respawn %.0f s"
                  % (room.key, zone, room.rules.situation, len(gens),
                     a.field_respawn_s), flush=True)
        taken = set(field)

        def free_slot():
            i = next((k for k in range(fielditems.FIELD_SLOTS) if k not in taken), None)
            if i is not None:
                taken.add(i)
            return i
        placed = room.gens.tick(now, free_slot)
        for _gi, slot, iid, qty, pos in placed:
            field[slot] = (iid, pos, qty)
        if not placed:
            return
        for m in room.present():
            ms, dst = member_dst(m)
            if dst is None:
                continue
            for _gi, slot, iid, qty, pos in placed:
                s.sendto(gamemsg.build_gs_notify(10, fielditems.field_item_payload(
                    iid, slot, pos, qty, head=fielditems.FIELD_QUIET),
                    seq=next_gs_seq(ms), ident=m), dst)
        print("  [field] table %d: SENT notify kind 10 x%d to %d member(s): %s"
              % (room.key, len(placed), len(room.present()),
                 ", ".join("0x%08x x%d@%d" % (i, q, sl)
                           for _g, sl, i, q, _p in placed[:6])
                 + (" ..." if len(placed) > 6 else "")), flush=True)

    _drop_rng = (random.Random(a.drop_seed) if a.drop_seed >= 0
                 else random.Random())

    def enemy_drop(room, mn, nid, pos):
        """2026-09-24 (ported 10-05): roll a dead mission enemy's drop on the
        retail client's own table (doc_drops; the client's roll is off online)
        and lay it on the field at `pos`, the enemy's last reported s16
        position: notify kind 10 to every member present. Picking it up is the
        ordinary 119 -> kind 11 path."""
        if a.enemy_drops != "on" or room is None or room.over:
            return
        zone, typ = (mn or {}).get("zone"), (mn or {}).get("types", {}).get(nid)
        defs = doc_missions.CHARDEF.get(int(zone or 0), ())
        model = defs[typ][0] if typ is not None and 0 <= typ < len(defs) else None
        sit = room.rules.situation
        got = (doc_drops.roll(model, int(zone or 0), sit, rng=_drop_rng)
               if model else None)
        if got is None or pos is None:
            print("  [drops] enemy 0x%x (%s): %s" % (
                nid, model or "model unknown",
                "no position reported" if got and pos is None else "no drop"),
                flush=True)
            return
        iid, count = got
        field = battle_field(room)
        slot = next((k for k in range(fielditems.FIELD_SLOTS) if k not in field), None)
        if slot is None:
            print("  [drops] enemy 0x%x: field full, 0x%08x x%d lost"
                  % (nid, iid, count), flush=True)
            return
        field[slot] = (iid, tuple(pos), count)
        n = 0
        for m in room.present():
            ms, dst = member_dst(m)
            if dst is None:
                continue
            s.sendto(gamemsg.build_gs_notify(10, fielditems.field_item_payload(
                iid, slot, pos, count, head=fielditems.FIELD_QUIET),
                seq=next_gs_seq(ms), ident=m), dst)
            n += 1
        print("  [drops] enemy 0x%x (%s) dropped 0x%08x x%d at %s -> slot %d, "
              "kind 10 to %d member(s)" % (nid, model, iid, count, tuple(pos),
                                           slot, n), flush=True)

    def battle_field(room):
        """2026-09-26: every battle has a field -- the capsules when the table
        or mission has them, else an empty one for dropped items."""
        if room is None:
            return None
        if capsule_field(room) is None and room.field is None:
            room.field = {}
        if room.mission is not None and not room.quest_items:
            room.quest_items = True
            place_quest_items(room)
        return room.field

    def place_quest_items(room):
        """2026-09-26: a mission's QUEST items (doc_npcquests.mission_items:
        Collector's Mind's Fuzzy Seed) go on its field once, at SE's own
        generator node, before the GO sends the field."""
        if a.fuzzy_seed != "field":
            return
        cid = next(iter(room.members), 0)
        ms = session_of(cid)
        zone = _battle_zone(ms.key if ms is not None else None, cid)
        for iid, qty, pos in doc_npcquests.mission_items(
                room.mission, zone, room.rules.situation):
            slot = next((i for i in range(fielditems.FIELD_SLOTS)
                         if i not in room.field), None)
            if slot is None:
                break
            room.field[slot] = (iid, pos, qty)
            print("  [npcquest] table %d: quest %d in zone %s -> 0x%08x x%d "
                  "on the field, slot %d at %s (SE's generator node)"
                  % (room.key, room.mission, zone, iid, qty, slot,
                     tuple(round(v, 1) for v in pos)), flush=True)

    def capsule_send_field(room, sess):
        """Kind 10 for every item on the field, to `sess` (its GO)."""
        field = battle_field(room)
        if not field or sess.gs_join_src[0] is None:
            return
        for slot, (iid, pos, *_c) in sorted(field.items()):
            s.sendto(gamemsg.build_gs_notify(10, fielditems.field_item_payload(iid, slot, pos,
                                                            _c[0] if _c else 1),
                                     seq=next_gs_seq(sess),
                                     ident=sess.seen_charid[0]), sess.gs_join_src[0])
        print("  [capsule] SENT notify kind 10 x%d (the field) to 0x%08x"
              % (len(field), sess.seen_charid[0]), flush=True)

    def _mp_battle(room):
        """(ledger battle key, Magic restricted?) -- the key request 60 uses."""
        if room is None:
            return ("no room",), False
        return ((room.key, room.opened),
                doc_magic.magic_restricted(room.rules.flags,
                                           room.rules.restrictions))

    def push_mp(cid, mp, why):
        """Notify kind 44 {MP << 16} to `cid` (R+48 = the MP it casts from)."""
        ms, dst = member_dst(cid)
        if dst is None:
            print("  [magic] 0x%x: MP %d (%s) -- no channel to push kind 44 on"
                  % (cid, mp, why), flush=True)
            return False
        s.sendto(gamemsg.build_gs_mp_push(mp, seq=next_gs_seq(ms), ident=cid), dst)
        print("  [magic] 0x%x: MP -> %d (%s) -- SENT notify kind 44"
              % (cid, mp, why), flush=True)
        return True

    def mp_point(cid, body, via):
        """2026-09-26 (doc_items): a 117 -- `cid` stands at MP point N with MP
        below max. The client sends one per frame in range and changes nothing
        itself; credit the ledger (OURS: --mp-point-amount every
        --mp-point-every s per point) and push kind 44."""
        p = doc_items.parse_mp_point(body)
        room = battle_of(cid)
        _n = _mp_point_seen[cid] = _mp_point_seen.get(cid, 0) + 1
        loud = _n <= 3 or _n % 200 == 0
        if p is None or room is None or a.mp_points == "off":
            if loud:
                print("  [mp point] %s 117 from 0x%08x ignored: %s (#%d)"
                      % (via, cid, "short payload" if p is None else
                         "not in a battle" if room is None else "--mp-points off",
                         _n), flush=True)
            return
        _kind, point, _cnt = p
        if a.mp_model != "ledger":
            if loud:
                print("  [mp point] %s 117 from 0x%08x (point %d): --mp-model %s "
                      "keeps no MP to credit (#%d)" % (via, cid, point,
                                                        a.mp_model, _n), flush=True)
            return
        bkey, restricted = _mp_battle(room)
        amt = _mp_points.credit(cid, bkey, point, time.time())
        if not amt:
            if loud:
                print("  [mp point] %s 117 from 0x%08x (point %d, n %s): cooling "
                      "down (#%d)" % (via, cid, point, _cnt, _n), flush=True)
            return
        mp = _magic.credit(cid, bkey, amt, restricted)
        push_mp(cid, mp, "MP point %d +%d, %s" % (point, amt, via))

    def capsule_server(cid, ptype, body):
        """A reliable 119 pick-up / 118 drop addressed to the server."""
        if ptype == p2pbattle.P2P_MP_POINT:
            return mp_point(cid, body, "reliable")
        room = battle_of(cid)
        if battle_field(room) is None:
            print("  [capsule] reliable %s from 0x%08x ignored: not in a battle"
                  % (p2pbattle.P2P_NAMES.get(ptype), cid), flush=True)
            return
        if ptype == p2pbattle.P2P_PICKUP:
            slot = fielditems.p2p_pickup_slot(body)
            msgs, note = fielditems.capsule_pickup(room, cid, slot)
            if len(body) >= 24:
                note += " (n %d, picker at %s)" % (
                    struct.unpack_from("<I", body, 8)[0],
                    tuple(round(v, 1) for v in struct.unpack_from("<fff", body, 12)))
        else:
            d = fielditems.p2p_drop(body)
            msgs, note = (fielditems.capsule_drop(room, cid, *d) if d is not None
                          else ([], "ignored (short 118)"))
        _capsule_after(room, cid, msgs, "reliable " + note)

    def _capsule_send(room, actor, msgs):
        for kind, payload, ident, to in msgs:
            for m in room.present():
                if (to == "self" and m != actor) or (to == "others" and m == actor):
                    continue
                ms, dst = member_dst(m)
                if dst is not None:
                    s.sendto(gamemsg.build_gs_notify(kind, payload, seq=next_gs_seq(ms),
                                             ident=ident), dst)

    def capsule_p2p(sender, inner, ptype):
        """Arbitrate a 119 pick-up / 118 drop (never relayed)."""
        _t, _f, _sid, _tgt, _payload = p2pbattle.p2p_record(inner["plain"])
        cid = sender.seen_charid[0] or _sid
        if ptype == p2pbattle.P2P_MP_POINT:
            return mp_point(cid, _payload, "p2p")
        room = battle_of(cid)
        if battle_field(room) is None:
            print("  [capsule] %s from 0x%08x ignored: not in a battle"
                  % (p2pbattle.P2P_NAMES.get(ptype), cid), flush=True)
            return
        if ptype == p2pbattle.P2P_PICKUP:
            msgs, note = fielditems.capsule_pickup(room, cid, fielditems.p2p_pickup_slot(_payload))
        else:
            d = fielditems.p2p_drop(_payload)
            msgs, note = (fielditems.capsule_drop(room, cid, *d) if d is not None
                          else ([], "ignored (short 118)"))
        _capsule_after(room, cid, msgs, note)

    def _capsule_after(room, cid, msgs, note):
        _capsule_send(room, cid, msgs)
        print("  [capsule] 0x%08x (team %d) %s" % (cid, room.team_of(cid), note),
              flush=True)
        for kind, payload, ident, _to in msgs:
            if kind == 11 and room.gens is not None:
                _gi = room.gens.picked(struct.unpack_from("<H", payload, 10)[0],
                                       time.time())
                if _gi is not None:
                    print("  [field] table %d: generator %d emptied -- rolls "
                          "again in %.0f s" % (room.key, _gi,
                                               room.gens.respawn_s), flush=True)
            # 2026-09-26: keep the supplies ledger honest about field items
            if kind not in (10, 11):
                continue
            _fi, _fn = struct.unpack_from("<IH", payload, 4)
            if _fi == doc_stats.COIN_ITEM:
                # Chocobo Coins: +n for the picker (kind 11), -n for a
                # dropper (kind 10 from its own 118) -- paid at the end
                room.coins[ident] = max(0, room.coins.get(ident, 0)
                                        + (_fn if kind == 11 else -_fn))
                print("  [coins] table %d: 0x%08x holds %d Chocobo Coin(s)"
                      % (room.key, ident, room.coins[ident]), flush=True)
            if (_fi >> 16) == fielditems.CONSUMABLE_CLASS:
                _fp = room.field_picks.setdefault(ident, {})
                _fp[_fi] = _fp.get(_fi, 0) + (_fn if kind == 11 else -_fn)
            _fs = session_of(ident)
            if _fi in doc_npcquests.FIELD_QUEST_ITEMS:
                # a QUEST item (the Fuzzy Seed) is the SERVER bag's business:
                # Hiren checks that bag. kind 11 = picked up, 10 = dropped.
                _qk = (_wallet_key(_fs.seen_uid[0], ident, _fs)
                       if _fs is not None else _room_member_key.get(ident))
                if _qk:
                    print("  [npcquest] [%s] %s a quest item on the field: %s"
                          % (_qk, "PICKED UP" if kind == 11 else "DROPPED",
                             _bag_move(_qk, [(_fi, _fn if kind == 11
                                              else -_fn)])), flush=True)
            if (_fi in doc_missions.SUPPLY_ITEMS and _fs is not None
                    and _fs.key in _supply_bag):
                _held = _supply_bag[_fs.key]
                _held[_fi] = max(0, _held.get(_fi, 0)
                                 + (_fn if kind == 11 else -_fn))
        if fielditems.capsule_count(room) <= 0:
            return                  # a plain field: no capsule rules to run
        if msgs and room.mission is not None:
            # a mission has no team hold and no scoreboard (46 is the Team
            # Capsule HUD); the count alone wins it
            mnote = fielditems.capsule_mission_check(room)
            print("  [capsule] table %d: %s" % (room.key, mnote), flush=True)
            if room.over:
                end_battle(room, time.time())
        elif msgs:
            hmsgs, hnote = fielditems.capsule_hold(room, time.time())
            _capsule_send(room, cid, hmsgs)
            if hnote:
                print("  [capsule] table %d: %s" % (room.key, hnote), flush=True)

    _relay_seen = {}         # 2026-10-05: (sender key, type, ms, body) -> first seen

    def relay_dup(sender, plain, ptype, synth=False):
        """2026-10-05: True for a second copy of a peer packet. With every peer
        unit born holding our address (peer_addr), a console sends its stream
        ONCE PER UNIT -- all to us -- so N players mean N-1 identical copies
        per tick; relaying each to everyone would land damage N-1 times. A copy
        = same sender, type, sender clock (header +4) and body, inside
        --peer-relay-dedupe-s. The clock keeps a still player's identical
        poses flowing tick to tick (a unit with no accepted packet for 4 s
        shows the stale-link "!")."""
        if a.peer_relay_dedupe_s <= 0 or plain is None or len(plain) < framing.BODY_OFF:
            return False
        now = time.time()
        # 2026-10-05 (offline run of retail 0x005961a8): the copies share the
        # record's SEQUENCE (header +14) and body; only the sender clock at +4
        # is re-read PER COPY, so a copy that straddles a millisecond carried
        # a different +4 and slipped through. Key on the seq; a synthesised
        # header (unreadable mode 4, seq unknown) keys on the body and calls
        # clocks within 2 ms the same tick.
        _synth = synth or not any(plain[12:16])
        body = bytes(plain[framing.BODY_OFF:])
        ms = struct.unpack_from("<I", plain, 4)[0]
        k = ((sender.key, ptype, "ms", body) if _synth
             else (sender.key, ptype, "seq", bytes(plain[14:16]), body))
        t = _relay_seen.get(k)
        if t is not None and now - t[0] < a.peer_relay_dedupe_s and (
                not _synth or abs(ms - t[1]) <= 2):
            return True
        _relay_seen[k] = (now, ms)
        if len(_relay_seen) > 4096:
            for _k in [x for x, v in _relay_seen.items() if now - v[0] >= a.peer_relay_dedupe_s]:
                _relay_seen.pop(_k, None)
        return False

    _npc_relay_seen = {}     # (npc id, dst) -> count, for the log
    _npc_pose_at = {}        # npc id -> (x, y, z, t), its controller's last pose
    GS_KIND_EXTINCT = 22     # notify kind 22 {u32 id}: the client releases that NPC
    MISSION_EXTINCT_S = 4.5  # OURS: after the death animation, before the 5 s replacement
    MISSION_REPLACE_NEAR = 150.0  # OURS: a replacement's minimum distance (~15 m)
    SHOT_OWNER_NEAR = 60.0   # OURS: ~6 m (units ~10 cm) from shot origin to shooter

    def shot_owner(cid, data, room, fresh_s=2.0, near=SHOT_OWNER_NEAR):
        """2026-10-05 (static RE, retail; scratchpad re-udp2/): a shot whose
        mode-4 header we cannot read is stamped with the SENDER's id, but the
        room's NPC controller also fans out its NPCs' shots (0x00bee828 puts
        the NPC id at +16). Stamped as the controller's, an NPC's shot reads
        as a teammate's and the victim's team filter (0x00bcdfc8) cancels the
        damage. The shooter is whichever of the controller and its NPCs stood
        nearest the shot's origin (body+24), by their last poses; an NPC
        only when the origin is within `near` of it (a muzzle, not a guess)."""
        if room is None or room.mission is None:
            return cid
        shared = _room_mnpc.get(room.key)
        if shared is None or shared.get("room") is not room or shared.get("ctrl") != cid:
            return cid
        try:
            o = struct.unpack_from("<3f", data, framing.BODY_OFF + 24)
        except struct.error:
            return cid
        now = time.time()
        dead = shared.get("dead") or set()
        cands = [(cid, _battle_pose.get(cid))]
        cands += [(n, _npc_pose_at.get(n)) for n in shared.get("types", {})
                  if n not in dead]
        best = None
        for who, p in cands:
            if p is None or now - p[3] > fresh_s:
                continue
            d = ((p[0] - o[0]) ** 2 + (p[1] - o[1]) ** 2 + (p[2] - o[2]) ** 2) ** 0.5
            if best is None or d < best[0]:
                best = (d, who)
        if best is None or best[1] == cid or best[0] > near:
            return cid
        _k = ("npcshot", best[1])
        _npc_relay_seen[_k] = _npc_relay_seen.get(_k, 0) + 1
        if _npc_relay_seen[_k] in (1, 50) or _npc_relay_seen[_k] % 500 == 0:
            print("  [missions] unreadable shot from controller 0x%08x is NPC "
                  "0x%08x's (origin %.0f from it): %d so far"
                  % (cid, best[1], best[0], _npc_relay_seen[_k]), flush=True)
        return best[1]

    def relay_npc_pose(sender, data, inner, nid):
        """2026-10-05 (--mission-shared-npcs on): forward the room's enemy
        CONTROLLER's NPC pose (p2pbattle.npc_pose) to every OTHER present
        member, re-stamped like a relayed 0x83 (build_peer_relay: mode 0, flags
        8, checksum recomputed). On a non-controller the NPC exists from its
        kind 15 and is uncontrolled (+0x10 = 0, no kind 27 sent there), so the
        receive gate 0x00be7dd8 accepts it from us, and the pose handler
        0x00be33e8 drives it through the same store that moves relayed player
        avatars. NEVER echoed to the controller: its own NPC would accept the
        stale copy and stutter. Only the room set's controller's stream."""
        room = battle_of(sender.seen_charid[0])
        if room is None or room.mission is None:
            return 0
        shared = _room_mnpc.get(room.key)
        if shared is None or shared.get("room") is not room:
            return 0
        ctrl = shared.get("ctrl")
        if sender.seen_charid[0] != ctrl:
            return 0
        _syn = not (inner is not None and inner.get("plain") is not None)
        plain = (p2pbattle.synth_npc_inner(data, nid)["plain"] if _syn
                 else inner["plain"])
        if relay_dup(sender, plain, p2pbattle.NPC_POSE_TYPE, _syn):
            return 0
        _npc_pose_at[nid] = struct.unpack_from("<3f", plain, framing.BODY_OFF + 4) + (time.time(),)
        out = worldpose.build_peer_relay(plain)
        sent = 0
        for m in room.present():
            if not m or m == ctrl:
                continue
            ms = session_of(m)
            dst = (ms.gs_src[0] or ms.ka_src or ms.src) if ms is not None else None
            if dst is None:
                continue
            s.sendto(out, dst)
            sent += 1
            k = (nid, dst)
            _npc_relay_seen[k] = _npc_relay_seen.get(k, 0) + 1
            n = _npc_relay_seen[k]
            if n == 1 or n % 200 == 0:
                print("  [missions] NPC POSE 0x%08x (controller 0x%08x) -> 0x%08x "
                      "%s:%d: %d update(s)" % (nid, ctrl, m, dst[0], dst[1], n),
                      flush=True)
        return sent

    def relay_p2p_battle(sender, inner, ptype):
        """sec 4he: forward a shot / damage / entity datagram to the OTHER
        members of the sender's battle, re-stamped exactly like the 0x83 pose
        relay (mode 0, flags | 8, checksum recomputed, everything else
        verbatim -- the parser gate 0x00be20b0 wants the sender id at +16 to
        be a unit that exists and the source to be the game-server mirror,
        which we are). A 113 names its target at rec+8; everyone else drops
        it at 0x00be9860, so the whole room gets every packet and the
        receiver does the filtering the way it was built to."""
        plain = inner["plain"]
        if relay_dup(sender, plain, ptype, inner.get("synth", False)):
            return 0
        _t, _f, _sid, _tgt, _payload = p2pbattle.p2p_record(plain)
        _dent = []
        if ptype == p2pbattle.P2P_DAMAGE:
            # the real 113 layout (header sender / target, 16-byte entries)
            _sid, _tgt, _dent = p2pbattle.p2p_damage(plain)
        cid = sender.seen_charid[0] or _sid
        room = battle_of(cid)
        # 2026-10-05: a NON-controller's hit on a SHARED mission enemy. Its
        # console addresses the 113 to the NPC's controller id, which is 0
        # there (no kind 27), so every member dropped it (retail receiver
        # 0x00beeb38 takes -1 or its own id only) and the hit never landed.
        # Re-target it to the controller, the one console that applies it
        # (0x00beea50 -> 0x00beec10, a ring at unit+0x220 drops repeats).
        if (_dent and room is not None and room.mission is not None
                and a.mission_shared_npcs == "on"):
            _sh = _room_mnpc.get(room.key)
            _npc_hits = [e for e in _dent if (e[0] & 0xC0000000) == 0x40000000]
            if (_sh is not None and _sh.get("room") is room and _npc_hits
                    and cid != _sh.get("ctrl")):
                _ctl = _sh.get("ctrl")
                _pk = bytearray(plain)
                struct.pack_into("<I", _pk, 20, _ctl & 0xFFFFFFFF)
                _cs = session_of(_ctl)
                _cd = ((_cs.gs_src[0] or _cs.ka_src or _cs.src)
                       if _cs is not None else None)
                if _cd is not None:
                    s.sendto(worldpose.build_peer_relay(bytes(_pk)), _cd)
                _lh = _sh.setdefault("last_hit", {})
                for e in _npc_hits:
                    _lh[e[0]] = e[2] if e[2] in room.kills else cid
                k = (sender.key, "npc-hit")
                _p2p_seen[k] = _p2p_seen.get(k, 0) + 1
                if _p2p_seen[k] <= 3 or _p2p_seen[k] % 50 == 0:
                    print("  [missions] NPC HIT by 0x%08x: %s -> RE-TARGETED to the "
                          "controller 0x%08x%s (#%d)"
                          % (cid, ", ".join("0x%x:%+d shot %d" % (e[0], e[1], e[3])
                                            for e in _npc_hits[:3]),
                             _ctl, "" if _cd else " (no address yet)", _p2p_seen[k]),
                          flush=True)
                return 1 if _cd else 0
        peers = (room.members if room is not None
                 else [m for m in bt_store.members(bt_store.table_of(cid) or -1)
                       if m])
        out = worldpose.build_peer_relay(plain)
        sent = 0
        for m in peers:
            if not m or m == cid:
                continue
            ms = session_of(m)
            dst = (ms.gs_src[0] or ms.ka_src or ms.src) if ms is not None else None
            if dst is None:
                continue
            s.sendto(out, dst)
            sent += 1
        k = (sender.key, ptype)
        _p2p_seen[k] = _p2p_seen.get(k, 0) + 1
        n = _p2p_seen[k]
        if n <= 3 or n % 100 == 0:
            extra = ""
            if ptype == p2pbattle.P2P_DAMAGE:
                extra = " " + ", ".join(
                    "0x%x:%+d by 0x%x shot %d" % e for e in _dent[:4])
            print("  [p2p] %s (type %d, mode %d, %d B) from 0x%08x -> target %s "
                  "-> RELAYED to %d member(s) of %s (#%d)%s"
                  % (p2pbattle.P2P_NAMES.get(ptype, "?"), ptype, plain[1], len(plain),
                     _sid, "all" if _tgt == -1 else "0x%x" % (_tgt & 0xFFFFFFFF),
                     sent, ("battle table %d" % room.key) if room is not None
                     else "its table", n, extra), flush=True)
        if room is not None and ptype == p2pbattle.P2P_DAMAGE:
            room.saw_damage(cid, _dent, time.time())
        battle_capture("p2p", type=ptype, name=p2pbattle.P2P_NAMES.get(ptype, "?"),
                       flags=_f, sender=cid, target=_tgt,
                       table=room.key if room is not None else None,
                       payload=(bytes(plain[framing.BODY_OFF:])
                                if ptype == p2pbattle.P2P_DAMAGE else _payload))
        return sent

    def peer_addr(peer_id, dst_ip, self_id=0):
        """2026-10-05: {ip, port} for another player's 56-byte peer record
        (+16 IP, +28 port): OUR relay endpoint as the receiving console sees
        it. The console copies the record's address into the peer's UNIT at
        spawn and streams to it; a unit at 0.0.0.0 gets no stream, and the
        receive gate (retail 0x00be7dd8) gives a source address to ONE unit
        only -- every relayed packet comes from us, so the first peer to
        arrive took our address and every other peer was dropped ("bad
        packet"): at most two players ever saw each other, and the rest wore
        the 4-second staleness "!". Born with our address, every unit matches
        on the first compare. {} = leave +16/+28 zero (--peer-record-addr off,
        the receiver's own record, or no usable host)."""
        if a.peer_record_addr != "relay" or not peer_id or peer_id == self_id:
            return {}
        host = advertise.host_for(a.gs_connect_ip or a.lobby_ip, dst_ip)
        try:
            socket.inet_aton(host or "")
        except OSError:
            return {}
        return {"ip": host, "port": a.gs_connect_port}

    def battle_addr(dst_ip):
        """2026-10-05: (numeric IPv4, port) of OUR relay endpoint as the console
        at `dst_ip` sees it, for selector 38's roster entries and notify 31
        (+16 / +20) -- the address a BATTLE unit is created with. None with
        --peer-record-addr off or no usable host."""
        if a.peer_record_addr != "relay":
            return None
        host = advertise.host_for(a.gs_connect_ip or a.lobby_ip, dst_ip)
        try:
            import ipaddress
            return int(ipaddress.IPv4Address(host)), a.gs_connect_port
        except (ValueError, TypeError):
            return None

    relay_names = {}         # sec 4fu: relayed peer id -> name (cache misses)
    player_look = {}         # sec 4fu (look): charid -> o099 look code, the
                             # peer record's +36 -> slot+40 -> unit+88

    _gear_look = {}          # 2026-10-06: charid -> its gear-store costume (None = none)

    def _player_look(sess):
        """sec 4fu (look): the o099 costume code (doc_charastore.chr_code) of
        `sess`'s SELECTED character, or None without a store / a match."""
        if _store is None or not sess.seen_uid[0]:
            return None
        _cid = sess.seen_charid[0] & 0x3FFFFFFF
        if not _cid:
            return None
        # 2026-10-06 (live): a mask / armor change (lobby commands 17/18) is
        # stored by the gear store as the new costume; the roster keeps the
        # creation code, so everyone else kept seeing the old look. The gear
        # costume first (cached: this runs on every relayed pose).
        if _gearstore is not None:
            if _cid not in _gear_look:
                _grec = _gearstore.get(_wallet_key(sess.seen_uid[0], _cid, sess)) or {}
                _gear_look[_cid] = _grec.get("costume")
            if _gear_look[_cid] is not None:
                return _gear_look[_cid] & 0xFFFF
        # sec 4fx: through the member key (sec 4ft). The raw uid reads the
        # old uid-keyed backup roster, i.e. somebody else's (or no) look.
        _slots = _store.roster(_skey(sess.seen_uid[0], sess))
        for _si in range(doc_charastore.MAX_SLOTS):
            if _slots[_si] and sess.chara_ids.get(_si) == _cid:
                return doc_charastore.chr_code(_slots[_si]) & 0xFFFF
        return None
    relay_log = {}           # sec 4fu: (peer id, dst ip) -> [count, since]

    def relay_peer_pose(sender, inner, pose):
        """sec 4fu (2026-09-13): put `sender` in every OTHER in-world client's
        world and move it there, the way the client itself is built to.

        DoC's world was peer-to-peer with the server as a directory (sec 4bw),
        and the client ALREADY takes a peer's datagrams relayed by the game
        server (0x00be20b0 marks such a unit |= 0x01000000). Per receiver, all
        off the sender's own 0x83:
          1. a selector-37 peer record keyed by the sender's id (packet[16..19],
             its charid) -- the spawn resolves it in [kelsvc+284]. Sent ALONE
             the first time, so a type-125 cannot overtake it into a cache miss
             (which --peer-answer would fill with a nameless record);
          2. a type-125 naming that id -> 0x00bd2108 SPAWNS the remote unit (a
             flagged 0x83 for an unknown id is dropped in the parser, so this
             comes first). Its pose fields are the sender's own 40-byte pose
             record, and its time word is the SENDER's ms, so it never runs
             ahead of the relayed 0x83s (the FE lesson: map, never invent);
          3. 'raw': the 0x83 itself, build_peer_relay() -- flags|8, mode 0,
             verbatim otherwise -- consumed by the unit's own update on the
             sender's cadence. 'wu': one type-125 per 0x83 instead.
        Only clients whose OWN 0x83 stream is fresh receive anything: the world
        channel is shut everywhere else (sec 4bu/4df).
        """
        plain = inner.get("plain") if inner is not None else None
        rid = (inner.get("u32_16") if inner is not None else 0) or pose[0]
        # bits 30/31 must stay clear: bit 30 is the silent peer table, bit 31
        # breaks the sign-extended key compare (sec 4bw/4ch)
        if (plain is None or len(plain) < framing.BODY_OFF + 40 or not rid
                or rid & 0xC0000000):
            return
        if relay_dup(sender, plain, 0x83, inner.get("synth", False)):
            return
        now = datetime.datetime.now().timestamp()
        ms = struct.unpack_from("<I", plain, 4)[0]
        x, y, z, dx, dy, dz = pose[1:]
        b = framing.BODY_OFF
        h28, h30 = struct.unpack_from("<HH", plain, b + 28)
        # 2026-10-03 (live): after a restart the clients streamed on without
        # a world door, so `players` had no names and every peer record said
        # "Player_41050" -- the name the receiver keeps. The chara store
        # still knows the character; ask it before the placeholder.
        name = (players.get(sender.seen_charid[0], {}).get("name")
                or players.get(rid, {}).get("name") or relay_names.get(rid)
                or next((nm for _k, nm, _i in _rank_characters()
                         if nm and (_i & 0x3FFFFFFF) == rid), None))
        if name:
            relay_names[rid] = name
        else:
            name = "Player_%x" % rid
        sender.pos_id[0] = rid
        # KEY: sec 4fu (look, 2026-09-13): THE REMOTE AVATAR'S LOOK IS UNIT+88.
        # The unit update 0x00be4850 (vt+28's first call) does `lhu a0, 88(unit);
        # sh a0, 38(pose)` -- it OVERWRITES pose-record +38, where the sender
        # puts its own costume code (live 0x83s end `12 10` = 0x1012), with the
        # unit's +88. unit+88 is set once, at spawn, from the peer lookup's +26
        # = peer slot+40 = OUR peer record's wire+36. We sent 0 there: both
        # screens drew the default avatar (live 09-13). Serve the sender's
        # stored character look; its 0x83's own +38 is the fallback.
        look = _player_look(sender)
        if look is None:
            look = struct.unpack_from("<H", plain, b + 38)[0]
        player_look[rid] = look
        raw = worldpose.build_peer_relay(plain) if a.peer_relay == "raw" else None
        sub = a.world_subchannel if a.world_subchannel >= 0 else 7
        # 2026-10-03 (live): a lobby player's pose reached a client in the
        # arena and that client's arena pose reached the lobby, both ways
        # ghosts. Relay only within one battle room, or lobby to lobby.
        s_room = battle_of(sender.seen_charid[0] or rid)
        for other in list(sessions.values()):
            if other is sender or other.src is None:
                continue
            if battle_of(other.seen_charid[0]) is not s_room:
                continue
            if now - other.last_stream[0] > a.peer_relay_live_s:
                # 2026-10-05 (static RE + 9 battle starts, live 10-05): in a
                # BATTLE a console streams only once a relayed packet has
                # given one of its units an address (retail gate 0x00be7dd8),
                # so "relay only to the already streaming" deadlocked a member
                # that missed the race: Kanon sent GS traffic all mission and
                # got ZERO relays. A battle-room member still talking to us
                # (any datagram in 15 s) gets the relay; the lobby keeps the
                # old rule (its world channel is shut when not streaming).
                if not (s_room is not None and other.last_peer_rx[0]
                        and now - other.last_peer_rx[0] <= 15.0):
                    continue
            dst = other.src
            first = rid not in other.relay_pushed
            if first or now - other.relay_pushed[rid] >= a.peer_relay_push_s:
                other.relay_pushed[rid] = now
                s.sendto(peerrecords.build_peer_answer(
                    None, rid, seq=a.lobby_seq, subchannel=sub,
                    ptype=a.world_type, ident=other.seen_charid[0],
                    blob=peerrecords.build_peer_record(rid, name=name, zone=a.user_zone,
                                           rank=rank_of_cid(rid),
                                           flags=peer_flags(rid),
                                           f36=look,
                                           **peer_addr(rid, dst[0],
                                                       other.seen_charid[0]))[4:]), dst)
                print("  [peer-relay] PEER record 0x%08x (%s, look 0x%04x) -> "
                      "%s:%d%s"
                      % (rid, name, look, dst[0], dst[1],
                         " -- first sight; the spawn follows on the next 0x83"
                         if first else ""), flush=True)
                if first:
                    continue
            if raw is None or (now - other.relay_wu.get(rid, 0.0)
                               >= a.peer_relay_spawn_ms / 1000.0):
                if rid not in other.relay_wu:
                    print("  [peer-relay] SPAWN 0x%08x at (%.1f, %.1f, %.1f) -> "
                          "%s:%d (type 125, sender ms %d)"
                          % (rid, x, y, z, dst[0], dst[1], ms), flush=True)
                other.relay_wu[rid] = now
                s.sendto(worldpose.build_world_update([dict(
                    id=rid, x=x, y=y, z=z, dx=dx, dy=dy, dz=dz,
                    h6=h28, h20=h30, b4=plain[b + 32], b5=plain[b + 35],
                    h22=ms & 0xFFFF)], seq=a.lobby_seq, ms=ms), dst)
            if raw is not None:
                s.sendto(raw, dst)
            st = relay_log.setdefault((rid, dst[0]), [0, now])
            st[0] += 1
            if now - st[1] >= 10.0:
                print("  [peer-relay] 0x%08x -> %s: %d position update(s) in "
                      "%.0f s (%s)" % (rid, dst[0], st[0], now - st[1],
                                       a.peer_relay), flush=True)
                st[0], st[1] = 0, now
    if a.lobby_keepalive_ms > 0:
        print("[docudp] lobby keepalive: selector-%d every %d ms once a 96-byte "
              "template has been seen" % (a.lobby_sustain_selector or a.lobby_selector,
                                          a.lobby_keepalive_ms), flush=True)
    _ack_selectors = set()
    for _t in (a.reliable_ack_selectors or "").replace(",", " ").split():
        _ack_selectors.add(int(_t, 0))
    _pending_ack_after = {int(x) for x in a.pending_ack_after.split(",")
                          if x.strip()}

    # --lobby-map-mask -> the module global every selector-13 answer reads.
    # Parsed loudly at startup for the same reason --lobby-spawn is: an empty
    # mask and a mask that failed to parse look identical on screen (an empty
    # map picker), and that is the bug we are fixing.
    arenamaps.LOBBY_MAP_MASK = arenamaps.parse_map_mask(a.lobby_map_mask)
    arenamaps.LOBBY_ZONE = a.lobby_zone
    print("[docudp] LOBBY ZONE %d at world-door body[42..43] (sec 4hg addendum 4)"
          % arenamaps.LOBBY_ZONE, flush=True)
    if arenamaps.LOBBY_MAP_MASK:
        _names = arenamaps.describe_map_mask(arenamaps.LOBBY_MAP_MASK)
        print("[map] selector %d will carry map mask 0x%016x at body[%d..%d] "
              "-- %d map(s) in the battletable picker"
              % (arenamaps.WORLD_SPAWN_SELECTOR_ANS, arenamaps.LOBBY_MAP_MASK, arenamaps.LOBBY_MAP_MASK_OFF,
                 arenamaps.LOBBY_MAP_MASK_OFF + 7, len(_names)), flush=True)
        print("[map]   %s" % ", ".join(_names), flush=True)
    else:
        print("[map] --lobby-map-mask none: body[%d..%d] stays zero, so the "
              "battletable Map row builds an EMPTY list (the pre-fix "
              "behaviour, sec 4gv)" % (arenamaps.LOBBY_MAP_MASK_OFF,
                                       arenamaps.LOBBY_MAP_MASK_OFF + 7), flush=True)

    # --lobby-spawn -> (x, y, z, dirx, diry, dirz, index) or None. Parsed once,
    # loudly, at startup: a spawn that silently fails to parse is indistinguishable
    # from the zeros we are trying to stop sending.
    _spawn = None
    if a.lobby_spawn.strip():
        if a.lobby_spawn.strip().lower() in arenamaps.SPAWN_PRESETS:
            _spawn = arenamaps.SPAWN_PRESETS[a.lobby_spawn.strip().lower()]
        else:
            _f = [x for x in a.lobby_spawn.replace(",", " ").split() if x]
            if len(_f) not in (3, 6, 7):
                raise SystemExit("--lobby-spawn wants 3, 6 or 7 numbers (or one of %s), "
                                 "got %d: %r" % (sorted(arenamaps.SPAWN_PRESETS), len(_f),
                                                 a.lobby_spawn))
            _v = [float(x) for x in _f[:6]] + [0.0] * (6 - min(len(_f), 6))
            _spawn = tuple(_v[:6]) + (int(float(_f[6])) if len(_f) == 7 else 0,)
        print("[spawn] selector %d will carry world position (%.3f, %.3f, %.3f) "
              "facing (%.3f, %.3f, %.3f) index %d"
              % ((arenamaps.WORLD_SPAWN_SELECTOR_ANS,) + _spawn), flush=True)
        print("[spawn]   body[28..51] floats, body[52..53] index; descriptor Y is "
              "%.3f (+%.1f, the getter subtracts it back). Zeros here were the "
              "p(0,0,0) spawn -- sec 4dh."
              % (_spawn[1] + arenamaps.SPAWN_Y_BIAS, arenamaps.SPAWN_Y_BIAS), flush=True)
    # sec 4dw: one endpoint, used by both writers of the game-server sockaddr --
    # --gs-connect's selector 104 and the phase-44 selector-21 answer.
    _gs_endpoint = a.world_gs_ip or a.gs_connect_ip or a.lobby_ip
    _gs_ready_after = {int(x, 0) for x in
                       a.gs_ready_after.replace(" ", "").split(",") if x}
    # sec 4fq: --peer is now an allowlist (comma-separated IPs); empty = any.
    peer_allow = {x.strip() for x in (a.peer or "").replace(",", " ").split()
                  if x.strip()}
    short_ladder = {int(x, 0) for x in a.short_ladder.replace(" ", "").split(",")
                    if x}   # sec 4dv: 36-byte rungs we are allowed to answer
    # 2026-09-13: the two table verbs whose request carries NOTHING are 36-byte
    # datagrams too -- DISSOLVE 125 (phase 50) and CANCEL 155 (phase 46). With
    # only `--short-ladder=22` they fell to "log-only" before battletable_verb:
    # a live server on 09-13 had 0 dissolves / 0 cancels ever handled, and Lex's disband left
    # table 1 in the store (the Deck kept listing it). They name no key; the verb
    # resolves the requester's own table from its charid.
    if a.battletable_verbs:
        short_ladder |= {tableverbs.BT_REQ_DISSOLVE, tableverbs.BT_REQ_CANCEL}
    # 2026-09-13: selector 159 (phase 123, vt+1412 0x00bd8050, parks state 51)
    # is the SOLO BATTLE list -- solo = story mode, and 160's arm 0x00bcd74c ->
    # 0x00bcaba8 reads a QUEST-ID list ("Quest id %d"): rec+15 count, rec+16
    # u16[count]. It is a 36-byte request too, so it fell to "log-only" and the
    # player got CER-47117 on opening Solo. The generic zero-body 160 = count
    # 0 (an empty list), state 2, bit 31 clear -- the doc_bt_verbs_proof ladder
    # sweep. Real quest ids are not decoded yet; do not guess them in.
    short_ladder.add(questlist.QUEST_LIST_REQ)
    _solo_quests = questlist.parse_id_ranges(a.solo_quests)
    # 2026-09-23: MISSION MODE per player (tools/doc_missions.py). The career
    # store (--stats) holds each character's rank / rank points / battles and
    # the exams an instructor has "added to Missions"; 159 -> 160 lists them
    # and the instructors' command 26 answers come from that state.
    _ledger = a.mission_ledger == "on" and _stats is not None
    _magic = doc_magic.Ledger()   # 2026-09-24: per-character MP (--mp-model ledger)
    # 2026-09-26 (doc_items): MP points (117) and item use (21 -> 22)
    _mp_points = doc_items.MpPoints(a.mp_point_amount, a.mp_point_every)
    _mp_point_seen = {}   # charid -> 117 count (log throttle)
    _item_uses = doc_items.UseLedger()
    _spawn_of = {}        # charid -> ((x, y, z), bmap) of its kind-2 spawn
    _spawn_zone = {}      # 2026-10-06: charid -> the arena zone of that spawn
    _battle_pose = {}     # 2026-09-26: charid -> (x, y, z, t), its last 0x83
    if a.mission_ledger == "on" and _stats is None:
        print("[missions] LEDGER OFF: --mission-ledger=on needs --stats (no "
              "career store) -- static --solo-quests list, instructors greet",
              flush=True)
    elif _ledger:
        print("[missions] LEDGER ON: instructors %s grant the rank exams %s from "
              "the career (3 battles, then %s rank points); 159 -> 160 = the "
              "player's open exams + %d always-available mission(s) %s"
              % (sorted(doc_missions.INSTRUCTORS),
                 [q for q, _, _ in doc_missions.EXAMS.values()],
                 "/".join(str(n) for _, n, _ in list(doc_missions.EXAMS.values())[1:]),
                 len([q for q in _solo_quests if q not in doc_missions.EXAM_QUESTS]),
                 [q for q in _solo_quests if q not in doc_missions.EXAM_QUESTS]),
              flush=True)
    _list148 = questlist.parse_list148_spec(a.list_148)
    if _list148:
        print("[147-list] PROBE ON (sec 4gt add.1): selector %d -> %d, %d entr(ies) "
              "%s -- the generic answer is a ZERO-length list, which is what "
              "draws the blank unselectable rows. Values are NOT decoded; this "
              "only asks whether a non-zero count puts rows on screen."
              % (questlist.LIST148_REQ, questlist.LIST148_ANS, len(_list148),
                 ",".join("%d:%d:%d" % e for e in _list148)), flush=True)
    # session key (sec 4gz: (ip, port)) -> (quest id, time) from its last
    # command 41; consumed by the next Start. Main-scope on purpose: Session
    # has __slots__. NB keyed by the ADDRESS until 09-21, which two consoles in
    # one house share.
    _quest_pick = {}
    # session key (sec 4gz) -> quest id while its current battle is a MISSION
    # (set by a mission 38, dropped by any other 38): no fake teammates, solo
    # seating.
    _mission_battle = {}
    # 2026-09-24: doc_missions.MISSION_SETUP gives every set-up mission its
    # arena; --quest-zones pairs still override it.
    _quest_zone = dict(doc_missions.ARCHIVE_ZONES)
    _quest_zone.update({q: r[0] for q, r in doc_missions.MISSION_SETUP.items()})
    _quest_zone.update({int(q, 0): int(v, 0) for q, _, v in
                        (p.partition(":") for p in
                         a.quest_zones.replace(" ", "").split(",") if p)})

    _map_zone = arenamaps.parse_map_zones(a.battle_map_zones)
    # the inverse, for the command-41 answer's map label. First index wins, so
    # a hand-written table that points two maps at one zone stays single-valued.
    _zone_map = {}
    for _mi, _mz in sorted(_map_zone.items()):
        _zone_map.setdefault(_mz, _mi)

    def _map_name(m):
        return arenamaps.LOBBY_MAP_NAMES[m] if 0 <= m < len(arenamaps.LOBBY_MAP_NAMES) else "?"

    def _table_arena(cid):
        """sec 4hb: (arena zone, note) for the MAP the client's own battletable
        record holds, or (None, note) when it has no table, no decoded zone for
        that map, or no spawn in that zone.  `note` is None when there is simply
        nothing to say (no table at all); otherwise it is the log line."""
        if not a.battle_map_zone or not cid:
            return None, None
        k = bt_store.table_of(cid)
        if k is None:
            return None, None
        rec = bt_store.record(k)
        if not rec or len(rec) <= tablerecords.BT_OFF_MAP:
            return None, None
        m = rec[tablerecords.BT_OFF_MAP]
        z, why = arenamaps.battle_map_arena(m, _map_zone, a.gs_battle_zone,
                                  zone_spawns=_zone_spawn,
                                  needs_spawn=a.battle_map_needs_spawn)
        if why == arenamaps.ARENA_NO_ZONE:
            return None, ("table %d picked map %d (%s), which has NO decoded "
                          "arena zone -- staying in zone %d. sec 4hb: 8 of the "
                          "28 roster labels match no arena in zonelist.txt, and "
                          "a guess lands in someone else's map or a stub"
                          % (k, m, _map_name(m), a.gs_battle_zone))
        if why == arenamaps.ARENA_NO_SPAWN:
            return None, ("table %d picked map %d (%s) = arena zone %d, but no "
                          "--zone-spawns point exists for z%d -- staying in "
                          "zone %d rather than spawning in the VOID (sec 4gr). "
                          "pass --battle-map-needs-spawn to keep this guard"
                          % (k, m, _map_name(m), _map_zone[m], _map_zone[m],
                             a.gs_battle_zone))
        return z, ("table %d map %d (%s) -> ARENA ZONE %d (sec 4hb)"
                   % (k, m, _map_name(m), z))

    def _battle_zone_note(key, cid=None):
        """(zone, note) -- the whole precedence in one place, so the log line
        and the byte on the wire can never disagree."""
        q = _mission_battle.get(key) if key else None
        if q is None and cid:
            # Accept Mission -> a mission TABLE never sends
            # command 41, so _mission_battle stayed empty and Collector's Mind
            # (quest 16, Church) opened in the table map's Jungle. The table
            # record itself names the quest (flags 0x10000, wire+26).
            q = _record_quest(cid)
        if q is not None:
            _qz = _quest_zone.get(q, a.gs_battle_zone)
            return _qz, ("quest %d is a MISSION -> arena zone %d "
                         "(--quest-zones; the table's map does not apply)"
                         % (q, _qz))
        z, note = _table_arena(cid)
        return (a.gs_battle_zone if z is None else z), note

    def _battle_zone(key, cid=None):
        """Kind 2's arena zone for the client keyed `key` (sec 4gz: its
        (ip, port), not its address -- a household NAT shares the address):
        its quest's zone while its battle is a mission (--quest-zones), else
        the zone its BATTLETABLE'S CHOSEN MAP is played in (sec 4hb, needs
        `cid`), else --gs-battle-zone."""
        return _battle_zone_note(key, cid)[0]

    def _battle_result(sess, room=None):
        """2026-09-13: (kind-4 RESULT record, log note) for this client, and
        the career tally it reports (doc_stats.py).

        The server has NO combat data yet: the client's 1 Hz report (message
        24) needs a kind 3 we never send, and request 44 is item-use counts. So
        a PvP battle is judged a DRAW, and a mission that ran to our timer is a
        FAILURE -- its own defeat text is "Exceed Time Limit". Kind 4 carries
        NEW TOTALS for rank points (+8) and gil (+16); the zero record we used
        to send set both to 0 on screen."""
        cid = sess.seen_charid[0]
        # 2026-09-26: THIS client's account. Without `sess` the key came from
        # current[0] -- whoever sent the last packet -- and end_battle runs off
        # the room clock or another member's request 30, so with --pol-members
        # every other member missed its tally row and got the all-zero record:
        # a LOSS, 0 rank points, 0 gil on screen (live tables 30-32, 09-26).
        key = _wallet_key(sess.seen_uid[0], cid, sess)
        quest = _mission_battle.get(sess.key)
        if room is not None:
            # sec 4he: the ROOM's tally, computed ONCE for every member
            # (kills / KOs / team / winner from the kind-9 ledger) and read
            # back per member here.
            if room.tally is None:
                rows = []
                for m in room.members:
                    ms = session_of(m)
                    # a member whose session is gone keeps the key it had at
                    # its 47 -- the fallback would file its battle under
                    # current[0]'s account (2026-09-26)
                    mk = (_wallet_key(ms.seen_uid[0], m, ms) if ms is not None
                          else _room_member_key.get(m)
                          or _wallet_key(0, m, None))
                    rows.append({"key": mk, "id": m,
                                 "name": next((n for k, n, _i in
                                               _rank_characters() if k == mk),
                                              None),
                                 "team": (room.team_of(m) if room.rules.mode
                                          != "BT" else m),
                                 "kills": room.kills.get(m, 0),
                                 "kos": room.deaths.get(m, 0),
                                 "first_kill": m == room.first_killer,
                                 "finisher": m == room.finisher,
                                 # 2026-09-26: Assault "captures his enemy's
                                 # base and brings his team victory" = the
                                 # OCCUPIER, not the destroyer
                                 "base_capture": m == room.occupier,
                                 # 2026-09-26: the launch medals' inputs
                                 # (doc_stats.MODE_MEDALS): standing at the
                                 # end (Survivor), capsule carriers KO'd
                                 # (Capsule Seeker), the winning hold's last
                                 # capsule, enemy leaders KO'd (Leader Slayer)
                                 "survived": (m not in room.left
                                              and not room.eliminated(m)),
                                 "carrier_kos": room.carrier_kos.get(m, 0),
                                 "last_capsule": m == room.last_capsule,
                                 "leader_kills": room.leader_kills.get(m, 0),
                                 "left": m in room.left,
                                 "coins": (room.coins.get(m, 0)
                                           if a.chocobo_coins == "on" else 0),
                                 **(result_inputs(room, m)
                                    if room.mission is None else {})})
                if a.leave_rp_penalty > 0:
                    # 2026-09-24: a player who left partway already paid the
                    # --leave-rp-penalty; the end tally must not score them too
                    rows = [r for r in rows if r["id"] not in room.left]
                if room.mission is not None:
                    mode = "MISSION"
                    winner = 0 if room.outcome(room.members[0]) == "w" else None
                    for r in rows:
                        r["team"] = 0
                else:
                    mode = room.rules.mode if room.rules.mode in ("BT", "TBT", "FA") \
                        else "TBT"
                    w = room.winner_slot()
                    if w is None:
                        winner = None
                    elif mode == "BT":
                        winner = next((m for m in room.members
                                       if room.slot_of(m) == w), None)
                    else:
                        winner = room.winner_team()
                # variant: the table's own mode -- the tally files TDM / TBS /
                # TCP / ... under TBT, but Star of Victory is "TBT mode" only
                room.tally = _stats.record_battle(
                    mode, rows, winner, room.elapsed(time.time()),
                    quest=room.mission, variant=room.rules.mode)
                room.tally_keys = {r["id"]: r["key"] for r in rows}
                # 2026-09-24: a UNIT battle also settles the two units --
                # each gets its members' rank points and a W/D/L (doc_unit)
                if (_units is not None and room.mission is None
                        and room.rules.flags & tablerecords.BT_FLAG_UNIT):
                    _usides = {}
                    for r in rows:
                        _u = _units.enlisted(r["key"])
                        _t = room.tally.get(r["key"])
                        if not _u or _t is None:
                            continue
                        _o, _p = _usides.get(_u, (_t["outcome"], 0))
                        _usides[_u] = (_o, _p + int(_t.get("rp", 0)))
                    _ures = _units.record_battle(
                        [(u, o, p) for u, (o, p) in _usides.items()])
                    print("  [units] UNIT BATTLE table %d settled: %s" % (
                        room.key, ", ".join("%s %s +%d pts (now %d)" % (
                            h, o.upper(), p, tot)
                            for h, (o, p, tot) in _ures.items()) or "no units"),
                        flush=True)
            summ = room.tally.get(key)
            mode = room.rules.mode
            if summ is None:
                raise KeyError("0x%x has no row in table %d's tally" % (cid, room.key))
        else:
            if quest is not None:
                mode, winner = "MISSION", 1          # the player is team 0
            else:
                mode = "TBT" if len(set(sess.gs_teams.values())) >= 2 else "BT"
                winner = None
            name = next((n for k, n, _i in _rank_characters() if k == key), None)
            summ = _stats.record_battle(
                mode, [{"key": key, "name": name, "id": cid,
                        "team": 0 if quest is not None
                        else sess.gs_teams.get(cid, 0)}],
                winner, a.gs_battle_length, quest=quest)[key]
        c = _stats.career(key)
        # 2026-09-23 (sec 4hc): SE's rule -- the novice mark comes off at 20
        # kills. The ceremony plays on lobby re-entry because vl_main saved
        # "novice at departure" in event flag 5 (quest_scr003.ev(9998)).
        if (_novice is not None and a.novice == "on"
                and _novice.graduate_by_kills(key)):
            broadcast_graduate(cid, "%d career kills" % c.get("kills", 0))
        gil = 0
        if _shop is not None:
            w = _shop.wallet(key)
            if summ["gil"]:
                w["gil"] = min(w["gil"] + summ["gil"], doc_shop.GIL_MAX)
                _shop.save()
            gil = w["gil"]
            # 2026-09-26: the Soldier Mask is EARNED by clearing the DG Drone
            # 2nd exam (doc_gear.settle_soldier_mask: into the bag at the
            # next world door, once there is room)
            if (summ.get("quest") == doc_gear.SOLDIER_MASK_EXAM
                    and summ.get("outcome") == "w"
                    and doc_gear.owe_soldier_mask(w)):
                _shop.save()
                print("  [gear] [%s] cleared the Drone 2nd exam: Soldier Mask "
                      "OWED (in the bag from the next world door)" % key,
                      flush=True)
            # 2026-09-24: Collector's Mind is where the Fuzzy Seeds come from
            # (Lifestream fan archive) -- Hiren grows them (doc_npcquests)
            if (a.fuzzy_seed == "clear"
                    and summ.get("quest") == doc_npcquests.COLLECTORS_MIND
                    and summ.get("outcome") == "w"):
                print("  [npcquest] [%s] cleared Collector's Mind: %s"
                      % (key, _bag_move(key, [(doc_npcquests.FUZZY_SEED,
                                               doc_npcquests.SEEDS_PER_CLEAR)])),
                      flush=True)
        if _rank is not None:
            _stats.push_rankings(_rank)
        # 2026-09-24: the Results board -- every player's kills / KOs / rank
        # points and who won each medal, in THIS client's roster order
        holders, columns = None, None
        if room is not None:
            holders, columns = doc_stats.result_board(
                cid, room.members,
                {m: room.tally.get(k) for m, k in room.tally_keys.items()})
        # 2026-10-01: what the retail Results screen computes its rank-point
        # breakdown from (doc_stats.results_rp): the counts, the battle
        # type, the mode block and the player count
        _rtype, _rwin = 0, None
        _is_mission = summ.get("mode") == "MISSION" or (room is not None
                                                        and room.mission is not None)
        # 2026-10-04 (live): the Reward page (+28 bit 5) carries "Promotion
        # Granted" (55:46) beside Reward / Item Obtained / Rank; we asked for it
        # on EVERY mission and always set +44 RANK, so a quit showed a reward
        # page and a promotion that never happened (the server kept the exam
        # open). Only a CLEARED mission gets the page, and +44 is only set when
        # this battle raised the rank (0 = "leave R+763 alone", the arm writes
        # 1..254 only).
        _res_rank = c["rank"]
        if _is_mission:
            if summ.get("outcome") == "w":
                _rtype = doc_stats.RES_TYPE_REWARD
            if not summ.get("promoted"):
                _res_rank = 0
        elif room is not None:
            if not room.individual():
                _rtype |= doc_stats.RES_TYPE_TEAM
                _rwin = room.winner_team()
            _why = room.why or ""
            if _why.startswith("kill target"):
                _rtype |= doc_stats.RES_TYPE_KILLS
            elif "capsule" in _why:
                _rtype |= doc_stats.RES_TYPE_CAPSULES
            elif "base destroyed" in _why:
                _rtype |= doc_stats.RES_TYPE_BASE
        rec = doc_stats.result_record(summ["outcome"], c["rp"], gil,
                                      doc_stats.medal_mask(c), _res_rank,
                                      score=summ["rp"], holders=holders,
                                      columns=columns,
                                      counts=(summ.get("kills", 0),
                                              summ.get("kos", 0),
                                              summ.get("team_kos", 0),
                                              summ.get("streak", 0)),
                                      rtype=_rtype, winner=_rwin,
                                      mode=summ.get("mode_idx"),
                                      block=summ.get("block"),
                                      players=summ.get("players", 0))
        return rec, ("RESULT [%s] %s %s%s: +%d rank points, +%d gil, medals %s -> %s"
                     % (key, mode, {"w": "WIN", "l": "LOSS", "d": "DRAW"}.get(
                         summ["outcome"], summ["outcome"]),
                        (" (%d kills / %d KOs)" % (summ.get("kills", 0),
                                                   summ.get("kos", 0)))
                        if room is not None else "", summ["rp"],
                        summ["gil"], [doc_stats.MEDALS[m] for m in summ["medals"]]
                        or "none", _stats.summary_line(key)))

    _zone_spawn = {}
    for _zs in (a.zone_spawns or "").replace(" ", "").split(";"):
        if _zs:
            _zk, _, _zv = _zs.partition(":")
            _zone_spawn[int(_zk, 0)] = tuple(float(x) for x in
                                              _zv.split(","))[:3]

    def _spawn_team(key, cid):
        """2026-09-24: `cid`'s team when its battle is a TEAM battle (not a
        mission, not individual), else None."""
        if not cid:
            return None
        room = battle_of(cid)
        if room is not None:
            if room.mission is not None or room.individual():
                return None
            return room.team_of(cid)
        tk = bt_store.table_of(cid)
        rec = bt_store.record(tk) if tk is not None else None
        if not rec or len(rec) <= tablerecords.BT_OFF_MODE:
            return None
        if struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0] & tablerecords.BT_FLAG_MISSION:
            return None
        if tablerecords.BT_MODE_NAMES.get(rec[tablerecords.BT_OFF_MODE], "TBT") == "BT":
            return None
        ms = session_of(cid)
        return ms.gs_teams.get(cid, 0) if ms is not None else 0

    def _battle_pos(key, cid=None, per_team=True):
        """Kind 2's spawn for the client keyed `key` (sec 4gz): its arena
        zone's entry in --zone-spawns, else --gs-battle-pos.  Takes `cid` for
        the same reason _battle_zone does -- a table's map moves the zone, and
        the spawn has to move with it (sec 4gr.6: a z201 point is the VOID in
        z208). 2026-09-24: in a team battle, the player's TEAM start point
        (team_start) when the arena has one; per_team=False = the zone's."""
        z = _battle_zone(key, cid)
        if per_team:
            tm = _spawn_team(key, cid)
            # 2026-10-05: one of the situation's own start nodes per seat
            _sit = _record_situation(cid)
            _seat, _nseat = _seat_of(cid, team=tm)
            ts = (arenadata.team_start(z, tm, _sit, _seat)
                  if tm is not None else None)
            if ts is not None:
                if _nseat > arenadata.team_start_count(z, tm, _sit):
                    ts = _seat_spread(ts, cid, team=tm)
                print("  [arena] 0x%08x spawns at team %d's start %s (zone %d, "
                      "situation %s, seat %d)" % (cid, tm, tuple(round(v, 1) for v in ts),
                                                  z, _sit, _seat), flush=True)
                return ts
            if cid and _is_bt_pvp(cid):
                _bp = arenadata.bt_start(z, _sit, _seat)
                if _bp is not None:
                    print("  [arena] 0x%08x spawns at individual start %s (zone %d, "
                          "situation %s, seat %d)" % (cid, tuple(round(v, 1) for v in _bp),
                                                      z, _sit, _seat), flush=True)
                    return _bp
        if z in _zone_spawn:
            p = _zone_spawn[z]
        else:
            try:
                p = tuple(float(x) for x in a.gs_battle_pos.split(","))[:3]
            except ValueError:
                p = (0.0, 0.0, 0.0)
        # 2026-10-04: a mission whose controller has its own player node may
        # start the player there, among its enemies, instead of at the generic
        # zone spawn (which can sit far from the fight -- Dual Horn Duel, live).
        if a.mission_player_spawn == "on" and cid:
            _mq = _record_quest(cid)
            _mctl_ps = _quest_sit.get(_mq, 0) if _mq else 0
            if _mctl_ps:
                _mp = arenadata.mission_player_spawn(z, _mctl_ps, p,
                                                     radius=a.mission_player_radius,
                                                     seat=_seat_of(cid)[0])
                if tuple(round(v, 1) for v in _mp) != tuple(round(v, 1) for v in p):
                    print("  [missions] quest %s controller %d: player starts at "
                          "its own node %s, not the generic z%d spawn %s "
                          "(--mission-player-spawn)"
                          % (_mq, _mctl_ps, tuple(round(v, 1) for v in _mp), z,
                             tuple(round(v, 1) for v in p)), flush=True)
                    p = _mp
        if per_team and cid:
            # 2026-10-05: no ring when every seat has its own start node (the
            # 15-unit nudge pushed a player off a ledge, Iron Curtain)
            _mq2 = _record_quest(cid) if a.mission_player_spawn == "on" else None
            _nst = (arenadata.mission_player_starts(z, _quest_sit.get(_mq2, 0))
                    if _mq2 else 0)
            if not (_nst and _seat_of(cid)[1] <= _nst):
                p = _seat_spread(p, cid)
            print("  [arena] 0x%08x spawns at %s (zone %d)"
                  % (cid, tuple(round(v, 1) for v in p), z), flush=True)
        return p

    def _seat_spread(p, cid, team=None):
        """2026-09-28 (Dirge report): every player of a table used to get the
        SAME point -- 8 of 9 live matches -- and two avatars on one spot is
        the likeliest source of the reported out-of-bounds spawns. Seat i of
        the n players sharing the point (the table, or `team`'s members at a
        team start) goes on a SEAT_SPREAD ring around it (units are ~10 cm:
        a running player covers ~50 a second, measured), same height; alone,
        the point itself."""
        i, n = _seat_of(cid, team=team)
        if n < 2:
            return p
        ang = 2.0 * math.pi * i / n
        return (p[0] + SEAT_SPREAD * math.cos(ang), p[1],
                p[2] + SEAT_SPREAD * math.sin(ang))

    def forgotten_table(key, cid):
        """2026-10-05: True when a game-server request echoes table `key`
        (body+2, from selector 38) that this server does not seat `cid` at --
        no such table at all (a restart forgot it), or the player is known
        and sits elsewhere. 0 / 0xFFFF = no table echoed."""
        if key in (0, 0xFFFF):
            return False
        if bt_store.get(key) is None:
            return True
        return bool(cid) and bt_store.table_of(cid) != key

    def _seat_of(cid, team=None):
        """(seat index, seats) of `cid` among its table's players (or among
        `team`'s); (0, 0) when it is not seated."""
        room = battle_of(cid) if cid else None
        seats = (list(room.members) if room is not None
                 else [m for m in bt_store.members(bt_store.table_of(cid) or -1) if m]
                 if cid else [])
        if team is not None:
            seats = [m for m in seats if _spawn_team(None, m) == team]
        if cid not in seats:
            return 0, 0
        return seats.index(cid), len(seats)

    def _record_situation(cid):
        """2026-10-05: the situation id of `cid`'s table record (wire+34),
        else --bt-situation; None when neither is set."""
        tk = bt_store.table_of(cid) if cid else None
        rec = bt_store.record(tk) if tk is not None else None
        if rec and len(rec) > tablerecords.BT_OFF_SITUATION + 1:
            v = struct.unpack_from("<H", rec, tablerecords.BT_OFF_SITUATION)[0]
            if v:
                return v
        return bt_store.situation or None

    def _is_bt_pvp(cid):
        """True when `cid`'s battle is an individual (BT) PvP battle."""
        room = battle_of(cid)
        if room is not None:
            return room.mission is None and room.individual()
        tk = bt_store.table_of(cid)
        rec = bt_store.record(tk) if tk is not None else None
        if not rec or len(rec) <= tablerecords.BT_OFF_MODE:
            return False
        if struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0] & tablerecords.BT_FLAG_MISSION:
            return False
        return tablerecords.BT_MODE_NAMES.get(rec[tablerecords.BT_OFF_MODE], "TBT") == "BT"
    def _mission_quest(sess):
        """2026-09-23: the quest id of `sess`'s Mission-flagged table, or 0."""
        cid = sess.seen_charid[0] if sess is not None else 0
        tk = bt_store.table_of(cid) if cid else None
        rec = bt_store.record(tk) if tk is not None else None
        if not rec or len(rec) <= tablerecords.BT_OFF_MISSION + 1:
            return 0
        if not struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0] & tablerecords.BT_FLAG_MISSION:
            return 0
        return struct.unpack_from("<H", rec, tablerecords.BT_OFF_MISSION)[0]

    def _record_quest(cid):
        """The mission quest id of `cid`'s battle table, or None when the
        table is not a mission (flags 0x10000, u16 at wire+26)."""
        tk = bt_store.table_of(cid) if cid else None
        rec = bt_store.record(tk) if tk is not None else None
        if not rec or len(rec) <= tablerecords.BT_OFF_MISSION + 1:
            return None
        if not struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0] & tablerecords.BT_FLAG_MISSION:
            return None
        return struct.unpack_from("<H", rec, tablerecords.BT_OFF_MISSION)[0] or None

    def _mission_ctrl(sess):
        """2026-09-23: the NPC controller id for `sess`'s battle -- its
        table's mission quest mapped through --quest-situations -- or 0."""
        cid = sess.seen_charid[0] if sess is not None else 0
        tk = bt_store.table_of(cid) if cid else None
        rec = bt_store.record(tk) if tk is not None else None
        if not rec or len(rec) <= tablerecords.BT_OFF_MISSION + 1:
            return 0
        if not struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0] & tablerecords.BT_FLAG_MISSION:
            return 0
        return _quest_sit.get(struct.unpack_from("<H", rec, tablerecords.BT_OFF_MISSION)[0], 0)

    _r24_next = {}

    def _base_setup(sess):
        """2026-09-24: (gimmicks, hp, controller, owner teams, spots) when
        `sess`'s battle is a TEAM BASE table (mode byte 3) with a Base
        Durability and its arena has bases, else None. 2026-10-05: or a BASE
        MISSION (doc_missions.MISSION_BASES): its one enemy base, owned by
        team 1, at its own spot. spots None = the arena's PvP pair."""
        cid = sess.seen_charid[0] if sess is not None else 0
        tk = bt_store.table_of(cid) if cid else None
        rec = bt_store.record(tk) if tk is not None else None
        if not rec or len(rec) <= tablerecords.BT_OFF_MODE:
            return None
        hp = struct.unpack_from("<I", rec, tablerecords.BT_OFF_BASE_HP)[0]
        if not hp:
            return None
        ctrl = bt_store.leader_cid(tk) or cid
        _mq = _record_quest(cid)
        if _mq is not None:
            if _mq not in doc_missions.MISSION_BASES:
                return None
            _row, _team, _pos = doc_missions.MISSION_BASES[_mq]
            return (_row,), hp, ctrl, (_team,), (_pos,)
        if rec[tablerecords.BT_OFF_MODE] != 3:
            return None
        g = arenadata.base_gimmicks(_battle_zone(sess.key, cid), _record_situation(cid))
        if not g:
            return None
        return g, hp, ctrl, (0, 1), None

    def base_report_in(room, bs, reports, zone=None):
        """The CONTROLLER's base HP: forward changes (kind 33) to the other
        members' HUDs. A base that falls opens its OCCUPATION phase
        (--base-occupy, base_occupy_tick in fire_battles); with no spot for
        the arena, or --base-occupy off, it ends the room at once."""
        if room.base_spots is None and len(bs) > 4 and bs[4] is not None:
            room.base_spots = bs[4]          # a base mission's own base
            room.base_teams = bs[3]
        if room.base_spots is None and zone is not None:
            room.base_spots = arenadata.base_spots(
                zone, _record_situation(room.members[0] if room.members else 0))
        _occ = a.base_occupy == "on" and room.base_spots is not None
        _was_down = set(room.base_down)
        changed = room.base_update(reports, occupy=_occ)
        for _bi in sorted(set(room.base_down) - _was_down):
            print("  [base] table %d: base %d (team %d) DESTROYED -- team %d "
                  "must occupy it: stand within %.0f of %s for %.0f s"
                  % (room.key, _bi, _bi, room.base_down[_bi],
                     a.base_occupy_radius,
                     tuple(round(v, 1) for v in room.base_spots[_bi]),
                     a.base_occupy_s), flush=True)
        if a.base_occupy == "on" and room.base_spots is None and changed:
            print("  [base] table %d: no base spot for zone %s -- a destroyed "
                  "base ends the battle at once (the old rule)"
                  % (room.key, zone), flush=True)
        for idx, hp in changed:
            for m in room.present():
                if m == bs[2]:
                    continue            # the controller owns the HP already
                ms, dst = member_dst(m)
                if dst is not None:
                    s.sendto(gamemsg.build_gs_notify(33, arenadata.base_hp_payload(idx, bs[2], hp),
                                             seq=next_gs_seq(ms), ident=m), dst)
            print("  [base] table %d: base %d (team %d) HP %d" % (room.key, idx,
                                                              idx, hp), flush=True)
        if changed and room.over and room.why.endswith("base destroyed"):
            end_battle(room, time.time())

    def _send_base_objects(sess, dst, why):
        bs = _base_setup(sess)
        if bs is None or dst is None:
            return
        s.sendto(gamemsg.build_gs_notify(29, arenadata.base_objects_payload(bs[0], bs[3]),
                                 seq=next_gs_seq(sess), ident=sess.seen_charid[0]),
                 dst)
        print("  [base] SENT notify kind 29: bases %s (team 0, team 1), %s"
              % (list(bs[0]), why), flush=True)

    # 2026-09-24: situation per mission from doc_missions.MISSION_SETUP,
    # --quest-situations pairs override.
    _quest_sit = {q: r[1] for q, r in doc_missions.MISSION_SETUP.items()}
    _quest_sit.update({int(q, 0): int(v, 0) for q, _, v in
                       (p.partition(":") for p in
                        a.quest_situations.replace(" ", "").split(",") if p)})
    bt_store = tableverbs.BattletableStore(
        tablerecords.parse_battletable_spec(a.battletable_list,
                               name=a.user_list_name or a.lobby_chara_name),
        gs_ip=_gs_endpoint, gs_port=(a.world_gs_port or a.gs_connect_port),
        cur_min=(2 if a.bt_start_ready else 0),
        situation=a.bt_situation)
    # 2026-10-06: a PvP table carries a situation its arena HAS (else the
    # client builds every fence -- arenadata.situation_for)
    bt_store.situation_for = lambda rec, ind: arenadata.situation_for(
        _map_zone.get(rec[tablerecords.BT_OFF_MAP], a.gs_battle_zone), ind)
    bt_store.mission_time = dict(doc_missions.MISSION_TIME)
    bt_store.time_unit = a.bt_time_unit
    # 2026-10-04: a mission table lists its OWN arena and player cap, not the
    # create screen's (Jungle / 12). Only quests with a known zone / archive cap.
    bt_store.mission_map = {q: _zone_map[z] for q, z in _quest_zone.items()
                            if z in _zone_map}
    bt_store.mission_max = dict(doc_missions.MAX_PLAYERS)
    bt_store.mission_situation = dict(_quest_sit)
    # 2026-10-05: enemy-less capsule missions carry the situation whose
    # generators are their capsule spots (no controller: no enemies)
    bt_store.mission_situation.update(
        {q: zs[1] for q, zs in doc_missions.CAPSULE_SITUATIONS.items()
         if q not in bt_store.mission_situation})
    bt_store.mission_base_hp = {q: doc_missions.MISSION_BASE_HP
                                for q in doc_missions.MISSION_BASES}
    bt_tables = bt_store.records()
    if bt_tables:
        print("[battletable] serving %d table(s) on selector %d -> %d"
              % (len(bt_tables), tablerecords.BATTLETABLE_LIST_REQ, tablerecords.BATTLETABLE_LIST_ANS),
              flush=True)
    if a.battletable_verbs:
        print("[battletable] console verbs ON (sec 4dz): %s"
              % ", ".join("%d->%d %s" % (r, r + 1, worldchannel.selector_name(r))
                          for r in tableverbs.BT_VERB_REQS), flush=True)
        print("[battletable] reservation ECHO (sec 4fl): %s -- selector 152 "
              "after CREATE-ok/JOIN-ok so the leader holds a reservation on "
              "their own table (the 0x683b Start gate)"
              % ("OFF (--bt-no-reserve-echo)" if a.bt_no_reserve_echo
                 else "ON"), flush=True)
        print("[battletable] START -> BATTLE READY (sec 4fm): %s -- selector 38 "
              "right after the 241 answer to lobby command 3 (the leader's "
              "start_onlinebattle request)"
              % ("OFF (--bt-no-start-ready)" if a.bt_no_start_ready
                 else "ON"), flush=True)
        print("[gs] post-join battle start: ARM-ONCE per BATTLE READY (sec 4fn), "
              "%.0f s after the FIRST request 31; fake teammates pushed once"
              % a.gs_battle_after_join, flush=True)
    print("[gs] sec 4ft: kind 2 serves arena zone %d map %s (0 = the old title "
          "bounce); start-all %s; real roster %s; real distribution %s "
          "(settle %.0f s)"
          % (a.gs_battle_zone, _gs_bmap, "ON" if a.bt_start_all else "OFF",
             "ON" if a.gs_real_roster else "OFF",
             "ON" if a.gs_real_dist else "OFF", a.gs_real_dist_settle),
          flush=True)
    if not a.battle_map_zone or not _map_zone:
        print("[gs] sec 4hb: the table's CHOSEN MAP is IGNORED -- every table "
              "plays in zone %d whatever its Map row says (%s). This is the "
              "2026-09-23 'always the Jungle' bug; drop --no-battle-map-zone / "
              "--battle-map-zones=off to fix it."
              % (a.gs_battle_zone,
                 "--no-battle-map-zone" if not a.battle_map_zone
                 else "--battle-map-zones is empty"), flush=True)
    else:
        _ready = sorted(z for z in set(_map_zone.values())
                        if z == a.gs_battle_zone or z in _zone_spawn)
        _nospawn = sorted(set(_map_zone.values()) - set(_ready))
        print("[gs] sec 4hb: the table's MAP picks the arena zone -- %d of the "
              "%d roster maps decoded: %s"
              % (len(_map_zone), len(arenamaps.LOBBY_MAP_NAMES),
                 ", ".join("%d(%s)->z%d" % (i, _map_name(i), z)
                           for i, z in sorted(_map_zone.items()))), flush=True)
        print("[gs] sec 4hb: zones with a spawn (playable now): %s%s"
              % (", ".join("z%d" % z for z in _ready) or "NONE",
                 ("; NO --zone-spawns point for %s -- those maps %s"
                  % (", ".join("z%d" % z for z in _nospawn),
                     "stay in zone %d" % a.gs_battle_zone
                     if a.battle_map_needs_spawn
                     else "WILL be served anyway (default since 2026-09-23, "
                          "--battle-map-needs-spawn restores the guard): "
                          "expect the VOID until each floor is surveyed"))
                 if _nospawn else ""), flush=True)
        _undecoded = [i for i in range(len(arenamaps.LOBBY_MAP_NAMES))
                      if i not in _map_zone and i not in arenamaps.LOBBY_MAP_HOLES]
        if _undecoded:
            print("[gs] sec 4hb: NO zone decoded for map %s -- a table on one "
                  "of those stays in zone %d"
                  % (", ".join("%d(%s)" % (i, _map_name(i))
                               for i in _undecoded), a.gs_battle_zone),
                  flush=True)
    print("[gs] sec 4fv: solo distribution %s -- kind 20 after the "
          "post-join battle pushes when the table has < 2 seated members"
          % ("ON" if a.gs_solo_dist else "OFF (--gs-no-solo-distribution)"),
          flush=True)

    def next_gs_seq(sess):
        """The sequence for the next type-130 packet -- and it MUST move.

        WARNING:KEY: sec 4cx. The game-server channel runs a sequence WINDOW that every
        other channel here lets us ignore, and `--lobby-seq` defaults to 0 and
        never advances, so every reliable message we have ever sent it after the
        first was thrown away. In `0x00bc4e98`, past the three gates that stamp
        `[chan+224]`:

            delta = (seq - [chan+212]) & 0xffff
            if delta > 0xf800 and (flags & 1):  0x00bc4dd8(chan, seq) < 0 -> DROP
            if (u32)(delta - 1) >= 10000                                 -> DROP
            ...accept, and [chan+212] = seq

        so an accepted sequence needs **1 <= delta <= 10000**. Repeat one and
        `delta - 1` is 0xffffffff: the client prints

            [KEL NET GAME SRV] Drop resend packet 130 0

        which is exactly what the live emulog shows once every 15.05 s -- our
        own `--gs-keepalive-ms=15000`, dropped every single time.

        WARNING: It is a SILENT failure everywhere else: `[chan+224]` is stamped at
        0x00bc4f40 BEFORE the window runs, so CER-48101's 40 s timeout stays
        quiet while nothing is ever dispatched. That is why the grants appeared
        to work -- `build_gs_stats` IS message 27, the arming message, and an
        arm lands only because bit 6 of `[chan+204]` is still clear and takes
        the `beql` at 0x00bc4f30 straight past the window. One grant per world
        session, every repeat dropped.

        WARNING: And why `doc_gsreply_proof.py` said the channel was fine: it builds
        with **flags=0x00**, and an unreliable packet skips the window at
        0x00bc4f20. We ship flags=0x01. Measured, all of it, by running the
        client's own handler in `an offline run of the client's own code (doc_gsseq_proof)`.

        A plain monotone u16 is correct in every case, with no reset: the ARM
        message always bypasses the window (the channel reset at 0x00bc03b8
        clears `[chan+204]`, and 0x00bc4ff0 then stores our seq into
        `[chan+212]`), so it re-synchronises the window to whatever value this
        counter has reached. `0x00bc03b8` does NOT clear `[chan+212]`, so a
        counter that never restarts also survives a reset with delta 1.
        """
        sess.gs_seq[0] = (sess.gs_seq[0] + 1) & 0xFFFF
        return sess.gs_seq[0]


    def players_connected(exclude=None, now=None):
        """sec 4fz: how many DoC clients are ON the server -- sessions heard
        from inside --keepalive-idle-s, the same window peer_idle() uses to
        decide a peer has LEFT. sec 4gz: one per CLIENT (sessions key by
        (ip, port)), so two consoles in one house now count as two; a session
        left behind by a moved port stops counting as soon as it falls out of
        that window, and is reaped by --session-idle-drop.
        `exclude` is the client asking: at Select Server it has not joined yet,
        so the column shows the OTHER players, the way a server list does."""
        now = now or datetime.datetime.now().timestamp()
        win = a.keepalive_idle_s if a.keepalive_idle_s > 0 else 90.0
        return sum(1 for _ss in sessions.values()
                   if _ss is not exclude and _ss.last_peer_rx[0]
                   and now - _ss.last_peer_rx[0] <= win)

    def peer_idle(sess, now):
        """the 2026-09-05 audit (C): no unsolicited sends to a peer that left."""
        return (a.keepalive_idle_s > 0 and sess.last_peer_rx[0] > 0
                and (now - sess.last_peer_rx[0]) > a.keepalive_idle_s)

    def fire_keepalives(sess, now):
        """Every timer-driven send, due or not -- called from BOTH the select
        timeout and after each inbound datagram.

        WARNING: the 2026-09-05 audit (B): the kelsvc and game-server keepalives
        used to sit after the blocking recvfrom, so they only ever ran when the
        client had just spoken -- 161 and 160 sends against 7,080 lobby
        keepalives over the same two days.  The client's 2 Hz stream goes quiet
        in menus, which is exactly where the 40 s kelsvc receive watchdog
        (CER-48102, sec 4cc) then had nothing refreshing it.  Now the loop
        selects on the earliest of all three deadlines and fires whatever is
        due, whether or not the client is transmitting.
        """

        if peer_idle(sess, now):
            return
        # 2026-09-23 (sec 4hc): the queued new-player intro push.
        _idue = _intro_due.get(sess.key)
        if _idue and now >= _idue:
            _intro_due.pop(sess.key, None)
            _intro_sent.add(sess.key)
            send_push(sess, doc_novice.intro_push(
                subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7)),
                sess.seen_charid[0], "sub 10 event 1 (the new-player intro)")
        # Drive the advance loop on OUR clock, not on the client's retransmits.
        if (a.lobby_keepalive_ms > 0 and sess.ka_template is not None and sess.ka_src is not None
                and not (a.nest_quiet_after_frag3 > 0
                         and sess.frag3_sent >= a.nest_quiet_after_frag3)
                and now >= (sess.ka_next or 0.0)):
            # Opening: beat fast until the nest is disarmed (we cannot observe that, so
            # we just keep trying for --lobby-keepalive-open-s). Steady: a gap wide
            # enough for the client's own 9001 ms poll gate to open (sec 4al/4am).
            opening = (a.lobby_keepalive_open_s > 0 and sess.ka_first is not None
                       and (now - sess.ka_first) < a.lobby_keepalive_open_s)
            ka_interval = (a.lobby_keepalive_open_ms if opening else a.lobby_keepalive_ms) / 1000.0
            sess.ka_next = now + ka_interval
            ka = handshake.build_lobby_advance(
                sess.ka_template,
                selector=a.lobby_sustain_selector or a.lobby_selector,
                seq=a.lobby_seq,
                inner_ip=advertise.host_for(a.lobby_ip, sess.ka_src[0]),
                empty_records=True, **sess.chara_kw)
            s.sendto(bytes(ka), sess.ka_src)
            sess.ka_sent += 1
            # The ladder extras ride the KEEPALIVE, not just the inbound path.
            # MEASURED (doc-rx-boot10-duty): a boot is only three packets --
            # entrance(80) -> lobby(96) -> mode-2(36) in 0.13 s -- and then the
            # client goes SILENT while it loads the zone and draws character
            # select.  The charamake timeout (CER-48104) fires in that silence.
            # An extra code sent only on inbound would therefore fire three times
            # at the start, when the nest is nowhere near state 9, and never once
            # during the phase we are trying to answer.
            for sel in extra_selectors:
                ex = handshake.build_lobby_advance(
                    sess.ka_template, selector=sel, seq=a.lobby_seq,
                    inner_ip=advertise.host_for(a.lobby_ip, sess.ka_src[0]),
                    empty_records=True)
                if ex is not None:
                    s.sendto(ex, sess.ka_src)
            kts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print("[%s] KEEPALIVE #%d (%s, %dms) -- unsolicited selector-%d%s to %s:%d"
                  % (kts, sess.ka_sent, "opening" if opening else "steady",
                     int(ka_interval * 1000),
                     a.lobby_sustain_selector or a.lobby_selector,
                     ("+ladder%s" % extra_selectors) if extra_selectors else "",
                     sess.ka_src[0], sess.ka_src[1]), flush=True)
        # KEY: sec 4cc: refresh the client's KELSVC receive watchdog. Its budget
        # is [conn+4] = 40000 ms against [conn+32], and the ONLY thing that
        # refreshes [conn+32] is a message reaching the driver 0x005895b0, which
        # stamps it in its tail for any selector. We send type-127 solely in
        # answer to requests, so an active player who simply is not REQUESTING
        # sees 40 s of silence on that channel -> CER-48102. A no-op selector
        # costs nothing: state and flags measured unchanged.
        if (a.kelsvc_keepalive_ms > 0 and sess.ka_src is not None
                and now >= sess.kel_ka_next):
            sess.kel_ka_next = now + a.kelsvc_keepalive_ms / 1000.0
            _kreq = bytearray(framing.HDR_LEN + 176)
            _kreq[0] = 0x04
            struct.pack_into("<H", _kreq, 2, len(_kreq))
            _kreq[8] = a.world_type & 0xFF
            _kk = worlddoor.build_world_answer(
                bytes(_kreq), selector=a.kelsvc_keepalive_selector, seq=a.lobby_seq,
                subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
                # sec 4dv: same reason as the game-server connect -- an arm
                # that reads record+4 compares it with [kelsvc+272], so send
                # the id the client told us it is using, not a constant 0.
                inner_ip=None, ptype=a.world_type, pad_to=a.world_pad,
                ident=sess.seen_charid[0])
            if _kk is not None:
                s.sendto(_kk, sess.ka_src)
                print("  KELSVC KEEPALIVE (type-%d selector %d no-op) -> %s:%d "
                      "-- refreshes [conn+32], sec 4cc"
                      % (a.world_type, a.kelsvc_keepalive_selector,
                         sess.ka_src[0], sess.ka_src[1]), flush=True)
        # sec 4cq: the GAME SERVER channel's own 40 s deadline. Once the arm
        # above has set [chan+204] bit 6, ANY accepted message refreshes
        # [chan+224] -- 0x00bc4e98 stamps it before it dispatches, so the type
        # does not matter. Message 29's table entry IS the shared epilogue, so
        # it is the cheapest no-op the channel has.
        # sec 4fw (live 09-13): the distribution's settle was only re-checked
        # on request 31 -- READY at 02:03:19.9, the last click's 31 at :22.7,
        # none after, so kind 20 never went out and both players sat in the
        # briefing room. Re-check it on the server's clock.
        if a.gs_real_dist and sess.seen_charid[0]:
            _rk = bt_store.table_of(sess.seen_charid[0])
            _due = (teamdist.gs_dist_due(gs_table_state(_rk), a.gs_real_dist_settle)
                    if _rk is not None else None)
            if _due is not None and now >= _due:
                try:
                    gs_sync_table(_rk)
                except Exception:
                    import traceback
                    print("  [roster] gs_sync_table (timer) FAILED:\n%s"
                          % traceback.format_exc(), flush=True)
        # sec 4ga: GO. Kind 5 (START) sets facade 0x80, which makes
        # getBattleInitPos return the player's OWN record instead of our kind-2
        # spawn -- so it (and 53) wait until ev2045.battlefield has read the
        # spawn and parked in waitlogin, which waits for exactly this bit.
        if (sess.gs_battle_go[0] and now >= sess.gs_battle_go[0]
                and sess.gs_join_src[0] is not None):
            sess.gs_battle_go[0] = 0.0
            _gspec = a.gs_battle_go
            _mctl = _mission_ctrl(sess)
            if _mctl:
                _gspec = ",".join(
                    ("28:" + arenadata.npc_controller_payload(_mctl).hex())
                    if part.strip() == "28" else part
                    for part in (_gspec or "").split(","))
                print("  [missions] GO burst: kind 28 names NPC controller %d"
                      % _mctl, flush=True)
            elif a.mp_points == "on":
                # 2026-09-26 (doc_items): the same MP-point record the spawn
                # carried; a zero 28 here would re-send count 0
                _gspec = ",".join(
                    ("28:" + doc_items.mp_points_record().hex())
                    if part.strip() == "28" else part
                    for part in (_gspec or "").split(","))
            _bs = _base_setup(sess)
            if _bs is not None:
                # the gate burst's kind 29 must carry the SAME bases: a zero
                # record would empty the object table the HUD reads HP from
                _gspec = ",".join(
                    ("29:" + arenadata.base_objects_payload(_bs[0], _bs[3]).hex())
                    if part.strip() == "29" else part
                    for part in (_gspec or "").split(","))
            for _k, _np in briefingroom.gs_battle_sequence(_gspec,
                                              seq_fn=lambda: next_gs_seq(sess),
                                              ident=sess.seen_charid[0]):
                s.sendto(_np, sess.gs_join_src[0])
                time.sleep(0.05)
                print("  [battle] GO: SENT notify kind %d (%s), %.1f s after "
                      "its 47 (sec 4ga)" % (_k, gamemsg.GS_NOTIFY_NAMES.get(_k, "?"),
                                            now - (sess.gs_battle_on[0] or now)),
                      flush=True)
            if _gspec:
                _go_resend[sess] = [now + GO_RESEND_S, _gspec, GO_RESEND_TRIES, now]
            try:
                capsule_send_field(battle_of(sess.seen_charid[0]), sess)
            except Exception:
                import traceback
                print("  [capsule] field FAILED:\n%s" % traceback.format_exc(),
                      flush=True)
            if _bs is not None:
                for _bi in range(len(_bs[0])):
                    s.sendto(gamemsg.build_gs_notify(33, arenadata.base_hp_payload(_bi, _bs[2], _bs[1]),
                                             seq=next_gs_seq(sess),
                                             ident=sess.seen_charid[0]),
                             sess.gs_join_src[0])
                print("  [base] SENT notify kind 33 x%d: HP %d, controller 0x%08x"
                      % (len(_bs[0]), _bs[1], _bs[2]), flush=True)
            if (a.npc_arena == "on" and _npc_arena_types) or _mission_ctrl(sess):
                _npc_arena_due[sess] = now + a.npc_arena_after
        # 2026-10-05: the GO burst again when the arena never reported in
        _gor = _go_resend.get(sess)
        if _gor is not None and now >= _gor[0]:
            _gcid = sess.seen_charid[0]
            if (_last_gs24.get(_gcid, 0.0) >= _gor[3] or _gor[2] <= 0
                    or sess.gs_join_src[0] is None or battle_of(_gcid) is None):
                _go_resend.pop(sess, None)
            else:
                _gor[2] -= 1
                _gor[0] = now + GO_RESEND_S
                # back to back: a sleep here stalls every other client
                for _k, _np in briefingroom.gs_battle_sequence(
                        _gor[1], seq_fn=lambda: next_gs_seq(sess), ident=_gcid):
                    s.sendto(_np, sess.gs_join_src[0])
                print("  [battle] GO RE-SENT to 0x%08x: no 1 Hz report %.1f s after "
                      "its GO (%d resend(s) left)" % (_gcid, now - _gor[3], _gor[2]),
                      flush=True)
        # sec 4gs addendum 4: the arena kind-15 test ring.
        _nad = _npc_arena_due.get(sess)
        if _nad and now >= _nad and sess.gs_join_src[0] is not None:
            _npc_arena_due.pop(sess, None)
            _ctr = _battle_pos(sess.key, sess.seen_charid[0], per_team=False)
            _rb = None
            _mctl2 = _mission_ctrl(sess)
            # 2026-10-05: a room whose enemies are already placed shares them
            _shared, _mroom = None, None
            if _mctl2:
                _mroom = battle_of(sess.seen_charid[0])
                if _mroom is not None and _mroom.mission is not None:
                    _shared = _room_mnpc.get(_mroom.key)
                    if _shared is not None and _shared.get("room") is not _mroom:
                        _room_mnpc.pop(_mroom.key, None)   # an older room's set
                        _shared = None
                else:
                    _mroom = None
            _mz = _battle_zone(sess.key, sess.seen_charid[0]) if _mctl2 else None
            _msp = (arenadata.MISSION_SPAWNS.get(str(_mz), {}).get(str(_mctl2))
                    if _mctl2 else None)
            # 2026-10-05 (static RE, retail 0x0066e440): a controller's ROSTER
            # [a, b) lists TABLE-14 GIMMICK rows (crates, bases), not enemy
            # nodes -- the extract's "spawn"/"count" read them as table-15
            # nodes, which only landed on type-4 nodes because the low node
            # indices are type 4, mostly OTHER controllers' (201:3001's 8 all
            # sat in 3000's pool). The enemy points are the controller's own
            # POOL type-4 nodes; the client never places a mission enemy itself
            # (kind 15 carries the position).
            _mpts = list((_msp or {}).get("pool") or [])
            if _mctl2 and _mpts:
                _msp = dict(_msp, count=len(_mpts), spawn=_mpts)
            elif _msp:
                _msp = dict(_msp, count=0, spawn=[])
            if _mctl2 and not (_msp and _msp.get("count") and _msp.get("spawn")):
                # 2026-09-23: the situation picks the MODELS (live: every type
                # value drew situation 3000's one enemy model, the dog), but
                # some mission controllers carry no spawn nodes (z201 3003..
                # 3005). Place the NPCs at the nearest mission controller that
                # has them (its pool, 2026-10-05).
                _zc = arenadata.MISSION_SPAWNS.get(str(_mz), {})
                _alt = sorted((abs(int(k) - _mctl2), k) for k, v in _zc.items()
                              if 3000 <= int(k) < 4000 and v.get("pool"))
                if _alt:
                    _mpts = list(_zc[_alt[0][1]]["pool"])
                    _msp = dict(_zc[_alt[0][1]], count=len(_mpts), spawn=_mpts)
                    print("  [missions] controller %d has no spawn nodes in zone "
                          "%s -> placing at controller %s's" % (_mctl2, _mz,
                                                               _alt[0][1]),
                          flush=True)
            if _shared is None and _msp and _msp.get("count") and _msp.get("spawn"):
                # 2026-09-23: the mission's own NPCs -- the controller's spawn
                # count at its own spawn nodes (arena bzd tables 28/29/15). The
                # enemy TYPE is not in the controller record yet, so the test
                # types are cycled and each id's type is logged: whichever
                # draws a DG soldier is the one to pin.
                # SIT:t,t,..;SIT:t,.. per situation, or one bare list for all
                _mtspec = {}
                for _part in (a.mission_npc_types or "").split(";"):
                    _k, _sep, _v = _part.strip().partition(":")
                    if _sep and _k.lower().startswith("q"):
                        _mtspec[("q", int(_k[1:], 0))] = doc_npc_spawn.parse_types(_v)
                    elif _sep:
                        _mtspec[int(_k, 0)] = doc_npc_spawn.parse_types(_v)
                    elif _k:
                        _mtspec[None] = doc_npc_spawn.parse_types(_k)
                _mquest = _mission_quest(sess)
                _msu = doc_missions.mission_setup(_mquest)
                if _msu and ("q", _mquest) not in _mtspec:
                    _mtspec[("q", _mquest)] = _msu[2]
                _mexact = _mtspec.get(("q", _mquest)) or _mtspec.get(_mctl2)
                _mtypes = (_mexact or _mtspec.get(None)
                           or _npc_arena_types or doc_npc_spawn.parse_types(
                               doc_npc_spawn.ARENA_TYPES_DEFAULT))
                if (_mexact and len(_msp["spawn"]) < len(_mexact)
                        and len(_mpts) > len(_msp["spawn"])):
                    # 2026-09-29: a roster shorter than the mission's enemies
                    # (36: one point, a DG Soldier AND a Beast Soldier) tops
                    # up from the controller's own pool
                    _msp = dict(_msp, count=len(_mpts), spawn=_mpts)
                    print("  [missions] controller %d in zone %s: roster too "
                          "short for %d enemies -> + its pool, %d spawn point(s)"
                          % (_mctl2, _mz, len(_mexact), len(_mpts)), flush=True)
                # 2026-10-05: the arena's own SPAWN GROUPS pick each enemy's
                # type and point (fixed groups first, then the mission's
                # named target, nearest the start); the row keeps only the
                # COUNT of enemies alive at once
                _planned = False
                _grp = _msp.get("pool_groups")
                if (a.mission_spawn_groups == "on" and _mexact and _msu
                        and _grp and len(_grp) == len(_mpts)):
                    _plan = arenadata.mission_enemy_plan(
                        _mpts, _grp, _ctr or _mpts[0], len(_mexact),
                        pick=lambda g: doc_missions.group_type(_mz, _mctl2, g),
                        prefer=lambda t: doc_missions.kill_target_type(_mquest, _mz, t),
                        near=a.mission_spawn_near)
                    if _plan:
                        _ppos = [list(p) for p, _t in _plan]
                        _pset = {tuple(p) for p in _ppos}
                        _msp = dict(_msp, count=len(_plan),
                                    spawn=_ppos + [p for p in _mpts
                                                   if tuple(p) not in _pset])
                        _mexact = _mtypes = [t for _p, t in _plan]
                        _planned = True
                        print("  [missions] quest %s controller %d: %d enemies from "
                              "the arena's spawn groups: %s" % (
                                  _mquest, _mctl2, len(_plan),
                                  ", ".join("t%d@%s" % (t, tuple(round(v) for v in p))
                                            for p, t in _plan)), flush=True)
                if (_mexact and _ctr and len(_mexact) < len(_mpts) and not _planned
                        and a.mission_spawn_near > 0):
                    # 2026-10-03 (live, quest 1 twice): ONE Beast Soldier at
                    # roster node 0, ~785 units from the player's start, idle
                    # there all mission (the 1 Hz report: HP 100, never moved)
                    # -- "no enemies". With fewer enemies than spawn points,
                    # use the points nearest the player, past a margin.
                    _near = arenadata.mission_spawn_order(_mpts, _ctr,
                                                          a.mission_spawn_near)
                    _msp = dict(_msp, spawn=_near)
                    print("  [missions] %d enemies for %d spawn point(s): "
                          "nearest the player first, >= %.0f away: %s"
                          % (len(_mexact), len(_mpts), a.mission_spawn_near,
                             _near[:len(_mexact)]), flush=True)
                _ments = [doc_npc_spawn.entry(
                    doc_npc_spawn.ARENA_ID_BASE + _i, _mtypes[_i % len(_mtypes)],
                    tuple(_p), (0.0, 0.0, 1.0),
                    # 2026-10-05: each enemy's own max HP (was a flat 100)
                    doc_missions.npc_hp(_mz, _mtypes[_i % len(_mtypes)], a.npc_spawn_hp))
                    for _i, _p in enumerate(_msp["spawn"][:(
                        min(_msp["count"], len(_mexact)) if _mexact
                        else _msp["count"])])]
                _rb = [struct.pack("<I", len(_ments[_j:_j + 8]))
                       + b"".join(_ments[_j:_j + 8])
                       for _j in range(0, len(_ments), 8)]
                _nmis = len(_ments)
                _mnpc[sess] = {
                    "types": {doc_npc_spawn.ARENA_ID_BASE + _i:
                              _mtypes[_i % len(_mtypes)] for _i in range(_nmis)},
                    "spawn": list(_msp["spawn"]), "next": _nmis, "due": [],
                    "rb": _rb, "n": _nmis, "ctrl": sess.seen_charid[0],
                    "csess": sess, "dead": set(), "room": _mroom, "zone": _mz,
                    "center": tuple(_ctr) if _ctr else None}
                if _mroom is not None and a.mission_shared_npcs == "on":
                    _room_mnpc[_mroom.key] = _mnpc[sess]
                print("  [missions] zone %s controller %d: %d NPC(s) at the "
                      "controller's spawn nodes, types by id: %s"
                      % (_mz, _mctl2, _nmis, ", ".join(
                          "0x%x=t%d" % (doc_npc_spawn.ARENA_ID_BASE + _i,
                                        _mtypes[_i % len(_mtypes)])
                          for _i in range(_nmis))), flush=True)
            if _shared is not None:
                # another member placed this room's enemies: the same Add Npc
                # batches (same ids, same spots), controlled by that console
                _rb, _nmis = _shared["rb"], _shared["n"]
                _mnpc[sess] = _shared
                print("  [missions] table %d: 0x%08x joins the room's enemy set "
                      "(%d NPC(s), controlled by 0x%08x)"
                      % (_mroom.key, sess.seen_charid[0], _nmis, _shared["ctrl"]),
                      flush=True)
            if _rb is None:
                if not (a.npc_arena == "on" and _npc_arena_types):
                    _rb = []
                else:
                    _rb = doc_npc_spawn.ring_payloads(_ctr, _npc_arena_types,
                                                      radius=a.npc_arena_radius,
                                                      hp=a.npc_spawn_hp)
                _nmis = len(_npc_arena_types) if _rb else 0
            for _b in _rb:
                s.sendto(gamemsg.build_gs_notify(doc_npc_spawn.KIND_ADD_NPC, _b,
                                         seq=next_gs_seq(sess),
                                         ident=sess.seen_charid[0]),
                         sess.gs_join_src[0])
                time.sleep(0.05)
            if _rb and not _msp:
                print("  [npc-arena] SENT notify kind %d 'Add Npc': %d NPC(s), types "
                      "%s counter-clockwise from +x, radius %.0f around (%.1f, %.1f, "
                      "%.1f), ids 0x%08x.. -> %s:%d"
                      % (doc_npc_spawn.KIND_ADD_NPC, len(_npc_arena_types),
                         a.npc_arena_types, a.npc_arena_radius, _ctr[0], _ctr[1],
                         _ctr[2], doc_npc_spawn.ARENA_ID_BASE,
                         sess.gs_join_src[0][0], sess.gs_join_src[0][1]),
                      flush=True)
            # Seen live (slot 7): the Add-Npc entries DO land in the
            # char table (8 x HP 100, flags 0x40050211) but never render: an
            # NPC entry gets an actor only from movement updates, and nobody
            # controls these. Notify kind 27 (retail arm 0x00bcc084) hands an
            # entity to a controller: body[16] u32 entity id, body[20] u32 new
            # controller's char id (== ours -> take over, 0x00be7bc8(.., 1)),
            # body[24] u32 mask (0 -> 0x7fffff). In a MISSION battle, give
            # every arena NPC to the player so its client simulates them.
            _me = sess.seen_charid[0]
            _ctl_id = (_mnpc[sess].get("ctrl") or _me) if sess in _mnpc else _me
            if _mission_ctrl(sess) and _nmis and _ctl_id != _me:
                # 2026-10-05: a NON-controller of a shared room set gets NO
                # kind 27: its NPC stays uncontrolled (+0x10 = 0), which the
                # receive gate 0x00be7dd8 accepts relayed poses for from any
                # address (relay_npc_pose); a 27 naming the controller would
                # redirect the gate to the controller's player unit instead.
                print("  [missions] 0x%08x shares the room's %d NPC(s): no kind 27 "
                      "(controller 0x%08x; their poses are relayed)"
                      % (_me, _nmis, _ctl_id), flush=True)
            if _mission_ctrl(sess) and _nmis and _ctl_id == _me:
                for _i in range(_nmis):
                    s.sendto(gamemsg.build_gs_notify(
                        27, struct.pack("<III", doc_npc_spawn.ARENA_ID_BASE + _i,
                                        _ctl_id, 0),
                        seq=next_gs_seq(sess), ident=_me), sess.gs_join_src[0])
                    time.sleep(0.02)
                print("  [missions] SENT notify kind 27 x%d to 0x%08x: NPC control "
                      "of 0x%08x.. -> 0x%08x%s"
                      % (_nmis, _me, doc_npc_spawn.ARENA_ID_BASE, _ctl_id,
                         " (the player)" if _ctl_id == _me else " (the room's controller)"),
                      flush=True)
                if sess in _mnpc and _ctl_id == _me:
                    _mnpc[sess]["ctl"] = {
                        doc_npc_spawn.ARENA_ID_BASE + _i:
                        [now + gamemsg.MISSION_CTL_CHECK_S, 1] for _i in range(_nmis)}
        # 2026-09-23: REPLACE dead mission NPCs. The situation's resource set
        # loads a fixed number of each model (bzd table 20: 3001 = e030 x1, w010,
        # w003, e102 x2) -- a third soldier draws nothing (live: six requested,
        # invisible). So spawn what the set holds and put a fresh one of the
        # same type on the next spawn node a few seconds after each death, until
        # the objective ends the room.
        _mn = _mnpc.get(sess)
        if _mn is not None and sess.gs_join_src[0] is not None:
            _room_r = battle_of(sess.seen_charid[0])
            if (_room_r is None or _room_r.over
                    or (_mn.get("room") or _room_r) is not _room_r):
                _mnpc.pop(sess, None)
                _gone = _mn.get("room")
                if _gone is not None and _room_mnpc.get(_gone.key) is _mn:
                    _room_mnpc.pop(_gone.key, None)
            else:
                # 2026-10-05: the room's controller left -> hand every live
                # enemy to a member still in it, and tell everyone who it is
                if (_room_mnpc.get(_room_r.key) is _mn
                        and _mn.get("ctrl") not in _room_r.present()):
                    _newc = next((m for m in _room_r.present()
                                  if session_of(m) is not None), None)
                    if _newc:
                        _live = [i for i in sorted(_mn["types"]) if i not in _mn["dead"]]
                        _mn["ctrl"], _mn["csess"] = _newc, session_of(_newc)
                        # only the NEW controller takes them over; the others
                        # stay uncontrolled and follow the relayed poses
                        for _nid in _live:
                            mission_npc_send(_newc, 27, struct.pack("<III", _nid, _newc, 0))
                        _mn["ctl"] = {_nid: [now + gamemsg.MISSION_CTL_CHECK_S, 1]
                                      for _nid in _live}
                        print("  [missions] table %d: enemy controller left -> %d "
                              "NPC(s) handed to 0x%08x" % (_room_r.key, len(_live), _newc),
                              flush=True)
                # replacements and control retries run ONCE per room: in the
                # controller's session (a room-less, unshared set is its own)
                if _mn.get("csess", sess) is sess and (_mn["due"] or _mn.get("ctl")
                                                       or _mn.get("extinct")):
                    _me = sess.seen_charid[0]
                    _others = [m for m in _room_r.present() if m != _me]
                    # 2026-10-05 (static RE, scratchpad re-invisible/): kind 22
                    # {u32 id} is the client's own NPC release (registry row,
                    # unit, scene chara, models; the per-frame update tears it
                    # down). We never sent it, so every dead enemy stayed
                    # allocated all battle -- live, quest 1's 8th Beast
                    # Soldier was solid, hittable and INVISIBLE. Sent before
                    # the replacement's kind 15 in the same tick.
                    for _ex in [e for e in _mn.get("extinct", ()) if now >= e[0]]:
                        _mn["extinct"].remove(_ex)
                        _xb = struct.pack("<I", _ex[1])
                        s.sendto(gamemsg.build_gs_notify(
                            GS_KIND_EXTINCT, _xb, seq=next_gs_seq(sess), ident=_me),
                            sess.gs_join_src[0])
                        for _m in _others:
                            mission_npc_send(_m, GS_KIND_EXTINCT, _xb)
                        print("  [missions] SENT kind 22 (extinct) for dead NPC 0x%x "
                              "-> 0x%x (+%d other member(s))"
                              % (_ex[1], _me, len(_others)), flush=True)
                    for _due, _typ in [d for d in _mn["due"] if now >= d[0]]:
                        _mn["due"].remove((_due, _typ))
                        _nid = doc_npc_spawn.ARENA_ID_BASE + _mn["next"]
                        # 2026-10-05 (live, quest 1): replacements cycled the
                        # pool in raw order and walked off ~1000 units from the
                        # player ("couldn't find any more"). Now: one of the
                        # three points nearest the controller's latest pose,
                        # past --mission-spawn-near.
                        # 2026-10-05 (live 18:08Z): a console whose arena pose
                        # stream we cannot read gave no pose, and the raw cycle
                        # came back -- so without a fresh pose, around the
                        # mission's own START point instead
                        _cp = _battle_pose.get(_me)
                        _ref = (_cp[:3] if _cp is not None and time.time() - _cp[3] < 10.0
                                else _mn.get("center"))
                        if _ref is not None:
                            # at least MISSION_REPLACE_NEAR away (prod's
                            # --mission-spawn-near 40 put them on top of the
                            # player: "swarmed", live 18:40Z), over the 6 nearest
                            _near_pts = arenadata.mission_spawn_order(
                                _mn["spawn"], _ref,
                                max(a.mission_spawn_near, MISSION_REPLACE_NEAR))
                            _pos = _near_pts[_mn["next"] % min(6, len(_near_pts))]
                        else:
                            _pos = _mn["spawn"][_mn["next"] % len(_mn["spawn"])]
                        _mn["next"] += 1
                        _mn["types"][_nid] = _typ
                        _add = struct.pack("<I", 1) + doc_npc_spawn.entry(
                            _nid, _typ, tuple(_pos), (0.0, 0.0, 1.0),
                            doc_missions.npc_hp(_mn.get("zone"), _typ, a.npc_spawn_hp))
                        s.sendto(gamemsg.build_gs_notify(
                            doc_npc_spawn.KIND_ADD_NPC, _add,
                            seq=next_gs_seq(sess), ident=_me), sess.gs_join_src[0])
                        # the other members get the same enemy (no kind 27:
                        # uncontrolled there, moved by the relayed poses)
                        for _m in _others:
                            mission_npc_send(_m, doc_npc_spawn.KIND_ADD_NPC, _add)
                        # 2026-09-28: a kind 27 sent straight
                        # after its Add Npc reached the client in the SAME frame
                        # and was handled FIRST (acks 235 before 234, 243 before
                        # 242), before the NPC existed. The soldier spawned
                        # uncontrolled, never entered the 1 Hz report, and its
                        # death was never counted (a mission stuck at 3 of 5).
                        # So the controller's 27 goes out MISSION_CTL_GAP_S later.
                        _mn.setdefault("ctl", {})[_nid] = [now + gamemsg.MISSION_CTL_GAP_S, 0]
                        print("  [missions] REPLACEMENT NPC 0x%x type %d at %s -> "
                              "control 0x%x in %.1f s (+%d other member(s))"
                              % (_nid, _typ, _pos, _me, gamemsg.MISSION_CTL_GAP_S,
                                 len(_others)), flush=True)
                    # Hand control (kind 27) to the controller and check it
                    # TOOK: a controlled NPC is listed in its 1 Hz report
                    # (mission_npc_report), so one missing from it after
                    # MISSION_CTL_CHECK_S gets its 27 again, up to
                    # MISSION_CTL_TRIES sends in all.
                    _seen = _mn.get("seen", ())
                    for _nid, _st in list(_mn.get("ctl", {}).items()):
                        if _nid in _seen:
                            _mn["ctl"].pop(_nid, None)
                            if _st[1] > 1:
                                print("  [missions] NPC 0x%x is in the 1 Hz report "
                                      "now (control took on send %d)"
                                      % (_nid, _st[1]), flush=True)
                            continue
                        if now < _st[0]:
                            continue
                        if _st[1] >= gamemsg.MISSION_CTL_TRIES:
                            _mn["ctl"].pop(_nid, None)
                            print("  [missions] NPC 0x%x STILL not in the 1 Hz "
                                  "report after %d kind-27 sends -- its death "
                                  "cannot be counted" % (_nid, _st[1]), flush=True)
                            continue
                        s.sendto(gamemsg.build_gs_notify(
                            27, struct.pack("<III", _nid, _me, 0),
                            seq=next_gs_seq(sess), ident=_me), sess.gs_join_src[0])
                        _st[1] += 1
                        _st[0] = now + gamemsg.MISSION_CTL_CHECK_S
                        if _st[1] > 1:
                            print("  [missions] NPC 0x%x not in the 1 Hz report -- "
                                  "RE-SENT notify kind 27 (send %d)"
                                  % (_nid, _st[1]), flush=True)
        # sec 4fy: the battle END. Kind 4 is the RESULT (its arm 0x00bc1760
        # sets facade 0x40, which ends ev2045's battle loop -> act_win/lose ->
        # the result windows), and selector 39's arm 0x00bcbd70 is the full
        # battle reset 0x00bd2a38 (facade 0x80/0x08/0x200/0x40 off) -- without
        # it ev2045 exit(217)s with 0x80 still set, main() picks br_main, and
        # the client hangs black in vl_brf2 (live 09-13, br_main stage 2).
        if (sess.gs_battle_end[0] and now >= sess.gs_battle_end[0]
                and sess.gs_join_src[0] is not None):
            # sec 4he: a battle with a ROOM ends on the room's clock
            # (fire_battles); this per-session end is the roomless fallback.
            sess.gs_battle_end[0] = 0.0
            _res_rec = bytes(gamemsg.GS_SETUP_LEN)
            if _stats is not None and sess.seen_charid[0]:
                try:
                    _res_rec, _res_note = _battle_result(sess)
                    print("  [stats] " + _res_note, flush=True)
                except Exception as _rex:      # never let a tally kill the END
                    print("  [stats] RESULT tally FAILED (%r) -- sending the "
                          "zero record" % (_rex,), flush=True)
            s.sendto(gamemsg.build_gs_notify(4, bytes(4) + _res_rec,
                                     seq=next_gs_seq(sess),
                                     ident=sess.seen_charid[0]),
                     sess.gs_join_src[0])
            sess.gs_battle_reset[0] = now + a.gs_battle_reset_after
            print("  [battle] SENT notify 4 (the RESULT, facade 0x40) -- "
                  "selector %d in %.0f s (sec 4fy)"
                  % (briefingroom.GS_BATTLE_OVER_SELECTOR, a.gs_battle_reset_after), flush=True)
        if sess.gs_battle_reset[0] and now >= sess.gs_battle_reset[0]:
            sess.gs_battle_reset[0] = 0.0
            sess.gs_battle_on[0] = 0.0
            if sess.ka_src is not None:
                _req = bytearray(framing.HDR_LEN + 176)
                _req[0] = 0x04
                struct.pack_into("<H", _req, 2, len(_req))
                _req[8] = a.world_type & 0xFF
                _bo = worlddoor.build_world_answer(
                    bytes(_req), selector=briefingroom.GS_BATTLE_OVER_SELECTOR,
                    seq=a.lobby_seq,
                    subchannel=(a.world_subchannel if a.world_subchannel >= 0
                                else 7),
                    inner_ip=None, ptype=a.world_type, pad_to=a.world_pad,
                    ident=sess.seen_charid[0])
                if _bo is not None:
                    s.sendto(_bo, sess.ka_src)
                    print("  [battle] SENT selector %d (battle over / reset, "
                          "arm 0x00bcbd70) to %s:%d -- expect the lobby, not "
                          "br_main (sec 4fy)" % (briefingroom.GS_BATTLE_OVER_SELECTOR,
                                                 sess.ka_src[0], sess.ka_src[1]),
                          flush=True)
            # sec 4gc (live 09-13): finished games stayed in the battle table
            # list -- the table outlived its battle. Dissolve it here (the
            # second member's reset finds it gone), and drop its roster /
            # distribution state so a re-created key starts clean.
            _dk = (bt_store.table_of(sess.seen_charid[0])
                   if sess.seen_charid[0] else None)
            _dmem = bt_store.members(_dk) if _dk is not None else []
            if _dk is not None and bt_store.dissolve(_dk):
                gs_tables.pop(_dk, None)
                print("  [battle] table %d DISSOLVED after the battle -- off "
                      "the battle table list (sec 4gc)" % _dk, flush=True)
                for m in _dmem:
                    send_reservation_clear(m, why="table %d dissolved after "
                                           "the battle" % _dk)
        if (sess.gs_join_deadline[0] and time.time() >= sess.gs_join_deadline[0]
                and sess.gs_battle_on[0]):
            # 2026-10-03 (live, table 1): the deadline armed by request 31
            # outlived the room's start and re-sent kind 2 73 s into the
            # battle -- one client's timer read 0, it could not shoot, and the
            # clients drew a result the server never sent. Its 47 already
            # had the spawn.
            sess.gs_join_deadline[0] = 0.0
            print("  [battle] post-join timer SKIPPED for 0x%08x -- its battle "
                  "already started (request 47)" % (sess.seen_charid[0] or 0),
                  flush=True)
        if sess.gs_join_deadline[0] and time.time() >= sess.gs_join_deadline[0]:
            sess.gs_join_deadline[0] = 0.0
            _bkey = sess.key if sess.gs_join_src[0] else None
            _bcid = sess.seen_charid[0] if sess.gs_join_src[0] else None
            _bpos = _battle_pos(_bkey, _bcid)
            _bzone, _bnote = _battle_zone_note(_bkey, _bcid)
            if _bnote:
                print("  [arena] " + _bnote, flush=True)
            if _bcid:
                # kind 25 (push_down) repeats this spawn and its M0/M1
                _spawn_of[_bcid] = (_bpos, arenamaps.spawn_bmap(
                    _bzone, _bpos, arenamaps.battle_bmap(_bzone, _zone_pieces, _gs_bmap)))
                _spawn_zone[_bcid] = _bzone
            for _k, _np in briefingroom.gs_battle_sequence(a.gs_battle_start, spawn=_bpos,
                                              seq_fn=lambda: next_gs_seq(sess),
                                              ident=sess.seen_charid[0],
                                              zone=_bzone,
                                              # 2026-10-06: the pieces AT the spawn
                                              bmap=arenamaps.spawn_bmap(
                                                  _bzone, _bpos, arenamaps.battle_bmap(
                                                      _bzone, _zone_pieces, _gs_bmap))):
                s.sendto(_np, sess.gs_join_src[0])
                time.sleep(0.05)
                print("  SENT notify kind %d (%s) on the post-join timer -- sec 4ed"
                      % (_k, gamemsg.GS_NOTIFY_NAMES.get(_k, "?")), flush=True)
            _send_base_objects(sess, sess.gs_join_src[0],
                               "with the spawn (post-join timer)")
            _mctl = _mission_ctrl(sess)
            if _mctl:
                s.sendto(gamemsg.build_gs_notify(28, arenadata.npc_controller_payload(_mctl),
                                         seq=next_gs_seq(sess),
                                         ident=sess.seen_charid[0]),
                         sess.gs_join_src[0])
                print("  [missions] SENT notify kind 28 naming NPC controller %d "
                      "(the mission's situation) with the spawn" % _mctl, flush=True)
            elif a.mp_points == "on":
                # 2026-09-26 (doc_items): kind 28's count + mask are what the
                # zone setup's "magic supply" step (0x00bf1370) reads to create
                # the situation's MP points -- ONCE, so with the spawn, like
                # the mission's controller record and the bases' kind 29
                s.sendto(gamemsg.build_gs_notify(28, doc_items.mp_points_record(),
                                         seq=next_gs_seq(sess),
                                         ident=sess.seen_charid[0]),
                         sess.gs_join_src[0])
                print("  [mp point] SENT notify kind 28 (MP points: count 64, "
                      "all enabled) with the spawn", flush=True)
            # sec 4fv: a solo leader never satisfies gs_real_ready, so the
            # distribution -- the only door vl_main has to get_onlinezone --
            # never opened. Push it AFTER kind 2 (which sets [chan+204] & 4 and
            # the zone byte get_onlinezone polls for).
            _self = sess.seen_charid[0] or 0
            _tk = bt_store.table_of(_self) if _self else None
            _seated = [m for m in bt_store.members(_tk) if m] if _tk else []
            if a.gs_solo_dist and _self and len(_seated) < 2:
                _dist = teamdist.gs_solo_distribution(sess.gs_teams, _self)
                s.sendto(gamemsg.build_gs_distribution(_dist, seq=next_gs_seq(sess),
                                               ident=_self),
                         sess.gs_join_src[0])
                if battle_of(_self) is None:
                    open_battle(_tk, [_self], {_self: sess.gs_teams.get(_self, 0)},
                                mission=_mission_battle.get(sess.key), now=now)
                print("  [solo] SENT notify 20 (PLAYER DISTRIBUTION) over %s "
                      "(table %s, %d seated). Watch: 'Player distribution has "
                      "been determined' -> OK -> request 47 -> get_onlinezone "
                      "-> KerberosZone.exit(z%d) (sec 4fv)"
                      % (["0x%x:t%d:s%d" % e for e in _dist], _tk, len(_seated),
                         _bzone),
                      flush=True)
        if (a.gs_keepalive_ms > 0 and sess.gs_ka_src[0] is not None
                and now >= sess.gs_ka_next[0]):
            sess.gs_ka_next[0] = now + a.gs_keepalive_ms / 1000.0
            s.sendto(gamemsg.build_gs_message(gamemsg.GS_KEEPALIVE_MSG, seq=next_gs_seq(sess),
                                      body_extra=bytes(64)), sess.gs_ka_src[0])
            print("  GAME-SERVER KEEPALIVE (message %d no-op) -> %s:%d -- "
                  "refreshes [chan+224], sec 4cq"
                  % (gamemsg.GS_KEEPALIVE_MSG, sess.gs_ka_src[0][0], sess.gs_ka_src[0][1]),
                  flush=True)

    def next_deadline(now):
        """The earliest timer across ALL sessions, or None to block (sec 4fq)."""
        due = []
        for sess in sessions.values():
            if peer_idle(sess, now):
                continue
            if (a.lobby_keepalive_ms > 0 and sess.ka_template is not None
                    and sess.ka_src is not None
                    and not (a.nest_quiet_after_frag3 > 0
                             and sess.frag3_sent >= a.nest_quiet_after_frag3)):
                due.append(sess.ka_next or 0.0)
            if a.kelsvc_keepalive_ms > 0 and sess.ka_src is not None:
                due.append(sess.kel_ka_next)
            if a.gs_keepalive_ms > 0 and sess.gs_ka_src[0] is not None:
                due.append(sess.gs_ka_next[0])
            if sess.frag3_pending is not None and sess.chara_burst_at is not None:
                due.append(sess.chara_burst_at + a.frag3_hold_s)
            if sess.gs_join_deadline[0]:
                due.append(sess.gs_join_deadline[0])
            for _bt in (sess.gs_battle_end[0], sess.gs_battle_reset[0],
                        sess.gs_battle_go[0]):
                if _bt:
                    due.append(_bt)            # sec 4fy: result / selector 39
            if _npc_arena_due.get(sess):
                due.append(_npc_arena_due[sess])   # sec 4gs addendum 4
            if _mnpc.get(sess):                    # mission NPC replace / kind 27
                due.extend(d[0] for d in _mnpc[sess]["due"])
                due.extend(c[0] for c in _mnpc[sess].get("ctl", {}).values())
            if _intro_due.get(sess.key):
                due.append(_intro_due[sess.key])   # sec 4hc: the intro push
            if a.gs_real_dist and sess.seen_charid[0]:
                _rk = bt_store.table_of(sess.seen_charid[0])
                if _rk is not None:
                    _due = teamdist.gs_dist_due(gs_table_state(_rk), a.gs_real_dist_settle)
                    if _due is not None:
                        due.append(_due)   # sec 4fw: wake for the settle
        due.extend(_fill_start.values())           # a full table's start
        due.extend(_rematch.values())              # a kept table's next round
        due.extend(battle_deadlines())             # sec 4he: room clocks
        _wd = weekly_deadline()                    # the weekly medals' rollover
        if _wd is not None:
            due.append(_wd)
        return min(due) if due else None

    while True:
        # sec 4fq: HELD FRAG3 + timers for EVERY client session, on our clock.
        _now = datetime.datetime.now().timestamp()
        for _sess in list(sessions.values()):
            if (_sess.frag3_pending is not None
                    and _sess.chara_burst_at is not None):
                held = _now - _sess.chara_burst_at
                if held >= a.frag3_hold_s:
                    fr_h, fsrc = _sess.frag3_pending
                    _sess.frag3_pending = None
                    s.sendto(fr_h, fsrc)
                    _sess.frag3_sent += 1
                    print("[%s]   SENT the HELD frag3 reply #%d after %.1f s to %s:%d"
                          % (datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
                             _sess.frag3_sent, held, fsrc[0], fsrc[1]), flush=True)
        # sec 4gz: REAP long-dead sessions. Keyed by (ip, port) the registry
        # grows with every re-bound NAT mapping, not just with every address,
        # so on a public server it has to be bounded -- and a stale entry would
        # otherwise sit in `players_connected` and in the adoption scan for the
        # life of the process. Nothing in flight is dropped: a session holding a
        # held frag3 or a pending chara reply is left alone.
        if a.session_idle_drop > 0:
            for _sk, _sess in list(sessions.items()):
                if (_sess.frag3_pending is None and _sess.chara_pending is None
                        and _sess.last_peer_rx[0]
                        and _now - _sess.last_peer_rx[0] > a.session_idle_drop):
                    sessions.pop(_sk, None)
                    print("[docudp] session %s:%d REAPED -- idle %.0f s, "
                          "%d client(s) now"
                          % (_sk[0], _sk[1], _now - _sess.last_peer_rx[0],
                             len(sessions)), flush=True)
                    if session_of(_sess.seen_charid[0]) is None:
                        vacate_seat(_sess.seen_charid[0], "session reaped")
        try:
            fire_battles(_now)                     # sec 4he: room clocks
        except Exception:
            import traceback
            print("  [battle] fire_battles FAILED:\n%s" % traceback.format_exc(),
                  flush=True)
        for _fk, _fdue in list(_fill_start.items()):
            if _now < _fdue:
                continue
            _fill_start.pop(_fk, None)
            try:
                _fm = [m for m in bt_store.members(_fk) if m]
                _frec = bt_store.record(_fk)
                _fmax = min((_frec[tablerecords.BT_OFF_MAX] if _frec else 0)
                            or tableverbs.BT_MAX_MEMBERS, tableverbs.BT_MAX_MEMBERS)
                if (not _fm or _frec is None or len(_fm) < _fmax
                        or _briefing_running(_fk) or bt_store.in_progress(_fk)):
                    print("  [fill-start] table %d: no longer full / already "
                          "started -- nothing to do" % _fk, flush=True)
                    continue
                print("  [fill-start] table %d is FULL (%d/%d) -- everyone "
                      "goes to the briefing room (manual p.29)"
                      % (_fk, len(_fm), _fmax), flush=True)
                begin_briefing(_fk, bt_store.leader_cid(_fk), _fm)
            except Exception:
                import traceback
                print("  [fill-start] FAILED:\n%s" % traceback.format_exc(),
                      flush=True)
        for _rk, _rdue in list(_rematch.items()):
            if _now < _rdue:
                continue
            # wait until every seated player is back in the lobby (no game-
            # server request for REMATCH_QUIET_S, poses still arriving)
            _since = _rematch_since.get(_rk, _rdue)
            _seated = [m for m in bt_store.members(_rk) if m]
            _away = [m for m in _seated
                     if not (_now - _last_gs_req.get(m, 0.0) >= REMATCH_QUIET_S
                             and _now - _last_pose_rx.get(m, 0.0) <= 3.0)]
            if _away and _now - _since < REMATCH_LOBBY_CAP_S:
                if int(_now - _since) % 5 == 0 and _rematch_logged.get(_rk) != int(_now - _since):
                    _rematch_logged[_rk] = int(_now - _since)
                    print("  [rematch] table %d waiting for %s to reach the lobby "
                          "(last game-server request / pose, s ago: %s)"
                          % (_rk, ", ".join("0x%08x" % m for m in _away),
                             ", ".join("%.0f/%.0f" % (_now - _last_gs_req.get(m, 0.0),
                                                      _now - _last_pose_rx.get(m, 0.0))
                                       for m in _away)), flush=True)
                continue
            for _m in _away:
                bt_store.cancel(_m)
                send_reservation_clear(_m, why="not back in the lobby %.0f s after "
                                       "table %d's battle" % (_now - _since, _rk))
                print("  [rematch] table %d: 0x%08x not back in the lobby after "
                      "%.0f s -- seat given up" % (_rk, _m, _now - _since), flush=True)
            _rematch.pop(_rk, None)
            _rematch_since.pop(_rk, None)
            try:
                start_rematch(_rk)
            except Exception:
                import traceback
                print("  [rematch] FAILED:\n%s" % traceback.format_exc(),
                      flush=True)
        _wd = weekly_deadline()
        if _wd is not None and _now >= _wd:
            try:
                weekly_close("week rollover")
            except Exception:
                import traceback
                print("  [stats] weekly close FAILED:\n%s"
                      % traceback.format_exc(), flush=True)
        _dl = next_deadline(_now)
        if _dl is not None:
            if not select.select([s], [], [], max(0.0, _dl - _now))[0]:
                _t = datetime.datetime.now().timestamp()
                for _sess in list(sessions.values()):
                    fire_keepalives(_sess, _t)
                continue
        try:
            data, src = s.recvfrom(65535)
        except ConnectionResetError:
            # Windows only: a datagram we sent to a client that has since
            # closed its socket comes back as an ICMP port-unreachable, and
            # Winsock reports it here on the next receive. Nothing was
            # received, so there is nothing to answer.
            continue
        # The addresses THIS sender can reach (host_for): every reply below that
        # carries one uses these, not a.lobby_ip / _gs_endpoint directly.
        _lip = advertise.host_for(a.lobby_ip, src[0])
        _gsip = advertise.host_for(_gs_endpoint, src[0])
        _bt_echo_key = None  # sec 4fl: JOIN-ok reservation echo target
        n += 1
        # sec 4fq: --peer is an ALLOWLIST now. A source not on it gets no session
        # and moves no state (the old single-global session let the 2nd client
        # clobber the 1st and die at CER-48104).
        if peer_allow and src[0] not in peer_allow:
            ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print("\n[%s] RECV #%d from %s:%d  %d bytes -- (ignoring: not in "
                  "--peer %s)" % (ts, n, src[0], src[1], len(data),
                                  sorted(peer_allow)), flush=True)
            continue
        # sec 4fq: bind (or create) THIS client's session, then rebind the boxed
        # per-client state so every existing name[0] access below is per client.
        # sec 4gz: (ip, PORT). One client = one UDP socket (measured, see the
        # `sessions` comment), and a NAT has to give two consoles in one house
        # two different external ports, so this is one session per console.
        sess = sessions.get(src)
        if sess is None:
            sess = sessions[src] = Session(src[0], src[1])
            print("[docudp] NEW CLIENT SESSION %s:%d -- %d client(s) now"
                  % (src[0], src[1], len(sessions)), flush=True)
        current[0] = sess
        sess.src = src
        gs_done = sess.gs_done
        gs_ka_src = sess.gs_ka_src
        gs_ka_next = sess.gs_ka_next
        gs_seq = sess.gs_seq
        gs_teams = sess.gs_teams
        gs_join_deadline = sess.gs_join_deadline
        gs_bots_sent = sess.gs_bots_sent
        gs_join_src = sess.gs_join_src
        gs_rearm_next = sess.gs_rearm_next
        last_pose = sess.last_pose
        last_wu = sess.last_wu
        seen_uid = sess.seen_uid
        seen_charid = sess.seen_charid
        last_stream = sess.last_stream
        last_peer_rx = sess.last_peer_rx
        save_count = sess.save_count
        sess.last_peer_rx[0] = datetime.datetime.now().timestamp()
        if len(data) == 96:
            sess.ka_template = data
            if sess.ka_first is None:
                sess.ka_first = datetime.datetime.now().timestamp()
        if sess.ka_src != src:
            sess.ka_src = src
        # NB: do NOT push ka_next out on inbound traffic (sec 4an).
        now = datetime.datetime.now().timestamp()
        fire_keepalives(sess, now)
        # 2026-09-13: PLAY TIME accrues while a selected character is online.
        if seen_charid[0]:
            _ptk = _pt_key.get((sess.key, seen_charid[0]))
            if _ptk is None:
                _ptk = _pt_key[(sess.key, seen_charid[0])] = _wallet_key(
                    seen_uid[0], seen_charid[0])
            _playtime.touch(sess.key, _ptk, now)
        # sec 4cx: THE CHANNEL CAN BE RESET UNDER US, AND WE NEVER NOTICE.
        # 0x00bc03b8 zeroes [chan+2148] (ready), [chan+204] (the arm bits) and
        # a dozen more fields, and it has four callers -- selector 39's arm
        # 0x00bccf20, the interface close at 0x0058c8c4, 0x00bd2ab0 and
        # 0x00bd75e8. `--gs-connect` only re-fires on a phase-27 round, so a
        # reset inside one world session leaves the item/stat manager reading
        # `[APP NET CLIENT] init item number -1` for the rest of it, exactly as
        # the 08-27 emulog shows: -1, then 0 once we connect, then -1 again at
        # the next zone entry with no reconnect in between.
        # Measured: re-running selector 104 + 38 on a reset channel takes it
        # straight back to ready=1, and on a HEALTHY channel it is harmless --
        # WARNING: except that it CLEARS [chan+204], so the arm must follow it, which
        # is exactly the order the gs_done block already sends them in.
        # WARNING: OFF by default: message 27 is a reward GRANT, and even an empty one
        # writes [array+0]/[array+4]. Arm this only for an experiment, and only
        # with --gs-stats empty.
        if a.gs_rearm_ms > 0 and gs_done[0] and now >= gs_rearm_next[0]:
            gs_rearm_next[0] = now + a.gs_rearm_ms / 1000.0
            gs_done[0] = False
            print("  GAME-SERVER RE-ARM due -- next in-game packet redoes "
                  "selector 104 + 38 + the arm (sec 4cx)", flush=True)
        if a.sweep and (now - last_rx) > BURST_GAP:
            sweep_i += 1
            if sweep_i < len(SWEEP):
                a.ptype, a.subtype, why = SWEEP[sweep_i]
                print("", flush=True)
                print("=" * 72, flush=True)
                print("SWEEP %d/%d -- type=%d subtype=%d   (%s)"
                      % (sweep_i + 1, len(SWEEP), a.ptype, a.subtype, why), flush=True)
                print("=" * 72, flush=True)
            else:
                print("", flush=True)
                print("[docudp] SWEEP EXHAUSTED -- holding at the last candidate",
                      flush=True)
        last_rx = now
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print("\n[%s] RECV #%d from %s:%d  %d bytes" % (ts, n, src[0], src[1], len(data)),
              flush=True)
        inner = None if a.no_decrypt else framing.describe_inner(data)
        if (inner is None and _KELCRYPT and not a.no_decrypt and len(data) >= 40
                and data[1] == 4):
            # 2026-10-03: a table LEADER's IV is [0, X, 0, 0]; learn an X we
            # have not seen from the client's own P2P datagrams
            _lx = doc_kelcrypt.learn_leader_iv(data, now)
            if _lx is None and sess is not None:
                # 2026-10-05: not an IV-only leader -- learn its KEY. The id
                # the header must carry: a 64-byte pose's body +0 (the charid
                # of a 0x83, the NPC id of a type 3), else the session's own.
                _lk_hint = (struct.unpack_from("<I", data, framing.BODY_OFF)[0]
                            if len(data) == framing.BODY_OFF + 40
                            else (sess.seen_charid[0] or sess.wire_cid[0]))
                if _lk_hint:
                    leader_key_search(data, _lk_hint, src)
            if _lx is not None:
                print("  [kelcrypt] LEARNED a leader IV X=0x%08x from %s:%d -- "
                      "its mode-4 headers decrypt from here (%d known)"
                      % (_lx, src[0], src[1], len(doc_kelcrypt.LEADER_IVS)),
                      flush=True)
                inner = framing.describe_inner(data)
        if inner is not None:
            print("  INNER (decrypted) type=0x%02x flags=0x%02x SEQ=%d ack-seq=%d%s%s"
                  % (inner["type"], inner["flags"], inner["seq"], inner["ack_seq"],
                     "  DATA" if inner["is_data"] else "",
                     "  ACK" if inner["is_ack"] else ""), flush=True)
        elif _KELCRYPT and not a.no_decrypt and len(data) >= 24:
            print("  INNER (decrypted) -- REJECTED by its own checksum "
                  "(unexpected mode/key?)", flush=True)
        print(framing.describe(data), flush=True)
        print(framing.hexdump(data), flush=True)
        if a.save:
            fn = os.path.join(a.save, "rx-%03d-%s.bin" % (n, ts.replace(":", "")))
            open(fn, "wb").write(data)
            save_count[0] += 1
            if a.save_max > 0 and save_count[0] % 500 == 1:
                try:
                    _fs = sorted((os.path.getmtime(os.path.join(a.save, f)),
                                  os.path.join(a.save, f))
                                 for f in os.listdir(a.save) if f.startswith("rx-"))
                    for _, _old in _fs[:max(0, len(_fs) - a.save_max)]:
                        os.remove(_old)
                except OSError as e:
                    print("  (save prune failed: %s)" % e, flush=True)

        if a.once and answered:
            continue

        extra_reply = None
        chara_burst_now = False

        # THE WORLD DOOR -- the type-0x7f GAME SERVER answer.
        #
        # Selecting a server at the character list sends a 132-byte mode-1 datagram
        # whose inner type is 127 (main = 128, lobby nest = 129).  Phase 27
        # (0x00ad3ef0) builds it in connectServer 0x00bce620 and prints "called
        # connectServer()."; phase 28 (0x00ad3f68) then calls kelsvc vt+44 =
        # 0x00bdb250 and advances ONLY on [kelsvc+12] == 2 exactly (`bne s0, 2`).
        #
        # Nothing we have ever sent lands on that channel, so the field is left at
        # the state 0x00589890 posted -- 1 -- and the 40 s receive watchdog runs out:
        # getIdle 0x00589a58 compares now - [kelsvc+32] against [kelsvc+8] == 40000,
        # and past it does `[kelsvc+12] = -1; return -1`.  The tick 0x00bcee70 sees
        # -1, takes its `s6 != -2` arm, calls 0x00589dc0(sub, 0xffff441a) -- that
        # constant IS -48102 -- and prints "[KEL LOBBY] lobby connection timeout."
        # That is exactly the observed `catch error = -1(phase = 28)` + CER-48102.
        #
        # The reply is the SAME recipe that already advances the nest, on a different
        # object with looser constants.  Driver 0x005895b0 is shared:
        #
        #     [record+20] body[0]  subchannel, must be <= [kelsvc+16] == 7  (nest: 5)
        #     [record+21] body[1]  SELECTOR -- 2 at state 1 -> arm 0x00589660
        #                          -> sub vt entry 6 = 0x00bc8aa0 (the kel overlay)
        #     [record+24] body[4]  bit 0 MUST be clear
        #
        # 0x00bc8aa0's first act is `0x005894f0(kelsvc+4, sockaddr, record)`, the same
        # m5 that advances the nest: it clears bit 31 of [kelsvc+28] and, iff
        # u16[record+24] & 1 == 0, does `[kelsvc+12] = 2`.  Otherwise it reports
        # -u16[record+26] as an error.  So body[4] carries the ECHOED command with bit
        # 0 doubling as the failure flag, and body[6..7] is the error code.
        #
        # WARNING: The request is MODE 1 and its first 16 body bytes are CIPHERTEXT, so
        # only body[16..] -- which carries the session token, plaintext -- may be
        # echoed.  build_world_answer synthesises body[0..15].  Echoing them put
        # body[0] = 216 on the wire and the driver rejected it at its first gate;
        # see that function's docstring and sec 4bj.
        # ROUTE ON THE INNER TYPE, NOT THE LENGTH.  Phase 28 is not the only round:
        # phases 29 and 31 send again on this same channel, both gated on
        # [kelsvc+12] == 2 and both answered by driving it back to 2 -- the same
        # selector-2 recipe (sec 4bn).  Their requests are NOT 132 bytes:
        # 0x00bd0688 zeroes a 532-byte buffer, writes the u16 arg at buf+32 and
        # adds 4 to the u16 length at buf+18, so each round is its own size.
        # Keying on len == 132 answered phase 28 and nothing after it.
        #
        # WARNING: data[8] IS NOT THE INNER TYPE ON A MODE-1 PACKET.  sec 4bj: mode 1
        # enciphers 32 bytes from offset 8, so pkt[8] is CIPHERTEXT -- the phase-27
        # request reads `type@8=125` on the wire while its decrypted type is 0x7f.
        # Routing on the raw byte therefore silently stopped answering the world
        # door: one boot, zero WORLD-DOOR lines, CER-48102 at the 40 s watchdog.
        # `inner` above is already the DECRYPTED header (describe_inner ->
        # doc_kelcrypt.header, self-checked by its own checksum), so use its type
        # and fall back to the raw byte only for the plaintext modes.
        # >= not >: phase 29's request is EXACTLY 40 bytes (BODY_OFF + 16), a
        # 16-byte body `07 0c 00 00 01 00 00 00 ...`, and `>` excluded it by one
        # byte -- we ACKed it and never answered, so phase 30 polled an empty
        # queue for 9 s and died -47117.  36-byte polls stay excluded.
        # KEY: sec 4fu (briefing, live 09-13): a PEER position datagram whose
        # header we cannot decrypt (the Deck's mode-4 0x83s in the briefing
        # room) -- recognised by its body carrying this client's OWN id, and
        # given the header the client meant, so it reaches the stream/relay
        # path below instead of being read as "GS request <charid & 0xffff>".
        if (inner is None and a.peer_relay != "off"
                and worldpose.peer_pos_id(data) in {i for i in (seen_charid[0],
                                                      sess.pos_id[0]) if i}):
            inner = p2pbattle.synth_peer_inner(data)
            print("  INNER (synthesised) type=0x83 flags=0x08 -- a PEER position "
                  "datagram, id 0x%08x from its body (sec 4fu)"
                  % inner["u32_16"], flush=True)
        _itype = (inner["type"] if inner is not None
                  else (data[8] if len(data) > 8 else -1))
        if _itype == 0x83 and seen_charid[0]:
            _last_pose_rx[seen_charid[0]] = time.time()
        # 2026-10-05: a mission NPC's POSE from the console simulating it
        # (inner type 3, the NPC id at +16 and in the body) -- relayed to the
        # room's other members under --mission-shared-npcs, never parsed as a
        # game-server request (it was "GS request 256/257", the id's low half)
        _npc_pid = p2pbattle.npc_pose(data, inner)
        if _npc_pid is not None:
            if a.mission_shared_npcs == "on":
                try:
                    relay_npc_pose(sess, data, inner, _npc_pid)
                except Exception:
                    import traceback
                    print("  [missions] NPC pose relay FAILED:\n%s"
                          % traceback.format_exc(), flush=True)
            continue
        # sec 4gz: THE CLIENT MAY HAVE MOVED PORT. Before a single field is
        # touched, fold in the session this charid was last playing on (its
        # router re-bound the mapping while the lobby socket idled). Done here,
        # ahead of every state read below, so nothing is written to a session
        # that is about to inherit -- and by copying INTO `sess`, so the boxed
        # locals rebound at the top of this iteration stay the right boxes.
        _pkt_cid = worldchannel.packet_charid(data, inner, _itype, a.world_type)
        if _pkt_cid:
            adopt_session(sess, _pkt_cid, now)
            # WARNING: NOT seen_charid: that is the ladder's own belief (sec 4dv) and
            # every reply, wallet key and table lookup keys on it. This is the
            # identity the WIRE carries, used for session keying and nothing
            # else -- so a client that has only ever streamed position (its
            # charid is in +16, but no type-127 round has landed) can still be
            # re-joined to its own session after a port move.
            sess.wire_cid[0] = _pkt_cid
        # the 2026-09-05 audit 2026-09-05 (A): a NEW SESSION starts at the entrance.
        # Learn the uid there (and again at the world door), and drop every
        # per-session belief the previous player left behind -- the stale uid
        # was measured live on 09-05 (a second account served the first one's
        # uid for its first two user lists) and the same guard answered a
        # fresh container's first user list with the empty body.
        _ue = worldpose.early_uid(data)
        # sec 4ea: THE GAME-SERVER LADDER. A type-130 datagram from the client
        # is a request whose u16 type sits at body[0]; the answer is type + 1
        # (GS_REQ_ANSWERS) and it is what puts [chan+2148] back to 1 so the
        # next request can go out. 47 = leaveBriefingRoom is where stage 4
        # begins: after 48 we push --gs-battle-start.
        _gs_answered = False
        # sec 4eb (live 09-11): the client's game-server requests are MODE 4
        # datagrams -- header enciphered with the third cipher instance we do
        # not hold, body PLAINTEXT. describe_inner rejects them, so the inner
        # type is unreadable; the mode byte alone names the channel.
        # sec 4fu: a mode-4 type-0x83 is a PEER POSITION, not a GS request
        # sec 4he: the P2P BATTLE LAYER (shots, damage, entity messages) is
        # addressed to us and must be RELAYED, never parsed as a GS request.
        _p2pk = p2pbattle.p2p_battle_type(data, inner)
        if _p2pk is None and inner is None and seen_charid[0]:
            # 2026-09-28: the same layer from a client whose mode-4 header
            # we cannot decrypt -- named by its body (p2p_battle_type_mode4)
            _rm4 = battle_of(seen_charid[0])
            _p2pk = p2pbattle.p2p_battle_type_mode4(
                data, inner, seen_charid[0],
                _rm4.members if _rm4 is not None else ())
            if _p2pk is not None:
                _shooter = seen_charid[0]
                if _p2pk == p2pbattle.P2P_SHOT:
                    _shooter = shot_owner(seen_charid[0], data, _rm4)
                inner = p2pbattle.synth_p2p_inner(data, _p2pk, _shooter)
        _srvk = None if _p2pk is not None else p2pbattle.p2p_server_type(data, inner)
        _srvb = bytes(inner["plain"][framing.BODY_OFF:]) if _srvk is not None else None
        if _p2pk is None and _srvk is None:
            _srvk = p2pbattle.p2p_server_type_mode4(data, inner)
            _srvb = bytes(data[framing.BODY_OFF:])   # mode 4: the body is plaintext
        if _srvk is not None:
            try:
                capsule_server(seen_charid[0], _srvk, _srvb)
            except Exception:
                import traceback
                print("  [capsule] FAILED:\n%s" % traceback.format_exc(),
                      flush=True)
            _gs_answered = True     # the reliable ACK stops the 500 ms resend
        if _p2pk in p2pbattle.P2P_SERVER_TYPES:
            try:
                capsule_p2p(sess, inner, _p2pk)
            except Exception:
                import traceback
                print("  [capsule] FAILED:\n%s" % traceback.format_exc(),
                      flush=True)
            _p2pk = None
        if _p2pk is not None and a.p2p_relay:
            try:
                relay_p2p_battle(sess, inner, _p2pk)
            except Exception:
                import traceback
                print("  [p2p] relay FAILED:\n%s" % traceback.format_exc(),
                      flush=True)
        _gs_mode4 = (len(data) >= framing.BODY_OFF + 2 and data[1] == 4
                     and _itype != 0x83 and _p2pk is None and _srvk is None)
        if (a.gs_answer and len(data) >= framing.BODY_OFF + 2
                and (_gs_mode4 or (_itype == gamemsg.GS_INNER_TYPE and inner is not None
                                   and inner["is_data"]))):
            _gmt, _gbody = gamemsg.gs_request_type(data, inner)
            if _gmt is not None and seen_charid[0]:
                _last_gs_req[seen_charid[0]] = time.time()
                if _gmt == 24:
                    _last_gs24[seen_charid[0]] = time.time()
                    # 2026-10-05: the 1 Hz report carries the player's own
                    # position in the clear (body+24 id, +28 x/y/z floats);
                    # a console whose 0x83 stream we cannot read had no
                    # arena pose at all (base occupation, near-the-player
                    # replacements and Reraise all read _battle_pose)
                    if _gbody is not None and len(_gbody) >= 40:
                        _rid = struct.unpack_from("<I", _gbody, 24)[0] & 0x3FFFFFFF
                        _rxyz = struct.unpack_from("<3f", _gbody, 28)
                        _bp0 = _battle_pose.get(seen_charid[0])
                        if (_rid == seen_charid[0] & 0x3FFFFFFF
                                and all(math.isfinite(v) and abs(v) < 100000.0
                                        for v in _rxyz)
                                and (_bp0 is None or time.time() - _bp0[3] > 2.0)):
                            _battle_pose[seen_charid[0]] = _rxyz + (time.time(),)
            # 2026-09-24: in a TEAM BASE battle the controller reports base HP
            # in request 24 (proto builder 0x00bc06d0: up to 4 x {u32 HP, u16
            # index, u16 0, u32 attacker mask}, count at body+61 -- retail
            # layout not re-derived). Dump it (every 5 s) until it is decoded.
            if _gmt == 24 and _gbody is not None:
                _bs24 = _base_setup(sess)
                _br24 = battle_of(seen_charid[0])
                if (_bs24 is not None and _br24 is not None
                        and seen_charid[0] == _bs24[2]):
                    try:
                        base_report_in(_br24, _bs24, arenadata.base_report(_gbody),
                                       zone=_battle_zone(sess.key,
                                                         seen_charid[0]))
                    except Exception:
                        import traceback
                        print("  [base] report FAILED:" + chr(10) + "%s"
                              % traceback.format_exc(), flush=True)
            if (_gmt == 44 and _gbody is not None
                    and sess.key in _supply_bag
                    and _supply_44.get(sess.key) != sess.gs_battle_on[0]):
                # the kind-4 reply is resent (0.5/1/2 s); count one per battle
                _supply_44[sess.key] = sess.gs_battle_on[0]
                _fired = doc_shop.fired_counts(_gbody)
                _held = _supply_bag[sess.key]
                for _fi, _fn in _fired.items():
                    _held[_fi] = max(0, _held.get(_fi, 0) - _fn)
                print("  [supplies] 0x%08x fired %s this battle -> holds %s"
                      % (seen_charid[0], ", ".join("0x%08x x%d" % f for f in
                                                   sorted(_fired.items()))
                         or "nothing",
                         ", ".join("0x%08x x%d" % h for h in
                                   sorted(_held.items()))), flush=True)
            _gname = gamemsg.GS_REQ_NAMES.get(_gmt, "?")
            if _gmt != 1:
                # the raw datagram too: request 24's header is often enciphered
                _bcr = battle_of(seen_charid[0])
                battle_capture("gs", type=_gmt, name=_gname,
                               sender=seen_charid[0],
                               table=_bcr.key if _bcr is not None else None,
                               body=_gbody or b"", raw=data)
            # 2026-09-23: a mission's enemy HP rides the 1 Hz report in the
            # clear even when the header is not readable (mission_npc_report).
            _npcs = gamemsg.mission_npc_report(data)
            # 2026-10-05: a room's shared enemies are simulated by ONE console;
            # another member's report lists its own idle copy (HP 100) and
            # would undo the controller's damage (live: 100 -> 60 -> 100).
            _mn24 = _mnpc.get(sess)
            if _npcs and _mn24 is not None and _mn24.get("csess", sess) is not sess:
                _npcs = []
            if _npcs:
                if _mn24 is not None:
                    _mn24["seen"] = {_n for _n, _hp in _npcs}
                _rmn = battle_of(seen_charid[0])
                if _rmn is not None and _rmn.mission is not None:
                    _me24 = seen_charid[0] or (_rmn.members[0] if _rmn.members else 0)
                    _died = _rmn.npc_hp_update(
                        _npcs, _me24, time.time(),
                        credit=(_mn24 or {}).get("last_hit"),
                        types=(_mn24 or {}).get("types"))
                    if _died:
                        print("  [missions] enemy down (1 Hz report): %s -> %d "
                              "enemy kill(s) for 0x%x%s"
                              % (["0x%x" % d for d in _died], _rmn.npc_kills,
                                 _me24, "; " + _rmn.why if _rmn.over else ""),
                              flush=True)
                        _mn = _mnpc.get(sess)
                        # 2026-10-05: each death rolls the enemy's own drop
                        # where this report last placed it
                        _dpos = gamemsg.mission_npc_positions(data)
                        for _d in _died:
                            enemy_drop(_rmn, _mn, _d, _dpos.get(_d))
                        if _mn is not None:
                            _mn.setdefault("dead", set()).update(_died)
                            # 2026-10-05: release each dead enemy on the clients
                            # (kind 22) when its body has lain MISSION_EXTINCT_S
                            for _d in _died:
                                _mn.setdefault("extinct", []).append(
                                    (time.time() + MISSION_EXTINCT_S, _d))
                        if _mn is not None and not _rmn.over:
                            for _d in _died:
                                _mn["due"].append((time.time() + 5.0,
                                                   _mn["types"].get(_d, 0)))
                        if _rmn.over:
                            end_battle(_rmn, time.time())
            _gs_was_up = sess.gs_src[0] is not None
            sess.gs_src[0] = src     # sec 4ft: its channel is up -- pushable
            # 2026-10-01, manual p.30: "you get various consumables on
            # entering the briefing room". The channel coming up after Start
            # (38 cleared gs_src) is that arrival. The grant at request 47
            # stays as the backstop; supply_grant only tops up what is missing.
            if (not _gs_was_up and seen_charid[0] and not sess.gs_battle_on[0]):
                _bk = bt_store.table_of(seen_charid[0])
                if _bk is not None and (gs_tables.get(_bk) or {}).get("started"):
                    issue_supplies(sess, src)
            # 2026-09-23: a member whose channel comes up AFTER the others
            # picked their teams never heard about them (sync ran only on
            # someone's 31). Catch it up now.
            if (not _gs_was_up and a.gs_real_roster and seen_charid[0]):
                _uk = bt_store.table_of(seen_charid[0])
                if (_uk is not None and _uk in gs_tables
                        and len([m for m in bt_store.members(_uk) if m]) >= 2):
                    try:
                        gs_sync_table(_uk)
                    except Exception:
                        import traceback
                        print("  [roster] gs_sync_table (channel up) FAILED:\n%s"
                              % traceback.format_exc(), flush=True)
            _garg = (struct.unpack_from("<I", _gbody, 8)[0]
                     if _gbody is not None and len(_gbody) >= 12 else None)
            if _gmt == 1:
                s.sendto(gamemsg.build_gs_message(1, seq=next_gs_seq(sess),
                                          ident=seen_charid[0]), src)
                _gs_answered = True
                print("  GS request 1 (keepalive) -> SENT 1 (the [chan+224] "
                      "stamp)", flush=True)
                if sess.gs_rearm_pending[0]:
                    # the team-join
                    # builder sends request 31 only while [chan+204] & 0x40 is
                    # set, and ONLY message 27 sets it. Keepalives flow without
                    # it, so a lost / early 27 leaves a client that can never
                    # join a team (it sends nothing but request 1). Arm again until its first 31/33 proves it is armed.
                    # WARNING: EMPTY on purpose: message 27 is also a reward GRANT
                    # (--gs-stats), and this one repeats every 7 s
                    s.sendto(gamemsg.build_gs_stats([], state=a.gs_arm_state,
                                            seq=next_gs_seq(sess),
                                            ident=seen_charid[0]), src)
                    print("  SENT GAME-SERVER RE-ARM (message %d) on the "
                          "keepalive -- no team request from 0x%08x since its "
                          "38 yet" % (gamemsg.GS_ARM_MSG, seen_charid[0] or 0),
                          flush=True)
            elif _gmt == gamemsg.GS_KILL_REQ:
                # sec 4he: the VICTIM's client reports its own death. Tally,
                # then kind 9 to everyone -- the only thing that moves the
                # team points [chan+1340..] and the kill / death counters.
                _gs_answered = True
                _kr = gamemsg.gs_kill_report(inner, _gbody)
                _room30 = battle_of(seen_charid[0])
                _kdd = 1.0
                if (_kr is None and _room30 is not None
                        and _room30.mission is not None
                        and _gbody is not None and len(_gbody) >= 12):
                    # 2026-09-23: header unreadable (per-boot game-server key),
                    # but the KILLER at body+8 is plaintext. In a mission an
                    # NPC killer means the player died; the player's own kills
                    # arrive through the 1 Hz report instead. The client
                    # resends an unacknowledged report, so dedupe over 5 s.
                    _kkil = struct.unpack_from("<I", _gbody, 8)[0]
                    if _kkil and _kkil not in _room30.kills and seen_charid[0]:
                        _kr, _kdd = (_kkil, seen_charid[0]), 10.0
                if (_kr is None and _room30 is not None
                        and _room30.mission is None and seen_charid[0]
                        and _gbody is not None and len(_gbody) >= 12):
                    # 2026-09-28 (Dirge report, table 6 TBT): the same unreadable
                    # header in PvP. The killer at body+8 is another SEATED
                    # player and the sender is the victim; before this only
                    # missions read it, so a PvP death was never tallied, no
                    # kind 9 / 25 / 13 went out, and the killer watched a
                    # corpse until the battle ended. Resends run ~8 s, past
                    # the 4 s respawn, hence the 10 s dedupe.
                    _kkil = struct.unpack_from("<I", _gbody, 8)[0]
                    if _kkil in _room30.kills and _kkil != seen_charid[0]:
                        _kr, _kdd = (_kkil, seen_charid[0]), 10.0
                if (_kr is None and not (_gbody is not None and len(_gbody) >= 12
                        and struct.unpack_from("<I", _gbody, 8)[0]
                        == (seen_charid[0] or -1))):
                    # the fallback was skipped with the room
                    # open -- say exactly which condition failed.
                    print("  GS request 30 fallback skipped: me=0x%x room=%s "
                          "mission=%s body=%s kills=%s"
                          % (seen_charid[0] or 0,
                             None if _room30 is None else _room30.key,
                             None if _room30 is None else _room30.mission,
                             _gbody.hex() if _gbody else None,
                             None if _room30 is None else
                             ["0x%x" % k for k in _room30.kills]), flush=True)
                if _kr is None or _room30 is None:
                    print("  GS request 30 (KILL REPORT) %s -- %s"
                          % ("0x%x killed 0x%x" % _kr if _kr else "unreadable",
                             "no room for 0x%08x" % (seen_charid[0] or 0)
                             if _kr else "dropped"), flush=True)
                else:
                    _was_over30 = _room30.over
                    # 2026-10-05: an enemy's TYPE, so "defeat N X" counts only X
                    # whichever of request 30 / the 1 Hz report lands first
                    _mn30 = _room_mnpc.get(_room30.key) or _mnpc.get(sess) or {}
                    _kf = _room30.kill(_kr[0], _kr[1], time.time(), dedupe_s=_kdd,
                                       npc_type=_mn30.get("types", {}).get(_kr[1]))
                    if _kf is None:
                        print("  GS request 30 (KILL REPORT) 0x%x killed 0x%x -- "
                              "duplicate / not a member, ignored" % _kr,
                              flush=True)
                        # 2026-09-26: a MISSION enemy kill (victim not a
                        # member) returns None but can complete a "kill"
                        # objective -- the room was marked over and never
                        # ended (found by doc_launch_e2e's exam clear)
                        if _room30.over and not _was_over30:
                            end_battle(_room30, time.time())
                    else:
                        push_kill_event(_room30, _kf)
                        # 2026-10-06: a KO'd capsule carrier drops its capsules
                        # where it fell -- the server's job (fielditems)
                        if (fielditems.capsule_count(_room30) > 0
                                and _room30.holders.get(_kr[1], 0) > 0):
                            _vp30 = _battle_pose.get(_kr[1])
                            _cm, _cn = fielditems.capsule_ko_drop(
                                _room30, _kr[1], _vp30[:3] if _vp30 else None)
                            if _cn:
                                _capsule_after(_room30, _kr[1], _cm, _cn)
                            else:
                                print("  [capsule] 0x%x KO'd holding %d capsule(s) "
                                      "but no pose is known -- not dropped"
                                      % (_kr[1], _room30.holders.get(_kr[1], 0)),
                                      flush=True)
                        if (a.respawn_kind and not _room30.over
                                and _kr[1] in _room30.dead_until):
                            push_down(_room30, _kr[1])
                        print("  GS request 30 (KILL REPORT) 0x%x killed 0x%x -> "
                              "SENT notify 9 to %d member(s): points %s%s%s"
                              % (_kr[0], _kr[1], len(_room30.present()),
                                 _kf[0], " (one from the target)" if _kf[3]
                                 else "", "; " + _room30.why if _room30.over
                                 else ""), flush=True)
                        if _room30.over:
                            end_battle(_room30, time.time())
            elif _gmt == gamemsg.GS_REVIVE_REQ:
                # RETRACTED 2026-09-23: request 43 is NOT a Phoenix Down. Its
                # only builder caller is 0x00bc9be8, called first thing by the
                # kind-9 arm 0x00bc9e70: every client ACKS every kill notice
                # with it. Answering it with a revive gave every death an
                # instant "Phoenix Down" (live: revived with the Phoenix Down
                # animation without using one). The message table 0x00bf0070
                # has no handler for 44, so nothing is sent.
                _gs_answered = True
                print("  GS request 43 (ack of the kill notice) from 0x%x -- "
                      "no answer" % (seen_charid[0] or 0), flush=True)
            elif _gmt == gamemsg.GS_ITEM_USE_REQ and a.item_use_answer != "off":
                # a Potion in battle sent request 21 and the
                # client kept resending it. Request 21 = {u16 21, u16 session,
                # u32 0, u32 ITEM} (builder 0x00bc53f0, arena state); there is
                # no target -- an item is used on oneself.
                # 2026-09-26 (doc_items, emulated): message 22 IS THE EFFECT.
                # Its arm stores body+8 for the unit named by the ident (self
                # or a teammate record) and the next tick runs "receiveUseItem"
                # -> the item's effect script: Potion 301 HEAL 150 -> the
                # client's own R+44 (lasts, no push needed); Ether 334 MP +50
                # on the LOCAL chara only (R+48 overwrites it every frame), so
                # the server pushes kind 44. The CLIENT took the item out of
                # its bag when it sent the request (0x00be6c08), so every NEW
                # use is answered -- live, three uses (seqs 3147,
                # 3151, 3152 in 0.3 s) got ONE answer under the old 10 s
                # window. A resend = the same transport seq, or (header
                # unreadable) the same item on the reliable resend schedule.
                _gs_answered = True
                _itm = (struct.unpack_from("<I", _gbody, 8)[0]
                        if _gbody is not None and len(_gbody) >= 12 else 0)
                _me21 = seen_charid[0] or 0
                _now21 = time.time()
                _seq21 = (inner.get("seq") if inner is not None
                          and inner.get("is_data") else None)
                _new21, _why21 = _item_uses.use(_me21, _itm, _now21, seq=_seq21)
                if not _new21:
                    print("  GS request 21 (USE ITEM 0x%08x) from 0x%08x: %s -- "
                          "answered already" % (_itm, _me21, _why21), flush=True)
                else:
                    _room21 = battle_of(_me21) if _me21 else None
                    _to21 = [_me21]
                    if _room21 is not None and a.item_use_broadcast == "on":
                        _to21 += [m for m in _room21.present() if m != _me21]
                    _sent21 = 0
                    for _m21 in _to21:
                        if _m21 == _me21:
                            _ms21, _dst21 = sess, src
                        else:
                            _ms21, _dst21 = member_dst(_m21)
                        if _dst21 is None:
                            continue
                        s.sendto(gamemsg.build_item_use_answer(
                            _itm, seq=next_gs_seq(_ms21), ident=_me21), _dst21)
                        _sent21 += 1
                    _bag21 = ""
                    if sess.key in _supply_bag and _itm in _supply_bag[sess.key]:
                        _h21 = _supply_bag[sess.key]
                        _h21[_itm] = max(0, _h21[_itm] - 1)
                        _bag21 = "; supplies 0x%08x -> x%d" % (_itm, _h21[_itm])
                    print("  GS request 21 (USE ITEM 0x%08x) from 0x%08x (%s) -> "
                          "SENT message 22 {ident = 0x%08x, body+8 = item} to %d "
                          "member(s)%s%s"
                          % (_itm, _me21, _why21, _me21, _sent21,
                             " (HP +%d on the client)" % doc_items.ITEM_HP[_itm]
                             if _itm in doc_items.ITEM_HP else "", _bag21),
                          flush=True)
                    if (_itm in doc_items.ITEM_MP and a.mp_model == "ledger"
                            and _me21):
                        _bk21, _rs21 = _mp_battle(_room21)
                        push_mp(_me21, _magic.credit(
                            _me21, _bk21, doc_items.ITEM_MP[_itm], _rs21),
                            "item 0x%08x +%d" % (_itm, doc_items.ITEM_MP[_itm]))
            elif _gmt == gamemsg.GS_MAGIC_REQ and a.mp_model != "zero":
                # one Fire cast = request 60 arg
                # 0x10001, resent at +0.6/+1.6/+3.6/+7.6 s, each answered with
                # the ZERO 61 -> MP 0 for the rest of the battle ("cast once,
                # then couldn't"). build_magic_answer has the client side;
                # doc_magic.Ledger prices the cast (element / level from the
                # arg, Magic Suit x0.6) and charges each cast ONCE -- a
                # same-spell copy on the resend schedule is answered with the
                # same MP. Every copy is answered: a lost 61 would otherwise
                # leave the client's request slot outstanding.
                _gs_answered = True
                _mcid = seen_charid[0] or 0
                _mroom = battle_of(_mcid) if _mcid else None
                _mnote = "full MP"
                _mmp = doc_magic.MP_MAX
                if a.mp_model == "ledger":
                    _mbk = ((_mroom.key, _mroom.opened) if _mroom is not None
                            else ("no room",))
                    _mres = (_mroom is not None and doc_magic.magic_restricted(
                        _mroom.rules.flags, _mroom.rules.restrictions))
                    _mmp, _mcost, _mnote = _magic.cast(
                        _mcid, _mbk, _garg or 0, time.time(),
                        suit=getattr(sess, "suit_item", None), restricted=_mres)
                s.sendto(gamemsg.build_magic_answer(_mmp, seq=next_gs_seq(sess),
                                            ident=_mcid), src)
                print("  GS request 60 (MAGIC CAST, element %d level %d) from "
                      "0x%x -> SENT 61 {status 0, MP %d} -- %s"
                      % ((_garg or 0) & 0xFFFF, ((_garg or 0) >> 16) & 0xFFFF,
                         _mcid, _mmp, _mnote), flush=True)
                if (_garg or 0) & 0xFFFF == 4:
                    # 2026-09-26 (doc_mp_heal_proof, emulated): a Cure's HEAL
                    # is the caster's type-113 entry with NEGATIVE damage,
                    # which we relay; the healed client applies it to its own
                    # R+44 (0x00be99d8 -> 0x00bdf7f0), the HP store itself,
                    # and the caster applies its own entries locally. Nothing
                    # to push.
                    print("  [magic] Cure/Bind: the heal rides the caster's "
                          "113 (relayed); each target applies it to its own "
                          "HP", flush=True)
            elif _gmt == gamemsg.GS_STATUS_REQ and a.status_echo:
                # 2026-10-01 (retail, re-battle/revive_emu.py): request 46 =
                # {u16 46, u16 session, u32 seconds, u32 NEW STATUS WORD},
                # fire and forget. Our 47 had no handler on the retail build,
                # so nothing ever came of it: Limit Break (bit 0x20) only
                # STARTS when the server echoes the status as notify kind 43
                # (arm 0x00bcc790, ident = the character), and Reraise (bit
                # 0x08, a Phoenix Down) shows only through the same push. A
                # table that bans Limit Break (wire+116 bit 0x04) gets the
                # bit back stripped, so it never starts.
                _gs_answered = True
                _scid = seen_charid[0] or 0
                _sroom = battle_of(_scid) if _scid else None
                _sval = (_garg or 0) & 0xFFFFFFFF
                if (_sroom is not None and _sroom.rules.flags
                        & tablerecords.BT_FLAG_HAS_RESTRICT
                        and _sroom.rules.restrictions & gamemsg.RESTRICT_LIMIT_BREAK
                        and _sval & gamemsg.STATUS_LIMIT_BREAK):
                    _sval &= ~gamemsg.STATUS_LIMIT_BREAK & 0xFFFFFFFF
                    print("  [status] 0x%08x: Limit Break is banned at table %d "
                          "-- echoed without it" % (_scid, _sroom.key), flush=True)
                # 2026-10-05: the same for a Bomb Fragment (lit = status 0x40,
                # the table's "Bomb Fragments banned" rule = wire+116 bit 0x10)
                if (_sroom is not None and _sroom.rules.flags
                        & tablerecords.BT_FLAG_HAS_RESTRICT
                        and _sroom.rules.restrictions & gamemsg.RESTRICT_BOMB
                        and _sval & gamemsg.STATUS_BOMB):
                    _sval &= ~gamemsg.STATUS_BOMB & 0xFFFFFFFF
                    print("  [status] 0x%08x: Bomb Fragments are banned at table %d "
                          "-- echoed without the lit bomb" % (_scid, _sroom.key), flush=True)
                _status[_scid] = _sval
                _sto = ([m for m in _sroom.present()] if _sroom is not None
                        else [_scid])
                for _sm in _sto:
                    _sms, _sdst = member_dst(_sm) if _sroom is not None else (sess, src)
                    if _sdst is None:
                        continue
                    s.sendto(gamemsg.build_gs_notify(
                        gamemsg.GS_KIND_STATUS, struct.pack("<I", _sval),
                        seq=next_gs_seq(_sms), ident=_scid), _sdst)
                print("  GS request 46 (STATUS) from 0x%08x: 0x%08x -> SENT "
                      "notify kind 43 to %d member(s)%s"
                      % (_scid, _sval, len(_sto),
                         " [Limit Break ON]" if _sval & gamemsg.STATUS_LIMIT_BREAK
                         else ""), flush=True)
            elif _gmt in gamemsg.GS_REQ_ANSWERS:
                _gans = gamemsg.GS_REQ_ANSWERS[_gmt]
                _g32 = b""
                if (_gmt == 31 and a.team_full_refuse and seen_charid[0]
                        and (_garg or 0) & 0xFF < gamemsg.GS_TEAM_NONE):
                    # 2026-10-01, manual p.30: "a team that is already full
                    # cannot be joined". Answer 32's u32 body[4..7] < 0 is
                    # the refusal (stub 0x00bc9538 -> facade +0x23c ->
                    # CER-44301 "This team cannot accept any more members.",
                    # MEASURED on the retail build, re-visibility); the
                    # client has no cap of its own. A side holds half the
                    # table's limit, rounded up; a mission is co-op.
                    _fk = bt_store.table_of(seen_charid[0])
                    _frec = bt_store.record(_fk) if _fk is not None else None
                    if (_frec is not None and not struct.unpack_from(
                            "<I", _frec, tablerecords.BT_OFF_FLAGS)[0]
                            & tablerecords.BT_FLAG_MISSION):
                        _ft = (_garg or 0) & 0xFF
                        _fmax = _frec[tablerecords.BT_OFF_MAX] or len(
                            bt_store.members(_fk))
                        _fon = [m for m, t in gs_table_state(_fk)["teams"].items()
                                if t == _ft and m != seen_charid[0]]
                        if _fmax and len(_fon) >= (_fmax + 1) // 2:
                            _g32 = struct.pack("<i", -gamemsg.CER_TEAM_FULL)
                            print("  [roster] 0x%08x: team %d at table %d is FULL "
                                  "(%d of %d) -- 32 refuses with CER-%d"
                                  % (seen_charid[0], _ft, _fk, len(_fon),
                                     (_fmax + 1) // 2, gamemsg.CER_TEAM_FULL),
                                  flush=True)
                            _garg = gamemsg.GS_TEAM_NONE    # = on no team
                if _gans == 57:
                    _gp = gamemsg.build_gs_team_list(
                        [(0, 0, seen_charid[0])], seq=next_gs_seq(sess),
                        ident=seen_charid[0])
                else:
                    _gp = gamemsg.build_gs_message(_gans, seq=next_gs_seq(sess),
                                           body_extra=_g32,
                                           ident=seen_charid[0])
                s.sendto(_gp, src)
                _gs_answered = True
                print("  GS request %d (%s, arg %s) -> SENT %d  [the stub sets "
                      "[chan+2148] = 1 again]"
                      % (_gmt, _gname, "0x%x" % _garg if _garg is not None else "-",
                         _gans), flush=True)
                # sec 4fn (live 2026-09-12): the briefing room re-sends
                # request 31 every 1-4 s (22:04:24.4, :25.4, :27.4, :31.4 ...),
                # so pushing the bots on EVERY 31 churned the team space and
                # the join timer below never fired. Push once per 38.
                # sec 4ft: a table with 2+ REAL seated members gets the real
                # roster (gs_sync_table below) instead of bots.
                if _gmt in (31, 33):
                    sess.gs_rearm_pending[0] = False   # it is armed
                _real_key = None
                if _gmt in (31, 33) and a.gs_real_roster and seen_charid[0]:
                    _tk31 = bt_store.table_of(seen_charid[0])
                    _mem31 = ([m for m in bt_store.members(_tk31) if m]
                              if _tk31 is not None else [])
                    if seen_charid[0] in _mem31 and len(_mem31) >= 2:
                        _real_key = _tk31
                if (_gmt == 31 and _real_key is None
                        and (a.gs_fake_teammates > 0 or a.gs_team_notify)
                        and not gs_bots_sent[0]):
                    gs_bots_sent[0] = True
                    # sec 4ek: the player got the "battle ready, hit OK" prompt
                    # only when the DISTRIBUTION (kind 20, facade 0x1000) fired --
                    # but with a 1-member team it bounced to ID_NO_USE -> title.
                    # Now: populate BOTH teams with bots (kind 31, slot=0, one
                    # clean team each, no count churn), THEN finalize over that
                    # full both-teams roster. A valid roster is the natural
                    # reason the client would proceed into the battle instead of
                    # the "cannot proceed" window.
                    _team = (_garg or 0) & 0xFF
                    gs_teams[seen_charid[0]] = _team
                    _roster = [(seen_charid[0], _team)]
                    _mq = _mission_battle.get(sess.key)
                    if _mq is not None:
                        print("  [quest] MISSION battle (quest %d): no fake "
                              "teammates -- the player is seated alone; arena "
                              "zone %d" % (_mq, _battle_zone(sess.key,
                                                            seen_charid[0])),
                              flush=True)
                    if a.gs_fake_teammates > 0 and _mq is None:
                        for _t in (0, 1):
                            for _k in range(1, a.gs_fake_teammates + 1):
                                _bot = (a.gs_fake_team_base + _t * 0x100 + _k) \
                                    & 0xFFFFFFFF
                                if _bot == seen_charid[0]:
                                    continue
                                gs_teams[_bot] = _t
                                s.sendto(gamemsg.build_gs_add_chara(
                                    _bot, _t, slot=0, seq=next_gs_seq(sess),
                                    self_ident=seen_charid[0]), src)
                                _roster.append((_bot, _t))
                        print("  SENT %d FAKE TEAMMATE(s) PER TEAM (notify 31) -- "
                              "both teams populated, %d total incl. self (sec 4ek)"
                              % (a.gs_fake_teammates, len(_roster)), flush=True)
                    if a.gs_team_notify:
                        _dist = [(cid, tm, i)
                                 for i, (cid, tm) in enumerate(_roster)]
                        s.sendto(gamemsg.build_gs_distribution(
                            _dist, seq=next_gs_seq(sess), ident=seen_charid[0]), src)
                        print("  SENT notify 20 (PLAYER DISTRIBUTION, FINALIZE) "
                              "over a %d-member both-teams roster -- posts facade "
                              "0x1000. Watch: does the client ENTER THE ARENA now, "
                              "or still ID_NO_USE -> title? (sec 4ek)"
                              % len(_roster), flush=True)
                if (_real_key is None and _gmt in (31, 33) and seen_charid[0]
                        and a.gs_real_roster):
                    # a SOLO table never reaches gs_sync_table, so its player got
                    # a bare 32 and the Ready row stayed 0 until the kind-20
                    # distribution. Kind 0 to itself is the +1;
                    # kind 1 takes it back off on 33. The client
                    # re-sends 31 every 0.5-4 s; a repeat Set Team to the same
                    # team is dec+inc = no change.
                    _me = seen_charid[0]
                    _st = (_garg or 0) & 0xFF if _gmt == 31 else gamemsg.GS_TEAM_NONE
                    if _st < gamemsg.GS_TEAM_NONE:
                        s.sendto(gamemsg.build_gs_team_set(_me, _st, seq=next_gs_seq(sess)),
                                 src)
                        print("  [roster] solo: SENT notify 0 (set team) 0x%08x "
                              "-> team %d to ITSELF" % (_me, _st), flush=True)
                    else:
                        s.sendto(gamemsg.build_gs_team_leave(_me, seq=next_gs_seq(sess)),
                                 src)
                        print("  [roster] solo: SENT notify 1 (leave team) "
                              "0x%08x to ITSELF" % _me, flush=True)
                if _real_key is not None:
                    _g31 = gs_table_state(_real_key)
                    # request 33 = leaveTeam (the player stepped OFF a space)
                    _t31 = (_garg or 0) & 0xFF if _gmt == 31 else gamemsg.GS_TEAM_NONE
                    _me = seen_charid[0]
                    if _t31 < gamemsg.GS_TEAM_NONE:
                        if _g31["teams"].get(_me) != _t31:
                            print("  [roster] 0x%08x is on team %d at table %d "
                                  "(%d seated, real roster, sec 4ft)"
                                  % (_me, _t31, _real_key,
                                     len(bt_store.members(_real_key))),
                                  flush=True)
                        _g31["teams"][_me] = _t31
                    elif _g31["teams"].pop(_me, None) is not None:
                        print("  [roster] 0x%08x left its team (arg 0x%x) at "
                              "table %d" % (_me, _t31, _real_key), flush=True)
                    try:
                        gs_sync_table(_real_key)
                    except Exception:   # a shared-table bug must not take
                        import traceback  # docudp down for BOTH clients
                        print("  [roster] gs_sync_table FAILED:\n%s"
                              % traceback.format_exc(), flush=True)
                # 2026-10-05 (live 01:38, the deploy restart): consoles in a
                # briefing room RETRANSMIT an unanswered 31 from before the
                # restart (seq behind their poses); the new server had no
                # such table, armed this timer and its kind 2 FROZE them
                # (handler 0x00bca5c8 -> 0x00be4180; only kind 5 or selector
                # 39 thaws). Every game-server request echoes the table key
                # selector 38 gave it (body+2, [chan+220]): a key this server
                # does not seat the player at is a table it forgot -- no timer.
                _sk31 = (struct.unpack_from("<H", _gbody, 2)[0]
                         if _gbody is not None and len(_gbody) >= 4 else 0)
                _stale31 = _gmt == 31 and forgotten_table(_sk31, seen_charid[0])
                if _stale31 and a.gs_battle_after_join > 0:
                    print("  [gs] request 31 from 0x%08x echoes table %d, which "
                          "this server does not seat it at (a table from before "
                          "a restart?) -- battle start NOT armed"
                          % (seen_charid[0] or 0, _sk31), flush=True)
                if _gmt == 31 and a.gs_battle_after_join > 0 and not _stale31:
                    gs_join_src[0] = src
                    if not gs_join_deadline[0]:
                        # sec 4fn: arm ONCE per 38 -- the repeated 31s used to
                        # push the deadline out forever.
                        # 2026-09-24: with a Briefing Time, at its zero (25 s
                        # after the first step used to start a 5:00 briefing
                        # at 0:35)
                        _jk = (bt_store.table_of(seen_charid[0])
                               if seen_charid[0] else None)
                        _jbe = (gs_tables.get(_jk, {}).get("brief_end")
                                if _jk is not None else None)
                        if _jbe:
                            gs_join_deadline[0] = max(
                                _jbe, time.time() + a.gs_real_dist_settle)
                        else:
                            gs_join_deadline[0] = (time.time()
                                                   + a.gs_battle_after_join)
                        print("  [gs] battle start armed for %.0f s after this "
                              "join (arm-once, sec 4fn%s)"
                              % (gs_join_deadline[0] - time.time(),
                                 ", the end of the briefing" if _jbe else ""),
                              flush=True)
                    else:
                        print("  [gs] repeat join -- battle start already armed, "
                              "%.0f s left"
                              % max(0.0, gs_join_deadline[0] - time.time()),
                              flush=True)
                if (_gmt == gamemsg.GS_LEAVE_BRIEFING and a.gs_battle_start
                        and sess.gs_battle_on[0]):
                    # sec 4fy (live 09-13): the client RETRANSMITS 47 (0.5/1/2/4
                    # s) and every copy re-pushed the whole start burst. The
                    # copies get their 48 (above) and nothing else.
                    print("  [battle] request 47 again -- 48 only, this battle "
                          "already started (sec 4fy)", flush=True)
                elif (_gmt == gamemsg.GS_LEAVE_BRIEFING and a.gs_battle_start
                      and forgotten_table(_sk31, seen_charid[0])):
                    # 2026-10-05: a 47 for a table this server forgot (the
                    # briefing loop also sends one on its way back to the
                    # lobby) gets its 48 only -- a start burst would freeze
                    # the player in the lobby
                    print("  [battle] request 47 from 0x%08x echoes table %d, "
                          "which this server does not seat it at -- 48 only"
                          % (seen_charid[0] or 0, _sk31), flush=True)
                elif _gmt == gamemsg.GS_LEAVE_BRIEFING and a.gs_battle_start:
                    sess.gs_battle_on[0] = time.time()
                    issue_supplies(sess, src)
                    if a.gs_battle_go:
                        sess.gs_battle_go[0] = time.time() + a.gs_battle_go_after
                    _room47 = battle_of(seen_charid[0])
                    if _room47 is not None:
                        # sec 4he: the ROOM owns the end, and (2026-09-26) the
                        # START: every member that lands its 47 in time gets ONE
                        # shared GO, and the room clock starts at that GO -- the
                        # moment each client starts its own HUD clock.
                        _gafter = a.gs_battle_go_after if a.gs_battle_go else 0.0
                        _tnow = time.time()
                        _shared = (_gafter > 0
                                   and (_room47.started is None
                                        or _room47.joins_go(_tnow, _gafter)))
                        _room_member_key[seen_charid[0]] = _wallet_key(
                            seen_uid[0], seen_charid[0], sess)
                        _first47 = _room47.arrive(seen_charid[0], _tnow,
                                                  go_after=_gafter,
                                                  go_wait=a.battle_go_wait)
                        if _shared:
                            for _gm in _room47.arrived:
                                _gms, _ = member_dst(_gm)
                                if _gms is not None and _gms.gs_battle_go[0]:
                                    _gms.gs_battle_go[0] = _room47.go_at
                            sess.gs_battle_go[0] = _room47.go_at
                            print("  [battle] table %d: 0x%08x rides the room's "
                                  "shared GO in %.1f s (%d arrived)"
                                  % (_room47.key, seen_charid[0],
                                     _room47.go_at - _tnow,
                                     len(_room47.arrived)), flush=True)
                        elif _gafter > 0:
                            print("  [battle] table %d: 0x%08x arrived after the "
                                  "room's GO window -- its own GO in %.0f s"
                                  % (_room47.key, seen_charid[0], _gafter),
                                  flush=True)
                        if _first47:
                            print("  [battle] table %d clock %s by 0x%08x: "
                                  "%s, kill target %d, KO limit %d, %d member(s) "
                                  "(sec 4he)"
                                  % (_room47.key,
                                     "ARMED (starts at the shared GO)"
                                     if _shared else "STARTED", seen_charid[0],
                                     ("%.0f s (the table's Time Limit)"
                                      % _room47.rules.time_limit)
                                     if _room47.rules.time_limit else
                                     "no time limit (the target ends it)",
                                     _room47.rules.kill_target,
                                     _room47.rules.ko_limit,
                                     len(_room47.members)), flush=True)
                        else:
                            print("  [battle] 0x%08x ARRIVED in table %d's room "
                                  "(%s)"
                                  % (seen_charid[0], _room47.key,
                                     ("%.0f s left" % max(0.0, _room47.end_at
                                                         - time.time()))
                                     if _room47.end_at else
                                     "clock not started yet" if _room47.go_at
                                     else "no time limit"), flush=True)
                    elif a.gs_battle_length > 0:
                        sess.gs_battle_end[0] = time.time() + a.gs_battle_length
                        print("  [battle] started (no room) -- the result (kind 4) "
                              "goes out in %.0f s, then selector 39 (sec 4fy)"
                              % a.gs_battle_length, flush=True)
                    _bpos = _battle_pos(sess.key, seen_charid[0])
                    _bzone, _bnote = _battle_zone_note(sess.key,
                                                       seen_charid[0])
                    if _bnote:
                        print("  [arena] " + _bnote, flush=True)
                    if seen_charid[0]:
                        # 2026-10-03 (live, 04:26): the respawn (kind 25)
                        # repeats THIS spawn and its pieces. Only the post-join
                        # timer stored it, and that timer now skips a battle
                        # already started -- so a death on Train Graveyard
                        # respawned at the player's previous battle's Church
                        # point with Church's pieces: sky only.
                        _spawn_of[seen_charid[0]] = (
                            _bpos, arenamaps.spawn_bmap(
                                _bzone, _bpos, arenamaps.battle_bmap(
                                    _bzone, _zone_pieces, _gs_bmap)))
                        _spawn_zone[seen_charid[0]] = _bzone
                    for _k, _np in briefingroom.gs_battle_sequence(
                            a.gs_battle_start, spawn=_bpos,
                            seq_fn=lambda: next_gs_seq(sess), ident=seen_charid[0],
                            zone=_bzone,
                            bmap=arenamaps.spawn_bmap(_bzone, _bpos, arenamaps.battle_bmap(
                                _bzone, _zone_pieces, _gs_bmap))):
                        s.sendto(_np, src)
                        time.sleep(0.05)
                        print("  SENT notify kind %d (%s) -- message %d, %d "
                              "bytes. STAGE 4: watch the emulog for "
                              "KEL_NET_GAMESERVER_NOTIFY_* and a zone load"
                              % (_k, gamemsg.GS_NOTIFY_NAMES.get(_k, "?"),
                                 gamemsg.GS_NOTIFY_MSG, len(_np)), flush=True)
                    _send_base_objects(sess, src, "with the spawn (request 47)")
            elif _gmt is not None:
                print("  GS request %d (%s, arg %s) -- no answer defined; "
                      "fire-and-forget or unread"
                      % (_gmt, _gname,
                         "0x%x" % _garg if _garg is not None else "-"),
                      flush=True)
        if _ue and _ue != seen_uid[0]:
            print("  [uid] client's own user id = 0x%08x (from the %s, was 0x%08x) "
                  "-- per-session state reset"
                  % (_ue, "entrance" if len(data) == 80 else "world door",
                     seen_uid[0]), flush=True)
            # sec 4he: a new sign-in under this session leaves whatever
            # table its previous character was seated at.
            vacate_seat(seen_charid[0], "new entrance")
            seen_uid[0] = _ue
            last_pose[0] = None
            last_stream[0] = 0.0
            gs_done[0] = False
            # sec 4ft: a new entrance follows a new POL sign-in, which may be a
            # different member at this address -- resolve the key again.
            sess.account_key = None
            refresh_roster(_ue)
            # sec 4fu: its peer table and remote units went with it -- re-push
            for _o in sessions.values():
                _o.relay_pushed.pop(seen_charid[0], None)
                _o.relay_wu.pop(seen_charid[0], None)
            sess.relay_pushed.clear()
            sess.relay_wu.clear()
        # Learn the player's own uid off the in-game position stream (sec 4bx).
        _u = worldpose.ingame_uid(data, inner)
        if _u:
            # The in-game stream is also the ONLY thing that keeps PCSX2's UDP
            # mapping open from the guest side, so its timestamp is what decides
            # whether ACKing is safe (sec 4bx).
            last_stream[0] = datetime.datetime.now().timestamp()
            _pose = worldpose.ingame_pose(data, inner)
            if _pose is not None:
                last_pose[0] = _pose[1:]
                # 2026-09-26: the pose TEAM BASE occupation reads
                _pk = seen_charid[0] or _pose[0]
                if _pk:
                    _battle_pose[_pk] = (_pose[1], _pose[2], _pose[3],
                                         last_stream[0])
                if a.peer_relay != "off":
                    relay_peer_pose(sess, inner, _pose)
            # KEY: sec 4de: THE WORLD HAS NEVER HAD ANYTHING IN IT. Nothing has ever
            # sent a type-125, so every session has been a lobby containing exactly
            # one entity -- which is what "waiting for teams to fill up" looks like
            # from the inside. Put one peer in it, standing next to the player.
            # WARNING: The client will NOT know this id and will print `Cache miss` and
            # ask selector 36 (sec 4bw). That is the designed pull, not a fault --
            # --peer-answer answers it.
            if a.world_update_ms > 0 and last_pose[0] is not None:
                _nowt = datetime.datetime.now().timestamp()
                if (_nowt - last_wu[0]) * 1000.0 >= a.world_update_ms:
                    last_wu[0] = _nowt
                    _x, _y, _z, _dx, _dy, _dz = last_pose[0]
                    # sec 4df: --world-update-id=0 means the CLIENT ITSELF, and
                    # --world-update-abs an absolute position instead of an offset
                    # from wherever it currently is. Together they ask the one
                    # question left: the client spawns at the ORIGIN, ~1900 units
                    # from the level, with no floor under it -- so it cannot move.
                    # Nothing we send has ever told it where to stand. Does a
                    # type-125 naming its OWN uid at a real position move it?
                    _wid = a.world_update_id or seen_uid[0]
                    if a.world_update_abs:
                        _ax, _ay, _az = [float(t) for t in
                                         a.world_update_abs.replace(",", " ").split()]
                    else:
                        _ax, _ay, _az = _x + a.world_update_offset, _y, _z
                    wu = worldpose.build_world_update([dict(
                        id=_wid, x=_ax, y=_ay, z=_az,
                        dx=_dx, dy=_dy, dz=_dz)],
                        seq=a.lobby_seq)
                    s.sendto(wu, src)
                    print("  SENT type-125 WORLD UPDATE: entity 0x%08x at "
                          "(%.1f, %.1f, %.1f)%s"
                          % (_wid, _ax, _ay, _az,
                             "  [SELF -- trying to place the player]"
                             if _wid == seen_uid[0] else ""), flush=True)
            # KEY: sec 4cd: the in-game stream is the first solid proof the client is
            # in world, so it is the right moment to open the GAME SERVER channel.
            # Both selectors are UNGATED (doc_armmap.py), which is what makes this
            # possible at all -- selector 21, the endpoint writer sec 4bs found,
            # needs [kelsvc+12] == 8 and can never run in world. Selector 104
            # reaches the SAME writer 0x00bca938 with no gate.
            if a.gs_connect and not gs_done[0]:
                gs_done[0] = True
                _ep = advertise.host_for(a.gs_connect_ip or a.lobby_ip, src[0])
                # KEY: sec 4df: THESE TWO ARE DIFFERENT THINGS AND WERE WELDED
                # TOGETHER. 104 writes the game-server ENDPOINT -- that is what
                # the item/stat manager needs, and without it the HP bar and item
                # count render garbage (sec 4cd) and the avatar does not appear to
                # be controllable. 38 sets the READY FLAG, i.e. "your match server
                # is up", and sec 4cd records that enabling this pair is exactly
                # what first put the account holder in the briefing room, with the
                # team-assignment prompt, on every world entry.
                #
                # So the pair traded one fault for the other: WITH it, a working
                # character in the wrong room; WITHOUT it, the right area and a
                # character that will not move. --gs-connect-selectors=104 asks
                # the question neither setting could: does the endpoint alone give
                # a working avatar without claiming a match is ready?
                _gs_sels = [int(t, 0) for t in
                            a.gs_connect_selectors.replace(",", " ").split()]
                for _sel in _gs_sels:
                    if _sel == worldchannel.GS_ENDPOINT_SELECTOR:
                        # sec 4gv: ONE builder for every 104 this server sends,
                        # so the world-entry declaration and the Start
                        # re-declaration cannot drift apart.
                        send_gs_endpoint(src, seen_charid[0], req=data,
                                         why="world entry")
                        continue
                    _g = worlddoor.build_world_answer(
                        data, selector=_sel, seq=a.lobby_seq,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7),
                        inner_ip=None, ptype=a.world_type, pad_to=a.world_pad,
                        # WARNING:KEY: sec 4dv: NOT 0 -- record+4. Selector 104's arm
                        # 0x00bcd248 OPENS with
                        #     lw v1, 4(s2); lw v0, 272(s1); bne v1, v0, <drop>
                        # so the endpoint message is dropped without a word
                        # unless record+4 equals [kelsvc+272]. Hardcoding 0 was
                        # correct only for as long as [kelsvc+272] was 0, which
                        # is to say only until the roster carried a real
                        # character id -- at which point the game-server channel
                        # would have gone quiet again and looked like a
                        # regression in something else entirely.
                        ident=seen_charid[0])
                    if _g is not None:
                        s.sendto(_g, src)
                print("  SENT GAME-SERVER CONNECT: selectors %s (104 = endpoint "
                      "%s:%d, id %d -> [kelsvc+268]; 38 = the READY flag, which is "
                      "what sends the client to the briefing room -- sec 4cd/4df)"
                      % (",".join(str(x) for x in _gs_sels), _ep,
                         a.gs_connect_port, a.gs_connect_id), flush=True)
                # sec 4cq: ARM the channel. Message 27 with a body of at
                # least 13 bytes is the only thing in the binary that sets
                # [chan+204] bit 6, and without that bit the last-heard stamp
                # CER-48101's 40 s timeout reads is never refreshed.
                if a.gs_keepalive_ms > 0:
                    _st = []
                    for _pair in a.gs_stats.replace(" ", "").split(","):
                        if not _pair:
                            continue
                        _k, _, _v = _pair.partition(":")
                        _st.append((int(_k, 0), int(_v, 0)))
                    s.sendto(gamemsg.build_gs_stats(_st, state=a.gs_arm_state,
                                            seq=next_gs_seq(sess)), src)
                    gs_ka_src[0] = src
                    gs_ka_next[0] = time.time() + a.gs_keepalive_ms / 1000.0
                    print("  SENT GAME-SERVER ARM: message %d, COUNT=%d "
                          "STATE=%d%s -> [chan+204] |= 0x40 -- sec 4cq"
                          % (gamemsg.GS_ARM_MSG, min(len(_st), 6), a.gs_arm_state,
                             ("  " + " ".join("%d:%d" % t for t in _st[:6]))
                             if _st else ""), flush=True)
                _mts = [int(x) for x in a.gs_msg.replace(" ", "").split(",")
                        if x] if a.gs_msg else []
                for _mt in _mts:
                    if not 1 <= _mt <= gamemsg.GS_MSG_MAX:
                        print("  gs-msg %d out of range 1..%d, skipped"
                              % (_mt, gamemsg.GS_MSG_MAX), flush=True)
                        continue
                    s.sendto(gamemsg.build_gs_message(_mt, seq=next_gs_seq(sess)), src)
                    print("  SENT GAME-SERVER MESSAGE type %d (inner 130, body[0]"
                          " = the type, body zeros) -- sec 4cq" % _mt, flush=True)
            # sec 4gs addendum 3: the lobby NPCs (doc_npc_spawn.py), off by default.
            if a.npc_spawn == "on":
                push_lobby_npcs(sess, src)
        # sec 4dr FIX (2026-09-11): a CHARAID must never be taken as the account
        # uid. The comment below ("the 64-byte stream carries only the account
        # uid") is REFUTED live: with --world-self-charaid the self-record id
        # ([kelsvc+272]) IS the charaid, so the client also streams its position
        # keyed by the charaid -- doc-rx holds 64-byte type-0x83 packets with
        # body[0] = 0x0002aa68 (Lex's id) mixed in with the real 0xa756a69a stream.
        # ingame_uid read that charaid as the account uid, seen_uid flipped to
        # 0x0002aa68, refresh_roster(0x0002aa68) rebuilt an EMPTY roster, and BOTH
        # the name plate and the auto-costume lookup (which key on seen_uid) came
        # back empty -- the avatar fell to the default look and the name went
        # blank. Reject any _u we have served as a character id, or that equals
        # the selected charaid [kelsvc+272].
        _u_is_charid = bool(_u) and (_u in sess.chara_ids.values()
                                     or _u == (seen_charid[0] & 0x3FFFFFFF))
        if _u and not _u_is_charid and _u != seen_uid[0]:
            seen_uid[0] = _u
            print("  [uid] client's own user id = 0x%08x (from its type-0x83)"
                  % _u, flush=True)
        # sec 4dr follow-up (2026-09-10): the per-account roster is otherwise
        # loaded into chara_kw ONLY on a fresh 80/132-byte entrance (early_uid).
        # This box recreates the `doc` container every few minutes (stale-check),
        # so a client that reconnects and resumes on the in-game type-0x83 stream
        # WITHOUT sending a new entrance is served the process's initial 4-empty
        # roster -- an existing account's characters vanish until a full back-out
        # and re-enter.  The in-game account uid rides the 64-byte stream too
        # (0xa455a599 / 0xa756a69a); refresh_roster keys the store by that uid,
        # so (re)loading here is safe and idempotent.  Guarded on _roster_uid so a
        # session whose entrance already loaded the roster does not refresh every
        # position packet -- and on _u_is_charid so the charaid stream (see above)
        # never rebuilds the roster against an empty account.
        if (_store is not None and _u and not _u_is_charid
                and sess.roster_uid[0] != _u):
            refresh_roster(_u)

        # KEY: sec 4dv: THE LENGTH GATE WAS DROPPING A WHOLE RUNG.  `>= BODY_OFF
        # + 16` (40 bytes) is right for every rung that carries an argument, and
        # WRONG for the ones that carry none: selector 22 -- the server handoff
        # phase 42 sends and phase 43 blocks on -- is a 36-byte datagram with a
        # 12-byte body, and it arrived SEVEN times in the 09-05 reserve corpus
        # and was answered zero times.  Nothing cleared bit 31 of [kelsvc+28],
        # so the client's own 10 s deadline (0x00589af0) expired and painted
        # CER-47117 at phase 43 -- the reservation stall, exactly.
        # WARNING: The other 36-byte type-7 traffic is the selector-5 driver poll (2099
        # of them in that corpus).  5 + 1 = 6 is a DRIVER arm whose whole job is
        # to move [kelsvc+12], so answering it is the sec 4bz self-harm again.
        # Hence an explicit ALLOWLIST rather than a lower bound.
        _short = len(data) < framing.BODY_OFF + 16
        _short_ok = (_short and len(data) >= framing.BODY_OFF + 12
                     and data[1] != 1 and len(data) > framing.BODY_OFF + 1
                     and (data[framing.BODY_OFF + 1] in short_ladder
                          # sec 4gk: trade CONFIRM 47 / CANCEL 49 are 36-byte
                          or (_trade is not None
                              and data[framing.BODY_OFF + 1] in doc_trade.SHORT_REQS)))
        if (a.world_answer and (not _short or _short_ok)
                and _itype == a.world_type
                # Seen live (CER-48102): a MODE-4 (game-server) datagram
                # whose header did not decrypt has no trustworthy type -- a
                # 136-byte 1 Hz NPC report read as 0x7f, was answered as lobby
                # "selector 73", and its garbage ident became the session's
                # character id. Game-server traffic never takes this path.
                and not (len(data) > 1 and data[1] == 4 and inner is None)
                and (a.world_len <= 0 or len(data) == a.world_len)):
            # KEY: THE ANSWER SELECTOR IS THE REQUEST'S SELECTOR + 1 (sec 4bs).
            # The driver 0x005895b0 RETURNS body[1] and the demux 0x00bcc718
            # dispatches on it through a 252-entry jump table at 0x00bf3230
            # (index = selector - 4).  The client's own outgoing header builder
            # 0x00bdb190 writes the selector at body[1], so every round names its
            # own answer:
            #   phase 27  request sel 1  -> answer 2   driver arm, state 1 -> 2
            #   phase 29  request sel 12 -> answer 13  0x00bca868: state = 2 AND
            #                                         [kelsvc+1064] = body[12..15];
            #                                         this is what releases phase 30
            #   phase 31  request sel 3  -> answer 4   0x00bc8ee0, the disconnect
            #                                         phase 32 waits for (state 0)
            # Selector 2 was NOT wrong for phase 27 and IS wrong for everything
            # after it -- three sessions of selector sweeps at phase 30 failed
            # because 2/4/5/6 are the DRIVER's arms and 13 is a TABLE arm.
            #
            # Read the selector out of the DECRYPTED body when we have it: mode 1
            # enciphers 32 bytes from offset 8, i.e. body[0..15] (sec 4bj), and
            # doc_kelcrypt.header hands back the whole plaintext packet, so even
            # phase 27's `07 01 ...` is readable.
            # WARNING: FALL BACK TO THE RAW BYTE FOR EVERY MODE BUT 1, exactly as the
            # pre-4bs code did.  header() returns None whenever the cipher blob is
            # missing (log-only builds) or the self-check fails, and phase 29 is
            # MODE 2 with a plaintext body -- so requiring the decrypt here would
            # silently drop phase 29 back to selector 2, which is the failure this
            # whole change exists to fix, and it would look like nothing happened.
            _plain = inner["plain"] if inner is not None else None
            _req_sel, _ident = worldchannel.world_reply_fields(data, inner)
            # KEY: sec 4dv: record+4 IS [kelsvc+272]. 0x00bdb190 stamps it into
            # every outgoing message, so the client tells us its own character
            # id on every request -- no probe needed. Learn it and stop guessing
            # 0 downstream.
            if _ident:
                if _ident != seen_charid[0]:
                    print("  [charid] the client's own [kelsvc+272] = 0x%08x "
                          "(record+4) -- getMyCharaId() now answers, sec 4dv"
                          % _ident, flush=True)
                seen_charid[0] = _ident
                # register the NAME now, not at the first
                # user-list request. The relay's peer records read `players`,
                # and until that request they went out as "Player_41050" --
                # which the other client keeps for good (first sight wins).
                _known = players.get(_ident, {}).get("name") or ""
                if not _known or _known.startswith("Player_"):
                    _pn = _player_name()
                    if _pn:
                        players[_ident] = {"name": _pn, "uid": seen_uid[0],
                                           "look": _player_look(sess)}
            _unpairable = False
            if a.world_selector_pair and _req_sel is not None and 0 < _req_sel < 255:
                _sel = _req_sel + 1
            elif _req_sel in (None, 1):
                _sel = a.world_selector
            else:
                # WARNING: THE 255 TRAP (sec 4bz). The pairing bound is `< 255`, so a
                # selector-255 request falls through to --world-selector-next,
                # which DEFAULTS TO 2 -- and selector 2 is a DRIVER arm
                # (0x00589660 -> 0x00bc8aa0 -> 0x005894f0) whose whole job is to
                # set [kelsvc+12] = 2.  So every unpairable notification we
                # "answered" was silently RESETTING THE CONNECTION STATE.  If the
                # client was sitting in state 7 waiting for its user list, that
                # knocks it out of the only state selector 11's arm will run in,
                # its pending request can never be cleared, and 10 s later it
                # paints CER-47117 (sec 4by).  The client sent selector 255 four
                # times on 08-27 and we did this four times.
                #
                # 255 cannot pair anyway: 255+1 = 256 is past the end of the
                # 252-entry table.  So the honest answer is NO answer -- the
                # datagram still gets its reliable ACK, which is what it is owed.
                _unpairable = True
                _sel = a.world_selector_next
            # Arms that read `[record+4]` compare it with `[kelsvc+272]` and drop
            # the message without a word on a mismatch, so echo it.  WARNING: sec 4bw
            # measured that this is PER-ARM, not a shared gate: 0x00bcaa70
            # (selector 37) never looks at it and inserts regardless.  Echoing
            # stays right; "every arm gates" was too strong.  The selector-2 rung
            # keeps the lobby-IP value it was proven live with; that arm is in
            # the driver and never reads the field.
            if _sel == 2:
                _ident = None
            # KEY: sec 4ce: RE-ARM the game-server connect. Selector 1 is phase 27,
            # the world door -- i.e. a NEW world session. Without this the connect
            # is one-shot per CONTAINER, so only the first session after a restart
            # gets its item/stat channel and every reconnect silently reverts to
            # the old behaviour. Reported live: first attempt reached a new room,
            # the second went back to the confined one.
            if _req_sel == 1:
                # sec 4dv: the world door is a NEW session, so the learned
                # character id must not carry over -- the same stale-across-
                # sessions class as `seen_uid` (the 2026-09-05 audit defect A). It is
                # relearned from the very next type-127 round (selector 12),
                # which is long before anything that needs it.
                if seen_charid[0]:
                    seen_charid[0] = 0
            if _req_sel == 1 and gs_done[0]:
                gs_done[0] = False
                print("  [gs] world door seen -- re-arming the game-server connect",
                      flush=True)
            # KEY: SELECTOR 36 IS NOT A LADDER RUNG -- it is the client asking who an
            # entity is (sec 4bw), and its answer's body[12] is a PEER RECORD
            # where build_world_answer would put its `result` word.  Answering it
            # with the generic builder inserts an entity whose id is the result
            # code.  Off by default: we never send a type-125, so the client never
            # cache-misses, and we have no entity data to serve yet.
            # KEY: SELECTOR 10 IS THE USER LIST REQUEST (sec 4bx). We have always
            # answered it with selector 11 -- and an EMPTY body, which the client
            # parses as a list of zero users, prints `user list 0 0`, and then
            # CER-47117. Serve the player's own uid instead; it is the entity it
            # is failing to find a name plate for.
            _bt_body = worldchannel.request_body(data, inner) if a.battletable_verbs else None
            # sec 4ep (2026-09-11): true when this JOIN targets an UNKNOWN
            # table and --bt-no-onfly-reserve is on -- the selector-21
            # endpoint answer below must then FAIL (result=-1) so the client
            # does NOT set [kelsvc+1092] bit 4 for a phantom reservation.
            _bt_phantom_join = False
            _bt_join_result = -1
            if (a.battletable_verbs and _req_sel == tableverbs.BT_REQ_CANCEL
                    and _ident):
                unqueue(_ident, "cancelled")
            if a.battletable_verbs and _req_sel in tableverbs.BT_JOIN_REQS and _bt_body:
                # sec 4dz: the JOIN rung names the table at body[12..13]; seat
                # the character before the endpoint answer below goes out.
                _jkey = struct.unpack_from("<H", _bt_body, 12)[0]
                _jpw = (_bt_body[tableverbs.BT_PASSWORD_OFF:tableverbs.BT_PASSWORD_OFF + 8]
                        if _req_sel == tableverbs.BT_REQ_JOIN_PW else None)
                _jt = bt_store.tables.get(_jkey)
                if (a.novice == "on" and a.novice_tables == "enforce"
                        and _jt is not None
                        and struct.unpack_from("<I", _jt["rec"], tablerecords.BT_OFF_FLAGS)[0]
                        & tablerecords.BT_FLAG_NOVICE
                        and not novice_cid(_ident or seen_charid[0] or 0)):
                    # sec 4hc: "a mode open only to novice players" (28:198/199)
                    _jres = -5
                elif (_units is not None and a.unit_tables == "enforce"
                        and _jt is not None
                        and struct.unpack_from("<I", _jt["rec"], tablerecords.BT_OFF_FLAGS)[0]
                        & tablerecords.BT_FLAG_UNIT
                        and (_ident or 0) not in _jt["members"]
                        and not doc_unit.join_allowed(
                            _jt["members"], _unit_of_cid,
                            _ident or seen_charid[0] or 0)[0]):
                    # 2026-09-24: SE's 28:197 -- "you cannot make a
                    # reservation unless you belong to one of the first two
                    # units to reserve"
                    print("  [units] JOIN table %d refused: %s" % (
                        _jkey, doc_unit.join_allowed(
                            _jt["members"], _unit_of_cid,
                            _ident or seen_charid[0] or 0)[1]), flush=True)
                    _jres = -6
                elif (_jt is not None and (_ident or 0) not in _jt["members"]
                        and _briefing_running(_jkey)):
                    # 2026-09-29 (Dirge report, a 3rd player joined a 2P
                    # match): Start fans the 38 out only to the members seated
                    # THEN, so a seat taken during the briefing never left the
                    # lobby, yet the room counted it. In Progress from Start.
                    print("  [battletable] JOIN table %d refused: its briefing "
                          "is running" % _jkey, flush=True)
                    _jres = -4
                else:
                    _jres, _jkey = bt_store.reserve(
                        _jkey, _ident or 0, _jpw,
                        rp=rp_of_cid(_ident or seen_charid[0] or 0))
                if _jres == -1 and _jkey and a.bt_no_onfly_reserve:
                    # sec 4eo/4ep (2026-09-11): the console default-targets
                    # the uninitialised [manager+11808] (59600) the moment
                    # the player signs in. Creating that table on the fly
                    # (sec 4ee) and answering the JOIN with the selector-21
                    # success endpoint sets the reserved flag [kelsvc+1092]
                    # bit 4 -- so the player is stuck "reserved" (prompt
                    # 0x6835) and the Create/Start-Immediately path is hidden.
                    # Do NOT invent the table; leave _jres = -1 and mark the
                    # join phantom so _result is forced to -1 below (the same
                    # "no such table" result the RESERVE arm returns), which
                    # keeps the phase-45 success path -- and the reserved
                    # flag -- from ever running. The player stays
                    # UNRESERVED and free to CREATE their own table and
                    # become its leader.
                    _bt_phantom_join = True
                    print("  [battletable] table %d UNKNOWN -- NOT creating on "
                          "the fly (sec 4eo, --bt-no-onfly-reserve); answering "
                          "JOIN selector 21 with result=-1 so the client stays "
                          "UNRESERVED and can CREATE" % _jkey, flush=True)
                elif _jres == -1 and _jkey:
                    # sec 4ee: the console reserves whatever [manager+11808]
                    # holds (59600 in every live boot where no table was
                    # picked from the browser). An unknown id used to leave
                    # the character unseated, so 38 carried no record and the
                    # briefing room had nobody in it. Make the table exist.
                    bt_store.add_record(tablerecords.build_battletable_record(
                        table_id=_jkey, leader=seen_uid[0], cur=0, maximum=8,
                        map_idx=0, mode=1, comment="Table %d" % _jkey))
                    _jres, _jkey = bt_store.reserve(
                        _jkey, _ident or 0, _jpw,
                        rp=rp_of_cid(_ident or seen_charid[0] or 0))
                    print("  [battletable] table %d did not exist -- CREATED it "
                          "on the fly (sec 4ee)" % _jkey, flush=True)
                if _jres == 0 and _jkey:
                    _bt_echo_key = _jkey  # sec 4fl: echo 152 after the 21
                    _jrec = bt_store.record(_jkey)
                    if (a.bt_fill_start >= 0 and _jrec is not None
                            and not (struct.unpack_from(
                                "<I", _jrec, tablerecords.BT_OFF_FLAGS)[0]
                                     & tablerecords.BT_FLAG_MISSION)
                            and len([m for m in bt_store.members(_jkey) if m])
                            >= min(_jrec[tablerecords.BT_OFF_MAX]
                                   or tableverbs.BT_MAX_MEMBERS,
                                   tableverbs.BT_MAX_MEMBERS)
                            and not _briefing_running(_jkey)):
                        _fill_start[_jkey] = time.time() + a.bt_fill_start
                        print("  [fill-start] table %d FILLED by this join -- "
                              "briefing in %.1f s" % (_jkey, a.bt_fill_start),
                              flush=True)
                elif _jres < 0:
                    # sec 4he: a REFUSED join (password / full / in progress)
                    # used to get the generic success 21, so the client sat
                    # "reserved" at a table the store never seated it at.
                    _bt_phantom_join = True
                    _bt_join_result = _jres
                if _jres == -4:
                    queue_join(_jkey, _ident or 0)
                elif _jres == 0 and _ident:
                    unqueue(_ident, "seated at table %d" % _jkey)
                print("  [battletable] JOIN table %d by 0x%08x -> %d (%s)"
                      % (_jkey, _ident or 0, _jres,
                         {0: "seated", -1: "no such table", -2: "wrong password",
                          -3: "full", -4: "IN PROGRESS",
                          -5: "NOVICES ONLY (--novice-tables enforce)",
                          battleroom.BT_REFUSE_RP: "RP LIMIT: %s (--rp-tables enforce)"
                              % (battleroom.rp_allowed(_jt["rec"] if _jt else None,
                                            rp_of_cid(_ident or seen_charid[0]
                                                      or 0))[1]),
                          -6: "UNIT: not one of the first two units "
                              "(--unit-tables enforce)"}.get(_jres, "?")),
                      flush=True)
            bt_tables = bt_store.records()
            if bt_tables and _req_sel == tablerecords.BATTLETABLE_LIST_REQ:
                # sec 4dv: the browser's list. Answering it with
                # build_world_answer's empty body is a well-formed list of ZERO
                # tables -- the handler's own completion test 0 == 0 passes, so
                # the screen is simply empty and nothing looks wrong.
                bl = tablerecords.build_battletable_list(
                    data, [advertise.rec_for(_r, _gs_endpoint, src[0])
                           for _r in bt_tables], seq=a.lobby_seq,
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7),
                    ptype=a.world_type, ident=_ident)
                s.sendto(bl, src)
                print("  SENT type-%d BATTLETABLE LIST (selector %d -> %d) "
                      "%d table(s) [%s], stride %d -- the arm needs [kelsvc+12] == 15,"
                      " which phase 34's own request parks it in"
                      % (a.world_type, tablerecords.BATTLETABLE_LIST_REQ,
                         tablerecords.BATTLETABLE_LIST_ANS, len(bt_tables),
                         # 2026-10-05: what each row SAYS (id cur/max map), so
                         # a count that does not move on screen can be told
                         # apart from one we never changed
                         ", ".join("#%d %d/%d map %d" % (
                             struct.unpack_from("<H", _r, tablerecords.BT_OFF_ID)[0],
                             struct.unpack_from("<H", _r, tablerecords.BT_OFF_CUR)[0],
                             _r[tablerecords.BT_OFF_MAX], _r[tablerecords.BT_OFF_MAP])
                             for _r in bt_tables[:6]),
                         tablerecords.BT_REC_LEN),
                      flush=True)
                _served_list = True
            elif (a.battletable_verbs and _req_sel in tableverbs.BT_VERB_REQS
                    and _bt_body is not None):
                # 2026-09-13: EVERY config goes through the store -- an unknown
                # key now answers result -1 there instead of reaching the
                # sentinel probe below (the phantom password table).
                _vp, _vnote = tableverbs.battletable_verb(
                    bt_store, data, _bt_body, _req_sel, _ident or 0,
                    seen_uid[0], seq=a.lobby_seq,
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7),
                    ptype=a.world_type, pad_to=a.world_pad,
                    probe=a.battletable_probe,
                    quest=((_quest_pick.get(sess.key) or (None,))[0]
                           if a.quest_mission else None),
                    # sec 4gv addendum: the record carries the game-server
                    # endpoint and the client installs it, so it is rewritten
                    # per recipient exactly as the list and 38 paths do.
                    peer_ip=src[0], default_gs_ip=_gs_endpoint,
                    rp=rp_of_cid(_ident or seen_charid[0] or 0))
                if _vp is not None:
                    s.sendto(_vp, src)
                    print("  SENT type-%d %s (selector %d -> %d): %s  [store: "
                          "%d table(s), %d seated]"
                          % (a.world_type, worldchannel.selector_name(_req_sel), _req_sel,
                             _req_sel + 1, _vnote, len(bt_store.tables),
                             len(bt_store.reservation)), flush=True)
                    # 2026-10-01 (manual p.27/29/37): a battletable INVITATION
                    # reaches the invitee as selector 129 (tableverbs
                    # build_invite_push). Request 127 names no table: the
                    # inviter's own reservation is the table.
                    if _req_sel == tableverbs.BT_REQ_INVITE and len(_bt_body) >= 16:
                        _inv = _ident or seen_charid[0] or 0
                        _itgt = struct.unpack_from("<I", _bt_body, 12)[0]
                        _online = {_ss.seen_charid[0] for _ss in list(sessions.values())
                                   if _ss.seen_charid[0]
                                   and not peer_idle(_ss, time.time())}
                        _ik, _ito = tableverbs.invite_targets(bt_store, _inv, _itgt,
                                                              _online)
                        if _ik is None:
                            print("  [invite] 0x%08x holds no reservation -- "
                                  "nothing to invite to" % _inv, flush=True)
                        elif _itgt == tableverbs.INVITE_ALL:
                            print("  [invite] 0x%08x: invite-ALL to a group (body "
                                  "[16..23] = %s) -- group membership is the POL "
                                  "friend service's, not resolved here"
                                  % (_inv, bytes(_bt_body[16:24]).hex()), flush=True)
                        for _it in _ito:
                            _is = session_of(_it)
                            _ipw = (bt_store.tables.get(_ik) or {}).get("password", b"")
                            if send_push(_is, tableverbs.build_invite_push(
                                    _ik, _ipw, subchannel=(a.world_subchannel
                                                           if a.world_subchannel >= 0
                                                           else 7)),
                                         _inv, "129 INVITATION to table %d for 0x%08x"
                                         % (_ik, _it)):
                                print("  [invite] 0x%08x invited 0x%08x to table %d"
                                      % (_inv, _it, _ik), flush=True)
                        if _ik is not None and not _ito and _itgt != tableverbs.INVITE_ALL:
                            print("  [invite] 0x%08x -> 0x%08x: not online, or "
                                  "already seated at table %d -- no push"
                                  % (_inv, _itgt, _ik), flush=True)
                    # sec 4fl: the leader never sends 151 for their own table;
                    # echo the reservation AFTER the 25 (0x00bcb638 clears it
                    # on the way in) so R+2970/R+684 bit 4 hold the new key.
                    _ck = (bt_store.table_of(_ident or 0)
                           if _req_sel == tableverbs.BT_REQ_CREATE else None)
                    if _ck and not a.bt_no_reserve_echo:
                        s.sendto(tableverbs.build_reserve_echo(
                            data, _ck, seq=a.lobby_seq,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7),
                            ptype=a.world_type, pad_to=a.world_pad,
                            ident=_ident), src)
                        print("  SENT type-%d RESERVATION ECHO (selector 152, "
                              "unsolicited) for table %d after the CREATE-ok "
                              "(sec 4fl)" % (a.world_type, _ck), flush=True)
                    # 2026-09-13: the mirror of that echo. After a DISSOLVE-ok
                    # the leader still held the reservation the echo gave them
                    # (R+2970 / R+684 bit 4), so "Reserved Table" pointed at a
                    # dead key and asked CONFIG for it (live table 1,
                    # 16:55 table 3). The CANCEL-ok arm ("Cancel %d", kel
                    # 0x00bcd6c0) calls the clear 0x00be33b0 when body[12]
                    # >= 0; the clear is a no-op if bit 4 is already off.
                    if (_req_sel == tableverbs.BT_REQ_DISSOLVE and " -> gone" in _vnote
                            and not a.bt_no_reserve_echo):
                        s.sendto(worlddoor.build_world_answer(
                            data, selector=tableverbs.BT_REQ_CANCEL + 1, result=0,
                            seq=a.lobby_seq,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7),
                            ptype=a.world_type, pad_to=a.world_pad,
                            ident=_ident), src)
                        print("  SENT type-%d RESERVATION CLEAR (selector 156, "
                              "unsolicited) after the DISSOLVE-ok" % a.world_type,
                              flush=True)
                        send_reservation_clear(_ident or seen_charid[0], dst=src,
                                               why="after the DISSOLVE-ok")
                    # 2026-09-22: the SAME orphan, without a dissolve. The
                    # store is in MEMORY, so every responder restart drops every
                    # table while the client keeps the reservation the echo above
                    # gave it (R+2970 / R+684 bit 4 -- nothing in the lobby
                    # re-clears them, sec 4fl). The client then opens Battle
                    # Entry holding a dead key: the extra "Confirm Reserved
                    # Battletable" row appears, CONFIG asks for a table we do not
                    # have, and our all-zero answer renders as a junk table
                    # (!!na!!, Max 0, Time Limit 35931752 min -- savestates 06/07,
                    # live table 4114 with [store: 0 table(s), 0 seated]).
                    # Leaving re-enters it because the reservation is still set.
                    # Clear it on the way out, exactly as the DISSOLVE-ok does.
                    if (_req_sel == tableverbs.BT_REQ_CONFIG and "table gone" in _vnote
                            and not a.bt_no_reserve_echo):
                        s.sendto(worlddoor.build_world_answer(
                            data, selector=tableverbs.BT_REQ_CANCEL + 1, result=0,
                            seq=a.lobby_seq,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7),
                            ptype=a.world_type, pad_to=a.world_pad,
                            ident=_ident), src)
                        print("  SENT type-%d RESERVATION CLEAR (selector 156, "
                              "unsolicited) -- CONFIG named a table the store "
                              "does not have, so the client's reservation is an "
                              "orphan" % a.world_type, flush=True)
                        # ...and the one that WORKS on this build (the 156
                        # above left the "!!na!!" table up, live)
                        send_reservation_clear(_ident or seen_charid[0], dst=src,
                                               why="CONFIG of a table the store "
                                               "does not have")
                else:
                    print("  [battletable] %s (selector %d): %s -- falling back "
                          "to the generic answer"
                          % (worldchannel.selector_name(_req_sel), _req_sel, _vnote),
                          flush=True)
                _served_list = _vp is not None
            elif _stats is not None and _req_sel == doc_stats.CAREER_REQ:
                # 2026-09-13: the Status window's CAREER RECORD, asked EVERY
                # time it opens (139 -> 140, arm 0x00bcd4e0, state 44 -> 2).
                # The generic echo put the request's own bytes into the W/L and
                # medal counts. The asked-for charid (0 = self) is read at
                # body[12]; the raw bytes are logged until a live one settles it.
                _crq = worldchannel.request_body(data, inner) or b""
                _cwant = (struct.unpack_from("<I", _crq, 12)[0]
                          if len(_crq) >= 16 else 0)
                _cself = _ident or seen_charid[0]
                _ckey = (_stats.key_for_charid(_cwant)
                         if _cwant and (_cwant & 0x3FFFFFFF) != (_cself & 0x3FFFFFFF)
                         else _wallet_key(seen_uid[0], _cself))
                _cc = _stats.peek(_ckey) if _ckey else doc_stats.new_career()
                # 2026-10-01, manual p.36: an Anonymous player's record is
                # not shown to others. No client code hides it on its own
                # (re-visibility), so another player's request gets an empty
                # career; your own is always served.
                if (_cwant and (_cwant & 0x3FFFFFFF) != (_cself & 0x3FFFFFFF)
                        and _stats.is_private(_ckey)):
                    _cc = doc_stats.new_career()
                    print("  [stats] 0x%08x is Anonymous -- its career is not "
                          "shown to 0x%08x" % (_cwant, _cself or 0), flush=True)
                s.sendto(worldchannel.seal_world_body(
                    data, doc_stats.career_body(
                        _cc, subchannel=(a.world_subchannel
                                         if a.world_subchannel >= 0 else 7)),
                    seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                print("  SENT type-%d CAREER RECORD (selector 139 -> 140) [%s]: "
                      "%s  [req body[12..27] = %s]"
                      % (a.world_type, _ckey, _stats.summary_line(_ckey)
                         if _ckey and _ckey in _stats.data["chars"]
                         else "no career yet", _crq[12:28].hex(" ")), flush=True)
                _served_list = True
            elif _shop is not None and _req_sel in doc_shop.SHOP_REQS:
                # sec 4gk: the shop lists and the 145 -> 146 item transaction.
                _swk = _wallet_key(seen_uid[0], _ident or seen_charid[0])
                _sbody, _snote = _shop.body_for(
                    _req_sel, worldchannel.request_body(data, inner), _swk,
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7))
                if _sbody is not None:
                    s.sendto(worldchannel.seal_world_body(data, _sbody, seq=a.lobby_seq,
                                             ptype=a.world_type, ident=_ident),
                             src)
                print("  %s type-%d SHOP selector %d -> %d [%s]: %s"
                      % ("SENT" if _sbody is not None else "NOT SENT (generic "
                         "answer instead)", a.world_type, _req_sel, _req_sel + 1,
                         _swk, _snote), flush=True)
                _served_list = _sbody is not None
            elif _rank is not None and _req_sel in doc_rank.RANK_REQS:
                # 2026-09-13: the Ranking menu (doc_rank.py). The generic echo
                # put the request's page size in the answer's row count.
                _rwk = _wallet_key(seen_uid[0], _ident or seen_charid[0])
                _rbody, _rnote = _rank.body_for(
                    _req_sel, worldchannel.request_body(data, inner), _rwk,
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7))
                if _rbody is not None:
                    s.sendto(worldchannel.seal_world_body(data, _rbody, seq=a.lobby_seq,
                                             ptype=a.world_type, ident=_ident),
                             src)
                print("  %s type-%d RANKING selector %d -> %d [%s]: %s"
                      % ("SENT" if _rbody is not None else "NOT SENT (generic "
                         "answer instead)", a.world_type, _req_sel, _req_sel + 1,
                         _rwk, _rnote), flush=True)
                _served_list = _rbody is not None
            elif (_req_sel == questlist.LIST148_REQ and not _list148
                  and (_ledger or _solo_quests)):
                # 2026-09-23 LIVE: on the RETAIL build "Accept Mission" sends
                # selector 147, not 159 (live log: a player in Accept
                # Mission, zero 159s, 147 with capacity 256 at body[16]). The
                # 148 answer feeds the mission window's populator 0x00aae2d0:
                # {u16 quest id -> name KelStr 0xBBFF+id, u8 RANK (0-based;
                # 0x00aae950 maps it onto the "Mission: DG <class>" tab table
                # 0x00b12158 = thresholds 0/3/6/9/12/15), u8 flags (bit0 ->
                # rec+26 229 else -1, bit1 -> rec+4 0 else 2; left 0)}.
                _mids = _solo_quests
                _mnote = a.solo_quests
                if _ledger:
                    _mkey = _wallet_key(seen_uid[0], _ident or seen_charid[0])
                    _mc = _stats.peek(_mkey)
                    _mids = doc_missions.mission_list(_mc, _solo_quests)
                    _mnote = "[%s] ledger %s" % (_mkey, _mc.get("quests_open") or [])
                # flags bit1 -> row state rec+4 = 0 (selectable); without it the
                # populator writes 2 and every row drew GREYED (live
                # 2026-09-23). The ledger already hides what is not earned, so
                # every listed mission is takeable.
                _ment = [(q, doc_missions.list_rank(q), questlist.MISSION_ROW_OPEN)
                         for q in _mids]
                s.sendto(worldchannel.seal_world_body(
                    data, questlist.build_list148_body(
                        _ment,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7)),
                    seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                print("  SENT type-%d MISSION LIST (selector 147 -> 148, retail "
                      "Accept Mission): %d mission(s) %s -- %s"
                      % (a.world_type, len(_ment), _mids, _mnote), flush=True)
                _served_list = True
            elif _req_sel == questlist.LIST148_REQ and _list148:
                # sec 4gt add.1 probe. The generic answer here is a well-formed list
                # of ZERO entries, which is exactly what draws the blank,
                # unselectable rows (memory
                # doc-server-list-is-gated-on-state-10, corrected 2026-09-22).
                s.sendto(worldchannel.seal_world_body(
                    data, questlist.build_list148_body(
                        _list148,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7)),
                    seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                print("  SENT type-%d 147 LIST PROBE (selector %d -> %d): "
                      "%d entr(ies) %s -- PROBE, values are not decoded"
                      % (a.world_type, questlist.LIST148_REQ, questlist.LIST148_ANS,
                         len(_list148),
                         ",".join("%d:%d:%d" % e for e in _list148)),
                      flush=True)
                _served_list = True
            elif _req_sel == questlist.QUEST_LIST_REQ and (_solo_quests or _ledger):
                # 2026-09-13: Solo Battle = story mode; list the quest ids
                # (build_quest_list_body). Empty --solo-quests = the generic
                # zero-body answer (an empty list).
                # 2026-09-23: with the MISSION LEDGER the list is PER PLAYER
                # (doc_missions.mission_list): the exams an instructor has
                # authorized for this character, then --solo-quests minus every
                # exam. peek() so a lookup never creates a career.
                _qids, _qnote = _solo_quests, a.solo_quests
                if _ledger:
                    _qkey = _wallet_key(seen_uid[0], _ident or seen_charid[0])
                    _qc = _stats.peek(_qkey)
                    _qids = doc_missions.mission_list(_qc, _solo_quests)
                    _qnote = ("[%s] ledger %s, rank %d, %d rp, %d battle(s)"
                              % (_qkey, _qc.get("quests_open") or [],
                                 _qc.get("rank", 1), _qc.get("rp", 0),
                                 _qc.get("battles", 0)))
                s.sendto(worldchannel.seal_world_body(
                    data, questlist.build_quest_list_body(
                        _qids,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7)),
                    seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                print("  SENT type-%d %s (selector 159 -> 160): "
                      "%d quest(s) %s -- %s"
                      % (a.world_type,
                         "MISSION LIST" if _ledger else "SOLO QUEST LIST",
                         len(_qids), _qids, _qnote), flush=True)
                _served_list = True
            elif _trade is not None and _req_sel in doc_trade.TRADE_REQS:
                # sec 4gk addendum 5: TRADE. Never the generic answer: a
                # generic 42 back to the INVITER runs its own "invited"
                # handler (flag 0x400, partner = our result word 0).
                _tme = _ident or seen_charid[0]
                _tacts, _tnote = _trade.request(_req_sel, _tme,
                                                worldchannel.request_body(data, inner))
                print("  [trade] request %d from 0x%08x: %s"
                      % (_req_sel, _tme, _tnote), flush=True)
                for _ta in _tacts:
                    if _ta[0] == "ack":
                        s.sendto(worldchannel.seal_world_body(
                            data, doc_trade.bare_body(doc_trade.ACK_ANS),
                            seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                    elif _ta[0] == "push":
                        trade_push(_ta[1], _ta[2])
                    elif _ta[0] == "swap":
                        trade_swap(_ta[1])
                _served_list = True
            elif a.battletable_probe and _req_sel == 26:
                bt = tablerecords.build_battletable_probe(
                    data, seq=a.lobby_seq,
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7),
                    ptype=a.world_type, ident=_ident)
                s.sendto(bt, src)
                print("  SENT type-%d BATTLETABLE PROBE (selector 26 -> 27) -- "
                      "sentinels in every field; read the config screen (sec 4do)"
                      % a.world_type, flush=True)
                _served_list = True
            elif (a.user_list and _req_sel in userlist.USER_SELECTOR_REQS
                    and seen_uid[0]):
                # KEY: sec 4cg: serve the id the client ASKED FOR, not our own uid.
                _want = userlist.user_list_wanted_id(data, inner)
                # 0xffff is "none" too: --gs-connect-id=65535 (at no table)
                _ids = ([_want] if (_want not in (None, 0, 0xFFFF))
                        else [seen_uid[0]])
                # sec 4fr: register THIS player and fold in every OTHER player
                # so two clients see each other (and resolve each other's name).
                if seen_charid[0]:
                    players[seen_charid[0]] = {
                        "name": _player_name() or ("Player_%x" % seen_charid[0]),
                        "uid": seen_uid[0],
                        "look": _player_look(sess)}      # sec 4fx
                _other_ids = [c for c in players
                              if c and c != seen_charid[0]]
                _ids = _ids + [c for c in _other_ids if c not in _ids]
                # 2026-09-13: THIS player's own CHARID, named, right after the
                # self record. That record is keyed by the ASKED id (the uid),
                # but a table's leader (b2d40362) and the kind-20 distribution
                # name members by CHARID -- the one id a client could not
                # resolve on its own screen: own table ownerless, own team
                # empty after "Player distribution has been determined".
                if seen_charid[0] and seen_charid[0] not in _ids:
                    _ids = _ids[:1] + [seen_charid[0]] + _ids[1:]
                # KEY: sec 4ci: the FIRST live session with a decoded record
                # measured 13 x (10 -> 11) and exactly ONE (18 -> 19). Only 19
                # reaches the profile cache the UI reads (sec 4ch), so all the
                # frequent traffic was landing on the rung that discards it.
                # --user-list-selector forces the answer rung regardless of what
                # was asked; both arms take the same handler and the same
                # [kelsvc+12] == 7 gate, and the demux dispatches on the selector
                # WE send, not the one the client sent.
                _ans = a.user_list_selector or (_req_sel + 1)
                # WARNING: and the id is the other half. The record is keyed on its
                # +0, and 0x00bd8528 binary-searches it with a SIGN-EXTENDING
                # `lw` against a 64-bit compare -- so a uid with bit 31 set
                # (0xa756a69a is one) stores fine and may never be found. Rather
                # than guess which id the UI resolves, serve a SPREAD: the asked
                # id plus 1..N. The cache holds 32 and the client drops the ones
                # it does not want, so the sweep costs nothing but bytes.
                _sweep_ids = []
                if a.user_list_sweep:
                    _sweep_ids = [i for i in range(1, a.user_list_sweep + 1)
                                  if i not in _ids]
                    _ids = _ids + _sweep_ids
                # KEY: sec 4fx (2026-09-13): f36 (wire+36) is the o099 LOOK, and
                # --user-costume stamped Lex's 0x1012 on EVERY record -- this
                # player's own and the other player's alike -- so everyone wore
                # Lex. Each record now carries its own player's SELECTED
                # character: this client's for the first (self) record, the
                # shared registry's for another player. --user-costume is only
                # the fallback for ids with no known look (the sweep).
                def _ul_fields(_uid):
                    _f = dict(peerrecords._user_rec_fields(a) or {})
                    if _uid in (_ids[0], seen_charid[0]):
                        _lk = _player_look(sess)
                    else:
                        _lk = players.get(_uid, {}).get("look")
                        if _lk is None:
                            _lk = player_look.get(_uid)
                    if _lk is not None:
                        _f["f36"] = _lk & 0xFFFF
                    if _uid in players:          # real players only, not sweep ids
                        _f.update(peer_addr(_uid, src[0], seen_charid[0] or _ids[0]))
                    # 2026-10-05 (live): the list left rank unset, so it shipped
                    # 0 = "DGD-3" for a DGD-2; the career rank, as the peer
                    # records carry it (--user-rank still wins when set)
                    if "rank" not in _f and _uid in (_ids[0], seen_charid[0]) + tuple(players):
                        _rk = rank_of_cid(_uid)
                        if _rk is not None:
                            _f["rank"] = _rk
                    return _f
                _ul_recs = [peerrecords.build_peer_record(
                    _uid, name=(players.get(_uid, {}).get("name")
                                or (_player_name() if _uid == _ids[0]
                                    else "Slot%d" % _uid)),
                    **_ul_fields(_uid)) for _uid in _ids]
                ul = userlist.build_user_list_answer(
                    data, _ids, seq=a.lobby_seq,
                    name=_player_name(), records=_ul_recs,
                    fields=peerrecords._user_rec_fields(a),
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7),
                    ptype=a.world_type, ident=_ident,
                    answer_selector=_ans)
                s.sendto(ul, src)
                print("  SENT type-%d USER LIST (selector %d -> %d) total=1 "
                      "index=0 records=%d uid=0x%08x%s"
                      % (a.world_type, _req_sel, _ans, len(_ids), _ids[0],
                         "  (+%d swept)" % (len(_ids) - 1) if len(_ids) > 1
                         else ""), flush=True)
                # KEY: sec 4dj: THE USER LIST AND THE PEER TABLE ARE DIFFERENT
                # TABLES, and the battletable check reads the one we never fill.
                # Measured in doc_reserve_slot06 with --user-list-sweep=32 live:
                #     CACHE [kelsvc+280] count = 32   <- the sweep landed here
                #     PEER  [kelsvc+284] count =  0   <- and this stayed empty
                # getCharacterTableId does `lw a0, 284(a0)` on kelsvc, i.e. the
                # PEER table, so its lookup still missed and still returned
                # 0xffff4867 as the "table id". The cache is the Status/Profile
                # rung; the peer table is selector 37's.
                #
                # Nothing ever fills the peer table unsolicited (sec 4bw: it is a
                # PULL -- the client asks with selector 36 on a type-125 cache
                # miss, and it has never once asked). But selector 37's arm
                # 0x00bccee8 has NO state gate, so an unsolicited answer simply
                # runs and inserts. Push one per swept id, right here, where the
                # client has just proved it is in the right state and `_ident` is
                # known good.
                if a.peer_push:
                    # KEY:KEY: ID 0 IS THE ONE THAT MATTERS, and no sweep produces it.
                    # getMyCharaId() is `lw v0, 272(a0)` on kelsvc (0x00bdb2b0),
                    # i.e. [kelsvc+272] -- which is 0 in every savestate we hold,
                    # because the code that sets it has never been reached (sec
                    # 4ch). So the client looks ITSELF up by id 0, while
                    # --user-list-sweep serves 1..N. Proven in doc_eemu against
                    # doc_reserve_slot06:
                    #     before            getCharacterTableId(0) = -47001
                    #     after pushing 7   getCharacterTableId(0) = -47001
                    #     after pushing 0   getCharacterTableId(0) = 0
                    # 0 = "no battletable", which is the whole point.
                    # sec 4dv: id 0 was only ever right BECAUSE [kelsvc+272]
                    # was 0. Now that the roster carries a real id, push the id
                    # the client itself is using -- record+4 of its own
                    # messages -- and fall back to 0 for the old behaviour.
                    _self = seen_charid[0]
                    # 2026-09-13: never the sweep ids. The peer table IS what
                    # Player Search searches (0x00bda970, name prefix), and
                    # they went in under the ASKER's name: 32 "Lex" rows.
                    _push_ids = doc_playtime.peer_push_ids(_self, players, _ids,
                                                           _sweep_ids)
                    for _pid in _push_ids:
                        _pnm = (players.get(_pid, {}).get("name")
                                or _player_name())
                        pp = peerrecords.build_peer_answer(
                            data, _pid, seq=a.lobby_seq,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7),
                            ptype=a.world_type, ident=_ident,
                            blob=peerrecords.build_peer_record(
                                _pid, name=_pnm,
                                zone=a.user_zone, rank=rank_of_cid(_pid),
                                flags=peer_flags(_pid),
                                # sec 4fu (look): another player's look, so
                                # a zero record cannot win the peer table
                                f36=(player_look.get(_pid)
                                     if _pid != _self else None),
                                **(peer_addr(_pid, src[0], _self)
                                   if _pid in players else {}))[4:])
                            # sec 4et (2026-09-11): [4:] DROPS the redundant
                            # leading id. build_peer_answer re-embeds `blob` at
                            # record+4 (it prepends ent_id itself), so passing a
                            # FULL build_peer_record shifted every field +4 --
                            # the zone (wire+32, which getCharacterTableId reads
                            # at peer slot+42) landed at wire+36/slot+40 instead,
                            # leaving slot+42 = 0 = "table 0" = the false
                            # "already reserved". Dropping the id aligns zone ->
                            # wire+32 -> slot+42 = --user-zone (0xffff = none).
                            # Verified on the live build's 0x00bd9090 (slot 6).
                        s.sendto(pp, src)
                    print("  SENT %d unsolicited PEER answers (selector %d), ids "
                          "%d..%d INCLUDING 0x%08x -- that is what "
                          "getMyCharaId() returns ([kelsvc+272], read off the "
                          "client's own record+4), and it is the id the "
                          "battletable check looks up (sec 4dj/4dv)"
                          % (len(_push_ids), peerrecords.PEER_SELECTOR_ANS,
                             min(_push_ids), max(_push_ids), _self), flush=True)
                _served_list = True
            else:
                _served_list = False
            _miss = peerrecords.peer_miss_id(data, inner)
            if a.peer_answer and _miss is not None:
                # sec 4fu: a miss on a RELAYED peer gets that peer's record
                _rn = relay_names.get(_miss)
                pr = peerrecords.build_peer_answer(data, _miss, seq=a.lobby_seq,
                                       subchannel=(a.world_subchannel
                                                   if a.world_subchannel >= 0 else 7),
                                       ptype=a.world_type, ident=_ident,
                                       blob=(peerrecords.build_peer_record(
                                           _miss, name=_rn, zone=a.user_zone,
                                           rank=rank_of_cid(_miss),
                                           flags=peer_flags(_miss),
                                           f36=player_look.get(_miss),
                                           **peer_addr(_miss, src[0],
                                                       seen_charid[0]))[4:]
                                             if _rn else None))
                s.sendto(pr, src)
                print("  SENT type-%d PEER answer (selector %d -> %d) for entity "
                      "0x%08x  [%s]"
                      % (a.world_type, peerrecords.PEER_SELECTOR_REQ, peerrecords.PEER_SELECTOR_ANS,
                         _miss, ("relayed peer %s" % _rn) if _rn
                         else "zero record"), flush=True)
            # NO `continue` -- the rest of the loop still owes this datagram its
            # ACK, which is exactly the omission that cost the phase-29 round in
            # sec 4bt ("we ACKed it and never answered" is the mirror of it).
            if _req_sel == doc_chat.SEL_CHAT:
                relay_chat(_ident or seen_charid[0], worldchannel.request_body(data, inner))
            if _unpairable and not a.world_answer_unpairable:
                print("  (selector %s is UNPAIRABLE -- NOT answering; sending it "
                      "--world-selector-next=%d would reset [kelsvc+12], sec 4bz)"
                      % (_req_sel, a.world_selector_next), flush=True)
            # KEY: SELECTOR 241's body[12] IS THE COMMAND ID, not a result word.
            # build_world_answer packs `result` there, it defaults to 0, and the
            # handler's window is [3, 41] -- so every "Command Result" we have
            # ever sent bailed at 0x00bc9274 before it selected anything.  Echo
            # the id the client itself put at request body[12] (lobby_cmd_id).
            # WARNING: ONE OFFSET, TWO MEANINGS: on selector 13 body[12] really is the
            # result and must stay 0, so this override is keyed on the ANSWER
            # rung and nothing else.
            _result = a.world_result
            # sec 4ep (2026-09-11): a phantom/unknown JOIN (see the JOIN
            # block above) must fail so the client never sets [kelsvc+1092]
            # bit 4. The generic ladder answers selector 20/30 with 21/31
            # (a GS_ENDPOINT_SELECTORS rung), whose body[12..15] result the
            # phase-44 JOIN arm reads: 0/positive = success (reserved), a
            # negative = "no such table". Override it to -1 here.
            if _bt_phantom_join:
                _result = _bt_join_result
            _cmd = None
            _cmd_arg = None
            if _sel == lobbycmd.LOBBY_CMD_SELECTOR_ANS and a.lobby_cmd != "off":
                _cmd = (lobbycmd.lobby_cmd_id(data, inner) if a.lobby_cmd == "echo"
                        else int(a.lobby_cmd, 0))
                if _cmd is not None:
                    _result = _cmd
                    if _cmd == lobbycmd.LOBBY_CMD_QUEST:
                        _qb = worldchannel.request_body(data, inner)
                        _qid = (struct.unpack_from("<H", _qb, 16)[0]
                                if _qb is not None and len(_qb) >= 18 else 0)
                        if _qid:
                            _quest_pick[sess.key] = (_qid, time.time())
                            print("  [quest] %s picked Solo quest %d (command "
                                  "41) -- the next Start plays it as a MISSION%s"
                                  % (src[0], _qid, "" if a.quest_mission
                                     else " (OFF: --no-quest-mission)"),
                                  flush=True)
                    # 2026-09-23 (sec 4hc): command 33 = clearNovicePlayerFlag
                    # (the Cactuar Beginner's Machine). Answer with the 241 whose
                    # sub-33 arm clears the local mark (doc_novice_proof C), then
                    # record it and tell every client (selector 134 sub 11).
                    if (_cmd in (lobbycmd.LOBBY_CMD_ANONYMOUS,
                                 lobbycmd.LOBBY_CMD_PUBLIC) and _stats is not None):
                        # 2026-10-01: Status -> Public / Anonymous. Keep it, and
                        # tell every client (selector 134 sub 0 sets peer flag
                        # 0x04, sub 1 clears it; the sender's own copy too).
                        _vcid = _ident or seen_charid[0] or 0
                        _vkey = _wallet_key(seen_uid[0], _vcid)
                        _vpriv = _stats.set_private(
                            _vkey, _cmd == lobbycmd.LOBBY_CMD_ANONYMOUS, rid=_vcid)
                        _vn = 0
                        for _vs in list(sessions.values()):
                            if not _vs.seen_charid[0] or peer_idle(_vs, time.time()):
                                continue
                            if send_push(_vs, doc_novice.push_body(
                                    0 if _vpriv else 1, 0,
                                    (a.world_subchannel if a.world_subchannel >= 0
                                     else 7)), _vcid,
                                    "sub %d (record %s for 0x%08x)"
                                    % (0 if _vpriv else 1,
                                       "Anonymous" if _vpriv else "Public", _vcid)):
                                _vn += 1
                        print("  [stats] [%s] record set %s (command %d), told %d "
                              "client(s)" % (_vkey, "ANONYMOUS" if _vpriv else
                                             "PUBLIC", _cmd, _vn), flush=True)
                    if _cmd == doc_novice.CMD_GRADUATE and _novice is not None:
                        _gcid = (_ident or seen_charid[0] or 0)
                        s.sendto(worldchannel.seal_world_body(data, doc_npc.answer_body(
                            _cmd, subchannel=(a.world_subchannel
                                              if a.world_subchannel >= 0 else 7)),
                            seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                        _served_list = True
                        _gk = _novice_key(sess)
                        if _gk is not None and _novice.graduate(_gk, "machine"):
                            broadcast_graduate(_gcid, "Beginner's Machine, command 33")
                        else:
                            print("  [novice] command 33 from [%s]: already "
                                  "graduated, answered only" % _gk, flush=True)
                    # command 27 id 1 = the intro chain finished (ev2046.main).
                    if (_cmd == doc_novice.CMD_EVENT_DONE and _novice is not None
                            and doc_novice.event_done_id(worldchannel.request_body(data, inner))
                            == doc_novice.EV_INTRO):
                        _ik = _novice_key(sess)
                        if _ik is not None and _novice.mark_intro_seen(_ik):
                            print("  [intro] [%s] finished the new-player intro "
                                  "(command 27 id 1) -- recorded, it will not "
                                  "play again" % _ik, flush=True)
                        # sec 4hg addendum 3: no notify here. Kind 39 was
                        # tried (after command 27, and 8 s into the intro):
                        # the client drops every game-server message but
                        # the keepalive until obj+0x858 (a battle join) is
                        # set, and the crash is the zone loader, not the
                        # facade standby.
                    if _cmd == lobbycmd.LOBBY_CMD_PLAYTIME:
                        if a.lobby_clock == "play":
                            _cmd_arg = _playtime.answer(_wallet_key(
                                seen_uid[0], _ident or seen_charid[0]))
                        else:
                            _cmd_arg = lobbycmd.lobby_clock_value(a.lobby_clock)
                    # sec 4dz: KICK (2) and APPOINT LEADER (1) are lobby
                    # commands whose 12-byte argument opens with the target's
                    # character id (0x00bd1cf0 / 0x00bd1c28 pass &target as a3
                    # to the 0x00589c48 builder, which copies it to body[16]).
                    if (a.battletable_verbs and _cmd in (lobbycmd.LOBBY_CMD_KICK,
                                                         lobbycmd.LOBBY_CMD_APPOINT)
                            and _bt_body is not None and len(_bt_body) >= 20):
                        _tgt = struct.unpack_from("<I", _bt_body, 16)[0]
                        _tkey = bt_store.table_of(_ident or 0)
                        _ok = (bt_store.kick if _cmd == lobbycmd.LOBBY_CMD_KICK
                               else bt_store.appoint)(_tkey, _tgt, _ident,
                                                      uid=seen_uid[0])
                        print("  [battletable] command %d %s 0x%08x at table %s "
                              "-> %s" % (_cmd, "KICK" if _cmd == lobbycmd.LOBBY_CMD_KICK
                                         else "APPOINT", _tgt, _tkey,
                                         "ok" if _ok else
                                         "REFUSED (not a member, or not the "
                                         "leader -- sec 4he)"),
                              flush=True)
                        if _ok and _cmd == lobbycmd.LOBBY_CMD_KICK:
                            vacate_seat(_tgt, "kicked")
                    # 2026-09-13: UNIT MANAGEMENT (doc_unit.py). The panel's
                    # commands get a real 241 instead of the sec 4dy zeroes:
                    # lists for 24/13/25, a verdict for 8/12/9/10/11 (fee or
                    # SE's refusal code in the header, body[4]/body[6]).
                    if _units is not None and _cmd in doc_unit.UNIT_CMDS:
                        _uk = _wallet_key(seen_uid[0], _ident or seen_charid[0])
                        _ub, _un = _units.body_for(
                            _cmd, worldchannel.request_body(data, inner), _uk,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7))
                        if _ub is not None:
                            s.sendto(worldchannel.seal_world_body(data, _ub, seq=a.lobby_seq,
                                                     ptype=a.world_type,
                                                     ident=_ident), src)
                            _served_list = True
                        print("  %s type-%d UNIT selector %d -> %d [%s]: %s"
                              % ("SENT" if _ub is not None else "NOT SENT (generic "
                                 "answer instead)", a.world_type,
                                 lobbycmd.LOBBY_CMD_SELECTOR_REQ, lobbycmd.LOBBY_CMD_SELECTOR_ANS,
                                 _uk, _un), flush=True)
                    # 2026-09-24: UNIT VERSUS INFO (command 34, doc_unit). The
                    # unit table's window asks for the two sides; the Start
                    # gate 0x00aa12c8 counts the nonzero unit ids in this
                    # answer and refuses (0x683b) below two. The sides are the
                    # first two units seated -- the same rule JOIN enforces.
                    if _units is not None and _cmd == doc_unit.CMD_VERSUS:
                        _vreq = worldchannel.request_body(data, inner)
                        _vtid = (struct.unpack_from("<H", _vreq, 16)[0]
                                 if _vreq is not None and len(_vreq) >= 18
                                 else bt_store.table_of(_ident or 0) or 0)
                        _vt = bt_store.tables.get(_vtid)
                        _vmem = list(_vt["members"]) if _vt is not None else []
                        _vuo = {m: _unit_of_cid(m) for m in _vmem}
                        _vsides = [(u, (_units.unit(u) or {}).get("name")
                                    or "Unit %X" % (u & 0xFFFFFFFF),
                                    sum(1 for m in _vmem if _vuo[m] == u))
                                   for u in doc_unit.unit_sides(_vmem, _vuo.get)]
                        s.sendto(worldchannel.seal_world_body(
                            data, doc_unit.versus_body(
                                _vtid, _vsides,
                                subchannel=(a.world_subchannel
                                            if a.world_subchannel >= 0 else 7)),
                            seq=a.lobby_seq, ptype=a.world_type, ident=_ident), src)
                        _served_list = True
                        print("  [units] SENT UNIT VERSUS (command 34) for table %d: "
                              "%s -> Start %s" % (
                                  _vtid, " vs ".join("%s %r x%d" % (
                                      doc_unit.hexid(u), n, c) for u, n, c in _vsides)
                                  or "no units seated",
                                  "OPEN (2 units)" if len(_vsides) >= 2 else
                                  "REFUSED client-side (0x683b) until a 2nd unit "
                                  "joins"), flush=True)
                    # 2026-09-13: CHANGE MASK / ARMOR (doc_gear.py). Command 17
                    # EQUIP(slot, item) / 18 UNEQUIP(slot): the 241 arm stores
                    # body[6] VERBATIM as the costume code (R+728), so the
                    # generic zero answer reset the character's look. Answer
                    # with the new code and remember (mask, suit, costume).
                    if _gearstore is not None and _cmd in doc_gear.GEAR_CMDS:
                        _gcid = (_ident or seen_charid[0] or 0) & 0x3FFFFFFF
                        _gk = _wallet_key(seen_uid[0], _gcid)
                        _gbase = None
                        if _store is not None and seen_uid[0]:
                            _gr = _store.roster(_skey(seen_uid[0]))
                            for _gi in range(doc_charastore.MAX_SLOTS):
                                if sess.chara_ids.get(_gi) == _gcid and _gr[_gi]:
                                    _gbase = doc_charastore.chr_code(_gr[_gi])
                                    break
                        _gb, _gn = _gearstore.body_for(
                            _cmd, worldchannel.request_body(data, inner), _gk, _gbase,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7))
                        if _gb is not None:
                            s.sendto(worldchannel.seal_world_body(data, _gb, seq=a.lobby_seq,
                                                     ptype=a.world_type,
                                                     ident=_ident), src)
                            _served_list = True
                            # the relayed peer records carry the new look now
                            _gear_look[_gcid] = (_gearstore.get(_gk) or {}).get("costume")
                        print("  %s type-%d GEAR selector %d -> %d: %s"
                              % ("SENT" if _gb is not None else "NOT SENT (generic "
                                 "answer instead)", a.world_type,
                                 lobbycmd.LOBBY_CMD_SELECTOR_REQ, lobbycmd.LOBBY_CMD_SELECTOR_ANS,
                                 _gn), flush=True)
                    # 2026-09-13: LOBBY NPCs (doc_npc.py). Command 26 is Java
                    # checkQuestEvent(trigger, 0): the answer's body[6] is the
                    # event the client plays (quest_scr003 NPC scene); 27 =
                    # scene done, 39 = clear. Every request is logged raw -- the
                    # trigger == NPC number reading is not yet confirmed on a console.
                    if a.npc == "on" and _cmd in doc_npc.NPC_CMDS:
                        # 2026-09-23: the INSTRUCTORS (NPCs 7-10) answer from
                        # the career when the mission ledger is on: no battle
                        # yet / fewer than three / not enough rank points / the
                        # exam authorized -- which "adds it to Missions" here,
                        # on the answer, exactly as the dialogue says. An
                        # admin --npc-events override for that trigger still
                        # wins; only the b == 0 walk-up is judged.
                        _npc_use = _npc_over
                        _nq = doc_npc.parse_request(worldchannel.request_body(data, inner))
                        if (_ledger and _cmd == doc_npc.CMD_CHECK and _nq
                                and _nq["b"] == 0
                                and _nq["trigger"] in doc_missions.INSTRUCTORS
                                and _nq["trigger"] not in _npc_over):
                            _mkey = _wallet_key(seen_uid[0],
                                                _ident or seen_charid[0])
                            _mc = _stats.peek(_mkey)
                            _mev, _mgrant, _mwhy = doc_missions.instructor_event(
                                _nq["trigger"], _mc)
                            if _mgrant is not None:
                                _mc = _stats.career(_mkey)
                                if doc_missions.grant(_mc, _mgrant):
                                    _stats.save()
                            _npc_use = dict(_npc_over)
                            _npc_use[_nq["trigger"]] = _mev
                            print("  [missions] instructor NPC %d for [%s]: rank %d, "
                                  "%d rp, %d battle(s), open %s -> event %d (%s)"
                                  % (_nq["trigger"], _mkey, _mc.get("rank", 1),
                                     _mc.get("rp", 0), _mc.get("battles", 0),
                                     _mc.get("quests_open") or [], _mev, _mwhy),
                                  flush=True)
                        # 2026-09-24: ARGENTO (lnpc 4) answers from the career
                        # too: first meeting 302 / asks again 304 / the chain
                        # 305 / chain complete 300; the accept arm's (4, 2)
                        # records the rank held (doc_missions.argento_event).
                        # An exact --npc-events 4:B:E (or 4:E for the walk-up)
                        # still wins.
                        if (_ledger and _cmd == doc_npc.CMD_CHECK and _nq
                                and _nq["trigger"] == doc_missions.ARGENTO
                                and (_nq["trigger"], _nq["b"]) not in _npc_over
                                and (_nq["b"] or _nq["trigger"] not in _npc_over)):
                            _akey = _wallet_key(seen_uid[0],
                                                _ident or seen_charid[0])
                            _ac = _stats.peek(_akey)
                            _aev, _ast, _awhy = doc_missions.argento_event(
                                _ac, _nq["b"])
                            if _ast is not None:
                                _ac = _stats.career(_akey)
                                _ac[doc_missions.ARGENTO_KEY] = _ast
                                _stats.save()
                            _npc_use = dict(_npc_over)
                            _npc_use[(_nq["trigger"], _nq["b"])] = _aev
                            print("  [missions] Argento for [%s] (b %d): rank %d, "
                                  "state %s -> event %d (%s)"
                                  % (_akey, _nq["b"], _ac.get("rank", 1),
                                     _ac.get(doc_missions.ARGENTO_KEY) or {},
                                     _aev, _awhy), flush=True)
                        # 2026-09-24: the ITEM QUESTS -- Soar (26, broken items
                        # by wins), Este-D (29, Dandelion -> Gasmask at random),
                        # Hiren (36, grows a Fuzzy Seed over 7 days) answer
                        # from the career + the server bag (doc_npcquests).
                        if (_ledger and _shop is not None
                                and _cmd == doc_npc.CMD_CHECK and _nq
                                and _nq["b"] == 0
                                and _nq["trigger"] in doc_npcquests.NPCS
                                and _nq["trigger"] not in _npc_over):
                            _qkey = _wallet_key(seen_uid[0],
                                                _ident or seen_charid[0])
                            _qc = _stats.career(_qkey)
                            _qbag = {int(k, 16): v for k, v in
                                     _shop.wallet(_qkey)["bag"].items()}
                            _qev, _qst, _qmv, _qwhy = doc_npcquests.decide(
                                _nq["trigger"], _qc, _qbag,
                                day=a.npc_quest_day,
                                accept=a.npc_este_accept,
                                wither=a.npc_hiren_wither)
                            doc_npcquests.apply(_qc, _nq["trigger"], _qst)
                            _stats.save()
                            _qmoved = _bag_move(_qkey, _qmv)
                            _npc_use = dict(_npc_use)
                            _npc_use[_nq["trigger"]] = _qev
                            print("  [npcquest] NPC %d for [%s]: %s -> event %d%s"
                                  % (_nq["trigger"], _qkey, _qwhy, _qev,
                                     (" (bag %s)" % _qmoved) if _qmoved else ""),
                                  flush=True)
                        # ...and the scene reporting itself DONE (command 27)
                        # is where the gifts / trades happen
                        if (_ledger and _shop is not None
                                and _cmd == doc_novice.CMD_EVENT_DONE):
                            _qdone = doc_novice.event_done_id(
                                worldchannel.request_body(data, inner))
                            _qkey = _wallet_key(seen_uid[0],
                                                _ident or seen_charid[0])
                            _qc = _stats.career(_qkey)
                            _qr = doc_npcquests.on_done(_qdone, _qc)
                            if _qr is not None:
                                _qn, _qst, _qmv, _qwhy = _qr
                                doc_npcquests.apply(_qc, _qn, _qst)
                                _stats.save()
                                _qmoved = _bag_move(_qkey, _qmv)
                                print("  [npcquest] NPC %d scene %d DONE for [%s]: "
                                      "%s%s" % (_qn, _qdone, _qkey, _qwhy,
                                                (" (bag %s)" % _qmoved)
                                                if _qmoved else ""), flush=True)
                        _nb, _nn = doc_npc.body_for(
                            _cmd, worldchannel.request_body(data, inner), _npc_use,
                            subchannel=(a.world_subchannel
                                        if a.world_subchannel >= 0 else 7))
                        if _nb is not None:
                            s.sendto(worldchannel.seal_world_body(data, _nb, seq=a.lobby_seq,
                                                     ptype=a.world_type,
                                                     ident=_ident), src)
                            _served_list = True
                        print("  [npc] %s command %d (%s): %s"
                              % ("SENT 241" if _nb is not None else "NOT SENT",
                                 _cmd, doc_npc.CMD_NAMES.get(_cmd, "?"), _nn),
                              flush=True)
            # sec 4dr AUTO-DRESS (2026-09-11): on the selector-2 world-door reply,
            # dress the lobby avatar from the SELECTED character's stored look.
            # The world-door request names the chosen character at body+80 (u32
            # char id, MEASURED: Lex 0x0002a664 sits there); match it to the
            # account's roster, turn its charamake nibbles into the costume code
            # (doc_charastore.chr_code) and hand it to build_world_answer, which
            # writes it at the pinned body+100. --self-costume (raw) still wins.
            _self_cost = a.self_costume
            if a.self_costume_file and _sel == 2:
                # sec 4dr live calibration: read the code FRESH each time so it
                # can be changed with a file write + one lobby re-entry, no
                # recreate. Overrides --self-costume and --self-costume-auto.
                try:
                    with open(a.self_costume_file) as _scf:
                        _sct = _scf.read().strip()
                    if _sct:
                        _self_cost = int(_sct, 0) & 0xFFFF
                except (OSError, ValueError):
                    pass
            # 2026-10-05: every per-character store keys on THIS id. Each
            # lookup below used to re-check the request length and drop it to 0
            # for a SHORT world-door request (a re-entry after a battle) --
            # undoing the session fallback: live, Ruuko's world door served
            # the bare account's wallet and career (rank 1, 0 RP, no medals),
            # and every result then "awarded" the career's old medals again.
            _wd_cid = _world_door_charid(data, sess) if _sel == 2 else 0
            if (_self_cost is None and a.self_costume_auto and _store is not None
                    and _sel == 2 and seen_uid[0]
                    and len(data) >= framing.BODY_OFF + 84):
                _sel_cid = _wd_cid & 0x3FFFFFFF
                _sl_roster = _store.roster(_skey(seen_uid[0]))
                for _si in range(doc_charastore.MAX_SLOTS):
                    if sess.chara_ids.get(_si) == _sel_cid and _sl_roster[_si]:
                        _self_cost = doc_charastore.chr_code(_sl_roster[_si])
                        print("  [self-costume] dressing selected char id 0x%08x "
                              "(slot %d, %s) -> code 0x%04x at body+100"
                              % (_sel_cid, _si, _sl_roster[_si].get("name", "?"),
                                 _self_cost), flush=True)
                        break
            # sec 4ew (2026-09-11): the self-record id (mgr+304 [+52]) is set
            # ONCE, from the state-1 selector-2 world-door answer's body[44]
            # (RE: 0x00bc8aa0 setMySelfRecord, key = datagram+68 = body[44]).
            # The charaid isn't yet learnable from record+4 at that first
            # message -- but the selector-2 REQUEST already carries the SELECTED
            # character id at body[80] (the same id the self-costume path reads),
            # which IS [kelsvc+272]. Read it straight from the request so the
            # override lands on the FIRST message, unconditionally.
            # 2026-09-13: the SELECTED character's name for the self record
            # (world-door body[112..127]); same selection as self-costume-auto.
            _self_name = None
            if (a.self_name and _store is not None and _sel == 2 and seen_uid[0]
                    and len(data) >= framing.BODY_OFF + 84):
                _nc = _wd_cid & 0x3FFFFFFF
                _nr = _store.roster(_skey(seen_uid[0]))
                for _si in range(doc_charastore.MAX_SLOTS):
                    if sess.chara_ids.get(_si) == _nc and _nr[_si]:
                        _self_name = _nr[_si].get("name") or None
                        break
                if _self_name:
                    print("  [self-name] selector 2: self record name <- %r at "
                          "answer body[112..127] (char 0x%08x)" % (_self_name, _nc),
                          flush=True)
            # LEARN the character id here. The world door
            # clears seen_charid (sec 4dv) and it came back only from a later
            # request's record+4 -- but lobby commands (selector 240: units,
            # Start) carry ident 0, so a player who went straight to Unit
            # Management was keyed as the bare account ("member:15"), saw 0
            # units, and every Create was refused as "already a unit".
            if _sel == 2 and len(data) >= framing.BODY_OFF + 84:
                _wdc = _wd_cid & 0x3FFFFFFF
                if _wdc and not seen_charid[0]:
                    seen_charid[0] = _wdc
                    print("  [charid] 0x%08x from the world-door request "
                          "body[80] (the selected character)" % _wdc, flush=True)
            _world_self_id = None
            if (a.world_self_charaid and _sel == 2
                    and len(data) >= framing.BODY_OFF + 84):
                _wsi = _wd_cid & 0x3FFFFFFF
                if _wsi:
                    _world_self_id = _wsi
                    print("  [world-self-charaid] selector 2: self-record id <- "
                          "0x%08x (selected charaid, req body[80]) at answer "
                          "body[44]; keys mgr+304 by charaid (sec 4ew)"
                          % _wsi, flush=True)
            # sec 4gk: the selected character's gil and bag on the world door.
            # The request names the character at body[80] -- the same id every
            # later request carries at record+4, which keys its 145s.
            _shop_gil = _shop_bag = None
            if _shop is not None and _sel == 2:
                _lc = (_wd_cid & 0x3FFFFFFF)
                _lk = _wallet_key(seen_uid[0], _lc)
                _shop_gil, _shop_bag = _shop.login_fields(_lk)
                print("  [shop] selector 2 [%s]: gil %d at body[52], bag %d "
                      "item(s) at body[140]/[240+]: %s"
                      % (_lk, _shop_gil, len(_shop_bag),
                         ", ".join("%s x%d" % (_shop.name(i), q)
                                   for i, q in _shop_bag) or "(empty)"),
                      flush=True)
            # sec 4go: top the bag up with the issued bullets -- without them
            # every magazine stays 0 (0x004a5780) and the gun never fires.
            if _ammo and _sel == 2:
                _shop_bag = doc_shop.issue_items(_shop_bag, _ammo)
                print("  [ammo] selector 2: bag now %s (issued, not persisted; "
                      "sec 4go)" % ", ".join("0x%08x x%d" % (i, q)
                                             for i, q in _shop_bag), flush=True)
            if _sel == 2 and a.mission_supplies:
                _supply_bag[sess.key] = {
                    i: q for i, q in (_shop_bag or ())
                    if i in doc_missions.SUPPLY_ITEMS}
            # 2026-09-13: the starter MASK + SUIT, in the bag and equipped at
            # body[76]/[80] (doc_shop.starter_gear). The mask follows the
            # selected character's gender: chr_code bit 6, 1 = female (the
            # repacker 0x005a2598 reads it there).
            _gear_login = None
            if a.issue_gear == "standard" and _sel == 2:
                _gc = (_wd_cid & 0x3FFFFFFF)
                _female, _armor = False, 0
                if _store is not None and seen_uid[0]:
                    _gr = _store.roster(_skey(seen_uid[0]))
                    for _gi in range(doc_charastore.MAX_SLOTS):
                        if sess.chara_ids.get(_gi) == _gc and _gr[_gi]:
                            _code = doc_charastore.chr_code(_gr[_gi])
                            _female = bool(_code & 0x40)
                            _armor = doc_gear.armor_of(_code)
                            break
                # the suit follows the creation ARMOR pick (chr_code bits 3-5)
                _gear_login = doc_gear.starter_gear(_female, _armor)
                # 2026-09-26: the Soldier Mask is EARNED (Drone 2nd exam), not
                # issued -- worn only when the persisted bag holds one (a
                # character made before the rule keeps its own). Without a
                # shop there is no bag to hold it: the old issue stands.
                _mask_note = "issued (no --shop)"
                if _shop is not None:
                    _mw = _shop.wallet(_wallet_key(seen_uid[0], _gc))
                    _mheld, _mnotes = doc_gear.settle_soldier_mask(
                        _mw, _female, doc_shop.BAG_MAX)
                    if _mnotes:
                        _shop.save()
                    _gear_login = (_mheld if _mheld is not None
                                   else doc_gear.NO_ITEM, _gear_login[1])
                    _mask_note = ("held" if _mheld is not None
                                  else "none (earned on the Drone 2nd exam)")
                    if _mnotes:
                        _mask_note += "; " + "; ".join(_mnotes)
                _shop_bag = doc_shop.issue_items(
                    _shop_bag, [(i, 1) for i in _gear_login
                                if i != doc_gear.NO_ITEM])
                print("  [gear] selector 2 (char 0x%08x, %s): mask 0x%08x at "
                      "body[76] [%s], suit 0x%08x at body[80], in the bag"
                      % (_gc, "F" if _female else "M", _gear_login[0],
                         _mask_note, _gear_login[1]), flush=True)
            # 2026-09-13: the character's OWN mask/suit/costume once it has
            # changed them (doc_gear.GearStore, lobby commands 17/18). The
            # starter pair stays in the bag; --self-costume(-file) still win.
            if _gearstore is not None and _sel == 2:
                _gcl = (_wd_cid & 0x3FFFFFFF)
                _glk = _wallet_key(seen_uid[0], _gcl)
                if _gearstore.get(_glk) is not None:
                    _gm, _gsu, _gco = _gearstore.login(_glk, _gear_login, _self_cost)
                    _gear_login = (_gm, _gsu)
                    if (a.self_costume is None and not a.self_costume_file
                            and _gco is not None):
                        _self_cost = _gco
                    print("  [gear-store] selector 2 [%s]: mask 0x%08x, suit 0x%08x, "
                          "costume %s (the character's own changes)"
                          % (_glk, _gm, _gsu, "0x%04x" % _self_cost
                             if _self_cost is not None else "unset"), flush=True)
            # 2026-09-24: the HP follows the suit served at body[80] -- the
            # retail server's durability lookup (doc_gear.suit_hp).
            _hp_login = a.self_hp if (a.self_hp and _sel == 2) else None
            if _sel == 2 and _gear_login is not None:
                sess.suit_item = _gear_login[1]
            if a.suit_hp == "on" and _sel == 2 and _gear_login is not None:
                _shp = doc_gear.suit_hp(_gear_login[1])
                if _shp is not None:
                    _hp_login = _shp
                print("  [hp] selector 2: suit 0x%08x -> HP %s at body[48]%s"
                      % (_gear_login[1], _hp_login,
                         "" if _shp is not None else " (unknown suit, --self-hp)"),
                      flush=True)
            # 2026-09-13: the selected character's enlisted unit (or 0) on the
            # world door, keyed like its shop wallet (doc_unit.py).
            _unit_login = None
            if _units is not None and _sel == 2:
                _uc = (_wd_cid & 0x3FFFFFFF)
                _ulk = _wallet_key(seen_uid[0], _uc)
                _unit_login = _units.enlisted(_ulk)
                print("  [units] selector 2 [%s]: enlisted unit 0x%x at "
                      "body[60..67] (R+720)" % (_ulk, _unit_login), flush=True)
            # 2026-09-13: the selected character's career (doc_stats.py), keyed
            # like its shop wallet -- medal mask, rank points and rank.
            _career_login = None
            if _stats is not None and _sel == 2:
                _cc = (_wd_cid & 0x3FFFFFFF)
                _clk = _wallet_key(seen_uid[0], _cc)
                _career_login = _stats.peek(_clk)
                print("  [stats] selector 2 [%s]: rank %d, %d rank points, medal "
                      "mask 0x%06x at body[131]/[68]/[56]"
                      % (_clk, doc_stats.clamp_rank(_career_login["rank"]),
                         _career_login["rp"], doc_stats.medal_mask(_career_login)),
                      flush=True)
            # 2026-09-23 (sec 4hc): the selected character's NOVICE mark.
            _novice_login = False
            if (_novice is not None and a.novice == "on" and _sel == 2
                    and len(data) >= framing.BODY_OFF + 84):
                _nvc = _wd_cid
                _nvk = _wallet_key(seen_uid[0], _nvc)
                _novice_login = _novice.is_novice(_nvk)
                print("  [novice] selector 2 [%s]: %s (body[129] bit 0x40 %s)"
                      % (_nvk, "NOVICE" if _novice_login else "graduated",
                         "SET" if _novice_login else "clear"), flush=True)
            wr = None if (_served_list or (_unpairable
                                           and not a.world_answer_unpairable)
                          or (a.peer_answer and _miss is not None)) else worlddoor.build_world_answer(
                data, selector=_sel, seq=a.lobby_seq,
                subchannel=(a.world_subchannel if a.world_subchannel >= 0 else 7),
                inner_ip=_lip, ptype=a.world_type, pad_to=a.world_pad,
                ident=_ident, result=_result, cmd_arg=_cmd_arg,
                # WARNING:KEY: sec 4dw: ONLY on the endpoint rungs, and NEVER empty.
                # WARNING: Two reasons this is keyed on the selector rather than just
                # passed through:
                #   * body[52..55] is the GAME SERVER IP on selector 21 and the
                #     SPAWN INDEX on selector 13 -- the same collision sec 4dh
                #     already had to guard once;
                #   * --world-gs-ip has always defaulted to "", which made the
                #     answer an all-zero endpoint rather than no endpoint. A
                #     rung nobody had ever reached, so nobody noticed.
                # The default is the --gs-connect endpoint, so the two paths
                # that write the same sockaddr cannot disagree.
                gs_ip=(_gsip if _sel in worldchannel.GS_ENDPOINT_SELECTORS else None),
                gs_port=(a.world_gs_port or a.gs_connect_port),
                gs_id=a.gs_connect_id,
                spawn=_spawn, self_probe=a.self_costume_probe,
                self_costume=_self_cost,
                self_id=_world_self_id,
                self_hp=_hp_login,
                self_name=_self_name,
                self_gil=_shop_gil, self_bag=_shop_bag,
                self_unit=_unit_login,
                self_career=_career_login,
                self_gear=_gear_login,
                self_novice=_novice_login)
            if wr is not None:
                # 2026-09-23 (sec 4hc): the lobby spawn is the client entering
                # the lobby -- queue the intro push for a character that has
                # never confirmed it (command 27 id 1), once per session.
                if (_sel == arenamaps.WORLD_SPAWN_SELECTOR_ANS and a.intro == "on"
                        and _novice is not None and seen_charid[0]
                        and sess.key not in _intro_sent
                        and sess.key not in _intro_due):
                    _ik = _novice_key(sess)
                    if _ik is not None and not _novice.intro_seen(_ik):
                        _intro_due[sess.key] = time.time() + a.intro_delay
                        print("  [intro] [%s] has not seen the new-player intro "
                              "-- pushing it in %.1f s (selector 134 sub 10 event 1)"
                              % (_ik, a.intro_delay), flush=True)
                if _spawn is not None and _sel == arenamaps.WORLD_SPAWN_SELECTOR_ANS:
                    print("  [spawn] selector %d carrying (%.1f, %.1f, %.1f) index %d "
                          "at body[28..53]. The oracle is the emulog's own "
                          "copyMatrixFromActor() line, NOT this one -- it prints the "
                          "actor's matrix and its Y is ours minus 3.0."
                          % ((arenamaps.WORLD_SPAWN_SELECTOR_ANS, _spawn[0], _spawn[1],
                              _spawn[2], _spawn[6])), flush=True)
                if _cmd_arg is not None:
                    print("  [cmd] command %d is PLAY TIME -- serving %d s "
                          "at body[16]. The client caches it with a local tick and "
                          "extrapolates; it asks ONLY while [kelsvc+256] == 0, so "
                          "the proof is that command 20 STOPS."
                          % (lobbycmd.LOBBY_CMD_CLOCK, _cmd_arg), flush=True)
                if _cmd is not None:
                    print("  [cmd] selector %d -> %d carrying COMMAND %d "
                          "(was 0, which could never dispatch; sec 4cy). Watch "
                          "the emulog: an arm that RUNS is the proof."
                          % (lobbycmd.LOBBY_CMD_SELECTOR_REQ, lobbycmd.LOBBY_CMD_SELECTOR_ANS,
                             _cmd), flush=True)
                if _cmd == lobbycmd.LOBBY_CMD_RETURN and seen_charid[0]:
                    # a player who ARRIVED in a running room and returns to the
                    # lobby has left it; fire_battles ends an empty room and
                    # close_battle dissolves its table (live: the quit
                    # Wastelands table stayed listed, its room ran on).
                    _rr = battle_of(seen_charid[0])
                    if (_rr is not None and _rr.over and a.post_battle_briefing > 0
                            and seen_charid[0] in _rr.members
                            and seen_charid[0] not in _rr.left):
                        # the post-battle briefing room's TRANSPORTER: this
                        # player is back in the lobby (the client ran its own
                        # reset). No penalty: the battle was over. The last
                        # one out closes the table now.
                        _rr.left.add(seen_charid[0])
                        print("  [battle] 0x%08x took the transporter out of "
                              "table %d's briefing room (%d still in it)"
                              % (seen_charid[0], _rr.key,
                                 len([m for m in _rr.members if m not in _rr.left])),
                              flush=True)
                        if all(m in _rr.left for m in _rr.members):
                            _rr.reset_at = time.time()
                    elif (_rr is not None and not _rr.over
                            and seen_charid[0] in _rr.arrived
                            and _rr.mission is not None
                            and len(_rr.present()) <= 1):
                        # quitting a solo MISSION showed the
                        # client's own result screen with the WIN bits left by
                        # the previous battle ([chan+1388] is written only by
                        # kind 4). End it as a quit instead: kind 4 carries the
                        # mission verdict (a LOSS -- no objective), the tally
                        # records a failed mission, selector 39 resets as after
                        # any battle.
                        print("  [battle] 0x%08x QUIT solo mission table %d "
                              "(command 4) -- ending it with its verdict"
                              % (seen_charid[0], _rr.key), flush=True)
                        end_battle(_rr, time.time(), "player quit the mission")
                    elif (_rr is not None and not _rr.over
                            and seen_charid[0] in _rr.arrived):
                        _was_ldr = _rr.is_team_leader(seen_charid[0])
                        _nl = _rr.leave(seen_charid[0])
                        if _was_ldr:
                            tag_leaders(_rr, [seen_charid[0]], False,
                                        "returned to the lobby")
                        tag_leaders(_rr, list(_nl.values()), True,
                                    "took over as leader")
                        print("  [battle] 0x%08x RETURNED TO LOBBY (command 4) "
                              "-- LEFT table %d's room, %d still in it"
                              % (seen_charid[0], _rr.key, len(_rr.present())),
                              flush=True)
                        # the client's own warning (0x5c0d): leaving partway
                        # reduces rank points. Amount unknown -> flag, 0 = off.
                        if _stats is not None and a.leave_rp_penalty > 0:
                            _lk = _wallet_key(seen_uid[0], seen_charid[0], sess)
                            _ls = _stats.record_leave(
                                _lk, a.leave_rp_penalty, _rr.rules.mode,
                                time.time() - (_rr.started or time.time()),
                                rid=seen_charid[0])
                            print("  [stats] [%s] LEFT a running battle: %d rank "
                                  "points (--leave-rp-penalty %d)"
                                  % (_lk, _ls["rp"], a.leave_rp_penalty),
                                  flush=True)
                # 2026-09-13: the quest-detail answer names the quest's MAP --
                # the Solo screen label read "Jungle" (entry 0) for every quest.
                # Index = the arena zone's own roster index, from the same
                # --quest-zones.  WARNING: 2026-09-23: this used to be `zone - 201`,
                # "the list parallels zones 201..212 by index; inferred". Sec
                # 4hb MEASURED that parallel and it holds only for 201..208 --
                # z209 is 倉庫 (roster 14), not roster 8. _zone_map is the
                # measured inverse; the old arithmetic survives as the fallback
                # for a hand-set --quest-zones outside the decoded table, and is
                # now capped where it was actually right.
                if (_cmd == lobbycmd.LOBBY_CMD_QUEST and a.quest_mission
                        and len(wr) > framing.BODY_OFF + questlist.QUEST_DETAIL_MAP_OFF):
                    _qp41 = _quest_pick.get(sess.key)
                    if _qp41:
                        _qz = _quest_zone.get(_qp41[0], a.gs_battle_zone)
                        _qmap = _zone_map.get(
                            _qz, _qz - 201 if 201 <= _qz <= 208 else 0)
                        _wb = bytearray(wr)
                        _wb[framing.BODY_OFF + questlist.QUEST_DETAIL_MAP_OFF] = _qmap & 0xFF
                        _wb[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
                        _wb[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(_wb))
                        wr = bytes(_wb)
                        print("  [quest] command 41 answer: quest %d -> map "
                              "index %d (zone %d) at body[%d]"
                              % (_qp41[0], _qmap, _qz, questlist.QUEST_DETAIL_MAP_OFF),
                              flush=True)
                if (_cmd == lobbycmd.LOBBY_CMD_QUEST_INFO and a.quest_mission
                        and len(wr) > framing.BODY_OFF + 38):
                    _qb29 = worldchannel.request_body(data, inner)
                    _qp29 = _quest_pick.get(sess.key)
                    _q29 = (_qp29[0] if _qp29 else
                            (struct.unpack_from("<H", _qb29, 16)[0]
                             if _qb29 is not None and len(_qb29) >= 18 else 0))
                    if _q29:
                        _wb = bytearray(wr)
                        struct.pack_into("<H", _wb, framing.BODY_OFF + 16, _q29)
                        _wb[framing.BODY_OFF + 37] = doc_missions.players(_q29)
                        _wb[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = bytes(2)
                        _wb[framing.CKSUM_OFF:framing.CKSUM_OFF + 2] = struct.pack("<H", framing.cksum(_wb))
                        wr = bytes(_wb)
                    print("  [quest] command 29 (quest info) answered with quest "
                          "%d at body[16], limit %d at body[37] (doc_missions."
                          "players)" % (_q29, doc_missions.players(_q29)),
                          flush=True)
                for _i in range(max(1, a.world_burst)):
                    s.sendto(wr, src)
                    time.sleep(a.chara_burst_ms / 1000.0)
                # req body[1] is the client's own selector and body[4] its command;
                # both are CIPHERTEXT on the 132-byte phase-27 request (mode 1, sec
                # 4bj) but are worth printing for every round -- this log line is how
                # phases 29 and 31 get identified on the wire.
                # KEY: sec 4ca: some answer arms do their job WITHOUT clearing the
                # pending marker. Selector 13 is the one that bites: it releases
                # phase 30 (state 2 + [kelsvc+1064]) and the client reaches the
                # game, but bit 31 of [kelsvc+28] stays set, so 10 s later the
                # deadline in 0x00589af0 returns -2 -> CER-47117. Follow it with
                # the bare ack (selector 128, arm 0x00bcd4a4: clear bit 31, set
                # state 2, nothing else). Proven offline against a savestate
                # captured WITH the bit set: 13 alone leaves pending=1, 13 then
                # 128 leaves pending=0 with state and [+1064] unchanged.
                # KEY: sec 4dx: THE BATTLE-READY FLAG, ON A REAL TRIGGER.
                # Selector 38 was disarmed at world entry because it dragged the
                # player into the briefing room with no match behind it (sec
                # 4df/4di). It was never wrong -- it was early. Selector 21 is
                # the phase-44 answer, the last rung of a reservation that
                # actually completed (sec 4dw), which is the first moment in
                # this protocol where "your battle instance is ready" is a true
                # statement.
                # sec 4fm (live 2026-09-12): the trigger that is TRUE for a
                # solo leader. Start Immediately -> 0x00AA2218 -> zone flag 10
                # -> start_onlinebattle -> netclient bit 0x40 -> kelsvc vt+604
                # 0x00bd1db8 = lobby COMMAND 3 (seen on the wire at 21:48:10,
                # body[12]=03, 100 s after the CREATE). Its 241 arm is a no-op;
                # what the client waits for next is 38 -> [chan+2148] = 1 ->
                # its game-server hello (--gs-connect answers that ladder).
                _start_now = (_cmd == lobbycmd.LOBBY_CMD_START
                              and not a.bt_no_start_ready)
                if _start_now:
                    # sec 4he: command 3 is RETRANSMITTED like every reliable
                    # request; a second copy re-ran the whole Start (38 again,
                    # timers zeroed, the chosen teams wiped). One per 10 s.
                    _ls = _start_seen.get(sess.key, 0.0)
                    _start_seen[sess.key] = time.time()
                    if time.time() - _ls < 10.0:
                        _start_now = False
                        print("  [cmd] command 3 (START) again %.1f s after the "
                              "last -- a retransmit, 241 only (sec 4he)"
                              % (time.time() - _ls), flush=True)
                if _start_now:
                    # 2026-10-01: manual p.29 -- "Start Immediately" is the
                    # LEADER's command. The client only hides the row; a seated
                    # member's command 3 started the table for everyone.
                    _me3 = _ident or seen_charid[0] or 0
                    _tk3 = bt_store.table_of(_me3) if _me3 else None
                    if (_tk3 is not None
                            and not bt_store.is_leader(_tk3, _me3, seen_uid[0])):
                        _start_now = False
                        print("  [cmd] command 3 (START) from 0x%08x, who is not "
                              "table %d's leader -- refused, 241 only"
                              % (_me3, _tk3), flush=True)
                    elif _tk3 is not None and _briefing_running(_tk3):
                        # the table FILLED and went to the briefing room by
                        # itself (--bt-fill-start): a Start after that would
                        # start it a second time
                        _start_now = False
                        print("  [cmd] command 3 (START) at table %d, whose "
                              "briefing is already running -- 241 only"
                              % _tk3, flush=True)
                if _start_now:
                    print("  [cmd] command %d is START (start_onlinebattle) -- "
                          "pushing BATTLE READY (selector %d) behind the 241 "
                          "(sec 4fm)" % (lobbycmd.LOBBY_CMD_START, worldchannel.GS_READY_SELECTOR),
                          flush=True)
                if _sel in _gs_ready_after or _start_now:
                    # WARNING:KEY: sec 4gv (2026-09-23): RE-DECLARE THE ENDPOINT FIRST.
                    # Selector 38 rides the LOBBY channel and always lands; the
                    # message-27 re-arm four statements below rides the GAME
                    # SERVER channel, whose receive handler drops anything whose
                    # source != [chan+184..191]. That sockaddr was written once,
                    # at --gs-connect, and any channel reset since has wiped it.
                    # Live (table 2): the peer
                    # with a 2 m 10 s connect->Start gap sent 0 game-server
                    # hellos and its [chan+212] was still the uninitialised
                    # 65528 -- not one of our datagrams was ever accepted.
                    # ORDER: 104 FIRST (it is what makes the next two
                    # deliverable), then 38, then the arm LAST -- 38's
                    # 0x00bc0260 zeroes [chan+204] (sec 4eb). Re-running 104 on
                    # a healthy channel is measured harmless (sec 4cx).
                    if a.gs_connect and a.gs_start_endpoint:
                        send_gs_endpoint(src, seen_charid[0],
                                         why="Start, leader")
                    _rd = worlddoor.build_world_answer(
                        data, selector=worldchannel.GS_READY_SELECTOR, seq=a.lobby_seq,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7),
                        inner_ip=None, ptype=a.world_type, pad_to=a.world_pad,
                        ident=_ident)
                    if _rd is not None and a.gs_ready_roster:
                        # 2026-09-13: the leader's command 3 carries ident 0
                        # (26c502ee), so by ident the table was never found and
                        # the leader's own roster went out EMPTY (count 0 -- the
                        # all-zero [chan+2144] in its briefing savestate). Fall
                        # back to the session's charid, as start-all does.
                        _me38 = _ident or seen_charid[0] or 0
                        _tk = bt_store.table_of(_me38)
                        _rec38 = bt_store.record(_tk) if _tk is not None else None
                        # 2026-09-13: a Start right after a Solo quest pick is
                        # that quest -> cut 38's record as a MISSION (one use).
                        _qp = _quest_pick.pop(sess.key, None) if _start_now else None
                        if (_qp and a.quest_mission
                                and time.time() - _qp[1] <= a.quest_pick_window):
                            if _rec38 is None:
                                _rec38 = bytes(tablerecords.build_battletable_record(
                                    table_id=a.gs_connect_id & 0xFFFF,
                                    leader=seen_uid[0], cur=1, maximum=1))
                                if bt_store.situation:
                                    _rec38 = bytearray(_rec38)
                                    struct.pack_into("<H", _rec38,
                                                     tablerecords.BT_OFF_SITUATION,
                                                     bt_store.situation)
                            _rec38 = briefingroom.quest_mission_record(
                                _rec38, _qp[0], flags=tablerecords.BT_FLAG_MISSION,
                                situation=_quest_sit.get(_qp[0], 0))
                            # live 09-13: the quest RAN ("1-player MS", sentry
                            # robots) but our team scaffolding took the count
                            # 1 -> 5. A mission seats the player alone: drop
                            # the session's old team map (bots from an earlier
                            # battle linger there) and mark it for the 31 path.
                            _mission_battle[sess.key] = _qp[0]
                            sess.gs_teams.clear()
                            print("  [quest] START after Solo quest %d -> 38 as "
                                  "a MISSION (flags |0x%08x, mission %d, "
                                  "situation %d, table %s)"
                                  % (_qp[0], tablerecords.BT_FLAG_MISSION, _qp[0],
                                     struct.unpack_from("<H", _rec38,
                                                        tablerecords.BT_OFF_SITUATION)[0],
                                     _tk), flush=True)
                        else:
                            _mission_battle.pop(sess.key, None)
                        # RETAIL picks a mission with command
                        # 29 and CREATEs a mission table itself, so the quest-pick
                        # branch above never runs and the table's own situation
                        # (1100, the PvP set) went out -- no enemies. A mission's
                        # enemies load only from a 3000+ set (mdlResLoad), so any
                        # mission-flagged record gets its quest's --quest-situations.
                        if _rec38 is not None and len(_rec38) > tablerecords.BT_OFF_SITUATION + 1:
                            _mfl = struct.unpack_from("<I", _rec38, tablerecords.BT_OFF_FLAGS)[0]
                            _mq = struct.unpack_from("<H", _rec38, tablerecords.BT_OFF_MISSION)[0]
                            if (_mfl & tablerecords.BT_FLAG_MISSION) and _mq in _quest_sit:
                                _rec38 = bytearray(_rec38)
                                struct.pack_into("<H", _rec38, tablerecords.BT_OFF_SITUATION,
                                                 _quest_sit[_mq])
                                _rec38 = bytes(_rec38)
                                print("  [quest] mission table %s, quest %d -> 38 "
                                      "situation %d (--quest-situations)"
                                      % (_tk, _mq, _quest_sit[_mq]), flush=True)
                        _rd = briefingroom.gs_ready_roster(
                            _rd, _me38, a.gs_connect_id,
                            bt_store.members(_tk) if _tk else (),
                            rec=advertise.rec_for(_rec38, _gs_endpoint, src[0]),
                            addr=battle_addr(src[0]))
                    if _rd is not None:
                        _pm_me = _ident or seen_charid[0] or 0
                        _pm_tk = bt_store.table_of(_pm_me) if _pm_me else None
                        if _pm_tk is not None:
                            push_member_peers(_pm_me, src, bt_store.members(_pm_tk),
                                              why="leader")
                        s.sendto(_rd, src)
                        # sec 4fn: a fresh briefing room -> the once-per-38 state
                        # (bot push, join timer) starts over.
                        gs_join_deadline[0] = 0.0
                        gs_bots_sent[0] = False
                        sess.gs_battle_on[0] = 0.0     # sec 4fy: a new battle
                        sess.gs_battle_end[0] = 0.0
                        sess.gs_battle_reset[0] = 0.0
                        sess.gs_battle_go[0] = 0.0
                        print("  SENT type-%d BATTLE READY (selector %d) after "
                              "answer selector %d -- the sole writer of "
                              "[chan+2148] = 1. Watch for the client's first "
                              "type-0x82 (its game-server hello) and for "
                              "br_main / the team prompt (sec 4dx); record flags "
                              "0x%08x (0x200 = individual)"
                              % (a.world_type, worldchannel.GS_READY_SELECTOR, _sel,
                                 _rec_flags(_rec38) if a.gs_ready_roster else 0),
                              flush=True)
                        # sec 4eb (live 09-11): 38's routine 0x00bc0260 does
                        # `[chan+204] = 0`, which DROPS the armed bit message 27
                        # set at world entry. Unarmed, the receive preamble never
                        # refreshes [chan+224], and 40 s after 38 the client
                        # printed `timeout gameserver 40007` -> CER-48101. Send
                        # the arm again right behind 38.
                        _st2 = []
                        for _pair in (a.gs_stats or "").replace(" ", "").split(","):
                            if not _pair:
                                continue
                            _k2, _, _v2 = _pair.partition(":")
                            _st2.append((int(_k2, 0), int(_v2, 0)))
                        s.sendto(gamemsg.build_gs_stats(_st2, state=a.gs_arm_state,
                                                seq=next_gs_seq(sess),
                                                ident=_ident or 0), src)
                        gs_ka_src[0] = src
                        gs_ka_next[0] = time.time() + a.gs_keepalive_ms / 1000.0
                        sess.gs_rearm_pending[0] = a.gs_rearm_until_team
                        print("  SENT GAME-SERVER RE-ARM (message %d) behind selector "
                              "38 -- 0x00bc0260 zeroed [chan+204], so the arm bit "
                              "was gone and no packet refreshed the 40 s stamp "
                              "(CER-48101 live 09-11, sec 4eb)" % gamemsg.GS_ARM_MSG,
                              flush=True)
                        sess.gs_src[0] = None    # sec 4ft: a new briefing room
                        # sec 4ft: only the LEADER sends command 3, so fan the
                        # same 38 + re-arm out to every other seated member --
                        # otherwise a joiner never leaves the lobby.
                        if _start_now and a.bt_start_all:
                            _sk, _lead, _others = teamdist.bt_start_targets(
                                bt_store, _ident, seen_charid[0])
                            if _sk is None:
                                print("  [start-all] leader 0x%08x is not seated "
                                      "at any table -- nobody to fan 38 out to"
                                      % (_lead or 0), flush=True)
                            else:
                                begin_briefing(_sk, _lead, _others,
                                               skip_sess=sess)
                if _sel in _pending_ack_after:
                    pa = worlddoor.build_world_answer(
                        data, selector=a.pending_ack_selector, seq=a.lobby_seq,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7),
                        inner_ip=_lip, ptype=a.world_type,
                        pad_to=a.world_pad, ident=_ident)
                    if pa is not None:
                        s.sendto(pa, src)
                        print("  SENT type-%d bare ACK (selector %d) after answer "
                              "selector %d -- clears the pending marker, sec 4ca"
                              % (a.world_type, a.pending_ack_selector, _sel),
                              flush=True)
                print("  SENT type-%d WORLD answer x%d (req selector %s -> answer "
                      "selector %d, body[0]=%d, ident=%s) <- req len=%d mode=%d "
                      "reqbody[0..7]=%s%s"
                      % (a.world_type, max(1, a.world_burst),
                         _req_sel, _sel,
                         wr[framing.BODY_OFF] if len(wr) > framing.BODY_OFF else -1,
                         "0x%08x" % _ident if _ident is not None else "lobby-ip",
                         len(data), data[1],
                         (_plain if _plain is not None else data)
                         [framing.BODY_OFF:framing.BODY_OFF + 8].hex(" "),
                         "  [decrypted]" if _plain is not None else ""), flush=True)
                # 2026-09-28 (Dirge report): the JOIN's 21 goes out HERE, and
                # `reply` stays None, so the echo in the `reply` block below
                # never ran for a JOIN: the joiner held no reservation and
                # its Reserve option stayed open. Echo after the 21, as there.
                if _bt_echo_key is not None and not a.bt_no_reserve_echo:
                    s.sendto(tableverbs.build_reserve_echo(
                        data, _bt_echo_key, seq=a.lobby_seq,
                        subchannel=(a.world_subchannel
                                    if a.world_subchannel >= 0 else 7),
                        ptype=a.world_type, pad_to=a.world_pad, ident=_ident), src)
                    print("  SENT RESERVATION ECHO (selector 152, unsolicited) for "
                          "table %d after the JOIN-ok (sec 4fl)" % _bt_echo_key,
                          flush=True)
                    _bt_echo_key = None

        # THE DELETE ANSWER.  Pressing DELETE on a slot sends a 40-byte mode-2
        # message whose body is `05 11 00 00 <slot> ...` -- selector 17, an odd
        # (request) selector, with the slot index at body[4].  Same shape as the
        # charamake: the request parks the nest at a state and the server owes the
        # paired even code.  Per the sec 4ao ladder the code gated on state 11 is
        # 18 (handler 0x00587f00).
        # 2026-10-06 (live): ANY datagram with body[1] == 17 matched -- in a
        # battle the enciphered game-server traffic does, 1 in 256 -- and
        # deleted slot body[4] (member 30's only character went mid-battle,
        # one row written, no menu open). Only the real message: 40 bytes
        # (cli --delete-answer, sec 4ao), body 05 11, from a player who is not
        # in a battle.
        if (a.delete_answer and sess.ka_template is not None
                and len(data) == 40
                and data[framing.BODY_OFF] == 0x05 and data[framing.BODY_OFF + 1] == 17
                and battle_of(seen_charid[0]) is None):
            dl = handshake.build_lobby_advance(sess.ka_template, selector=18, seq=a.lobby_seq,
                                     inner_ip=_lip, empty_records=True)
            if dl is not None:
                for _i in range(max(1, a.charamake_burst)):
                    s.sendto(dl, src)
                    time.sleep(a.chara_burst_ms / 1000.0)
                print("  SENT selector-18 DELETE ACK x%d (slot %d, state 11 -> ..)"
                      % (max(1, a.charamake_burst), data[framing.BODY_OFF + 4]
                         if len(data) > framing.BODY_OFF + 4 else -1), flush=True)
            if _store is not None and seen_uid[0] and len(data) > framing.BODY_OFF + 4:
                _slot = data[framing.BODY_OFF + 4]
                if _store.delete(_skey(seen_uid[0]), _slot):
                    refresh_roster(seen_uid[0])
                    print("  [chara] DELETED slot %d for 0x%08x, PERSISTED"
                          % (_slot, seen_uid[0]), flush=True)

        # THE CHARAMAKE ANSWER.  REGISTER sends a 232-byte mode-2 message (sec 4bc:
        # name at wire+104, appearance nibbles at wire+92/93/127) and parks the nest
        # at STATE 10.  Phase 10's poll 0x00588cf8 spins while [nest+8] == 10, so the
        # client sits there until we move it -- that is the -47111(phase = 10) death.
        # The response code gated on state 10 is 16, whose handler 0x00587e98 is
        # blunt: optionally copy a record via [nest+0xE8], then [nest+8] = 2. Once it
        # is 2 the poll returns [nest+20] or 1 -- positive -- and phase 10 advances.
        #
        # Built from the 96-byte TEMPLATE, never from the request: the 232-byte body
        # starts 0xb9, and the classifier 0x005895b0 rejects anything whose body[0]
        # exceeds [nest+12] == 5, so a reply echoing that body would never be read.
        if (a.charamake_answer and sess.ka_template is not None
                and len(data) == a.charamake_len):
            # 2026-09-13: store FIRST, so the answer can carry the new
            # character's record and the select list updates in place
            # (build_charamake_answer). Without a store: the old empty ACK.
            _new_rec = None
            _refused = None
            if _store is not None and seen_uid[0]:
                _c = doc_charastore.parse_register(data)
                if _c is not None and _c.get("name"):
                    # 2026-10-01: SE's name rules (doc_charastore.register):
                    # a bad or taken name is never stored, and a second
                    # character with an existing name no longer overwrites it.
                    _slot, _refused = _store.register(_skey(seen_uid[0]), _c)
                    if _refused:
                        print("  [chara] REGISTER '%s' REFUSED: CER-%d (%s)"
                              % (_c["name"], _refused,
                                 {doc_charastore.CER_NAME_LENGTH: "3 to 15 characters",
                                  doc_charastore.CER_NAME_CHARS: "letters, digits, - and _",
                                  doc_charastore.CER_NAME_TAKEN: "name already in use"}
                                 .get(_refused, "?")), flush=True)
                        _c = None
                if (_c is not None and _c.get("name") and isinstance(_slot, int)
                        and a.chara_id_source == "content"):
                    # 2026-10-05: the new character takes one of its member's
                    # DoC Content IDs (the client keeps a loadout only for one)
                    _ck = _skey(seen_uid[0])
                    try:
                        _ids = []
                        if isinstance(_ck, str) and _ck.startswith("member:"):
                            _conn = docdb.accounts().connect()
                            try:
                                _ids = docdb.accounts().member_content_id_list(
                                    _conn, int(_ck[7:]), doc_charastore.DOC_CONTENT_CODE,
                                    active_only=True)
                            finally:
                                _conn.close()
                        _cid = _store.assign_content_id(_ck, _slot, _ids)
                        print("  [chara] '%s' (%s slot %d): Content ID %s"
                              % (_c["name"], _ck, _slot,
                                 ("%d (0x%08x)" % (_cid, _cid)) if _cid
                                 else "none free of %r -- the derived id" % (_ids,)),
                              flush=True)
                    except Exception as _ex:   # never fail a REGISTER on this
                        print("  [chara] Content ID lookup for '%s' FAILED (%s) -- "
                              "the derived id" % (_c["name"], _ex), flush=True)
                if _c is not None and _c.get("name"):
                    refresh_roster(seen_uid[0])
                    print("  [chara] REGISTERED '%s' (voice %d, gender %d) -> "
                          "slot %s for 0x%08x, PERSISTED" %
                          (_c["name"], _c["voice"], _c["gender"], _slot,
                           seen_uid[0]), flush=True)
                    if isinstance(_slot, int) and 0 <= _slot < doc_charastore.MAX_SLOTS:
                        _new_rec = charrecords.build_used_record(
                            _slot, _c["name"], _c,
                            char_id=charrecords.chara_id_of(
                                a.chara_id_base, seen_uid[0], _skey(seen_uid[0]), _slot,
                                _store.roster(_skey(seen_uid[0]))[_slot]),
                            chr_code=a.chara_chrcode)
            if _refused:
                # 2026-10-01: SE's own refusal (charrecords.build_charamake_refusal):
                # the client shows CER-<code> and stays on the creation screen.
                # The burst below is identical copies with nothing between --
                # any other mode-2 reply would rewrite [nest+20].
                cm = charrecords.build_charamake_refusal(sess.ka_template, data,
                                                         _refused, seq=a.lobby_seq,
                                                         inner_ip=_lip)
            elif _new_rec is not None:
                cm = charrecords.build_charamake_answer(sess.ka_template, data, _new_rec,
                                            seq=a.lobby_seq, inner_ip=_lip)
            else:
                cm = handshake.build_lobby_advance(sess.ka_template, selector=16,
                                         seq=a.lobby_seq, inner_ip=_lip,
                                         empty_records=True)
            if cm is not None:
                for _i in range(max(1, a.charamake_burst)):
                    s.sendto(cm, src)
                    time.sleep(a.chara_burst_ms / 1000.0)
                print("  SENT selector-16 CHARAMAKE ACK x%d (state 10 -> 2, releases "
                      "phase 10)%s" % (max(1, a.charamake_burst),
                                       " CARRYING the new record (slot %d)" % _new_rec[84]
                                       if _new_rec is not None else ""), flush=True)
        if (a.nest_quiet_after_frag3 > 0 and sess.frag3_sent >= a.nest_quiet_after_frag3
                and is_lobby(data) and not _is_close_request(data)):
            # Phase 110 waits for [nest+8] == 0.  Going quiet was the WRONG read of
            # that (the nest does not close on its own -- it closes on an inbound
            # selector 4, see _is_close_request), so the close request is answered
            # even here.  See --nest-quiet-after-frag3.
            reply = None
            print("  (nest QUIET after %d frag3 -- not answering, so [nest+8] can "
                  "reach 0 for phase 110)" % sess.frag3_sent, flush=True)
        elif a.lobby_probe != "off" and is_lobby(data):
            # The lobby (type-129) sub-connection ignores the type-128 redirect;
            # answer it on its own terms.
            if a.lobby_probe == "advance" and _is_close_request(data):
                # THE NEST CLOSE.  Phase 109 calls the nest's vtable+220
                # (0x00587a98), which builds a message with selector 3 and hands it
                # to 0x005899d0 -> [nest+8] = 4.  Phase 110 then polls 0x00587b40,
                # which returns 1 only when [nest+8] == 0.  The ONLY thing that
                # clears state 4 is an inbound SELECTOR 4 (classifier 0x005895b0 arm
                # 0x00589690), after which the router's code-4 arm 0x005880f8 runs
                # the reset 0x005894a8.  PROVEN offline end to end, on kel's own code
                # against a live nest: an offline run of the client's own code (doc_close_proof).
                #
                # Answering the selector-3 request with anything else (our code-8,
                # or silence) leaves the nest at 4 forever and phase 110 never
                # advances -- that is CER-48103, sec 4ay.
                reply = handshake.build_lobby_advance(
                    data, selector=4, seq=a.lobby_seq, inner_ip=_lip,
                    empty_records=True)
                note = "CLOSE ack sel=4 (answers the client selector-3 close request)"
            elif a.lobby_probe == "advance":
                # Only the 96-byte type-129 packets carry the body the nest driver
                # dispatches on.  Two selectors drive the connection forward:
                #   selector 2  -> m5 advances the nest 1->2  (first handshake step)
                #   selector 8  -> state-6 handler 0x00587c10 advances 6->2, which
                #                  self-advances 2->6 and RE-STAMPS the liveness the
                #                  10s watchdog watches -> defeats CER-48103 AND pulls
                #                  the next user-data chunk.  (PROVEN offline against a
                #                  live state-6 savestate: doc_state6_router.py.)
                # State-1 and state-6 requests are byte-identical on the wire, so we
                # can't read the state.  Send BOTH replies to EVERY 96-B packet:
                #   selector 2 advances 1->2 and is a no-op at every other state (the
                #     driver gates m5 on nest[8]==1), and selector 8 advances 6->2 and
                #     is a no-op before state 6.  Neither interferes with the other.
                # NB: do NOT gate selector-2 on a per-run counter -- the responder is a
                # long-lived process, so a lifetime counter skips selector-2 on the 2nd
                # boot and the nest never leaves state 1 (MEASURED: state-1 savestates,
                # 14 s disconnect).  --lobby-sel2-count 0 disables selector-2 entirely.
                if len(data) == 96:
                    if a.lobby_sustain_selector:
                        reply = handshake.build_lobby_advance(
                            data, selector=a.lobby_sustain_selector,
                            seq=a.lobby_seq, inner_ip=_lip, empty_records=True,
                            **sess.chara_kw)
                        if a.lobby_sel2_count != 0:
                            extra_reply = handshake.build_lobby_advance(
                                data, selector=a.lobby_selector,
                                seq=a.lobby_seq, inner_ip=_lip)
                    else:
                        reply = handshake.build_lobby_advance(data, selector=a.lobby_selector,
                                                    seq=a.lobby_seq, inner_ip=_lip)
                    note = ("advance sel=%d" % (a.lobby_sustain_selector or a.lobby_selector)
                            + (" +sel2" if extra_reply else ""))
                elif sess.chara_kw and len(data) == 36 and data[framing.BODY_OFF + 1] == 7:
                    # THE ONE STATE-6 WINDOW.  0x005884d0 (the 2->6 arm) is the only
                    # thing that puts the nest in state 6, and it does so at the moment
                    # it TRANSMITS selector 7 -- this packet.  The code-8 handler
                    # 0x00587c10 is gated on [nest+8]==6 and drops the nest to 2 on the
                    # first acceptance, so there is exactly one chance per window, and
                    # the client may never open another: boot 13:22 saw ONE selector-7
                    # in the whole session, and char stayed 0 even though all 17 of our
                    # code-8s carried body[16..17] = 10 01.
                    # A code-8 at any other state is a PROVEN no-op (the state sweep in
                    # an offline run of the client's own code (doc_code8_wire_proof)), so repeating it costs nothing.
                    reply = handshake.build_lobby_advance(
                        data, selector=(a.lobby_sustain_selector or 8),
                        seq=a.lobby_seq, inner_ip=_lip, **sess.chara_kw)
                    if a.chara_on_request:
                        # MEASURED (savestate 15:41:32, inside the held window):
                        # [nest+8]=2 with the armed HIGH bit CLEAR is the code-8
                        # arm's own signature -- it clears that bit only after its
                        # state==6 check and then the handler sets 2. So the code-8
                        # WAS accepted. But [nest+0xF4] was untouched, and holds
                        # byte-identical garbage across three boots: the client had
                        # not yet pointed that field at the real buffer, so our count
                        # landed somewhere else and the one window was spent.
                        # Leaving selector-7 UNANSWERED parks the nest at 6 (armed),
                        # and the watchdog budget is [nest+4]=40000 ~ 20 s while the
                        # 00 01 request lands ~4 s later.  Answer then instead.
                        sess.chara_pending = reply
                        reply = None
                        note = ('CHARA code-8 HELD for the 00 01 request '
                                '(nest parked at 6)')
                    else:
                        note = ('CHARA code-8 to the SELECTOR-7 window (count=%d, '
                                'burst=%d)'
                                % (sess.chara_kw.get('chara_count', 0), a.chara_burst))
                        chara_burst_now = True
                elif data[1] == 4:
                    # sec 4eb: a MODE-4 datagram is the game-server channel (the
                    # client's 36-byte keepalive `01 00 ..` every 7 s). It was
                    # answered above by name; the 424-byte nest roster this arm
                    # used to send it is what the emulog logged as bad packets.
                    reply = None
                    note = "mode-4 game-server datagram, answered by the GS ladder"
                elif len(data) == 36 and data[framing.BODY_OFF] == 7:
                    # the 2026-09-05 audit (D): body[0] == 7 is the KELSVC
                    # subchannel, not the nest (5).  In world the client sends a
                    # 36-byte unreliable `07 05 ...` every ~4 s (624 in two
                    # sessions) and the arm below answered every one with a
                    # 424-byte type-129 roster the closed nest ignores.  Selector 5
                    # is a DRIVER arm (0x005895b0 handles 2/4/5/6 itself) that has
                    # never been read; log it and leave it alone.
                    reply = None
                    note = ("log-only (KELSVC subchannel 7, selector %d, 36-byte "
                            "poll -- no nest roster here; the arm is unread)"
                            % data[framing.BODY_OFF + 1])
                elif sess.chara_kw and len(data) == 36:
                    # THE CHARACTER-SELECT EXPERIMENT (an earlier run).  In the
                    # mode-2 phase the client stops sending 96-byte packets, so the
                    # selector-8 reply above never fires and the code-8 handler never
                    # runs -- which is exactly the phase the character-select screen
                    # sits in.  Answer the 36-byte mode-2 packet on its own terms: a
                    # MODE-0 code-8 whose body we build from the client own (its body
                    # is plaintext: 05 07 00 00 01 ... = subchannel 5, selector 7),
                    # padded out to the 20-byte chara header.  Mode 0 is a verified
                    # no-op on the client decrypt path, so no cipher is needed here.
                    reply = handshake.build_lobby_advance(
                        data, selector=(a.lobby_sustain_selector or 8),
                        seq=a.lobby_seq, inner_ip=_lip, **sess.chara_kw)
                    note = ("CHARA code-8 to 36-B mode-2 (count=%d)"
                            % sess.chara_kw.get("chara_count", 0))
                else:
                    reply = None
                    note = "log-only (not a 96-byte type-129)"
            else:  # echo
                reply = bytearray(data)
                note = "echo"
                if len(data) == 96:
                    for off, val in lobby_edits:
                        if off < len(reply):
                            reply[off] = val
                            note = "edit [%d]=%02x" % (off, val)
                reply = bytes(reply)
            print("  (lobby packet -> probe=%s %s)" % (a.lobby_probe, note), flush=True)
        else:
            reply = framing.build_reply(data, a.mode, a.subtype, a.crypto, a.body_len,
                                a.mode_byte, not a.no_cksum, a.ptype, a.flags,
                                _lip, a.lobby_port)
        # Reliable-ACK sweep: cancel the framework's retransmit of its pending
        # message (sec 4ae).  The client's seq is encrypted, so sweep [lo,hi].
        if a.reliable_ack_lo >= 0 and a.lobby_probe != "off" and is_lobby(data):
            nack = 0
            for seq in range(a.reliable_ack_lo, a.reliable_ack_hi + 1):
                s.sendto(framing.build_reliable_ack(seq), src)
                nack += 1
            print("  SENT %d reliable ACKs (seq %d..%d) to %s:%d"
                  % (nack, a.reliable_ack_lo, a.reliable_ack_hi, src[0], src[1]), flush=True)

        if extra_reply is not None:
            s.sendto(extra_reply, src)
            print("  SENT %d bytes (selector-2 pre-advance) to %s:%d"
                  % (len(extra_reply), src[0], src[1]), flush=True)
            print(framing.hexdump(extra_reply, indent="    2 "), flush=True)
        if reply is not None and chara_burst_now and a.chara_burst > 1:
            # Fire the extra copies first, so the whole burst sits as close to the
            # client own transmit as possible.
            for _i in range(a.chara_burst - 1):
                s.sendto(reply, src)
                time.sleep(a.chara_burst_ms / 1000.0)
            print('  SENT %d extra CHARA code-8 copies (%d ms apart) to cover the '
                  'state-6 window' % (a.chara_burst - 1, a.chara_burst_ms), flush=True)
            sess.chara_burst_at = datetime.datetime.now().timestamp()
            if a.frag3_hold_s > 0:
                print('  >>> SAVESTATE WINDOW OPEN for %.0f s -- the frag3 answer is '
                      'held, the client is parked in phase 3' % a.frag3_hold_s,
                      flush=True)
        if reply is not None:
            s.sendto(reply, src)
            answered += 1
            print("  SENT %d bytes back to %s:%d" % (len(reply), src[0], src[1]), flush=True)
            print(framing.describe(reply), flush=True)
            # sec 4fl: a successful JOIN was answered with the selector-21
            # endpoint above; 0x00bca9cc clears the reservation on the way in,
            # so the 152 echo must FOLLOW it.
            if _bt_echo_key is not None and not a.bt_no_reserve_echo:
                s.sendto(tableverbs.build_reserve_echo(
                    data, _bt_echo_key, seq=a.lobby_seq,
                    subchannel=(a.world_subchannel
                                if a.world_subchannel >= 0 else 7),
                    ptype=a.world_type, pad_to=a.world_pad, ident=_ident), src)
                print("  SENT RESERVATION ECHO (selector 152, unsolicited) for "
                      "table %d after the JOIN-ok (sec 4fl)" % _bt_echo_key,
                      flush=True)
            print(framing.hexdump(reply, indent="    > "), flush=True)

        # THE LOBBY REQUEST ANSWER.  Only for 80-byte type-128 packets whose body
        # tail is `00 01` -- the two requests (33 c1 / b3 44) that go unanswered
        # today.  The entrance (tail `00 02`) is deliberately excluded: sending
        # subtype 3 to it broke the handshake live (sec 4aw).
        if (sess.chara_pending is not None and len(data) == 80
                and data[76:78] == b"\x00\x01"):
            # Phase 2 has now issued the request, so [nest+0xF4] points where the
            # list is actually read from.  Send the held code-8 BEFORE the frag3
            # answer, because the frag3 answer is what releases phase 3 -> phase 4.
            for _i in range(max(1, a.chara_burst)):
                s.sendto(sess.chara_pending, src)
                time.sleep(a.chara_burst_ms / 1000.0)
            print("  SENT the HELD CHARA code-8 x%d on the 00 01 request -- "
                  "AFTER phase 2 set the buffer" % max(1, a.chara_burst), flush=True)
            sess.chara_pending = None
            sess.chara_burst_at = datetime.datetime.now().timestamp()
            if a.frag3_hold_s > 0:
                print("  >>> SAVESTATE WINDOW OPEN for %.0f s -- the frag3 answer is "
                      "held, the client is parked in phase 3" % a.frag3_hold_s,
                      flush=True)

        if a.frag3 and len(data) == 80 and data[76:78] == b"\x00\x01":
            # the 2026-09-05 audit (J): the Select Server screen has a NAME column
            # and a `Players Connected` column (KelStr group 29) and we have
            # always written id 0 / tail 0 into both. --frag3-servers now takes
            # an optional `:id:tail` so one boot can name which field is which
            # without a code change.  ip:port[:id[:tail]]
            entries = b""
            # KEY: sec 4fz (2026-09-13): PLAYERS CONNECTED is entry+10. Render loop 0x00aaed9c prints row+0xF0 with %d (entry+10 via copy 0x005862d0 -> list builder 0x00aae890); >= 1000 = 'server is full'. entry+0 = server id (the name), entry+8 = the tab.
            # We served 0 forever. An explicit :id:tail in --frag3-servers
            # still wins.
            _online = players_connected(exclude=sess)
            print("  [server list] %d other player(s) connected -> entry+10"
                  % _online, flush=True)
            if a.lobby_capacity > 0 and _online >= a.lobby_capacity:
                # 2026-10-01, manual p.25: a lobby whose player count is over
                # its limit cannot be joined. The client draws a row of 1000+
                # as "server is full" and does not enter it.
                print("  [server list] FULL (%d of --lobby-capacity %d) -> "
                      "entry+10 = 1000" % (_online, a.lobby_capacity), flush=True)
                _online = 1000
            for x in a.frag3_servers.split(","):
                x = x.strip()
                if not x:
                    continue
                f = x.split(":")
                entries += handshake.build_srv_entry(
                    advertise.host_for(f[0], src[0]), int(f[1]),
                    id0=int(f[2], 0) if len(f) > 2 and f[2] else a.frag3_server_id,
                    tail=(int(f[3], 0) if len(f) > 3 and f[3]
                          else _online),                      # sec 4fz
                    area=(int(f[4], 0) if len(f) > 4 and f[4]
                          else a.frag3_area))
            fr = handshake.build_frag3(data, parts=a.frag3_parts, index=0, payload=entries,
                             crypto=a.crypto, body_len=a.body_len,
                             mode_byte=a.mode_byte, do_cksum=not a.no_cksum)
            held_now = (a.frag3_hold_s > 0 and sess.chara_burst_at is not None
                        and (datetime.datetime.now().timestamp() - sess.chara_burst_at)
                        < a.frag3_hold_s)
            if fr is not None and held_now:
                sess.frag3_pending = (fr, src)
                print('  (frag3 HELD -- savestate window, %.1f s left)'
                      % (a.frag3_hold_s - (datetime.datetime.now().timestamp()
                                           - sess.chara_burst_at)), flush=True)
            elif fr is not None:
                s.sendto(fr, src)
                sess.frag3_sent += 1
                print("  SENT %d bytes (SUBTYPE-3 frag reply #%d, parts=%d idx=0) to %s:%d"
                      % (len(fr), sess.frag3_sent, a.frag3_parts, src[0], src[1]), flush=True)
                print(framing.hexdump(fr, indent="    3 "), flush=True)

        # Extra SUBTYPES for the non-lobby (80-byte, type-128) packets.  The client
        # gates each subtype on the connection state (0x00585fc4), so the wrong one
        # is discarded for free and we do not have to observe the state to pick.
        if extra_subtypes and not is_lobby(data):
            for st in extra_subtypes:
                ex = framing.build_reply(data, a.mode, st, a.crypto, a.body_len,
                                 a.mode_byte, not a.no_cksum, a.ptype, a.flags,
                                 _lip, a.lobby_port)
                if ex is not None:
                    s.sendto(ex, src)
                    print("  SENT %d bytes (extra subtype %d) to %s:%d"
                          % (len(ex), st, src[0], src[1]), flush=True)

        # The ladder extras, after the advance replies and before the ACK.  Each is
        # state-gated inside the client (sec 4ao), so a code for a state the nest is
        # not in costs a datagram and does nothing -- which is why this is a LIST the
        # user keeps short, not a sweep.
        if extra_selectors and a.lobby_probe == "advance" and is_lobby(data):
            for sel in extra_selectors:
                ex = handshake.build_lobby_advance(
                    data, selector=sel, seq=a.lobby_seq, inner_ip=_lip,
                    empty_records=True)
                if ex is not None:
                    s.sendto(ex, src)
                    print("  SENT %d bytes (ladder response code %d) to %s:%d"
                          % (len(ex), sel, src[0], src[1]), flush=True)

        # ONE exact ACK, last -- so it never competes with the advance replies for
        # a slot in the client's small receive ring (that is what killed the sweep).
        # NB this must sit OUTSIDE the `reply is not None` arm: the 36-byte mode-2
        # packets are exactly the channel we have no advance reply for (sec 4af),
        # and they are the ones whose retransmit we are trying to cancel.
        # WARNING: THE ACK IS A TRADE, NOT A SETTING (sec 4bx). ACK always and the
        # client goes quiet in the lobby -> PCSX2 unbinds its UDP port after ~48 s
        # of GUEST-transmit idle -> our packets vanish -> CER-48104. ACK never and
        # the client resends forever, its reliable queue never drains, and it can
        # end up hearing nothing from us for 40 s -> CER-48102. Both were measured
        # live on 08-27, in that order. The rule that resolves it is the
        # own wording: never ACK unless SOMETHING ELSE keeps the guest
        # transmitting -- and in game its 2 Hz position stream is exactly that.
        _streaming = (a.reliable_ack_ingame and last_stream[0]
                      and (datetime.datetime.now().timestamp() - last_stream[0])
                      <= a.reliable_ack_idle)
        # KEY: sec 4dd: THE GATE ABOVE IS PURELY TEMPORAL -- it has no idea WHAT it is
        # refusing to ACK, and that is what boomerangs the account holder out of the
        # lobby.  Measured live 2026-08-27 03:25:48Z:
        #
        #   03:25:48.934  SEQ=2922 flags=0x01 DATA   <- the lobby-entry command
        #   03:25:49.455  SEQ=2922  retransmit
        #   03:25:50.485  SEQ=2922  retransmit
        #   03:25:52.505  SEQ=2922  retransmit
        #   03:25:56.509  SEQ=2922  retransmit -> the client gives up
        #   03:25:56.610  SENT 1 reliable ACK for seq 2922    <- 7.68 s LATE
        #
        # The 2 Hz position stream is quiet during exactly the transition the
        # client is trying to make, so `--reliable-ack-ingame` holds the ACK until
        # after the transition has already failed, and then sends it.
        #
        # WARNING: THIS DOES NOT REOPEN THE sec 4by TRADE. That trade is about ACKing
        # while the client is IDLE: the ACK silences it, PCSX2 unbinds the guest
        # UDP port after ~48 s of GUEST-transmit idle, and everything we send
        # vanishes (CER-48104). A selector-240 request is the opposite situation --
        # the client is mid-transaction and will keep transmitting whatever we do.
        # So this is an exception for MESSAGES WE ARE ALREADY ANSWERING, not a
        # return to `--reliable-ack-exact`.
        _urgent = False
        if _ack_selectors and inner is not None and inner["is_data"] \
                and inner["type"] == a.world_type:
            _s, _ = worldchannel.world_reply_fields(data, inner)
            _urgent = _s in _ack_selectors
        if _gs_answered:
            _urgent = True
        if (a.reliable_ack_exact or _streaming or _urgent) \
                and inner is not None and inner["is_data"]:
            s.sendto(framing.build_reliable_ack(inner["seq"]), src)
            print("  SENT 1 reliable ACK for seq %d to %s:%d%s"
                  % (inner["seq"], src[0], src[1],
                     "  [urgent: a selector we answer -- not gated on the 2 Hz "
                     "stream, sec 4dd]" if _urgent and not _streaming else ""),
                  flush=True)
