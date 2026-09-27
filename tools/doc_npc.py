#!/usr/bin/env python3
"""Dirge of Cerberus lobby NPCs: the QUEST-EVENT channel (2026-09-13; tables
re-derived from the RETAIL build 2026-09-22).

Every NPC conversation in the Visual Lobby (instructors, exam briefers, shop
clerks, unit registrars, reservation desks, the four area officers) is a
server-driven "quest event", read out of a savestate of the lobby with
doc_jclass / doc_dis:

  1. The engine raises ZONE flag 45 and puts a trigger in ZONE flag 40 (a byte;
     what raises them is NOT yet found -- not mm_z217, not the lobby's own flag
     helper 0x00ad6970, which only ever sets flags 10 and 1).
  2. Java quest.handle_packet -> KerberosNetLobby.checkQuestEvent(trigger, 0)
     -> kelsvc vt+1112 0x00bd6c58 = LOBBY COMMAND 26 (selector 240). Its 12-byte
     argument (request body[16..27]) = {u32 0, u16 b, u16 trigger}, so the
     trigger is body[22..23] and b body[20..21].
     WARNING: RETRACTED 2026-09-22, live: b is NOT "always 0 from Java". Only the
     WALK-UP caller, quest.handle_packet, passes 0; a SCENE re-asks with its own
     sub-code once the player has answered. A live log showed trigger 4 with b 0 and
     then twice with b 2 after the player accepted Argento's offer. FOLLOWUP
     (below) is the (trigger, b) table; the old parenthesis was simply wrong.
  3. Our 241 answer, sub 26 (0x00bc95e4): header body[4] bit 0 = refusal -> the
     client queues event 0xffff; else 0x00bc8f38 queues event = header u16
     body[6] ([kelsvc+24]): facade setQuestEventId 0x0058e8a8 + flag 0x40000.
     If the inner header's u16 at packet+22 is >= 84 it ALSO copies body[16..83]
     into the 68-byte quest data at [kelsvc+1240] (0x00bc8f80) -- undecoded, and
     docudp's seal_world_body writes 0 there, so that never runs.
  4. Java quest.handle_event (only while getflag() & 0x40000) -> getQuestEventId
     -> quest_scr003.ev(id): the id is looked up in one table per NPC (below);
     the matching NPC number drives a switch 4..43 to the scene ev_nNN
     (RETAIL; the prototype class this file used to carry switched 7..43).
  5. The scene ends with reportQuestEventDone(id) = LOBBY COMMAND 27 (vt+1128,
     u32 id at body[16]); 241 sub 27 (0x00bc9630) can chain the same way.
     clearQuestData() = LOBBY COMMAND 39 (vt+1360); its 241 sub is a no-op.

NPC_EVENTS is the client's own table (quest_scr003.ev, int arrays at locals
25..54 in the retail class); SIDE is the single-id side table beside some of
them; GREETING is the id we answer a bare "I talked to NPC n" with.

VERIFIED: The trigger IS the lnpc number -- PROVEN LIVE 2026-09-22: the
client sent command 26 with trigger 40, 31 and 4, which are exactly the lnpc
numbers of the NPCs a player walked up to (an area officer, Restrictor-East
and Argento). It is no longer an inference from the switch range.
"""
import struct

CMD_CHECK, CMD_DONE, CMD_CLEAR = 26, 27, 39
NPC_CMDS = (CMD_CHECK, CMD_DONE, CMD_CLEAR)
CMD_NAMES = {CMD_CHECK: "CHECK QUEST EVENT", CMD_DONE: "QUEST EVENT DONE",
             CMD_CLEAR: "CLEAR QUEST DATA"}
CMD_ANS = 241
HDR_FLAGS, HDR_VALUE, ANS_CMD = 4, 6, 12
FLAG_FAIL = 0x0001
ANS_LEN = 20                     # short: see step 3 (quest data stays untouched)
REQ_ARG, REQ_B, REQ_TRIGGER = 16, 20, 22

#: quest_scr003.ev's per-NPC event tables (NPC number -> event ids)
#:
#: WARNING:KEY: RE-DERIVED 2026-09-22 from the RETAIL build
#: (SLPM-66271 CRC 139D8DF9, savestate slot 08, quest_scr003 class header
#: 0x009C9400 -- an address from THAT dump, nothing else). The table this file
#: shipped until now came from the PROTOTYPE tree and is a DIFFERENT class:
#: retail's `ev()` dispatches `tableswitch 4..43` over 24 NPCs (the same 24
#: lnpc numbers doc_npc_spawn places), the prototype's was 7..43 over a
#: different set. Retail has scenes for 4 / 31 / 32 / 33 / 34 / 39, which the
#: old table had no entry for at all, and it gives 26 / 29 / 30 / 40 / 41 /
#: 42 / 43 completely different event ids. Live on 2026-09-22 the client
#: asked for triggers 40, 31 and 4; 31 and 4 got 0xffff ("no NPC table") and
#: 40 got 1508, which is in NO retail table -- all three played nothing.
#:
#: How it was read: `ev()` builds one int[] per NPC (locals 25..54), then one
#: scan loop per NPC -- `for i in tbl: if i == id { npcnum = N; name =
#: "lnpc_NN" }` -- and finally `tableswitch 4..43 -> ev_nNN(zone, pc, npc,
#: win, id)`. Each scene method's own switch was cross-checked against the
#: table: every id in a table has a case, and no case is missing.
NPC_EVENTS = {
    4: [300, 301, 302, 303, 304, 305],
    7: list(range(1000, 1030)) + list(range(1180, 1187)) + [1208, 1212],
    8: list(range(1030, 1060)) + list(range(1187, 1194)) + [1209, 1213],
    9: list(range(1060, 1090)) + list(range(1194, 1201)) + [1210, 1214],
    10: list(range(1090, 1120)) + list(range(1201, 1208)) + [1211, 1215],
    11: [1130, 1131] + list(range(1220, 1231)),
    12: [1132, 1133],
    13: [1134, 1135],
    14: [1136, 1137],
    18: [2003, 2007],
    20: [1502, 1503],
    26: [1530, 1531, 1532, 1533, 1534, 1570],
    29: [200, 201, 202, 203, 204, 205, 206],
    30: [2014, 2019],
    31: [400, 401], 32: [500, 501], 33: [600, 601], 34: [700, 701],
    36: list(range(1535, 1543)) + list(range(1550, 1562)),
    39: [100, 101, 9998, 9999],
    40: [1580, 1581], 41: [1590, 1591], 42: [1600, 1601], 43: [1610, 1611],
}
#: the single-id side tables beside NPCs 4, 7-10 and 18 (retail). An id that is
#: in one makes `ev()` set its local 23, which changes how the scene walks the
#: PC in -- it is also, in every case, the NPC's ordinary opening line.
SIDE = {4: 302, 7: 1001, 8: 1031, 9: 1061, 10: 1091, 18: 2003}

#: KEY: The id we answer a bare "I talked to NPC n" with.
#:
#: SE's ids come in pairs/sets and one of them is the STANDBY line, played when
#: the player is sitting on a battle reservation: its ev2046 key carries the
#: `_Y_` / `_YOK_` / `_YOYAKU_` / `_YA_.._YD_` marker ("sakusen taiki-chuu da
#: na?" = "you are on standby, aren't you?"). Serving that one reads as the NPC
#: brushing you off. So the default is the NON-standby id -- the tutorial /
#: explanation / first-meeting line -- taken from the side table where there is
#: one. Checked key by key against SE's own text (the patch
#: 20060124_3 NPC dialogue table).
GREETING = {
    4: 302,     # ID_AR_FIRST_01   (300 = AR_LOCK, 301 = AR_YOYAKU standby)
    7: 1001,    # ID_KY_DR_03_A_01 (1000 = KY_YOYAKU_H standby)
    8: 1031,    # ID_KY_DR_03_B_01
    9: 1061,    # ID_KY_DR_03_C_01
    10: 1091,   # ID_KY_DR_03_D_01
    11: 1131,   # ID_BT_TU_A_01    (1130 = BT_Y standby)
    12: 1133,   # ID_BT_TU_B_01
    13: 1135,   # ID_BT_TU_C_01
    14: 1137,   # ID_BT_TU_D_01
    18: 2003,   # ID_SHOP_T_01     (2007 = SHOP_Y standby)
    20: 1502,   # ID_BUTAI_TU_01   (1503 = BUTAI_Y standby)
    26: 1530,   # ID_VICT_BALERU_GET_01 (1570 = VICT_Y standby)
    29: 201,    # ID_ED_FST_01     (200 = ED_Y standby)
    30: 2019,   # ID_MAHOU_R1_01   (2014 = MAHOU_Y standby)
    31: 401,    # ID_RR_DEF_31_03  (400 = RR_YOK standby)
    32: 501,    # ID_RR_DEF_32_01
    33: 601,    # ID_RR_DEF_33_01
    34: 701,    # ID_RR_DEF_34_01
    36: 1535,   # ID_HR_HANA_KARE_01
    39: 101,    # the Cactuar "Beginner's Machine" MENU (2026-09-23, sec 4hc,
                # retail ev_n39): a novice gets Graduate / DG advice / Cancel,
                # and Graduate sends lobby command 33 (doc_novice); anyone else
                # gets advice / Cancel. 100 = ID_CACUTO_Y_01 "no reaction at
                # all" (what this used to serve). 9998 = the graduation scene
                # and 9999 = the Novice-room briefing tip; the CLIENT plays both
                # itself (vl_main / br_main), so neither is served here.
    40: 1581,   # ID_AREA_A_01     (1580 = AREA_YA standby)
    41: 1591,   # ID_AREA_B_01
    42: 1601,   # ID_AREA_C_01
    43: 1611,   # ID_AREA_D_01
}
ROLE = {}
for _n, _r in (((4,), "Argento"), ((7, 8, 9, 10), "instructor"),
               ((11, 12, 13, 14), "battle-system briefer"),
               ((18,), "shop clerk"), ((20,), "unit registrar"),
               ((26,), "DGD Soar (broken-item gifts)"),
               ((29,), "Este-D (Dandelion -> Gasmask)"),
               ((36,), "DGSC Hiren (grows seeds)"),
               ((30,), "DGD Peliry (magic tutor)"),
               ((31, 32, 33, 34), "Restrictor"), ((39,), "Cactuar jukebox"),
               ((40, 41, 42, 43), "area officer")):
    for _k in _n:
        ROLE[_k] = _r


def npc_of_event(event):
    for npc, ids in NPC_EVENTS.items():
        if event in ids:
            return npc
    return None


#: KEY: (trigger, b) -> the event the SCENE is asking for next.
#:
#: `b` is the second argument of `KerberosNetLobby.checkQuestEvent(trigger, b)`.
#: `quest.handle_packet` -- the walk-up path -- always passes 0 (`iconst_0;
#: istore_2`), which is why b was believed to be constant. It is not: a SCENE
#: can re-ask with its own sub-code once the player has answered something.
#:
#: MEASURED, not guessed: every `checkQuestEvent` call site in the 23 classes
#: loaded in the retail savestate was decoded (an offline run of the client's own code (doc_npc_followup_proof)).
#: There are exactly three, and only one scene passes a non-zero b:
#:     quest.handle_packet   @46    checkQuestEvent(flag40, 0)   <- the walk-up
#:     quest_scr003.ev_n04   @1333  checkQuestEvent(4, 2)        <- literal consts
#:     quest_scr003.ev_n04   @1574  checkQuestEvent(4, 2)        <- literal consts
#: Both ev_n04 sites sit on the ACCEPT arm of Argento's question: the window
#: opens on ID_AR_FIRST_05 ("do you seek to be the strongest?"), `getstate() == 2`
#: branches to ID_AR_FIRST_07 + _08 and then sends (4, 2); anything else branches
#: to ID_AR_FIRST_06 ("there is nothing to say -- go") and sends NOTHING.
#: So b is a SCENE-ISSUED SUB-REQUEST CODE baked into the bytecode. It is not a
#: menu index (the choice is read separately, as `getstate()`), and it is not a
#: counter the server keeps.
#:
#: WARNING: The VALUE below is the one inference here. 305 is the only forward branch
#: ev_n04 has left (300 = ID_AR_LOCK "the time has not come", 301 = the standby
#: brush-off, 302 = the intro that ends in the question, 303/304 = the question
#: on its own, 305 = ID_AR_MIS01_01..07, Argento's mission list). Nothing in the
#: class names 305 at the call site, so this is read off the dialogue, not off a
#: constant. If it is wrong a server admin can retune it with
#: `--npc-events 4:2:<id>` without a code change.
FOLLOWUP = {
    (4, 2): 305,        # accepted "do you seek to be the strongest?" -> the missions
}


def parse_overrides(spec):
    """'7:1001,15:2000' -> {7: 1001, 15: 2000}; '4:2:305' -> {(4, 2): 305}.

    Two fields are trigger:event (the walk-up answer, b-blind, as before);
    three are trigger:b:event, which pins one follow-up only."""
    out = {}
    for part in (spec or "").replace(" ", "").split(","):
        if not part:
            continue
        f = part.split(":")
        if len(f) >= 3:
            out[(int(f[0], 0), int(f[1], 0))] = int(f[2], 0)
        else:
            out[int(f[0], 0)] = int(f[1], 0)
    return out


def event_for(trigger, overrides=None, b=0):
    """The event a command 26 for `trigger` (sub-code `b`) answers with.

    Order: an exact (trigger, b) override, then the class's own FOLLOWUP for a
    non-zero b, then the b-blind path exactly as it was -- a plain trigger
    override, the greeting, the table's first id, None. WARNING: An unknown non-zero b
    therefore falls back to the walk-up answer rather than refusing: that keeps
    every NPC that talks today talking, and the log says when it happened."""
    if overrides and (trigger, b) in overrides:
        return overrides[(trigger, b)]
    if b and (trigger, b) in FOLLOWUP:
        return FOLLOWUP[(trigger, b)]
    if overrides and trigger in overrides:
        return overrides[trigger]
    if trigger in GREETING:
        return GREETING[trigger]
    ids = NPC_EVENTS.get(trigger)
    return ids[0] if ids else None


def parse_request(req_body):
    """The 240's argument: {'trigger', 'b', 'id', 'raw'} or None."""
    if req_body is None or len(req_body) < REQ_TRIGGER + 2:
        return None
    return {"trigger": struct.unpack_from("<H", req_body, REQ_TRIGGER)[0],
            "b": struct.unpack_from("<H", req_body, REQ_B)[0],
            "id": struct.unpack_from("<I", req_body, REQ_ARG)[0],
            "raw": bytes(req_body[REQ_ARG:REQ_ARG + 12]).hex(" ")}


NO_EVENT = 0xFFFF   # the client's own "nothing" (what it queues on a failure)
REFUSE_CODE = 1     # WARNING: must be NON-zero: the demux stores -body[6] on a refusal
                    # and sub 26 tests `bltz` -- a 0 code is "success, event 0".
                    # WARNING: 2026-09-23 (sec 4hc): event 0 does NOTHING in retail; the
                    # "0/1 = lobby intro" reading was the PROTOTYPE class. Retail
                    # event 1 exits to zone 240, the new-player intro chain, so an
                    # answer of 1 starts the intro (doc_novice pushes it).


def answer_body(cmd, value=0, fail=False, subchannel=7):
    """A short 241: command at body[12], the header u16 at body[6] (the event
    id for sub 26), body[4] bit 0 = refusal (with a non-zero code at body[6])."""
    b = bytearray(ANS_LEN)
    b[0] = subchannel & 0xFF
    b[1] = CMD_ANS
    if fail:
        struct.pack_into("<H", b, HDR_FLAGS, FLAG_FAIL)
        value = value or REFUSE_CODE
    struct.pack_into("<H", b, HDR_VALUE, value & 0xFFFF)
    struct.pack_into("<H", b, ANS_CMD, cmd & 0xFFFF)
    return bytes(b)


def body_for(cmd, req_body, overrides=None, subchannel=7):
    """(241 body, log note) for commands 26/27/39, or (None, why)."""
    if cmd not in NPC_CMDS:
        return None, "not an NPC command"
    q = parse_request(req_body)
    raw = q["raw"] if q else "(unreadable)"
    if cmd == CMD_CHECK:
        # WARNING: NOT a refusal: body[4] bit 0 makes the demux store -code as a lobby
        # ERROR ([kelsvc+1064]) and skip the sub table (measured in
        # doc_npc_proof). NO_EVENT is what the client itself queues on failure:
        # quest_scr003 finds no NPC for it and quest.handle_event no case.
        if q is None:
            return answer_body(cmd, value=NO_EVENT, subchannel=subchannel), \
                "CHECK with an unreadable body -> event 0xffff (nothing plays)"
        ev = event_for(q["trigger"], overrides, q["b"])
        if ev is None:
            return answer_body(cmd, value=NO_EVENT, subchannel=subchannel), \
                "CHECK trigger %d (b %d, raw %s): no NPC table -> event 0xffff (nothing plays)" \
                % (q["trigger"], q["b"], raw)
        npc = npc_of_event(ev)
        # KEY: name the arm that answered, so an unread (trigger, b) shows up in the
        # log instead of looking like an ordinary walk-up.
        if q["b"] == 0:
            why = "walk-up"
        elif (overrides and (q["trigger"], q["b"]) in overrides) \
                or (q["trigger"], q["b"]) in FOLLOWUP:
            why = "FOLLOW-UP b %d" % q["b"]
        else:
            why = "b %d UNREAD -> walk-up answer (see FOLLOWUP)" % q["b"]
        return answer_body(cmd, value=ev, subchannel=subchannel), \
            "CHECK trigger %d (b %d, raw %s) [%s] -> event %d = NPC %s (%s)" \
            % (q["trigger"], q["b"], raw, why, ev, npc, ROLE.get(npc, "?"))
    if cmd == CMD_DONE:
        ev = q["id"] if q else None
        npc = npc_of_event(ev) if ev is not None else None
        return answer_body(cmd, subchannel=subchannel), \
            "DONE event %s (NPC %s, %s), raw %s -> ack, no chain" \
            % (ev, npc, ROLE.get(npc, "?"), raw)
    return answer_body(cmd, subchannel=subchannel), "CLEAR quest data, raw %s -> ack" % raw


def _selftest():
    fails = []

    def check(name, cond):
        print("  %s %s" % ("ok  " if cond else "FAIL", name))
        if not cond:
            fails.append(name)

    check("24 NPCs, 4..43 (retail ev() tableswitch)",
          len(NPC_EVENTS) == 24 and min(NPC_EVENTS) == 4 and max(NPC_EVENTS) == 43)
    check("instructors hold 39 ids each", all(len(NPC_EVENTS[n]) == 39 for n in (7, 8, 9, 10)))
    # the whole point of the 09-22 re-derivation: the NPCs the client asked
    # about live, and the ones whose ids the prototype table got wrong.
    check("the six NPCs the prototype table had no entry for are present",
          all(n in NPC_EVENTS for n in (4, 31, 32, 33, 34, 39)))
    check("no NPC the lobby does not place, and none it does is missing",
          set(NPC_EVENTS) == {4, 7, 8, 9, 10, 11, 12, 13, 14, 18, 20, 26, 29, 30,
                              31, 32, 33, 34, 36, 39, 40, 41, 42, 43})
    check("the area officers carry retail's ids, not the prototype's 1508/1513/1518/1523",
          NPC_EVENTS[40] == [1580, 1581] and NPC_EVENTS[43] == [1610, 1611]
          and all(1508 not in v for v in NPC_EVENTS.values()))
    check("every greeting and every side id is in its own NPC's table",
          all(GREETING[n] in NPC_EVENTS[n] for n in GREETING)
          and all(SIDE[n] in NPC_EVENTS[n] for n in SIDE))
    check("every NPC has a greeting", set(GREETING) == set(NPC_EVENTS))
    allids = [i for v in NPC_EVENTS.values() for i in v]
    check("no event id belongs to two NPCs", len(allids) == len(set(allids)))
    check("event_for: greeting first, then the table's first id, then None",
          event_for(8) == 1031 and event_for(26) == 1530 and event_for(99) is None)
    check("the default is never the STANDBY line (what the old table served)",
          event_for(40) == 1581 and event_for(31) == 401 and event_for(11) == 1131)
    check("overrides win", event_for(7, {7: 1180}) == 1180)
    check("parse_overrides", parse_overrides("7:1001, 0x27:9999") == {7: 1001, 39: 9999})

    # --- the follow-up sub-code b (2026-09-22) --------------------------------
    # WARNING: THE FALSIFYING TWIN. This is what event_for DID until today: one answer
    # per trigger, b thrown away. Every b check below is written so that this
    # reference implementation FAILS it -- a check the old behaviour also passes
    # would prove nothing about the change.
    def _b_blind(trigger, overrides=None, b=0):
        if overrides and trigger in overrides:
            return overrides[trigger]
        if trigger in GREETING:
            return GREETING[trigger]
        ids = NPC_EVENTS.get(trigger)
        return ids[0] if ids else None

    check("every FOLLOWUP id is in its own NPC's table",
          all(v in NPC_EVENTS.get(k[0], []) for k, v in FOLLOWUP.items()))
    check("b 0 is unchanged for every NPC -- nothing that talks today regresses",
          all(event_for(n) == _b_blind(n) for n in NPC_EVENTS))
    check("(4, 2) -- Argento accepted -> 305, the mission list",
          event_for(4, b=2) == 305)
    check("...and the OLD b-blind lookup gets that wrong (it answers 302 again)",
          _b_blind(4, b=2) == 302 and _b_blind(4, b=2) != event_for(4, b=2))
    check("an UNREAD (trigger, b) falls back to the walk-up answer, not a refusal",
          event_for(4, b=7) == _b_blind(4) == 302 and event_for(40, b=3) == 1581)
    check("parse_overrides takes trigger:b:event too",
          parse_overrides("4:2:300, 7:1001") == {(4, 2): 300, 7: 1001})
    check("an exact (trigger, b) override beats FOLLOWUP, and only for that b",
          event_for(4, {(4, 2): 300}, 2) == 300 and event_for(4, {(4, 2): 300}) == 302)

    req = bytearray(28)
    struct.pack_into("<IHH", req, 16, 0, 0, 18)
    q = parse_request(bytes(req))
    check("request: trigger at body[22], b at body[20]", q["trigger"] == 18 and q["b"] == 0)
    b, note = body_for(CMD_CHECK, bytes(req))
    check("26 -> event 2003 at body[6], cmd 26 at body[12], no fail bit",
          struct.unpack_from("<H", b, 6)[0] == 2003 and struct.unpack_from("<H", b, 12)[0] == 26
          and not b[4] & 1 and b[1] == 241 and len(b) == ANS_LEN)
    # the three triggers a live server saw on 2026-09-22
    for _t, _e in ((40, 1581), (31, 401), (4, 302)):
        struct.pack_into("<H", req, 22, _t)
        _b, _n = body_for(CMD_CHECK, bytes(req))
        check("live trigger %d -> event %d (was %s before the retail re-derivation)"
              % (_t, _e, "1508" if _t == 40 else "0xffff"),
              struct.unpack_from("<H", _b, 6)[0] == _e and not _b[4] & 1)
    # the follow-up a live server saw: trigger 4, b 2, twice
    struct.pack_into("<IHH", req, 16, 0, 2, 4)
    _q = parse_request(bytes(req))
    check("request: b 2 reads back at body[20]", _q["b"] == 2 and _q["trigger"] == 4)
    _b, _n = body_for(CMD_CHECK, bytes(req))
    check("live (trigger 4, b 2) -> event 305 and the note says FOLLOW-UP",
          struct.unpack_from("<H", _b, 6)[0] == 305 and "FOLLOW-UP b 2" in _n
          and not _b[4] & 1)
    struct.pack_into("<H", req, 20, 9)
    _b, _n = body_for(CMD_CHECK, bytes(req))
    check("an unread b is answered AND flagged UNREAD in the log",
          struct.unpack_from("<H", _b, 6)[0] == 302 and "UNREAD" in _n)
    struct.pack_into("<IHH", req, 16, 0, 0, 99)
    b, _ = body_for(CMD_CHECK, bytes(req))
    check("unknown trigger -> success with event 0xffff, NOT a refusal",
          b[4] & 1 == 0 and struct.unpack_from("<H", b, 6)[0] == NO_EVENT)
    rb = answer_body(CMD_CHECK, fail=True)
    check("a refusal always carries a non-zero code (0 would read as event 0)",
          rb[4] & 1 == 1 and struct.unpack_from("<H", rb, 6)[0] == REFUSE_CODE)
    struct.pack_into("<I", req, 16, 2003)
    b, note = body_for(CMD_DONE, bytes(req))
    check("27 -> ack, value 0", struct.unpack_from("<H", b, 6)[0] == 0 and "2003" in note)
    b, _ = body_for(CMD_CLEAR, bytes(req))
    check("39 -> ack", struct.unpack_from("<H", b, 12)[0] == 39)
    ub = body_for(CMD_CHECK, b"\0" * 8)[0]
    check("unreadable request -> short success, event 0xffff",
          len(ub) == ANS_LEN and ub[4] & 1 == 0 and struct.unpack_from("<H", ub, 6)[0] == NO_EVENT)
    print("%d check(s) failed" % len(fails) if fails else "ALL PASS")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
