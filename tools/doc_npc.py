#!/usr/bin/env python3
"""Dirge of Cerberus lobby NPCs: the QUEST-EVENT channel (2026-09-13, static).

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
     trigger is body[22..23] and b (always 0 from Java) body[20..21].
  3. Our 241 answer, sub 26 (0x00bc95e4): header body[4] bit 0 = refusal -> the
     client queues event 0xffff; else 0x00bc8f38 queues event = header u16
     body[6] ([kelsvc+24]): facade setQuestEventId 0x0058e8a8 + flag 0x40000.
     If the inner header's u16 at packet+22 is >= 84 it ALSO copies body[16..83]
     into the 68-byte quest data at [kelsvc+1240] (0x00bc8f80) -- undecoded, and
     docudp's seal_world_body writes 0 there, so that never runs.
  4. Java quest.handle_event (only while getflag() & 0x40000) -> getQuestEventId
     -> quest_scr003.ev(id): the id is looked up in one table per NPC (below);
     the matching NPC number drives a switch 7..43 to the scene ev_nNN.
  5. The scene ends with reportQuestEventDone(id) = LOBBY COMMAND 27 (vt+1128,
     u32 id at body[16]); 241 sub 27 (0x00bc9630) can chain the same way.
     clearQuestData() = LOBBY COMMAND 39 (vt+1360); its 241 sub is a no-op.

NPC_EVENTS is the client's own table (quest_scr003.ev, int arrays at locals
25..57). GREETING is the single-id side table beside some NPCs (NPC 8's 1031 is
the one id that plays ev_n08 itself; the rest of 8's ids replay NPC 7's scene
shifted by 30), used as the default answer. WARNING: That the trigger IS the NPC number
(7..43) is an INFERENCE from the switch range; the first live command 26 settles
it -- every request is logged raw.
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
NPC_EVENTS = {
    7: list(range(1000, 1030)) + list(range(1180, 1187)) + [1208, 1212, 1120],
    8: list(range(1030, 1060)) + list(range(1187, 1194)) + [1209, 1213, 1121],
    9: list(range(1060, 1090)) + list(range(1194, 1201)) + [1210, 1214, 1122],
    10: list(range(1090, 1120)) + list(range(1201, 1208)) + [1211, 1215, 1123],
    11: [1130, 1131] + list(range(1220, 1231)),
    12: [1132, 1133] + list(range(1240, 1251)),
    13: [1134, 1135] + list(range(1260, 1271)),
    14: [1136, 1137] + list(range(1280, 1291)),
    15: [2000, 2004], 16: [2001, 2005], 17: [2002, 2006], 18: [2003, 2007],
    19: [1500, 1501], 20: [1502, 1503], 21: [1504, 1505], 22: [1506, 1507],
    26: list(range(1528, 1535)) + [1570],
    29: list(range(1169, 1178)),
    30: [2010] + list(range(2014, 2020)),
    36: list(range(1535, 1543)) + list(range(1550, 1561)),
    40: list(range(1508, 1513)) + list(range(1580, 1585)),
    41: list(range(1513, 1518)) + list(range(1590, 1595)),
    42: list(range(1518, 1523)) + list(range(1600, 1605)),
    43: list(range(1523, 1528)) + list(range(1610, 1615)),
}
#: the single-id side tables beside NPCs 7-10, 15-18 and 30
GREETING = {7: 1001, 8: 1031, 9: 1061, 10: 1091,
            15: 2000, 16: 2001, 17: 2002, 18: 2003, 30: 2010}
ROLE = {}
for _n, _r in (((7, 8, 9, 10), "instructor"), ((11, 12, 13, 14), "exam briefer"),
               ((15, 16, 17, 18), "shop clerk"), ((19, 20, 21, 22), "unit registrar"),
               ((26, 29, 36), "reservation desk"), ((30,), "'WIZZ'"),
               ((40, 41, 42, 43), "area officer")):
    for _k in _n:
        ROLE[_k] = _r


def npc_of_event(event):
    for npc, ids in NPC_EVENTS.items():
        if event in ids:
            return npc
    return None


def parse_overrides(spec):
    """'7:1001,15:2000' -> {7: 1001, 15: 2000}."""
    out = {}
    for part in (spec or "").replace(" ", "").split(","):
        if part:
            k, _, v = part.partition(":")
            out[int(k, 0)] = int(v, 0)
    return out


def event_for(trigger, overrides=None):
    """The event a command 26 for `trigger` answers with, or None to refuse."""
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
                    # and sub 26 tests `bltz` -- a 0 code is "success, event 0",
                    # which is the lobby INTRO cutscene (quest.handle_event key 0)


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
        ev = event_for(q["trigger"], overrides)
        if ev is None:
            return answer_body(cmd, value=NO_EVENT, subchannel=subchannel), \
                "CHECK trigger %d (b %d, raw %s): no NPC table -> event 0xffff (nothing plays)" \
                % (q["trigger"], q["b"], raw)
        npc = npc_of_event(ev)
        return answer_body(cmd, value=ev, subchannel=subchannel), \
            "CHECK trigger %d (b %d, raw %s) -> event %d = NPC %s (%s)" \
            % (q["trigger"], q["b"], raw, ev, npc, ROLE.get(npc, "?"))
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

    check("24 NPCs, 7..43", len(NPC_EVENTS) == 24 and min(NPC_EVENTS) == 7 and max(NPC_EVENTS) == 43)
    check("instructors hold 40 ids each", all(len(NPC_EVENTS[n]) == 40 for n in (7, 8, 9, 10)))
    allids = [i for v in NPC_EVENTS.values() for i in v]
    check("no event id belongs to two NPCs", len(allids) == len(set(allids)))
    check("every greeting is in its own NPC's table",
          all(GREETING[n] in NPC_EVENTS[n] for n in GREETING))
    check("event_for: greeting first, then the table's first id, then None",
          event_for(8) == 1031 and event_for(26) == 1528 and event_for(99) is None)
    check("overrides win", event_for(7, {7: 1180}) == 1180)
    check("parse_overrides", parse_overrides("7:1001, 0x0f:2004") == {7: 1001, 15: 2004})
    req = bytearray(28)
    struct.pack_into("<IHH", req, 16, 0, 0, 15)
    q = parse_request(bytes(req))
    check("request: trigger at body[22], b at body[20]", q["trigger"] == 15 and q["b"] == 0)
    b, note = body_for(CMD_CHECK, bytes(req))
    check("26 -> event 2000 at body[6], cmd 26 at body[12], no fail bit",
          struct.unpack_from("<H", b, 6)[0] == 2000 and struct.unpack_from("<H", b, 12)[0] == 26
          and not b[4] & 1 and b[1] == 241 and len(b) == ANS_LEN)
    struct.pack_into("<H", req, 22, 99)
    b, _ = body_for(CMD_CHECK, bytes(req))
    check("unknown trigger -> success with event 0xffff, NOT a refusal",
          b[4] & 1 == 0 and struct.unpack_from("<H", b, 6)[0] == NO_EVENT)
    rb = answer_body(CMD_CHECK, fail=True)
    check("a refusal always carries a non-zero code (0 would read as event 0)",
          rb[4] & 1 == 1 and struct.unpack_from("<H", rb, 6)[0] == REFUSE_CODE)
    struct.pack_into("<I", req, 16, 2000)
    b, note = body_for(CMD_DONE, bytes(req))
    check("27 -> ack, value 0", struct.unpack_from("<H", b, 6)[0] == 0 and "2000" in note)
    b, _ = body_for(CMD_CLEAR, bytes(req))
    check("39 -> ack", struct.unpack_from("<H", b, 12)[0] == 39)
    ub = body_for(CMD_CHECK, b"\0" * 8)[0]
    check("unreadable request -> short success, event 0xffff",
          len(ub) == ANS_LEN and ub[4] & 1 == 0 and struct.unpack_from("<H", ub, 6)[0] == NO_EVENT)
    print("%d check(s) failed" % len(fails) if fails else "ALL PASS")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
