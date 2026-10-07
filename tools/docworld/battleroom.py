"""One battle: the rules its table record asks for (BattleRules), the running room (BattleRoom), rank point and unit gates."""
import struct
import doc_missions
from . import fielditems, gamemsg, tablerecords



class BattleRules(object):
    """What the battletable RECORD says the battle is (sec 4he). Every field
    here used to be a flat command-line knob; the record the LEADER wrote on
    the config screen is the source now, with the knob as the fallback only
    where the record carries nothing."""
    __slots__ = ("mode", "kind", "time_limit", "kill_target", "respawn",
                 "maximum", "situation", "map_idx", "mission", "flags",
                 "random_teams", "briefing", "npc", "ko_limit", "friendly_fire",
                 "restrictions", "base_hp", "capsules")

    def __init__(self, mode="TBT", time_limit=180.0, kill_target=0,
                 respawn=4.0, maximum=0, situation=0, map_idx=0, mission=0,
                 flags=0, kind=0, random_teams=False, briefing=0.0, npc=False,
                 ko_limit=0, friendly_fire=False, restrictions=0, base_hp=0,
                 capsules=0):
        self.mode, self.kind, self.flags = mode, kind, flags
        self.time_limit = float(time_limit)      # seconds; 0 = no clock
        self.kill_target = int(kill_target)
        self.respawn = float(respawn)            # seconds; < 0 = never
        self.maximum, self.situation = int(maximum), int(situation)
        self.map_idx, self.mission = int(map_idx), int(mission)
        self.random_teams, self.briefing, self.npc = bool(random_teams), float(briefing), bool(npc)
        self.ko_limit = int(ko_limit)            # deaths that put a player out
        self.friendly_fire = bool(friendly_fire)
        self.restrictions, self.base_hp, self.capsules = int(restrictions), int(base_hp), int(capsules)

    def __repr__(self):
        return ("BattleRules(%s kind %d, %s, kill target %d, respawn %.0f s, "
                "KO limit %d, max %d, situation %d, map %d, mission %d%s%s%s)"
                % (self.mode, self.kind,
                   ("%.0f s" % self.time_limit) if self.time_limit else "no clock",
                   self.kill_target, self.respawn, self.ko_limit, self.maximum,
                   self.situation, self.map_idx, self.mission,
                   ", random teams" if self.random_teams else "",
                   ", NPCs" if self.npc else "",
                   ", restrictions 0x%02x" % self.restrictions
                   if self.restrictions else ""))


#: OURS (2026-10-01): a kill counts toward "Kill Streak Bonus" from the
#: third one in a single life (the client only receives the count)
STREAK_FROM = 3

LEADER_TAG = "[L]"              # 2026-09-24: the Team Leader name tag (--leader-tag)


class BattleRoom(object):
    """ONE battle, keyed by its battletable (sec 4he, 2026-09-23).

    Before this every battle timer lived on the SESSION: two players who
    pressed OK seconds apart got two battle ends, the first player's reset
    dissolved the shared table under the second, and the result read the
    bot team map instead of the table's. The room owns the clock, the
    roster, the teams, the tally and the verdict; sessions only deliver.

    Score keeping follows the client (sec 4he): the VICTIM's client reports
    its own death as request 30 {killer, victim}; the server tallies and
    pushes notify kind 9 (four team point slots + killer + victim) to every
    member, which is the only thing that moves the HUD counters. Win / lose
    / draw is the server's verdict in the kind-4 record, never a client
    comparison."""
    __slots__ = ("key", "members", "teams", "rules", "kills", "deaths",
                 "points", "seq9", "arrived", "started", "end_at", "reset_at",
                 "result_sent", "dead_until", "last_death", "over", "why",
                 "mission", "leader", "opened", "left", "damage_seen", "tally",
                 "npc_kills", "npc_hp", "npc_counted", "team_leaders", "leader_kills",
                 "first_killer", "finisher",
                 "tally_keys", "field", "holders", "cap_hold", "capsule_winner",
                 "base_hp", "go_at", "go_fired", "go_cap", "gens",
                 "quest_items", "coins", "base_down", "occupy", "occupier",
                 "base_spots", "base_teams", "carrier_kos", "last_ko", "carrier_drop", "last_pick",
                 "cap_last", "last_capsule", "field_picks",
                 "team_kos", "life_kills", "streaks")

    def __init__(self, key, members, teams, rules, leader=0, mission=None,
                 now=None):
        self.key = key
        self.members = [m for m in members if m]
        self.teams = dict(teams)
        self.rules = rules
        self.leader = leader
        self.mission = mission
        self.kills = {m: 0 for m in self.members}
        self.deaths = {m: 0 for m in self.members}
        self.points = [0] * gamemsg.GS_TEAM_SLOTS
        self.seq9 = 0
        self.arrived = set()        # members whose request 47 has landed
        self.left = set()           # members gone before the end
        self.started = None         # the FIRST 47
        self.end_at = None
        # 2026-09-26: ONE GO for the room. Each client starts its HUD clock
        # at its own kind 5, and every GO went out --gs-battle-go-after s
        # after THAT client's 47 while the room clock ran from the FIRST 47:
        # live table 31 (09-26, 300 s) GOed at +20.0 / +21.6 / +30.4 s and
        # ended 300 s after the first 47 -- "battles end ~30 s early".
        self.go_at = None           # the room's shared GO, pending
        self.go_fired = None        # when it went out: the clock starts here
        self.go_cap = None          # arrivals later than this GO on their own
        self.gens = None            # doc_field.Generators, from the shared GO
        self.quest_items = False    # doc_npcquests.mission_items placed once
        self.reset_at = None
        self.result_sent = set()
        self.dead_until = {}        # victim -> respawn due
        self.last_death = {}        # victim -> time of its last counted death
        self.over = False
        self.why = None
        self.opened = now
        self.damage_seen = 0
        self.tally = None           # doc_stats.record_battle, once, at the end
        self.tally_keys = {}        # member id -> its key in `tally`
        self.npc_kills = 0          # mission: request 30s whose victim is no member
        # 2026-10-05: NPC ids already counted -- request 30 AND the 1 Hz HP
        # report both report one enemy's death (live: Course I "cleared" on
        # 3 real kills, each counted twice)
        self.npc_counted = set()
        self.npc_hp = {}            # mission: NPC id -> last HP from the 1 Hz report
        # 2026-09-24: TEAM CAPSULE -- slot -> (item, pos) on the field, who
        # holds how many, the running hold (team, until), the decided team
        self.field = None
        self.holders = {}
        # 2026-09-26: member -> Chocobo Coins picked up (kind 11 +, own drop
        # -); paid 1000 each at the end (doc_stats.coin_gil) and cut from the
        # client's bag (kind 21, ident = itself) before its kind 4
        self.coins = {}
        # 2026-10-01: member -> {consumable id: net picked up on the field}
        # (kind 11 +, own drop -). Manual p.33: consumables found on the
        # battlefield "generally cannot be taken back to the lobby", so
        # end_battle cuts them (kind 21) as it cuts the coins.
        self.field_picks = {}
        # 2026-10-01: the Results screen's "Teammate KO'd" and "Kill Streak
        # Bonus" rows (doc_stats.results_rp) read counts the server sends.
        # team_kos = teammates this player KO'd (a friendly-fire table);
        # life_kills = kills since this player's last KO; streaks = kills
        # made on a streak. SE's streak rule is not in the client: OURS --
        # every kill from the STREAK_FROM-th in one life counts once.
        self.team_kos = {}
        self.life_kills = {}
        self.streaks = {}
        self.cap_hold = None
        self.capsule_winner = None
        # 2026-09-26: the two TEAM CAPSULE medals (launch build, 60:[47] /
        # [48]). Capsule Seeker: "defeated the most mako capsule carriers and
        # made them drop" -> killer -> carriers KO'd; `last_ko` = victim ->
        # [killer, when, credited] and `carrier_drop` = dropper -> when, so a
        # carrier's 118 DROP and its request 30 pair up in EITHER order
        # within CARRIER_DROP_S, once. Last Capsule: "obtained the last mako
        # capsule" -> the member whose pick-up completed the hold that WON
        # (last_pick -> cap_last -> last_capsule; INFERRED reading).
        self.carrier_kos = {}
        self.last_ko = {}
        self.carrier_drop = {}      # member -> when it dropped a capsule unKO'd
        self.last_pick = None
        self.cap_last = None
        self.last_capsule = None
        self.base_hp = {}           # TEAM BASE: base index -> last reported HP
        # 2026-09-26: TEAM BASE = destroy + OCCUPY (Additional Manual, Jan
        # 2006). A base at HP 0 opens an occupation phase for the team that
        # destroyed it; a member standing on the spot long enough wins it.
        self.base_down = {}         # base index -> the team that must occupy it
        self.occupy = {}            # base index -> (occupier cid, since)
        self.occupier = None        # the member whose hold won the battle
        self.base_spots = None      # (team 0 base, team 1 base) world positions
        # 2026-10-05: the owning team per base INDEX; None = index i is team
        # i's (PvP Team Base). A base mission lists ONE base, team 1's.
        self.base_teams = None
        # 2026-09-24: TEAM LEADER (mode byte 5, "TLD"). SE's 28:205: "Two
        # teams compete to defeat one another's team leader. Defeating the
        # enemy leader earns points." The client keeps no leader (its
        # isCharacterTeamLeader native is a -1 stub), so the server picks one
        # per team and only a kill of an enemy LEADER scores.
        self.team_leaders = {}      # team -> the member leading it
        self.leader_kills = {m: 0 for m in self.members}
        if self.leader_mode():
            self.pick_leaders()
        # 2026-09-24: the two medals the kill ledger can name (group 60 [41]
        # First Attack "defeats the first enemy", [46] The Finisher "ends a
        # battle or mission") -- the member, or None
        self.first_killer = None
        self.finisher = None

    # ── roster ────────────────────────────────────────────────────────
    def leader_mode(self):
        return self.rules.mode == "TLD" and self.mission is None

    def pick_leaders(self):
        """Each team's leader: the table's own leader leads their team, every
        other team is led by its first seated member. Returns the leaders
        chosen by this call as {team: cid}."""
        new = {}
        for m in [self.leader] + self.members:
            if not m or m not in self.members or m in self.left:
                continue
            t = self.team_of(m)
            if t not in self.team_leaders:
                self.team_leaders[t] = new[t] = m
        return new

    def is_team_leader(self, cid):
        return cid in self.team_leaders.values()

    def team_of(self, cid):
        return self.teams.get(cid, 0)

    def individual(self):
        return self.rules.mode == "BT"

    def slot_of(self, cid):
        """The team point slot a kill by `cid` is credited to (team modes:
        the team, folded into the four HUD slots). In BT every player is its
        own score (kind 9 carries killer / victim points) and the
        slot is only used for the verdict: the player's index."""
        if self.individual():
            return self.members.index(cid) if cid in self.members else 0
        return min(max(self.team_of(cid), 0), gamemsg.GS_TEAM_SLOTS - 1)

    def eliminated(self, cid):
        """Out of the battle: TDM after one death; otherwise at the KO limit."""
        d = self.deaths.get(cid, 0)
        if self.rules.mode == "TDM":
            return d > 0
        return bool(self.rules.ko_limit) and d >= self.rules.ko_limit

    def alive(self):
        return [m for m in self.present() if not self.eliminated(m)]

    def arrive(self, cid, now, go_after=0.0, go_wait=0.0):
        """Request 47 from `cid`. Returns True for the room's first 47.

        go_after 0: the clock starts at the first 47 (no GO to wait for).
        go_after > 0: the room's GO is due go_after s after the LATEST
        arrival, but never later than go_after + go_wait s after the first;
        the clock starts when go() fires it. `joins_go(cid)` says whether
        `cid` rides that shared GO or (arriving after it) gets its own."""
        first = self.started is None
        self.arrived.add(cid)
        if first:
            self.started = now
            if go_after > 0:
                self.go_cap = now + go_after + max(0.0, go_wait)
        if go_after > 0:
            if first or self.joins_go(now, go_after):
                self.go_at = max(self.go_at or 0.0, now + go_after)
            return first
        if first:
            self._start_clock(now)
        return first

    def _start_clock(self, now):
        if self.rules.time_limit > 0:
            self.end_at = now + self.rules.time_limit
        else:
            self.end_at = None          # "Time Limit: None" -- the target ends it

    def joins_go(self, now, go_after):
        """True while an arrival at `now` can still ride the shared GO."""
        return (self.go_fired is None and self.go_cap is not None
                and (self.go_at is None or now < self.go_at)
                and now + go_after <= self.go_cap)

    def go_due(self, now):
        return (self.go_at is not None and self.go_fired is None
                and now >= self.go_at)

    def go(self):
        """The shared GO went out: the room clock starts AT it."""
        self.go_fired = self.go_at
        self.go_at = None
        self._start_clock(self.go_fired)

    def leave(self, cid):
        """`cid` left. Returns {team: new leader} when it led a team in a
        Team Leader battle (the next member of that team takes over)."""
        self.left.add(cid)
        self.arrived.discard(cid)
        self.dead_until.pop(cid, None)
        if self.leader_mode():
            for t, m in list(self.team_leaders.items()):
                if m == cid:
                    del self.team_leaders[t]
            return self.pick_leaders()
        return {}

    def present(self):
        return [m for m in self.members if m not in self.left]

    # ── the tally ─────────────────────────────────────────────────────
    def saw_damage(self, sender, entries, now):
        self.damage_seen += 1

    def kill(self, killer, victim, now, dedupe_s=1.0, npc_type=None):
        """A request 30 from `victim`'s client (or from an observer). Returns
        the kind-9 record fields (points, killer, victim, last_one) or None
        when the report is a duplicate / not this room's. Ends the room when
        the kill target is reached."""
        if self.over:
            return None
        if victim not in self.kills:
            # 2026-09-23 (doc_missions): in a MISSION room a death report whose
            # victim is not a seated player can only be an enemy. Whether the
            # client ever sends one is UNPROVEN (its request-30 callers are the
            # character-table HP paths); count it if it does, and let a "kill"
            # mission end on its target.
            if self.mission is not None and killer in self.kills:
                # 2026-10-05: "defeat N Dual Horns" counts only Dual Horns
                if not doc_missions.kill_counts(self.mission, npc_type):
                    return None
                if victim in self.npc_counted:
                    return None
                self.npc_counted.add(victim)
                self.npc_kills += 1
                self.kills[killer] += 1
                if self.first_killer is None:
                    self.first_killer = killer
                if doc_missions.npc_kill_ends(self.mission, self.npc_kills):
                    self.over, self.why = True, "%s: %d enemy kill(s)" % (
                        doc_missions.WHY_OBJECTIVE, self.npc_kills)
                    self.finisher = killer
            return None
        last = self.last_death.get(victim)
        if last is not None and now - last < dedupe_s:
            return None
        if victim in self.dead_until and now < self.dead_until[victim]:
            # the client resends an unacknowledged kill
            # report for seconds; while the victim is still down it is the
            # same death, not a second one.
            return None
        self.last_death[victim] = now
        self.deaths[victim] += 1
        self.life_kills[victim] = 0
        if (killer in self.kills and killer != victim and not self.individual()
                and self.team_of(killer) == self.team_of(victim)):
            self.team_kos[killer] = self.team_kos.get(killer, 0) + 1
        if (self.mission is not None
                and doc_missions.ko_out(self.mission, self.deaths[victim])):
            self.over, self.why = True, "%s: %d KO(s)" % (
                doc_missions.WHY_KO, self.deaths[victim])
        credited = (killer in self.kills and killer != victim
                    and (self.individual()
                         or self.team_of(killer) != self.team_of(victim)))
        # 2026-09-24: in Team Leader only the enemy LEADER's death scores
        scored = credited and (not self.leader_mode()
                               or self.team_leaders.get(self.team_of(victim)) == victim)
        if credited:
            self.kills[killer] += 1
            self.life_kills[killer] = self.life_kills.get(killer, 0) + 1
            if self.life_kills[killer] >= STREAK_FROM:
                self.streaks[killer] = self.streaks.get(killer, 0) + 1
            if self.first_killer is None:
                self.first_killer = killer
            self.last_ko[victim] = [killer, now, False]
            dropped = self.carrier_drop.pop(victim, None)
            if (self.holders.get(victim, 0) > 0 or (
                    dropped is not None and now - dropped <= fielditems.CARRIER_DROP_S)):
                self.credit_carrier_ko(victim)
            if scored and self.leader_mode():
                self.leader_kills[killer] = self.leader_kills.get(killer, 0) + 1
            if scored and not self.individual():
                s = self.slot_of(killer)
                self.points[s] = min(self.points[s] + 1, 0xFFFF)
        if self.rules.respawn >= 0 and not self.eliminated(victim):
            self.dead_until[victim] = now + self.rules.respawn
        else:
            self.dead_until.pop(victim, None)   # out: no respawn pending
        self.seq9 = (self.seq9 + 1) & 0xFF
        target = self.rules.kill_target
        score = (self.kills[killer] if self.individual()
                 else self.points[self.slot_of(killer)]) if scored else 0
        last_one = bool(target and scored and score == target - 1)
        if target and scored and score >= target:
            self.over, self.why = True, "kill target %d reached" % target
        if (self.rules.mode == "TDM" or self.rules.ko_limit) and not self.over:
            # Team Survival / KO Limit: a side with nobody left standing loses;
            # in individual play the last one standing wins
            if self.individual():
                if len(self.present()) >= 2 and len(self.alive()) <= 1:
                    self.over, self.why = True, "last one standing (KO limit)"
            else:
                sides = {self.team_of(m) for m in self.present()}
                up = {self.team_of(m) for m in self.alive()}
                if len(sides) >= 2 and len(up) < len(sides):
                    self.over, self.why = True, ("team wiped out (%s)" % (
                        "survival" if self.rules.mode == "TDM" else "KO limit"))
        if self.over and credited and self.finisher is None:
            # the kill that ENDED it (target reached / side wiped / last one
            # standing); a mission lost to a KO is ended by an enemy -- nobody
            self.finisher = killer
        if self.individual():
            # kind 9 in BT (arm 0x00bc1e10): +0 the KILLER's points, +2 the
            # VICTIM's points -- per player, not four team totals
            pts = [self.kills.get(killer, 0) if credited else 0,
                   self.kills.get(victim, 0), 0, 0]
        else:
            pts = list(self.points)
        return (pts, killer if credited else 0, victim, last_one)

    def credit_carrier_ko(self, victim, now=None, window=None):
        """Capsule Seeker: credit `victim`'s last KO to its killer once -- at
        the KO when it held a capsule, or (now given) when its capsule DROP
        lands within `window` s of that KO. Returns the killer or None."""
        lk = self.last_ko.get(victim)
        if lk is None or lk[2]:
            return None
        if now is not None and now - lk[1] > (fielditems.CARRIER_DROP_S if window is None
                                              else window):
            return None
        lk[2] = True
        self.carrier_kos[lk[0]] = self.carrier_kos.get(lk[0], 0) + 1
        return lk[0]

    def npc_hp_update(self, entries, player, now, credit=None, types=None):
        """2026-09-23: a mission's enemy deaths from the controlling client's
        1 Hz report (mission_npc_report). An NPC whose HP falls from > 0 to 0
        is a kill for `player`; returns the ids that died this report.
        `types` = {id: kind-15 type} (only a mission's named enemy counts)."""
        died = []
        for nid, hp in entries:
            # 2026-10-05: keyed by (reporter, id). Each member's console can
            # simulate its OWN copy of an id (live 10-05: three consoles,
            # HP 100 -> 60 -> 100 as two of them reported one Dual Horn), and
            # a shared set changes controller on a handover; one id's history
            # across consoles made fake rises, and a fall to 0 could repeat.
            key = (player, nid)
            prev = self.npc_hp.get(key)
            self.npc_hp[key] = hp
            if prev is not None and hp != prev:
                # 2026-09-23: the game's DAMAGE SCALE, measured -- no shipped
                # table gives player HP (the server always set it; ours is a
                # placeholder 100), so log every NPC HP change.
                print("  [missions] NPC 0x%x HP %d -> %d (%+d)"
                      % (nid, prev, hp, hp - prev), flush=True)
            if prev and hp == 0 and not self.over:
                # 2026-10-05: the kill is the LAST HITTER's when one is known
                # (a non-controller's 113, re-targeted to the controller of a
                # shared set), not the reporting controller's
                _k = (credit or {}).get(nid)
                self.kill(_k if _k in self.kills else player, nid, now,
                          npc_type=(types or {}).get(nid))
                died.append(nid)
        return died

    def respawns_due(self, now):
        out = [c for c, t in self.dead_until.items() if now >= t]
        for c in out:
            self.dead_until.pop(c, None)
        return out

    # ── the verdict ───────────────────────────────────────────────────
    def base_update(self, reports, occupy=False):
        """The controller's request-24 bases. Returns [(index, hp)] that
        CHANGED (base index i is team i's: kind 29 lists them in order). A
        base that falls from HP > 0 to 0:
          * occupy=False (the old rule): ends the room, won by the other team;
          * occupy=True (2026-09-26, the January manual: "destroy the enemy
            base and occupy it for a set time"): opens the OCCUPATION phase
            for the other team (base_down); base_occupy_tick() decides it."""
        changed = []
        for idx, hp, _mask in reports:
            prev = self.base_hp.get(idx)
            if prev == hp:
                continue
            self.base_hp[idx] = hp
            changed.append((idx, hp))
            owner = (self.base_teams[idx] if self.base_teams is not None
                     and idx < len(self.base_teams) else idx)
            if hp == 0 and prev and not self.over and owner in (0, 1):
                if self.mission is not None:
                    # 2026-10-05: a BASE MISSION's base is the enemy's and
                    # taking it is every member's objective (mission rooms
                    # split players across teams 0 / 1). -1 = any member holds.
                    if occupy:
                        self.base_down.setdefault(idx, -1)
                        continue
                    self.over = True
                    self.why = "%s: the enemy base destroyed" % doc_missions.WHY_OBJECTIVE
                    continue
                if occupy:
                    self.base_down.setdefault(idx, 1 - owner)
                    continue
                self.capsule_winner = 1 - owner
                self.over = True
                self.why = "team %d's base destroyed" % owner
        return changed

    def winner_slot(self):
        """The leading side: a team point slot, or in BT the leading member's
        index. None for a tie / no points. TDM: the side still standing."""
        if self.capsule_winner is not None:
            return self.capsule_winner
        if self.over and self.why and ("wiped" in self.why or "standing" in self.why):
            up = self.alive()
            if self.individual() and len(up) == 1:
                return self.members.index(up[0])
            sides = {self.team_of(m) for m in up}
            if not self.individual() and len(sides) == 1:
                return min(max(sides.pop(), 0), gamemsg.GS_TEAM_SLOTS - 1)
        if self.individual():
            best = max(self.kills.values()) if self.kills else 0
            if best <= 0:
                return None
            lead = [m for m in self.members if self.kills.get(m, 0) == best]
            return self.members.index(lead[0]) if len(lead) == 1 else None
        best = max(self.points)
        if best <= 0:
            return None
        lead = [i for i, p in enumerate(self.points) if p == best]
        return lead[0] if len(lead) == 1 else None

    def winner_cid(self):
        """BT: the winning player, or None."""
        w = self.winner_slot()
        return self.members[w] if (self.individual() and w is not None) else None

    def outcome(self, cid):
        """'w' / 'l' / 'd' for `cid` under the rules. A mission (Solo quest)
        is a win iff the room was ended by its objective, not the clock."""
        if self.mission is not None:
            # 2026-09-23: the mission's own victory / defeat lines (SE's text,
            # doc_missions.OBJECTIVES): KO limit loses, objective wins, and an
            # "as many as possible" mission wins when the clock ends it.
            won_base = (None if self.capsule_winner is None
                        else self.slot_of(cid) == self.capsule_winner)
            return doc_missions.verdict(self.mission, self.over, self.why,
                                        self.deaths.get(cid, 0), won_base)
        w = self.winner_slot()
        if w is None:
            return "d"
        return "w" if self.slot_of(cid) == w else "l"

    def winner_team(self):
        w = self.winner_slot()
        if w is None:
            return None
        for m in self.members:
            if self.slot_of(m) == w:
                return self.team_of(m)
        return w

    def elapsed(self, now):
        t0 = self.go_fired if self.go_fired is not None else self.started
        return 0.0 if t0 is None else max(0.0, now - t0)

    def summary(self):
        return ("table %d %s: points %s, kills %s, deaths %s, %s"
                % (self.key, self.rules.mode, self.points,
                   {"0x%x" % k: v for k, v in self.kills.items()},
                   {"0x%x" % k: v for k, v in self.deaths.items()},
                   self.why or "running"))


def battle_rules_from_record(rec, default_length=180.0, default_kill=0,
                             default_respawn=4.0, time_unit=1.0):
    """The BattleRules the battletable RECORD asks for. Decoded fields:
    wire+0 flags, +26 mission, +34 situation, +108 window kind, +109 max,
    +110 mode, +111 respawn delay (HUD: record[+57]*1000 + 4000 ms), +113
    map, +116 time limit (HUD countdown = record[+64] * 1000, sec 4he; the
    unit is `time_unit` seconds per count -- see --bt-time-unit). The kill
    target and the rest come from BT_RULE_FIELDS once they are decoded; a
    field that is not decoded keeps the fallback the caller passes."""
    if rec is None or len(rec) < tablerecords.BT_REC_LEN:
        return BattleRules(time_limit=default_length, kill_target=default_kill,
                           respawn=default_respawn)
    flags = struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0]
    mode_b = rec[tablerecords.BT_OFF_MODE]
    kind = rec[tablerecords.BT_OFF_UNK108]
    if flags & tablerecords.BT_FLAG_MISSION:
        mode = "MISSION"
    elif flags & tablerecords.BT_FLAG_INDIVIDUAL:
        mode = "BT"
    else:
        mode = tablerecords.BT_MODE_NAMES.get(mode_b, "TBT")
    kt = struct.unpack_from("<H", rec, tablerecords.BT_OFF_TARGET)[0] or default_kill
    ko = rec[tablerecords.BT_OFF_KO_LIMIT] if flags & tablerecords.BT_FLAG_KO_LIMIT else 0
    tl = struct.unpack_from("<I", rec, tablerecords.BT_OFF_TIME)[0]
    if tl and time_unit > 0:
        time_limit = tl * time_unit
    elif tl == 0 and (kt or ko) and time_unit > 0:
        time_limit = 0.0                # "Time Limit: None": the target ends it
    else:
        time_limit = default_length
    rs = rec[tablerecords.BT_OFF_PENALTY]
    respawn = float(rs) + 4.0 if rs else default_respawn
    if mode == "TDM":
        respawn = -1.0                  # Team Survival: no respawns (0x70c9)
    return BattleRules(mode=mode, time_limit=time_limit, kill_target=kt,
                       respawn=respawn, maximum=rec[tablerecords.BT_OFF_MAX],
                       situation=struct.unpack_from("<H", rec, tablerecords.BT_OFF_SITUATION)[0],
                       map_idx=rec[tablerecords.BT_OFF_MAP],
                       mission=struct.unpack_from("<H", rec, tablerecords.BT_OFF_MISSION)[0],
                       flags=flags, kind=kind,
                       random_teams=bool(flags & tablerecords.BT_FLAG_RANDOM_TEAMS),
                       briefing=float(rec[tablerecords.BT_OFF_BRIEFING]) * 60.0,
                       npc=bool(flags & tablerecords.BT_FLAG_NPC), ko_limit=ko,
                       friendly_fire=bool(flags & tablerecords.BT_FLAG_FRIENDLY_FIRE),
                       restrictions=rec[tablerecords.BT_OFF_RESTRICT],
                       base_hp=struct.unpack_from("<I", rec, tablerecords.BT_OFF_BASE_HP)[0],
                       capsules=rec[tablerecords.BT_OFF_CAPSULES])


#: 2026-09-26: the JOIN / RESERVE result for a joiner whose rank points are
#: outside the table's Min/Max RP. SE's code is NOT located: the client ships
#: the text (KelStr 26:124, 0x687c "Your current ranking points do not fall
#: within the requirements of this battletable.") but no code in the
#: slot-08 image loads that id as an immediate, so which result selects it
#: is unknown. -7 is OURS, a nonzero refusal in the same class as the
#: novice (-5) and unit (-6) gates: the JOIN arm treats any negative as a
#: failure and the client stays unreserved.
BT_REFUSE_RP = -7


def rp_allowed(rec, rp):
    """(ok, why): may a character holding `rp` rank points sit at the table
    whose record is `rec`? source: January 2006 player guide, multiplayer
    page: a table can cap rank points so that mostly beginners meet, and the
    limit is set in the table's own game rules. The record's Maximum RP (wire+60, flags 0x00080000) and Minimum
    RP (wire+64, flags 0x00100000), both inclusive (OURS: the client's
    labels "Above %d RP" / "Below %d RP" do not say)."""
    if rec is None or rp is None or len(rec) < tablerecords.BT_OFF_MIN_RP + 4:
        return True, "no limit"
    flags = struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0]
    rp = int(rp)
    if flags & tablerecords.BT_FLAG_MAX_RP:
        mx = struct.unpack_from("<I", rec, tablerecords.BT_OFF_MAX_RP)[0]
        if rp > mx:
            return False, "%d RP > the table's maximum %d" % (rp, mx)
    if flags & tablerecords.BT_FLAG_MIN_RP:
        mn = struct.unpack_from("<I", rec, tablerecords.BT_OFF_MIN_RP)[0]
        if rp < mn:
            return False, "%d RP < the table's minimum %d" % (rp, mn)
    return True, "within the table's RP limits"


def record_password(rec):
    """The table password the CREATE record carries (flags bit 0, 8 bytes at
    wire+68, 4 chars used), or b"" -- sec 4he: JOIN-with-password (30) and
    RESERVE-with-password (153) compare against THIS; the store used to keep
    b"" for every created table, so every password check passed."""
    if rec is None or len(rec) < tablerecords.BT_OFF_PW_REC + 8:
        return b""
    if not struct.unpack_from("<I", rec, tablerecords.BT_OFF_FLAGS)[0] & tablerecords.BT_FLAG_PASSWORD:
        return b""
    return bytes(rec[tablerecords.BT_OFF_PW_REC:tablerecords.BT_OFF_PW_REC + 8]).rstrip(b"\x00")


def unit_teams(teams, members, unit_of):
    """sec 4he: a UNIT table (flags 0x01000000) is unit vs unit --
    SE's help text 0x70c5: the first two units to reserve own the two sides.
    The client never maps unit -> team (kind 20 applies whatever team byte we
    send), so this is the server's. `unit_of(cid)` -> unit id or 0. Members
    of the first two units seated get team 0 / 1; anyone else keeps the team
    request 31 gave them (or none)."""
    out = dict(teams)
    sides = []
    for m in members:
        u = unit_of(m) if m else 0
        if u and u not in sides and len(sides) < 2:
            sides.append(u)
    for m in members:
        u = unit_of(m) if m else 0
        if u in sides:
            out[m] = sides.index(u)
    return out
