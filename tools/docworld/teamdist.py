"""The player distribution (notify kind 20): when a table is ready, the automatic teams, rebalancing a one-sided table, the Solo briefing."""



def gs_real_ready(teams, members):
    """sec 4ft: (ready, why) for the REAL distribution of a table: at least two
    seated members, every one of them on a team, and both sides occupied."""
    members = [m for m in members if m]
    if len(members) < 2:
        return False, "%d seated member(s), need 2" % len(members)
    missing = [m for m in members if m not in teams]
    if missing:
        return False, "no team yet for %s" % ", ".join("0x%x" % m for m in missing)
    if len({teams[m] for m in members}) < 2:
        return False, "everyone is on team %d -- stand on OPPOSITE teams" \
            % teams[members[0]]
    return True, "all %d seated players are on a team, both sides occupied" \
        % len(members)


def gs_dist_due(g, settle):
    """sec 4fw: when a READY table's real distribution is due (ready_at +
    settle), or None if it is not ready or has already gone out.  Checked on
    the server's clock as well as on request 31: the briefing room sends 31
    only when a player clicks a team, so a settle that ends after the last
    click was never re-checked (live 09-13, table 4).
    2026-09-24: never before the briefing countdown the players are shown
    (brief_end = Start + the record's Briefing Time).  The client's countdown
    is display only and it waits for us, so starting at "ready + settle" cut
    a 5:00 briefing off at 0:35."""
    if g.get("dist"):
        return None
    if g.get("ready_at") is None:
        # 2026-09-23: not ready yet -- wake for the auto-team deadline
        return g.get("auto_at")
    _be = g.get("brief_end")
    if _be and g["ready_at"] >= _be:
        return g["ready_at"]     # the countdown is over: no one can still move
    return max(g["ready_at"] + settle, _be or 0.0)


def gs_auto_teams(teams, members):
    """(teams, assigned) with every seated member that never
    chose a team put on the SMALLER side (ties -> team 0), so a briefing whose
    countdown ran out still gets its distribution. Live: the
    joiner stood on a team space but its client never sent request 31, so
    gs_real_ready said 'no team yet' forever and the countdown ended in
    nothing. Pure: the caller decides when."""
    out = dict(teams)
    count = {0: 0, 1: 0}
    for m in members:
        if m in out:
            count[out[m]] = count.get(out[m], 0) + 1
    assigned = []
    for m in members:
        if m and m not in out:
            t = 0 if count[0] <= count[1] else 1
            out[m] = t
            count[t] += 1
            assigned.append(m)
    return out, assigned


def gs_rebalance_teams(teams, members):
    """2026-09-24: a stuck briefing only frustrates players, so return
    (teams, moved) when the briefing time is up and every seated member is on
    ONE side -- the table can never be ready, so move the LAST floor(n/2) in
    seat order (the leader stays) to the other side.  A lopsided but playable
    split (3 v 1) is the players' choice and is left alone.  Pure."""
    members = [m for m in members if m]
    out = dict(teams)
    sides = {out[m] for m in members if m in out}
    if len(members) < 2 or len(sides) != 1 or any(m not in out for m in members):
        return out, []
    other = 0 if sides.pop() else 1
    moved = members[len(members) - len(members) // 2:]
    for m in moved:
        out[m] = other
    return out, moved


def gs_real_distribution(teams, members):
    """sec 4ft: the kind-20 entries for a REAL table, in seat order: every
    seated member that has chosen a team, slot = its index in THIS LIST.

    Seen live (tables 31/32, "3 joined, only 2 got in-game"): the slot
    is NOT a per-team index. The arm 0x00bc23d8 swaps each id to battle
    roster [chan+2144] entry `slot` (0x00bc254c..0x00bc25b0, then writes the
    id there at 0x00bc2610) and stores the client's own index [chan+16] =
    the entry's LIST position (`sw s1, 16(s2)` at 0x00bc24b0 / 0x00bc2528).
    Both agree only when slot == list position. A per-team slot gave two
    players slot 0 in every two-team table, so the roster and the own index
    disagreed on who is player #N."""
    return [(cid, teams[cid], i) for i, cid in
            enumerate(c for c in members if c and c in teams)]


def bt_start_targets(store, ident, self_cid):
    """sec 4ft (LIVE 2026-09-13): (table key, the OTHER seated members) for a
    leader's Start. The command-3 request carries ident 0 (logged live:
    `ident=0x00000000`), so `table_of(0)` found nothing and the fan-out never
    ran -- fall back to the session's learned charid."""
    lead = ident or self_cid
    key = store.table_of(lead) if lead else None
    if key is None:
        return None, lead, []
    return key, lead, [m for m in store.members(key) if m and m != lead]


def gs_solo_distribution(teams, self_cid):
    """sec 4fv: the kind-20 entries for a SOLO leader's briefing room:
    the player first (team 0 if request 31 never told us one), then every
    other id we seated there (the --gs-fake-teammates bots), slot = index
    within the team.  The distribution is what opens vl_main's door to
    leaveBriefingRoom -> KerberosZone.exit(get_onlinezone(false)); a solo
    table never satisfies gs_real_ready, so without this it never fires."""
    t = dict(teams)
    t.setdefault(self_cid, 0)
    order = [self_cid] + [c for c in t if c != self_cid]
    return gs_real_distribution(t, order)
