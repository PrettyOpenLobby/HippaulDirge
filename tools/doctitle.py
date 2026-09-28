"""The Dirge of Cerberus title plugin for the OpenLobby core.

The world responder (docudp.py) runs as its own service. This module is the
part of Dirge of Cerberus that lives INSIDE the core's login process: the
content profile the Viewer shows for a Dirge Content ID (prof_010.pfb), built
from two of the tables the responder keeps in the stack's PostgreSQL database
(docdb.py; they were doc-characters.json and doc-stats.json on the logs
volume):

    doc_character   key member:<id>    -> [ {slot, name, ...}, ... ]
    doc_career      key member:<id>/<n> -> {name, rank, rp, ...}

The core's login already has POL_DATABASE_URL, so nothing names a database
here. Loaded with POL_TITLES=doctitle in the core's login and authsess
services; see docker-compose.title.yml.
"""
import titles

import docdb

#: the N of prof_010.pfb
CONTENT_CODE = 10

#: the profile's slots: Name, Rank (the career ladder, 1..16), Ranking Points
SLOT_NAME, SLOT_RANK, SLOT_RANKPOINT = 4, 6, 8

#: the tables this plugin reads
CHARACTERS, CAREERS = "doc_character", "doc_career"


def profile_for(member_id):
    """`{slot: value}` for a member: the lowest-slot named character and, when
    the career store has a career for it, its rank and ranking points. {} when
    the database cannot be read: a profile is never a guess."""
    try:
        roster = docdb.Table(CHARACTERS).get(f"member:{member_id}") or []
        first = min((c for c in roster if c.get("name")),
                    key=lambda c: int(c.get("slot", 0)), default=None)
        if not first:
            return {}
        out = {SLOT_NAME: first["name"]}
        careers = docdb.Table(CAREERS).with_prefix(f"member:{member_id}/")
    except docdb.errors() as exc:
        print(f"[doctitle] profile for member {member_id} not read: {exc}",
              flush=True)
        return {}
    mine = sorted(k for k, c in careers.items()
                  if (c or {}).get("name") == first["name"])
    if mine:
        c = careers[mine[0]]
        out[SLOT_RANK] = min(max(int(c.get("rank") or 1), 1), 16)
        out[SLOT_RANKPOINT] = max(0, int(c.get("rp") or 0))
    return out


class DirgeOfCerberus(titles.Title):
    tag = b"DC0"
    content_code = CONTENT_CODE

    def describe(self):
        return f"Dirge of Cerberus characters ({CHARACTERS}, {docdb.where()})"

    def profile_fields(self, cid, member_id):
        if member_id is None:
            return {}
        return profile_for(member_id)


def register():
    # the responder's tables, so a profile can be read before it first ran
    docdb.migrate_at_start("doctitle")
    return titles.register(DirgeOfCerberus())
