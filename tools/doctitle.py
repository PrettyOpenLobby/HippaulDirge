"""The Dirge of Cerberus title plugin for the OpenLobby core.

The world responder (docudp.py) runs as its own service. This module is the
part of Dirge of Cerberus that lives INSIDE the core's login process: the
content profile the Viewer shows for a Dirge Content ID (prof_010.pfb), built
from the two files the responder keeps on the shared logs volume:

    doc-characters.json   {"member:<id>": [ {slot, name, ...}, ... ]}
    doc-stats.json        {"chars": {"member:<id>/<n>": {name, rank, rp, ...}}}

Loaded with POL_TITLES=doctitle in the core's login and authsess services;
see docker-compose.title.yml.
"""
import json
import os

import titles

#: the N of prof_010.pfb
CONTENT_CODE = 10

#: the profile's slots: Name, Rank (the career ladder, 1..16), Ranking Points
SLOT_NAME, SLOT_RANK, SLOT_RANKPOINT = 4, 6, 8


def _log_dir():
    return os.environ.get("POL_LOG_DIR", "/logs")


def chara_store():
    return os.environ.get("POL_DOC_CHARA_STORE", os.path.join(_log_dir(), "doc-characters.json"))


def stats_store():
    return os.environ.get("POL_DOC_STATS", os.path.join(_log_dir(), "doc-stats.json"))


def _load(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh) or default
    except FileNotFoundError:
        return default


def profile_for(member_id):
    """`{slot: value}` for a member: the lowest-slot named character and, when
    the stats file has a career for it, its rank and ranking points."""
    roster = _load(chara_store(), {}).get(f"member:{member_id}") or []
    first = min((c for c in roster if c.get("name")),
                key=lambda c: int(c.get("slot", 0)), default=None)
    if not first:
        return {}
    out = {SLOT_NAME: first["name"]}
    careers = _load(stats_store(), {}).get("chars") or {}
    pre = f"member:{member_id}/"
    mine = sorted(k for k, c in careers.items()
                  if k.startswith(pre) and (c or {}).get("name") == first["name"])
    if mine:
        c = careers[mine[0]]
        out[SLOT_RANK] = min(max(int(c.get("rank") or 1), 1), 16)
        out[SLOT_RANKPOINT] = max(0, int(c.get("rp") or 0))
    return out


class DirgeOfCerberus(titles.Title):
    tag = b"DC0"
    content_code = CONTENT_CODE

    def describe(self):
        return f"Dirge of Cerberus characters {chara_store()}"

    def profile_fields(self, cid, member_id):
        if member_id is None:
            return {}
        return profile_for(member_id)


def register():
    return titles.register(DirgeOfCerberus())
