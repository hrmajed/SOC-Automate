"""Read-only investigation tools the agent may call. Nothing here changes state."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from .guardrails import ParamSpec, ToolSpec
from .rag import KnowledgeBase
from .store import DataStore, Event, is_internal_ip, parse_ts

TS = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?"
NAME = r"[\w.@\\\-\[\] :]{1,128}"
IP = r"[0-9a-fA-F:.]{3,45}"

TIME_PARAMS = {"start": ParamSpec("string", 40, pattern=TS), "end": ParamSpec("string", 40, pattern=TS),
               "limit": ParamSpec("integer", maximum=100)}

TOOL_SPECS: dict[str, ToolSpec] = {
    "lookup_asset": ToolSpec("lookup_asset", "Look up a host, IP or cloud resource in the network map / cloud inventory.",
                             {"name": ParamSpec("string", 128, pattern=NAME)}, ["name"]),
    "lookup_identity": ToolSpec("lookup_identity", "Look up a user in the identity directory (role, privilege, "
                                "usual locations, linked AWS IAM users).",
                                {"user": ParamSpec("string", 128, pattern=NAME)}, ["user"]),
    "lookup_ip": ToolSpec("lookup_ip", "Classify an IP: internal segment/asset or local threat-intel verdict.",
                          {"ip": ParamSpec("string", 45, pattern=IP)}, ["ip"]),
    "query_edr": ToolSpec("query_edr", "Search EDR telemetry (process, network, file, logon, scheduled task events).",
                          {"host": ParamSpec("string", 64, pattern=NAME), "user": ParamSpec("string", 128, pattern=NAME),
                           **TIME_PARAMS}),
    "query_cloudtrail": ToolSpec("query_cloudtrail", "Search AWS CloudTrail events by user/IAM principal, source IP "
                                 "or event name.",
                                 {"user": ParamSpec("string", 128, pattern=NAME),
                                  "source_ip": ParamSpec("string", 45, pattern=IP),
                                  "event_name": ParamSpec("string", 64, pattern=r"[A-Za-z]{2,64}"), **TIME_PARAMS}),
    "query_idp": ToolSpec("query_idp", "Search identity-provider (Okta) sign-in and MFA events.",
                          {"user": ParamSpec("string", 128, pattern=NAME),
                           "source_ip": ParamSpec("string", 45, pattern=IP), **TIME_PARAMS}),
    "search_knowledge": ToolSpec("search_knowledge", "Semantic search over past incident reports, compliance "
                                 "obligations, policies and the network map.",
                                 {"query": ParamSpec("string", 300), "k": ParamSpec("integer", maximum=6)}, ["query"]),
    "get_related_alerts": ToolSpec("get_related_alerts", "List other open alerts that share an entity "
                                   "(host, user or IP).", {"entity": ParamSpec("string", 128, pattern=NAME)},
                                   ["entity"]),
}


class ToolBox:
    def __init__(self, store: DataStore, kb: KnowledgeBase, rag_guarded: bool = True):
        self.store = store
        self.kb = kb
        self.rag_guarded = rag_guarded
        self.fns: dict[str, Callable[..., dict[str, Any]]] = {
            "lookup_asset": self.lookup_asset, "lookup_identity": self.lookup_identity, "lookup_ip": self.lookup_ip,
            "query_edr": self.query_edr, "query_cloudtrail": self.query_cloudtrail, "query_idp": self.query_idp,
            "search_knowledge": self.search_knowledge, "get_related_alerts": self.get_related_alerts,
        }

    def run(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return self.fns[name](**args)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _window(events: list[Event], start: str | None, end: str | None, limit: int | None) -> list[Event]:
        s: datetime | None = parse_ts(start) if start else None
        e: datetime | None = parse_ts(end) if end else None
        out = [ev for ev in events if (s is None or ev.timestamp >= s) and (e is None or ev.timestamp <= e)]
        return out[: (limit or 50)]

    def _events(self, evs: list[Event]) -> dict[str, Any]:
        return {"count": len(evs), "events": [ev.to_dict() for ev in evs]}

    # ------------------------------------------------------------------ tools
    def lookup_asset(self, name: str) -> dict[str, Any]:
        a = self.store.asset(name)
        if a:
            return {"found": True, "kind": "host", "asset": a, "segment": self.store.segment_for_ip(a["ip"])}
        r = self.store.cloud_resource(name)
        if r:
            return {"found": True, "kind": "cloud_resource", "resource": r}
        return {"found": False, "name": name}

    def lookup_identity(self, user: str) -> dict[str, Any]:
        ident = self.store.identity(user)
        if not ident:
            return {"found": False, "user": user}
        return {"found": True, "identity": ident}

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        seg = self.store.segment_for_ip(ip)
        asset = self.store.asset(ip)
        ti = self.store.ti_lookup(ip)
        return {"ip": ip, "internal": bool(seg) or is_internal_ip(ip), "segment": seg,
                "asset": asset["hostname"] if asset else None,
                "threat_intel": ti or {"verdict": "unknown", "description": "No local intel for this IP."}}

    def query_edr(self, host: str | None = None, user: str | None = None, start: str | None = None,
                  end: str | None = None, limit: int | None = 50) -> dict[str, Any]:
        u = self.store.resolve_user(user) if user else None
        evs = [ev for ev in self.store.events if ev.source == "edr"
               and (host is None or (ev.host or "").lower() == host.lower()
                    or host.lower() in [h.lower() for h in ev.entities.get("hosts", [])] and ev.event_type == "Logon")
               and (u is None or ev.user == u)]
        return self._events(self._window(evs, start, end, limit))

    def query_cloudtrail(self, user: str | None = None, source_ip: str | None = None, event_name: str | None = None,
                         start: str | None = None, end: str | None = None, limit: int | None = 50) -> dict[str, Any]:
        u = self.store.resolve_user(user) if user else None
        evs = [ev for ev in self.store.events if ev.source == "cloudtrail"
               and (u is None or ev.user == u) and (source_ip is None or ev.src_ip == source_ip)
               and (event_name is None or ev.event_type.lower() == event_name.lower())]
        return self._events(self._window(evs, start, end, limit))

    def query_idp(self, user: str | None = None, source_ip: str | None = None, start: str | None = None,
                  end: str | None = None, limit: int | None = 50) -> dict[str, Any]:
        u = self.store.resolve_user(user) if user else None
        evs = [ev for ev in self.store.events if ev.source == "idp"
               and (u is None or ev.user == u) and (source_ip is None or ev.src_ip == source_ip)]
        return self._events(self._window(evs, start, end, limit))

    def search_knowledge(self, query: str, k: int | None = 4) -> dict[str, Any]:
        return self.kb.search(query, k=k or 4, guarded=self.rag_guarded)

    def get_related_alerts(self, entity: str) -> dict[str, Any]:
        e = entity.lower()
        canonical = (self.store.resolve_user(entity) or "").lower()
        out = []
        for a in self.store.alerts:
            vals = [v.lower() for vs in a["entities"].values() for v in vs]
            if e in vals or canonical in vals:
                out.append({k: a[k] for k in ("id", "title", "source", "severity", "created_at")})
        return {"entity": entity, "alerts": out}
