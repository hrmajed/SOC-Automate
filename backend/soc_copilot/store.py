"""Loads sample telemetry and normalises EDR, CloudTrail and IdP records into one evidence schema."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import DATA_DIR


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def is_internal_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback


def decode_powershell(cmd: str) -> str | None:
    m = re.search(r"-(?:e|en|enc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", cmd, re.IGNORECASE)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16le")
    except Exception:
        return None


@dataclass
class Event:
    evidence_id: str
    source: str
    timestamp: datetime
    event_type: str
    summary: str
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    outcome: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    entities: dict[str, list[str]] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "event_type": self.event_type,
            "summary": self.summary,
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "outcome": self.outcome,
            "fields": self.fields,
            "entities": self.entities,
        }


class DataStore:
    def __init__(self, data_dir: Path = DATA_DIR):
        self.data_dir = Path(data_dir)
        self.network_map = json.loads((self.data_dir / "network_map.json").read_text())
        self.threat_intel = json.loads((self.data_dir / "threat_intel.json").read_text())
        self.alerts: list[dict[str, Any]] = json.loads((self.data_dir / "alerts.json").read_text())
        self.identities = self.network_map["identities"]
        self._alias_to_user: dict[str, str] = {}
        for ident in self.identities:
            names = [ident["username"], ident["email"], ident["windows_account"], *ident.get("aliases", []),
                     *ident.get("aws_iam_users", [])]
            for n in names:
                if n:
                    self._alias_to_user[n.lower()] = ident["username"]
        self.events: list[Event] = []
        self.load_logs()

    # ---------- identity & asset helpers ----------
    def resolve_user(self, value: str | None) -> str | None:
        if not value:
            return None
        v = value.lower()
        if v in self._alias_to_user:
            return self._alias_to_user[v]
        if "\\" in v:
            return self._alias_to_user.get(v.split("\\")[-1], value.split("\\")[-1])
        return value

    def identity(self, username: str) -> dict[str, Any] | None:
        canonical = self.resolve_user(username)
        return next((i for i in self.identities if i["username"] == canonical), None)

    def asset(self, name_or_ip: str) -> dict[str, Any] | None:
        key = name_or_ip.strip().lower()
        for a in self.network_map["assets"]:
            if a["hostname"].lower() == key or a["ip"] == key:
                return a
        return None

    def segment_for_ip(self, ip: str) -> dict[str, Any] | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for seg in self.network_map["segments"]:
            if addr in ipaddress.ip_network(seg["cidr"]):
                return seg
        return None

    def cloud_resource(self, name: str) -> dict[str, Any] | None:
        for acct in self.network_map.get("cloud", []):
            for r in acct["resources"]:
                if r["name"].lower() == name.lower():
                    return {**r, "account_id": acct["account_id"], "account_alias": acct["alias"]}
        return None

    def ti_lookup(self, value: str) -> dict[str, Any] | None:
        return next((i for i in self.threat_intel["indicators"] if i["value"] == value), None)

    def alert(self, alert_id: str) -> dict[str, Any] | None:
        return next((a for a in self.alerts if a["id"] == alert_id), None)

    def event(self, evidence_id: str) -> Event | None:
        return next((e for e in self.events if e.evidence_id == evidence_id), None)

    # ---------- normalisation ----------
    def load_logs(self) -> None:
        logs = self.data_dir / "logs"
        parsers = {"edr.jsonl": self._norm_edr, "cloudtrail.jsonl": self._norm_cloudtrail, "idp.jsonl": self._norm_idp}
        events: list[Event] = []
        for fname, fn in parsers.items():
            path = logs / fname
            if not path.exists():
                continue
            for line in path.read_text().splitlines():
                if line.strip():
                    events.append(fn(json.loads(line)))
        self.events = sorted(events, key=lambda e: e.timestamp)

    def add_raw(self, source: str, record: dict[str, Any]) -> Event:
        fn = {"edr": self._norm_edr, "cloudtrail": self._norm_cloudtrail, "idp": self._norm_idp}[source]
        ev = fn(record)
        self.events = sorted([e for e in self.events if e.evidence_id != ev.evidence_id] + [ev],
                             key=lambda e: e.timestamp)
        return ev

    def _entities(self, **kw: list[str | None]) -> dict[str, list[str]]:
        return {k: sorted({v for v in vals if v}) for k, vals in kw.items() if any(vals)}

    def _norm_edr(self, r: dict[str, Any]) -> Event:
        dev = r.get("device", {})
        host = dev.get("hostname")
        user = self.resolve_user(r.get("user"))
        proc = r.get("process") or {}
        et = r["event_type"]
        fields: dict[str, Any] = {}
        dst_ip = None
        src_ip = dev.get("ip")
        users = [user]
        hosts = [host]
        outcome = "success"
        if et == "ProcessCreate":
            cmd = proc.get("command_line", "")
            fields.update(process=proc.get("name"), parent=proc.get("parent_name"), command_line=cmd,
                          sha256=proc.get("sha256"))
            if proc.get("target_process"):
                fields["target_process"] = proc["target_process"]
            decoded = decode_powershell(cmd)
            if decoded:
                fields["decoded_command"] = decoded
            if r.get("email"):
                fields["email_sender"] = r["email"]["sender"]
                fields["email_subject"] = r["email"]["subject"]
            summary = f"{proc.get('parent_name', '?')} spawned {proc.get('name')} on {host}"
        elif et == "NetworkConnect":
            net = r.get("network", {})
            dst_ip = net.get("remote_ip")
            fields.update(process=proc.get("name"), remote_ip=dst_ip, remote_port=net.get("remote_port"),
                          bytes_out=net.get("bytes_out"), bytes_in=net.get("bytes_in"))
            dst_asset = self.asset(dst_ip) if dst_ip else None
            if dst_asset:
                hosts.append(dst_asset["hostname"])
                fields["remote_host"] = dst_asset["hostname"]
            summary = f"{proc.get('name')} on {host} connected to {dst_ip}:{net.get('remote_port')}"
        elif et in ("FileWrite", "FileRead"):
            f = r.get("file", {})
            fields.update(process=proc.get("name"), file_path=f.get("path"), sha256=f.get("sha256"),
                          command_line=proc.get("command_line"))
            verb = "wrote" if et == "FileWrite" else "read"
            summary = f"{proc.get('name')} {verb} {f.get('path')} on {host}"
        elif et == "ScheduledTaskCreate":
            t = r.get("task", {})
            fields.update(process=proc.get("name"), command_line=proc.get("command_line"), task_name=t.get("name"),
                          task_action=t.get("action"), task_trigger=t.get("trigger"),
                          task_description=t.get("description"))
            summary = f"Scheduled task '{t.get('name')}' created on {host} ({t.get('trigger')})"
        elif et == "Logon":
            lg = r.get("logon", {})
            src_ip = lg.get("src_ip")
            outcome = lg.get("outcome")
            fields.update(logon_type=lg.get("logon_type"), account=lg.get("account"), logon_src_ip=src_ip)
            src_asset = self.asset(src_ip) if src_ip else None
            if src_asset:
                hosts.append(src_asset["hostname"])
                fields["logon_src_host"] = src_asset["hostname"]
            kind = {2: "interactive", 3: "network", 10: "RDP"}.get(lg.get("logon_type"), str(lg.get("logon_type")))
            summary = f"{kind} logon by {lg.get('account')} on {host}" + (f" from {src_ip}" if kind == "RDP" else "")
        else:
            summary = f"{et} on {host}"
        ips = [dst_ip] + ([src_ip] if src_ip and src_ip != "127.0.0.1" else [])
        return Event(evidence_id=r["event_id"], source="edr", timestamp=parse_ts(r["timestamp"]), event_type=et,
                     summary=summary, host=host, user=user, src_ip=src_ip, dst_ip=dst_ip, outcome=outcome,
                     fields={k: v for k, v in fields.items() if v is not None},
                     entities=self._entities(hosts=hosts, users=users, ips=ips), raw=r)

    def _norm_cloudtrail(self, r: dict[str, Any]) -> Event:
        ui = r.get("userIdentity", {})
        principal = ui.get("userName")
        role = None
        if ui.get("type") == "AssumedRole":
            parts = ui.get("arn", "").split("/")
            role = parts[1] if len(parts) > 2 else None
            principal = parts[-1]
        user = self.resolve_user(principal)
        req = r.get("requestParameters") or {}
        extra = r.get("additionalEventData") or {}
        if r["eventName"] == "AssumeRole":
            role = req.get("roleArn", "").split("/")[-1] or role
        bucket = req.get("bucketName")
        outcome = "failure" if r.get("errorCode") else "success"
        fields: dict[str, Any] = {
            "event_name": r["eventName"], "event_source": r["eventSource"], "principal": principal,
            "principal_type": ui.get("type"), "access_key_id": ui.get("accessKeyId"), "user_agent": r.get("userAgent"),
            "account_id": r.get("recipientAccountId"), "role": role, "bucket": bucket, "object_key": req.get("key"),
            "request_count": extra.get("aggregatedRequestCount"), "bytes_out": extra.get("bytesTransferredOut"),
            "error_code": r.get("errorCode"), "error_message": r.get("errorMessage"),
        }
        new_key = ((r.get("responseElements") or {}).get("accessKey") or {}).get("accessKeyId")
        if new_key:
            fields["new_access_key_id"] = new_key
        if r["eventName"] == "StopLogging":
            fields["trail"] = req.get("name")
        summary = f"{r['eventName']} by {principal} from {r.get('sourceIPAddress')}"
        if bucket:
            n = extra.get("aggregatedRequestCount") or 1
            mb = (extra.get("bytesTransferredOut") or 0) / 1e6
            summary += f" on s3://{bucket} ({n} request(s), {mb:,.0f} MB)"
        if role and r["eventName"] == "AssumeRole":
            summary += f" into role {role}"
        if outcome == "failure":
            summary += f" [{r.get('errorCode')}]"
        return Event(evidence_id=r["eventID"], source="cloudtrail", timestamp=parse_ts(r["eventTime"]),
                     event_type=r["eventName"], summary=summary, host=None, user=user,
                     src_ip=r.get("sourceIPAddress"), outcome=outcome,
                     fields={k: v for k, v in fields.items() if v is not None},
                     entities=self._entities(users=[user], ips=[r.get("sourceIPAddress")], buckets=[bucket],
                                             roles=[role], cloud_accounts=[r.get("recipientAccountId")]),
                     raw=r)

    def _norm_idp(self, r: dict[str, Any]) -> Event:
        actor = r.get("actor", {})
        user = self.resolve_user(actor.get("alternateId"))
        client = r.get("client", {})
        geo = client.get("geographicalContext", {})
        outcome = r.get("outcome", {})
        fields: dict[str, Any] = {
            "idp_event_type": r["eventType"], "display_message": r.get("displayMessage"),
            "actor_email": actor.get("alternateId"), "actor_name": actor.get("displayName"),
            "city": geo.get("city"), "country": geo.get("country"),
            "user_agent": (client.get("userAgent") or {}).get("rawUserAgent"),
            "is_proxy": (r.get("securityContext") or {}).get("isProxy"),
            "outcome_reason": outcome.get("reason"),
        }
        if r.get("target"):
            fields["target_device"] = r["target"][0].get("displayName")
        loc = f"{geo.get('city')}, {geo.get('country')}"
        summary = f"{r.get('displayMessage')} for {actor.get('alternateId')} from {client.get('ipAddress')} ({loc})"
        if outcome.get("result") == "FAILURE":
            summary += f" - {outcome.get('reason')}"
        return Event(evidence_id=r["uuid"], source="idp", timestamp=parse_ts(r["published"]), event_type=r["eventType"],
                     summary=summary, user=user, src_ip=client.get("ipAddress"),
                     outcome="success" if outcome.get("result") == "SUCCESS" else "failure",
                     fields={k: v for k, v in fields.items() if v is not None},
                     entities=self._entities(users=[user], ips=[client.get("ipAddress")]), raw=r)
