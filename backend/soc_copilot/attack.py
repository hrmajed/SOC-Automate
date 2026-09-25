"""MITRE ATT&CK (and ATLAS) mapping of normalised evidence.

Mapping is deterministic so a fooled model can describe evidence but never invent techniques or events.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .store import DataStore, Event, is_internal_ip

TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access"},
    "T1204.002": {"name": "User Execution: Malicious File", "tactic": "Execution"},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
    "T1053.005": {"name": "Scheduled Task/Job: Scheduled Task", "tactic": "Persistence"},
    "T1036.004": {"name": "Masquerading: Masquerade Task or Service", "tactic": "Defense Evasion"},
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "tactic": "Credential Access"},
    "T1021.001": {"name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "T1078.002": {"name": "Valid Accounts: Domain Accounts", "tactic": "Privilege Escalation"},
    "T1552.001": {"name": "Unsecured Credentials: Credentials In Files", "tactic": "Credential Access"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1621": {"name": "Multi-Factor Authentication Request Generation", "tactic": "Credential Access"},
    "T1078.004": {"name": "Valid Accounts: Cloud Accounts", "tactic": "Initial Access"},
    "T1090.003": {"name": "Proxy: Multi-hop Proxy", "tactic": "Command and Control"},
    "T1098.005": {"name": "Account Manipulation: Device Registration", "tactic": "Persistence"},
    "T1033": {"name": "System Owner/User Discovery", "tactic": "Discovery"},
    "T1619": {"name": "Cloud Storage Object Discovery", "tactic": "Discovery"},
    "T1530": {"name": "Data from Cloud Storage", "tactic": "Collection"},
    "T1562.008": {"name": "Impair Defenses: Disable or Modify Cloud Logs", "tactic": "Defense Evasion"},
    "T1098.001": {"name": "Account Manipulation: Additional Cloud Credentials", "tactic": "Persistence"},
    "AML.T0051": {"name": "LLM Prompt Injection (MITRE ATLAS)", "tactic": "Defense Evasion"},
}

HIGH_IMPACT = {"T1003.001", "T1552.001", "T1041", "T1530", "T1562.008", "T1098.001", "T1098.005", "AML.T0051"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}


@dataclass
class Mapping:
    techniques: list[str] = field(default_factory=list)
    score: int = 0
    phrase: str = ""
    notes: list[str] = field(default_factory=list)


def _lower(v: Any) -> str:
    return str(v or "").lower()


def map_event(ev: Event, store: DataStore) -> Mapping:
    f = ev.fields
    m = Mapping()
    who = ev.user or "unknown user"
    cite = f"[{ev.evidence_id}]"
    if ev.source == "edr":
        proc, parent, cmd = _lower(f.get("process")), _lower(f.get("parent")), _lower(f.get("command_line"))
        if ev.event_type == "ProcessCreate":
            if parent == "outlook.exe" and proc in OFFICE and any(x in cmd for x in (".docm", ".xlsm", ".dotm")):
                m.techniques += ["T1566.001", "T1204.002"]
                m.score += 3
                subj = f.get("email_subject")
                m.phrase = (f"the user {who} opened the macro-enabled attachment "
                            f"'{cmd.rsplit(chr(92), 1)[-1].strip(chr(34))}' from Outlook"
                            + (f" (email '{subj}' from {f.get('email_sender')})" if subj else "") + f" {cite}")
            elif proc == "powershell.exe":
                m.techniques.append("T1059.001")
                decoded = _lower(f.get("decoded_command"))
                if f.get("decoded_command"):
                    m.techniques.append("T1027")
                if parent in OFFICE:
                    m.techniques.append("T1204.002")
                    m.score += 4
                    m.phrase = f"{parent.upper()} spawned hidden, base64-encoded PowerShell {cite}"
                if any(x in decoded for x in ("downloadstring", "iex", "invoke-expression", "http")):
                    m.techniques.append("T1105")
                    m.score += 3
                    m.phrase = (m.phrase or f"Encoded PowerShell ran on {ev.host} {cite}") + \
                        f" whose decoded payload downloads and executes a script ({f.get('decoded_command')})"
                if "invoke-webrequest" in cmd and "post" in cmd and "-infile" in cmd:
                    m.techniques.append("T1041")
                    m.score += 4
                    if ".aws" in cmd:
                        m.techniques.append("T1552.001")
                    m.phrase = f"the credentials file was uploaded by HTTP POST to the C2 server from {ev.host} {cite}"
                if not m.phrase:
                    m.score += 1
                    m.phrase = f"{parent or 'a process'} ran encoded PowerShell as {who} on {ev.host} {cite}"
            elif proc == "rundll32.exe" and ("minidump" in cmd or _lower(f.get("target_process")) == "lsass.exe"):
                m.techniques.append("T1003.001")
                m.score += 5
                m.phrase = f"LSASS memory was dumped with comsvcs.dll MiniDump on {ev.host}, exposing cached credentials {cite}"
        elif ev.event_type == "NetworkConnect":
            rip = f.get("remote_ip")
            ti = store.ti_lookup(rip) if rip else None
            if ti and ti["verdict"] == "malicious":
                m.techniques.append("T1071.001")
                m.score += 4
                m.phrase = (f"{f.get('process')} on {ev.host} contacted {rip}:{f.get('remote_port')}, a known "
                            f"{'/'.join(ti['labels'])} server per local threat intel {cite}")
                if (f.get("bytes_in") or 0) > 10000:
                    m.techniques.append("T1105")
            elif f.get("remote_port") == 3389 and is_internal_ip(rip):
                m.techniques.append("T1021.001")
                m.score += 2
                src_seg, dst_seg = store.segment_for_ip(ev.src_ip or ""), store.segment_for_ip(rip or "")
                if src_seg and dst_seg and src_seg["name"] == "Finance VLAN" and dst_seg["name"] == "Management":
                    m.score += 2
                    m.notes.append("Finance VLAN -> Management RDP violates SEC-POL-07")
                m.phrase = (f"{ev.host} opened an RDP session to {f.get('remote_host', rip)} "
                            f"({dst_seg['name'] if dst_seg else 'internal'}) {cite}")
        elif ev.event_type == "FileWrite":
            path = _lower(f.get("file_path"))
            if path.endswith(".exe") and "appdata" in path:
                m.techniques.append("T1105")
                m.score += 2
                if store.ti_lookup(f.get("sha256", "")):
                    m.score += 2
                m.phrase = f"a second-stage executable was dropped at {f.get('file_path')} {cite}"
        elif ev.event_type == "FileRead":
            if ".aws" in _lower(f.get("file_path")) or "credentials" in _lower(f.get("file_path")):
                m.techniques.append("T1552.001")
                m.score += 4
                m.phrase = f"the plaintext AWS credentials file {f.get('file_path')} was read on {ev.host} {cite}"
        elif ev.event_type == "ScheduledTaskCreate":
            m.techniques += ["T1053.005", "T1036.004"]
            m.score += 3
            m.phrase = (f"persistence was set via scheduled task '{f.get('task_name')}' running "
                        f"{f.get('task_action')} at {f.get('task_trigger')} {cite}")
        elif ev.event_type == "Logon" and f.get("logon_type") == 10:
            m.techniques += ["T1021.001", "T1078.002"]
            m.score += 2
            ident = store.identity(ev.user or "")
            if ident and ident.get("privileged") and f.get("logon_src_ip") != "10.10.1.2":
                m.score += 2
                m.notes.append("privileged logon to Management from a non-PAM source")
            m.phrase = (f"the privileged account {who} logged on to {ev.host} over RDP from "
                        f"{f.get('logon_src_host', f.get('logon_src_ip'))} (not the PAM gateway) {cite}")
    elif ev.source == "cloudtrail":
        name = ev.event_type
        src = ev.src_ip or ""
        corp = bool(store.segment_for_ip(src))
        ti = store.ti_lookup(src)
        offnet = not corp
        if name == "GetCallerIdentity" and offnet:
            m.techniques.append("T1033")
            m.score += 2
            m.phrase = f"the stolen key for {f.get('principal')} was first tested with GetCallerIdentity from {src} {cite}"
        elif name == "ListBuckets" and offnet:
            m.techniques.append("T1619")
            m.score += 2
            m.phrase = f"S3 buckets were enumerated (ListBuckets) {cite}"
        elif name == "AssumeRole" and offnet:
            m.techniques.append("T1078.004")
            m.score += 3
            m.phrase = f"the attacker assumed role {f.get('role')} to reach trial data {cite}"
        elif name == "GetObject" and ((f.get("request_count") or 1) > 100 or (f.get("bytes_out") or 0) > 1e9):
            m.techniques.append("T1530")
            m.score += 6
            m.phrase = (f"{f.get('request_count')} objects (~{(f.get('bytes_out') or 0) / 1e9:.1f} GB) were downloaded "
                        f"from s3://{f.get('bucket')} {cite}")
        elif name == "GetObject" and offnet:
            m.techniques.append("T1530")
            m.score += 3
            m.phrase = f"s3://{f.get('bucket')}/{f.get('object_key')} was downloaded {cite}"
        elif name == "StopLogging":
            m.techniques.append("T1562.008")
            m.score += 4
            m.phrase = (f"an attempt to stop CloudTrail logging on {f.get('trail')} was "
                        f"{'blocked by SCP' if ev.outcome == 'failure' else 'successful'} {cite}")
        elif name == "CreateAccessKey":
            m.techniques.append("T1098.001")
            m.score += 4
            m.phrase = f"a new access key was created for {f.get('principal')} as a persistence backdoor {cite}"
        if offnet and m.techniques and "T1078.004" not in m.techniques:
            m.techniques.append("T1078.004")
        if ti and m.techniques:
            m.techniques.append("T1090.003")
            m.score += 1
    elif ev.source == "idp":
        proxy = bool(f.get("is_proxy")) or bool(store.ti_lookup(ev.src_ip or ""))
        et = ev.event_type
        if et == "system.push.send_factor_verify_push" and ev.outcome == "failure":
            m.techniques.append("T1621")
            m.score += 2
            m.phrase = f"an MFA push for {who} was rejected ({f.get('city')}, {f.get('country')}) {cite}"
        elif et == "user.session.start" and proxy:
            m.techniques += ["T1078.004", "T1090.003"]
            m.score += 3
            m.phrase = (f"{who} signed in to Okta from {ev.src_ip} ({f.get('city')}, {f.get('country')}), an "
                        f"anonymizing proxy, after MFA fatigue {cite}")
        elif et == "user.mfa.factor.activate" and proxy:
            m.techniques.append("T1098.005")
            m.score += 4
            m.phrase = f"a new MFA device '{f.get('target_device')}' was enrolled for {who} from {ev.src_ip} {cite}"
    m.techniques = list(dict.fromkeys(m.techniques))
    return m


def technique_info(tid: str) -> dict[str, str]:
    t = TECHNIQUES.get(tid, {"name": tid, "tactic": "Unknown"})
    base = tid.split(".")[0]
    url = (f"https://atlas.mitre.org/techniques/{tid}" if tid.startswith("AML")
           else f"https://attack.mitre.org/techniques/{base}/" + (f"{tid.split('.')[1]}/" if "." in tid else ""))
    return {"id": tid, "name": t["name"], "tactic": t["tactic"], "url": url}
