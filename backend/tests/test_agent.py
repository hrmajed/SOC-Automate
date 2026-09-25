import json

import pytest

from soc_copilot.agent import Investigator
from soc_copilot.llm import MockBackend


@pytest.fixture
def run(store, kb, settings):
    def _run(alert_id, **kw):
        return Investigator(store, kb, MockBackend(), settings, **kw).run(alert_id)
    return _run


def test_phishing_alert_reconstructs_full_attack_path(run):
    r = run("ALR-1001")
    assert r["verdict"] == "true_positive" and r["severity"] == "critical"
    assert [n["label"] for n in r["attack_path"]] == [
        "WKS-FIN-023", "JMP-ADM-01", "Okta (identity provider)", "AWS helix-prod", "s3://helix-clinical-trials-phi"]
    techniques = {t["id"] for t in r["attack_mapping"]}
    assert {"T1566.001", "T1059.001", "T1053.005", "T1003.001", "T1021.001", "T1552.001", "T1621", "T1098.005",
            "T1530", "T1562.008", "T1098.001", "AML.T0051"} <= techniques
    assert set(r["metrics"]["sources"]) == {"edr", "cloudtrail", "idp"}
    for t in r["attack_mapping"]:
        assert t["evidence_ids"] and all(e in r["evidence"] for e in t["evidence_ids"])
    assert {"ALR-1002", "ALR-1003", "ALR-1005"} <= set(r["related_alerts"])


def test_environment_context_explains_why(run):
    r = run("ALR-1001")
    docs = {e["doc_id"] for e in r["environment_context"]}
    assert {"COMP-GDPR-33", "INC-2026-0033", "SEC-POL-07"} <= docs
    assert "INC-2025-0147" not in docs, "unrelated past incidents must not be offered as context"
    assert any("DPO" in a["action"] for a in r["recommended_actions"])
    assert all(a["requires_approval"] for a in r["recommended_actions"])


def test_known_false_positive_is_marked_benign_with_reason(run):
    r = run("ALR-1004")
    assert r["verdict"] == "likely_benign" and r["severity"] == "low"
    assert "INC-2025-0147" in r["narrative"]
    assert r["attack_path"] == []


def test_injection_is_redacted_but_kept_as_evidence(run):
    r = run("ALR-1001")
    inj = [f for f in r["guardrails"]["findings"] if f["kind"] == "prompt_injection"]
    assert len(inj) == 1 and inj[0]["location"].startswith("edr-7f09")
    transcript = json.dumps(r["llm"]["transcript"])
    assert "Ignore previous instructions" not in transcript
    assert "RT-2291" not in transcript
    entry = next(t for t in r["timeline"] if t["evidence_id"] == "edr-7f09")
    assert entry["injection"] and any(t["id"] == "AML.T0051" for t in entry["techniques"])


def test_llm_never_sees_raw_pii(run):
    r = run("ALR-1001")
    transcript = json.dumps(r["llm"]["transcript"])
    for secret in ("j.alvarez", "jalvarez", "m.chen", "marcus.chen@helixdyn.example", "Julia Alvarez",
                   "078-05-1120", "AKIA4HLXMCHEN7QXZ2RT", "617-555-0199"):
        assert secret not in transcript, secret
    assert "[USER_1]" in transcript
    assert r["pii"]["unique_values_masked"] >= 5
    assert "j.alvarez" in r["narrative"], "analyst-facing output is unmasked"


def test_every_citation_in_narrative_exists(run):
    import re
    r = run("ALR-1001")
    known = set(r["evidence"]) | {e["doc_id"] for e in r["environment_context"]}
    for ref in re.findall(r"\[([a-z]+-[0-9a-f]{4})\]", r["narrative"]):
        assert ref in known


def test_stream_events(store, kb, settings):
    events = list(Investigator(store, kb, MockBackend(), settings).run_iter("ALR-1003"))
    types = [e["type"] for e in events]
    assert types[0] == "phase" and types[-1] == "report"
    assert "tool_call" in types and "tool_result" in types
