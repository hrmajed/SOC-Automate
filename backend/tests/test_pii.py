from soc_copilot.pii import PiiMasker


def test_identity_variants_share_one_token(store):
    m = PiiMasker(store.identities)
    text = ("HELIX\\mchen logged in; marcus.chen@helixdyn.example approved MFA; "
            "IAM user m.chen-admin; display name Marcus Chen")
    masked = m.mask_text(text)
    assert "chen" not in masked.lower()
    assert masked.count("[USER_1]") == 4
    assert m.unmask_text("[USER_1]") == "m.chen"


def test_generic_pii_patterns(store):
    m = PiiMasker(store.identities)
    text = ("SSN 078-05-1120 card 4111 1111 1111 1111 phone +1 617-555-0100 key AKIA4HLXMCHEN7QXZ2RT "
            "password=Hunter2Hunter2 contact attacker@evil.example ip 45.137.21.9")
    masked = m.mask_text(text)
    for secret in ("078-05-1120", "4111 1111 1111 1111", "617-555-0100", "AKIA4HLXMCHEN7QXZ2RT", "Hunter2Hunter2",
                   "attacker@evil.example"):
        assert secret not in masked
    assert "45.137.21.9" in masked, "IPs are operational data and stay visible"
    assert "password=[SECRET_1]" in masked


def test_non_luhn_numbers_are_not_cards(store):
    m = PiiMasker(store.identities)
    assert m.mask_text("bytes 1234567890123") == "bytes 1234567890123"


def test_round_trip(store):
    m = PiiMasker(store.identities)
    obj = {"user": "j.alvarez", "path": "C:\\Users\\jalvarez\\Documents\\W2_Alvarez_SSN-078-05-1120.xlsx"}
    masked = m.mask(obj)
    assert "alvarez" not in str(masked).lower()
    assert m.unmask(masked)["user"] == "j.alvarez"
