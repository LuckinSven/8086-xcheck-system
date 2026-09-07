from xcheck.services.threatbook import parse_ip_result, redact_secrets
from xcheck.services.whitelist import classify_whitelist_result


def test_every_whitelist_hit_is_removed():
    assert classify_whitelist_result("active") == "whitelist_removed"
    assert classify_whitelist_result("reference") == "whitelist_removed"
    assert classify_whitelist_result("inactive") == "whitelist_removed"
    assert classify_whitelist_result("not_found") == "whitelist_clear"
    assert classify_whitelist_result("invalid") == "invalid"


def test_threatbook_response_mapping_and_recursive_redaction():
    mapped = parse_ip_result(
        "8.8.8.8",
        {
            "is_malicious": True,
            "confidence_level": "high",
            "severity": "high",
            "judgments": ["Scanner"],
            "basic": {"carrier": "Carrier", "location": {"country": "US", "city": "X"}},
            "asn": {"number": 15169, "info": "GOOGLE"},
        },
    )
    assert mapped["is_malicious"] is True
    assert mapped["judgments"] == ["Scanner"]
    assert mapped["asn_number"] == 15169
    assert redact_secrets({"apikey": "secret", "nested": {"api_key": "other", "ok": 1}}) == {
        "apikey": "***",
        "nested": {"api_key": "***", "ok": 1},
    }
