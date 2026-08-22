import suricatamon


def _alert(action: str):
    return {
        "timestamp": "2026-08-09T21:00:00+0800",
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "src_port": 51515,
        "dest_ip": "198.51.100.20",
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "tls",
        "alert": {
            "action": action,
            "signature": "ET TEST blocked connection",
            "signature_id": 2000001,
            "gid": 1,
            "rev": 2,
        },
    }


def test_allowed_alert_is_not_a_drop():
    event = _alert("allowed")

    assert suricatamon.drop_action(event) is None
    assert suricatamon.format_drop_record(event) is None
    assert "Summary         : [ALERT] [ET] ET TEST blocked connection" in suricatamon.format_trigger_record(event)


def test_blocked_et_alert_creates_plain_drop_record():
    record = suricatamon.format_drop_record(_alert("blocked"))

    assert record is not None
    assert "[DROP] action=blocked" in record
    assert "[ET] ET TEST blocked connection [1:2000001:2]" in record
    assert "src=192.0.2.10:51515" in record
    assert "dst=198.51.100.20:443" in record
    assert "\033" not in record


def test_flow_drop_is_detected_and_appended(tmp_path):
    event = {
        "timestamp": "2026-08-09T21:01:00+0800",
        "event_type": "flow",
        "src_ip": "192.0.2.10",
        "dest_ip": "198.51.100.20",
        "proto": "UDP",
        "flow": {"action": "drop"},
    }
    record = suricatamon.format_trigger_record(
        event,
        domains=["blocked.example"],
        collected_at="2026-08-09T21:01:01+08:00",
    )
    output = tmp_path / "ET Trigger Drop.txt"

    assert record is not None
    assert "Collected at    : 2026-08-09T21:01:01+08:00" in record
    assert "Event time      : 2026-08-09T21:01:00+0800" in record
    assert "Source IP       : 192.0.2.10" in record
    assert "Destination IP  : 198.51.100.20" in record
    assert "DNS / Domain    : blocked.example" in record
    assert suricatamon.append_trigger_record(str(output), record)
    assert output.read_text(encoding="utf-8") == record + "\n"


def test_tor_et_alert_is_preserved_as_hunting_evidence():
    event = _alert("allowed")
    event["alert"]["signature"] = "ET TOR Known Tor Exit Node Traffic group 11"
    event["alert"]["category"] = "Misc Attack"
    event["flow_id"] = 123456789
    event["in_iface"] = "wlan0"

    record = suricatamon.format_trigger_record(event)

    assert record is not None
    assert "Summary         : [ALERT] [ET] ET TOR Known Tor Exit Node Traffic group 11" in record
    assert "Rule ID         : 1:2000001:2" in record
    assert "Category        : Misc Attack" in record
    assert "Action          : allowed" in record
    assert "Flow ID         : 123456789" in record
    assert "Interface       : wlan0" in record


def test_dns_response_enriches_later_alert_by_destination_ip():
    cache = {}
    dns_event = {
        "event_type": "dns",
        "dns": {
            "queries": [{"rrname": "tor-context.example", "rrtype": "A"}],
            "answers": [{"rrname": "tor-context.example", "rdata": "198.51.100.20"}],
        },
    }
    suricatamon.update_domain_cache(dns_event, cache)
    alert = _alert("allowed")

    domains = suricatamon.domain_context(alert, cache)
    record = suricatamon.format_trigger_record(alert, domains)

    assert domains == ["tor-context.example"]
    assert "DNS / Domain    : tor-context.example" in record
