from src.analyze_connections import calculate_risk_scores


def test_failed_alert_score():
    failed_alert_ips = {"192.168.1.10"}
    port_scan_alert_ips = set()
    risk_scores, reasons = calculate_risk_scores(failed_alert_ips, port_scan_alert_ips)
    assert risk_scores["192.168.1.10"] == 40
    assert reasons["192.168.1.10"] == ["Failed connection threshold exceeded"]


def test_port_scan_alert_score():
    failed_alert_ips = set()
    port_scan_alert_ips = {"192.168.1.10"}
    risk_scores, reasons = calculate_risk_scores(failed_alert_ips, port_scan_alert_ips)
    assert risk_scores["192.168.1.10"] == 60
    assert reasons["192.168.1.10"] == ["Port scan threshold exceeded"]


def test_both_alerts_score():
    failed_alert_ips = {"192.168.1.10"}
    port_scan_alert_ips = {"192.168.1.10"}
    risk_scores, reasons = calculate_risk_scores(failed_alert_ips, port_scan_alert_ips)
    assert risk_scores["192.168.1.10"] == 100
    assert reasons["192.168.1.10"] == ["Failed connection threshold exceeded", "Port scan threshold exceeded"]