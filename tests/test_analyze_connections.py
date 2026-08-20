from src.analyze_connections import calculate_risk_scores, get_risk_level, parse_conn_log, should_alert, load_config




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


def test_low_risk_level():
    assert get_risk_level(0) == "Low"

def test_medium_risk_level():
    assert get_risk_level(40) == "Medium"

def test_high_risk_level():
    assert get_risk_level(60) == "High"

def test_critical_risk_level():
    assert get_risk_level(100) == "Critical"


def test_parse_conn_log():
    counts, ports_by_ip, failed_counts = parse_conn_log("tests/sample_conn.log")

    assert counts["192.168.1.194"] == 1
    assert counts["192.168.1.196"] == 1
    assert ports_by_ip["192.168.1.194"] == {"5353"}
    assert ports_by_ip["192.168.1.196"] == {"5353"}
    assert failed_counts["192.168.1.194"] == 1
    assert failed_counts["192.168.1.196"] == 1


def test_should_alert_low():
    assert should_alert(0, "High") == False

def test_should_alert_medium():
    assert should_alert(40, "High") == False

def test_should_alert_high():
    assert should_alert(60, "High") == True

def test_should_alert_critical():
    assert should_alert(100, "High") == True


def test_load_config():
    config = load_config()
    assert config["FAILED_CONNECTION_THRESHOLD"] == 2
    assert config["PORT_SCAN_THRESHOLD"] == 10
    assert config["MIN_ALERT_LEVEL"] == "Critical"


def test_should_alert_between_levels():
    assert should_alert(79, "High") == True
    assert should_alert(79, "Critical") == False