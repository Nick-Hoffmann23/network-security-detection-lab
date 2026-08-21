def calculate_risk_scores(failed_alert_ips, port_scan_alert_ips, failed_target_alert_ips):
    risk_scores = {}
    reasons = {}

    for ip in failed_alert_ips:
        risk_scores[ip] = 40
        reasons[ip] = ["Failed connection threshold exceeded"]
    for ip in port_scan_alert_ips:
        if ip in risk_scores:
            risk_scores[ip] += 60
            reasons[ip].append("Port scan threshold exceeded")
        else:
            risk_scores[ip] = 60
            reasons[ip] = ["Port scan threshold exceeded"]
    for ip in failed_target_alert_ips:
        if ip in risk_scores:
            risk_scores[ip] += 50
            reasons[ip].append("Repeated failed connections to same target")
        else:
            risk_scores[ip] = 50
            reasons[ip] = ["Repeated failed connections to same target"]
    return risk_scores, reasons


def get_risk_level(score):
    if score >= 100:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"


def should_alert(score, min_alert_level):
    risk_level = get_risk_level(score)

    levels = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }

    return levels[risk_level] >= levels[min_alert_level]


def find_high_risk_ips(failed_alert_ips, port_scan_alert_ips, failed_target_alert_ips):
    all_alert_ips = failed_alert_ips | port_scan_alert_ips | failed_target_alert_ips
    high_risk_ips = set()

    for ip in all_alert_ips:
        alert_count = 0

        if ip in failed_alert_ips:
            alert_count += 1

        if ip in port_scan_alert_ips:
            alert_count += 1

        if ip in failed_target_alert_ips:
            alert_count += 1

        if alert_count >= 2:
            high_risk_ips.add(ip)

    return high_risk_ips
