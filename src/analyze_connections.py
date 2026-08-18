from datetime import datetime 
import csv
import os



PORT_SCAN_THRESHOLD = 3
FAILED_CONNECTION_THRESHOLD = 2
failed_alert_ips = set()
port_scan_alert_ips = set()



def parse_conn_log(file_path):
    counts = {}
    ports_by_ip = {}
    failed_counts = {}

    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue

            fields = line.split("\t")
            ts = fields[0]
            uid = fields[1]
            source_ip = fields[2]
            source_port = fields[3]
            destination_ip = fields[4]
            destination_port = fields[5]
            conn_state = fields[11]

            if source_ip in counts:
                counts[source_ip] += 1
            else:
                counts[source_ip] = 1

            if source_ip not in ports_by_ip:
                new_ports = set()
                ports_by_ip[source_ip] = new_ports
        
            ports_by_ip[source_ip].add(destination_port)

            if conn_state == "S0":
                if source_ip in failed_counts:
                    failed_counts[source_ip] += 1
                else:
                    failed_counts[source_ip] = 1
    return counts, ports_by_ip, failed_counts
counts, ports_by_ip, failed_counts = parse_conn_log("conn.log")


def calculate_risk_scores(failed_alert_ips, port_scan_alert_ips):
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
    return risk_scores, reasons



for source_ip, count in failed_counts.items():
    if count >= FAILED_CONNECTION_THRESHOLD:
        print("Possible failed connection alert:", source_ip, count)
        failed_alert_ips.add(source_ip)


for source_ip, ports in ports_by_ip.items():
    unique_ports = len(ports)

    if unique_ports > PORT_SCAN_THRESHOLD:
        print("Possible port scan alert:", source_ip, unique_ports, ports)
        port_scan_alert_ips.add(source_ip)


high_risk_ips = failed_alert_ips.intersection(port_scan_alert_ips)

for source_ip in high_risk_ips:
    print("High risk IP detected:", source_ip)


def get_risk_level(score):
    if score >= 100:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"


def print_security_report(ip, score, reasons):
    risk_level = get_risk_level(score)
    print("Security Report for IP:", ip)
    print("Risk Score:", score)
    print("Risk Level:", risk_level)
    print("Reasons:")
    for reason in reasons:
        print("-", reason)
    print()


def save_security_report(ip, score, reasons):
    timestamp = datetime.now()
    formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")

    with open("security_report.txt", "a") as report_file:
        risk_level = get_risk_level(score)
        report_file.write("Timestamp: " + formatted_time + "\n")
        report_file.write("Security Report for IP:" + ip + "\n")
        report_file.write("Risk Score::" + str(score) + "\n")
        report_file.write("Risk Level:" + risk_level + "\n")
        report_file.write("Reasons: \n")
        for reason in reasons:
            report_file.write("-" + reason + "\n")

        report_file.write("\n")


def save_csv_report(ip, score, reasons):
    risk_level = get_risk_level(score)
    timestamp = datetime.now()
    formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")

    file_exists = os.path.isfile("security_report.csv")

    with open("security_report.csv", "a", newline="") as csvfile:
        writer = csv.writer(csvfile)

        if not file_exists:
            writer.writerow(["Timestamp", "IP Address", "Risk Score", "Risk Level", "Reasons"])

        writer.writerow([formatted_time, ip, score, risk_level, "; ".join(reasons)])


risk_scores, reasons = calculate_risk_scores(failed_alert_ips, port_scan_alert_ips)


def print_analysis_summary(counts, failed_alert_ips, port_scan_alert_ips, high_risk_ips):
    print("\nAnalysis Summary:")
    print("Total unique source IPs:", len(counts))
    print("IPs exceeding failed connection threshold:", len(failed_alert_ips))
    print("IPs exceeding port scan threshold:", len(port_scan_alert_ips))
    print("High risk IPs (both thresholds exceeded):", len(high_risk_ips))
    print()


for ip, score in risk_scores.items():
    print_security_report(ip, score, reasons[ip])
    save_security_report(ip, score, reasons[ip])
    save_csv_report(ip, score, reasons[ip])
    print_analysis_summary(counts, failed_alert_ips, port_scan_alert_ips, high_risk_ips)
