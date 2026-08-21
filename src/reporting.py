import csv
from datetime import datetime
import os



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

    with open("reports/security_report.txt", "a") as report_file:
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

    file_exists = os.path.isfile("reports/security_report.csv")

    with open("reports/security_report.csv", "a", newline="") as csvfile:
        writer = csv.writer(csvfile)

        if not file_exists:
            writer.writerow(["Timestamp", "IP Address", "Risk Score", "Risk Level", "Reasons"])

        writer.writerow([formatted_time, ip, score, risk_level, "; ".join(reasons)])


def save_analysis_summary(counts, failed_alert_ips, port_scan_alert_ips, failed_target_alert_ips, high_risk_ips):
    timestamp = datetime.now()
    formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")

    with open("reports/analysis_summary.txt", "a") as summary_file:
        summary_file.write("Timestamp: " + formatted_time + "\n")
        summary_file.write("Total unique source IPs: " + str(len(counts)) + "\n")
        summary_file.write("IPs exceeding failed connection threshold: " + str(len(failed_alert_ips)) + "\n")
        summary_file.write("IPs exceeding port scan threshold: " + str(len(port_scan_alert_ips)) + "\n")
        summary_file.write("High risk IPs (2+ alert types): " + str(len(high_risk_ips)) + "\n")
        summary_file.write(f"IPs exceeding repeated target threshold: {len(failed_target_alert_ips)}\n")
        summary_file.write("\n")


def print_analysis_summary(counts, failed_alert_ips, port_scan_alert_ips, failed_target_alert_ips, high_risk_ips):
    print("\nAnalysis Summary:")
    print("Total unique source IPs:", len(counts))
    print("IPs exceeding failed connection threshold:", len(failed_alert_ips))
    print("IPs exceeding port scan threshold:", len(port_scan_alert_ips))
    print("High risk IPs (2+ alert types):", len(high_risk_ips))
    print("IPs exceeding repeated target threshold: ", len(failed_target_alert_ips))
    print()