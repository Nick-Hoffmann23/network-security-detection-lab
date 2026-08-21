import sys 
import os

from src.config import load_config

from src.reporting import save_analysis_summary, print_analysis_summary, print_security_report, save_csv_report, save_security_report

from src.detectors import get_risk_level, find_high_risk_ips, calculate_risk_scores, should_alert


def parse_conn_log(file_path):
    counts = {}
    ports_by_ip = {}
    failed_counts = {}
    failed_by_target = {}


    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue

            fields = line.split("\t")

            if len(fields) < 12:
                continue

            ts = fields[0]
            uid = fields[1]
            source_ip = fields[2]
            source_port = fields[3]
            destination_ip = fields[4]
            try:
                destination_port = int(fields[5])
            except ValueError:
                continue 

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

                target_pair = (source_ip, destination_ip)
                if target_pair in failed_by_target:
                    failed_by_target[target_pair] += 1
                else:
                    failed_by_target[target_pair] = 1

    return counts, ports_by_ip, failed_counts, failed_by_target



def main():
    if len(sys.argv) < 2:
        print("Usage: src/analyze_connections.py <log_file>>")
        return
    
    file_path = sys.argv[1] 
    if not os.path.isfile(file_path):
        print("Error: File not found:", file_path)
        return

    config = load_config()
    FAILED_CONNECTION_THRESHOLD = config["FAILED_CONNECTION_THRESHOLD"]
    PORT_SCAN_THRESHOLD = config["PORT_SCAN_THRESHOLD"]
    MIN_ALERT_LEVEL = config["MIN_ALERT_LEVEL"]
    FAILED_TARGET_THRESHOLD = config["FAILED_TARGET_THRESHOLD"]


    
    counts, ports_by_ip, failed_counts, failed_by_target = parse_conn_log(file_path)


    failed_alert_ips = set()
    port_scan_alert_ips = set()
    failed_target_alert_ips = set()


    for source_ip, count in failed_counts.items():
        if count >= FAILED_CONNECTION_THRESHOLD:
            print("Possible failed connection alert:", source_ip, count)
            failed_alert_ips.add(source_ip)

    
    for source_ip, ports in ports_by_ip.items():
        unique_ports = len(ports)

        if unique_ports > PORT_SCAN_THRESHOLD:
            print("Possible port scan alert:", source_ip, unique_ports, ports)
            port_scan_alert_ips.add(source_ip)


    for target_pair, count in failed_by_target.items():
        source_ip, destination_ip, = target_pair

        if count >= FAILED_TARGET_THRESHOLD:
            print(
                "Repeated failed target alert", 
                source_ip,
                destination_ip,
                count
            )
            failed_target_alert_ips.add(source_ip)

    high_risk_ips = find_high_risk_ips(failed_alert_ips, port_scan_alert_ips, failed_target_alert_ips)


    for source_ip in high_risk_ips:
        print("High risk IP detected:", source_ip)

    risk_scores, reasons = calculate_risk_scores(failed_alert_ips, port_scan_alert_ips, failed_target_alert_ips)

    for ip, score in risk_scores.items():
        if should_alert(score, MIN_ALERT_LEVEL):
            print_security_report(ip, score, reasons[ip])
            save_security_report(ip, score, reasons[ip])
            save_csv_report(ip, score, reasons[ip])



    print_analysis_summary(counts, failed_alert_ips, port_scan_alert_ips, failed_target_alert_ips, high_risk_ips)
    save_analysis_summary(counts, failed_alert_ips, port_scan_alert_ips, failed_target_alert_ips, high_risk_ips)


if __name__ == "__main__":
    main()


    