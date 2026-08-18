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
    for ip in failed_alert_ips:
        risk_scores[ip] = 40
    for ip in port_scan_alert_ips:
        if ip in risk_scores:
            risk_scores[ip] += 60
        else:
            risk_scores[ip] = 60
    return risk_scores



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


risk_scores = calculate_risk_scores(failed_alert_ips, port_scan_alert_ips)

for ip, score in risk_scores.items():
    print("IP:", ip, "Risk score:", score)