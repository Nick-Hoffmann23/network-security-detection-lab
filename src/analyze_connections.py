counts = {}
ports_by_ip = {}
failed_counts = {}
PORT_SCAN_THRESHOLD = 3
FAILED_CONNECTION_THRESHOLD = 2

with open("conn.log", "r") as f:
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


    for source_ip, count in failed_counts.items():
        if count >= FAILED_CONNECTION_THRESHOLD:
            print("Possible failed connection alert:", source_ip, count)


for source_ip, ports in ports_by_ip.items():
    unique_ports = len(ports)

    if unique_ports > PORT_SCAN_THRESHOLD:
        print("Possible port scan alert:", source_ip, unique_ports, ports)

    

