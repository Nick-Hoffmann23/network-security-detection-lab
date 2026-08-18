counts = {}
ports_by_ip = {}
PORT_SCAN_THRESHOLD = 3

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

        if source_ip in counts:
            counts[source_ip] += 1
        else:
            counts[source_ip] = 1

        if source_ip not in ports_by_ip:
            new_ports = set()
            ports_by_ip[source_ip] = new_ports
        
        ports_by_ip[source_ip].add(destination_port)

        
        
        

for source_ip, count in counts.items():
    print(source_ip, count)


for source_ip, ports in ports_by_ip.items():
    unique_ports = len(ports)

    if unique_ports > PORT_SCAN_THRESHOLD:
        print("Possible port scan alert:", source_ip, unique_ports, ports)

    

