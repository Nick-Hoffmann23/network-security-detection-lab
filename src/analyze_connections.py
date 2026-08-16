counts = {}

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