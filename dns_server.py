"""
Mini DNS Server (UDP)
---------------------
Listens on a UDP port, reads a DNS query, looks the name up in a small
table (ZONE) and sends back an answer. Unknown names get NXDOMAIN.

Run:            python3 dns_server.py
Run with drops: python3 dns_server.py 2      (drops every 2nd query, to test retries)
"""
import socket
import sys

HOST = "127.0.0.1"
PORT = 5353          # 53 is the real DNS port but needs admin rights, so we use 5353
TTL = 60             # seconds a client may cache an answer

# Our "zone file": name -> IP address (the local department websites)
ZONE = {
    "cse.local": "127.0.0.1",
    "library.local": "127.0.0.1",
    "admin.local": "127.0.0.1",
}

# 0 = never drop packets. N = drop every Nth query (simulates packet loss).
DROP_EVERY = int(sys.argv[1]) if len(sys.argv) > 1 else 0


def parse_question(data):
    """Read the name being asked for. DNS writes a name as length-prefixed labels:
    'cse.local' -> 3 'cse' 5 'local' 0   (0 marks the end)."""
    labels = []
    i = 12                                   # the first 12 bytes are the header
    while data[i] != 0:
        n = data[i]
        labels.append(data[i + 1:i + 1 + n].decode("ascii").lower())
        i += n + 1
    qtype = int.from_bytes(data[i + 1:i + 3], "big")   # 1 means "A" (IPv4 address)
    end = i + 5                              # 0 byte + QTYPE(2) + QCLASS(2)
    return ".".join(labels), qtype, data[12:end]


def build_response(data):
    txid = data[0:2]                         # copy the query ID so the client can match it
    rd = int.from_bytes(data[2:4], "big") & 0x0100   # "recursion desired" copied back
    name, qtype, question = parse_question(data)

    ip = ZONE.get(name)
    rcode = 0 if ip else 3                   # 0 = OK, 3 = NXDOMAIN (name does not exist)
    send_answer = ip is not None and qtype == 1

    # Flags: 0x8000 = this is a response, 0x0400 = authoritative answer, plus rcode
    flags = 0x8000 | 0x0400 | rd | rcode
    header = (
        txid
        + flags.to_bytes(2, "big")
        + (1).to_bytes(2, "big")                          # 1 question
        + (1 if send_answer else 0).to_bytes(2, "big")    # answer count
        + b"\x00\x00\x00\x00"                             # no authority / extra records
    )
    body = question                                       # repeat the question
    if send_answer:
        body += (
            b"\xc0\x0c"                                   # name = pointer back to the question
            + (1).to_bytes(2, "big")                      # TYPE A
            + (1).to_bytes(2, "big")                      # CLASS IN (internet)
            + TTL.to_bytes(4, "big")                      # time to live
            + (4).to_bytes(2, "big")                      # length of the IP data
            + socket.inet_aton(ip)                        # the IP address itself
        )
    return header + body


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # UDP socket
    sock.bind((HOST, PORT))
    print(f"Mini DNS on {HOST}:{PORT} | names={list(ZONE)} | drop_every={DROP_EVERY}")

    count = 0
    while True:
        data, addr = sock.recvfrom(512)      # wait for one UDP packet
        count += 1
        if DROP_EVERY and count % DROP_EVERY == 0:
            print(f"[{count}] dropped query from {addr} (simulated loss)")
            continue
        try:
            name, _, _ = parse_question(data)
            sock.sendto(build_response(data), addr)
            print(f"[{count}] {name} -> {ZONE.get(name, 'NXDOMAIN')}")
        except (IndexError, UnicodeDecodeError) as e:
            print(f"[{count}] bad packet from {addr}: {e}")


if __name__ == "__main__":
    main()
