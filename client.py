"""
Mini DNS Client
---------------
1. Checks its own cache first.
2. If not cached, sends a DNS query over UDP to the Mini DNS server.
3. If no reply arrives in time, it retries (up to RETRIES times).
4. Caches the IP for the TTL the server gave.
5. Opens the website at that IP over HTTP (TCP).

Run: python3 client.py cse.local library.local nosuch.local
"""
import random
import socket
import sys
import time
import urllib.request

DNS_SERVER = ("127.0.0.1", 5353)
WEB_PORT = 8080
TIMEOUT = 1.0        # seconds to wait for a reply before retrying
RETRIES = 3

cache = {}           # name -> (ip, time when the cache entry expires)
stats = {"queries": 0, "cache_hits": 0, "timeouts": 0, "lookup_ms": []}


def build_query(name):
    """Make a DNS query packet: header + question (name, type A, class IN)."""
    txid = random.randint(0, 65535)                       # random ID to match replies
    header = (
        txid.to_bytes(2, "big")
        + (0x0100).to_bytes(2, "big")                     # flags: recursion desired
        + (1).to_bytes(2, "big")                          # 1 question
        + b"\x00" * 6                                     # no other records
    )
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return txid, header + qname + (1).to_bytes(2, "big") + (1).to_bytes(2, "big")


def parse_answer(data, txid):
    """Return (ip, ttl, status) from a DNS reply."""
    if int.from_bytes(data[0:2], "big") != txid:
        raise ValueError("reply ID does not match query")
    rcode = int.from_bytes(data[2:4], "big") & 0x000F
    ancount = int.from_bytes(data[6:8], "big")
    if rcode == 3:
        return None, 0, "NXDOMAIN (name does not exist)"
    if ancount == 0:
        return None, 0, "no answer"

    i = 12                                               # skip the question section
    while data[i] != 0:
        i += data[i] + 1
    a = i + 5                                            # start of the answer record
    ttl = int.from_bytes(data[a + 6:a + 10], "big")
    rdata = data[a + 12:a + 16]                          # the 4 IP bytes
    return socket.inet_ntoa(rdata), ttl, "OK"


def resolve(name):
    """Return (ip, source) where source says whether it came from cache or the server."""
    now = time.time()
    if name in cache and cache[name][1] > now:
        stats["cache_hits"] += 1
        return cache[name][0], "cache"

    txid, packet = build_query(name)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # UDP socket
    sock.settimeout(TIMEOUT)
    start = time.time()
    try:
        for attempt in range(1, RETRIES + 1):
            stats["queries"] += 1
            sock.sendto(packet, DNS_SERVER)
            try:
                data, _ = sock.recvfrom(512)
            except socket.timeout:
                stats["timeouts"] += 1
                print(f"    no reply (attempt {attempt}), retrying...")
                continue
            ip, ttl, status = parse_answer(data, txid)
            stats["lookup_ms"].append((time.time() - start) * 1000)
            if ip is None:
                raise LookupError(status)
            cache[name] = (ip, now + ttl)
            return ip, "server"
        raise TimeoutError("DNS server did not answer")
    finally:
        sock.close()


def fetch_page(ip):
    """Open the website over HTTP (TCP) at the IP we just found."""
    url = f"http://{ip}:{WEB_PORT}/"
    with urllib.request.urlopen(url, timeout=3) as r:
        return r.status, len(r.read())


def main():
    names = sys.argv[1:] or ["cse.local"]
    for name in names:
        print(f"\nLooking up {name}")
        try:
            ip, source = resolve(name)
            print(f"    {name} -> {ip}  (from {source})")
            status, size = fetch_page(ip)
            print(f"    HTTP {status}, page size {size} bytes")
        except LookupError as e:
            print(f"    lookup failed: {e}")
        except TimeoutError as e:
            print(f"    lookup failed: {e}")
        except OSError as e:
            print(f"    could not open website: {e}")

    print("\n--- Stats ---")
    print(f"DNS queries sent : {stats['queries']}")
    print(f"Timeouts         : {stats['timeouts']}")
    print(f"Cache hits       : {stats['cache_hits']}")
    if stats["lookup_ms"]:
        avg = sum(stats["lookup_ms"]) / len(stats["lookup_ms"])
        print(f"Avg lookup time  : {avg:.2f} ms (server replies only)")


if __name__ == "__main__":
    main()
