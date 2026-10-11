# Mini DNS Server with Local Website Hosting

Needs only Python 3. No extra libraries.

## Run (3 terminals)

Terminal 1, DNS server (normal):
    python3 dns_server.py

Terminal 1, DNS server (simulate packet loss, drops every 2nd query):
    python3 dns_server.py 2

Terminal 2, website:
    python3 -m http.server 8080 --directory site

Terminal 3, client:
    python3 client.py cse.local library.local nosuch.local

## Test cases
1. Normal: cse.local resolves and the page loads (HTTP 200).
2. Cache: the second lookup of cse.local comes from cache, not the server.
3. Loss: with `dns_server.py 2`, the client retries after a timeout and still succeeds.
4. Unknown name: nosuch.local returns NXDOMAIN.
5. Server down: stop the DNS server and run the client; it reports "DNS server did not answer" after 3 tries.

## Wireshark
- Filter `udp.port == 5353` to see the DNS query and reply.
- Filter `tcp.port == 8080` to see the TCP handshake and the HTTP GET.
