# Cyber Security Internship: Task 1
## Basic Network Sniffer

**Program:** CodeAlpha Cyber Security Internship
**Task:** 1: Basic Network Sniffer (packet capture and analysis)
**Author:** Muhammad Rizik Sudrajat
**Date:** 1 November 2026
**Environment:** Windows 11, Python 3.11, Scapy, Npcap
**Engagement Type:** Passive traffic capture on my own network

---

## 1. Disclaimer

This tool was tested only on my own computer and home network. No third-party systems or private data were targeted. Packet sniffing must only be used on networks you own or have written permission to monitor.

## 2. Summary

This project is a command-line network sniffer written in Python with Scapy. It captures live packets, decodes each protocol layer, and prints the source and destination addresses, protocol, ports, and a payload preview. When the capture ends it prints a summary of the captured protocols.

In a 50-packet test, the sniffer captured DNS queries and encrypted QUIC (HTTP/3) traffic, showing how a normal browsing session looks on the wire and why HTTPS payloads cannot be read.

## 3. Scope and Methodology

| Item | Detail |
|---|---|
| Language | Python 3.11 |
| Library | Scapy |
| Capture driver | Npcap (Windows) |
| Privileges | Terminal run as Administrator |
| Approach | Capture, decode per layer, display, summarize |

**Features**

- Live capture on any network interface
- Decodes IPv4 / IPv6, TCP (with flags), UDP, ICMP, and DNS queries
- Maps well-known ports to service names (HTTP, HTTPS, DNS, SSH, ...)
- Payload preview (first 60 bytes, printable characters only)
- BPF filters, packet count limit, and optional `.pcap` export
- Protocol statistics at the end

## 4. Setup and Usage

```bash
pip install scapy
```

```bash
py sniffer.py [-i IFACE] [-c COUNT] [-f FILTER] [-o OUTPUT.pcap]
```

| Option | Description |
|---|---|
| `-i`, `--iface` | Network interface (default: Scapy's default) |
| `-c`, `--count` | Number of packets to capture (`0` = until Ctrl+C) |
| `-f`, `--filter` | BPF filter expression |
| `-o`, `--output` | Save captured packets to a `.pcap` file |

**Examples**

```bash
py sniffer.py -c 50                      # capture 50 packets
py sniffer.py -c 20 -f "icmp"            # only ping traffic
py sniffer.py -c 20 -f "tcp port 80"     # only HTTP
py sniffer.py -c 100 -o capture.pcap     # save to a pcap file
```

On Linux or macOS, use `sudo python3 sniffer.py ...` with the same options.

## 5. Results and Analysis

### 5.1 Test 1: General traffic capture (50 packets)

```bash
py sniffer.py -c 50
```

```text
[19:12:28] UDP   192.168.43.209:59369 -> 192.168.43.47:DNS DNS query: clients4.google.com.  len=79
[19:12:28] UDP   192.168.43.209:62632 -> 142.250.4.138:HTTPS  len=1292
           payload: ......,..0.<.b.@F......C.?rqu...$.5.07.?.......3?....D.ga&..
[19:12:32] UDP   192.168.43.209:62776 -> 192.168.43.47:DNS DNS query: www.linkedin.com.  len=76

==================================================
RINGKASAN CAPTURE
==================================================
Total paket: 50
  UDP                50
```

![General capture](screenshots/dns_udp_capture.png)

**Observations**

- **DNS (UDP/53):** the laptop asks the DNS server to resolve a domain name before connecting.
- **HTTPS over UDP (port 443):** the browser uses **QUIC / HTTP/3**, which runs over UDP. The payload looks random because it is encrypted.
- All 50 captured packets were UDP in this run, which is typical for a browser using QUIC.

### 5.2 Test 2: ICMP (ping) capture

```bash
py sniffer.py -c 20 -f "icmp"
```

![ICMP capture](screenshots/icmp_capture.png)

ICMP type 8 is an echo request and type 0 is an echo reply. This matches the `ping` output shown in the screenshot.

### 5.3 Test 3: TCP / HTTP capture

```bash
py sniffer.py -c 20 -f "tcp port 80" -o capture.pcap
```

![TCP capture](screenshots/tcp_http_capture.png)

Plain HTTP is not encrypted, so readable text such as request lines can appear in the payload. TCP flags (SYN, ACK, PSH) show the connection setup and data transfer.

## 6. How It Works

1. `sniff()` from Scapy captures raw frames and calls `handle_packet()` for each one.
2. The handler checks the network layer (IPv4 or IPv6) and extracts the source and destination.
3. It inspects the transport layer: **TCP** (ports and flags), **UDP** (ports and DNS query names), or **ICMP** (message type).
4. If a raw payload exists, a printable preview is shown (non-printable bytes become `.`).
5. Counters track each protocol and are printed as a summary when the capture stops.

## 7. Key Takeaways

- Without encryption, anyone on the same network path can read the traffic. This is why HTTPS matters.
- Even with HTTPS, metadata such as IP addresses, ports, packet sizes, and DNS queries is still visible.
- Filters (BPF) make it easy to focus on one protocol instead of reading everything.

## 8. Limitations and Improvements

- The port-to-service mapping is a small static list.
- DNS responses are also labeled "DNS query" because the query section is repeated in replies.
- Possible extensions: separate DNS request and response, ARP decoding, per-IP traffic statistics, a live dashboard, and alerts for suspicious patterns.

## 9. Conclusion

The sniffer successfully captures and decodes live traffic, shows how data flows through the network, and demonstrates the basics of common protocols (DNS, UDP/QUIC, ICMP, TCP). It also shows the difference between readable plain traffic and encrypted traffic.

---

**Tools used:** Python, Scapy, Npcap, Windows Command Prompt
**Project structure:**

```text
Task1_Network_Sniffer/
├── sniffer.py
├── README.md
└── screenshots/
```
