Task 1: Basic Network Sniffer

CodeAlpha Cyber Security Internship

A command-line network sniffer written in Python with Scapy. It captures live packets, decodes each protocol layer, and prints source/destination addresses, protocol, ports, and a payload preview. A summary of captured protocols is shown when the capture ends.

Ethical use: only capture traffic on networks you own or have written permission to monitor.

Features
Live packet capture on any network interface
Decodes IPv4 / IPv6, TCP (with flags), UDP, ICMP, and DNS queries
Maps well-known ports to service names (HTTP, HTTPS, DNS, SSH, ...)
Printable payload preview (first 60 bytes)
BPF capture filters (e.g. tcp port 80, icmp)
Packet count limit and optional .pcap export (openable in Wireshark)
Protocol statistics summary at the end
Requirements
Python 3.8+
Scapy: pip install scapy
Windows: Npcap (the packet capture driver). Run the terminal as Administrator.
Linux/macOS: run with sudo.
Usage
bash
python sniffer.py [-i IFACE] [-c COUNT] [-f FILTER] [-o OUTPUT.pcap]
Option	Description
-i, --iface	Network interface (default: Scapy's default)
-c, --count	Number of packets to capture (0 = until Ctrl+C)
-f, --filter	BPF filter expression
-o, --output	Save captured packets to a .pcap file
Examples
bash
py sniffer.py -c 50                              # capture 50 packets
py sniffer.py -c 20 -f "icmp"                    # only ping traffic
py sniffer.py -c 20 -f "tcp port 80"             # only HTTP
py sniffer.py -c 100 -o capture.pcap             # save to pcap

(On Linux/macOS use sudo python3 sniffer.py ....)

Sample output
[*] Sniffing... iface=default filter='none' (Ctrl+C buat stop)

[19:12:28] UDP   192.168.43.209:59369 -> 192.168.43.47:DNS DNS query: clients4.google.com.  len=79
[19:12:28] UDP   192.168.43.209:62632 -> 142.250.4.138:HTTPS  len=1292
           payload: ......,..0.<.b.@F......C.?rqu...$.5.07.?.......3?....D.ga&..
[19:12:32] UDP   192.168.43.209:62776 -> 192.168.43.47:DNS DNS query: www.linkedin.com.  len=76

==================================================
RINGKASAN CAPTURE
==================================================
Total paket: 50
  UDP                50
Screenshots

Add your screenshots to the screenshots/ folder and keep the file names below (or edit the links).

Capture	Screenshot
DNS and QUIC (UDP) traffic	DNS/UDP capture
ICMP (ping) traffic	ICMP capture
TCP / HTTP traffic	TCP capture
How it works
sniff() from Scapy captures raw frames from the interface and calls handle_packet() for each one.
The handler checks the network layer (IPv4 or IPv6) and extracts source and destination.
It then inspects the transport layer: TCP (ports and flags), UDP (ports, plus DNS query names), or ICMP (message type).
If a raw payload exists, a printable preview is shown (non-printable bytes become .).
Counters track each protocol and are printed as a summary when capture stops.
What the results show
DNS (UDP/53): the host asks the DNS server to resolve a domain name (e.g. www.linkedin.com) before connecting.
HTTPS over UDP (port 443): modern browsers use QUIC / HTTP/3, which runs over UDP. The payload looks random because it is encrypted, so the content cannot be read by a sniffer.
Plain HTTP (TCP/80): unencrypted, so readable text such as request lines can appear in the payload. This is why HTTPS matters.
ICMP: type 8 is an echo request (ping) and type 0 is an echo reply.
Limitations and ideas for improvement
Port-to-service mapping is a small static list.
DNS responses are also labeled "DNS query" because the query section is repeated in replies.
Possible extensions: separate DNS request/response, ARP decoding, per-IP traffic statistics, a live dashboard, alerts for suspicious patterns.
