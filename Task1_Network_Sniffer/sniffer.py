import argparse
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw
except ImportError:
    sys.exit("scapy belum ke-install. Jalankan: py -m pip install scapy")

stats = Counter()
captured = []

PORT_NAMES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP",
}


def payload_preview(packet, limit=60):
    if Raw not in packet:
        return ""
    data = bytes(packet[Raw].load)[:limit]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def service_name(port):
    return PORT_NAMES.get(port, str(port))


def handle_packet(packet):
    if IP in packet:
        ip = packet[IP]
        src, dst = ip.src, ip.dst
    elif IPv6 in packet:
        ip = packet[IPv6]
        src, dst = ip.src, ip.dst
    else:
        stats["Non-IP (ARP/etc)"] += 1
        return

    ts = datetime.now().strftime("%H:%M:%S")
    proto, info = "OTHER", ""

    if TCP in packet:
        t = packet[TCP]
        proto = "TCP"
        info = f"{src}:{service_name(t.sport)} -> {dst}:{service_name(t.dport)} flags={t.flags}"
    elif UDP in packet:
        u = packet[UDP]
        proto = "UDP"
        info = f"{src}:{service_name(u.sport)} -> {dst}:{service_name(u.dport)}"
        if DNS in packet and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode(errors="ignore")
            info += f" DNS query: {qname}"
    elif ICMP in packet:
        proto = "ICMP"
        info = f"{src} -> {dst} type={packet[ICMP].type}"
    else:
        info = f"{src} -> {dst}"

    stats[proto] += 1
    captured.append(packet)

    print(f"[{ts}] {proto:<5} {info}  len={len(packet)}")
    preview = payload_preview(packet)
    if preview:
        print(f"           payload: {preview}")


def print_summary():
    print("\n" + "=" * 50)
    print("RINGKASAN CAPTURE")
    print("=" * 50)
    total = sum(stats.values())
    print(f"Total paket: {total}")
    for proto, count in stats.most_common():
        print(f"  {proto:<18} {count}")


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer (scapy)")
    parser.add_argument("-i", "--iface", help="Interface (contoh: Wi-Fi)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Jumlah paket (0 = sampai Ctrl+C)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter, contoh: 'tcp port 80'")
    parser.add_argument("-o", "--output", help="Simpan ke file .pcap")
    args = parser.parse_args()

    print(f"[*] Sniffing... iface={args.iface or 'default'} filter='{args.filter or 'none'}' (Ctrl+C buat stop)\n")
    try:
        sniff(iface=args.iface, filter=args.filter or None, prn=handle_packet,
              count=args.count, store=False)
    except PermissionError:
        sys.exit("[!] Butuh akses admin. Jalankan CMD sebagai administrator.")
    except KeyboardInterrupt:
        pass

    print_summary()
    if args.output and captured:
        wrpcap(args.output, captured)
        print(f"[+] Disimpan ke {args.output}")


if __name__ == "__main__":
    main()
