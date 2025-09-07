#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' 
Python Network Packet Sniffer & Analyzer
- Live capture with Scapy (requires admin/root)
- Rich dashboard (protocol counts, top talkers, alerts)
- Anomaly detection: port scans & DoS bursts
- Save to PCAP; offline PCAP analysis
'''

import argparse
import os
import sys
import time
import signal
from collections import Counter, defaultdict, deque
from datetime import datetime
from typing import Optional, Deque, Dict, Tuple, List

from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from rich.layout import Layout
from rich import box

console = Console()

# Scapy imports
try:
    from scapy.all import (
        sniff, AsyncSniffer, get_if_list, IP, TCP, UDP, ICMP,
        PcapWriter, rdpcap
    )
except Exception as e:
    console.print("[red]Failed to import Scapy. Did you install requirements?[/red]")
    raise


def list_interfaces():
    console.print("[bold cyan]Available Interfaces:[/bold cyan]")
    for name in get_if_list():
        console.print(f" - {name}")


class PortScanDetector:
    def __init__(self, window_seconds: int = 30, distinct_ports_threshold: int = 50):
        self.window = window_seconds
        self.threshold = distinct_ports_threshold
        self.events: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self.port_counts: Dict[str, Counter] = defaultdict(Counter)

    def observe(self, ts: float, src: str, dport: Optional[int]) -> Optional[str]:
        if dport is None:
            return None
        evq = self.events[src]
        pc = self.port_counts[src]
        evq.append((ts, dport))
        pc[dport] += 1

        cutoff = ts - self.window
        while evq and evq[0][0] < cutoff:
            old_ts, old_port = evq.popleft()
            pc[old_port] -= 1
            if pc[old_port] <= 0:
                del pc[old_port]

        distinct_now = len(pc)
        if distinct_now >= self.threshold:
            return f"Possible PORT SCAN from {src}: contacted {distinct_now} distinct ports in last {self.window}s"
        return None


class DosDetector:
    def __init__(self, window_seconds: int = 10, pps_threshold: int = 300):
        self.window = window_seconds
        self.threshold = pps_threshold
        self.events: Dict[str, Deque[float]] = defaultdict(deque)

    def observe(self, ts: float, src: str) -> Optional[str]:
        dq = self.events[src]
        dq.append(ts)
        cutoff = ts - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.threshold:
            return f"Possible DoS from {src}: ~{len(dq)/self.window:.1f} pps in last {self.window}s"
        return None


class Dashboard:
    def __init__(self, alert_buffer: int = 10):
        self.alerts: Deque[str] = deque(maxlen=alert_buffer)

    def add_alert(self, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.alerts.appendleft(f"[{ts}] {text}")

    def render(self, proto_counts: Counter, src_counts: Counter, dst_counts: Counter) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="upper", ratio=3),
            Layout(name="lower", ratio=2)
        )
        layout["upper"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )

        # Protocol table
        t_proto = Table(title="Protocol Counts", box=box.MINIMAL_DOUBLE_HEAD, expand=True)
        t_proto.add_column("Protocol", justify="left")
        t_proto.add_column("Packets", justify="right")
        for proto in ["IP", "TCP", "UDP", "ICMP", "Other"]:
            t_proto.add_row(proto, str(proto_counts.get(proto, 0)))

        # Top talkers
        def top_table(title: str, counter: Counter):
            t = Table(title=title, box=box.MINIMAL, expand=True)
            t.add_column("IP", justify="left")
            t.add_column("Packets", justify="right")
            for ip, cnt in counter.most_common(5):
                t.add_row(ip, str(cnt))
            return t

        layout["upper"]["left"].update(Panel(t_proto, title="Stats", border_style="cyan"))
        two = Layout()
        two.split_column(
            Layout(Panel(top_table("Top Source IPs", src_counts), title="Sources", border_style="green")),
            Layout(Panel(top_table("Top Destination IPs", dst_counts), title="Destinations", border_style="magenta"))
        )
        layout["upper"]["right"].update(two)

        # Alerts
        t_alerts = Table(title="Alerts", box=box.SIMPLE, expand=True)
        t_alerts.add_column("Recent", justify="left", no_wrap=False)
        if self.alerts:
            for a in list(self.alerts):
                t_alerts.add_row(a)
        else:
            t_alerts.add_row("No alerts yet.")
        layout["lower"].update(Panel(t_alerts, title="Security Events", border_style="yellow"))
        return layout


def parse_args():
    p = argparse.ArgumentParser(description="Python Packet Sniffer & Analyzer")
    p.add_argument("--list", action="store_true", help="List available network interfaces")
    p.add_argument("--iface", type=str, default=None, help="Interface to capture on (exact name)")
    p.add_argument("--bpf", type=str, default="ip", help="BPF filter (e.g., 'tcp or udp or icmp')")
    p.add_argument("--pcap", type=str, default=None, help="Save captured packets to this PCAP file")
    p.add_argument("--duration", type=int, default=0, help="Duration to run (seconds). 0 = until Ctrl+C")
    p.add_argument("--offline", type=str, default=None, help="Analyze an existing PCAP file instead of live capture")
    p.add_argument("--ps-window", type=int, default=30, help="Port-scan window in seconds")
    p.add_argument("--ps-ports", type=int, default=50, help="Port-scan unique destination ports threshold")
    p.add_argument("--dos-window", type=int, default=10, help="DoS window in seconds")
    p.add_argument("--dos-pps", type=int, default=300, help="DoS packets-per-window threshold")
    p.add_argument("--no-dashboard", action="store_true", help="Disable Rich dashboard; print summaries only")
    p.add_argument("--log-dir", type=str, default="logs", help="Directory for logs and summaries")
    return p.parse_args()


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def print_summary(proto_counts: Counter, src_counts: Counter, dst_counts: Counter, summary_path: str):
    lines: List[str] = []
    lines.append("=== SUMMARY ===")
    lines.append("Protocol counts:")
    for k in ["IP", "TCP", "UDP", "ICMP", "Other"]:
        lines.append(f"  {k}: {proto_counts.get(k, 0)}")

    def top_str(counter: Counter, title: str):
        lines.append(title)
        for ip, cnt in counter.most_common(10):
            lines.append(f"  {ip}: {cnt}")

    top_str(src_counts, "Top sources:")
    top_str(dst_counts, "Top destinations:")

    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    console.rule("[bold blue]Summary[/bold blue]")
    for ln in lines:
        console.print(ln)


def main():
    args = parse_args()

    if args.list:
        list_interfaces()
        return

    ensure_dir(args.log_dir)

    # Stats
    proto_counts = Counter()
    src_counts = Counter()
    dst_counts = Counter()

    # Detectors
    ps = PortScanDetector(window_seconds=args.ps_window, distinct_ports_threshold=args.ps_ports)
    dos = DosDetector(window_seconds=args.dos_window, pps_threshold=args.dos_pps)

    dash = Dashboard(alert_buffer=20)
    start_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile_path = os.path.join(args.log_dir, f"alerts_{start_ts}.log")
    summary_path = os.path.join(args.log_dir, f"summary_{start_ts}.log")

    def log_alert(text: str):
        dash.add_alert(text)
        with open(logfile_path, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} {text}\n")

    pcap_writer = None
    if args.pcap:
        pcap_writer = PcapWriter(args.pcap, append=False, sync=True)

    def handle_packet(pkt):
        ts = time.time()
        src_ip = pkt[IP].src if IP in pkt else None
        dst_ip = pkt[IP].dst if IP in pkt else None

        proto = "Other"
        if IP in pkt:
            proto = "IP"
            if TCP in pkt:
                proto = "TCP"
            elif UDP in pkt:
                proto = "UDP"
            elif ICMP in pkt:
                proto = "ICMP"

        proto_counts[proto] += 1
        if src_ip:
            src_counts[src_ip] += 1
        if dst_ip:
            dst_counts[dst_ip] += 1

        if pcap_writer is not None:
            try:
                pcap_writer.write(pkt)
            except Exception:
                pass

        if TCP in pkt and IP in pkt:
            alert = ps.observe(ts, pkt[IP].src, int(pkt[TCP].dport))
            if alert:
                log_alert(alert)
        if IP in pkt:
            alert2 = dos.observe(ts, pkt[IP].src)
            if alert2:
                log_alert(alert2)

    # OFFLINE MODE
    if args.offline:
        try:
            packets = rdpcap(args.offline)
        except Exception as e:
            console.print(f"[red]Failed to read PCAP: {e}[/red]")
            sys.exit(1)

        if args.no_dashboard:
            for pkt in packets:
                handle_packet(pkt)
        else:
            with Live(dash.render(proto_counts, src_counts, dst_counts), refresh_per_second=4, console=console):
                for pkt in packets:
                    handle_packet(pkt)
                    time.sleep(0.002)
        print_summary(proto_counts, src_counts, dst_counts, summary_path)
        console.print(f"[green]Offline analysis complete. Summary saved to {summary_path}[/green]")
        return

    # LIVE CAPTURE MODE
    if not args.iface:
        console.print("[red]No interface provided. Use --iface or --list to see names.[/red]")
        sys.exit(2)

    sniffer = AsyncSniffer(
        iface=args.iface,
        prn=handle_packet,
        store=False,
        filter=args.bpf
    )

    stop_flag = False

    def stop_sniffer(*_):
        nonlocal stop_flag
        stop_flag = True
        try:
            sniffer.stop()
        except Exception:
            pass

    signal.signal(signal.SIGINT, stop_sniffer)
    signal.signal(signal.SIGTERM, stop_sniffer)

    try:
        sniffer.start()
    except Exception as e:
        console.print(f"[red]Failed to start sniffer on '{args.iface}': {e}[/red]")
        console.print("[yellow]Tips: Run as Administrator/root, install Npcap (Windows), or check interface name.[/yellow]")
        sys.exit(3)

    end_time = None
    if args.duration and args.duration > 0:
        end_time = time.time() + args.duration

    if args.no_dashboard:
        while not stop_flag and (end_time is None or time.time() < end_time):
            time.sleep(0.2)
    else:
        with Live(dash.render(proto_counts, src_counts, dst_counts), refresh_per_second=4, console=console) as live:
            while not stop_flag and (end_time is None or time.time() < end_time):
                live.update(dash.render(proto_counts, src_counts, dst_counts))
                time.sleep(0.25)

    try:
        sniffer.stop()
    except Exception:
        pass
    if pcap_writer:
        try:
            pcap_writer.close()
        except Exception:
            pass

    print_summary(proto_counts, src_counts, dst_counts, summary_path)
    console.print(f"[green]Capture complete. Summary saved to {summary_path}[/green]")


if __name__ == "__main__":
    main()
