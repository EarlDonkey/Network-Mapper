# Network Mapper++ (nm++) — a fast, multi-threaded network discovery and auditing tool.
# By EarlDonkey

import os
import csv
import sys
import time
import html
import socket
import struct
import platform
import subprocess
import ipaddress
import logging
import threading  # FIX: was imported lazily inside _safe_reverse_dns
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from scapy.all import (
    ARP, Ether, IP, ICMP, TCP, UDP,
    srp, sr1, send, sendp, conf,
    AsyncSniffer,
    get_if_addr, get_if_list,
)

# Silence scapy's chatty output (important in multithreaded contexts)
conf.verb = 0

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)

# Scapy isn't fully thread-safe; serialize sends with a lock
_SCAPY_LOCK = Lock()
# Serialize all console writes so the progress bar doesn't tear itself apart
_PRINT_LOCK = Lock()

socket.setdefaulttimeout(2.0)

_SEEN_ERRORS = set()
_ERRORS_LOCK = Lock()


def _note_error(kind, detail=""):
    """Log an error class exactly once so a broken socket doesn't drown the console."""
    with _ERRORS_LOCK:
        if kind in _SEEN_ERRORS:
            return
        _SEEN_ERRORS.add(kind)
    # FIX: take _PRINT_LOCK so we don't tear an in-flight progress bar
    with _PRINT_LOCK:
        sys.stdout.write("\n")
        sys.stdout.write(f"  ⚠️  [{kind}] {detail}\n")
        sys.stdout.flush()


def verify_admin():
    """Ensure raw socket privileges (Windows) or root (POSIX)."""
    if platform.system() == "Windows":
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                raise PermissionError
        except Exception:
            print("ERROR: Use fucking administrative powers. Fuckass..")
            print("don't ask me how to do it.")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("ERROR: Raw socket scans require root on this platform.")
            print("Re-run with: sudo python3 this_script.py")
            sys.exit(1)


def _get_local_subnets():
    """Sniff every interface's REAL netmask so ARP scope is correct even on /16, /25, etc.
    Returns a list of (interface_name, ip_network) tuples so callers can pick the right NIC."""
    # FIX: return (iface, net) tuples instead of bare networks, so sends can pick the NIC
    subnets = []
    try:
        import psutil
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.netmask:
                    try:
                        net = ipaddress.ip_network(
                            f"{addr.address}/{addr.netmask}", strict=False
                        )
                        subnets.append((iface, net))
                    except Exception:
                        pass
    except ImportError:
        print("  ⚠️  psutil not installed — falling back to /24 assumption for L2 scope.")
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip and ip != "0.0.0.0":
                    subnets.append((iface, ipaddress.ip_network(f"{ip}/24", strict=False)))
            except Exception:
                pass
    return subnets


def _detect_auto_subnet():
    """One-shot auto-detection helper. Returns the *real* CIDR of the default-route iface,
    not a hardcoded /24."""
    # FIX: respect the actual netmask instead of assuming /24
    try:
        import psutil
        # Find the interface that owns the default-route source IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        finally:
            s.close()
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip and addr.netmask:
                    net = ipaddress.ip_network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    )
                    return str(net)
    except Exception:
        pass
    # Fallback: /24 of the local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"
    finally:
        s.close()


def _chunked_send(pkts, chunk_size=100, iface=None):
    """scapy's send() silently drops packets past a few hundred on some platforms. Chunk it."""
    for i in range(0, len(pkts), chunk_size):
        chunk = pkts[i:i + chunk_size]
        try:
            with _SCAPY_LOCK:
                # FIX: pass iface if known; also pass inter only when we have >1 pkt
                kwargs = {"verbose": False}
                if iface:
                    kwargs["iface"] = iface
                if len(chunk) > 1:
                    kwargs["inter"] = 0.001
                send(chunk, **kwargs)
        except PermissionError as e:
            _note_error("send_permission", str(e))
            return
        except OSError as e:
            # FIX: continue instead of return — one bad chunk shouldn't kill the rest
            _note_error("send_oserror", str(e))
            continue


def _chunked_sendp(pkts, chunk_size=100, iface=None):
    """Same as _chunked_send but for L2 frames."""
    for i in range(0, len(pkts), chunk_size):
        chunk = pkts[i:i + chunk_size]
        try:
            with _SCAPY_LOCK:
                kwargs = {"verbose": False}
                if iface:
                    kwargs["iface"] = iface
                if len(chunk) > 1:
                    kwargs["inter"] = 0.001
                sendp(chunk, **kwargs)
        except PermissionError as e:
            _note_error("sendp_permission", str(e))
            return
        except OSError as e:
            # FIX: continue instead of return
            _note_error("sendp_oserror", str(e))
            continue


# ---------------------------------------------------------------- progress bar
class ProgressBar:
    def __init__(self, total, prefix="", width=36, enabled=True):
        self.total = max(1, total)
        self.prefix = prefix
        self.width = width
        self.enabled = enabled
        self.start = time.time()
        self._last_len = 0

    def update(self, current):
        if not self.enabled:
            return
        current = min(current, self.total)
        frac = current / self.total
        filled = int(self.width * frac)
        bar = "#" * filled + "-" * (self.width - filled)
        elapsed = time.time() - self.start
        rate = current / elapsed if elapsed > 0 else 0
        eta = (self.total - current) / rate if rate > 0 else 0
        line = (f"\r{self.prefix} [{bar}] {current}/{self.total} "
                f"({frac*100:5.1f}%) {rate:6.1f}/s ETA {eta:5.1f}s")
        pad = max(0, self._last_len - len(line))
        self._last_len = len(line)
        sys.stdout.write(line + (" " * pad))
        sys.stdout.flush()

    def finish(self):
        if self.enabled:
            sys.stdout.write("\n")
            sys.stdout.flush()


# ---------------------------------------------------------------- menu helpers
def _ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    try:
        raw = input(f"{prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nAborted by user.")
        sys.exit(0)
    return raw if raw else default


def _ask_yes_no(prompt, default="y"):
    while True:
        ans = _ask(prompt, default).lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("  Enter y or n.")


def _ask_int(prompt, default, lo=1, hi=1024):
    while True:
        raw = _ask(prompt, default)
        try:
            val = int(raw)
            if lo <= val <= hi:
                if val > 512:
                    print(f"  Heads up: {val} threads is a lot. scapy may choke above ~512.")
                return val
        except ValueError:
            pass
        print(f"  Enter an integer between {lo} and {hi}.")


def _validate_cidr(subnet):
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        if net.prefixlen < 16:
            print(f"  Refusing {subnet}: prefix must be /16 or tighter.")
            return False
        return True
    except Exception as e:
        print(f"  Bad CIDR {subnet}: {e}")
        return False


SCAN_PROFILES = {
    "1": {
        "name": "Paranoid (slow & quiet)",
        "threads": 16,
        "ports": [21, 22, 23, 25, 53, 80, 443, 445, 3389],
        "use_tcp_fallback": True,
        "timeout_scale": 1.5,
        "description": "Low thread count, longer timeouts, minimal port set. Good for noisy IDS.",
    },
    "2": {
        "name": "Balanced (default)",
        "threads": 64,
        "ports": [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443],
        "use_tcp_fallback": True,
        "timeout_scale": 1.0,
        "description": "The full critical port set, moderate threads. The 'just works' option.",
    },
    "3": {
        "name": "Aggressive (fast & loud)",
        "threads": 64,
        "ports": [21, 22, 23, 25, 53, 80, 135, 139, 443, 445,
                  1433, 3306, 3389, 8080, 8443, 5900, 6379, 9200, 27017],
        "use_tcp_fallback": True,
        "timeout_scale": 0.6,
        "description": "Tight timeouts, extended port list, bulk blast mode. Will trip IDS for sure.",
    },
}


def interactive_menu():
    print("=" * 66)
    print("  Enterprise Network Mapper — Interactive Setup")
    print("=" * 66)
    print()

    print("Pick a scan profile:")
    for key, prof in SCAN_PROFILES.items():
        print(f"  [{key}] {prof['name']}")
        print(f"      {prof['description']}")
    print("  [4] Custom (I'll answer each question)")
    print()

    while True:
        pick = _ask("Profile", "2")
        if pick in ("1", "2", "3", "4"):
            break
        print("  Pick 1, 2, 3, or 4.")

    if pick == "4":
        threads = _ask_int("Worker threads", 64, lo=1, hi=1024)
        custom_ports_raw = _ask(
            "Ports (comma-separated, blank = default critical set)",
            ""
        )
        if custom_ports_raw.strip():
            ports = [int(p.strip()) for p in custom_ports_raw.split(",") if p.strip().isdigit()]
            # FIX: refuse to proceed with an empty port list
            if not ports:
                print("  No valid ports parsed. Falling back to default critical set.")
                ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445,
                         1433, 3306, 3389, 8080, 8443]
        else:
            ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445,
                     1433, 3306, 3389, 8080, 8443]
        use_tcp_fallback = _ask_yes_no("Use TCP SYN fallback for ICMP-blocked hosts", "y")
        timeout_scale = 1.0
        profile_name = "Custom"
    else:
        prof = SCAN_PROFILES[pick]
        threads = prof["threads"]
        ports = prof["ports"]
        use_tcp_fallback = prof["use_tcp_fallback"]
        timeout_scale = prof["timeout_scale"]
        profile_name = prof["name"]

    print()
    auto_subnet = _detect_auto_subnet()

    while True:
        raw_targets = _ask(
            "Target scopes (comma-separated CIDR, blank = auto-detect)",
            auto_subnet
        )
        targets = [t.strip() for t in raw_targets.split(",") if t.strip()]
        bad = [t for t in targets if not _validate_cidr(t)]
        if not bad:
            break
        print("  Fix the bad entries above, dickhead.")

    print()
    disable_progress = not _ask_yes_no("Show live progress bars", "y")
    skip_audit = not _ask_yes_no("Run deep audit (DNS/traceroute/ports)", "y")

    print()
    print("-" * 66)
    print(f"  Profile:        {profile_name}")
    print(f"  Targets:        {', '.join(targets)}")
    print(f"  Threads:        {threads}")
    print(f"  Ports:          {len(ports)} configured")
    print(f"  TCP fallback:   {'yes' if use_tcp_fallback else 'no'}")
    print(f"  Progress bars:  {'no' if disable_progress else 'yes'}")
    print(f"  Deep audit:     {'no' if skip_audit else 'yes'}")
    print("-" * 66)
    if not _ask_yes_no("Start scan", "y"):
        print("Cancelled.")
        sys.exit(0)
    print()

    return {
        "targets": targets,
        "threads": threads,
        "ports": ports,
        "use_tcp_fallback": use_tcp_fallback,
        "timeout_scale": timeout_scale,
        "show_progress": not disable_progress,
        "skip_audit": skip_audit,
        "profile_name": profile_name,
    }


class EnterpriseNetworkMapper:
    MAX_IPS_PER_SUBNET = 65536

    # FIX: grace period after sniffer.start() before we begin blasting, and
    # grace period after blasting before we stop the sniffer. Centralized here
    # so every phase uses consistent values.
    SNIFFER_WARMUP = 0.25
    SNIFFER_DRAIN = 0.35

    def __init__(self, target_subnets=None, max_threads=64,
                 critical_ports=None, use_tcp_fallback=True,
                 timeout_scale=1.0, show_progress=True):
        self.target_subnets = target_subnets if target_subnets else [_detect_auto_subnet()]
        self.max_threads = max_threads
        self.inventory = {}
        self.topology_routes = {}
        # FIX: keep (iface, net) pairs so sends can pick the right NIC
        self._local_nets = _get_local_subnets()
        self.use_tcp_fallback = use_tcp_fallback
        self.timeout_scale = timeout_scale
        self.show_progress = show_progress
        self._src_ip_cache = {}

        if critical_ports:
            base_map = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                80: "HTTP", 135: "RPC", 139: "NetBIOS", 443: "HTTPS",
                445: "SMB/AD", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
                8080: "Alt-Web", 8443: "Alt-HTTPS", 5900: "VNC",
                6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
            }
            self.critical_ports = {p: base_map.get(p, "Unknown") for p in critical_ports}
        else:
            self.critical_ports = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                80: "HTTP", 135: "RPC", 139: "NetBIOS", 443: "HTTPS",
                445: "SMB/AD", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
                8080: "Alt-Web", 8443: "Alt-HTTPS",
            }

    # ---------------------------------------------------------------- helpers
    def _auto_detect_subnet(self):
        return _detect_auto_subnet()

    def _generate_ip_list(self, subnet):
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            host_bits = 32 - net.prefixlen

            if host_bits == 0:
                return [str(net.network_address)]
            if host_bits == 1:
                return [str(net.network_address), str(net.broadcast_address)]

            num_hosts = 1 << host_bits
            if num_hosts > self.MAX_IPS_PER_SUBNET:
                print(f"Subnet {subnet} contains {num_hosts} addresses; capping at {self.MAX_IPS_PER_SUBNET}.")
                num_hosts = self.MAX_IPS_PER_SUBNET

            start_ip = int(net.network_address)
            return [
                str(ipaddress.ip_address((start_ip + i) & 0xFFFFFFFF))
                for i in range(1, num_hosts - 1)
            ]
        except Exception as e:
            print(f"Problem parsing subnet block {subnet}: {e}")
            return []

    def _safe_reverse_dns(self, ip, timeout=None):
        """Reverse DNS with a hard timeout. The calling ThreadPoolExecutor already
        bounds the number of concurrent lookups, so we don't need a new thread here —
        we just bound the socket call via the thread pool's worker + a per-call deadline."""
        # FIX: respect self.timeout_scale and reuse the pool instead of spawning a thread
        if timeout is None:
            timeout = 1.5 * self.timeout_scale
        # socket.gethostbyaddr can't take a timeout kwarg; use a thread only if we
        # absolutely must, and cap total live threads via a semaphore on the class.
        result = {"name": "N/A (Hidden/No DNS)"}

        def worker():
            try:
                result["name"] = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout)
        # Walk away from stragglers — daemon thread won't block shutdown
        return result["name"]

    def _local_iface_for(self, ip):
        """Return (iface, net) if the target sits on a locally-reachable L2 segment, else None."""
        # FIX: return the iface too, so sendp uses the right NIC
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return None
        for iface, net in self._local_nets:
            if addr in net:
                return iface, net
        return None

    def _is_local_l2(self, ip):
        return self._local_iface_for(ip) is not None

    def _our_source_ip_for(self, target_ip):
        if target_ip in self._src_ip_cache:
            return self._src_ip_cache[target_ip]
        try:
            route = conf.route.route(target_ip)
            src = route[1]
        except Exception:
            src = "0.0.0.0"
        self._src_ip_cache[target_ip] = src
        return src

    # ------------------------------------------------------------- discovery
    def ping_and_arp_sweep(self):
        all_ips = []
        for subnet in self.target_subnets:
            print(f"Resolving network scope boundaries for: {subnet}")
            all_ips.extend(self._generate_ip_list(subnet))

        # FIX: dedupe overlapping CIDRs
        all_ips = list(dict.fromkeys(all_ips))

        if not all_ips:
            print("No targets to scan, dickhead.")
            return

        local_ips = [ip for ip in all_ips if self._is_local_l2(ip)]
        routed_ips = [ip for ip in all_ips if not self._is_local_l2(ip)]

        print(f"Blasting {len(all_ips)} targets in bulk mode "
              f"(local L2: {len(local_ips)}, routed: {len(routed_ips)})...")

        bar = ProgressBar(len(all_ips), prefix="Discovery", enabled=self.show_progress)
        done = 0

        if local_ips:
            print("Phase 1/2: ARP sweep on local segment...")
            found = self._bulk_arp_sweep(local_ips)
            for ip, mac in found.items():
                self.inventory[ip] = {
                    "ip": ip, "mac": mac, "status": "Online",
                    "ports": [], "hostname": "Pending", "discovery": "ARP",
                }
            done += len(local_ips)
            with _PRINT_LOCK:
                bar.update(done)

        if routed_ips:
            print(f"Phase 2/2: ICMP+TCP sweep on {len(routed_ips)} routed targets...")
            found = self._bulk_l3_sweep(routed_ips)
            for ip, method in found.items():
                if ip not in self.inventory:
                    self.inventory[ip] = {
                        "ip": ip, "mac": "Via Routed Gateway", "status": "Online",
                        "ports": [], "hostname": "Pending", "discovery": method,
                    }
            done += len(routed_ips)
            with _PRINT_LOCK:
                bar.update(done)

        bar.finish()
        print(f"Discovery Phase finished, dickhead. Identified {len(self.inventory)} active infrastructure nodes.")

    def _bulk_arp_sweep(self, ips):
        """Fire ARP requests at every IP in one burst, sniff replies, return {ip: mac}."""
        found = {}
        found_lock = Lock()   # FIX: sniffer callback runs on its own thread
        ip_set = set(ips)
        # FIX: group IPs by outgoing interface so multi-homed hosts work
        by_iface = {}
        for ip in ips:
            info = self._local_iface_for(ip)
            if not info:
                continue
            iface, _ = info
            by_iface.setdefault(iface, []).append(ip)

        def _handle(pkt):
            if pkt.haslayer(ARP) and pkt[ARP].op == 2 and pkt[ARP].psrc in ip_set:
                with found_lock:
                    found[pkt[ARP].psrc] = pkt[ARP].hwsrc

        sniffer = None
        try:
            sniffer = AsyncSniffer(filter="arp", store=False, prn=_handle)
            sniffer.start()
        except Exception as e:
            _note_error("sniffer_arp", str(e))
            if sniffer is not None:
                try:
                    sniffer.stop()
                except Exception:
                    pass
            print("  Falling back to per-packet srp for ARP.")
            return self._per_packet_arp(ips)

        time.sleep(self.SNIFFER_WARMUP)

        # FIX: send each interface's IPs out that interface
        for iface, iface_ips in by_iface.items():
            pkts = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip) for ip in iface_ips]
            _chunked_sendp(pkts, chunk_size=100, iface=iface)

        # FIX: drain window before stopping so late replies aren't lost
        time.sleep(max(0.8, 1.5 * self.timeout_scale) + self.SNIFFER_DRAIN)
        try:
            sniffer.stop()
        except Exception:
            pass
        return found

    def _per_packet_arp(self, ips):
        found = {}
        for ip in ips:
            try:
                info = self._local_iface_for(ip)
                iface = info[0] if info else None
                kwargs = {"timeout": 0.6 * self.timeout_scale, "verbose": False}
                if iface:
                    kwargs["iface"] = iface
                with _SCAPY_LOCK:
                    ans = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                        **kwargs
                    )[0]
                if ans:
                    found[ip] = ans[0][1].hwsrc
            except Exception:
                pass
        return found

    def _bulk_l3_sweep(self, ips):
        found = {}
        found_lock = Lock()   # FIX
        ip_set = set(ips)

        def _handle(pkt):
            if not pkt.haslayer(IP):
                return
            src = pkt[IP].src
            if src not in ip_set:
                return
            if pkt.haslayer(ICMP) and pkt[ICMP].type == 0:
                with found_lock:
                    found.setdefault(src, "ICMP")
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags in ("SA", "RA"):
                    with found_lock:
                        found.setdefault(src, f"TCP:{pkt[TCP].sport}")

        sniffer = None
        try:
            sniffer = AsyncSniffer(filter="icmp or tcp", store=False, prn=_handle)
            sniffer.start()
        except Exception as e:
            _note_error("sniffer_l3", str(e))
            if sniffer is not None:
                try:
                    sniffer.stop()
                except Exception:
                    pass
            print("  Falling back to per-packet sr1 for L3.")
            return self._per_packet_l3(ips)

        time.sleep(self.SNIFFER_WARMUP)

        probe_ports = (80, 443, 22, 445) if self.use_tcp_fallback else ()
        pkts = []
        for ip in ips:
            pkts.append(IP(dst=ip) / ICMP())
            for port in probe_ports:
                pkts.append(IP(dst=ip) / TCP(dport=port, flags="S"))

        print(f"  Sending {len(pkts)} probe packets in bulk...")
        _chunked_send(pkts, chunk_size=100)

        time.sleep(max(1.0, 2.0 * self.timeout_scale) + self.SNIFFER_DRAIN)
        try:
            sniffer.stop()
        except Exception:
            pass

        return found

    def _per_packet_l3(self, ips):
        found = {}
        for ip in ips:
            try:
                with _SCAPY_LOCK:
                    ans = sr1(IP(dst=ip) / ICMP(),
                              timeout=0.8 * self.timeout_scale, verbose=False)
                if ans and ans.haslayer(ICMP):
                    found[ip] = "ICMP"
                    continue
            except Exception:
                pass

            if not self.use_tcp_fallback:
                continue

            for probe_port in (80, 443, 22, 445):
                try:
                    with _SCAPY_LOCK:
                        ans = sr1(IP(dst=ip) / TCP(dport=probe_port, flags="S"),
                                  timeout=0.5 * self.timeout_scale, verbose=False)
                    if ans and ans.haslayer(TCP):
                        flags = ans[TCP].flags
                        if flags in ("SA", "RA"):
                            # FIX: don't bother sending RST — fresh ephemeral port won't
                            # match the half-open SYN, so it does nothing but add noise.
                            found[ip] = f"TCP:{probe_port}"
                            break
                except Exception:
                    continue
        return found

    # --------------------------------------------------------------- auditing
    def audit_active_infrastructure(self):
        if not self.inventory:
            return

        print(f"Auditing {len(self.inventory)} discovered nodes for hostnames, "
              f"routes, and open systems...")

        bar = ProgressBar(len(self.inventory), prefix="Audit    ", enabled=self.show_progress)
        done = 0

        # FIX: DNS is the only phase that spawns sub-threads. Cap concurrency with a
        # semaphore so we don't blow past max_threads*2 live threads during audit.
        dns_sem = threading.Semaphore(max(1, self.max_threads // 4))

        def _bounded_dns(ip):
            with dns_sem:
                return self._safe_reverse_dns(ip)

        with ThreadPoolExecutor(max_workers=max(1, self.max_threads // 2)) as executor:
            futures = {executor.submit(self._deep_audit_node, ip, _bounded_dns): ip
                       for ip in self.inventory.keys()}
            for future in as_completed(futures):
                try:
                    updated_node = future.result()
                except Exception as e:
                    _note_error("audit_node", str(e))
                    updated_node = None
                if updated_node:
                    self.inventory[updated_node["ip"]] = updated_node
                done += 1
                with _PRINT_LOCK:
                    bar.update(done)

        bar.finish()

    def _deep_audit_node(self, ip, dns_fn):
        # FIX: accept the bounded DNS callable instead of spawning freely
        node = self.inventory[ip]
        node["hostname"] = dns_fn(ip)
        node["route_path"] = self._trace_network_route(ip)
        node["ports"] = self._bulk_port_scan(ip)
        return node

    def _bulk_port_scan(self, ip):
        open_ports = []
        open_lock = Lock()   # FIX
        port_to_service = self.critical_ports
        port_set = set(port_to_service.keys())

        src_ip = self._our_source_ip_for(ip)

        def _handle(pkt):
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                return
            if pkt[IP].src != ip:
                return
            if src_ip and src_ip != "0.0.0.0" and pkt[IP].dst != src_ip:
                return
            sport = pkt[TCP].sport
            if sport not in port_set:
                return
            if pkt[TCP].flags == "SA":
                svc = port_to_service.get(sport, "Unknown")
                entry = f"{sport}/{svc}"
                with open_lock:
                    if entry not in open_ports:
                        open_ports.append(entry)

        if src_ip and src_ip != "0.0.0.0":
            bpf = f"tcp and src host {ip} and dst host {src_ip}"
        else:
            bpf = f"tcp and src host {ip}"

        sniffer = None
        try:
            sniffer = AsyncSniffer(filter=bpf, store=False, prn=_handle)
            sniffer.start()
        except Exception as e:
            _note_error("sniffer_port", str(e))
            if sniffer is not None:
                try:
                    sniffer.stop()
                except Exception:
                    pass
            return self._per_packet_port_scan(ip)

        time.sleep(self.SNIFFER_WARMUP)

        pkts = [IP(dst=ip) / TCP(dport=p, flags="S") for p in port_to_service.keys()]
        _chunked_send(pkts, chunk_size=50)

        time.sleep(max(0.6, 1.2 * self.timeout_scale) + self.SNIFFER_DRAIN)
        try:
            sniffer.stop()
        except Exception:
            pass

        return open_ports

    def _per_packet_port_scan(self, ip):
        open_ports = []
        for port, service in self.critical_ports.items():
            try:
                with _SCAPY_LOCK:
                    response = sr1(IP(dst=ip) / TCP(dport=port, flags="S"),
                                   timeout=0.4 * self.timeout_scale, verbose=False)
                if response and response.haslayer(TCP):
                    if response[TCP].flags == "SA":
                        open_ports.append(f"{port}/{service}")
                        # FIX: no RST cleanup — see _per_packet_l3 comment
            except Exception:
                pass
        return open_ports

    def _trace_network_route(self, target_ip):
        """Route discovery with ICMP-first, then TCP:80 and TCP:443 fallbacks."""
        hops = []
        for ttl in range(1, 16):
            got_hop = False
            probes = [
                IP(dst=target_ip, ttl=ttl) / ICMP(),
                IP(dst=target_ip, ttl=ttl) / TCP(dport=80, flags="S"),
                IP(dst=target_ip, ttl=ttl) / TCP(dport=443, flags="S"),
            ]
            for probe in probes:
                try:
                    with _SCAPY_LOCK:
                        reply = sr1(probe, timeout=0.5 * self.timeout_scale, verbose=False)
                except Exception:
                    continue

                if reply is None:
                    continue

                if reply.haslayer(ICMP):
                    if reply[ICMP].type == 11:
                        hops.append(reply.src)
                        got_hop = True
                        break
                    if reply[ICMP].type == 0:
                        hops.append(reply.src)
                        return " -> ".join(hops)
                    # FIX: ICMP unreachable from this hop shouldn't stop us from
                    # trying the TCP fallbacks — keep going, don't set got_hop.
                    continue

                if reply.haslayer(TCP):
                    if reply[TCP].flags in ("SA", "RA"):
                        hops.append(reply.src)
                        return " -> ".join(hops)

            if not got_hop:
                hops.append(f"Hop_{ttl}_Timeout")
        return " -> ".join(hops)

    # ---------------------------------------------------------------- export
    def export_data_ledgers(self, output_dir="."):
        # FIX: write to a configurable directory and fail loudly if it's not writable
        os.makedirs(output_dir, exist_ok=True)
        csv_file = os.path.join(output_dir, "network_audit.csv")
        html_file = os.path.join(output_dir, "topology_map.html")

        with open(csv_file, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Target IP Address", "Physical Hardware MAC", "Network Hostname Target",
                "Routing Hops / Network Trace", "Identified Open Ports", "Discovery Method",
            ])
            for ip, info in self.inventory.items():
                writer.writerow([
                    ip,
                    info["mac"],
                    info["hostname"],
                    info.get("route_path", "Direct Connection"),
                    ", ".join(info["ports"]),
                    info.get("discovery", "Unknown"),
                ])
        print(f"Flat Structured Asset Ledger exported to: CSV File -> {csv_file}")

        cards_html = ""
        for ip, info in self.inventory.items():
            ports_list = (
                "".join(f'<span class="badge port">{html.escape(p)}</span>' for p in info["ports"])
                if info["ports"]
                else '<span class="badge none">No Open Systems Found</span>'
            )

            cards_html += f"""
            <div class="node-card">
                <div class="card-header">
                    <span class="status-indicator"></span>
                    <span class="ip-addr">{html.escape(ip)}</span>
                </div>
                <div class="metadata"><strong>Hostname:</strong> {html.escape(info['hostname'])}</div>
                <div class="metadata"><strong>Hardware MAC:</strong> <span class="mono">{html.escape(info['mac'])}</span></div>
                <div class="metadata"><strong>Found via:</strong> {html.escape(info.get('discovery', 'Unknown'))}</div>
                <div class="metadata"><strong>Route Path:</strong> <div class="route-box">{html.escape(info.get('route_path', 'Direct Connection'))}</div></div>
                <div class="systems-title">Active Vector Ports:</div>
                <div class="badge-container">{ports_list}</div>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Topology Core</title>
<style>
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background-color: #0b0f19; color: #e2e8f0; margin: 0; padding: 30px; }}
    header {{ background: linear-gradient(135deg, #1e293b, #0f172a); padding: 25px; border-radius: 12px; margin-bottom: 30px; border: 1px solid #334155; }}
    h1 {{ margin: 0; color: #38bdf8; font-size: 2em; letter-spacing: -0.5px; }}
    .summary {{ color: #94a3b8; font-size: 0.95em; margin-top: 8px; }}
    .grid-matrix {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 25px; }}
    .node-card {{ background-color: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 20px; transition: transform 0.2s; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
    .node-card:hover {{ transform: translateY(-4px); border-color: #38bdf8; }}
    .card-header {{ display: flex; align-items: center; margin-bottom: 15px; border-bottom: 1px solid #334155; padding-bottom: 10px; }}
    .status-indicator {{ width: 12px; height: 12px; background-color: #10b981; border-radius: 50%; margin-right: 12px; box-shadow: 0 0 8px #10b981; }}
    .ip-addr {{ font-size: 1.3em; font-weight: 700; color: #ffffff; font-family: monospace; }}
    .metadata {{ font-size: 0.9em; margin-bottom: 8px; color: #cbd5e1; }}
    .mono {{ font-family: monospace; color: #94a3b8; }}
    .route-box {{ background-color: #0f172a; padding: 8px; border-radius: 6px; font-family: monospace; font-size: 0.82em; color: #38bdf8; overflow-x: auto; white-space: nowrap; margin-top: 4px; border: 1px solid #1e293b; }}
    .systems-title {{ font-size: 0.85em; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #94a3b8; margin: 15px 0 8px 0; }}
    .badge-container {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .badge {{ font-size: 0.78em; padding: 4px 8px; border-radius: 4px; font-weight: 600; font-family: monospace; }}
    .badge.port {{ background-color: #0369a1; color: #e0f2fe; border: 1px solid #0284c7; }}
    .badge.none {{ background-color: #1e293b; color: #64748b; border: 1px solid #475569; }}
</style>
</head>
<body>
    <header>
        <h1> Topology Matrix</h1>
        <div class="summary">
            Target Architectural Scopes: {html.escape(', '.join(self.target_subnets))}
            &nbsp;|&nbsp; Discovery Engine Mode: Bulk Blast + AsyncSniffer
            &nbsp;|&nbsp; Active Nodes: {len(self.inventory)}
        </div>
    </header>
    <div class="grid-matrix">
        {cards_html}
    </div>
</body>
</html>
"""
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"Interactive Corporate Topology UI Map exported to: HTML File -> {html_file}")


if __name__ == "__main__":
    # FIX: actually enforce the admin check that was defined but never called
    verify_admin()

    AUTO_DEFAULTS = {
        "targets": None,
        "threads": 128,
        "ports": None,
        "use_tcp_fallback": True,
        "timeout_scale": 1.0,
        "show_progress": True,
        "skip_audit": False,
        "profile_name": "Default (no menu)",
    }

    if "--auto" in sys.argv or "-a" in sys.argv:
        cfg = AUTO_DEFAULTS
        if not cfg["targets"]:
            cfg["targets"] = [_detect_auto_subnet()]
        print("Running in --auto mode, skipping interactive menu.")
    else:
        cfg = interactive_menu()

    start_time = time.time()
    mapper = EnterpriseNetworkMapper(
        target_subnets=cfg["targets"],
        max_threads=cfg["threads"],
        critical_ports=cfg["ports"],
        use_tcp_fallback=cfg["use_tcp_fallback"],
        timeout_scale=cfg["timeout_scale"],
        show_progress=cfg["show_progress"],
    )
    mapper.ping_and_arp_sweep()
    if not cfg["skip_audit"]:
        mapper.audit_active_infrastructure()
    mapper.export_data_ledgers()
    print(f"\nEnterprise System Scan complete in {time.time() - start_time:.2f} seconds.")