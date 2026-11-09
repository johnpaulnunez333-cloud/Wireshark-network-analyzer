import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import platform
from datetime import datetime
from collections import defaultdict

from colorama import init

init(autoreset=True)

TOOL_VERSION = "3.0"
AUTHOR = "John Paul Nunez"

packet_stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "dns": 0, "arp": 0, "other": 0}
connections = defaultdict(int)
packet_log = []
start_time = None

FONT = {
    "W": ["█   █", "█   █", "█ █ █", "██ ██", "█   █"],
    "I": ["███", " █ ", " █ ", " █ ", "███"],
    "R": ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
    "E": ["█████", "█    ", "████ ", "█    ", "█████"],
    "S": [" ████", "█    ", " ███ ", "    █", "████ "],
    "H": ["█   █", "█   █", "█████", "█   █", "█   █"],
    "A": [" ███ ", "█   █", "█████", "█   █", "█   █"],
    "K": ["█   █", "█  █ ", "███  ", "█  █ ", "█   █"],
}

GRADIENT = [93, 99, 63, 69, 33, 39, 45, 49, 48, 47, 46]

ANSI_RE = re.compile(r"\033\[[0-9;]*m")

PROTO_COLORS = {
    "TCP": 51, "UDP": 39, "ICMP": 203, "ICMPV6": 203, "DNS": 220, "MDNS": 220,
    "ARP": 177, "TLS": 48, "HTTP": 114, "QUIC": 111,
}

FIELDS = [
    "frame.number", "frame.time_relative", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "_ws.col.Protocol", "frame.len", "tcp.srcport", "tcp.dstport", "udp.srcport",
    "udp.dstport", "_ws.col.Info",
]


def c(code, text, bold=False):
    return f"\033[{'1;' if bold else ''}38;5;{code}m{text}\033[0m"


def vlen(text):
    return len(ANSI_RE.sub("", text))


def clip(text, n):
    return text if len(text) <= n else text[: max(n - 1, 0)] + "…"


def term_cols():
    return shutil.get_terminal_size((80, 24)).columns


def panel_width():
    return max(34, min(46, term_cols() - 2))


def render_word(word):
    rows = ["", "", "", "", ""]
    for ch in word:
        glyph = FONT[ch]
        for i in range(5):
            rows[i] += glyph[i] + " "
    return [r.rstrip() for r in rows]


def paint(text, width):
    out = []
    for x, ch in enumerate(text):
        if ch == " ":
            out.append(" ")
        else:
            idx = min(len(GRADIENT) - 1, int(x * len(GRADIENT) / max(width, 1)))
            out.append(f"\033[38;5;{GRADIENT[idx]}m{ch}")
    return "".join(out) + "\033[0m"


def rule(w):
    return paint("━" * w, w)


def panel_top(w):
    return paint("╭" + "─" * (w - 2) + "╮", w)


def panel_mid(w):
    return paint("├" + "─" * (w - 2) + "┤", w)


def panel_bot(w):
    return paint("╰" + "─" * (w - 2) + "╯", w)


def panel_row(content, w):
    pad = max(w - 4 - vlen(content), 0)
    return c(GRADIENT[0], "│") + " " + content + " " * pad + " " + c(GRADIENT[-1], "│")


def split_row(left, right, w):
    gap = max(w - 4 - vlen(left) - vlen(right), 1)
    return panel_row(left + " " * gap + right, w)


def ok(msg):
    print(c(48, "✔ ", True) + c(255, msg))


def err(msg):
    print(c(203, "✘ ", True) + c(255, msg))


def warn(msg):
    print(c(214, "! ", True) + c(255, msg))


def note(msg):
    print("  " + c(245, msg))


def ask(label):
    return input(c(51, "❯ ", True) + c(255, label) + c(245, " › ")).strip()


def find_tshark():
    path = shutil.which("tshark")
    if path:
        return path
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", "")):
            cand = os.path.join(base, "Wireshark", "tshark.exe")
            if os.path.exists(cand):
                return cand
    return None


def tshark_version(tshark):
    if not tshark:
        return "not installed"
    try:
        out = subprocess.run([tshark, "--version"], capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"(\d+\.\d+\.\d+)", out)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


def show_banner(tshark):
    os.system("cls" if os.name == "nt" else "clear")
    cols = term_cols()
    full = render_word("WIRESHARK")
    width = max(len(r) for r in full)
    print()
    if cols >= width + 1:
        for row in full:
            print(paint(row, width))
    else:
        for part in ("WIRE", "SHARK"):
            rows = render_word(part)
            w = max(len(r) for r in rows)
            for row in rows:
                print(paint(row, w))
            print()
    print()
    w = panel_width()
    engine = f"TShark {tshark_version(tshark)}" if tshark else "TShark not installed"
    print(rule(w))
    print(c(245, "Python version".ljust(16)) + c(99, platform.python_version(), True))
    print(c(245, "Tool version".ljust(16)) + c(48, TOOL_VERSION, True) + c(245, "  ·  ") + c(39, engine))
    print(c(245, "Develop by".ljust(16)) + c(255, AUTHOR, True))
    print(rule(w))
    print()


def show_status(label, is_root):
    dot = 48 if is_root else 203
    print(c(dot, "●", True) + " " + c(245, "Privilege".ljust(13)) + c(dot, label, True))
    if not is_root:
        hint = "Grant root (Magisk/su) to Termux" if is_android() else "Run with sudo or as Administrator"
        note("Live capture needs root (real Wireshark process).")
        note(hint + ".")
        note("No root? Analyze .pcap files with option 5.")
    print()


def show_menu(is_root):
    w = panel_width()
    items = [
        ("1", "Monitor URL / Domain", True, 99),
        ("2", "Monitor all traffic", True, 69),
        ("3", "Monitor protocol", True, 39),
        ("4", "Monitor port", True, 45),
        ("5", "Analyze .pcap file", False, 48),
        ("0", "Exit", None, 245),
    ]
    print(panel_top(w))
    print(panel_row(c(255, "MONITORING OPTIONS", True), w))
    print(panel_mid(w))
    for key, label, needs, col in items:
        left = c(col, f"[{key}]", True) + "  " + c(255, label)
        if needs is True:
            tag = c(48, "● ready") if is_root else c(203, "● needs root")
        elif needs is False:
            tag = c(48, "● no root")
        else:
            tag = ""
        print(split_row(left, tag, w))
    print(panel_bot(w))
    print()


def is_android():
    return "ANDROID_ROOT" in os.environ or "com.termux" in os.environ.get("PREFIX", "")


def detect_privilege():
    if os.name == "nt":
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                return "direct", "Administrator"
        except Exception:
            pass
        return None, "non-root"
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return "direct", "root"
    if shutil.which("su"):
        try:
            r = subprocess.run(["su", "-c", "id"], capture_output=True, text=True, timeout=20)
            if "uid=0" in r.stdout:
                return "su", "rooted device (su)"
        except Exception:
            pass
    return None, "non-root"


def wrap_cmd(cmd, mode):
    if mode == "su":
        env = f"export PATH={shlex.quote(os.environ.get('PATH', ''))}; "
        if os.environ.get("LD_LIBRARY_PATH"):
            env += f"export LD_LIBRARY_PATH={shlex.quote(os.environ['LD_LIBRARY_PATH'])}; "
        return ["su", "-c", env + "exec " + " ".join(shlex.quote(x) for x in cmd)]
    return cmd


def get_target_ips(url):
    try:
        clean = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        return sorted(set(socket.gethostbyname_ex(clean)[2]))
    except socket.gaierror:
        return []


def list_interfaces(tshark, mode):
    try:
        r = subprocess.run(wrap_cmd([tshark, "-D"], mode), capture_output=True, text=True, timeout=30)
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def choose_interface(tshark, mode):
    lines = list_interfaces(tshark, mode)
    default = "1" if os.name == "nt" or sys.platform == "darwin" else "any"
    if lines:
        print()
        print(c(255, "Available interfaces", True))
        for l in lines:
            m = re.match(r"(\d+)\.\s*(.*)", l)
            if m:
                print("  " + c(99, m.group(1).rjust(2), True) + " " + c(255, clip(m.group(2), term_cols() - 8)))
            else:
                print("  " + c(255, l))
        print()
    return ask(f"Interface [{default}]") or default


def base_cmd(tshark):
    cmd = [tshark, "-l", "-n", "-Q", "-T", "fields", "-E", "separator=/t"]
    for f in FIELDS:
        cmd += ["-e", f]
    return cmd


def first(v):
    return v.split(",")[0] if v else ""


def start_banner(text):
    print()
    print(c(48, "● ", True) + c(255, text, True) + c(245, "   Ctrl+C to stop"))
    print(rule(panel_width()))
    print()


def display_statistics():
    if not start_time:
        return
    w = panel_width()
    elapsed = int(time.time() - start_time)
    print()
    print(panel_top(w))
    print(panel_row(c(255, "STATISTICS", True) + c(245, f"  ·  uptime {elapsed}s"), w))
    print(panel_mid(w))
    print(split_row(c(245, "Total packets"), c(255, str(packet_stats["total"]), True), w))
    rows = [("tcp", "TCP", 51), ("udp", "UDP", 39), ("icmp", "ICMP", 203),
            ("dns", "DNS", 220), ("arp", "ARP", 177), ("other", "Other", 245)]
    for key, label, col in rows:
        print(split_row(c(col, "● ") + c(255, label), c(255, str(packet_stats[key])), w))
    if connections:
        print(panel_mid(w))
        print(panel_row(c(255, "TOP CONNECTIONS", True), w))
        top = sorted(connections.items(), key=lambda x: x[1], reverse=True)[:5]
        for conn, count in top:
            text = clip(conn, w - 4 - len(str(count)) - 2)
            print(split_row(c(111, text), c(48, str(count), True), w))
    print(panel_bot(w))
    print()


def handle_line(line):
    if not line.strip():
        return
    if "\t" not in line:
        print(c(214, "[tshark] ") + c(245, line.strip()))
        return
    p = line.rstrip("\n").split("\t")
    p += [""] * (len(FIELDS) - len(p))
    _, _, ip_s, ip_d, ip6_s, ip6_d, proto, length, tsp, tdp, usp, udp_, info = p[:13]

    src = first(ip_s) or first(ip6_s)
    dst = first(ip_d) or first(ip6_d)
    proto = proto or "OTHER"
    up = proto.upper()
    timestamp = datetime.now().strftime("%H:%M:%S")

    packet_stats["total"] += 1
    if up == "ARP":
        packet_stats["arp"] += 1
    elif up.startswith("ICMP"):
        packet_stats["icmp"] += 1
    elif tsp:
        packet_stats["tcp"] += 1
    elif usp:
        packet_stats["udp"] += 1
    else:
        packet_stats["other"] += 1
    if up in ("DNS", "MDNS", "LLMNR"):
        packet_stats["dns"] += 1

    color = next((v for k, v in PROTO_COLORS.items() if up.startswith(k)), 51 if tsp else 245)
    out = c(color, f"{proto[:8]:<8}", True) + " " + c(245, timestamp) + "  "
    if src or dst:
        out += c(111, src or "?") + c(245, " → ") + c(48, dst or "?")
        connections[f"{src} → {dst}"] += 1
    sport, dport = first(tsp) or first(usp), first(tdp) or first(udp_)
    if sport or dport:
        out += c(245, "  port ") + c(255, f"{sport} → {dport}")
    out += c(245, "  ·  ") + c(255, f"{length}B")
    print(out)
    if info:
        print("  " + c(240, "└ ") + c(244, clip(info, term_cols() - 6)))

    packet_log.append({"timestamp": timestamp, "protocol": proto, "src": src, "dst": dst,
                       "length": length, "info": info})
    if packet_stats["total"] % 20 == 0:
        display_statistics()


def run_tshark(cmd):
    global start_time
    start_time = time.time()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, errors="replace")
    except FileNotFoundError:
        err(f"Cannot start process: {cmd[0]}")
        return
    try:
        for line in proc.stdout:
            handle_line(line)
        proc.wait()
    except KeyboardInterrupt:
        print()
        warn("Stopping capture...")
    finally:
        try:
            proc.stdout.close()
            proc.terminate()
        except Exception:
            pass
    display_statistics()


def save_log_to_file():
    if not packet_log:
        return None
    filename = f"packet_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = os.path.join(os.getcwd(), filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("WIRESHARK ANALYZER - CAPTURE LOG\n")
        f.write(f"Capture Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        for e in packet_log:
            f.write(f"[{e['timestamp']}] {e['protocol']} | {e['src']} -> {e['dst']} | "
                    f"Length: {e['length']} | {e['info']}\n")
    ok(f"Log saved to {filepath}")
    return filepath


def finish():
    print()
    if packet_log:
        if ask("Save capture log? (y/n)").lower() == "y":
            save_log_to_file()
    print()
    print(rule(panel_width()))
    print(c(51, "Thank you for using Wireshark Analyzer!", True))
    print(c(245, f"Total packets: {packet_stats['total']}"))


def main():
    tshark = find_tshark()
    show_banner(tshark)

    if not tshark:
        err("Wireshark (tshark) is not installed.")
        note("Linux     sudo apt install tshark")
        note("Termux    pkg install tshark")
        note("Windows   install Wireshark from wireshark.org")
        return

    mode, label = detect_privilege()
    is_root = mode is not None
    show_status(label, is_root)
    show_menu(is_root)
    choice = ask("Select option (0-5)")

    if choice == "0":
        return

    if choice == "5":
        note("Example filter:  http   or   ip.addr == 1.1.1.1")
        path = ask("Path to .pcap/.pcapng").strip("'\"")
        if not os.path.isfile(path):
            err("File not found.")
            return
        dfilter = ask("Display filter (optional)")
        cmd = base_cmd(tshark) + ["-r", path]
        if dfilter:
            cmd += ["-Y", dfilter]
        start_banner("READING FILE")
        run_tshark(cmd)
        finish()
        return

    if choice not in ("1", "2", "3", "4"):
        err("Invalid choice.")
        return

    if not is_root:
        err("Live capture requires a rooted device / root privileges.")
        note("Use option 5 to analyze a capture file without root.")
        return

    bpf = ""
    if choice == "1":
        url = ask("Enter URL to monitor")
        ips = get_target_ips(url)
        if ips:
            ok(f"Resolved {url} to {', '.join(ips)}")
            bpf = " or ".join(f"host {ip}" for ip in ips)
        else:
            warn("Could not resolve URL. Monitoring all traffic instead.")
    elif choice == "2":
        ok("Monitoring all network traffic")
    elif choice == "3":
        proto = ask("Protocol (tcp/udp/icmp)").lower()
        if proto in ("tcp", "udp", "icmp"):
            bpf = proto
            ok(f"Monitoring {proto.upper()} traffic only")
        else:
            warn("Invalid protocol. Monitoring all traffic.")
    elif choice == "4":
        port = ask("Enter port number")
        if port.isdigit() and 0 < int(port) < 65536:
            bpf = f"port {port}"
            ok(f"Monitoring traffic on port {port}")
        else:
            warn("Invalid port. Monitoring all traffic.")

    iface = choose_interface(tshark, mode)
    cmd = base_cmd(tshark) + ["-i", iface]
    if bpf:
        cmd += ["-f", bpf]

    start_banner("CAPTURING")
    run_tshark(wrap_cmd(cmd, mode))
    finish()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
