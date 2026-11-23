import argparse
import ipaddress
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

MAX_PORT = 65535
DEFAULT_VISIBLE = {"open", "error"}


@dataclass(frozen=True)
class ScanResult:
    port: int
    status: str  # open | closed | no_response | error
    error: str | None = None


#validation
def ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid IPv4 address: {value!r}")


def positive(number_type):
    def parse(value):
        try:
            number = number_type(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid number: {value!r}")
        if number <= 0:
            raise argparse.ArgumentTypeError("must be greater than 0")
        return number
    return parse

#parsing
def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise argparse.ArgumentTypeError("empty element in port list")
        try:
            start, _, end = part.partition("-")
            start = int(start)
            end = int(end) if end else start
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid port format: {part!r}")
        if start > end:
            raise argparse.ArgumentTypeError(f"range start is greater than end: {part!r}")
        if start < 1 or end > MAX_PORT:
            raise argparse.ArgumentTypeError(f"ports must be between 1 and {MAX_PORT}: {part!r}")
        ports.update(range(start, end + 1))
    return sorted(ports)


def build_parser():
    p = argparse.ArgumentParser(description="Simple TCP connect scanner")
    p.add_argument("target", type=ipv4)
    p.add_argument("-p", "--ports", type=parse_ports, default="1-1024")
    p.add_argument("-t", "--timeout", type=positive(float), default=1.0)
    p.add_argument("-w", "--workers", type=positive(int), default=100)
    p.add_argument("-o", "--output")
    p.add_argument("--mode", choices=("sequential", "concurrent"), default="concurrent")
    p.add_argument("--show-all", action="store_true",
                   help="display closed and no-response ports as well")
    return p


#scanning
def scan_port(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
        return ScanResult(port, "open")
    except socket.timeout as e:
        return ScanResult(port, "no_response", str(e))
    except ConnectionRefusedError as e:
        return ScanResult(port, "closed", str(e))
    except OSError as e:
        return ScanResult(port, "error", str(e))


def scan(ip, ports, timeout, mode, workers):
    def task(port):
        return scan_port(ip, port, timeout)

    if mode == "sequential":
        return [task(p) for p in ports]
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(task, ports))  # preserves port order


#reporting
def build_report(stats, results, show_all):
    lines = ["=" * 10 + " Statistics " + "=" * 10, ""]
    lines += [f"{key}: {value}" for key, value in stats.items()]
    lines += ["", "=" * 12 + " Results " + "=" * 12, "",
              f"{'PORT':<14}STATUS", "-" * 20]

    for r in results:
        if not (show_all or r.status in DEFAULT_VISIBLE):
            continue
        line = f"{r.port:<14}{r.status}"
        if r.status == "error" and r.error:
            line += f": {r.error}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def main(argv=None):
    args = build_parser().parse_args(argv)

    start = time.perf_counter()
    results = scan(args.target, args.ports, args.timeout, args.mode, args.workers)
    elapsed_ms = (time.perf_counter() - start) * 1000

    counts = Counter(r.status for r in results)
    stats = {
        "Target": args.target,
        "Scan Type": "TCP Connect",
        "Scan Mode": args.mode,
        "Duration": f"{elapsed_ms:.2f} ms",
        "Ports Scanned": len(results),
        "Open Ports": counts["open"],
        "Closed Ports": counts["closed"],
        "No Response": counts["no_response"],
        "Errors": counts["error"],
        "Timeout": args.timeout,
        "Workers": args.workers if args.mode == "concurrent" else 1,
    }

    report = build_report(stats, results, args.show_all)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report, end="")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
