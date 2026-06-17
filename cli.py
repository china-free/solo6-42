import argparse
import sys
from typing import List, Tuple
from pathlib import Path

from models import ScanType


def parse_port_range(port_range_str: str) -> List[int]:
    if "-" in port_range_str:
        parts = port_range_str.split("-", 1)
        try:
            start = int(parts[0])
            end = int(parts[1])
            if start < 1 or end > 65535 or start > end:
                raise ValueError
        except (ValueError, IndexError):
            raise ValueError(
                f"Invalid port range: {port_range_str}. "
                "Use format 'start-end' where 1 <= start <= end <= 65535"
            )
        return list(range(start, end + 1))
    else:
        try:
            port = int(port_range_str)
            if port < 1 or port > 65535:
                raise ValueError
        except ValueError:
            raise ValueError(
                f"Invalid port: {port_range_str}. Port must be between 1 and 65535"
            )
        return [port]


def parse_ports(ports_str: str) -> List[int]:
    ports = set()
    for part in ports_str.split(","):
        part = part.strip()
        if part:
            ports.update(parse_port_range(part))
    return sorted(ports)


def read_hosts_from_file(file_path: str) -> List[str]:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Hosts file not found: {file_path}")

    hosts = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)

    if not hosts:
        raise ValueError(f"No valid hosts found in file: {file_path}")

    return hosts


def parse_arguments(argv: List[str] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Port Scanner - Scan hosts for open ports and identify services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single host on default ports (1-1024) using TCP Connect
  %(prog)s 192.168.1.1

  # Scan a domain with custom port range using TCP SYN (simulated)
  %(prog)s example.com -p 1-1000 -t tcp-syn

  # Scan multiple hosts from a file with custom threads and timeout
  %(prog)s -f hosts.txt -p 80,443,8080 -T 200 --timeout 3

  # Scan without service identification (faster)
  %(prog)s 10.0.0.1 --no-service-id

  # Scan without banner grabbing
  %(prog)s 10.0.0.1 --no-banner
        """,
    )

    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument(
        "host",
        nargs="?",
        help="Target host (IP address or domain name)",
    )
    host_group.add_argument(
        "-f",
        "--host-file",
        metavar="FILE",
        help="File containing a list of hosts to scan (one per line)",
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="Port range to scan (default: 1-1024). "
        "Can be a single port (80), range (1-1000), "
        "or comma-separated list (80,443,8080-8090)",
    )

    parser.add_argument(
        "-t",
        "--scan-type",
        choices=[st.value for st in ScanType],
        default=ScanType.TCP_CONNECT.value,
        help="Scan type to use (default: tcp-connect)",
    )

    parser.add_argument(
        "-T",
        "--threads",
        type=int,
        default=100,
        help="Maximum number of concurrent threads (default: 100)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Timeout in seconds for each connection (default: 2.0)",
    )

    parser.add_argument(
        "--no-service-id",
        action="store_true",
        help="Disable service identification (faster scan)",
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable banner grabbing (faster, less accurate service ID)",
    )

    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bar during scanning",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase output verbosity (use -vv for more details)",
    )

    args = parser.parse_args(argv)

    try:
        args.ports_list = parse_ports(args.ports)
        args.scan_type = ScanType(args.scan_type)
        args.identify_services = not args.no_service_id
        args.grab_banners = not args.no_banner
        args.show_progress = not args.no_progress
    except ValueError as e:
        parser.error(str(e))

    if args.host_file:
        try:
            args.hosts = read_hosts_from_file(args.host_file)
        except (FileNotFoundError, ValueError) as e:
            parser.error(str(e))
    else:
        args.hosts = [args.host]

    return args
