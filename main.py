#!/usr/bin/env python3
import sys
from typing import List

from cli import parse_arguments
from port_scanner import create_scanner
from models import HostScanResult
from output_formatter import OutputFormatter


def main(argv: List[str] = None) -> int:
    try:
        args = parse_arguments(argv)
    except SystemExit as e:
        return e.code

    formatter = OutputFormatter(verbose=args.verbose)

    formatter.set_batch_mode(
        total_hosts=len(args.hosts),
        ports_per_host=len(args.ports_list),
    )

    formatter.print_header(
        hosts=args.hosts,
        ports=args.ports_list,
        scan_type=args.scan_type.value,
    )

    scanner = create_scanner(
        scan_type=args.scan_type,
        timeout=args.timeout,
        max_threads=args.threads,
        identify_services=args.identify_services,
        grab_banners=args.grab_banners,
    )

    if args.show_progress:
        scanner.set_progress_callback(formatter.print_progress)

    all_results: List[HostScanResult] = []

    try:
        for i, host in enumerate(args.hosts, 1):
            formatter.start_host(i, host)

            result = scanner.scan_host(
                host=host,
                ports=args.ports_list,
                scan_type=args.scan_type,
            )

            formatter.finish_host(len(result.open_ports))
            all_results.append(result)
            formatter.print_host_result(result)

    except KeyboardInterrupt:
        formatter.clear_progress()
        print("\n\n扫描被用户中断。")
        if all_results:
            formatter.print_batch_summary(all_results)
        return 130

    formatter.print_batch_summary(all_results)

    total_open = sum(len(r.open_ports) for r in all_results)
    return 0 if total_open > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
