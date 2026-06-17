import sys
from typing import List
from models import HostScanResult, PortResult, PortState


class OutputFormatter:
    def __init__(self, verbose: int = 0):
        self.verbose = verbose
        self._last_progress_line = ""

    def print_header(self, hosts: List[str], ports: List[int], scan_type: str) -> None:
        print("=" * 70)
        print("PORT SCANNER")
        print("=" * 70)
        print(f"Target(s):    {', '.join(hosts)}")
        print(f"Port range:   {min(ports)}-{max(ports)} ({len(ports)} ports)")
        print(f"Scan type:    {scan_type}")
        print(f"Start time:   {self._get_current_time()}")
        print("=" * 70)
        print()

    def print_progress(self, current: int, total: int, open_count: int) -> None:
        if total == 0:
            return

        percent = (current / total) * 100
        bar_length = 40
        filled = int(bar_length * current / total)
        bar = "█" * filled + "░" * (bar_length - filled)

        progress_line = f"\rScanning: |{bar}| {percent:5.1f}% ({current}/{total}) Open: {open_count}"

        sys.stdout.write(progress_line)
        sys.stdout.flush()
        self._last_progress_line = progress_line

    def clear_progress(self) -> None:
        if self._last_progress_line:
            sys.stdout.write("\r" + " " * len(self._last_progress_line) + "\r")
            sys.stdout.flush()
            self._last_progress_line = ""

    def print_host_result(self, result: HostScanResult) -> None:
        self.clear_progress()

        print(f"\n{'=' * 70}")
        print(f"SCAN RESULTS FOR: {result.host}")
        print(f"{'=' * 70}")

        if not result.open_ports:
            print("No open ports found.")
            return

        print(f"\nFound {len(result.open_ports)} open port(s):\n")

        print(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<20} {'RESPONSE TIME':<15}")
        print(f"{'-' * 8} {'-' * 10} {'-' * 20} {'-' * 15}")

        for port_result in result.open_ports:
            self._print_port_row(port_result)

        if self.verbose >= 1:
            self._print_verbose_details(result)

        if self.verbose >= 2:
            self._print_closed_ports_summary(result)

    def _print_port_row(self, port_result: PortResult) -> None:
        port_str = str(port_result.port)
        state_str = port_result.state.value.upper()
        service_str = port_result.service or "unknown"
        time_str = f"{port_result.response_time:.2f} ms"

        print(f"{port_str:<8} {state_str:<10} {service_str:<20} {time_str:<15}")

        if self.verbose >= 1 and port_result.banner:
            banner_preview = port_result.banner[:100]
            banner_preview = banner_preview.replace("\n", "\\n").replace("\r", "\\r")
            print(f"{' ' * 8} {' ' * 10} Banner: {banner_preview}")

    def _print_verbose_details(self, result: HostScanResult) -> None:
        print(f"\n{'=' * 70}")
        print("DETAILED INFORMATION")
        print(f"{'=' * 70}")

        print(f"\nScan type:      {result.scan_type.value}")
        print(f"Total scanned:  {len(result.ports)} ports")
        print(f"Open:           {len(result.open_ports)}")
        print(f"Closed:         {len([r for r in result.results if r.state == PortState.CLOSED])}")
        print(f"Filtered:       {len([r for r in result.results if r.state == PortState.FILTERED])}")

        if result.open_ports:
            print(f"\nOpen ports with full banner info:")
            for port_result in result.open_ports:
                print(f"\n  Port {port_result.port} ({port_result.service}):")
                if port_result.banner:
                    banner_lines = port_result.banner.splitlines()[:10]
                    for line in banner_lines:
                        print(f"    {line}")
                    if len(port_result.banner.splitlines()) > 10:
                        print(f"    ... (truncated)")
                else:
                    print("    (no banner received)")

    def _print_closed_ports_summary(self, result: HostScanResult) -> None:
        closed_ports = [r for r in result.results if r.state != PortState.OPEN]
        if closed_ports:
            print(f"\n{'=' * 70}")
            print("CLOSED/FILTERED PORTS SUMMARY")
            print(f"{'=' * 70}")
            print(f"\nTotal non-open ports: {len(closed_ports)}")

            filtered = [r for r in closed_ports if r.state == PortState.FILTERED]
            if filtered:
                print(f"\nFiltered ports ({len(filtered)}):")
                port_nums = [str(r.port) for r in filtered]
                print(f"  {', '.join(port_nums[:50])}")
                if len(port_nums) > 50:
                    print(f"  ... and {len(port_nums) - 50} more")

    def print_summary(self, all_results: List[HostScanResult]) -> None:
        self.clear_progress()
        print(f"\n{'=' * 70}")
        print("SCAN SUMMARY")
        print(f"{'=' * 70}")
        print(f"\nEnd time:     {self._get_current_time()}")

        total_open = sum(len(r.open_ports) for r in all_results)
        total_scanned = sum(len(r.ports) for r in all_results)

        print(f"Total hosts:  {len(all_results)}")
        print(f"Total ports:  {total_scanned}")
        print(f"Total open:   {total_open}")
        print()

        for result in all_results:
            open_ports = [str(r.port) for r in result.open_ports]
            if open_ports:
                print(f"  {result.host}: {len(open_ports)} open - {', '.join(open_ports)}")
            else:
                print(f"  {result.host}: No open ports")

        print(f"\n{'=' * 70}")

    @staticmethod
    def _get_current_time() -> str:
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
