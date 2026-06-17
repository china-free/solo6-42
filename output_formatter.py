import sys
from typing import List, Dict, Set
from collections import defaultdict
from models import HostScanResult, PortResult, PortState


class OutputFormatter:
    def __init__(self, verbose: int = 0):
        self.verbose = verbose
        self._last_progress_line = ""
        self._batch_mode = False
        self._total_hosts = 0
        self._ports_per_host = 0
        self._hosts_done = 0
        self._cumulative_open = 0

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

    def set_batch_mode(self, total_hosts: int, ports_per_host: int) -> None:
        self._batch_mode = total_hosts > 1
        self._total_hosts = total_hosts
        self._ports_per_host = ports_per_host
        self._hosts_done = 0
        self._cumulative_open = 0

    def start_host(self, host_index: int, host: str) -> None:
        self._hosts_done = host_index - 1
        self.clear_progress()
        if self._batch_mode:
            print(f"\n[{host_index}/{self._total_hosts}] Scanning: {host}")

    def finish_host(self, open_count: int) -> None:
        self._hosts_done += 1
        self._cumulative_open += open_count

    def print_progress(self, current: int, total: int, open_count: int) -> None:
        if total == 0:
            return

        if not self._batch_mode:
            percent = (current / total) * 100
            bar_length = 40
            filled = int(bar_length * current / total)
            bar = "█" * filled + "░" * (bar_length - filled)
            progress_line = f"\rScanning: |{bar}| {percent:5.1f}% ({current}/{total}) Open: {open_count}"
        else:
            overall_done = self._hosts_done * total + current
            overall_total = self._total_hosts * total
            overall_percent = (overall_done / overall_total) * 100 if overall_total > 0 else 0

            bar_length = 30
            current_filled = int(bar_length * current / total)
            current_bar = "█" * current_filled + "░" * (bar_length - current_filled)
            current_pct = (current / total) * 100

            overall_filled = int(bar_length * overall_done / overall_total) if overall_total > 0 else 0
            overall_bar = "█" * overall_filled + "░" * (bar_length - overall_filled)

            cumulative_total = self._cumulative_open + open_count

            progress_line = (
                f"\r  当前主机: |{current_bar}| {current_pct:5.1f}%  "
                f"总体: |{overall_bar}| {overall_percent:5.1f}%  "
                f"主机: {self._hosts_done + 1}/{self._total_hosts}  "
                f"累计开放: {cumulative_total}"
            )

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
        else:
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

    def print_batch_summary(self, all_results: List[HostScanResult]) -> None:
        self.clear_progress()
        print(f"\n{'=' * 70}")
        print("BATCH SCAN SUMMARY")
        print(f"{'=' * 70}")
        print(f"\n结束时间:   {self._get_current_time()}")

        total_open = sum(len(r.open_ports) for r in all_results)
        total_scanned = sum(len(r.ports) for r in all_results)

        print(f"扫描主机:   {len(all_results)}")
        print(f"扫描端口:   {total_scanned}")
        print(f"开放端口:   {total_open}")

        if len(all_results) > 1:
            print()
            self._print_summary_by_host(all_results)
            print()
            self._print_summary_by_port(all_results)
            print()
            self._print_summary_by_service(all_results)
        else:
            print()
            self._print_summary_by_host(all_results)

        print(f"\n{'=' * 70}")

    def _print_summary_by_host(self, all_results: List[HostScanResult]) -> None:
        print(f"{'─' * 70}")
        print("【按主机查看】")
        print(f"{'─' * 70}")
        print(f"{'主机':<25} {'开放数':<8} {'开放端口列表'}")
        print(f"{'-' * 25} {'-' * 8} {'-' * 37}")

        for result in all_results:
            host_display = result.host[:24] if len(result.host) > 24 else result.host
            open_ports = [str(r.port) for r in result.open_ports]
            if open_ports:
                ports_str = ", ".join(open_ports[:10])
                if len(open_ports) > 10:
                    ports_str += f" ... (+{len(open_ports) - 10})"
                print(f"{host_display:<25} {len(open_ports):<8} {ports_str}")
            else:
                print(f"{host_display:<25} 0        (无开放端口)")

    def _print_summary_by_port(self, all_results: List[HostScanResult]) -> None:
        port_to_hosts: Dict[int, Set[str]] = defaultdict(set)
        port_to_service: Dict[int, str] = {}

        for result in all_results:
            for port_result in result.open_ports:
                port_to_hosts[port_result.port].add(result.host)
                if port_result.port not in port_to_service:
                    port_to_service[port_result.port] = port_result.service

        print(f"{'─' * 70}")
        print("【按端口查看】")
        print(f"{'─' * 70}")
        print(f"{'端口':<10} {'服务':<20} {'开放主机数':<10} {'主机列表'}")
        print(f"{'-' * 10} {'-' * 20} {'-' * 10} {'-' * 30}")

        sorted_ports = sorted(port_to_hosts.keys(), key=lambda p: (-len(port_to_hosts[p]), p))

        for port in sorted_ports:
            hosts = port_to_hosts[port]
            service = port_to_service.get(port, "unknown")
            service_display = service[:19] if len(service) > 19 else service

            host_list = sorted(hosts)
            hosts_str = ", ".join(h[:12] for h in host_list[:3])
            if len(hosts) > 3:
                hosts_str += f" ... (+{len(hosts) - 3})"

            print(f"{port:<10} {service_display:<20} {len(hosts):<10} {hosts_str}")

    def _print_summary_by_service(self, all_results: List[HostScanResult]) -> None:
        service_to_ports: Dict[str, Set[int]] = defaultdict(set)
        service_to_hosts: Dict[str, Set[str]] = defaultdict(set)
        service_count: Dict[str, int] = defaultdict(int)

        for result in all_results:
            for port_result in result.open_ports:
                service = port_result.service or "unknown"
                service_to_ports[service].add(port_result.port)
                service_to_hosts[service].add(result.host)
                service_count[service] += 1

        print(f"{'─' * 70}")
        print("【按服务查看】")
        print(f"{'─' * 70}")
        print(f"{'服务':<22} {'实例数':<8} {'主机数':<8} {'端口列表'}")
        print(f"{'-' * 22} {'-' * 8} {'-' * 8} {'-' * 32}")

        sorted_services = sorted(service_count.keys(), key=lambda s: (-service_count[s], s))

        for service in sorted_services:
            count = service_count[service]
            hosts = service_to_hosts[service]
            ports = sorted(service_to_ports[service])
            service_display = service[:21] if len(service) > 21 else service

            ports_str = ", ".join(str(p) for p in ports[:5])
            if len(ports) > 5:
                ports_str += f" ... (+{len(ports) - 5})"

            print(f"{service_display:<22} {count:<8} {len(hosts):<8} {ports_str}")

    @staticmethod
    def _get_current_time() -> str:
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
