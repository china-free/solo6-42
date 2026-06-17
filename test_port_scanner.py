import unittest
import errno
import io
import sys
from cli import parse_ports, parse_port_range
from models import ScanType, PortState, PortResult, HostScanResult
from service_identifier import ServiceIdentifier, COMMON_PORTS
from port_scanner import _classify_connect_error
from output_formatter import OutputFormatter


class TestPortParsing(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(parse_port_range("80"), [80])

    def test_port_range(self):
        self.assertEqual(parse_port_range("1-10"), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

    def test_comma_separated_ports(self):
        self.assertEqual(parse_ports("80,443,8080"), [80, 443, 8080])

    def test_mixed_ports(self):
        self.assertEqual(parse_ports("80,100-102,443"), [80, 100, 101, 102, 443])

    def test_invalid_port_low(self):
        with self.assertRaises(ValueError):
            parse_port_range("0")

    def test_invalid_port_high(self):
        with self.assertRaises(ValueError):
            parse_port_range("65536")

    def test_invalid_range(self):
        with self.assertRaises(ValueError):
            parse_port_range("100-50")


class TestModels(unittest.TestCase):
    def test_scan_type_enum(self):
        self.assertEqual(ScanType.TCP_CONNECT.value, "tcp-connect")
        self.assertEqual(ScanType.TCP_SYN.value, "tcp-syn")

    def test_port_state_enum(self):
        self.assertEqual(PortState.OPEN.value, "open")
        self.assertEqual(PortState.CLOSED.value, "closed")
        self.assertEqual(PortState.FILTERED.value, "filtered")

    def test_port_result_str(self):
        result = PortResult(
            port=80,
            state=PortState.OPEN,
            service="HTTP",
            response_time=12.345,
        )
        self.assertIn("80: HTTP", str(result))
        self.assertIn("12.35ms", str(result))


class TestConnectErrorClassification(unittest.TestCase):
    def test_success_is_open(self):
        self.assertEqual(_classify_connect_error(0), PortState.OPEN)

    def test_econnrefused_is_closed_posix(self):
        self.assertEqual(_classify_connect_error(errno.ECONNREFUSED), PortState.CLOSED)

    def test_econnrefused_is_closed_windows(self):
        self.assertEqual(_classify_connect_error(10061), PortState.CLOSED)

    def test_etimedout_is_filtered_posix(self):
        self.assertEqual(_classify_connect_error(errno.ETIMEDOUT), PortState.FILTERED)

    def test_etimedout_is_filtered_windows(self):
        self.assertEqual(_classify_connect_error(10060), PortState.FILTERED)

    def test_ehostunreach_is_filtered_posix(self):
        self.assertEqual(_classify_connect_error(errno.EHOSTUNREACH), PortState.FILTERED)

    def test_ehostunreach_is_filtered_windows(self):
        self.assertEqual(_classify_connect_error(10065), PortState.FILTERED)

    def test_enetunreach_is_filtered_posix(self):
        self.assertEqual(_classify_connect_error(errno.ENETUNREACH), PortState.FILTERED)

    def test_enetunreach_is_filtered_windows(self):
        self.assertEqual(_classify_connect_error(10051), PortState.FILTERED)

    def test_unknown_error_defaults_to_closed(self):
        self.assertEqual(_classify_connect_error(99999), PortState.CLOSED)


class TestBatchSummary(unittest.TestCase):
    def _create_mock_result(self, host: str, open_ports_dict: dict) -> HostScanResult:
        result = HostScanResult(
            host=host,
            scan_type=ScanType.TCP_CONNECT,
            ports=[1, 2, 3, 4, 5],
        )
        for port, service in open_ports_dict.items():
            result.results.append(PortResult(
                port=port,
                state=PortState.OPEN,
                service=service,
                response_time=1.23,
            ))
        for port in [p for p in [1, 2, 3, 4, 5] if p not in open_ports_dict]:
            result.results.append(PortResult(
                port=port,
                state=PortState.CLOSED,
                service="unknown",
            ))
        return result

    def test_single_host_summary(self):
        formatter = OutputFormatter()
        results = [self._create_mock_result("host1", {80: "HTTP", 443: "HTTPS"})]

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            formatter.print_batch_summary(results)
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()
        self.assertIn("【按主机查看】", output)
        self.assertIn("host1", output)
        self.assertNotIn("【按端口查看】", output)

    def test_multi_host_summary_has_three_views(self):
        formatter = OutputFormatter()
        results = [
            self._create_mock_result("host1", {80: "HTTP"}),
            self._create_mock_result("host2", {80: "HTTP", 22: "SSH"}),
        ]

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            formatter.print_batch_summary(results)
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()
        self.assertIn("【按主机查看】", output)
        self.assertIn("【按端口查看】", output)
        self.assertIn("【按服务查看】", output)

    def test_by_port_view_sorted_by_host_count(self):
        formatter = OutputFormatter()
        results = [
            self._create_mock_result("host1", {80: "HTTP", 22: "SSH", 443: "HTTPS"}),
            self._create_mock_result("host2", {80: "HTTP", 443: "HTTPS"}),
            self._create_mock_result("host3", {80: "HTTP"}),
        ]

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            formatter.print_batch_summary(results)
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()

        port_section_start = output.index("【按端口查看】")
        port_section = output[port_section_start:]

        lines = port_section.strip().split("\n")
        port_lines = [
            line for line in lines
            if line.strip() and not line.startswith("─")
            and not line.startswith("【")
            and not line.startswith("端口")
            and not line.startswith("---")
        ]

        ports_in_order = []
        for line in port_lines:
            parts = line.split()
            if parts and parts[0].isdigit():
                ports_in_order.append(int(parts[0]))

        self.assertEqual(ports_in_order[0], 80)
        self.assertEqual(ports_in_order[1], 443)
        self.assertEqual(ports_in_order[2], 22)

    def test_by_service_view_aggregates_correctly(self):
        formatter = OutputFormatter()
        results = [
            self._create_mock_result("host1", {80: "HTTP", 8080: "HTTP-Proxy"}),
            self._create_mock_result("host2", {80: "HTTP", 443: "HTTPS"}),
            self._create_mock_result("host3", {8080: "HTTP-Proxy"}),
        ]

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            formatter.print_batch_summary(results)
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()
        self.assertIn("HTTP", output)
        self.assertIn("HTTPS", output)
        self.assertIn("HTTP-Proxy", output)

    def test_batch_mode_progress(self):
        formatter = OutputFormatter()
        formatter.set_batch_mode(total_hosts=3, ports_per_host=100)

        self.assertTrue(formatter._batch_mode)
        self.assertEqual(formatter._total_hosts, 3)
        self.assertEqual(formatter._ports_per_host, 100)

        formatter.start_host(1, "host1")
        formatter.finish_host(5)

        self.assertEqual(formatter._hosts_done, 1)
        self.assertEqual(formatter._cumulative_open, 5)

    def test_single_host_batch_mode_disabled(self):
        formatter = OutputFormatter()
        formatter.set_batch_mode(total_hosts=1, ports_per_host=100)
        self.assertFalse(formatter._batch_mode)


class TestServiceIdentifier(unittest.TestCase):
    def setUp(self):
        self.identifier = ServiceIdentifier()

    def test_identify_by_port_known(self):
        self.assertEqual(self.identifier.identify_by_port(80), "HTTP")
        self.assertEqual(self.identifier.identify_by_port(443), "HTTPS")
        self.assertEqual(self.identifier.identify_by_port(22), "SSH")
        self.assertEqual(self.identifier.identify_by_port(21), "FTP")
        self.assertEqual(self.identifier.identify_by_port(3306), "MySQL")

    def test_identify_by_port_unknown(self):
        self.assertEqual(self.identifier.identify_by_port(61001), "unknown")

    def test_identify_by_banner_ssh(self):
        banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
        self.assertEqual(self.identifier.identify_by_banner(banner), "SSH")

    def test_identify_by_banner_http(self):
        banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41"
        self.assertEqual(self.identifier.identify_by_banner(banner), "HTTP")

    def test_identify_by_banner_ftp(self):
        banner = "220 FTP Server ready."
        self.assertEqual(self.identifier.identify_by_banner(banner), "FTP")

    def test_common_ports_coverage(self):
        well_known_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080]
        for port in well_known_ports:
            self.assertIn(port, COMMON_PORTS, f"Port {port} should be in COMMON_PORTS")

    def test_port_result_defaults(self):
        result = PortResult(port=8080, state=PortState.OPEN)
        self.assertEqual(result.service, "unknown")
        self.assertEqual(result.response_time, 0.0)
        self.assertIsNone(result.banner)


if __name__ == "__main__":
    unittest.main(verbosity=2)
