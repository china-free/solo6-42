import socket
import time
import errno
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Callable
from abc import ABC, abstractmethod

from models import PortResult, PortState, HostScanResult, ScanType
from service_identifier import ServiceIdentifier


def _classify_connect_error(error_code: int) -> PortState:
    if error_code == 0:
        return PortState.OPEN

    closed_codes = (
        errno.ECONNREFUSED,
        getattr(errno, "WSAECONNREFUSED", 10061),
    )
    filtered_codes = (
        errno.ETIMEDOUT,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        getattr(errno, "WSAETIMEDOUT", 10060),
        getattr(errno, "WSAEHOSTUNREACH", 10065),
        getattr(errno, "WSAENETUNREACH", 10051),
    )

    if error_code in closed_codes:
        return PortState.CLOSED
    if error_code in filtered_codes:
        return PortState.FILTERED

    return PortState.CLOSED


class PortScannerBase(ABC):
    def __init__(
        self,
        timeout: float = 2.0,
        max_threads: int = 100,
        identify_services: bool = True,
        grab_banners: bool = True,
    ):
        self.timeout = timeout
        self.max_threads = max_threads
        self.identify_services = identify_services
        self.grab_banners = grab_banners
        self.service_identifier = ServiceIdentifier(banner_timeout=timeout)
        self._progress_callback: Optional[Callable[[int, int, int], None]] = None

    def set_progress_callback(self, callback: Callable[[int, int, int], None]) -> None:
        self._progress_callback = callback

    def _report_progress(self, current: int, total: int, open_count: int) -> None:
        if self._progress_callback:
            self._progress_callback(current, total, open_count)

    @abstractmethod
    def _scan_port(self, host: str, port: int) -> PortResult:
        pass

    def _resolve_host(self, host: str) -> str:
        try:
            ip = socket.gethostbyname(host)
            return ip
        except socket.gaierror:
            return host

    def scan_host(
        self,
        host: str,
        ports: List[int],
        scan_type: ScanType,
    ) -> HostScanResult:
        resolved_host = self._resolve_host(host)
        result = HostScanResult(
            host=host,
            scan_type=scan_type,
            ports=ports,
        )

        total_ports = len(ports)
        completed = 0
        open_count = 0

        self._report_progress(completed, total_ports, open_count)

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self._scan_port, resolved_host, port): port
                for port in ports
            }

            for future in as_completed(future_to_port):
                port_result = future.result()
                result.results.append(port_result)

                if port_result.state == PortState.OPEN:
                    open_count += 1

                completed += 1
                self._report_progress(completed, total_ports, open_count)

        result.results.sort(key=lambda x: x.port)
        return result


class TCPConnectScanner(PortScannerBase):
    def _scan_port(self, host: str, port: int) -> PortResult:
        result = PortResult(port=port, state=PortState.CLOSED)
        connect_result = None

        try:
            start_time = time.perf_counter()

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                connect_result = sock.connect_ex((host, port))

                end_time = time.perf_counter()
                result.response_time = (end_time - start_time) * 1000

                if connect_result == 0:
                    result.state = PortState.OPEN

                    if self.identify_services:
                        service, banner = self.service_identifier.identify_service(
                            host, port, grab_banner=self.grab_banners
                        )
                        result.service = service
                        result.banner = banner
                else:
                    result.state = _classify_connect_error(connect_result)

        except socket.timeout:
            result.state = PortState.FILTERED
        except ConnectionRefusedError:
            result.state = PortState.CLOSED
        except (BlockingIOError, OSError) as e:
            error_code = getattr(e, "errno", None)
            if error_code is not None:
                result.state = _classify_connect_error(error_code)
            else:
                result.state = PortState.CLOSED
        except Exception:
            result.state = PortState.CLOSED

        return result


class TCPSynScanner(PortScannerBase):
    def _scan_port(self, host: str, port: int) -> PortResult:
        result = PortResult(port=port, state=PortState.CLOSED)

        try:
            start_time = time.perf_counter()

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.setblocking(False)

                try:
                    sock.connect((host, port))
                except BlockingIOError:
                    pass
                except Exception:
                    result.state = PortState.CLOSED
                    return result

                time.sleep(0.01)

                try:
                    data = sock.recv(1024)
                    if data:
                        result.state = PortState.OPEN
                    else:
                        result.state = PortState.OPEN
                except BlockingIOError:
                    result.state = PortState.OPEN
                except socket.timeout:
                    result.state = PortState.FILTERED
                except Exception:
                    result.state = PortState.CLOSED

                end_time = time.perf_counter()
                result.response_time = (end_time - start_time) * 1000

                if result.state == PortState.OPEN and self.identify_services:
                    service, banner = self.service_identifier.identify_service(
                        host, port, grab_banner=self.grab_banners
                    )
                    result.service = service
                    result.banner = banner

        except Exception:
            result.state = PortState.CLOSED

        return result


def create_scanner(
    scan_type: ScanType,
    timeout: float = 2.0,
    max_threads: int = 100,
    identify_services: bool = True,
    grab_banners: bool = True,
) -> PortScannerBase:
    if scan_type == ScanType.TCP_CONNECT:
        return TCPConnectScanner(
            timeout=timeout,
            max_threads=max_threads,
            identify_services=identify_services,
            grab_banners=grab_banners,
        )
    elif scan_type == ScanType.TCP_SYN:
        return TCPSynScanner(
            timeout=timeout,
            max_threads=max_threads,
            identify_services=identify_services,
            grab_banners=grab_banners,
        )
    else:
        raise ValueError(f"Unsupported scan type: {scan_type}")
