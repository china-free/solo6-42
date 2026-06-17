from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class ScanType(str, Enum):
    TCP_CONNECT = "tcp-connect"
    TCP_SYN = "tcp-syn"


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass
class PortResult:
    port: int
    state: PortState
    service: str = "unknown"
    response_time: float = 0.0
    banner: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.port}: {self.service} ({self.state}, {self.response_time:.2f}ms)"


@dataclass
class HostScanResult:
    host: str
    scan_type: ScanType
    ports: List[int]
    results: List[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> List[PortResult]:
        return [r for r in self.results if r.state == PortState.OPEN]

    def __str__(self) -> str:
        lines = [f"Host: {self.host} (Scan type: {self.scan_type.value})"]
        lines.append(f"Scanned ports: {min(self.ports)}-{max(self.ports)}")
        lines.append(f"Open ports: {len(self.open_ports)}")
        if self.open_ports:
            lines.append("\nOpen Ports Details:")
            for result in self.open_ports:
                lines.append(f"  {result}")
                if result.banner:
                    lines.append(f"    Banner: {result.banner[:100]}")
        return "\n".join(lines)
