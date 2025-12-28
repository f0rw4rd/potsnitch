"""Main scanner orchestrator."""

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

from potsnitch.core.registry import DetectorRegistry
from potsnitch.core.result import DetectionResult, ScanReport
from potsnitch.utils.network import scan_ports


class HoneypotScanner:
    """Main honeypot scanner orchestrator."""

    def __init__(
        self,
        timeout: float = 5.0,
        max_workers: int = 10,
        verbose: bool = False,
    ):
        """Initialize scanner.

        Args:
            timeout: Connection timeout in seconds
            max_workers: Maximum concurrent scan threads
            verbose: Enable verbose output
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.verbose = verbose

        # Load all detectors
        DetectorRegistry.load_detectors()

    def scan(
        self,
        target: str,
        ports: Optional[list[int]] = None,
        modules: Optional[list[str]] = None,
    ) -> ScanReport:
        """Scan a target for honeypots.

        Args:
            target: IP address or hostname
            ports: Specific ports to scan (None = auto-detect from modules)
            modules: Specific detector modules to use (None = all)

        Returns:
            ScanReport with all findings
        """
        report = ScanReport(target=target, scan_time=datetime.utcnow())

        # Get detectors to use
        detectors = self._get_detectors(modules)

        # Determine ports to scan
        if ports is None:
            ports = self._get_default_ports(detectors)

        # First, find open ports
        if self.verbose:
            print(f"Scanning {len(ports)} ports on {target}...")

        open_ports = scan_ports(target, ports, timeout=self.timeout)

        if self.verbose:
            print(f"Found {len(open_ports)} open ports: {open_ports}")

        if not open_ports:
            return report

        # Run detectors on open ports
        results = self._run_detectors(target, open_ports, detectors)
        report.detections = results

        return report

    def scan_range(
        self,
        network: str,
        ports: Optional[list[int]] = None,
        modules: Optional[list[str]] = None,
    ) -> list[ScanReport]:
        """Scan a network range for honeypots.

        Args:
            network: CIDR notation (e.g., "192.168.1.0/24")
            ports: Specific ports to scan
            modules: Specific detector modules to use

        Returns:
            List of ScanReports for hosts with findings
        """
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid network: {e}")

        reports = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.scan, str(ip), ports, modules): str(ip)
                for ip in net.hosts()
            }

            for future in as_completed(futures):
                ip = futures[future]
                try:
                    report = future.result()
                    if report.has_honeypot:
                        reports.append(report)
                except Exception as e:
                    if self.verbose:
                        print(f"Error scanning {ip}: {e}")

        return reports

    def validate(
        self,
        target: str,
        honeypot_type: str,
        port: Optional[int] = None,
    ) -> tuple[DetectionResult, list[str]]:
        """Run validation tests for a specific honeypot type.

        Args:
            target: IP address or hostname
            honeypot_type: Type of honeypot to validate (e.g., "cowrie")
            port: Specific port (None = use default)

        Returns:
            Tuple of (DetectionResult, list of recommendations)
        """
        # Find detectors for this honeypot type
        detectors = DetectorRegistry.get_detectors_for_honeypot(honeypot_type)

        if not detectors:
            raise ValueError(f"No detector found for honeypot type: {honeypot_type}")

        detector_class = detectors[0]
        detector = detector_class(timeout=self.timeout, verbose=self.verbose)

        # Use provided port or first default port
        if port is None:
            port = detector.default_ports[0] if detector.default_ports else 22

        # Run validation
        result = detector.validate(target, port)
        result.honeypot_type = honeypot_type

        # Get recommendations
        recommendations = detector.get_recommendations(result)

        return result, recommendations

    def _get_detectors(self, modules: Optional[list[str]]) -> list:
        """Get detector classes to use."""
        all_detectors = DetectorRegistry.get_all_detectors()

        if modules is None:
            return list(all_detectors.values())

        detectors = []
        for name in modules:
            if name in all_detectors:
                detectors.append(all_detectors[name])

        return detectors

    def _get_default_ports(self, detectors: list) -> list[int]:
        """Get all default ports from detectors."""
        ports = set()
        for detector in detectors:
            ports.update(detector.default_ports)
        return sorted(ports)

    def _run_detectors(
        self,
        target: str,
        open_ports: list[int],
        detectors: list,
    ) -> list[DetectionResult]:
        """Run appropriate detectors on open ports."""
        results = []

        for port in open_ports:
            # Find detectors for this port
            port_detectors = [d for d in detectors if port in d.default_ports]

            # If no specific detectors, try all (some might work on non-default ports)
            if not port_detectors:
                port_detectors = detectors

            for detector_class in port_detectors:
                try:
                    detector = detector_class(
                        timeout=self.timeout, verbose=self.verbose
                    )
                    result = detector.detect(target, port)

                    if result.indicators:  # Only add if there are findings
                        results.append(result)

                except Exception as e:
                    if self.verbose:
                        print(f"Error running {detector_class.name} on port {port}: {e}")

        return results

    @staticmethod
    def list_modules() -> list[dict]:
        """List all available detector modules."""
        return DetectorRegistry.list_detectors()
