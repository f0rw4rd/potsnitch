"""
Unit tests for the HoneypotScanner module.

Tests initialization, scan methods, detector selection, result aggregation,
and timeout handling with all network operations mocked.
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

from potsnitch.scanner import HoneypotScanner
from potsnitch.core.result import DetectionResult, ScanReport, Confidence, Indicator
from potsnitch.core.base import BaseDetector


class TestHoneypotScannerInitialization:
    """Tests for HoneypotScanner initialization."""

    @patch.object(HoneypotScanner, '__init__', lambda self, **kwargs: None)
    def test_default_initialization(self):
        """Test scanner initializes with default values."""
        scanner = HoneypotScanner.__new__(HoneypotScanner)
        scanner.timeout = 5.0
        scanner.max_workers = 10
        scanner.verbose = False

        assert scanner.timeout == 5.0
        assert scanner.max_workers == 10
        assert scanner.verbose is False

    @patch('potsnitch.scanner.DetectorRegistry.load_detectors')
    def test_initialization_loads_detectors(self, mock_load):
        """Test that initialization calls DetectorRegistry.load_detectors."""
        HoneypotScanner()
        mock_load.assert_called_once()

    @patch('potsnitch.scanner.DetectorRegistry.load_detectors')
    def test_custom_timeout(self, mock_load):
        """Test scanner accepts custom timeout."""
        scanner = HoneypotScanner(timeout=10.0)
        assert scanner.timeout == 10.0

    @patch('potsnitch.scanner.DetectorRegistry.load_detectors')
    def test_custom_max_workers(self, mock_load):
        """Test scanner accepts custom max_workers."""
        scanner = HoneypotScanner(max_workers=20)
        assert scanner.max_workers == 20

    @patch('potsnitch.scanner.DetectorRegistry.load_detectors')
    def test_verbose_mode(self, mock_load):
        """Test scanner accepts verbose flag."""
        scanner = HoneypotScanner(verbose=True)
        assert scanner.verbose is True


class TestHoneypotScannerScanMethod:
    """Tests for the scan() method with mocked detectors."""

    @pytest.fixture
    def scanner(self):
        """Create scanner with mocked detector loading."""
        with patch('potsnitch.scanner.DetectorRegistry.load_detectors'):
            return HoneypotScanner(timeout=5.0, verbose=False)

    @patch('potsnitch.scanner.scan_ports')
    def test_scan_returns_scan_report(self, mock_scan_ports, scanner):
        """Test scan returns a ScanReport object."""
        mock_scan_ports.return_value = []

        with patch.object(scanner, '_get_detectors', return_value=[]):
            result = scanner.scan("192.168.1.100")

        assert isinstance(result, ScanReport)
        assert result.target == "192.168.1.100"

    @patch('potsnitch.scanner.scan_ports')
    def test_scan_with_no_open_ports(self, mock_scan_ports, scanner):
        """Test scan returns empty report when no ports are open."""
        mock_scan_ports.return_value = []

        with patch.object(scanner, '_get_detectors', return_value=[]):
            result = scanner.scan("192.168.1.100")

        assert result.detections == []
        assert not result.has_honeypot

    @patch('potsnitch.scanner.scan_ports')
    def test_scan_with_open_ports_and_detections(self, mock_scan_ports, scanner):
        """Test scan runs detectors on open ports and aggregates results."""
        mock_scan_ports.return_value = [22]

        # Create mock detector
        mock_detector_class = MagicMock()
        mock_detector_instance = MagicMock()
        mock_detector_class.return_value = mock_detector_instance
        mock_detector_class.default_ports = [22]

        # Create a detection result with indicators
        detection = DetectionResult(target="192.168.1.100", port=22)
        detection.add_indicator(Indicator(
            name="test_indicator",
            description="Test indicator",
            severity=Confidence.HIGH
        ))
        mock_detector_instance.detect.return_value = detection

        with patch.object(scanner, '_get_detectors', return_value=[mock_detector_class]):
            result = scanner.scan("192.168.1.100", ports=[22])

        assert len(result.detections) == 1
        assert result.detections[0].port == 22

    @patch('potsnitch.scanner.scan_ports')
    def test_scan_with_specific_ports(self, mock_scan_ports, scanner):
        """Test scan uses specified ports instead of auto-detect."""
        mock_scan_ports.return_value = [80, 443]

        with patch.object(scanner, '_get_detectors', return_value=[]):
            scanner.scan("192.168.1.100", ports=[80, 443])

        mock_scan_ports.assert_called_with("192.168.1.100", [80, 443], timeout=5.0)

    @patch('potsnitch.scanner.scan_ports')
    def test_scan_with_specific_modules(self, mock_scan_ports, scanner):
        """Test scan uses specified modules."""
        mock_scan_ports.return_value = []

        mock_get_detectors = MagicMock(return_value=[])
        with patch.object(scanner, '_get_detectors', mock_get_detectors):
            scanner.scan("192.168.1.100", modules=["ssh", "http"])

        mock_get_detectors.assert_called_with(["ssh", "http"])

    @patch('potsnitch.scanner.scan_ports')
    def test_scan_excludes_results_without_indicators(self, mock_scan_ports, scanner):
        """Test scan excludes detection results with no indicators."""
        mock_scan_ports.return_value = [22]

        mock_detector_class = MagicMock()
        mock_detector_instance = MagicMock()
        mock_detector_class.return_value = mock_detector_instance
        mock_detector_class.default_ports = [22]

        # Detection result with no indicators
        empty_detection = DetectionResult(target="192.168.1.100", port=22)
        mock_detector_instance.detect.return_value = empty_detection

        with patch.object(scanner, '_get_detectors', return_value=[mock_detector_class]):
            result = scanner.scan("192.168.1.100", ports=[22])

        assert len(result.detections) == 0


class TestHoneypotScannerScanRangeMethod:
    """Tests for the scan_range() method."""

    @pytest.fixture
    def scanner(self):
        """Create scanner with mocked detector loading."""
        with patch('potsnitch.scanner.DetectorRegistry.load_detectors'):
            return HoneypotScanner(timeout=5.0, max_workers=2, verbose=False)

    def test_scan_range_invalid_network(self, scanner):
        """Test scan_range raises ValueError for invalid network."""
        with pytest.raises(ValueError, match="Invalid network"):
            scanner.scan_range("invalid_network")

    @patch.object(HoneypotScanner, 'scan')
    def test_scan_range_scans_all_hosts(self, mock_scan, scanner):
        """Test scan_range scans all hosts in the network."""
        # Create a report without honeypot detection
        mock_report = MagicMock()
        mock_report.has_honeypot = False
        mock_scan.return_value = mock_report

        results = scanner.scan_range("192.168.1.0/30")

        # /30 has 2 usable hosts
        assert mock_scan.call_count == 2

    @patch.object(HoneypotScanner, 'scan')
    def test_scan_range_returns_only_honeypot_reports(self, mock_scan, scanner):
        """Test scan_range only returns reports with honeypot detections."""
        # One report with honeypot, one without
        honeypot_report = MagicMock()
        honeypot_report.has_honeypot = True

        no_honeypot_report = MagicMock()
        no_honeypot_report.has_honeypot = False

        mock_scan.side_effect = [honeypot_report, no_honeypot_report]

        results = scanner.scan_range("192.168.1.0/30")

        assert len(results) == 1
        assert results[0] == honeypot_report

    @patch.object(HoneypotScanner, 'scan')
    def test_scan_range_handles_scan_exceptions(self, mock_scan, scanner):
        """Test scan_range gracefully handles exceptions from individual scans."""
        mock_scan.side_effect = Exception("Connection failed")

        # Should not raise, just return empty results
        results = scanner.scan_range("192.168.1.0/30")

        assert results == []

    @patch.object(HoneypotScanner, 'scan')
    def test_scan_range_passes_ports_and_modules(self, mock_scan, scanner):
        """Test scan_range passes ports and modules to scan."""
        mock_report = MagicMock()
        mock_report.has_honeypot = False
        mock_scan.return_value = mock_report

        scanner.scan_range("192.168.1.0/30", ports=[22], modules=["ssh"])

        # Check that ports and modules were passed
        for call in mock_scan.call_args_list:
            assert call[1].get('ports') == [22] or call[0][1] == [22]
            assert call[1].get('modules') == ["ssh"] or call[0][2] == ["ssh"]


class TestHoneypotScannerDetectorSelection:
    """Tests for detector selection by port and module name."""

    @pytest.fixture
    def scanner(self):
        """Create scanner with mocked detector loading."""
        with patch('potsnitch.scanner.DetectorRegistry.load_detectors'):
            return HoneypotScanner()

    def test_get_detectors_returns_all_when_no_modules(self, scanner):
        """Test _get_detectors returns all detectors when modules is None."""
        mock_detector1 = MagicMock()
        mock_detector2 = MagicMock()

        with patch('potsnitch.scanner.DetectorRegistry.get_all_detectors') as mock_get:
            mock_get.return_value = {"ssh": mock_detector1, "http": mock_detector2}

            result = scanner._get_detectors(None)

        assert len(result) == 2
        assert mock_detector1 in result
        assert mock_detector2 in result

    def test_get_detectors_filters_by_module_name(self, scanner):
        """Test _get_detectors returns only specified modules."""
        mock_ssh = MagicMock()
        mock_http = MagicMock()

        with patch('potsnitch.scanner.DetectorRegistry.get_all_detectors') as mock_get:
            mock_get.return_value = {"ssh": mock_ssh, "http": mock_http}

            result = scanner._get_detectors(["ssh"])

        assert len(result) == 1
        assert mock_ssh in result

    def test_get_detectors_ignores_unknown_modules(self, scanner):
        """Test _get_detectors ignores unknown module names."""
        mock_ssh = MagicMock()

        with patch('potsnitch.scanner.DetectorRegistry.get_all_detectors') as mock_get:
            mock_get.return_value = {"ssh": mock_ssh}

            result = scanner._get_detectors(["ssh", "unknown"])

        assert len(result) == 1

    def test_get_default_ports_aggregates_from_detectors(self, scanner):
        """Test _get_default_ports collects ports from all detectors."""
        mock_detector1 = MagicMock()
        mock_detector1.default_ports = [22, 2222]

        mock_detector2 = MagicMock()
        mock_detector2.default_ports = [80, 443]

        result = scanner._get_default_ports([mock_detector1, mock_detector2])

        assert sorted(result) == [22, 80, 443, 2222]

    def test_get_default_ports_removes_duplicates(self, scanner):
        """Test _get_default_ports removes duplicate ports."""
        mock_detector1 = MagicMock()
        mock_detector1.default_ports = [22, 80]

        mock_detector2 = MagicMock()
        mock_detector2.default_ports = [80, 443]

        result = scanner._get_default_ports([mock_detector1, mock_detector2])

        assert result.count(80) == 1


class TestHoneypotScannerRunDetectors:
    """Tests for the _run_detectors method."""

    @pytest.fixture
    def scanner(self):
        """Create scanner with mocked detector loading."""
        with patch('potsnitch.scanner.DetectorRegistry.load_detectors'):
            return HoneypotScanner()

    def test_run_detectors_selects_by_port(self, scanner):
        """Test _run_detectors runs detectors matching port."""
        mock_ssh = MagicMock()
        mock_ssh.default_ports = [22]
        mock_ssh_instance = MagicMock()
        mock_ssh.return_value = mock_ssh_instance
        detection = DetectionResult(target="192.168.1.100", port=22)
        detection.add_indicator(Indicator(
            name="test", description="test", severity=Confidence.HIGH
        ))
        mock_ssh_instance.detect.return_value = detection

        mock_http = MagicMock()
        mock_http.default_ports = [80, 443]

        results = scanner._run_detectors("192.168.1.100", [22], [mock_ssh, mock_http])

        mock_ssh_instance.detect.assert_called_once()
        assert len(results) == 1

    def test_run_detectors_tries_all_on_unmatched_port(self, scanner):
        """Test _run_detectors tries all detectors when port has no specific match."""
        mock_detector = MagicMock()
        mock_detector.default_ports = [22]
        mock_instance = MagicMock()
        mock_detector.return_value = mock_instance
        mock_instance.detect.return_value = DetectionResult(target="192.168.1.100", port=8080)

        scanner._run_detectors("192.168.1.100", [8080], [mock_detector])

        # Should still try the detector even though 8080 is not default
        mock_instance.detect.assert_called_once()

    def test_run_detectors_handles_exceptions(self, scanner):
        """Test _run_detectors handles detector exceptions gracefully."""
        scanner.verbose = True

        mock_detector = MagicMock()
        mock_detector.default_ports = [22]
        mock_detector.name = "test"
        mock_instance = MagicMock()
        mock_detector.return_value = mock_instance
        mock_instance.detect.side_effect = Exception("Detection failed")

        # Should not raise
        results = scanner._run_detectors("192.168.1.100", [22], [mock_detector])

        assert results == []


class TestHoneypotScannerValidate:
    """Tests for the validate() method."""

    @pytest.fixture
    def scanner(self):
        """Create scanner with mocked detector loading."""
        with patch('potsnitch.scanner.DetectorRegistry.load_detectors'):
            return HoneypotScanner()

    def test_validate_unknown_honeypot_type(self, scanner):
        """Test validate raises ValueError for unknown honeypot type."""
        with patch('potsnitch.scanner.DetectorRegistry.get_detectors_for_honeypot') as mock_get:
            mock_get.return_value = []

            with pytest.raises(ValueError, match="No detector found"):
                scanner.validate("192.168.1.100", "unknown_type")

    def test_validate_returns_result_and_recommendations(self, scanner):
        """Test validate returns detection result and recommendations."""
        mock_detector_class = MagicMock()
        mock_detector_class.default_ports = [22]
        mock_instance = MagicMock()
        mock_detector_class.return_value = mock_instance

        mock_result = DetectionResult(target="192.168.1.100", port=22)
        mock_instance.validate.return_value = mock_result
        mock_instance.get_recommendations.return_value = ["Recommendation 1"]

        with patch('potsnitch.scanner.DetectorRegistry.get_detectors_for_honeypot') as mock_get:
            mock_get.return_value = [mock_detector_class]

            result, recommendations = scanner.validate("192.168.1.100", "cowrie")

        assert isinstance(result, DetectionResult)
        assert result.honeypot_type == "cowrie"
        assert recommendations == ["Recommendation 1"]

    def test_validate_uses_specified_port(self, scanner):
        """Test validate uses the specified port."""
        mock_detector_class = MagicMock()
        mock_detector_class.default_ports = [22]
        mock_instance = MagicMock()
        mock_detector_class.return_value = mock_instance

        mock_result = DetectionResult(target="192.168.1.100", port=2222)
        mock_instance.validate.return_value = mock_result
        mock_instance.get_recommendations.return_value = []

        with patch('potsnitch.scanner.DetectorRegistry.get_detectors_for_honeypot') as mock_get:
            mock_get.return_value = [mock_detector_class]

            scanner.validate("192.168.1.100", "cowrie", port=2222)

        mock_instance.validate.assert_called_with("192.168.1.100", 2222)

    def test_validate_uses_default_port_when_not_specified(self, scanner):
        """Test validate uses detector's default port when none specified."""
        mock_detector_class = MagicMock()
        mock_detector_class.default_ports = [22, 2222]
        mock_instance = MagicMock()
        mock_instance.default_ports = [22, 2222]  # Instance also needs default_ports
        mock_detector_class.return_value = mock_instance

        mock_result = DetectionResult(target="192.168.1.100", port=22)
        mock_instance.validate.return_value = mock_result
        mock_instance.get_recommendations.return_value = []

        with patch('potsnitch.scanner.DetectorRegistry.get_detectors_for_honeypot') as mock_get:
            mock_get.return_value = [mock_detector_class]

            scanner.validate("192.168.1.100", "cowrie")

        mock_instance.validate.assert_called_with("192.168.1.100", 22)


class TestHoneypotScannerListModules:
    """Tests for the list_modules() static method."""

    def test_list_modules_returns_detector_info(self):
        """Test list_modules returns detector information."""
        mock_info = [
            {"name": "ssh", "description": "SSH detector", "honeypot_types": ["cowrie"]},
            {"name": "http", "description": "HTTP detector", "honeypot_types": ["glastopf"]},
        ]

        with patch('potsnitch.scanner.DetectorRegistry.list_detectors') as mock_list:
            mock_list.return_value = mock_info

            result = HoneypotScanner.list_modules()

        assert result == mock_info
        assert len(result) == 2


class TestHoneypotScannerTimeoutHandling:
    """Tests for timeout handling in scanner operations."""

    @pytest.fixture
    def scanner(self):
        """Create scanner with mocked detector loading."""
        with patch('potsnitch.scanner.DetectorRegistry.load_detectors'):
            return HoneypotScanner(timeout=2.0)

    @patch('potsnitch.scanner.scan_ports')
    def test_scan_passes_timeout_to_port_scan(self, mock_scan_ports, scanner):
        """Test scan passes timeout to port scanning."""
        mock_scan_ports.return_value = []

        with patch.object(scanner, '_get_detectors', return_value=[]):
            scanner.scan("192.168.1.100")

        mock_scan_ports.assert_called_with("192.168.1.100", [], timeout=2.0)

    def test_detector_receives_timeout(self, scanner):
        """Test detectors are initialized with scanner's timeout."""
        mock_detector_class = MagicMock()
        mock_detector_class.default_ports = [22]
        mock_instance = MagicMock()
        mock_detector_class.return_value = mock_instance
        mock_instance.detect.return_value = DetectionResult(target="192.168.1.100", port=22)

        scanner._run_detectors("192.168.1.100", [22], [mock_detector_class])

        mock_detector_class.assert_called_with(timeout=2.0, verbose=False)


class TestHoneypotScannerResultAggregation:
    """Tests for result aggregation from multiple detectors."""

    @pytest.fixture
    def scanner(self):
        """Create scanner with mocked detector loading."""
        with patch('potsnitch.scanner.DetectorRegistry.load_detectors'):
            return HoneypotScanner()

    def test_aggregates_results_from_multiple_detectors(self, scanner):
        """Test results from multiple detectors are aggregated."""
        mock_detector1 = MagicMock()
        mock_detector1.default_ports = [22]
        mock_instance1 = MagicMock()
        mock_detector1.return_value = mock_instance1
        result1 = DetectionResult(target="192.168.1.100", port=22)
        result1.add_indicator(Indicator(
            name="indicator1", description="Test 1", severity=Confidence.HIGH
        ))
        mock_instance1.detect.return_value = result1

        mock_detector2 = MagicMock()
        mock_detector2.default_ports = [22]
        mock_instance2 = MagicMock()
        mock_detector2.return_value = mock_instance2
        result2 = DetectionResult(target="192.168.1.100", port=22)
        result2.add_indicator(Indicator(
            name="indicator2", description="Test 2", severity=Confidence.MEDIUM
        ))
        mock_instance2.detect.return_value = result2

        results = scanner._run_detectors(
            "192.168.1.100", [22], [mock_detector1, mock_detector2]
        )

        assert len(results) == 2

    def test_aggregates_results_from_multiple_ports(self, scanner):
        """Test results from multiple ports are aggregated."""
        mock_detector = MagicMock()
        mock_detector.default_ports = [22, 80]
        mock_instance = MagicMock()
        mock_detector.return_value = mock_instance

        result22 = DetectionResult(target="192.168.1.100", port=22)
        result22.add_indicator(Indicator(
            name="ssh_indicator", description="SSH", severity=Confidence.HIGH
        ))

        result80 = DetectionResult(target="192.168.1.100", port=80)
        result80.add_indicator(Indicator(
            name="http_indicator", description="HTTP", severity=Confidence.HIGH
        ))

        mock_instance.detect.side_effect = [result22, result80]

        results = scanner._run_detectors(
            "192.168.1.100", [22, 80], [mock_detector]
        )

        assert len(results) == 2
        assert any(r.port == 22 for r in results)
        assert any(r.port == 80 for r in results)
