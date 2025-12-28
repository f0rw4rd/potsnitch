"""Unit tests for potsnitch.utils.output module."""

import json
from datetime import datetime
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from potsnitch.core.result import (
    Confidence,
    DetectionResult,
    Indicator,
    ScanReport,
)
from potsnitch.utils.output import (
    format_json,
    format_csv,
    format_table,
    print_validation_report,
)


@pytest.fixture
def sample_indicator():
    """Create a sample indicator."""
    return Indicator(
        name="default_banner",
        description="Default Cowrie SSH banner detected",
        severity=Confidence.HIGH,
        details="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
    )


@pytest.fixture
def sample_detection_result(sample_indicator):
    """Create a sample detection result."""
    result = DetectionResult(
        target="192.168.1.100",
        port=22,
        honeypot_type="cowrie",
        is_honeypot=True,
        confidence=Confidence.HIGH,
        scan_time=datetime(2024, 1, 15, 10, 30, 0),
    )
    result.indicators.append(sample_indicator)
    return result


@pytest.fixture
def sample_scan_report(sample_detection_result):
    """Create a sample scan report."""
    return ScanReport(
        target="192.168.1.100",
        scan_time=datetime(2024, 1, 15, 10, 30, 0),
        detections=[sample_detection_result],
    )


class TestFormatJson:
    """Tests for format_json function."""

    def test_format_detection_result(self, sample_detection_result):
        """Test JSON formatting of DetectionResult."""
        result = format_json(sample_detection_result)
        data = json.loads(result)

        assert data["target"] == "192.168.1.100"
        assert data["port"] == 22
        assert data["honeypot_type"] == "cowrie"
        assert data["is_honeypot"] is True
        assert data["confidence"] == "high"
        assert data["confidence_score"] == 0.75
        assert len(data["indicators"]) == 1

    def test_format_scan_report(self, sample_scan_report):
        """Test JSON formatting of ScanReport."""
        result = format_json(sample_scan_report)
        data = json.loads(result)

        assert data["target"] == "192.168.1.100"
        assert data["has_honeypot"] is True
        assert data["highest_confidence"] == "high"
        assert len(data["detections"]) == 1

    def test_format_list_of_results(self, sample_detection_result):
        """Test JSON formatting of list of DetectionResults."""
        results = [sample_detection_result, sample_detection_result]
        output = format_json(results)
        data = json.loads(output)

        assert isinstance(data, list)
        assert len(data) == 2
        assert all(d["target"] == "192.168.1.100" for d in data)

    def test_json_is_indented(self, sample_detection_result):
        """Test JSON output is properly indented."""
        result = format_json(sample_detection_result)

        assert "\n" in result
        assert "  " in result  # 2-space indentation

    @pytest.mark.parametrize("confidence,expected", [
        (Confidence.LOW, "low"),
        (Confidence.MEDIUM, "medium"),
        (Confidence.HIGH, "high"),
        (Confidence.DEFINITE, "definite"),
    ])
    def test_confidence_serialization(self, confidence, expected):
        """Test confidence levels are serialized correctly."""
        result = DetectionResult(
            target="10.0.0.1",
            port=80,
            confidence=confidence,
            scan_time=datetime(2024, 1, 1),
        )
        output = format_json(result)
        data = json.loads(output)

        assert data["confidence"] == expected


class TestFormatCsv:
    """Tests for format_csv function."""

    def test_csv_header(self, sample_scan_report):
        """Test CSV output includes correct header."""
        result = format_csv(sample_scan_report)
        lines = result.strip().split("\n")
        header = lines[0]

        expected_fields = [
            "target",
            "port",
            "honeypot_type",
            "is_honeypot",
            "confidence",
            "confidence_score",
            "indicators",
            "scan_time",
        ]
        for field in expected_fields:
            assert field in header

    def test_csv_data_row(self, sample_scan_report):
        """Test CSV output includes data rows."""
        result = format_csv(sample_scan_report)
        lines = result.strip().split("\n")

        assert len(lines) == 2  # header + 1 data row
        data_row = lines[1]
        assert "192.168.1.100" in data_row
        assert "22" in data_row
        assert "cowrie" in data_row

    def test_csv_from_list(self, sample_detection_result):
        """Test CSV formatting from list of DetectionResults."""
        results = [sample_detection_result]
        output = format_csv(results)
        lines = output.strip().split("\n")

        assert len(lines) == 2
        assert "192.168.1.100" in lines[1]

    def test_csv_multiple_indicators(self):
        """Test CSV formats multiple indicators with semicolon separator."""
        indicators = [
            Indicator("ind1", "First indicator", Confidence.LOW),
            Indicator("ind2", "Second indicator", Confidence.MEDIUM),
        ]
        result = DetectionResult(
            target="10.0.0.1",
            port=80,
            indicators=indicators,
            scan_time=datetime(2024, 1, 1),
        )
        output = format_csv([result])

        assert "First indicator; Second indicator" in output

    def test_csv_empty_honeypot_type(self):
        """Test CSV handles None honeypot_type."""
        result = DetectionResult(
            target="10.0.0.1",
            port=80,
            honeypot_type=None,
            scan_time=datetime(2024, 1, 1),
        )
        output = format_csv([result])
        lines = output.strip().split("\n")

        # Should have empty string for honeypot_type
        assert "10.0.0.1" in lines[1]

    @pytest.mark.parametrize("is_honeypot", [True, False])
    def test_csv_boolean_serialization(self, is_honeypot):
        """Test boolean values are serialized correctly."""
        result = DetectionResult(
            target="10.0.0.1",
            port=80,
            is_honeypot=is_honeypot,
            scan_time=datetime(2024, 1, 1),
        )
        output = format_csv([result])

        assert str(is_honeypot) in output


class TestFormatTable:
    """Tests for format_table function."""

    def test_no_honeypots_message(self, capsys):
        """Test message when no honeypots detected."""
        result = DetectionResult(
            target="10.0.0.1",
            port=80,
            is_honeypot=False,
            scan_time=datetime(2024, 1, 1),
        )
        report = ScanReport(
            target="10.0.0.1",
            detections=[result],
        )

        with patch("potsnitch.utils.output.console") as mock_console:
            format_table(report)
            # Check that the "No honeypots detected" message was printed
            calls = [str(c) for c in mock_console.print.call_args_list]
            assert any("No honeypots detected" in str(c) for c in calls)

    def test_table_with_honeypots(self, sample_scan_report):
        """Test table is created for honeypot results."""
        with patch("potsnitch.utils.output.console") as mock_console:
            format_table(sample_scan_report)

            # Should have called print at least once with a Table
            assert mock_console.print.called

    def test_table_from_list(self, sample_detection_result):
        """Test table formatting from list of DetectionResults."""
        with patch("potsnitch.utils.output.console") as mock_console:
            format_table([sample_detection_result])

            assert mock_console.print.called

    def test_empty_list_handling(self):
        """Test handling of empty results list."""
        with patch("potsnitch.utils.output.console") as mock_console:
            format_table([])

            # Should print "Unknown" as target with no honeypots message
            calls = [str(c) for c in mock_console.print.call_args_list]
            assert any("No honeypots detected" in str(c) for c in calls)

    def test_indicator_truncation(self):
        """Test indicators are truncated when more than 3."""
        indicators = [
            Indicator(f"ind{i}", f"Indicator {i}", Confidence.MEDIUM)
            for i in range(5)
        ]
        result = DetectionResult(
            target="10.0.0.1",
            port=22,
            is_honeypot=True,
            indicators=indicators,
            scan_time=datetime(2024, 1, 1),
        )

        with patch("potsnitch.utils.output.console"):
            with patch("potsnitch.utils.output.Table") as mock_table:
                mock_table_instance = MagicMock()
                mock_table.return_value = mock_table_instance

                format_table([result])

                # Check that add_row was called with truncated indicators
                add_row_calls = mock_table_instance.add_row.call_args_list
                if add_row_calls:
                    indicators_arg = add_row_calls[0][0][3]
                    assert "+2 more" in indicators_arg


class TestPrintValidationReport:
    """Tests for print_validation_report function."""

    def test_validation_report_structure(self, sample_detection_result):
        """Test validation report is printed with correct structure."""
        with patch("potsnitch.utils.output.console") as mock_console:
            print_validation_report(
                target="192.168.1.100",
                honeypot_type="cowrie",
                result=sample_detection_result,
                recommendations=["Update SSH banner", "Randomize responses"],
            )

            assert mock_console.print.called
            # Should print Panel with report
            calls = mock_console.print.call_args_list
            assert len(calls) >= 1

    def test_empty_recommendations(self, sample_detection_result):
        """Test validation report with empty recommendations."""
        with patch("potsnitch.utils.output.console") as mock_console:
            print_validation_report(
                target="192.168.1.100",
                honeypot_type="cowrie",
                result=sample_detection_result,
                recommendations=[],
            )

            assert mock_console.print.called

    @pytest.mark.parametrize("severity,expected_status", [
        (Confidence.DEFINITE, "[FAIL]"),
        (Confidence.HIGH, "[FAIL]"),
        (Confidence.MEDIUM, "[WARN]"),
        (Confidence.LOW, "[PASS]"),
    ])
    def test_severity_status_mapping(self, severity, expected_status):
        """Test severity levels map to correct status indicators."""
        indicator = Indicator(
            name="test",
            description="Test indicator",
            severity=severity,
        )
        result = DetectionResult(
            target="10.0.0.1",
            port=22,
            indicators=[indicator],
            scan_time=datetime(2024, 1, 1),
        )

        with patch("potsnitch.utils.output.console") as mock_console:
            with patch("potsnitch.utils.output.Panel") as mock_panel:
                print_validation_report(
                    target="10.0.0.1",
                    honeypot_type="test",
                    result=result,
                    recommendations=[],
                )

                # Check Panel was called with content containing expected status
                panel_call = mock_panel.call_args
                if panel_call:
                    content = panel_call[0][0]
                    assert expected_status in content

    def test_indicator_details_included(self):
        """Test indicator details are included in report."""
        indicator = Indicator(
            name="test",
            description="Test indicator",
            severity=Confidence.HIGH,
            details="Detailed information about the finding",
        )
        result = DetectionResult(
            target="10.0.0.1",
            port=22,
            indicators=[indicator],
            scan_time=datetime(2024, 1, 1),
        )

        with patch("potsnitch.utils.output.console"):
            with patch("potsnitch.utils.output.Panel") as mock_panel:
                print_validation_report(
                    target="10.0.0.1",
                    honeypot_type="test",
                    result=result,
                    recommendations=[],
                )

                panel_call = mock_panel.call_args
                if panel_call:
                    content = panel_call[0][0]
                    assert "Detailed information" in content
