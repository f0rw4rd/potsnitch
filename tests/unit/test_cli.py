"""
Unit tests for the CLI module.

Tests argument parsing, scan command, list-modules command,
validate command, and output format options using click.testing.CliRunner.
"""

import pytest
from unittest.mock import MagicMock, patch
from click.testing import CliRunner

from potsnitch.cli import main, scan, validate, list_modules
from potsnitch.core.result import DetectionResult, ScanReport, Confidence, Indicator


@pytest.fixture
def runner():
    """Create a CliRunner instance."""
    return CliRunner()


class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_main_group_help(self, runner):
        """Test main command shows help."""
        result = runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert 'PotSnitch' in result.output

    def test_main_version(self, runner):
        """Test version option displays version."""
        result = runner.invoke(main, ['--version'])
        assert result.exit_code == 0
        assert 'potsnitch' in result.output.lower()

    def test_scan_requires_target(self, runner):
        """Test scan command requires target argument."""
        result = runner.invoke(main, ['scan'])
        assert result.exit_code != 0
        assert 'Missing argument' in result.output

    def test_validate_requires_honeypot_type_and_target(self, runner):
        """Test validate command requires honeypot_type and target."""
        result = runner.invoke(main, ['validate'])
        assert result.exit_code != 0

        result = runner.invoke(main, ['validate', 'cowrie'])
        assert result.exit_code != 0


class TestScanCommand:
    """Tests for the scan command."""

    @patch('potsnitch.cli.HoneypotScanner')
    def test_scan_single_target(self, mock_scanner_class, runner):
        """Test scanning a single target."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        mock_report = ScanReport(target="192.168.1.100")
        mock_scanner.scan.return_value = mock_report

        result = runner.invoke(main, ['scan', '192.168.1.100'])

        assert result.exit_code == 0
        mock_scanner.scan.assert_called_once()

    @patch('potsnitch.cli.HoneypotScanner')
    def test_scan_with_custom_ports(self, mock_scanner_class, runner):
        """Test scanning with custom port list."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        mock_report = ScanReport(target="192.168.1.100")
        mock_scanner.scan.return_value = mock_report

        result = runner.invoke(main, ['scan', '192.168.1.100', '-p', '22,80,443'])

        assert result.exit_code == 0
        call_args = mock_scanner.scan.call_args
        assert call_args[1]['ports'] == [22, 80, 443]

    @patch('potsnitch.cli.HoneypotScanner')
    def test_scan_with_invalid_ports(self, mock_scanner_class, runner):
        """Test scanning with invalid port format."""
        result = runner.invoke(main, ['scan', '192.168.1.100', '-p', 'invalid'])

        assert result.exit_code == 1
        assert 'Invalid port format' in result.output

    @patch('potsnitch.cli.HoneypotScanner')
    def test_scan_with_custom_modules(self, mock_scanner_class, runner):
        """Test scanning with custom module list."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        mock_report = ScanReport(target="192.168.1.100")
        mock_scanner.scan.return_value = mock_report

        result = runner.invoke(main, ['scan', '192.168.1.100', '-m', 'ssh,http'])

        assert result.exit_code == 0
        call_args = mock_scanner.scan.call_args
        assert call_args[1]['modules'] == ['ssh', 'http']

    @patch('potsnitch.cli.HoneypotScanner')
    def test_scan_network_range(self, mock_scanner_class, runner):
        """Test scanning a network range."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan_range.return_value = []

        result = runner.invoke(main, ['scan', '192.168.1.0/24'])

        assert result.exit_code == 0
        mock_scanner.scan_range.assert_called_once()

    @patch('potsnitch.cli.HoneypotScanner')
    def test_scan_with_timeout_option(self, mock_scanner_class, runner):
        """Test scanning with custom timeout."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        mock_report = ScanReport(target="192.168.1.100")
        mock_scanner.scan.return_value = mock_report

        result = runner.invoke(main, ['scan', '192.168.1.100', '-t', '10.0'])

        assert result.exit_code == 0
        mock_scanner_class.assert_called_with(timeout=10.0, max_workers=10, verbose=False)

    @patch('potsnitch.cli.HoneypotScanner')
    def test_scan_with_workers_option(self, mock_scanner_class, runner):
        """Test scanning with custom worker count."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        mock_report = ScanReport(target="192.168.1.100")
        mock_scanner.scan.return_value = mock_report

        result = runner.invoke(main, ['scan', '192.168.1.100', '-w', '20'])

        assert result.exit_code == 0
        mock_scanner_class.assert_called_with(timeout=5.0, max_workers=20, verbose=False)

    @patch('potsnitch.cli.HoneypotScanner')
    def test_scan_with_verbose_option(self, mock_scanner_class, runner):
        """Test scanning with verbose flag."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        mock_report = ScanReport(target="192.168.1.100")
        mock_scanner.scan.return_value = mock_report

        result = runner.invoke(main, ['scan', '192.168.1.100', '-v'])

        assert result.exit_code == 0
        mock_scanner_class.assert_called_with(timeout=5.0, max_workers=10, verbose=True)


class TestOutputFormatOptions:
    """Tests for output format options."""

    @patch('potsnitch.cli.HoneypotScanner')
    @patch('potsnitch.cli.format_json')
    def test_scan_json_output(self, mock_format_json, mock_scanner_class, runner):
        """Test JSON output format."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        mock_report = ScanReport(target="192.168.1.100")
        mock_scanner.scan.return_value = mock_report
        mock_format_json.return_value = '{"target": "192.168.1.100"}'

        result = runner.invoke(main, ['scan', '192.168.1.100', '-o', 'json'])

        assert result.exit_code == 0
        mock_format_json.assert_called_once_with(mock_report)

    @patch('potsnitch.cli.HoneypotScanner')
    @patch('potsnitch.cli.format_csv')
    def test_scan_csv_output(self, mock_format_csv, mock_scanner_class, runner):
        """Test CSV output format."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        mock_report = ScanReport(target="192.168.1.100")
        mock_scanner.scan.return_value = mock_report
        mock_format_csv.return_value = 'target,port\n192.168.1.100,22'

        result = runner.invoke(main, ['scan', '192.168.1.100', '-o', 'csv'])

        assert result.exit_code == 0
        mock_format_csv.assert_called_once_with(mock_report)

    @patch('potsnitch.cli.HoneypotScanner')
    @patch('potsnitch.cli.format_table')
    def test_scan_table_output_default(self, mock_format_table, mock_scanner_class, runner):
        """Test table output format is default."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        mock_report = ScanReport(target="192.168.1.100")
        mock_scanner.scan.return_value = mock_report

        result = runner.invoke(main, ['scan', '192.168.1.100'])

        assert result.exit_code == 0
        mock_format_table.assert_called_once_with(mock_report)


class TestListModulesCommand:
    """Tests for the list-modules command."""

    @patch('potsnitch.cli.HoneypotScanner.list_modules')
    def test_list_modules(self, mock_list_modules, runner):
        """Test list-modules command."""
        mock_list_modules.return_value = [
            {
                'name': 'ssh',
                'description': 'SSH honeypot detector',
                'honeypot_types': ['cowrie', 'kippo'],
                'default_ports': [22, 2222],
            }
        ]

        result = runner.invoke(main, ['list-modules'])

        assert result.exit_code == 0
        assert 'ssh' in result.output
        assert 'cowrie' in result.output
        assert '22' in result.output

    @patch('potsnitch.cli.HoneypotScanner.list_modules')
    def test_list_modules_empty(self, mock_list_modules, runner):
        """Test list-modules with no modules."""
        mock_list_modules.return_value = []

        result = runner.invoke(main, ['list-modules'])

        assert result.exit_code == 0
        assert 'Available Detector Modules' in result.output


class TestValidateCommand:
    """Tests for the validate command."""

    @patch('potsnitch.cli.HoneypotScanner')
    @patch('potsnitch.cli.print_validation_report')
    def test_validate_success(self, mock_print_report, mock_scanner_class, runner):
        """Test successful validation."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        mock_result = DetectionResult(target="192.168.1.100", port=22)
        mock_scanner.validate.return_value = (mock_result, ["Recommendation 1"])

        result = runner.invoke(main, ['validate', 'cowrie', '192.168.1.100'])

        assert result.exit_code == 0
        mock_print_report.assert_called_once()

    @patch('potsnitch.cli.HoneypotScanner')
    def test_validate_unknown_honeypot_type(self, mock_scanner_class, runner):
        """Test validate with unknown honeypot type."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.validate.side_effect = ValueError("No detector found")
        mock_scanner.list_modules.return_value = [
            {'name': 'ssh', 'honeypot_types': ['cowrie']}
        ]

        result = runner.invoke(main, ['validate', 'unknown', '192.168.1.100'])

        assert result.exit_code == 1
        assert 'Error' in result.output

    @patch('potsnitch.cli.HoneypotScanner')
    @patch('potsnitch.cli.print_validation_report')
    def test_validate_with_port_option(self, mock_print_report, mock_scanner_class, runner):
        """Test validate with custom port."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        mock_result = DetectionResult(target="192.168.1.100", port=2222)
        mock_scanner.validate.return_value = (mock_result, [])

        result = runner.invoke(main, ['validate', 'cowrie', '192.168.1.100', '-p', '2222'])

        assert result.exit_code == 0
        mock_scanner.validate.assert_called_with("192.168.1.100", "cowrie", 2222)

    @patch('potsnitch.cli.HoneypotScanner')
    @patch('potsnitch.cli.print_validation_report')
    def test_validate_with_timeout_option(self, mock_print_report, mock_scanner_class, runner):
        """Test validate with custom timeout."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        mock_result = DetectionResult(target="192.168.1.100", port=22)
        mock_scanner.validate.return_value = (mock_result, [])

        result = runner.invoke(main, ['validate', 'cowrie', '192.168.1.100', '-t', '10.0'])

        assert result.exit_code == 0
        mock_scanner_class.assert_called_with(timeout=10.0, verbose=False)

    @patch('potsnitch.cli.HoneypotScanner')
    @patch('potsnitch.cli.print_validation_report')
    def test_validate_with_verbose_option(self, mock_print_report, mock_scanner_class, runner):
        """Test validate with verbose flag."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner

        mock_result = DetectionResult(target="192.168.1.100", port=22)
        mock_scanner.validate.return_value = (mock_result, [])

        result = runner.invoke(main, ['validate', 'cowrie', '192.168.1.100', '-v'])

        assert result.exit_code == 0
        mock_scanner_class.assert_called_with(timeout=5.0, verbose=True)


class TestCLIErrorHandling:
    """Tests for CLI error handling."""

    def test_invalid_output_format(self, runner):
        """Test invalid output format is rejected."""
        result = runner.invoke(main, ['scan', '192.168.1.100', '-o', 'invalid'])

        assert result.exit_code != 0
        # Click should reject invalid choices
        assert 'Invalid value' in result.output or 'invalid' in result.output.lower()

    @patch('potsnitch.cli.HoneypotScanner')
    def test_scan_range_no_honeypots_message(self, mock_scanner_class, runner):
        """Test appropriate message when no honeypots found in range."""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan_range.return_value = []

        result = runner.invoke(main, ['scan', '192.168.1.0/30'])

        assert result.exit_code == 0
        assert 'No honeypots detected' in result.output
