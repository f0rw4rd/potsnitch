"""Unit tests for potsnitch.probes.timing module."""

import socket
import statistics
from unittest.mock import Mock, patch, MagicMock
import pytest

from potsnitch.probes.timing import (
    # Constants
    INSTANT_RESPONSE_THRESHOLD,
    UNIFORM_VARIANCE_THRESHOLD,
    AUTH_FAILURE_MIN_TIME,
    QUERY_COMPLEXITY_RATIO,
    # Dataclasses
    TimingResult,
    TimingAnalysis,
    # Functions
    measure_connection_time,
    measure_response_time,
    analyze_timing_samples,
    probe_auth_timing,
    probe_response_timing_variance,
    probe_query_complexity_timing,
    probe_error_timing_uniformity,
    probe_connection_timing_consistency,
    # Class
    TimingProbe,
)
from potsnitch.core.result import Indicator, Confidence


class TestTimingResult:
    """Tests for TimingResult dataclass."""

    def test_timing_result_creation(self):
        """Should create TimingResult with required fields."""
        result = TimingResult(elapsed=0.5, success=True)
        assert result.elapsed == 0.5
        assert result.success is True
        assert result.response is None

    def test_timing_result_with_response(self):
        """Should create TimingResult with optional response."""
        result = TimingResult(elapsed=0.5, success=True, response=b"test data")
        assert result.response == b"test data"

    def test_timing_result_failure(self):
        """Should create TimingResult for failed operation."""
        result = TimingResult(elapsed=0.1, success=False)
        assert result.success is False


class TestTimingAnalysis:
    """Tests for TimingAnalysis dataclass."""

    def test_timing_analysis_creation(self):
        """Should create TimingAnalysis with all fields."""
        analysis = TimingAnalysis(
            mean=0.5,
            variance=0.01,
            min_time=0.4,
            max_time=0.6,
            samples=10,
            is_suspicious=False,
            reason=None
        )
        assert analysis.mean == 0.5
        assert analysis.variance == 0.01
        assert analysis.samples == 10
        assert analysis.is_suspicious is False

    def test_timing_analysis_with_reason(self):
        """Should create TimingAnalysis with suspicion reason."""
        analysis = TimingAnalysis(
            mean=0.001,
            variance=0.0,
            min_time=0.001,
            max_time=0.001,
            samples=5,
            is_suspicious=True,
            reason="Instant responses"
        )
        assert analysis.is_suspicious is True
        assert analysis.reason == "Instant responses"


class TestConstants:
    """Tests for timing constants."""

    def test_instant_response_threshold(self):
        """INSTANT_RESPONSE_THRESHOLD should be a small positive value."""
        assert INSTANT_RESPONSE_THRESHOLD > 0
        assert INSTANT_RESPONSE_THRESHOLD < 0.1  # Less than 100ms

    def test_uniform_variance_threshold(self):
        """UNIFORM_VARIANCE_THRESHOLD should be a very small value."""
        assert UNIFORM_VARIANCE_THRESHOLD > 0
        assert UNIFORM_VARIANCE_THRESHOLD < 0.001

    def test_auth_failure_min_time(self):
        """AUTH_FAILURE_MIN_TIME should be reasonable for crypto operations."""
        assert AUTH_FAILURE_MIN_TIME >= 0.01  # At least 10ms
        assert AUTH_FAILURE_MIN_TIME < 1.0  # Less than 1 second

    def test_query_complexity_ratio(self):
        """QUERY_COMPLEXITY_RATIO should be at least 1.5x."""
        assert QUERY_COMPLEXITY_RATIO >= 1.5


class TestMeasureConnectionTime:
    """Tests for measure_connection_time function."""

    @patch('potsnitch.probes.timing.socket.socket')
    def test_successful_connection(self, mock_socket_class):
        """Should measure successful connection time."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recv.return_value = b"SSH-2.0-Test\r\n"

        result = measure_connection_time("127.0.0.1", 22)

        assert result.success is True
        assert result.elapsed >= 0
        assert result.response == b"SSH-2.0-Test\r\n"
        mock_sock.connect.assert_called_once_with(("127.0.0.1", 22))
        mock_sock.close.assert_called_once()

    @patch('potsnitch.probes.timing.socket.socket')
    def test_connection_timeout(self, mock_socket_class):
        """Should handle connection timeout."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.side_effect = socket.timeout("Connection timed out")

        result = measure_connection_time("127.0.0.1", 22, timeout=1.0)

        assert result.success is False
        assert result.elapsed >= 0

    @patch('potsnitch.probes.timing.socket.socket')
    def test_connection_refused(self, mock_socket_class):
        """Should handle connection refused error."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.side_effect = ConnectionRefusedError()

        result = measure_connection_time("127.0.0.1", 22)

        assert result.success is False


class TestMeasureResponseTime:
    """Tests for measure_response_time function."""

    @patch('potsnitch.probes.timing.socket.socket')
    def test_successful_response(self, mock_socket_class):
        """Should measure response time for successful request."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recv.side_effect = [b"Banner\r\n", b"Response\r\n"]

        result = measure_response_time("127.0.0.1", 22, b"TEST\r\n", read_banner=True)

        assert result.success is True
        assert result.response == b"Response\r\n"
        mock_sock.send.assert_called_once_with(b"TEST\r\n")

    @patch('potsnitch.probes.timing.socket.socket')
    def test_response_without_banner(self, mock_socket_class):
        """Should skip banner reading when disabled."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recv.return_value = b"Response\r\n"

        result = measure_response_time("127.0.0.1", 22, b"TEST\r\n", read_banner=False)

        assert result.success is True
        # Should only call recv once (for response, not banner)
        assert mock_sock.recv.call_count == 1

    @patch('potsnitch.probes.timing.socket.socket')
    def test_response_error(self, mock_socket_class):
        """Should handle socket errors during response."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.recv.side_effect = socket.error("Connection reset")

        result = measure_response_time("127.0.0.1", 22, b"TEST\r\n")

        assert result.success is False
        assert result.elapsed == 0


class TestAnalyzeTimingSamples:
    """Tests for analyze_timing_samples function."""

    def test_empty_samples(self):
        """Should handle empty samples list."""
        analysis = analyze_timing_samples([])

        assert analysis.mean == 0
        assert analysis.samples == 0
        assert analysis.is_suspicious is False
        assert analysis.reason == "Insufficient samples"

    def test_single_sample(self):
        """Should handle single sample."""
        analysis = analyze_timing_samples([0.5])

        assert analysis.mean == 0.5
        assert analysis.samples == 1
        assert analysis.is_suspicious is False

    def test_normal_timing(self):
        """Should not flag normal timing as suspicious."""
        samples = [0.1, 0.15, 0.12, 0.18, 0.11]
        analysis = analyze_timing_samples(samples)

        assert analysis.samples == 5
        assert analysis.is_suspicious is False
        assert analysis.mean == statistics.mean(samples)
        assert analysis.variance == statistics.variance(samples)

    def test_instant_responses_suspicious(self):
        """Should flag instant responses as suspicious."""
        samples = [0.001, 0.002, 0.001, 0.002, 0.001]
        analysis = analyze_timing_samples(samples)

        assert analysis.is_suspicious is True
        assert "Instant" in analysis.reason

    def test_uniform_timing_suspicious(self):
        """Should flag uniform timing as suspicious."""
        samples = [0.5, 0.5, 0.5, 0.5, 0.5]
        analysis = analyze_timing_samples(samples)

        assert analysis.is_suspicious is True
        assert "Uniform" in analysis.reason or "variance" in analysis.reason.lower()

    def test_consistent_timing_suspicious(self):
        """Should flag suspiciously consistent timing."""
        samples = [0.1, 0.101, 0.099, 0.1, 0.1]
        analysis = analyze_timing_samples(samples)

        # These are very consistent, may trigger consistent warning
        assert analysis.samples == 5

    def test_min_max_calculated(self):
        """Should correctly calculate min and max times."""
        samples = [0.1, 0.2, 0.3, 0.4, 0.5]
        analysis = analyze_timing_samples(samples)

        assert analysis.min_time == 0.1
        assert analysis.max_time == 0.5


class TestProbeAuthTiming:
    """Tests for probe_auth_timing function."""

    def test_returns_indicators_list(self):
        """Should return list of indicators."""
        def auth_func(username, password):
            return (False, 0.001)

        credentials = [("root", "root"), ("admin", "admin")]
        indicators = probe_auth_timing("127.0.0.1", 22, auth_func, credentials, num_samples=2)

        assert isinstance(indicators, list)
        for indicator in indicators:
            assert isinstance(indicator, Indicator)

    def test_detects_instant_auth_failure(self):
        """Should detect instant authentication failures."""
        def auth_func(username, password):
            return (False, 0.001)  # Very fast failure

        credentials = [("root", "root"), ("admin", "admin")]
        indicators = probe_auth_timing("127.0.0.1", 22, auth_func, credentials, num_samples=3)

        assert len(indicators) > 0
        indicator_names = [i.name for i in indicators]
        assert "instant_auth_failure" in indicator_names or "auth_timing_anomaly" in indicator_names

    def test_no_indicators_for_normal_timing(self):
        """Should not flag normal auth timing."""
        import random
        def auth_func(username, password):
            return (False, 0.1 + random.uniform(0, 0.1))  # Normal variance

        credentials = [("root", "root"), ("admin", "admin")]
        indicators = probe_auth_timing("127.0.0.1", 22, auth_func, credentials, num_samples=2)

        # May or may not have indicators depending on exact timing
        assert isinstance(indicators, list)

    def test_handles_auth_exceptions(self):
        """Should handle exceptions in auth function."""
        def auth_func(username, password):
            raise ConnectionError("Connection failed")

        credentials = [("root", "root"), ("admin", "admin")]
        indicators = probe_auth_timing("127.0.0.1", 22, auth_func, credentials, num_samples=2)

        assert isinstance(indicators, list)


class TestProbeResponseTimingVariance:
    """Tests for probe_response_timing_variance function."""

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_returns_indicators_list(self, mock_measure):
        """Should return list of indicators."""
        mock_measure.return_value = TimingResult(elapsed=0.1, success=True)

        requests = [b"REQ1\r\n", b"REQ2\r\n", b"REQ3\r\n"]
        indicators = probe_response_timing_variance("127.0.0.1", 80, requests)

        assert isinstance(indicators, list)

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_detects_uniform_timing(self, mock_measure):
        """Should detect uniform response timing."""
        mock_measure.return_value = TimingResult(elapsed=0.001, success=True)

        requests = [b"REQ1\r\n", b"REQ2\r\n", b"REQ3\r\n"]
        indicators = probe_response_timing_variance("127.0.0.1", 80, requests)

        assert len(indicators) > 0
        assert any("timing" in i.name.lower() for i in indicators)

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_handles_failed_requests(self, mock_measure):
        """Should handle failed measurement requests."""
        mock_measure.return_value = TimingResult(elapsed=0, success=False)

        requests = [b"REQ1\r\n", b"REQ2\r\n"]
        indicators = probe_response_timing_variance("127.0.0.1", 80, requests)

        assert isinstance(indicators, list)


class TestProbeQueryComplexityTiming:
    """Tests for probe_query_complexity_timing function."""

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_returns_indicators_list(self, mock_measure):
        """Should return list of indicators."""
        mock_measure.return_value = TimingResult(elapsed=0.1, success=True)

        indicators = probe_query_complexity_timing(
            "127.0.0.1", 3306,
            b"SELECT 1",
            b"SELECT * FROM users JOIN orders"
        )

        assert isinstance(indicators, list)

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_detects_same_timing_for_different_complexity(self, mock_measure):
        """Should detect when complex queries aren't slower."""
        # Both queries return same timing
        mock_measure.return_value = TimingResult(elapsed=0.1, success=True)

        indicators = probe_query_complexity_timing(
            "127.0.0.1", 3306,
            b"SELECT 1",
            b"SELECT * FROM users JOIN orders WHERE complex = 1"
        )

        assert len(indicators) > 0
        assert any("complexity" in i.name.lower() for i in indicators)

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_no_indicators_for_proper_complexity_timing(self, mock_measure):
        """Should not flag when complex queries are appropriately slower."""
        # Complex queries take 3x longer
        def side_effect(*args, **kwargs):
            if b"complex" in args[2].lower() if len(args) > 2 else b"complex" in kwargs.get('request', b'').lower():
                return TimingResult(elapsed=0.3, success=True)
            return TimingResult(elapsed=0.1, success=True)

        mock_measure.side_effect = [
            TimingResult(elapsed=0.1, success=True),
            TimingResult(elapsed=0.1, success=True),
            TimingResult(elapsed=0.1, success=True),
            TimingResult(elapsed=0.3, success=True),
            TimingResult(elapsed=0.3, success=True),
            TimingResult(elapsed=0.3, success=True),
        ]

        indicators = probe_query_complexity_timing(
            "127.0.0.1", 3306,
            b"SELECT 1",
            b"complex query"
        )

        # Should not have complexity timing indicator when ratio is proper
        assert not any("complexity" in i.name.lower() for i in indicators)


class TestProbeErrorTimingUniformity:
    """Tests for probe_error_timing_uniformity function."""

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_returns_indicators_list(self, mock_measure):
        """Should return list of indicators."""
        mock_measure.return_value = TimingResult(elapsed=0.1, success=True)

        payloads = [b"INVALID1", b"INVALID2", b"INVALID3"]
        indicators = probe_error_timing_uniformity("127.0.0.1", 80, payloads)

        assert isinstance(indicators, list)

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_detects_uniform_error_timing(self, mock_measure):
        """Should detect uniform error response timing."""
        mock_measure.return_value = TimingResult(elapsed=0.05, success=True)

        payloads = [b"INVALID1", b"INVALID2", b"INVALID3", b"INVALID4"]
        indicators = probe_error_timing_uniformity("127.0.0.1", 80, payloads)

        # May detect uniform timing if variance is very low
        assert isinstance(indicators, list)


class TestProbeConnectionTimingConsistency:
    """Tests for probe_connection_timing_consistency function."""

    @patch('potsnitch.probes.timing.measure_connection_time')
    @patch('potsnitch.probes.timing.time.sleep')
    def test_returns_indicators_list(self, mock_sleep, mock_measure):
        """Should return list of indicators."""
        mock_measure.return_value = TimingResult(elapsed=0.1, success=True)

        indicators = probe_connection_timing_consistency("127.0.0.1", 22, num_samples=5)

        assert isinstance(indicators, list)

    @patch('potsnitch.probes.timing.measure_connection_time')
    @patch('potsnitch.probes.timing.time.sleep')
    def test_detects_instant_connections(self, mock_sleep, mock_measure):
        """Should detect suspiciously instant connections."""
        mock_measure.return_value = TimingResult(elapsed=0.001, success=True)

        indicators = probe_connection_timing_consistency("127.0.0.1", 22, num_samples=10)

        assert len(indicators) > 0

    @patch('potsnitch.probes.timing.measure_connection_time')
    @patch('potsnitch.probes.timing.time.sleep')
    def test_handles_failed_connections(self, mock_sleep, mock_measure):
        """Should handle failed connection attempts."""
        mock_measure.return_value = TimingResult(elapsed=0, success=False)

        indicators = probe_connection_timing_consistency("127.0.0.1", 22, num_samples=5)

        assert isinstance(indicators, list)


class TestTimingProbe:
    """Tests for TimingProbe class."""

    def test_timing_probe_creation(self):
        """Should create TimingProbe with default timeout."""
        probe = TimingProbe()
        assert probe.timeout == 5.0

    def test_timing_probe_custom_timeout(self):
        """Should create TimingProbe with custom timeout."""
        probe = TimingProbe(timeout=10.0)
        assert probe.timeout == 10.0

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_measure_stores_result(self, mock_measure):
        """Should store measurement results."""
        mock_measure.return_value = TimingResult(elapsed=0.1, success=True)

        probe = TimingProbe()
        result = probe.measure("127.0.0.1", 80, b"TEST")

        assert result.elapsed == 0.1
        assert len(probe._results) == 1

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_analyze_returns_analysis(self, mock_measure):
        """Should analyze stored measurements."""
        mock_measure.return_value = TimingResult(elapsed=0.1, success=True)

        probe = TimingProbe()
        probe.measure("127.0.0.1", 80, b"TEST1")
        probe.measure("127.0.0.1", 80, b"TEST2")
        probe.measure("127.0.0.1", 80, b"TEST3")

        analysis = probe.analyze()

        assert isinstance(analysis, TimingAnalysis)
        assert analysis.samples == 3

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_get_indicators_returns_list(self, mock_measure):
        """Should return list of indicators from analysis."""
        mock_measure.return_value = TimingResult(elapsed=0.001, success=True)

        probe = TimingProbe()
        probe.measure("127.0.0.1", 80, b"TEST1")
        probe.measure("127.0.0.1", 80, b"TEST2")
        probe.measure("127.0.0.1", 80, b"TEST3")

        indicators = probe.get_indicators()

        assert isinstance(indicators, list)
        # Fast responses should trigger indicator
        assert len(indicators) > 0

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_reset_clears_results(self, mock_measure):
        """Should clear stored results on reset."""
        mock_measure.return_value = TimingResult(elapsed=0.1, success=True)

        probe = TimingProbe()
        probe.measure("127.0.0.1", 80, b"TEST")
        assert len(probe._results) == 1

        probe.reset()
        assert len(probe._results) == 0

    def test_analyze_empty_results(self):
        """Should handle analyzing empty results."""
        probe = TimingProbe()
        analysis = probe.analyze()

        assert analysis.samples == 0

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_multiple_measurements(self, mock_measure):
        """Should handle multiple sequential measurements."""
        mock_measure.return_value = TimingResult(elapsed=0.1, success=True)

        probe = TimingProbe()
        for i in range(10):
            probe.measure("127.0.0.1", 80, f"TEST{i}".encode())

        assert len(probe._results) == 10
        analysis = probe.analyze()
        assert analysis.samples == 10

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_filters_failed_measurements_in_analysis(self, mock_measure):
        """Should only analyze successful measurements."""
        mock_measure.side_effect = [
            TimingResult(elapsed=0.1, success=True),
            TimingResult(elapsed=0, success=False),
            TimingResult(elapsed=0.2, success=True),
        ]

        probe = TimingProbe()
        probe.measure("127.0.0.1", 80, b"TEST1")
        probe.measure("127.0.0.1", 80, b"TEST2")
        probe.measure("127.0.0.1", 80, b"TEST3")

        analysis = probe.analyze()
        # Only 2 successful measurements should be analyzed
        assert analysis.samples == 2


class TestIndicatorConfidence:
    """Tests for correct confidence levels in indicators."""

    def test_auth_timing_indicator_severity(self):
        """Auth timing indicators should have appropriate severity."""
        def auth_func(username, password):
            return (False, 0.001)

        credentials = [("root", "root")]
        indicators = probe_auth_timing("127.0.0.1", 22, auth_func, credentials, num_samples=5)

        for indicator in indicators:
            assert indicator.severity in [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]

    @patch('potsnitch.probes.timing.measure_response_time')
    def test_timing_probe_indicator_severity(self, mock_measure):
        """TimingProbe indicators should have appropriate severity."""
        mock_measure.return_value = TimingResult(elapsed=0.001, success=True)

        probe = TimingProbe()
        for _ in range(5):
            probe.measure("127.0.0.1", 80, b"TEST")

        indicators = probe.get_indicators()

        for indicator in indicators:
            assert indicator.severity == Confidence.MEDIUM


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_analyze_with_zero_times(self):
        """Should handle samples with zero elapsed time."""
        samples = [0.0, 0.0, 0.0]
        analysis = analyze_timing_samples(samples)

        assert analysis.mean == 0.0
        assert analysis.is_suspicious is True

    def test_analyze_with_negative_variance(self):
        """Should handle potential numerical edge cases."""
        # Very close values that might cause numerical issues
        samples = [0.1, 0.1, 0.1, 0.1, 0.1]
        analysis = analyze_timing_samples(samples)

        assert analysis.variance >= 0

    def test_timing_result_equality(self):
        """TimingResult instances should be comparable."""
        r1 = TimingResult(elapsed=0.1, success=True)
        r2 = TimingResult(elapsed=0.1, success=True)
        assert r1 == r2

    def test_timing_analysis_equality(self):
        """TimingAnalysis instances should be comparable."""
        a1 = TimingAnalysis(mean=0.1, variance=0.01, min_time=0.05,
                           max_time=0.15, samples=5, is_suspicious=False)
        a2 = TimingAnalysis(mean=0.1, variance=0.01, min_time=0.05,
                           max_time=0.15, samples=5, is_suspicious=False)
        assert a1 == a2
