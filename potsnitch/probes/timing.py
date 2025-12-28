"""Timing-based honeypot detection utilities.

Honeypots often exhibit timing anomalies:
- Instant responses (no real processing)
- Uniform response times (pre-computed responses)
- No variance across different request types
- Fast authentication failures (no real crypto)
"""

import socket
import statistics
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple, Callable

from potsnitch.core.result import Indicator, Confidence


@dataclass
class TimingResult:
    """Result of a timing measurement."""
    elapsed: float  # Time in seconds
    success: bool  # Whether the operation succeeded
    response: Optional[bytes] = None  # Response data if any


@dataclass
class TimingAnalysis:
    """Analysis of timing measurements."""
    mean: float
    variance: float
    min_time: float
    max_time: float
    samples: int
    is_suspicious: bool
    reason: Optional[str] = None


# Timing thresholds (in seconds)
INSTANT_RESPONSE_THRESHOLD = 0.005  # 5ms - too fast to be real
UNIFORM_VARIANCE_THRESHOLD = 0.0001  # Near-zero variance = suspicious
AUTH_FAILURE_MIN_TIME = 0.05  # Real crypto takes at least 50ms
QUERY_COMPLEXITY_RATIO = 2.0  # Complex queries should take 2x+ longer


def measure_connection_time(target: str, port: int, timeout: float = 5.0) -> TimingResult:
    """Measure time to establish TCP connection and receive first data.

    Honeypots often respond instantly (<5ms) because they're optimized
    for logging, not for realistic service emulation.

    Args:
        target: Target host
        port: Target port
        timeout: Socket timeout

    Returns:
        TimingResult with elapsed time
    """
    start = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        data = sock.recv(1024)
        elapsed = time.perf_counter() - start
        sock.close()
        return TimingResult(elapsed=elapsed, success=True, response=data)
    except (socket.error, socket.timeout, OSError) as e:
        elapsed = time.perf_counter() - start
        return TimingResult(elapsed=elapsed, success=False)


def measure_response_time(
    target: str,
    port: int,
    request: bytes,
    timeout: float = 5.0,
    read_banner: bool = True
) -> TimingResult:
    """Measure time from sending request to receiving response.

    Args:
        target: Target host
        port: Target port
        request: Request data to send
        timeout: Socket timeout
        read_banner: Whether to read initial banner first

    Returns:
        TimingResult with elapsed time
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        if read_banner:
            sock.recv(4096)  # Consume banner

        start = time.perf_counter()
        sock.send(request)
        response = sock.recv(4096)
        elapsed = time.perf_counter() - start

        sock.close()
        return TimingResult(elapsed=elapsed, success=True, response=response)
    except (socket.error, socket.timeout, OSError):
        return TimingResult(elapsed=0, success=False)


def analyze_timing_samples(times: List[float]) -> TimingAnalysis:
    """Analyze a list of timing samples for anomalies.

    Args:
        times: List of elapsed times in seconds

    Returns:
        TimingAnalysis with statistics and suspicion flag
    """
    if not times or len(times) < 2:
        return TimingAnalysis(
            mean=times[0] if times else 0,
            variance=0,
            min_time=times[0] if times else 0,
            max_time=times[0] if times else 0,
            samples=len(times),
            is_suspicious=False,
            reason="Insufficient samples"
        )

    mean = statistics.mean(times)
    variance = statistics.variance(times)
    min_time = min(times)
    max_time = max(times)

    is_suspicious = False
    reason = None

    # Check for instant responses
    if mean < INSTANT_RESPONSE_THRESHOLD:
        is_suspicious = True
        reason = f"Instant responses (mean={mean*1000:.2f}ms < {INSTANT_RESPONSE_THRESHOLD*1000}ms)"

    # Check for uniform timing (near-zero variance)
    elif variance < UNIFORM_VARIANCE_THRESHOLD:
        is_suspicious = True
        reason = f"Uniform timing (variance={variance:.6f} < {UNIFORM_VARIANCE_THRESHOLD})"

    # Check for suspiciously consistent responses
    elif (max_time - min_time) < 0.01 and len(times) >= 5:
        is_suspicious = True
        reason = f"Suspiciously consistent (range={max_time-min_time:.4f}s)"

    return TimingAnalysis(
        mean=mean,
        variance=variance,
        min_time=min_time,
        max_time=max_time,
        samples=len(times),
        is_suspicious=is_suspicious,
        reason=reason
    )


def probe_auth_timing(
    target: str,
    port: int,
    auth_func: Callable[[str, str], Tuple[bool, float]],
    credentials: List[Tuple[str, str]],
    num_samples: int = 5
) -> List[Indicator]:
    """Analyze authentication timing patterns.

    Real systems have variable auth timing due to:
    - Crypto operations (password hashing)
    - Database lookups
    - Rate limiting delays

    Honeypots often have instant/uniform auth failures.

    Args:
        target: Target host
        port: Target port
        auth_func: Function(username, password) -> (success, elapsed_time)
        credentials: List of (username, password) tuples to try
        num_samples: Number of times to test each credential

    Returns:
        List of timing-based indicators
    """
    indicators = []
    failure_times = []
    success_times = []

    for username, password in credentials[:3]:  # Limit to 3 creds
        for _ in range(num_samples):
            try:
                success, elapsed = auth_func(username, password)
                if success:
                    success_times.append(elapsed)
                else:
                    failure_times.append(elapsed)
            except Exception:
                continue

    # Analyze failure timing
    if failure_times:
        analysis = analyze_timing_samples(failure_times)

        if analysis.is_suspicious:
            indicators.append(
                Indicator(
                    name="auth_timing_anomaly",
                    description=f"Authentication timing anomaly: {analysis.reason}",
                    severity=Confidence.MEDIUM,
                    details=f"Mean: {analysis.mean*1000:.2f}ms, Variance: {analysis.variance:.6f}",
                )
            )

        # Check for instant failures (no real crypto)
        if analysis.mean < AUTH_FAILURE_MIN_TIME:
            indicators.append(
                Indicator(
                    name="instant_auth_failure",
                    description="Authentication failures are instant (no crypto processing)",
                    severity=Confidence.HIGH,
                    details=f"Mean failure time: {analysis.mean*1000:.2f}ms",
                )
            )

    return indicators


def probe_response_timing_variance(
    target: str,
    port: int,
    requests: List[bytes],
    timeout: float = 5.0,
    read_banner: bool = True
) -> List[Indicator]:
    """Check if different requests have suspiciously similar response times.

    Real services have varying response times based on request complexity.
    Honeypots often return pre-computed responses with uniform timing.

    Args:
        target: Target host
        port: Target port
        requests: Different requests to send
        timeout: Socket timeout
        read_banner: Whether to read initial banner

    Returns:
        List of timing-based indicators
    """
    indicators = []
    times = []

    for request in requests:
        result = measure_response_time(target, port, request, timeout, read_banner)
        if result.success:
            times.append(result.elapsed)

    if len(times) >= 2:
        analysis = analyze_timing_samples(times)

        if analysis.is_suspicious:
            indicators.append(
                Indicator(
                    name="uniform_response_timing",
                    description=f"Response timing anomaly: {analysis.reason}",
                    severity=Confidence.MEDIUM,
                    details=f"Tested {len(requests)} different requests",
                )
            )

    return indicators


def probe_query_complexity_timing(
    target: str,
    port: int,
    simple_query: bytes,
    complex_query: bytes,
    timeout: float = 5.0
) -> List[Indicator]:
    """Compare timing of simple vs complex queries.

    Real databases take longer for complex queries.
    Honeypots return dummy data at similar speeds.

    Args:
        target: Target host
        port: Target port
        simple_query: Simple query (e.g., SELECT 1)
        complex_query: Complex query (e.g., JOIN with WHERE)
        timeout: Socket timeout

    Returns:
        List of timing-based indicators
    """
    indicators = []

    # Measure simple query multiple times
    simple_times = []
    for _ in range(3):
        result = measure_response_time(target, port, simple_query, timeout)
        if result.success:
            simple_times.append(result.elapsed)

    # Measure complex query multiple times
    complex_times = []
    for _ in range(3):
        result = measure_response_time(target, port, complex_query, timeout)
        if result.success:
            complex_times.append(result.elapsed)

    if simple_times and complex_times:
        simple_mean = statistics.mean(simple_times)
        complex_mean = statistics.mean(complex_times)

        # Complex should be at least 2x slower
        if simple_mean > 0 and complex_mean / simple_mean < QUERY_COMPLEXITY_RATIO:
            indicators.append(
                Indicator(
                    name="no_query_complexity_timing",
                    description="Complex queries not slower than simple queries",
                    severity=Confidence.MEDIUM,
                    details=f"Simple: {simple_mean*1000:.2f}ms, Complex: {complex_mean*1000:.2f}ms",
                )
            )

    return indicators


def probe_error_timing_uniformity(
    target: str,
    port: int,
    invalid_payloads: List[bytes],
    timeout: float = 5.0
) -> List[Indicator]:
    """Check if different error conditions have uniform timing.

    Real services handle different errors differently, causing timing variance.
    Honeypots often have a single error path with uniform timing.

    Args:
        target: Target host
        port: Target port
        invalid_payloads: Different malformed payloads to send
        timeout: Socket timeout

    Returns:
        List of timing-based indicators
    """
    indicators = []
    times = []

    for payload in invalid_payloads:
        result = measure_response_time(target, port, payload, timeout, read_banner=True)
        if result.success or result.elapsed > 0:
            times.append(result.elapsed)

    if len(times) >= 3:
        analysis = analyze_timing_samples(times)

        if analysis.variance < UNIFORM_VARIANCE_THRESHOLD:
            indicators.append(
                Indicator(
                    name="uniform_error_timing",
                    description="All error responses have identical timing",
                    severity=Confidence.MEDIUM,
                    details=f"Variance: {analysis.variance:.8f} across {len(times)} different errors",
                )
            )

    return indicators


def probe_connection_timing_consistency(
    target: str,
    port: int,
    num_samples: int = 10
) -> List[Indicator]:
    """Measure connection timing consistency across multiple attempts.

    Real services have network-induced variance.
    Local honeypots have very consistent timing.

    Args:
        target: Target host
        port: Target port
        num_samples: Number of connection attempts

    Returns:
        List of timing-based indicators
    """
    indicators = []
    times = []

    for _ in range(num_samples):
        result = measure_connection_time(target, port)
        if result.success:
            times.append(result.elapsed)
        time.sleep(0.1)  # Small delay between attempts

    if len(times) >= 5:
        analysis = analyze_timing_samples(times)

        if analysis.is_suspicious:
            indicators.append(
                Indicator(
                    name="connection_timing_anomaly",
                    description=f"Connection timing anomaly: {analysis.reason}",
                    severity=Confidence.LOW,
                    details=f"Tested {num_samples} connections",
                )
            )

    return indicators


class TimingProbe:
    """Reusable timing probe for integration with detectors."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._results: List[TimingResult] = []

    def measure(self, target: str, port: int, request: bytes) -> TimingResult:
        """Take a timing measurement and store it."""
        result = measure_response_time(target, port, request, self.timeout)
        self._results.append(result)
        return result

    def analyze(self) -> TimingAnalysis:
        """Analyze all stored measurements."""
        times = [r.elapsed for r in self._results if r.success]
        return analyze_timing_samples(times)

    def get_indicators(self) -> List[Indicator]:
        """Get indicators from timing analysis."""
        indicators = []
        analysis = self.analyze()

        if analysis.is_suspicious:
            indicators.append(
                Indicator(
                    name="timing_anomaly",
                    description=analysis.reason or "Timing anomaly detected",
                    severity=Confidence.MEDIUM,
                    details=f"Samples: {analysis.samples}, Mean: {analysis.mean*1000:.2f}ms",
                )
            )

        return indicators

    def reset(self):
        """Clear stored measurements."""
        self._results = []
