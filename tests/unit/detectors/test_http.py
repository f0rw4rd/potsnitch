"""
Unit tests for HTTP honeypot detector.

Tests cover:
- Header detection (Server, X-Powered-By)
- Response pattern matching
- Path probing (/robots.txt, /.git)
- Known content hash detection
- HellPot detection patterns
- Glastopf detection
"""

import hashlib
import pytest
from unittest.mock import MagicMock, patch

from potsnitch.detectors.http import (
    HTTPDetector,
    KNOWN_WEBSITE_HASHES,
    KNOWN_STYLESHEET_HASHES,
    HONEYPOT_VULN_PATHS,
    PATH_TRAVERSAL_TESTS,
)
from potsnitch.core.base import DetectionMode
from potsnitch.core.result import Confidence


class TestHTTPHeaderDetection:
    """Test HTTP header-based detection."""

    def test_missing_server_header(self):
        """Test detection of missing Server header."""
        detector = HTTPDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {}  # No Server header
            mock_response.content = b"<html>Test</html>"
            mock_response.text = "<html>Test</html>"
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "missing_server_header" in indicator_names

    @pytest.mark.parametrize(
        "server_header",
        [
            "honeypot",
            "Python/3.8",
            "Twisted/20.3.0",
            "SimpleHTTP/Python",
        ],
    )
    def test_suspicious_server_headers(self, server_header):
        """Test detection of suspicious Server headers."""
        detector = HTTPDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"Server": server_header}
            mock_response.content = b"<html>Test</html>"
            mock_response.text = "<html>Test</html>"
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "suspicious_server_header" in indicator_names

    def test_normal_server_header(self):
        """Test that normal Server headers don't trigger detection."""
        detector = HTTPDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"Server": "nginx/1.18.0"}
            mock_response.content = b"<html>Welcome</html>"
            mock_response.text = "<html>Welcome</html>"
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "suspicious_server_header" not in indicator_names


class TestHTTPContentHashDetection:
    """Test known content hash detection."""

    @pytest.mark.parametrize(
        "honeypot_name,content_hash",
        [
            ("shockpot", "c59e04f46e25c454e65544c236abd9d71705cc4e5c4b4b7dc3ff83fec0e9402f"),
            ("honeything", "d405fe3c5b902342565cbf5523bb44a78c6bfb15b38a40c81a5f7bf4d8eb7838"),
            ("dionaea", "351190a71ddca564e471600c3d403fd8042e6888c8c6abe9cdfe536cef005e82"),
            ("amun", "576137c8755b80c0751baa18c8306465fa02c641c683caf8b6d19469a5b96b86"),
        ],
    )
    def test_known_website_hash_detection(self, honeypot_name, content_hash):
        """Test detection of known honeypot website hashes."""
        detector = HTTPDetector()

        # Create content that matches the hash
        # We need to mock the hash check since we don't have actual content
        with patch("requests.get") as mock_get, patch(
            "hashlib.sha256"
        ) as mock_hash:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"Content-Type": "text/html"}
            mock_response.content = b"honeypot content"
            mock_response.text = "honeypot content"
            mock_get.return_value = mock_response

            # Mock hash to return the known hash
            mock_hash_instance = MagicMock()
            mock_hash_instance.hexdigest.return_value = content_hash
            mock_hash.return_value = mock_hash_instance

            result = detector.detect_passive("192.168.1.1", 80)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "known_website_hash" in indicator_names
        assert result.honeypot_type == honeypot_name

    def test_known_stylesheet_hash_detection(self):
        """Test detection of known honeypot stylesheet hashes."""
        detector = HTTPDetector()
        glastopf_css_hash = "1118635ac91417296e67cd0f3e6f9927e5f502e328b92bb3888b3b789a49a257"

        with patch("requests.get") as mock_get:
            # First call is for main page
            main_response = MagicMock()
            main_response.status_code = 200
            main_response.headers = {"Content-Type": "text/html"}
            main_response.content = b"not a known hash content"
            main_response.text = '<html><link href="style.css"></html>'

            # Second call is for CSS file
            css_response = MagicMock()
            css_response.status_code = 200
            css_response.content = b"css content"

            mock_get.side_effect = [main_response, css_response]

            # Mock the CSS hash calculation
            with patch("hashlib.sha256") as mock_hash:
                # First hash is for main content (unknown)
                # Second hash is for CSS (known glastopf)
                mock_hash_instance1 = MagicMock()
                mock_hash_instance1.hexdigest.return_value = "unknown_hash"

                mock_hash_instance2 = MagicMock()
                mock_hash_instance2.hexdigest.return_value = glastopf_css_hash

                mock_hash.side_effect = [mock_hash_instance1, mock_hash_instance2]

                result = detector.detect_passive("192.168.1.1", 80)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "known_stylesheet_hash" in indicator_names


class TestHTTPGlastopfDetection:
    """Test Glastopf-specific detection."""

    def test_glastopf_gutenberg_content(self):
        """Test detection of Glastopf Project Gutenberg content."""
        detector = HTTPDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"Server": "Apache"}
            mock_response.content = b"<html>Project Gutenberg text here</html>"
            mock_response.text = "<html>Project Gutenberg text here</html>"
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 80)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "glastopf_content" in indicator_names
        assert result.honeypot_type == "glastopf"


class TestHTTPPathProbing:
    """Test vulnerability path probing."""

    def test_many_vuln_paths_accessible(self):
        """Test detection when many vulnerability paths return 200."""
        detector = HTTPDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "Fake content"
            mock_get.return_value = mock_response

            result = detector._probe_vuln_paths("http://192.168.1.1:80", result=MagicMock())

            # Create proper result object and call
            from potsnitch.core.result import DetectionResult
            result = DetectionResult(target="192.168.1.1", port=80)
            detector._probe_vuln_paths("http://192.168.1.1:80", result)

        indicator_names = [ind.name for ind in result.indicators]
        assert "vuln_paths_accessible" in indicator_names
        # Check severity is HIGH when many paths accessible
        vuln_ind = [ind for ind in result.indicators if ind.name == "vuln_paths_accessible"]
        assert vuln_ind[0].severity in (Confidence.HIGH, Confidence.MEDIUM)

    def test_proper_404_responses(self):
        """Test when paths properly return 404."""
        detector = HTTPDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_get.return_value = mock_response

            from potsnitch.core.result import DetectionResult
            result = DetectionResult(target="192.168.1.1", port=80)
            detector._probe_vuln_paths("http://192.168.1.1:80", result)

        # No vuln_paths_accessible indicator should be added
        indicator_names = [ind.name for ind in result.indicators]
        assert "vuln_paths_accessible" not in indicator_names


class TestHTTPPathTraversal:
    """Test path traversal response detection."""

    @pytest.mark.parametrize(
        "passwd_content",
        [
            "root:x:0:0:root:/root:/bin/bash",
            "root:x:0:0::/root:/bin/sh",
            "daemon:x:1:1:daemon:/usr/sbin:/bin/sh",
        ],
    )
    def test_path_traversal_passwd_response(self, passwd_content):
        """Test detection of passwd-like content in path traversal response."""
        detector = HTTPDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = passwd_content
            mock_get.return_value = mock_response

            from potsnitch.core.result import DetectionResult
            result = DetectionResult(target="192.168.1.1", port=80)
            detector._probe_path_traversal("http://192.168.1.1:80", result)

        assert result.is_honeypot
        indicator_names = [ind.name for ind in result.indicators]
        assert "path_traversal_response" in indicator_names
        # This is definite honeypot indicator
        traversal_ind = [
            ind for ind in result.indicators if ind.name == "path_traversal_response"
        ]
        assert traversal_ind[0].severity == Confidence.DEFINITE

    def test_path_traversal_blocked(self):
        """Test when path traversal is properly blocked."""
        detector = HTTPDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 403  # Forbidden
            mock_response.text = "Access denied"
            mock_get.return_value = mock_response

            from potsnitch.core.result import DetectionResult
            result = DetectionResult(target="192.168.1.1", port=80)
            detector._probe_path_traversal("http://192.168.1.1:80", result)

        indicator_names = [ind.name for ind in result.indicators]
        assert "path_traversal_response" not in indicator_names


class TestHTTPErrorHandling:
    """Test HTTP error page handling."""

    def test_same_response_all_paths(self):
        """Test detection when all paths return same content."""
        detector = HTTPDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "Same content everywhere"
            mock_get.return_value = mock_response

            from potsnitch.core.result import DetectionResult
            result = DetectionResult(target="192.168.1.1", port=80)
            detector._check_error_handling("http://192.168.1.1:80", result)

        indicator_names = [ind.name for ind in result.indicators]
        assert "same_response_all_paths" in indicator_names

    def test_minimal_404_page(self):
        """Test detection of minimal 404 error page."""
        detector = HTTPDetector()

        with patch("requests.get") as mock_get:
            # First call: nonexistent page returns minimal 404
            error_response = MagicMock()
            error_response.status_code = 404
            error_response.text = "404"  # Very minimal

            mock_get.return_value = error_response

            from potsnitch.core.result import DetectionResult
            result = DetectionResult(target="192.168.1.1", port=80)
            detector._check_error_handling("http://192.168.1.1:80", result)

        indicator_names = [ind.name for ind in result.indicators]
        assert "minimal_404" in indicator_names


class TestHTTPDetectorModes:
    """Test HTTP detector in different modes."""

    def test_passive_mode(self):
        """Test detector in passive mode."""
        detector = HTTPDetector(mode=DetectionMode.PASSIVE)

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"Server": "honeypot/1.0"}
            mock_response.content = b"<html>Test</html>"
            mock_response.text = "<html>Test</html>"
            mock_get.return_value = mock_response

            result = detector.detect("192.168.1.1", 80)

        indicator_names = [ind.name for ind in result.indicators]
        assert "suspicious_server_header" in indicator_names

    def test_active_mode(self):
        """Test detector in active mode."""
        detector = HTTPDetector(mode=DetectionMode.ACTIVE)

        with patch("requests.get") as mock_get:
            # Simulate path traversal vulnerability
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "root:x:0:0:root:/root:/bin/bash"
            mock_get.return_value = mock_response

            result = detector.detect("192.168.1.1", 80)

        assert result.is_honeypot


class TestHTTPConnectionErrors:
    """Test HTTP detector error handling."""

    def test_connection_error(self):
        """Test handling of connection error."""
        detector = HTTPDetector()

        with patch("requests.get") as mock_get:
            import requests
            mock_get.side_effect = requests.ConnectionError()

            result = detector.detect_passive("192.168.1.1", 80)

        assert not result.is_honeypot
        assert len(result.indicators) == 0

    def test_timeout_error(self):
        """Test handling of timeout."""
        detector = HTTPDetector(timeout=1.0)

        with patch("requests.get") as mock_get:
            import requests
            mock_get.side_effect = requests.Timeout()

            result = detector.detect_passive("192.168.1.1", 80)

        assert not result.is_honeypot


class TestHTTPRecommendations:
    """Test HTTP detector recommendations."""

    def test_recommendations_for_hash(self):
        """Test recommendations for content hash detection."""
        detector = HTTPDetector()
        from potsnitch.core.result import DetectionResult, Indicator

        result = DetectionResult(target="192.168.1.1", port=80)
        result.add_indicator(
            Indicator(
                name="known_website_hash",
                description="Known honeypot hash",
                severity=Confidence.DEFINITE,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("content" in r.lower() for r in recommendations)

    def test_recommendations_for_server_header(self):
        """Test recommendations for suspicious server header."""
        detector = HTTPDetector()
        from potsnitch.core.result import DetectionResult, Indicator

        result = DetectionResult(target="192.168.1.1", port=80)
        result.add_indicator(
            Indicator(
                name="suspicious_server_header",
                description="Suspicious header",
                severity=Confidence.MEDIUM,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("server" in r.lower() or "header" in r.lower() for r in recommendations)

    def test_recommendations_for_path_traversal(self):
        """Test recommendations for path traversal response."""
        detector = HTTPDetector()
        from potsnitch.core.result import DetectionResult, Indicator

        result = DetectionResult(target="192.168.1.1", port=80)
        result.add_indicator(
            Indicator(
                name="path_traversal_response",
                description="Path traversal detected",
                severity=Confidence.DEFINITE,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any("passwd" in r.lower() or "traversal" in r.lower() for r in recommendations)
