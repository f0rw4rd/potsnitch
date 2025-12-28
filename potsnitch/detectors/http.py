"""HTTP/Web honeypot detector (Glastopf, generic web honeypots).

Detection is split into:
- PASSIVE: Server headers, X-Powered-By, content hashes, error page signatures
- ACTIVE: Endpoint probing, path traversal tests, CVE paths, vulnerability tests
"""

import hashlib
from typing import Optional

from potsnitch.core.base import BaseDetector, DetectionMode, register_detector
from potsnitch.core.result import DetectionResult, Indicator, Confidence


# Known website content hashes (from checkpot)
KNOWN_WEBSITE_HASHES = {
    "c59e04f46e25c454e65544c236abd9d71705cc4e5c4b4b7dc3ff83fec0e9402f": "shockpot",
    "d405fe3c5b902342565cbf5523bb44a78c6bfb15b38a40c81a5f7bf4d8eb7838": "honeything",
    "351190a71ddca564e471600c3d403fd8042e6888c8c6abe9cdfe536cef005e82": "dionaea",
    "576137c8755b80c0751baa18c8306465fa02c641c683caf8b6d19469a5b96b86": "amun",
}

# Known stylesheet hashes (from checkpot)
KNOWN_STYLESHEET_HASHES = {
    "1118635ac91417296e67cd0f3e6f9927e5f502e328b92bb3888b3b789a49a257": "glastopf",
}

# Known SSL certificate signatures (from honeyscanner)
KNOWN_CERT_SIGNATURES = [
    "dionaea.carnivore.it",
]


# Known CVE and vulnerability paths that honeypots often respond to
HONEYPOT_VULN_PATHS = [
    "/cgi-bin/php",
    "/cgi-bin/php-cgi",
    "/.git/config",
    "/.env",
    "/wp-admin/",
    "/phpmyadmin/",
    "/admin/",
    "/shell",
    "/cmd.php",
    "/xmlrpc.php",
    "/wp-login.php",
    "/.aws/credentials",
    "/config.php",
    "/backup.sql",
]

# Path traversal test patterns
PATH_TRAVERSAL_TESTS = [
    "/../../../etc/passwd",
    "/....//....//etc/passwd",
    "/%2e%2e/%2e%2e/etc/passwd",
]


@register_detector
class HTTPDetector(BaseDetector):
    """Detector for HTTP/Web honeypots.

    Static (Passive) Detection:
    - Server headers and X-Powered-By analysis
    - Known content hashes for honeypot defaults
    - Stylesheet fingerprinting
    - Response header anomalies

    Dynamic (Active) Detection:
    - Endpoint probing for fake vulnerability responses
    - Path traversal test responses
    - CVE path detection (honeypots respond to everything)
    - Error page consistency analysis
    """

    name = "http"
    description = "Detects web honeypots via content hashing, headers, and SSL analysis"
    honeypot_types = ["glastopf", "shockpot", "honeything", "wordpot", "snare"]
    default_ports = [80, 8080, 8888]

    def detect_passive(self, target: str, port: int) -> DetectionResult:
        """Run passive/static HTTP detection.

        Checks headers, content hashes, and stylesheets without
        sending exploit-like requests.

        Args:
            target: IP address or hostname
            port: HTTP port

        Returns:
            DetectionResult with passive findings
        """
        result = DetectionResult(target=target, port=port)

        try:
            import requests

            base_url = f"http://{target}:{port}"

            # Check main page content hash
            self._check_content_hash(base_url, result)

            # Check for honeypot-specific response patterns (headers)
            self._check_response_patterns(base_url, result)

        except Exception:
            pass

        return result

    def detect_active(self, target: str, port: int) -> DetectionResult:
        """Run active/dynamic HTTP probing.

        Sends exploit-like requests to detect honeypot behaviors:
        - Checks if server responds with fake vulnerabilities
        - Tests path traversal responses
        - Probes for CVE-specific paths

        Args:
            target: IP address or hostname
            port: HTTP port

        Returns:
            DetectionResult with active findings
        """
        result = DetectionResult(target=target, port=port)

        try:
            import requests

            base_url = f"http://{target}:{port}"

            # Check error handling (404 pages, etc.)
            self._check_error_handling(base_url, result)

            # Probe vulnerability paths
            self._probe_vuln_paths(base_url, result)

            # Test path traversal responses
            self._probe_path_traversal(base_url, result)

        except Exception:
            pass

        return result

    def _check_content_hash(self, base_url: str, result: DetectionResult) -> None:
        """Check if website content matches known honeypot hashes."""
        try:
            import requests

            response = requests.get(f"{base_url}/", timeout=self.timeout)

            if response.status_code == 200:
                content = response.content
                content_hash = hashlib.sha256(content).hexdigest()

                if content_hash in KNOWN_WEBSITE_HASHES:
                    honeypot = KNOWN_WEBSITE_HASHES[content_hash]
                    result.add_indicator(
                        Indicator(
                            name="known_website_hash",
                            description=f"Website content matches known {honeypot} hash",
                            severity=Confidence.DEFINITE,
                        )
                    )
                    result.honeypot_type = honeypot

                # Check for CSS/stylesheet
                if "text/html" in response.headers.get("Content-Type", ""):
                    self._check_stylesheets(base_url, response.text, result)

        except Exception:
            pass

    def _check_stylesheets(self, base_url: str, html: str, result: DetectionResult) -> None:
        """Check linked stylesheets for honeypot signatures."""
        try:
            import requests
            import re

            # Find CSS links
            css_links = re.findall(r'href=["\']([^"\']+\.css)["\']', html)

            for css_link in css_links:
                if not css_link.startswith("http"):
                    css_url = f"{base_url}/{css_link.lstrip('/')}"
                else:
                    css_url = css_link

                try:
                    css_response = requests.get(css_url, timeout=self.timeout)
                    if css_response.status_code == 200:
                        css_hash = hashlib.sha256(css_response.content).hexdigest()

                        if css_hash in KNOWN_STYLESHEET_HASHES:
                            honeypot = KNOWN_STYLESHEET_HASHES[css_hash]
                            result.add_indicator(
                                Indicator(
                                    name="known_stylesheet_hash",
                                    description=f"Stylesheet matches known {honeypot} hash",
                                    severity=Confidence.HIGH,
                                )
                            )
                            result.honeypot_type = honeypot
                except Exception:
                    pass

        except Exception:
            pass

    def _check_response_patterns(self, base_url: str, result: DetectionResult) -> None:
        """Check for honeypot-specific response patterns."""
        try:
            import requests

            response = requests.get(f"{base_url}/", timeout=self.timeout)

            # Check server header
            server = response.headers.get("Server", "")

            # Missing server header can be suspicious
            if not server:
                result.add_indicator(
                    Indicator(
                        name="missing_server_header",
                        description="Missing Server header",
                        severity=Confidence.LOW,
                    )
                )

            # Check for unusual server strings
            honeypot_servers = ["honeypot", "python", "twisted"]
            for hp_server in honeypot_servers:
                if hp_server.lower() in server.lower():
                    result.add_indicator(
                        Indicator(
                            name="suspicious_server_header",
                            description=f"Suspicious Server header: {server}",
                            severity=Confidence.MEDIUM,
                        )
                    )

            # Check for Glastopf-specific content patterns
            if "Gutenberg" in response.text or "Project Gutenberg" in response.text:
                result.add_indicator(
                    Indicator(
                        name="glastopf_content",
                        description="Glastopf-style content (Project Gutenberg text)",
                        severity=Confidence.HIGH,
                        details="Glastopf uses Project Gutenberg text as filler content",
                    )
                )
                result.honeypot_type = "glastopf"

        except Exception:
            pass

    def _check_error_handling(self, base_url: str, result: DetectionResult) -> None:
        """Check error page handling for honeypot indicators."""
        try:
            import requests

            # Request non-existent page
            response = requests.get(
                f"{base_url}/nonexistent_page_test_12345.html",
                timeout=self.timeout,
            )

            # Many honeypots return 200 for all paths
            if response.status_code == 200:
                # Check if it's the same as the main page
                main_response = requests.get(f"{base_url}/", timeout=self.timeout)
                if response.text == main_response.text:
                    result.add_indicator(
                        Indicator(
                            name="same_response_all_paths",
                            description="Server returns same content for all paths",
                            severity=Confidence.MEDIUM,
                            details="Honeypots often return identical content regardless of path",
                        )
                    )

            # Check for generic/fake 404 pages
            if response.status_code == 404:
                if len(response.text) < 50:
                    result.add_indicator(
                        Indicator(
                            name="minimal_404",
                            description="Minimal 404 error page",
                            severity=Confidence.LOW,
                        )
                    )

        except Exception:
            pass

    def _probe_vuln_paths(self, base_url: str, result: DetectionResult) -> None:
        """Probe for vulnerability paths that honeypots commonly respond to.

        Real servers typically return 404 for these paths, while honeypots
        often return 200 with fake content to attract attackers.
        """
        try:
            import requests

            successful_paths = []

            for path in HONEYPOT_VULN_PATHS:
                try:
                    response = requests.get(
                        f"{base_url}{path}",
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
                    # Real servers return 404, honeypots often return 200
                    if response.status_code == 200:
                        successful_paths.append(path)
                except Exception:
                    pass

            # If many vulnerability paths return 200, likely a honeypot
            if len(successful_paths) >= 5:
                result.add_indicator(
                    Indicator(
                        name="vuln_paths_accessible",
                        description=f"Many vulnerability paths return 200 ({len(successful_paths)} paths)",
                        severity=Confidence.HIGH,
                        details=f"Accessible: {', '.join(successful_paths[:5])}...",
                    )
                )
            elif len(successful_paths) >= 3:
                result.add_indicator(
                    Indicator(
                        name="vuln_paths_accessible",
                        description=f"Some vulnerability paths return 200 ({len(successful_paths)} paths)",
                        severity=Confidence.MEDIUM,
                        details=f"Accessible: {', '.join(successful_paths)}",
                    )
                )

        except Exception:
            pass

    def _probe_path_traversal(self, base_url: str, result: DetectionResult) -> None:
        """Test path traversal responses.

        Honeypots often respond with fake /etc/passwd content to
        path traversal attempts. Real servers block or return 404.
        """
        try:
            import requests

            for traversal_path in PATH_TRAVERSAL_TESTS:
                try:
                    response = requests.get(
                        f"{base_url}{traversal_path}",
                        timeout=self.timeout,
                        allow_redirects=False,
                    )

                    # Check if response contains fake passwd content
                    if response.status_code == 200:
                        content = response.text.lower()
                        if "root:" in content or "/bin/bash" in content or "/bin/sh" in content:
                            result.add_indicator(
                                Indicator(
                                    name="path_traversal_response",
                                    description="Server responds with passwd-like content to path traversal",
                                    severity=Confidence.DEFINITE,
                                    details=f"Path {traversal_path} returned passwd-like content",
                                )
                            )
                            return

                except Exception:
                    pass

        except Exception:
            pass

    def get_recommendations(self, result: DetectionResult) -> list[str]:
        """Get remediation recommendations for HTTP honeypots."""
        recommendations = []

        for indicator in result.indicators:
            if "hash" in indicator.name:
                recommendations.append(
                    "Customize website content - don't use default templates"
                )
            elif "server_header" in indicator.name:
                recommendations.append(
                    "Configure a realistic Server header (e.g., Apache, nginx)"
                )
            elif "glastopf" in indicator.name:
                recommendations.append(
                    "Replace default Glastopf content with custom content"
                )
            elif "same_response" in indicator.name:
                recommendations.append(
                    "Implement proper URL routing with different responses per path"
                )
            elif "vuln_paths" in indicator.name:
                recommendations.append(
                    "Configure proper 404 responses for non-existent vulnerability paths"
                )
            elif "path_traversal" in indicator.name:
                recommendations.append(
                    "Avoid returning fake /etc/passwd content - it's a strong honeypot indicator"
                )

        return recommendations
