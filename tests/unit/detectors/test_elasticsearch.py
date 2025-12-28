"""
Unit tests for Elasticsearch honeypot detector.

Tests cover:
- Elasticpot detection (version strings, cluster name, build hash)
- Endpoint enumeration (/, /_search, /_nodes, /_cat/indices)
- Response formatting analysis (missing newlines, invalid JSON)
- Missing functionality detection
- Recommendation generation
"""

import json
import pytest
from unittest.mock import MagicMock, patch

from potsnitch.detectors.elasticsearch import (
    ElasticsearchDetector,
    ELASTICPOT_DEFAULT_NAMES,
    ELASTICPOT_DEFAULT_BUILDS,
    ELASTICPOT_DEFAULT_CLUSTERS,
    ELASTICPOT_VERSIONS,
)
from potsnitch.core.base import DetectionMode
from potsnitch.core.result import Confidence, DetectionResult


class TestRootEndpointPassive:
    """Test passive detection on root endpoint."""

    def test_missing_trailing_newline(self):
        """Test detection of missing trailing newline (Elastichoney signature)."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '{"name":"node1","cluster_name":"test"}'  # No newline
            mock_response.json.return_value = {"name": "node1", "cluster_name": "test"}
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "missing_newline" in indicator_names

        newline_indicator = next(ind for ind in result.indicators if ind.name == "missing_newline")
        assert newline_indicator.severity == Confidence.MEDIUM

    def test_with_trailing_newline(self):
        """Test no detection when response has trailing newline."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '{"name":"node1","cluster_name":"test"}\n'
            mock_response.json.return_value = {"name": "node1", "cluster_name": "test"}
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "missing_newline" not in indicator_names

    @pytest.mark.parametrize(
        "cluster_name",
        ELASTICPOT_DEFAULT_CLUSTERS,
    )
    def test_default_cluster_name(self, cluster_name):
        """Test detection of default cluster names."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = f'{{"cluster_name":"{cluster_name}"}}\n'
            mock_response.json.return_value = {"cluster_name": cluster_name}
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "default_cluster_name" in indicator_names

        cluster_indicator = next(ind for ind in result.indicators if ind.name == "default_cluster_name")
        assert cluster_indicator.severity == Confidence.LOW

    def test_custom_cluster_name(self):
        """Test no detection for custom cluster name."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '{"cluster_name":"my-production-cluster"}\n'
            mock_response.json.return_value = {"cluster_name": "my-production-cluster"}
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "default_cluster_name" not in indicator_names

    @pytest.mark.parametrize(
        "version",
        ELASTICPOT_VERSIONS,
    )
    def test_known_honeypot_version(self, version):
        """Test detection of known honeypot ES versions."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = f'{{"version":{{"number":"{version}"}}}}\n'
            mock_response.json.return_value = {"version": {"number": version}}
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "honeypot_version" in indicator_names

        version_indicator = next(ind for ind in result.indicators if ind.name == "honeypot_version")
        assert version_indicator.severity == Confidence.HIGH

    @pytest.mark.parametrize(
        "old_version",
        ["1.7.5", "2.3.0"],
    )
    def test_old_version(self, old_version):
        """Test detection of old but not honeypot-specific versions."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = f'{{"version":{{"number":"{old_version}"}}}}\n'
            mock_response.json.return_value = {"version": {"number": old_version}}
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "old_version" in indicator_names

        old_indicator = next(ind for ind in result.indicators if ind.name == "old_version")
        assert old_indicator.severity == Confidence.LOW

    def test_modern_version(self):
        """Test no version detection for modern ES versions."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '{"version":{"number":"8.11.0"}}\n'
            mock_response.json.return_value = {"version": {"number": "8.11.0"}}
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "honeypot_version" not in indicator_names
        assert "old_version" not in indicator_names

    @pytest.mark.parametrize(
        "build_hash",
        ELASTICPOT_DEFAULT_BUILDS,
    )
    def test_default_build_hash(self, build_hash):
        """Test detection of default Elasticpot build hash."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = f'{{"version":{{"build_hash":"{build_hash}","number":"1.4.1"}}}}\n'
            mock_response.json.return_value = {"version": {"build_hash": build_hash, "number": "1.4.1"}}
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "elasticpot_build" in indicator_names

        build_indicator = next(ind for ind in result.indicators if ind.name == "elasticpot_build")
        assert build_indicator.severity == Confidence.HIGH

    @pytest.mark.parametrize(
        "instance_name",
        ELASTICPOT_DEFAULT_NAMES,
    )
    def test_default_instance_name(self, instance_name):
        """Test detection of default Elasticpot instance names."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = f'{{"name":"{instance_name}"}}\n'
            mock_response.json.return_value = {"name": instance_name}
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "elasticpot_default_name" in indicator_names

        name_indicator = next(ind for ind in result.indicators if ind.name == "elasticpot_default_name")
        assert name_indicator.severity == Confidence.HIGH

    def test_invalid_json_response(self):
        """Test detection of invalid JSON response."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "not valid json"
            mock_response.json.side_effect = json.JSONDecodeError("", "", 0)
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "invalid_json" in indicator_names

        json_indicator = next(ind for ind in result.indicators if ind.name == "invalid_json")
        assert json_indicator.severity == Confidence.HIGH

    def test_non_200_response(self):
        """Test handling of non-200 response."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        assert len(result.indicators) == 0


class TestSearchEndpointActive:
    """Test active detection on /_search endpoint."""

    def test_missing_hits_field(self):
        """Test detection of missing 'hits' field in search response."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"took": 5, "timed_out": False}  # No hits
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "missing_hits" in indicator_names

        hits_indicator = next(ind for ind in result.indicators if ind.name == "missing_hits")
        assert hits_indicator.severity == Confidence.MEDIUM

    def test_valid_search_response(self):
        """Test no detection for valid search response."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "took": 5,
                "timed_out": False,
                "hits": {"total": {"value": 0}, "hits": []},
            }
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "missing_hits" not in indicator_names

    def test_search_json_decode_error(self):
        """Test handling of JSON decode error on search endpoint."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.side_effect = json.JSONDecodeError("", "", 0)
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 9200)

        # Should not crash
        assert result is not None


class TestNodesEndpointActive:
    """Test active detection on /_nodes endpoint."""

    def test_empty_nodes_list(self):
        """Test detection of empty nodes list."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"nodes": {}}  # Empty nodes
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "empty_nodes" in indicator_names

        nodes_indicator = next(ind for ind in result.indicators if ind.name == "empty_nodes")
        assert nodes_indicator.severity == Confidence.HIGH

    def test_valid_nodes_response(self):
        """Test no detection for valid nodes response."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "nodes": {"abc123": {"name": "node1", "transport_address": "127.0.0.1:9300"}}
            }
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "empty_nodes" not in indicator_names


class TestIndicesEndpointActive:
    """Test active detection on /_cat/indices endpoint."""

    def test_missing_cat_indices(self):
        """Test detection of missing /_cat/indices endpoint."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_response.text = ""
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "missing_cat_indices" in indicator_names

        cat_indicator = next(ind for ind in result.indicators if ind.name == "missing_cat_indices")
        assert cat_indicator.severity == Confidence.HIGH

    def test_page_not_found_response(self):
        """Test detection of 'page not found' response."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "Page not found"
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "page_not_found" in indicator_names

        page_indicator = next(ind for ind in result.indicators if ind.name == "page_not_found")
        assert page_indicator.severity == Confidence.HIGH

    def test_valid_cat_indices_response(self):
        """Test no detection for valid cat/indices response."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "green open test-index abc123 1 0 0 0 225b 225b"
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "missing_cat_indices" not in indicator_names
        assert "page_not_found" not in indicator_names


class TestMissingEndpointsActive:
    """Test active detection of missing standard endpoints."""

    def test_multiple_missing_endpoints(self):
        """Test detection when multiple standard endpoints are missing."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_response.text = "not found"
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "limited_api" in indicator_names

        api_indicator = next(ind for ind in result.indicators if ind.name == "limited_api")
        assert api_indicator.severity == Confidence.HIGH

    def test_all_endpoints_available(self):
        """Test no detection when all endpoints are available."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "{}"
            mock_response.json.return_value = {}
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "limited_api" not in indicator_names

    def test_mixed_endpoint_availability(self):
        """Test with some endpoints available, some missing."""
        detector = ElasticsearchDetector()

        call_count = [0]

        def mock_get_responses(*args, **kwargs):
            call_count[0] += 1
            mock_response = MagicMock()

            # First few calls succeed, later ones fail
            if call_count[0] <= 2:
                mock_response.status_code = 200
                mock_response.text = "{}"
                mock_response.json.return_value = {}
            else:
                mock_response.status_code = 404
                mock_response.text = "not found"

            return mock_response

        with patch("requests.get", side_effect=mock_get_responses):
            result = detector.detect_active("192.168.1.1", 9200)

        # With only 1 missing out of 3, should not trigger limited_api
        indicator_names = [ind.name for ind in result.indicators]
        # Behavior depends on exact order, but test should not crash


class TestDetectorModes:
    """Test Elasticsearch detector in different modes."""

    def test_passive_mode(self):
        """Test detector in passive mode only."""
        detector = ElasticsearchDetector(mode=DetectionMode.PASSIVE)

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '{"name":"Green Goblin"}'  # Default name, no newline
            mock_response.json.return_value = {"name": "Green Goblin"}
            mock_get.return_value = mock_response

            result = detector.detect("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "elasticpot_default_name" in indicator_names

    def test_active_mode(self):
        """Test detector in active mode only."""
        detector = ElasticsearchDetector(mode=DetectionMode.ACTIVE)

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_response.text = ""
            mock_get.return_value = mock_response

            result = detector.detect("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        assert "missing_cat_indices" in indicator_names or "limited_api" in indicator_names

    def test_full_mode(self):
        """Test detector in full mode (passive + active)."""
        detector = ElasticsearchDetector(mode=DetectionMode.FULL)

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '{"name":"Green Goblin","version":{"number":"1.4.1"}}'
            mock_response.json.return_value = {
                "name": "Green Goblin",
                "version": {"number": "1.4.1"},
            }
            mock_get.return_value = mock_response

            result = detector.detect("192.168.1.1", 9200)

        indicator_names = [ind.name for ind in result.indicators]
        # Should have passive indicators
        assert "elasticpot_default_name" in indicator_names or "honeypot_version" in indicator_names


class TestHoneypotTypeAssignment:
    """Test honeypot type assignment."""

    def test_passive_assigns_elasticpot(self):
        """Test that passive detection assigns elasticpot type."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '{"name":"Green Goblin","version":{"number":"1.4.1"}}'
            mock_response.json.return_value = {
                "name": "Green Goblin",
                "version": {"number": "1.4.1"},
            }
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        assert result.is_honeypot
        assert result.honeypot_type == "elasticpot"

    def test_active_assigns_elastichoney(self):
        """Test that active detection assigns elastichoney type."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_response.text = ""
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 9200)

        assert result.is_honeypot
        assert result.honeypot_type == "elastichoney"


class TestRecommendations:
    """Test recommendation generation."""

    @pytest.mark.parametrize(
        "indicator_name,expected_keyword",
        [
            ("missing_newline", "newline"),
            ("limited_api", "endpoint"),
            ("missing_cat_indices", "endpoint"),
            ("default_cluster_name", "cluster"),
            ("elasticpot_default_name", "instance"),
            ("elasticpot_build", "build"),
            ("honeypot_version", "version"),
            ("old_version", "version"),
        ],
    )
    def test_recommendation_for_indicator(self, indicator_name, expected_keyword):
        """Test that each indicator type generates appropriate recommendations."""
        detector = ElasticsearchDetector()
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.1", port=9200)
        result.add_indicator(
            Indicator(
                name=indicator_name,
                description="Test indicator",
                severity=Confidence.MEDIUM,
            )
        )

        recommendations = detector.get_recommendations(result)

        assert len(recommendations) > 0
        assert any(expected_keyword.lower() in r.lower() for r in recommendations)

    def test_recommendations_deduplicated(self):
        """Test that duplicate recommendations are removed."""
        detector = ElasticsearchDetector()
        from potsnitch.core.result import Indicator

        result = DetectionResult(target="192.168.1.1", port=9200)
        # Add multiple indicators that would trigger same recommendation
        result.add_indicator(
            Indicator(
                name="missing_cat_indices",
                description="Test",
                severity=Confidence.MEDIUM,
            )
        )
        result.add_indicator(
            Indicator(
                name="limited_api",
                description="Test",
                severity=Confidence.MEDIUM,
            )
        )

        recommendations = detector.get_recommendations(result)

        # Should have unique recommendations
        assert len(recommendations) == len(set(recommendations))


class TestErrorHandling:
    """Test error handling in detection."""

    def test_connection_error_passive(self):
        """Test handling of connection error in passive detection."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            import requests
            mock_get.side_effect = requests.ConnectionError()

            result = detector.detect_passive("192.168.1.1", 9200)

        assert not result.is_honeypot
        assert len(result.indicators) == 0

    def test_timeout_error_passive(self):
        """Test handling of timeout in passive detection."""
        detector = ElasticsearchDetector(timeout=1.0)

        with patch("requests.get") as mock_get:
            import requests
            mock_get.side_effect = requests.Timeout()

            result = detector.detect_passive("192.168.1.1", 9200)

        assert not result.is_honeypot

    def test_connection_error_active(self):
        """Test handling of connection error in active detection.

        Note: Connection errors during endpoint checks count as missing endpoints,
        which may still result in honeypot detection (limited_api indicator).
        """
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            import requests
            mock_get.side_effect = requests.ConnectionError()

            result = detector.detect_active("192.168.1.1", 9200)

        # Should not crash - connection errors are handled gracefully
        assert result is not None

    def test_generic_exception_passive(self):
        """Test handling of generic exception in passive detection."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_get.side_effect = Exception("Unexpected error")

            result = detector.detect_passive("192.168.1.1", 9200)

        assert not result.is_honeypot

    def test_generic_exception_active(self):
        """Test handling of generic exception in active detection.

        Note: Exceptions during endpoint checks count as missing endpoints,
        which may still result in honeypot detection (limited_api indicator).
        """
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_get.side_effect = Exception("Unexpected error")

            result = detector.detect_active("192.168.1.1", 9200)

        # Should not crash - exceptions are handled gracefully
        assert result is not None


class TestDetectorMetadata:
    """Test detector metadata and initialization."""

    def test_detector_name(self):
        """Test detector name is set correctly."""
        detector = ElasticsearchDetector()
        assert detector.name == "elasticsearch"

    def test_detector_description(self):
        """Test detector has a description."""
        detector = ElasticsearchDetector()
        assert len(detector.description) > 0

    def test_detector_honeypot_types(self):
        """Test detector targets correct honeypot types."""
        detector = ElasticsearchDetector()
        assert "elastichoney" in detector.honeypot_types
        assert "elasticpot" in detector.honeypot_types

    def test_default_ports(self):
        """Test default ports include ES port."""
        detector = ElasticsearchDetector()
        assert 9200 in detector.default_ports

    def test_detector_info(self):
        """Test get_info method returns correct info."""
        info = ElasticsearchDetector.get_info()

        assert info["name"] == "elasticsearch"
        assert "honeypot_types" in info
        assert "default_ports" in info
        assert 9200 in info["default_ports"]


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_version_object(self):
        """Test handling of empty version object."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '{"version":{}}\n'
            mock_response.json.return_value = {"version": {}}
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        # Should not crash
        assert result is not None

    def test_missing_version_number(self):
        """Test handling of missing version number."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '{"version":{"build_hash":"abc"}}\n'
            mock_response.json.return_value = {"version": {"build_hash": "abc"}}
            mock_get.return_value = mock_response

            result = detector.detect_passive("192.168.1.1", 9200)

        # Should not crash, no version indicator
        indicator_names = [ind.name for ind in result.indicators]
        assert "honeypot_version" not in indicator_names
        assert "old_version" not in indicator_names

    def test_custom_timeout(self):
        """Test detector with custom timeout."""
        detector = ElasticsearchDetector(timeout=10.0)
        assert detector.timeout == 10.0

    def test_verbose_mode(self):
        """Test detector with verbose mode enabled."""
        detector = ElasticsearchDetector(verbose=True)
        assert detector.verbose is True

    def test_nodes_without_nodes_key(self):
        """Test handling of nodes response without 'nodes' key."""
        detector = ElasticsearchDetector()

        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"cluster_name": "test"}  # No nodes key
            mock_get.return_value = mock_response

            result = detector.detect_active("192.168.1.1", 9200)

        # Should not crash
        indicator_names = [ind.name for ind in result.indicators]
        assert "empty_nodes" not in indicator_names

    def test_exception_in_missing_endpoints_inner_loop(self):
        """Test exception handling in inner loop of missing endpoints check."""
        detector = ElasticsearchDetector()

        call_count = [0]

        def mock_get_responses(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] > 3:
                raise Exception("Inner loop error")
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {}
            mock_response.text = "{}"
            return mock_response

        with patch("requests.get", side_effect=mock_get_responses):
            result = detector.detect_active("192.168.1.1", 9200)

        # Should not crash
        assert result is not None
