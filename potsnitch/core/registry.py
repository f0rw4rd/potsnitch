"""Detector registry with auto-discovery."""

import importlib
import pkgutil
from pathlib import Path
from typing import Optional

from .base import BaseDetector, get_all_detectors, get_detector


class DetectorRegistry:
    """Registry for managing honeypot detectors."""

    _loaded = False

    @classmethod
    def load_detectors(cls) -> None:
        """Auto-discover and load all detector modules."""
        if cls._loaded:
            return

        # Import the detectors package to trigger registration
        try:
            import potsnitch.detectors

            # Get the detectors package path
            detectors_path = Path(potsnitch.detectors.__file__).parent

            # Import all modules in the detectors package
            for _, module_name, _ in pkgutil.iter_modules([str(detectors_path)]):
                if not module_name.startswith("_"):
                    importlib.import_module(f"potsnitch.detectors.{module_name}")

            cls._loaded = True
        except ImportError:
            pass

    @classmethod
    def get_detector(cls, name: str) -> Optional[type[BaseDetector]]:
        """Get a detector by name."""
        cls.load_detectors()
        return get_detector(name)

    @classmethod
    def get_all_detectors(cls) -> dict[str, type[BaseDetector]]:
        """Get all registered detectors."""
        cls.load_detectors()
        return get_all_detectors()

    @classmethod
    def get_detectors_for_port(cls, port: int) -> list[type[BaseDetector]]:
        """Get all detectors that handle a specific port."""
        cls.load_detectors()
        return [d for d in get_all_detectors().values() if port in d.default_ports]

    @classmethod
    def get_detectors_for_honeypot(cls, honeypot_type: str) -> list[type[BaseDetector]]:
        """Get all detectors that can identify a specific honeypot type."""
        cls.load_detectors()
        return [
            d for d in get_all_detectors().values() if honeypot_type.lower() in [h.lower() for h in d.honeypot_types]
        ]

    @classmethod
    def list_detectors(cls) -> list[dict]:
        """List all available detectors with their info."""
        cls.load_detectors()
        return [d.get_info() for d in get_all_detectors().values()]
