"""Honeypot detectors package.

All detector modules in this package are auto-discovered and registered.
"""

# Import all detectors to trigger registration
from . import ssh
from . import dionaea
from . import conpot
from . import rdp
from . import elasticsearch
from . import telnet
from . import http
from . import anomaly
from . import tpot
from . import database
from . import tarpit
from . import framework
from . import cve

__all__ = [
    "ssh",
    "dionaea",
    "conpot",
    "rdp",
    "elasticsearch",
    "telnet",
    "http",
    "anomaly",
    "tpot",
    "database",
    "tarpit",
    "framework",
    "cve",
]
