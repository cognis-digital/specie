"""Live intelligence source integration for Specie.

A catalog of 40+ counter-threat-finance / deanonymization sources spanning
sanctions lists, threat-intel feeds, Tor/anonymizer infrastructure, and
multi-chain blockchain explorers. Keyless sources fetch live over HTTP; every
fetch is cached to disk so the platform also runs fully offline / air-gapped.

Normalized parsers turn raw feeds into a common Indicator schema that plugs
straight into Lattice's sanctions screening, infrastructure attribution, and
fusion. See docs/SOURCES.md.
"""

from __future__ import annotations

from .catalog import CATALOG
from .client import HttpClient
from .normalize import Indicator, dedupe
from .registry import fetch, get_source, list_sources, stats

__all__ = ["CATALOG", "HttpClient", "Indicator", "dedupe",
           "fetch", "get_source", "list_sources", "stats"]
