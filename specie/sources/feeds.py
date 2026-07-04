"""Aggregate multiple feeds into a single intel bundle that plugs into Lattice's
sanctions screening and infrastructure attribution."""

from __future__ import annotations

from .normalize import dedupe
from .registry import fetch

DEFAULT_INTEL = [
    "ofac_sdn", "ransomwhere", "tor_exit_addresses", "tor_bulk_exitlist",
    "feodo_ipblocklist", "sslbl_certs", "sslbl_ips", "urlhaus", "cisa_kev",
]


def build_intel(client, sources=None, on_error="skip") -> dict:
    names = sources or DEFAULT_INTEL
    indicators = []
    errors = {}
    for name in names:
        try:
            res = fetch(name, client)
            if isinstance(res, list):
                indicators.extend(res)
        except Exception as e:  # network / offline-miss / parse
            errors[name] = str(e)
            if on_error == "raise":
                raise
    indicators = dedupe(indicators)
    intel = {"sanctioned_addresses": set(), "tor_exits": set(), "c2_ips": set(),
             "malicious_certs": set(), "malicious_urls": set(), "cves": set(),
             "indicators": indicators, "errors": errors}
    for i in indicators:
        if i.kind == "crypto-address" and ("sanctions" in i.tags or "ransomware" in i.tags):
            intel["sanctioned_addresses"].add(i.value.lower())
        elif i.kind == "ipv4" and "tor-exit" in i.tags:
            intel["tor_exits"].add(i.value)
        elif i.kind == "ipv4" and "c2" in i.tags:
            intel["c2_ips"].add(i.value)
        elif i.kind == "cert-sha1":
            intel["malicious_certs"].add(i.value.lower())
        elif i.kind == "url":
            intel["malicious_urls"].add(i.value)
        elif i.kind == "cve":
            intel["cves"].add(i.value)
    return intel


def summary(intel: dict) -> dict:
    return {k: len(v) for k, v in intel.items()
            if isinstance(v, (set, list)) and k != "indicators"} | {
        "indicators": len(intel["indicators"]), "sources_failed": len(intel["errors"])}
