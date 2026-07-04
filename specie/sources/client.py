"""HTTP client with on-disk cache and offline mode.

Live fetches are cached (content-addressed by URL). In offline mode the client
serves only from cache — so once feeds are refreshed, the whole platform runs
air-gapped with zero network.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request

USER_AGENT = "specie/0.2 (+https://cognis.digital)"


class HttpClient:
    def __init__(self, cache_dir=None, offline: bool = False, timeout: int = 30):
        self.cache_dir = cache_dir
        self.offline = offline
        self.timeout = timeout
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)

    def _cache_path(self, url: str):
        if not self.cache_dir:
            return None
        h = hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]
        return os.path.join(self.cache_dir, h + ".cache")

    def get(self, url: str) -> bytes:
        cp = self._cache_path(url)
        if self.offline:
            if cp and os.path.exists(cp):
                with open(cp, "rb") as f:
                    return f.read()
            raise RuntimeError(f"offline: no cached copy for {url}")
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = r.read()
        if cp:
            with open(cp, "wb") as f:
                f.write(data)
        return data

    def post(self, url: str, payload: dict) -> bytes:
        """JSON POST (for JSON-RPC endpoints), with the same cache/offline model."""
        cache_key = url + "|" + json.dumps(payload, sort_keys=True)
        cp = self._cache_path(cache_key)
        if self.offline:
            if cp and os.path.exists(cp):
                with open(cp, "rb") as f:
                    return f.read()
            raise RuntimeError(f"offline: no cached copy for POST {url}")
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"User-Agent": USER_AGENT,
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = r.read()
        if cp:
            with open(cp, "wb") as f:
                f.write(data)
        return data
