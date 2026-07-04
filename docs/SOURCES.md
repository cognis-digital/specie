# Intelligence Sources

Specie integrates **48 counter-threat-finance / deanonymization sources**
(46 keyless) across **16 blockchains**. Keyless sources fetch live over HTTP and
cache to disk, so the platform also runs fully offline / air-gapped.

## Categories

| Category | Count | Examples |
|---|---|---|
| blockchain-explorer | 20 | Blockstream Esplora (BTC), mempool.space, blockchair, Ethereum/Base/Arbitrum/Optimism/Polygon/BSC/Avalanche RPC, Solana, Tron, XRPL, Algorand, Litecoin, Dogecoin, Bitcoin-Cash |
| threat-intel | 12 | abuse.ch Feodo/URLhaus/ThreatFox/SSLBL, FireHOL, CINS, blocklist.de, Emerging Threats, Spamhaus DROP |
| sanctions | 6 | OFAC SDN + Consolidated, OpenSanctions (crypto), Ransomwhere, CryptoScamDB |
| tor-infra | 4 | Tor exit-addresses, Tor bulk exit list, Onionoo, dan.me.uk |
| vuln-intel | 4 | CISA KEV, NVD, EPSS, MITRE ATT&CK |
| chain-registry | 2 | chainid.network, DefiLlama |

**Chains:** bitcoin, ethereum, litecoin, bitcoin-cash, dogecoin, monero (feeds),
base, arbitrum, optimism, polygon, bsc, avalanche, solana, tron, xrpl, algorand.

## Normalized vs. raw

18 sources have **normalized parsers** that emit the common `Indicator` schema
(`crypto-address`, `ipv4`, `url`, `cert-sha1`, `cve`) or Lattice transactions
(esplora chains). The remainder are catalogued with correct endpoints and
fetch raw JSON (full normalization is incremental, tracked per source via the
`integrated` flag).

## Usage

```bash
specie sources-list --category threat-intel      # browse
specie sources-list --chain bitcoin
specie sources-stats                              # coverage json

specie sources-fetch feodo_ipblocklist           # live C2 IPs
specie sources-fetch ofac_sdn                     # live sanctioned wallets
specie sources-intel --cache .cache              # fuse feeds -> counts
specie sources-intel --offline --cache .cache    # air-gapped replay

# live on-chain trace (esplora chains: bitcoin, litecoin)
specie sources-address --chain bitcoin --address <ADDR>
```

```python
from specie.sources import HttpClient, feeds, registry
client = HttpClient(cache_dir=".cache")            # add offline=True to replay
intel = feeds.build_intel(client)                  # sanctioned addrs, tor exits, C2 IPs, certs...
txs = registry.fetch("btc_esplora", client, address="<ADDR>")   # -> Lattice transactions
```

## Offline / air-gap

Every fetch is cached (content-addressed by URL). Refresh feeds once on a
connected host, copy the cache into the enclave, and run with `offline=True`:
the entire pipeline — feeds, screening, tracing — works with zero network.

## Keys & compliance

Keyless sources need no credentials. A few (Etherscan-class explorers,
GreyNoise, Chainabuse) require API keys and are marked `keyless=false`. Respect
each source's terms of use and rate limits. See NOTICE for acceptable use.
