"""Source catalog: 40+ counter-threat-finance / deanonymization sources.

Each entry:
  name       unique id
  category   sanctions | threat-intel | tor-infra | blockchain-explorer |
             chain-registry | vuln-intel
  chains     relevant chain ids ([] if not chain-specific)
  url        fetch endpoint (address-based explorers use {addr})
  keyless    True if usable without an API key
  yields     what indicator kinds it produces
  parser     parser id (see registry.PARSERS); "raw_*" = catalog + raw fetch
  integrated True if a normalized parser turns it into Indicators
  doc        human reference
"""

from __future__ import annotations

_NORMALIZED = {
    "ofac_sdn_xml", "tor_exit_addresses", "tor_bulk_exitlist", "feodo_csv",
    "sslbl_csv", "urlhaus_csv", "threatfox_csv", "raw_iplist",
    "ransomwhere_json", "cisa_kev_json", "esplora",
    "blockscout_txlist", "evm_rpc", "solana_rpc",
    "blockchain_info", "tron_account_tx", "xrpl_account_tx", "raw_urls",
}

_RAW = [
    # name, category, chains, url, keyless, yields, parser, doc
    # ---- Sanctions / threat-finance ----
    ("ofac_sdn", "sanctions", [], "https://www.treasury.gov/ofac/downloads/sdn.xml", True,
     "crypto-address", "ofac_sdn_xml", "https://ofac.treasury.gov"),
    ("ofac_consolidated", "sanctions", [], "https://www.treasury.gov/ofac/downloads/consolidated/consolidated.xml", True,
     "crypto-address", "ofac_sdn_xml", "https://ofac.treasury.gov"),
    ("opensanctions_crypto", "sanctions", [], "https://data.opensanctions.org/datasets/latest/crypto/targets.simple.csv", True,
     "crypto-address", "raw_json", "https://www.opensanctions.org/datasets/crypto/"),
    ("ransomwhere", "sanctions", ["bitcoin", "ethereum", "monero"], "https://api.ransomwhe.re/export", True,
     "crypto-address", "ransomwhere_json", "https://ransomwhe.re"),
    ("cryptoscamdb", "sanctions", ["ethereum", "bitcoin"], "https://api.cryptoscamdb.org/v1/addresses", True,
     "crypto-address", "raw_json", "https://cryptoscamdb.org"),
    ("chainabuse_public", "sanctions", ["bitcoin", "ethereum"], "https://www.chainabuse.com", False,
     "crypto-address", "raw_json", "https://www.chainabuse.com"),
    # ---- Tor / anonymizer infrastructure ----
    ("tor_exit_addresses", "tor-infra", [], "https://check.torproject.org/exit-addresses", True,
     "ipv4", "tor_exit_addresses", "https://metrics.torproject.org"),
    ("tor_bulk_exitlist", "tor-infra", [], "https://check.torproject.org/torbulkexitlist", True,
     "ipv4", "tor_bulk_exitlist", "https://metrics.torproject.org"),
    ("onionoo_details", "tor-infra", [], "https://onionoo.torproject.org/details", True,
     "ipv4", "raw_json", "https://metrics.torproject.org/onionoo.html"),
    ("dan_torlist", "tor-infra", [], "https://www.dan.me.uk/torlist/", True,
     "ipv4", "raw_iplist", "https://www.dan.me.uk/tornodes"),
    # ---- Threat intel (C2 / IOC / infra) ----
    ("feodo_ipblocklist", "threat-intel", [], "https://feodotracker.abuse.ch/downloads/ipblocklist.csv", True,
     "ipv4", "feodo_csv", "https://feodotracker.abuse.ch"),
    ("feodo_recommended", "threat-intel", [], "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", True,
     "ipv4", "raw_iplist", "https://feodotracker.abuse.ch"),
    ("sslbl_certs", "threat-intel", [], "https://sslbl.abuse.ch/blacklist/sslblacklist.csv", True,
     "cert-sha1", "sslbl_csv", "https://sslbl.abuse.ch"),
    ("sslbl_ips", "threat-intel", [], "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv", True,
     "ipv4", "sslbl_csv", "https://sslbl.abuse.ch"),
    ("urlhaus", "threat-intel", [], "https://urlhaus.abuse.ch/downloads/csv_recent/", True,
     "url", "urlhaus_csv", "https://urlhaus.abuse.ch"),
    ("threatfox", "threat-intel", [], "https://threatfox.abuse.ch/export/csv/recent/", True,
     "ioc", "threatfox_csv", "https://threatfox.abuse.ch"),
    ("firehol_level1", "threat-intel", [], "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", True,
     "ipv4", "raw_iplist", "https://iplists.firehol.org"),
    ("cins_badguys", "threat-intel", [], "https://cinsscore.com/list/ci-badguys.txt", True,
     "ipv4", "raw_iplist", "https://cinsscore.com"),
    ("blocklist_de", "threat-intel", [], "https://lists.blocklist.de/lists/all.txt", True,
     "ipv4", "raw_iplist", "https://www.blocklist.de"),
    ("emergingthreats_compromised", "threat-intel", [], "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", True,
     "ipv4", "raw_iplist", "https://rules.emergingthreats.net"),
    ("spamhaus_drop", "threat-intel", [], "https://www.spamhaus.org/drop/drop.txt", True,
     "ipv4", "raw_iplist", "https://www.spamhaus.org/drop/"),
    ("greynoise_riot", "threat-intel", [], "https://api.greynoise.io/v3/community/", False,
     "ipv4", "raw_json", "https://www.greynoise.io"),
    ("openphish", "threat-intel", [], "https://openphish.com/feed.txt", True,
     "url", "raw_urls", "https://openphish.com"),
    ("phishtank", "threat-intel", [], "http://data.phishtank.com/data/online-valid.csv", True,
     "url", "urlhaus_csv", "https://phishtank.org"),
    ("dshield_block", "threat-intel", [], "https://feeds.dshield.org/block.txt", True,
     "ipv4", "raw_iplist", "https://www.dshield.org"),
    ("talos_blacklist", "threat-intel", [], "https://talosintelligence.com/documents/ip-blacklist", True,
     "ipv4", "raw_iplist", "https://talosintelligence.com"),
    ("botvrij_ip", "threat-intel", [], "https://www.botvrij.eu/data/ioclist.ip-dst.raw", True,
     "ipv4", "raw_iplist", "https://www.botvrij.eu"),
    ("binarydefense", "threat-intel", [], "https://www.binarydefense.com/banlist.txt", True,
     "ipv4", "raw_iplist", "https://www.binarydefense.com"),
    ("greensnow", "threat-intel", [], "https://blocklist.greensnow.co/greensnow.txt", True,
     "ipv4", "raw_iplist", "https://greensnow.co"),
    ("un_sc_sanctions", "sanctions", [], "https://scsanctions.un.org/resources/xml/en/consolidated.xml", True,
     "name", "raw_json", "https://www.un.org/securitycouncil/content/un-sc-consolidated-list"),
    # ---- Vulnerability intel ----
    ("cisa_kev", "vuln-intel", [], "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", True,
     "cve", "cisa_kev_json", "https://www.cisa.gov/kev"),
    ("nvd_cve", "vuln-intel", [], "https://services.nvd.nist.gov/rest/json/cves/2.0", True,
     "cve", "raw_json", "https://nvd.nist.gov"),
    ("epss", "vuln-intel", [], "https://epss.cyentia.com/epss_scores-current.csv.gz", True,
     "cve", "raw_json", "https://www.first.org/epss/"),
    ("mitre_attack", "vuln-intel", [], "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json", True,
     "ttp", "raw_json", "https://attack.mitre.org"),
    # ---- Blockchain explorers / RPC (address & tx tracing) ----
    ("btc_esplora", "blockchain-explorer", ["bitcoin"], "https://blockstream.info/api/address/{addr}/txs", True,
     "transaction", "esplora", "https://github.com/Blockstream/esplora"),
    ("btc_mempool", "blockchain-explorer", ["bitcoin"], "https://mempool.space/api/address/{addr}/txs", True,
     "transaction", "esplora", "https://mempool.space/docs/api"),
    ("btc_blockchain_info", "blockchain-explorer", ["bitcoin"], "https://blockchain.info/rawaddr/{addr}", True,
     "transaction", "blockchain_info", "https://www.blockchain.com/explorer/api"),
    ("blockchair_btc", "blockchain-explorer", ["bitcoin"], "https://api.blockchair.com/bitcoin/dashboards/address/{addr}", True,
     "transaction", "raw_json", "https://blockchair.com/api/docs"),
    ("ltc_esplora", "blockchain-explorer", ["litecoin"], "https://litecoinspace.org/api/address/{addr}/txs", True,
     "transaction", "esplora", "https://litecoinspace.org"),
    ("bch_blockchair", "blockchain-explorer", ["bitcoin-cash"], "https://api.blockchair.com/bitcoin-cash/dashboards/address/{addr}", True,
     "transaction", "raw_json", "https://blockchair.com/api/docs"),
    ("doge_blockchair", "blockchain-explorer", ["dogecoin"], "https://api.blockchair.com/dogecoin/dashboards/address/{addr}", True,
     "transaction", "raw_json", "https://blockchair.com/api/docs"),
    ("eth_cloudflare_rpc", "blockchain-explorer", ["ethereum"], "https://cloudflare-eth.com", True,
     "transaction", "evm_rpc", "https://developers.cloudflare.com/web3/"),
    ("eth_llamarpc", "blockchain-explorer", ["ethereum"], "https://eth.llamarpc.com", True,
     "transaction", "evm_rpc", "https://llamanodes.com"),
    ("eth_blockscout", "blockchain-explorer", ["ethereum"], "https://eth.blockscout.com/api?module=account&action=txlist&address={addr}", True,
     "transaction", "blockscout_txlist", "https://docs.blockscout.com"),
    ("base_blockscout", "blockchain-explorer", ["base"], "https://base.blockscout.com/api?module=account&action=txlist&address={addr}", True,
     "transaction", "blockscout_txlist", "https://docs.blockscout.com"),
    ("optimism_blockscout", "blockchain-explorer", ["optimism"], "https://optimism.blockscout.com/api?module=account&action=txlist&address={addr}", True,
     "transaction", "blockscout_txlist", "https://docs.blockscout.com"),
    ("polygon_blockscout", "blockchain-explorer", ["polygon"], "https://polygon.blockscout.com/api?module=account&action=txlist&address={addr}", True,
     "transaction", "blockscout_txlist", "https://docs.blockscout.com"),
    ("arbitrum_blockscout", "blockchain-explorer", ["arbitrum"], "https://arbitrum.blockscout.com/api?module=account&action=txlist&address={addr}", True,
     "transaction", "blockscout_txlist", "https://docs.blockscout.com"),
    ("gnosis_blockscout", "blockchain-explorer", ["gnosis"], "https://gnosis.blockscout.com/api?module=account&action=txlist&address={addr}", True,
     "transaction", "blockscout_txlist", "https://docs.blockscout.com"),
    ("base_rpc", "blockchain-explorer", ["base"], "https://mainnet.base.org", True,
     "transaction", "evm_rpc", "https://docs.base.org"),
    ("arbitrum_rpc", "blockchain-explorer", ["arbitrum"], "https://arb1.arbitrum.io/rpc", True,
     "transaction", "evm_rpc", "https://docs.arbitrum.io"),
    ("optimism_rpc", "blockchain-explorer", ["optimism"], "https://mainnet.optimism.io", True,
     "transaction", "evm_rpc", "https://docs.optimism.io"),
    ("polygon_rpc", "blockchain-explorer", ["polygon"], "https://polygon-rpc.com", True,
     "transaction", "evm_rpc", "https://docs.polygon.technology"),
    ("bsc_rpc", "blockchain-explorer", ["bsc"], "https://bsc-dataseed.binance.org", True,
     "transaction", "evm_rpc", "https://docs.bnbchain.org"),
    ("avalanche_rpc", "blockchain-explorer", ["avalanche"], "https://api.avax.network/ext/bc/C/rpc", True,
     "transaction", "evm_rpc", "https://docs.avax.network"),
    ("solana_rpc", "blockchain-explorer", ["solana"], "https://api.mainnet-beta.solana.com", True,
     "transaction", "solana_rpc", "https://docs.solana.com/api"),
    ("tron_trongrid", "blockchain-explorer", ["tron"], "https://api.trongrid.io/v1/accounts/{addr}/transactions", True,
     "transaction", "tron_account_tx", "https://developers.tron.network"),
    ("xrpl_rpc", "blockchain-explorer", ["xrpl"], "https://s1.ripple.com:51234/", True,
     "transaction", "xrpl_account_tx", "https://xrpl.org/account_tx.html"),
    ("algorand_algonode", "blockchain-explorer", ["algorand"], "https://mainnet-idx.algonode.cloud/v2/accounts/{addr}/transactions", True,
     "transaction", "raw_json", "https://algonode.io"),
    # ---- Chain registries ----
    ("chainid_network", "chain-registry", [], "https://chainid.network/chains.json", True,
     "chain-metadata", "raw_json", "https://chainid.network"),
    ("defillama_chains", "chain-registry", [], "https://api.llama.fi/v2/chains", True,
     "chain-metadata", "raw_json", "https://defillama.com/docs/api"),
]

CATALOG = [
    {"name": n, "category": c, "chains": ch, "url": u, "keyless": k,
     "yields": y, "parser": p, "integrated": p in _NORMALIZED, "doc": d}
    for (n, c, ch, u, k, y, p, d) in _RAW
]
