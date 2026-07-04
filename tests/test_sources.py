import pytest

from specie import chain
from specie.sources import feeds, parsers, registry
from specie.sources.catalog import CATALOG
from specie.sources.client import HttpClient

# ---------------- fixtures (inline; no network) ----------------
OFAC_XML = """<?xml version="1.0"?>
<sdnList xmlns="http://tempuri.org/sdnList.xsd">
 <sdnEntry><uid>1</uid><lastName>SYNTH ACTOR</lastName>
  <idList>
   <id><uid>11</uid><idType>Digital Currency Address - XBT</idType><idNumber>1TestBtcAddrABC</idNumber></id>
   <id><uid>12</uid><idType>Digital Currency Address - ETH</idType><idNumber>0xabc123</idNumber></id>
   <id><uid>13</uid><idType>Passport</idType><idNumber>X123</idNumber></id>
  </idList>
 </sdnEntry>
</sdnList>"""

TOR_EXIT = "ExitNode AAAA\nPublished 2026-01-01\nExitAddress 203.0.113.50 2026-01-01 00:00:00\nExitAddress 198.51.100.7 2026-01-02 00:00:00\n"
FEODO_CSV = '# comment\n"first_seen","dst_ip","dst_port"\n"2026-01-01","203.0.113.9","443"\n"2026-01-02","198.51.100.3","8080"\n'
SSLBL_CSV = '# ssl\n"Listingdate","SHA1","Reason"\n"2026-01-01","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","C2"\n'
RANSOM_JSON = '{"result":[{"address":"1RansomBtc","blockchain":"bitcoin","family":"Conti"},{"address":"0xdead","blockchain":"ethereum","family":"X"}]}'
KEV_JSON = '{"vulnerabilities":[{"cveID":"CVE-2026-0001","product":"X"},{"cveID":"CVE-2026-0002"}]}'
ESPLORA = '[{"txid":"abc","status":{"block_time":1700000000},"vin":[{"prevout":{"scriptpubkey_address":"A1","value":200000000}}],"vout":[{"scriptpubkey_address":"B1","value":150000000},{"scriptpubkey_address":"A2","value":49000000}]}]'
IPLIST = "# header\n203.0.113.1\n198.51.100.2/32\nnotanip\n"


BLOCKSCOUT = '{"status":"1","result":[{"hash":"0xaa","from":"0xfrom","to":"0xto","value":"1500000000000000000","timeStamp":"1700000000"}]}'
EVM_BLOCK = '{"jsonrpc":"2.0","id":1,"result":{"timestamp":"0x64b5f000","transactions":[{"hash":"0xbb","from":"0xa","to":"0xb","value":"0xde0b6b3a7640000"}]}}'
SOLANA_SIGS = '{"jsonrpc":"2.0","result":[{"signature":"sig1","slot":100,"blockTime":1700000000,"err":null},{"signature":"sig2","slot":101,"blockTime":1700000100,"err":null}]}'


class FakeClient:
    def __init__(self, mapping):
        self.mapping = mapping

    def get(self, url):
        for k, v in self.mapping.items():
            if k in url:
                return v.encode() if isinstance(v, str) else v
        raise RuntimeError("no fixture for " + url)

    def post(self, url, payload):
        method = payload.get("method", "")
        for k, v in self.mapping.items():
            if k in url or k in method:
                return v.encode() if isinstance(v, str) else v
        raise RuntimeError("no fixture for POST " + url)


# ---------------- catalog integrity ----------------
def test_catalog_size_and_uniqueness():
    assert len(CATALOG) >= 40
    names = [s["name"] for s in CATALOG]
    assert len(names) == len(set(names))


def test_catalog_required_fields():
    cats = {"sanctions", "threat-intel", "tor-infra", "blockchain-explorer",
            "chain-registry", "vuln-intel"}
    for s in CATALOG:
        assert s["name"] and s["url"].startswith("http")
        assert s["category"] in cats
        assert isinstance(s["chains"], list)
        assert isinstance(s["keyless"], bool)


def test_stats_coverage():
    st = registry.stats()
    assert st["total"] >= 40
    assert st["keyless"] >= 30
    assert st["integrated"] >= 10
    assert st["chain_count"] >= 10


# ---------------- parsers ----------------
def test_ofac_parser():
    inds = parsers.ofac_sdn_xml(OFAC_XML)
    vals = {i.value for i in inds}
    assert vals == {"1TestBtcAddrABC", "0xabc123"}
    assert all("sanctions" in i.tags for i in inds)
    assert {i.chain for i in inds} == {"bitcoin", "ethereum"}


def test_tor_and_iplist_parsers():
    assert {i.value for i in parsers.tor_exit_addresses(TOR_EXIT)} == {"203.0.113.50", "198.51.100.7"}
    assert {i.value for i in parsers.raw_iplist(IPLIST)} == {"203.0.113.1", "198.51.100.2"}


def test_feodo_sslbl_ransom_kev():
    assert {i.value for i in parsers.feodo_csv(FEODO_CSV)} == {"203.0.113.9", "198.51.100.3"}
    certs = parsers.sslbl_csv(SSLBL_CSV)
    assert certs and certs[0].kind == "cert-sha1"
    assert {i.value for i in parsers.ransomwhere_json(RANSOM_JSON)} == {"1RansomBtc", "0xdead"}
    assert {i.value for i in parsers.cisa_kev_json(KEV_JSON)} == {"CVE-2026-0001", "CVE-2026-0002"}


def test_esplora_to_lattice_txs_and_clustering():
    txs = parsers.esplora_txs(ESPLORA, address="A1", chain="bitcoin")
    assert txs[0]["inputs"][0] == {"address": "A1", "value": 2.0}
    assert txs[0]["outputs"][0] == {"address": "B1", "value": 1.5}
    clusters, _ = chain.common_input_clustering(txs)
    assert clusters  # integration: live-shaped txs feed chain analytics


# ---------------- registry fetch + client offline ----------------
def test_registry_fetch_ofac():
    inds = registry.fetch("ofac_sdn", FakeClient({"sdn.xml": OFAC_XML}))
    assert any(i.value == "1TestBtcAddrABC" for i in inds)


def test_registry_fetch_esplora_address():
    txs = registry.fetch("btc_esplora", FakeClient({"blockstream.info": ESPLORA}), address="A1")
    assert txs[0]["txid"] == "abc"


def test_evm_parsers_and_dispatch():
    # blockscout account txlist (GET)
    txs = registry.fetch_onchain("eth_blockscout", FakeClient({"blockscout.com": BLOCKSCOUT}), address="0xfrom")
    assert txs[0] == {"txid": "0xaa", "asset": "ethereum", "timestamp": 1700000000,
                      "inputs": [{"address": "0xfrom", "value": 1.5}],
                      "outputs": [{"address": "0xto", "value": 1.5}]}
    # EVM JSON-RPC block (POST) -> 1 ETH value decoded from hex
    btxs = registry.fetch_onchain("eth_llamarpc", FakeClient({"eth_getBlockByNumber": EVM_BLOCK}))
    assert btxs[0]["txid"] == "0xbb"
    assert btxs[0]["outputs"][0]["value"] == 1.0


def test_solana_signatures_dispatch():
    sigs = registry.fetch_onchain("solana_rpc", FakeClient({"getSignaturesForAddress": SOLANA_SIGS}),
                                  address="SoLaddr")
    assert [s["signature"] for s in sigs] == ["sig1", "sig2"]


TRON = '{"data":[{"txID":"t1","block_timestamp":123,"raw_data":{"contract":[{"parameter":{"value":{"owner_address":"41own","to_address":"41to","amount":5000000}}}]}}]}'
BLOCKCHAIN_INFO = '{"txs":[{"hash":"bi1","time":100,"inputs":[{"prev_out":{"addr":"A","value":200000000}}],"out":[{"addr":"B","value":150000000}]}]}'
XRPL = '{"result":{"transactions":[{"tx":{"hash":"x1","TransactionType":"Payment","Account":"rA","Destination":"rB","Amount":"5000000","date":100}}]}}'


def test_tron_and_blockchain_info_dispatch():
    tx = registry.fetch_onchain("tron_trongrid", FakeClient({"trongrid.io": TRON}), address="41own")
    assert tx[0] == {"txid": "t1", "asset": "tron", "timestamp": 123,
                     "inputs": [{"address": "41own", "value": 5.0}],
                     "outputs": [{"address": "41to", "value": 5.0}]}
    bi = registry.fetch_onchain("btc_blockchain_info", FakeClient({"blockchain.info": BLOCKCHAIN_INFO}), address="A")
    assert bi[0]["inputs"][0] == {"address": "A", "value": 2.0}
    assert bi[0]["outputs"][0] == {"address": "B", "value": 1.5}


def test_xrpl_dispatch():
    tx = registry.fetch_onchain("xrpl_rpc", FakeClient({"account_tx": XRPL}), address="rA")
    assert tx[0]["inputs"][0] == {"address": "rA", "value": 5.0}
    assert tx[0]["outputs"][0] == {"address": "rB", "value": 5.0}


SOL_TX = ('{"jsonrpc":"2.0","result":{"blockTime":1700000000,'
          '"transaction":{"signatures":["sig1"],"message":{"accountKeys":["Sender","Receiver"]}},'
          '"meta":{"preBalances":[5000000000,1000000000],"postBalances":[3000000000,3000000000]}}}')


class SolClient:
    def post(self, url, payload):
        if payload.get("method") == "getSignaturesForAddress":
            return SOLANA_SIGS.encode()
        return SOL_TX.encode()


def test_openphish_urls_parser():
    inds = parsers.raw_urls("http://evil.example/a\nnot-a-url\nhttps://evil.example/b")
    assert {i.value for i in inds} == {"http://evil.example/a", "https://evil.example/b"}
    assert all(i.kind == "url" for i in inds)


def test_solana_full_tx_from_balance_deltas():
    txs = registry.fetch_solana_txs(SolClient(), "Sender")
    assert len(txs) == 2  # two signatures
    tx = txs[0]
    assert tx["inputs"][0] == {"address": "Sender", "value": 2.0}
    assert tx["outputs"][0] == {"address": "Receiver", "value": 2.0}


def test_client_offline(tmp_path):
    url = "https://example.test/resource"
    c = HttpClient(cache_dir=str(tmp_path), offline=False)
    with open(c._cache_path(url), "wb") as f:
        f.write(b"cached-bytes")
    off = HttpClient(cache_dir=str(tmp_path), offline=True)
    assert off.get(url) == b"cached-bytes"
    with pytest.raises(RuntimeError):
        off.get("https://example.test/missing")


# ---------------- feeds fusion ----------------
def test_build_intel_fuses_feeds():
    client = FakeClient({"sdn.xml": OFAC_XML, "exit-addresses": TOR_EXIT,
                         "ipblocklist.csv": FEODO_CSV, "ransomwhe": RANSOM_JSON})
    intel = feeds.build_intel(client, sources=["ofac_sdn", "tor_exit_addresses",
                                               "feodo_ipblocklist", "ransomwhere"])
    assert "1testbtcaddrabc" in intel["sanctioned_addresses"]
    assert "1ransombtc" in intel["sanctioned_addresses"]
    assert "203.0.113.50" in intel["tor_exits"]
    assert "203.0.113.9" in intel["c2_ips"]
    assert feeds.summary(intel)["indicators"] >= 6
