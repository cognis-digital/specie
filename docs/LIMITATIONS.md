# Limitations & Responsible Use

Specie is an **investigative-lead generator**, not an oracle. Read this
before acting on any output.

## What it does NOT do

- **It does not break Tor, VPN, or proxy cryptography.** It correlates
  observations you have lawfully collected (server logs, TLS fingerprints, timing).
  It cannot decrypt traffic or unmask a Tor circuit cryptographically.
- **It does not deterministically de-anonymize privacy coins.** Monero and similar
  protocols are out of scope for tracing here. For transparent-ledger mixers we
  emit *candidate* links with explicitly reduced confidence, never certainties.
- **It does not adjudicate guilt.** Every output is a confidence-scored lead for
  authorized analysts to corroborate, not evidence of wrongdoing on its own.

## Known heuristic failure modes

- **Common-input clustering** can be defeated by CoinJoin/PayJoin and can
  over-merge if a service co-spends customer funds. Treat clusters as hypotheses.
- **De-mix candidates** are inherently ambiguous in equal-value mixing; confidence
  is deliberately low when many outputs match an input.
- **Infrastructure clustering** by shared domain can over-merge on shared CDNs or
  hosting; TLS-certificate matches are stronger. Review before fusing.
- **Behavioral/temporal correlation** can produce coincidental co-occurrence.

## Data responsibilities

- `data/ofac_sample.json` is **synthetic test data**, not the real OFAC SDN list.
  Ingest the authoritative list before any operational screening.
- Sample IPs use RFC 5737 documentation ranges and sample addresses are fictitious.

## Legal & oversight

This is dual-use security software. Use it only against systems, data, and
identities you own or are explicitly authorized in writing to investigate, and in
compliance with all applicable laws, intelligence-oversight rules, and the
minimization/sharing procedures governing your organization. You are solely
responsible for your use (see LICENSE §9 and NOTICE).
