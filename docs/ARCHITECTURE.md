# Architecture

Specie is a small, composable, dependency-free pipeline. Each stage is a
pure module you can use independently or wire together through `fusion`.

```
 transactions ─┐
               ├─► chain      ─► wallet clusters ─┐
 observations ─┼─► netattr    ─► infra clusters  ─┼─► fusion ─► threat-actor graph ─► stix / report
 sdn list     ─┼─► sanctions  ─► sanction hits   ─┤            (confidence-scored)
 linkages     ─┘                                  ┘
```

## Modules

| Module | Responsibility |
|---|---|
| `model` | `Entity`, `Edge`, `Graph`; deterministic content-addressed IDs. |
| `confidence` | Noisy-OR evidence combination; HIGH/MODERATE/LOW banding. |
| `chain` | Blockchain analytics: clustering, tracing, mixer/de-mix, peel chains. |
| `netattr` | Infrastructure attribution: enrichment, fingerprint clustering, temporal/behavioral. |
| `sanctions` | OFAC-style SDN screening (addresses + names). |
| `fusion` | Merge all sources into a graph; resolve threat-actor profiles. |
| `stix` | STIX 2.1 bundle export with deterministic UUIDv5 IDs. |
| `report` | Human-readable and JSON intelligence products. |
| `cli` | `specie` command-line entry point. |

## Design principles

1. **Zero dependencies.** Standard library only, so the platform deploys inside
   restricted or air-gapped enclaves with no supply chain to vet.
2. **Deterministic & reproducible.** Same inputs → identical graph and STIX
   bundle. Content-addressed IDs and fixed timestamps make outputs evidentiary.
3. **Confidence everywhere.** No stage emits a bare assertion; every derived link
   carries a probability and its rationale.
4. **Provenance & self-hosting.** Data never leaves the operator's environment;
   every edge records the evidence that produced it.
5. **Composable.** Each module is independently usable and testable.

## Extending

- New chains: feed the uniform transaction schema (inputs/outputs) from any
  transparent ledger adapter.
- New feeds (abuse.ch, CISA KEV, MITRE ATT&CK): add enrichment/screeners that
  emit entities and edges; `fusion` and `stix` pick them up automatically.
- New export formats: mirror `stix.py` (e.g. MISP, GraphML).
