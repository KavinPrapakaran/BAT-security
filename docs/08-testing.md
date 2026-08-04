# COGNESIS — Testing

## 1. Strategy

- **Unit tests** cover each engine in isolation with deterministic fixtures.
- **Spring context smoke test** (`CognesisApplicationTests`) boots the entire
  wiring against in-memory H2 and exercises the pipeline end-to-end.
- **Mockito** isolates the ACDE from its engine dependencies.
- **No real network/IO**: the live-source tests use `MockRestServiceServer`
  against a fake base URL; the build is green with `mvn test` (no services
  required, PostgreSQL integration excluded unless Docker is available).
- **CI**: `.github/workflows/ci.yml` runs the full suite on Java 21 for every
  push/PR (see §5).

## 2. Coverage map

| Test class | Engine under test | Assertions |
|---|---|---|
| `SynapseEngineTest` | SYNAPSE fusion, bands, confidence | 6 tests: neutral slices are inert; high evidence → containment band; low → ALLOW; seven-band ordering; low-confidence escalation; unit intervals |
| `FidesTrustEngineTest` | Fides trust dynamics | 4 tests: new entity neutral 0.5; positive drift; asymmetric negative drop; confidence saturation with observations |
| `TrustEvolutionTest` | Trust over time | 2 tests: trust erodes monotonically through certificate/DNS changes, suspicious behaviour and confirmed compromise; negative events outweigh positives |
| `MnemonicMemoryEngineTest` | Memory graph + activation | 5 tests: empty recall → salience 0.5; memorize→recall surfaces entity; 2-hop propagation; baseline deviation; severity→base weight |
| `MnemonicDecisionMemoryTest` | Decision/outcome memory | 3 tests: `recordDecision` stores a DECISION node with the reasoning chain; `recordOutcome` closes the loop via OUTCOME_OF; relationship type inference |
| `SituationalContextEngineTest` | CONTEXT environment | 4 tests: known labels map to baseline risk; unknown is neutral; prod raises weight; anonymised source raises risk |
| `DnsAnalyzersTest` | 15 DNS analyzers | 8 tests: DGA flags machine label, passes readable word; homograph flags Cyrillic spoof, passes ASCII; typosquat catches near-miss; fast flux; age; DNSSEC; policy; registrar |
| `CognitiveDnsEngineTest` | CODE end-to-end via ACDE | 4 tests: well-known domain → ALLOW; typosquat riskier than brand; hard policy override → BLOCK with risk/conf 1.0; reasoning chain present |
| `AcdeEngineTest` | ACDE full pipeline | 1 test (Mockito): all engines invoked, ≥ 10 reasoning steps, decision persisted, reasoning path stored in memory |
| `CognesisApplicationTests` | Spring wiring + H2 | 3 tests: context loads; DNS decision persisted to DB; ACDE runs through pipeline |
| `DetectionRuleGeneratorTest` | Sigma + YARA export | 4 tests: well-formed Sigma (dns_query, level per band); severity mapping; well-formed YARA (domain + claims, risk score); bundle filenames |
| `ThreatFeedIngestorTest` | abuse.ch-style feed ingestion | 5 tests: host-file parsing flags IOCs; comments/blanks ignored; flags accumulate; disabled feed skips network; unreachable feed swallowed |
| `LiveDnsFactsRepositoryTest` | live DNS/RDAP/CT facts via mock HTTP | 5 tests: assembles facts from all three sources; wholesale fallback when every source is offline; partial failure still uses responding sources; feed flags survive the live merge; results cached (no second network round-trip) |
| `IocEscalationTest` | feed IOC → ACDE verdict | 2 tests: flagged domain strictly riskier + non-ALLOW; reasoning chain contains the `CODE:THREAT_INTEL` step |

**Total: 78 tests, 0 failures.**

## 3. Running

```bash
# all tests
mvn test

# single class
mvn test -Dtest=SynapseEngineTest

# full build (compile + test + package)
mvn package
```

Reports land in `target/surefire-reports/`.

## 4. Calibration tests worth highlighting

These encode the framework's key design decisions as regression guards:

1. **`synapseNeutralSlicesAreInert`** — a slice at 0.5 must not move the fused
   risk (locks the log-odds-relative-to-0.5 design).
2. **`dgaAnalyzerAcceptsReadableWord`** — `billing-portal` scores below 0.5
   (locks the pronounceability-aware DGA scorer, not naive entropy).
3. **`homographAnalyzerFlagsCyrillicSpoof`** — `amаzon.com` with a single
   Cyrillic character flags ≥ 0.55 (locks the 0.55 floor).
4. **`emptyRecallIsNeutral`** — empty memory returns salience 0.5, never
   anomaly (locks the neutral-on-empty rule).
5. **`policyOverrideBlocksBeforeFusion`** — a hard policy rule forces
   BLOCK/1.0/1.0 regardless of other evidence.
6. **`negativeEventHurtsMoreThanPositiveHelps`** — Fides asymmetric gain is a
   regression-tested invariant.
7. **`trustEvolvesDownThroughAdversarialEvents`** — a healthy 0.95 trust erodes
   monotonically and collapses below neutral once compromise is confirmed
   (locks the Fides asymmetry + the semantic event vocabulary).
8. **`recordDecisionStoresDecisionNodeLinkedToEntity`** — every decision keeps
   its reasoning path in memory, so "why did we do X" is always answerable.

## 5. CI

`.github/workflows/ci.yml` runs on every push/PR to `main`/`master`:

1. Checkout, then Java 21 (Temurin) with a Maven dependency cache.
2. `mvn test` — the full suite (PostgreSQL integration test runs via
   Testcontainers; Docker is available on the runner).
3. `mvn package -DskipTests` — verifies the runnable jar builds.
4. On failure, `target/surefire-reports/**` is uploaded as an artifact.

Local equivalent: `mvn test`. H2 covers DB integration without a server;
Docker is only needed for the PostgreSQL integration test.
