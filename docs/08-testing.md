# BAT security — Testing

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
| `DnsAnalyzersTest` | 17 DNS analyzers | 8 tests: DGA flags machine label, passes readable word; homograph flags Cyrillic spoof, passes ASCII; typosquat catches near-miss; fast flux; age; DNSSEC; policy; registrar |
| `DnsIntelligenceEngineTest` | DIE end-to-end via ACDE | 4 tests: well-known domain → ALLOW; typosquat riskier than brand; hard policy override → BLOCK with risk/conf 1.0; reasoning chain present |
| `SecurityKnowledgeGraphTest` | ACTG trust graph | 5 tests: entity/relation model; edge strengthening on repeat; high-water risk ratchet; neighborhood risk skips zero-risk neighbours; graph wiring |
| `ActgEngineTest` | ACTG slice through DIE | 3 tests: first-touch domain inherits a dirty IP's risk; reasoning chain carries the ACTG step; neutral when no relationships exist |
| `LoreLearningEngineTest` | LORE weight learning | 7 tests: malicious confirmation raises weights; false positive lowers them; benign confirmation nudges less; calibration bounds; weight caps; signal strengths optional |
| `ProfileEvaluationEngineTest` | org profiles | 5 tests: seeded defaults (hospital/bank/university); tolerance scaling; org-scoped rules; unknown org → DEFAULT; invalid tolerance rejected |
| `OrgPolicyAcdeTest` | org policy through ACDE | 2 tests: org-scoped block rule short-circuits to BLOCK; unrelated org rule not applied |
| `AcdeEngineTest` | ACDE full pipeline | 1 test (Mockito): all engines invoked, ≥ 10 reasoning steps, decision persisted, reasoning path stored in memory |
| `CognesisApplicationTests` | Spring wiring + H2 | 3 tests: context loads; DNS decision persisted to DB; ACDE runs through pipeline |
| `DetectionRuleGeneratorTest` | Sigma + YARA export | 4 tests: well-formed Sigma (dns_query, level per band); severity mapping; well-formed YARA (domain + claims, risk score); bundle filenames |
| `ThreatFeedIngestorTest` | abuse.ch-style feed ingestion | 5 tests: host-file parsing flags IOCs; comments/blanks ignored; flags accumulate; disabled feed skips network; unreachable feed swallowed |
| `LiveDnsFactsRepositoryTest` | live DNS/RDAP/CT facts via mock HTTP | 7 tests: assembles facts from all three sources; wholesale fallback when every source is offline; partial failure still uses responding sources; feed flags survive the live merge; results cached (no second network round-trip); **secondary DoH resolver failover (Google-format response)**; **unsafe domain input rejected with no outbound call** |
| `IocEscalationTest` | feed IOC → ACDE verdict | 2 tests: flagged domain strictly riskier + non-ALLOW; reasoning chain contains the `DIE:THREAT_INTEL` step |
| `JdbcIocStoreTest` | persistent IOC store (H2) | 3 tests: flag counts survive a new store instance; unknown domain → zero flags; `first_seen` stable across reflags |
| `JdbcActgStoreTest` | persistent ACTG graph (H2) | 4 tests: nodes/edges survive a new store instance; high-water risk and neighborhood risk survive reload; repeated associations stay one strengthening edge; `clear` wipes the database too |
| `IocPersistenceTest` | feed flags across repository instances | 2 tests: a feed-flagged IOC surfaces through a fresh repository sharing the store; unknown domain stays clean |
| `EmailAnalyzersTest` | 8 email analyzers | 12 tests: auth verdicts (pass/none/fail); sender-age (brand-new vs aged); spoofing; suspicious links; malicious attachments; negative sender reputation; threat-intel flag; policy hard-block; clean message floor; per-analyzer evidence types |
| `EmailIntelligenceEngineTest` | VOID end-to-end via ACDE | 5 tests: phishing msg-002 → BLOCK with intent; clean msg-001 → ALLOW; internal msg-003 → ALLOW; ambiguous msg-004 → non-ALLOW; reasoning chain + ACTG association recorded |
| `DecisionBenchmarkTest` | calibration benchmark | 3 tests: DNS catalog beats base-rate baseline (Brier < 0.20); email catalog beats baseline; both engines separate positives from negatives |
| `EmailControllerTest` | VOID REST endpoint | 2 tests: unknown message handled; known message produces a decision |
| `RateLimitFilterTest` | sliding-window rate limiter | 5 tests: requests within window pass; over-window → 429 + `Retry-After: 60`; clients limited independently; disabled filter never limits; `/actuator/health` exempt |
| `FailClosedTest` | security fail-closed posture | 3 tests: protected endpoints 403 with no configured keys; presented key still 403; `/actuator/metrics` locked too |
| `FeedHealthIndicatorTest` | feed health | 3 tests: disabled feed UP; enabled-but-never-refreshed DOWN; fresh refresh UP with IOC count |

**Total: 144 tests, 0 failures.** Line coverage and branch coverage both clear
the JaCoCo gate (line ≥ 70%, branch ≥ 55%).

## 3. Running

```bash
# all tests
mvn test

# all tests + JaCoCo coverage gate (line ≥ 70%, branch ≥ 55%)
mvn verify

# single class
mvn test -Dtest=SynapseEngineTest

# full build (compile + test + package)
mvn package
```

Reports land in `target/surefire-reports/`; the JaCoCo report in
`target/site/jacoco/index.html`.

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
9. **`dnsCatalogBeatsBaseRateBaseline` / `emailCatalogBeatsBaseline`** — the
   `DecisionBenchmark` harness asserts Brier score and 5-bin calibration error
   are strictly better than a base-rate guesser on both the DNS and email
   catalogs (both Brier < 0.20), locking calibration as a regression guard.
10. **`graphPersistsAcrossStoreInstances`** — nodes, exact edge weights and
    high-water risk survive a fresh store on the same database (locks the ACTG
    restart invariant).

## 5. CI

`.github/workflows/ci.yml` runs on every push/PR to `main`/`master`:

1. **`build` job** — checkout, Java 21 (Temurin) with a Maven dependency cache,
   then `mvn verify` (the full suite **plus the JaCoCo coverage gate**), then
   `mvn package -DskipTests`. On failure, `target/surefire-reports/**` is
   uploaded; the JaCoCo report is uploaded regardless.
2. **`smoke` job** — boots the packaged jar against a disposable PostgreSQL
   container with the **live URLhaus feed enabled**, then exercises the API
   (`/api/v1/dashboard`, `/api/v1/dns/evaluate`), checks `/actuator/health` is
   `UP` and `/actuator/health/feed` reports the ingested IOC count. Catches
   real-world feed format drift and wiring that unit tests cannot.
3. **`security-scan.yml`** (weekly + on `pom.xml` changes) — Trivy filesystem
   scan for HIGH/CRITICAL CVEs; fails the build on findings.
4. **Dependabot** keeps `pom.xml` and the GitHub Actions up to date.

Local equivalent: `mvn verify`. H2 covers DB integration without a server;
Docker is only needed for the PostgreSQL integration test (excluded locally
via `-Dtest="!PostgresIntegrationTest"`).
