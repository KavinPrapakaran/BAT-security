# COGNESIS — Testing

## 1. Strategy

- **Unit tests** cover each engine in isolation with deterministic fixtures.
- **Spring context smoke test** (`CognesisApplicationTests`) boots the entire
  wiring against in-memory H2 and exercises the pipeline end-to-end.
- **Mockito** isolates the orchestrator from its engine dependencies.
- **No network/IO**: all tests are local and fast; the build must be green
  with `mvn test` (no services required).

## 2. Coverage map

| Test class | Engine under test | Assertions |
|---|---|---|
| `SynapseEngineTest` | SYNAPSE fusion, bands, confidence | 6 tests: neutral slices are inert; high evidence → BLOCK; low → ALLOW; tolerance scaling; low-confidence escalation; monotonicity |
| `FidesTrustEngineTest` | Fides trust dynamics | 4 tests: new entity neutral 0.5; positive drift; asymmetric negative drop; confidence saturation with observations |
| `MnemonicMemoryEngineTest` | Memory graph + activation | 5 tests: empty recall → salience 0.5; memorize→recall surfaces entity; 2-hop propagation; baseline deviation; severity→base weight |
| `DnsAnalyzersTest` | 15 DNS analyzers | 8 tests: DGA flags machine label, passes readable word; homograph flags Cyrillic spoof, passes ASCII; typosquat catches near-miss; fast flux; age; DNSSEC; policy; registrar |
| `CognitiveDnsEngineTest` | CODE end-to-end | 4 tests: benign domain → ALLOW; DGA-like → BLOCK/MONITOR; hard policy override → BLOCK with risk/conf 1.0; reasoning chain present |
| `DecisionOrchestratorTest` | Full decision pipeline | 1 test (Mockito): all engines invoked, ≥ 8 reasoning steps, band produced |
| `CognesisApplicationTests` | Spring wiring + H2 | 3 tests: context loads; DNS decision persisted to DB; orchestrator runs through pipeline |

**Total: 31 tests, 0 failures.**

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

## 5. CI suggestion

A minimal pipeline: `git push` → `mvn -q package` → archive `target/*.jar`.
No external services required; H2 covers DB integration until PostgreSQL is
added in a later stage.
