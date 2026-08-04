# CODE — the Cognitive DNS Engine

**Full name:** **C**ognitive **D**NS **E**ngine.

CODE is the flagship module of COGNESIS: a DNS-resolution decision engine that
turns a single DNS query into a calibrated, explainable decision the same way a
domain-reputation analyst would — by reasoning over *many* independent views of
the requested domain before answering.

Implemented in `dns/*`:

- `CognitiveDnsEngineImpl` — the ACDE-facing engine: it collects DNS evidence
  fragments and asks the **ACDE** (`acde/AcdeEngine`) to decide.
- `DnsSignalAnalyzer` (interface) + **15 analyzers** in `dns/analyzer/`.
- `DnsFacts` / `DnsFactsRepository` (in-memory facts store) and `DnsSignal`.
- `DnsDecision` — the verdict, reusing the framework `DecisionResult` shape.

---

## 1. Pipeline

For each resolution request `(domain, clientId, clientIp)`:

```
 1  facts snapshot      ← DnsFactsRepository (whois, certs, history, policies...)
 2  analyzer sweep      ← all enabled DnsSignalAnalyzers produce DnsSignal[]
 3  policy override     ← hard rules checked FIRST
 4  intent enrichment   ← MotiveIntentEngine over signals with strength ≥ 0.4
 5  trust slice         ← FidesTrustEngine (dynamic reputation)
 6  memory slice        ← MnemonicMemoryEngine (similar past domains)
 7  prediction slice    ← SeerPredictionEngine (trend)
 8  deviation slice     ← behaviour baselines (Welford) for this domain
 9  synapse fusion      ← SynapseEngine (likelihood × impact blend)
10  pact actions        ← PactRecommendationEngine
11  reasoning chain     ← ≥ 10 steps (CODE:* senses, FIDES, MNEMONIC, SEER,
                          MOTIVE, RESOLVE, SYNAPSE, PACT)
12  persist             ← decision_log, trust events (see docs/07-database.md)
```

## 2. The 15 analyzers

Each analyzer returns a `DnsSignal(evidenceType, strength, confidence,
explanation, provenance)`.

| # | Analyzer | Evidence type | What it looks for | Key heuristic |
|---|---|---|---|---|
| 1 | DomainAge | `DNS_AGE` | domain younger than ~30 days? | sigmoid(age) |
| 2 | RegistrarHistory | `DNS_REGISTRAR` | recent registrar/status changes | change recency |
| 3 | DnssecAnalyzer | `DNS_DNSSEC` | missing/invalid DNSSEC | missing → 0.7 |
| 4 | FastFluxAnalyzer | `DNS_FAST_FLUX` | many A records, low TTL | flux metric |
| 5 | DgaAnalyzer | `DNS_DGA` | algorithmically-generated label | see §2.1 |
| 6 | HomographAnalyzer | `DNS_HOMOGRAPH` | non-ASCII / visual spoofing | 0.55 + fraction |
| 7 | TyposquattingAnalyzer | `DNS_TYPOSQUAT` | edit distance to trusted domains | min Levenshtein |
| 8 | SubdomainBehaviour | `DNS_SUBDOMAIN` | abnormal subdomain depth/count | depth signal |
| 9 | CertificateTransparency | `DNS_CT` | cert age vs domain age mismatch | gap signal |
| 10 | WhoisAnalyzer | `DNS_WHOIS` | expired/privacy-shielded WHOIS | flag checks |
| 11 | HistoricalTrust | `DNS_HIST_TRUST` | long-term reputation shift | trust delta |
| 12 | ThreatMemory | `DNS_THREAT_MEM` | same entity seen as malicious before | memory lookup |
| 13 | PolicyAnalyzer | `DNS_POLICY` | matches deny-list / policy rules | policy match |
| 14 | UserBehaviour | `DNS_USER_BEHAV` | does this user usually query this? | baseline deviation |
| 15 | NetworkBehaviour | `DNS_NET_BEHAV` | does this network usually resolve this? | baseline deviation |

### 2.1 DGA scoring (DgaAnalyzer)

A pure entropy test is a poor DGA detector (long readable words have high
entropy). CODE uses a **pronounceability-aware** score:

```
entropy  = Shannon entropy over label chars (bits/char)
consRun  = longest consecutive-consonant run

score = 0.15 · sigmoid((len−12)/4)
      + 0.20 · min(1, entropy/4.5)
      + 0.40 · min(1, consRun/8)          ← dominant term
      + 0.25 · (1 − min(1, vowelRatio/0.5))
```

Readable labels like `billing-portal` (long consonant run 2, vowel ratio ~0.29)
score ~0.47; machine-generated labels like `tkqzvbxkadnpqws` (run 8, vowel ratio
~0.07) score ~0.88. Tests lock in both behaviours.

### 2.2 Homograph scoring

Any non-ASCII character in a label is suspicious but a single one is easy to
dilute; CODE floors the strength:

```
if nonAscii > 0:  strength = min(1, 0.55 + fraction·0.40)
```

so a one-character Cyrillic swap (`amаzon.com`) still flags at ≥ 0.55.

## 3. Policy override semantics

**Hard policy wins.** If a policy rule matches (e.g. block-list), CODE
short-circuits before fusion:

```
decision = BLOCK, risk = 1.0, confidence = 1.0
rationale = "policy override: rule 'Block known malware domains' (priority 10)"
```

No evidence fusion can weaken a hard rule. Evidence still enters the log for
analysis, but the verdict is fixed.

## 4. Intent enrichment

MOTIVE (`intent/MotiveIntentEngine`) only consumes signal types with
`strength ≥ 0.4`, mapping them to intents:

```
DNS_DGA / DNS_FAST_FLUX / DNS_HOMOGRAPH  → MALICIOUS_OPERATION / EXFILTRATION
DNS_TYPOSQUAT / DNS_REGISTRAR           → PHISHING / BRAND_ABUSE
DNS_THREAT_MEM                          → REINFECTION (if prior malicious)
```

The dominant intent feeds the SYNAPSE intent slice.

## 5. Output & reasoning chain

`DnsDecision.decisionId()` = the persisted `decision_log` UUID. The chain always
includes, in order:

```
1  CODE:<analyzer>     (each strong signal, top contributors)
2  CODE:SENSE          (aggregate evidence slice)
3  FIDES               (trust)
4  MNEMONIC            (memory salience)
5  SEER                (prediction)
6  MOTIVE              (intent)
7  RESOLVE             (impact)
8  SYNAPSE             (fused risk + band)
9  PACT                (recommended action)
```

## 6. Facts model

`DnsFacts` bundles everything the analyzers read (resolved addresses, TTL,
registrar, registration date, DNSSEC status, certificate info, WHOIS fields,
policy tags). `InMemoryDnsFactsRepository` serves a seedable in-memory view;
a production deployment backs it with a facts store / threat-intel feed.

## 7. REST interface

```
POST /api/v1/dns/evaluate
{ "domain": "evil.example", "clientId": "alice", "clientIp": "10.1.1.5" }
→ DnsDecision (decision, outcome with chain, verdict explanation)
```

See `docs/06-api.md` for full payloads.

## 8. Why a DNS engine?

DNS is the first network touch of almost every attack — phishing, C2, DGA,
exfiltration, typosquatting. A *decision* at resolution time (allow / monitor /
warn / challenge / escalate / isolate / block) is the cheapest, least-disruptive
place to intervene. CODE is designed to
run inline in a DNS proxy/resolver or as a pre-resolution check API.

## 9. Extending

New evidence sources are one class each:

1. Implement `DnsSignalAnalyzer.analyze(request, facts) → DnsSignal`.
2. Register it as a Spring bean (auto-picked by `CognitiveDnsEngineImpl`).
3. (Optional) add its intent mapping in `MotiveIntentEngine`.

The engine core is untouched — the framework guarantee from
`docs/01-architecture.md` §7.
