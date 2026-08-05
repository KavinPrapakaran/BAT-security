# DIE — the DNS Intelligence Engine

**Full name:** **D**NS **I**ntelligence **E**ngine.

DIE is the flagship module of BAT security: a DNS-resolution decision engine that
turns a single DNS query into a calibrated, explainable decision the same way a
domain-reputation analyst would — by reasoning over *many* independent views of
the requested domain before answering.

Implemented in `dns/*`:

- `DnsIntelligenceEngineImpl` — the ACDE-facing engine: it collects DNS evidence
  fragments, records the domain→IP resolution into the ACTG graph first (so
  first-touch inheritance works), and asks the **ACDE** (`acde/AcdeEngine`) to
  decide. (`CognitiveDnsEngine` is kept as a deprecated alias for
  compatibility.)
- `DnsSignalAnalyzer` (interface) + **17 analyzers** in `dns/analyzer/`.
- `DnsFacts` / `DnsFactsRepository` and `DnsSignal`.
- `LiveDnsFactsRepository` — real-world facts from DNS-over-HTTPS (DoH,
  primary + secondary resolver), RDAP/WHOIS and certificate-transparency
  (crt.sh), cached + time-boxed, with SSRF-hardened input and honest fallback
  to the in-memory seed data when offline.
- `DnsDecision` — the verdict, reusing the framework `DecisionResult` shape.

---

## 1. Pipeline

For each resolution request `(domain, clientId, clientIp)`:

```
 1  graph record        ← ACTG: domain → IP edges recorded BEFORE analysis
 2  facts snapshot      ← DnsFactsRepository (whois, certs, history, policies...)
 3  analyzer sweep      ← all enabled DnsSignalAnalyzers produce DnsSignal[]
 4  policy override     ← hard rules checked FIRST
 5  intent enrichment   ← MotiveIntentEngine over signals with strength ≥ 0.4
 6  trust slice         ← FidesTrustEngine (dynamic reputation)
 7  memory slice        ← MnemonicMemoryEngine (similar past domains)
 8  prediction slice    ← SeerPredictionEngine (trend)
 9  deviation slice     ← behaviour baselines (Welford) for this domain
10  synapse fusion      ← SynapseEngine (likelihood × impact blend)
11  pact actions        ← PactRecommendationEngine
12  reasoning chain     ← ≥ 10 steps (DIE:* senses, ACTG, FIDES, MNEMONIC, SEER,
                          MOTIVE, RESOLVE, PROFILES, SYNAPSE, PACT)
13  persist             ← decision_log, trust events (see docs/07-database.md)
```

## 2. The 17 analyzers

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
| 16 | ThreatIntel | `THREAT_INTEL` | matches an IOC in the threat-intel feed | feed flag count |
| 17 | ActgAnalyzer | `ACTG` | relationship risk from the trust graph | neighbor association |

### 2.3 Threat-intel feed (analyzer 16)

`ThreatFeedIngestor` fetches a host-file style feed (abuse.ch URLhaus by default)
and flags every matching domain in the facts repository. `ThreatIntelAnalyzer`
turns those flags into a signal:

```
if maliciousFlagCount > 0:  strength = min(1, 0.55 + count·0.2), conf 0.85
else:                       strength 0.1, conf 0.9 (neutral)
```

A single flag already lands above the MOTIVE intent-enrichment threshold
(`strength ≥ 0.4`), so known-bad domains escalate through the normal pipeline.

### 2.4 ACTG graph slice (analyzer 17)

`ActgAnalyzer` queries the **Adaptive Cognitive Trust Graph**: nodes ratchet to
the high-water risk mark of their associations, edges strengthen by `+0.25` per
repeated observation (bounded `[1.0, 3.0]`), and `neighborhoodRisk` skips
zero-risk neighbours so a new user or IP can never dilute a dirty IP's signal.
Because the engine records the domain→IP edge *before* the analyzers run, a
never-seen domain resolving to a known-bad IP inherits its risk on first touch:

```
if domain has ACTG edges:  strength = neighborhoodRisk (carried from the graph)
                           confidence = min(0.9, 0.45 + edges·0.1)
else:                      strength 0.1, conf 0.9 (neutral, no relationships yet)
```

### 2.1 DGA scoring (DgaAnalyzer)

A pure entropy test is a poor DGA detector (long readable words have high
entropy). DIE uses a **pronounceability-aware** score:

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
dilute; DIE floors the strength:

```
if nonAscii > 0:  strength = min(1, 0.55 + fraction·0.40)
```

so a one-character Cyrillic swap (`amаzon.com`) still flags at ≥ 0.55.

## 3. Policy override semantics

**Hard policy wins.** If a policy rule matches (e.g. block-list), DIE
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
1  DIE:<analyzer>     (each strong signal, top contributors)
2  DIE:SENSE          (aggregate evidence slice)
3  ACTG               (graph relationship slice, when present)
4  FIDES              (trust)
5  MNEMONIC           (memory salience)
6  SEER               (prediction)
7  MOTIVE             (intent)
8  RESOLVE            (impact)
9  PROFILES           (org risk tolerance, when an org context is present)
10 SYNAPSE            (fused risk + band)
11 PACT               (recommended action)
```

## 6. Facts model

`DnsFacts` bundles everything the analyzers read (resolved addresses, TTL,
registrar, registration date, DNSSEC status, certificate info, WHOIS fields,
policy tags).

Two repositories implement `DnsFactsRepository`:

- `InMemoryDnsFactsRepository` — deterministic seed data (tests, offline dev),
  now backed by a persistent `IocStore` so feed flags survive restarts.
- `LiveDnsFactsRepository` — the default in production. It queries three public
  sources per domain, each guarded with try/catch and a connect/read timeout:
  - **Cloudflare DoH** (`https://cloudflare-dns.com/dns-query`) — A records; the
    `AD` (authentic data) flag becomes the `dnssecValid` fact. If the primary
    resolver fails, the lookup falls over to a **secondary resolver**
    (`cognesis.dns.live.doh-fallback-url`, Google by default); both Cloudflare
    and Google response formats are accepted.
  - **RDAP/WHOIS** (`https://rdap.org/domain`) — registration date → `ageDays`,
    `secureDNS.delegationSigned` → DNSSEC, registrar name.
  - **crt.sh** (`https://crt.sh`) — certificate transparency SAN entries →
    `subdomains`, `certificateCount`, `certificateIssuedAt`.

  Every lookup domain is **validated and URL-encoded** before any outbound
  call (strict label grammar rejects path/query injection outright), and a
  `cognesis-demo/1.0` User-Agent is sent. Results are cached for
  `cognesis.dns.live.cache-ttl-seconds`. If **no** live source responds the
  repository falls back wholesale to the in-memory sample facts — but it does
  so honestly: a `WARN` log and a `cognesis.dns.live.fallback` counter make the
  degraded mode visible, and the sample facts' `maliciousFlagCount` is carried
  into the merged result. Enable/disable via `cognesis.dns.live.enabled` (off
  by default in tests, on in production).

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
place to intervene. DIE is designed to
run inline in a DNS proxy/resolver or as a pre-resolution check API.

## 9. Extending

New evidence sources are one class each:

1. Implement `DnsSignalAnalyzer.analyze(request, facts) → DnsSignal`.
2. Register it as a Spring bean (auto-picked by `DnsIntelligenceEngineImpl`).
3. (Optional) add its intent mapping in `MotiveIntentEngine`.

The engine core is untouched — the framework guarantee from
`docs/01-architecture.md` §7.
