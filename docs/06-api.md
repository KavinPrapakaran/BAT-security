# BAT security — REST API

Base path: `/api/v1`. JSON everywhere. Actuator health at `/actuator/health`.

Spring Validation is active on request bodies (`jakarta.validation`).

---

## 1. `POST /api/v1/dns/evaluate`

Evaluate a DNS resolution request through DIE.

```json
{
  "domain": "paypa1.com",
  "clientId": "alice",
  "clientIp": "10.1.1.5"
}
```

Response (`DnsDecision`):

```json
{
  "decision": "BLOCK",
  "outcome": {
    "decisionId": "7f3c...",
    "entityId": "paypa1.com",
    "entityType": "DOMAIN",
    "decision": "BLOCK",
    "recommendedAction": "QUARANTINE_DOMAIN",
    "riskScore": 0.87,
    "trustScore": 0.31,
    "confidenceScore": 0.88,
    "businessImpactScore": 0.81,
    "rationale": "policy: ... | evidence: typosquatting 0.88 ...",
    "reasoningChain": [
      { "engine": "DIE:TYPO_SQUAT", "claim": "...", "score": 0.88, "confidence": 0.8 },
      { "engine": "FIDES", "claim": "trust 0.31 (conf 0.77)", "score": 0.31, "confidence": 0.77 }
    ],
    "decidedAt": "2026-08-01T..."
  },
  "verdictExplanation": "BLOCK: paypa1.com scored 0.87 ..."
}
```

Top-level convenience fields on `DnsDecision`: `riskScore()`, `trustScore()`,
`confidenceScore()`, `businessImpactScore()`, `decisionId()`.

## 2. `POST /api/v1/email/evaluate`

Evaluate an inbound email through VOID. The engine resolves the message by
`messageId` from its facts repository and runs the 8 email analyzers (SPF/
DKIM/DMARC auth, sender-domain age, spoofing, links, attachments, sender
reputation, threat intel, policy), then delegates to the ACDE with activity
`email`.

```json
{
  "messageId": "msg-002",
  "recipient": "billing@acme.com",
  "clientIp": "10.1.1.5",
  "context": { "senderIp": "45.155.205.233" }
}
```

Response (`EmailDecision`, reusing the `DecisionResult` shape):

```json
{
  "decision": "BLOCK",
  "outcome": {
    "decisionId": "9a2e...",
    "entityId": "msg-002",
    "entityType": "EMAIL",
    "decision": "BLOCK",
    "recommendedAction": "QUARANTINE_EMAIL",
    "riskScore": 0.83,
    "trustScore": 0.35,
    "confidenceScore": 0.87,
    "businessImpactScore": 0.74,
    "rationale": "evidence: email-auth fail ...",
    "reasoningChain": [
      { "engine": "VOID:EMAIL_AUTH", "claim": "...", "score": 0.9, "confidence": 0.9 }
    ],
    "decidedAt": "2026-08-01T..."
  },
  "verdictExplanation": "BLOCK: msg-002 scored 0.83 ..."
}
```

Same convenience projection as `DnsDecision`: `decisionId()`, `riskScore()`,
`trustScore()`, `confidenceScore()`, `businessImpactScore()`, `decidedAt()`.

## 3. `POST /api/v1/decisions/evaluate`

General-purpose decision for any entity type.

```json
{
  "entityId": "paypa1.com",
  "entityType": "DOMAIN",
  "requestor": "soc",
  "affectedAssetIds": ["asset-billing"],
  "activity": "dns-resolution",
  "context": { "env": "prod" }
}
```

Response: `DecisionResult` (same shape as `outcome` above), with a reasoning
chain of ≥ 10 steps: OBSERVATORY, ACTG (graph), FIDES, MNEMONIC (salience),
MNEMONIC (deviation), CONTEXT, MOTIVE, SEER, RESOLVE, PROFILES (org risk
tolerance, when `context.organizationId` is present), SYNAPSE, PACT.

## 4. Trust management

```
GET  /api/v1/trust/{entityType}/{entityId}
     → { "trust": 0.33, "confidence": 0.77, "observationCount": 12 }

POST /api/v1/trust/events
{ "entityId": "paypa1.com", "entityType": "DOMAIN",
  "eventType": "OBSERVATION_NEGATIVE", "strength": 1.0,
  "narrative": "blacklisted by feed X", "occurredAt": "..." }
     → TrustAssessment (post-update)
```

## 5. Memory

```
GET  /api/v1/memory/recall?entityId=evil.example&entityType=DOMAIN
     → MemoryRecall {
          salience, items: [ { key, type, activation, hops } ]
        }

POST /api/v1/memory/incidents
{ "subjectId": "evil.example", "subjectType": "DOMAIN",
  "relation": "CONNECTED_TO",
  "targetId": "ip:203.0.113.66", "targetType": "IP",
  "severity": 0.9, "occurredAt": "..." }
     → 202 Accepted
```

## 6. Evidence aggregation

```
POST /api/v1/evidence/aggregate
[ { "entityId": "evil.example", "entityType": "DOMAIN",
    "evidenceType": "DNS_DGA", "provenance": "DNS_RESPONSE",
    "strength": 0.9, "confidence": 0.75, "explanation": "...",
    "observedAt": "..." } ]
     → AggregatedEvidence { entityId, entityType, evidenceType,
          strength, confidence, signalCount, dominant }
```

Applies the weighted-mean + dominant-signal aggregation described in
`docs/01-architecture.md` §3.1.

## 7. `POST /api/v1/detections/dns`

Evaluates a DNS request and exports the verdict as SIEM-ready detection
artifacts (Sigma YAML + YARA). Body is the same `DnsResolutionRequest` as
§1.

```json
[
  { "format": "sigma", "content": "title: BAT security - BLOCK ...\n...",
    "filename": "batsec_7f3c....yml" },
  { "format": "yara", "content": "rule batsec_high_risk_block { ... }",
    "filename": "batsec_7f3c....yar" }
]
```

- Sigma: `logsource.category: dns_query`, `query|cstartswith: <domain>`, and
  the reasoning-chain claims embedded as `query|contains` terms. `level` maps
  from the decision band: ALLOW→informational, MONITOR→low, WARN/CHALLENGE→
  medium, ESCALATE→high, ISOLATE/BLOCK→critical.
- YARA: `$a` matches the domain (`ascii wide nocase`), up to 8 reasoning-chain
  claims as secondary strings, with `risk_score` and `decisionId` in meta.

## 8. `POST /api/v1/feeds/refresh`

Triggers a threat-intel feed refresh (abuse.ch ThreatFox/URLhaus host-file
format). No body. Requires a configured feed (see config below); the ingestor
is a no-op and returns `iocsIngested: 0` when disabled or unreachable.

```json
{ "status": "accepted", "iocsIngested": 42 }
```

Flagged domains (`maliciousFlagCount`) flow into ACDE verdicts via
`DnsEvidenceProvider`.

## 9. Enumerations (values used in the scaffold)

| Concept | Values |
|---|---|
| `Decision` | `ALLOW`, `MONITOR`, `WARN`, `CHALLENGE`, `ESCALATE`, `ISOLATE`, `BLOCK` |
| `RecommendedAction` | `NONE`, `ALLOW`, `ALERT_ONLY`, `MONITOR_ONGOING`, `WARN_NOTIFY`, `CHALLENGE_VERIFY`, `REQUIRE_MFA`, `ESCALATE_TO_ANALYST`, `ENRICH_INTELLIGENCE`, `INCREASE_MONITORING`, `RATE_LIMIT`, `QUARANTINE_DOMAIN`, `QUARANTINE_IP`, `QUARANTINE_ENDPOINT`, `SUSPEND_ACCOUNT`, `ISOLATE_ASSET`, `BLOCK_DOMAIN`, `BLOCK_IP`, `BLOCK_USER`, `REVOKE_CERTIFICATE` |
| `EvidenceType` | `DNS_AGE`, `DNS_REGISTRAR`, `DNS_DNSSEC`, `DNS_FAST_FLUX`, `DNS_DGA`, `DNS_HOMOGRAPH`, `DNS_TYPOSQUAT`, `DNS_SUBDOMAIN`, `DNS_CT`, `DNS_WHOIS`, `DNS_HIST_TRUST`, `DNS_THREAT_MEM`, `DNS_POLICY`, `DNS_USER_BEHAV`, `DNS_NET_BEHAV`, `NETWORK_REPUTATION`, `FILE_REPUTATION`, `AUTH_ANOMALY`, `EMAIL_REPUTATION`, `API_ABUSE`, ... |
| `Provenance` | `DNS_RESPONSE`, `NETWORK_FLOW`, `ENDPOINT_TELEMETRY`, `AUTH_LOG`, `EMAIL_GATEWAY`, `THREAT_INTEL`, `API_GATEWAY`, ... |

## 10. Config reference (`application.yml`, `cognesis.*`)

```yaml
cognesis:
  security:
    api-keys: ""                    # FAIL-CLOSED: no default. Set e.g. "key1,key2"
    rate-limit-enabled: true
    rate-limit-per-minute: 120
    rate-limit-burst: 60
  feed:
    enabled: true
    url: "https://urlhaus.abuse.ch/downloads/hostfile/"
    timeout-seconds: 10
    refresh-minutes: 60             # scheduled auto-refresh (0 = disabled)
  dns:
    live:
      enabled: true
      doh-url: "https://cloudflare-dns.com/dns-query"
      doh-fallback-url: "https://dns.google/resolve"   # secondary resolver
      rdap-url: "https://rdap.org/domain"
      crt-url: "https://crt.sh"
      timeout-seconds: 6
      cache-ttl-seconds: 300
    weights: { evidence: 0.50, trust: 0.15, memory: 0.08, intent: 0.08, prediction: 0.05, deviation: 0.04 }
  trust:
    default-trust: 0.5
    positive-gain: 0.15
    negative-gain: 0.35
    decay-rate: 0.005
    observations-for-full-confidence: 60
  memory:
    activation-decay: 0.02
    recall-limit: 20
  algorithm:
    band: { monitor: 0.30, warn: 0.45, challenge: 0.58, escalate: 0.68, isolate: 0.82, block: 0.92 }
    low-confidence-threshold: 0.25
    escalate-when-uncertain: true
```

`feed.enabled: true` fetches the URLhaus host-file once at startup, on
`POST /api/v1/feeds/refresh`, and every `feed.refresh-minutes` (via
`@Scheduled`). Flagged IOCs are written to the persistent IOC store
(`ioc_flag` table) so flag counts survive restarts. Set
`cognesis.dns.live.enabled: false` (or unset URLs) to use the in-memory seed
facts. Each live source is individually time-boxed; the DoH lookup falls over
to `doh-fallback-url` when the primary resolver fails, and only when every
live source is silent does the engine fall back to the seed facts (with an
explicit `WARN` log and a `cognesis.dns.live.fallback` counter). Domains are
validated and URL-encoded before any outbound call.

## 11. Security

`/api/v1/**` and `/actuator/**` (except `/actuator/health` and
`/actuator/info`) require an API key: `Authorization: Bearer <key>` or
`X-API-Key: <key>`. Keys configured via `cognesis.security.api-keys`
(comma-separated). **The service starts fail-closed**: with no keys
configured every protected endpoint returns 403, and no default key is
committed to the repository. Key comparison is constant-time
(`MessageDigest.isEqual`). Unauthorised requests → 403.

A sliding-window rate limiter (default 120 req/min per client, burst 60,
`cognesis.security.rate-limit-*`) runs after authentication and returns
`429 Too Many Requests` with `Retry-After: 60` when a client exceeds its
window. Health details at `/actuator/health/feed` report feed state and the
live IOC count.
