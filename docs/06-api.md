# COGNESIS — REST API

Base path: `/api/v1`. JSON everywhere. Actuator health at `/actuator/health`.

Spring Validation is active on request bodies (`jakarta.validation`).

---

## 1. `POST /api/v1/dns/evaluate`

Evaluate a DNS resolution request through CODE.

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
      { "engine": "CODE:TYPO_SQUAT", "claim": "...", "score": 0.88, "confidence": 0.8 },
      { "engine": "FIDES", "claim": "trust 0.31 (conf 0.77)", "score": 0.31, "confidence": 0.77 }
    ],
    "decidedAt": "2026-08-01T..."
  },
  "verdictExplanation": "BLOCK: paypa1.com scored 0.87 ..."
}
```

Top-level convenience fields on `DnsDecision`: `riskScore()`, `trustScore()`,
`confidenceScore()`, `businessImpactScore()`, `decisionId()`.

## 2. `POST /api/v1/decisions/evaluate`

General-purpose decision for any entity type.

```json
{
  "entityId": "paypa1.com",
  "entityType": "DOMAIN",
  "clientId": "soc",
  "assetIds": ["asset-billing"],
  "context": "dns-resolution",
  "metadata": { "env": "prod" }
}
```

Response: `DecisionResult` (same shape as `outcome` above), with a reasoning
chain of ≥ 8 steps: OBSERVATORY, FIDES, MNEMONIC, SEER, MOTIVE, RESOLVE,
SYNAPSE, PACT.

## 3. Trust management

```
GET  /api/v1/trust/{entityType}/{entityId}
     → { "trust": 0.33, "confidence": 0.77, "observationCount": 12 }

POST /api/v1/trust/events
{ "entityId": "paypa1.com", "entityType": "DOMAIN",
  "eventType": "OBSERVATION_NEGATIVE", "strength": 1.0,
  "narrative": "blacklisted by feed X", "occurredAt": "..." }
     → TrustAssessment (post-update)
```

## 4. Memory

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

## 5. Evidence aggregation

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

## 6. Enumerations (values used in the scaffold)

| Concept | Values |
|---|---|
| `Decision` | `ALLOW`, `WARN`, `MONITOR`, `BLOCK` |
| `RecommendedAction` | `NONE`, `WATCH`, `RATE_LIMIT`, `QUARANTINE_DOMAIN`, `QUARANTINE_IP`, `SUSPEND_ACCOUNT`, `BLOCK_DOMAIN`, `ISOLATE_HOST`, `ESCALATE_HUMAN` |
| `EvidenceType` | `DNS_AGE`, `DNS_REGISTRAR`, `DNS_DNSSEC`, `DNS_FAST_FLUX`, `DNS_DGA`, `DNS_HOMOGRAPH`, `DNS_TYPOSQUAT`, `DNS_SUBDOMAIN`, `DNS_CT`, `DNS_WHOIS`, `DNS_HIST_TRUST`, `DNS_THREAT_MEM`, `DNS_POLICY`, `DNS_USER_BEHAV`, `DNS_NET_BEHAV`, `NETWORK_REPUTATION`, `FILE_REPUTATION`, `AUTH_ANOMALY`, `EMAIL_REPUTATION`, `API_ABUSE`, ... |
| `Provenance` | `DNS_RESPONSE`, `NETWORK_FLOW`, `ENDPOINT_TELEMETRY`, `AUTH_LOG`, `EMAIL_GATEWAY`, `THREAT_INTEL`, `API_GATEWAY`, ... |

## 7. Config reference (`application.yml`, `cognesis.*`)

```yaml
cognesis:
  synapse:
    weights: { evidence: 0.50, trust: 0.15, memory: 0.08, intent: 0.08, prediction: 0.05, deviation: 0.04, impact: 0.70 }
    bands: { warn: 0.32, monitor: 0.55, block: 0.80, tolerance: 1.0, lowConfidenceThreshold: 0.25, escalateWhenUncertain: true }
  trust:
    positive-gain: 0.15
    negative-gain: 0.35
    confidence-n0: 60
    decay-half-life-hours: 24
  memory:
    propagation-factor: 0.4
    max-hops: 2
    decay-half-life-hours: 72
```
