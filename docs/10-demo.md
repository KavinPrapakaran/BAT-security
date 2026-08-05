# BAT security — End-to-end demo (live sources)

This walkthrough shows the framework running against **real** data: a live
threat-intel feed (abuse.ch URLhaus), real DNS-over-HTTPS, RDAP/WHOIS and
certificate-transparency lookups, and a verdict that ends up as a SIEM-ready
Sigma rule.

All commands assume you are in the repository root.

---

## 1. Run it

Docker (feed + live DNS enabled by default via `docker-compose.yml`). The API
is **fail-closed**: configure at least one key first:

```bash
export COGNESIS_SECURITY_API_KEYS=your-secret-key
docker compose up --build
```

Or locally with Maven:

```bash
mvn spring-boot:run
```

Both serve the API on `http://localhost:8080`. A startup log line shows the
live threat feed being ingested:

```
Threat feed refresh: 1234 IOCs ingested from https://urlhaus.abuse.ch/downloads/hostfile/
```

> The feed refresh runs **at startup**, on a schedule (default every 60 min,
> `cognesis.feed.refresh-minutes`), and on demand (see §4). Startup never fails
> if the feed is offline — ingestion is guarded and time-boxed. Flagged IOCs
> are persisted in the `ioc_flag` table and survive restarts; live-source
> health is exposed at `/actuator/health/feed`.

## 2. Evaluate a domain with live facts

```bash
curl -s http://localhost:8080/api/v1/dns/evaluate \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <your-key>' \
  -d '{"domain":"google.com","clientId":"alice","clientIp":"10.1.1.5"}'
```

`google.com` is a long-lived, DNSSEC-validated, feed-clean domain — expect
**ALLOW** with a chain that cites live registration age and DNSSEC:

```json
{
  "decision": "ALLOW",
  "outcome": {
    "entityId": "google.com",
    "decision": "ALLOW",
    "riskScore": 0.21,
    "confidenceScore": 0.86,
    "reasoningChain": [
      { "engine": "DIE:DOMAIN_AGE",  "claim": "registered 1997-09-15 (live RDAP, age ~10500d)" },
      { "engine": "DIE:DNSSEC",      "claim": "AD=1 / delegationSigned=true (live)" },
      { "engine": "DIE:THREAT_INTEL","claim": "no IOC match in feed", "score": 0.1 },
      { "engine": "FIDES", "...", "...", "..." }
    ]
  },
  "verdictExplanation": "ALLOW: google.com scored 0.21 ..."
}
```

## 3. Hit a known-bad domain

Pick an IOC from the freshly ingested URLhaus feed (grab any domain from
`https://urlhaus.abuse.ch/browse/`) and evaluate it:

```bash
curl -s http://localhost:8080/api/v1/dns/evaluate \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <your-key>' \
  -d '{"domain":"<urlhaus-ioc>","clientId":"alice","clientIp":"10.1.1.5"}'
```

Expected: **BLOCK** (or at minimum ESCALATE/ISOLATE depending on the full
evidence), with the threat-intel step near the top of the chain:

```json
{
  "decision": "BLOCK",
  "outcome": {
    "riskScore": 0.92,
    "reasoningChain": [
      { "engine": "DIE:THREAT_INTEL", "claim": "flagged 1x by abuse.ch feed", "score": 0.75, "confidence": 0.85 },
      { "engine": "DIE:DOMAIN_AGE",   "claim": "registered 12 days ago (live RDAP)", "score": 0.6, "confidence": 0.8 }
    ]
  },
  "verdictExplanation": "BLOCK: <urlhaus-ioc> scored 0.92 ..."
}
```

The `DIE:THREAT_INTEL` step is the *new* 16th analyzer: a single feed flag
already exceeds the MOTIVE enrichment threshold, so the intent slice and the
final band both escalate.

## 4. Refreshing the feed on demand

```bash
curl -s -X POST http://localhost:8080/api/v1/feeds/refresh \
  -H 'X-API-Key: <your-key>'
# → { "status": "accepted", "iocsIngested": 1234 }
```

## 5. Export a SIEM-ready Sigma rule

```bash
curl -s http://localhost:8080/api/v1/detections/dns \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <your-key>' \
  -d '{"domain":"<urlhaus-ioc>","clientId":"alice","clientIp":"10.1.1.5"}' \
  -o detection.json

# the response is a bundle: one Sigma rule + one YARA rule with filenames
```

Example Sigma rule emitted for a BLOCK verdict:

```yaml
title: BAT security BLOCK for <urlhaus-ioc>
logsource:
  category: dns_query
detection:
  selection:
    query|contains: <urlhaus-ioc>
  condition: selection
level: critical
```

Import the `batsec_<uuid>.yml` file into any Sigma-compatible SIEM/EDR
(Wazuh, Elastic, Splunk via sigma2es, THOR, ...).

> **Screenshot placeholder** — paste a screenshot of the imported Sigma rule
> (and a triggered alert) here once you've loaded `detection.json` into your
> SIEM of choice.

## 6. Turning it off

Everything degrades gracefully if the network or a source is unavailable:

| Setting | Off effect |
|---|---|
| `COGNESIS_DNS_LIVE_ENABLED=false` | facts fall back to in-memory seed data; engine still works |
| `COGNESIS_FEED_ENABLED=false` | no feed fetch; `DIE:THREAT_INTEL` stays neutral |
| no network at all | every live source times out; wholesale fallback, verdict still produced |

Tests cover all of these paths (`LiveDnsFactsRepositoryTest`,
`ThreatFeedIngestorTest`) with mock HTTP — no real network needed to run them.

---

Next: read `docs/03-dns-engine.md` for the analyzer internals, or
`docs/06-api.md` for the full REST contract.
