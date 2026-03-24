# masq_infra.json — Schema Reference

This document defines the data model for `_data/masq_infra.json`, the primary output
of the masquerading-infrastructure detection pipeline.

---

## Top-Level Keys

| Key | Type | Description |
|-----|------|-------------|
| `meta` | object | Pipeline run metadata |
| `records` | array | Confirmed or suspected malicious delivery domains |
| `campaigns` | array | Clustered campaigns (only included when confidence ≥ 70) |
| `weekly_summary` | object | Aggregate statistics for the current run |

---

## `meta`

| Field | Type | Description |
|-------|------|-------------|
| `generated_at` | string (ISO-8601) | Timestamp the file was written |
| `pipeline_version` | string | Semver string for the pipeline scripts |
| `schema_version` | string | Semver string for this schema |

---

## `records[]`

Each element represents a single confirmed or suspected malicious delivery domain,
as identified and enriched by the pipeline.

### Identity & Network

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `domain` | string | no | The delivery domain (apex or subdomain) |
| `ip` | string | yes | Last-resolved IPv4/IPv6 address |
| `asn` | string | yes | ASN string, e.g. `"AS13335 CLOUDFLARENET"` |
| `first_seen` | string (ISO-8601 date) | no | Earliest date the domain was observed |
| `last_seen` | string (ISO-8601 date) | no | Most recent date the domain was observed |
| `source` | string | no | Feed or hunt that surfaced this domain (e.g. `"threatfox"`, `"urlscan_hunt"`) |

### Payload

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `payload_sha256` | string (hex) | yes | SHA-256 of the served payload |
| `payload_family` | string | yes | Malware family name (e.g. `"Lumma"`, `"AsyncRAT"`) |
| `payload_class` | string (enum) | no | Broad class of payload — see value table below |
| `payload_file_type` | string | yes | MIME type or extension (e.g. `"application/x-msdownload"`, `".exe"`) |

**`payload_class` values:**

| Value | Meaning |
|-------|---------|
| `stealer` | Credential / data-stealing malware |
| `c2` | Command-and-control implant or beacon |
| `rmm` | Abused remote-management / monitoring tool |
| `loader` | Downloader / dropper that fetches a secondary payload |
| `unknown` | Class not yet determined |

### Lure

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `lure_brand` | string | yes | Brand being impersonated (e.g. `"Microsoft"`, `"Zoom"`) |
| `lure_type` | string | yes | Style of lure (e.g. `"captcha"`, `"software-update"`, `"invoice"`) |

### Delivery Chain

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `chain_observed` | boolean | no | Whether a multi-step redirect chain was traced |
| `chain_depth` | integer | no | Number of hops in the chain (`0` when `chain_observed` is `false`) |
| `chain` | array of `ChainNode` | no | Ordered list of hops; empty array when not observed |

#### `ChainNode` sub-schema

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `url` | string | no | Full URL of this hop |
| `domain` | string | no | Apex domain of this hop |
| `role` | string | no | Role in the chain (e.g. `"redirect"`, `"landing"`, `"payload-delivery"`) |
| `status_code` | integer | yes | HTTP status code returned by this hop |
| `ip` | string | yes | Resolved IP for this hop |

### TLS Certificate

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `cert_cn` | string | yes | Certificate Common Name |
| `cert_issuer` | string | yes | Certificate issuer (CA or self) |
| `cert_self_signed` | boolean | yes | `true` if the cert is self-signed |

### Threat Intelligence

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `favicon_hash` | string | yes | MurmurHash3 of the favicon (mmh3 int as string) |
| `urlscan_uuid` | string (UUID) | yes | URLScan.io scan UUID |
| `vt_detected` | boolean | yes | Whether VirusTotal returns ≥ 1 detection |
| `vt_detection_count` | integer | yes | Number of VT engines detecting this domain |

### Confidence

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `confidence` | integer (0–100) | no | Pipeline-assigned confidence score |
| `confidence_label` | string (enum) | no | Human-readable tier derived from `confidence` |

**`confidence_label` derivation:**

| Label | Range |
|-------|-------|
| `low` | 0–39 |
| `medium` | 40–69 |
| `high` | 70–89 |
| `confirmed` | 90–100 |

### Triage

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `triage_note` | string | yes | Free-text analyst or model observation |
| `triage_source` | string (enum) | no | What produced the triage decision |

**`triage_source` values:**

| Value | Meaning |
|-------|---------|
| `automated` | Rule-based pipeline logic |
| `analyst` | Human analyst |
| `claude` | Claude AI triage (via `claude_triage.py`) |

---

## `campaigns[]`

Campaigns group `records` that share a hard signal linking them to a common
threat actor or infrastructure cluster. **A campaign entry is only written when
the campaign's own confidence score is ≥ 70.**

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `campaign_id` | string | no | Unique slug, e.g. `"lmst-2025-04-a"` |
| `hard_signal` | string (enum) | no | The evidence type that anchors the cluster — see value table |
| `members` | array of string | no | Domain values from `records[]` belonging to this campaign |
| `confidence` | integer (≥ 70) | no | Campaign-level confidence score |
| `first_seen` | string (ISO-8601 date) | no | Earliest `first_seen` among member records |
| `last_seen` | string (ISO-8601 date) | no | Latest `last_seen` among member records |
| `notes` | string | yes | Free-text notes on the campaign |

**`hard_signal` values:**

| Value | Meaning |
|-------|---------|
| `shared_favicon` | Two or more domains share an identical favicon hash |
| `shared_ip` | Two or more domains resolve to the same IP address |
| `shared_payload` | Two or more domains serve the same payload (by SHA-256) |
| `shared_cert_pattern` | Two or more domains share a TLS certificate pattern (CN/issuer/self-signed combo) |

---

## `weekly_summary`

Aggregate statistics written at the end of each pipeline run.

| Field | Type | Description |
|-------|------|-------------|
| `run_date` | string (ISO-8601 date) | Date the pipeline ran |
| `record_count` | integer | Total number of records in `records[]` |
| `campaign_count` | integer | Total number of campaigns in `campaigns[]` |
| `new_records` | integer | Records added since the previous run |
| `high_confidence_count` | integer | Records with `confidence_label` of `high` or `confirmed` |

---

## Example Record (abbreviated)

```json
{
  "domain": "update-zoom-app.com",
  "ip": "185.220.101.42",
  "asn": "AS209650 ZWFNL",
  "first_seen": "2025-03-10",
  "last_seen": "2025-03-17",
  "source": "threatfox",
  "payload_sha256": "a3f1...c9d2",
  "payload_family": "Lumma",
  "payload_class": "stealer",
  "payload_file_type": "application/x-msdownload",
  "lure_brand": "Zoom",
  "lure_type": "software-update",
  "chain_observed": true,
  "chain_depth": 2,
  "chain": [
    {"url": "https://update-zoom-app.com/", "domain": "update-zoom-app.com", "role": "landing", "status_code": 200, "ip": "185.220.101.42"},
    {"url": "https://cdn-zoom-dl.com/zoom.exe", "domain": "cdn-zoom-dl.com", "role": "payload-delivery", "status_code": 200, "ip": "185.220.101.99"}
  ],
  "favicon_hash": "1234567890",
  "cert_cn": "update-zoom-app.com",
  "cert_issuer": "Let's Encrypt",
  "cert_self_signed": false,
  "urlscan_uuid": "abc12345-...",
  "vt_detected": true,
  "vt_detection_count": 18,
  "confidence": 92,
  "confidence_label": "confirmed",
  "triage_note": "Classic Lumma stealer lure impersonating Zoom installer; chain confirmed via URLScan trace.",
  "triage_source": "claude"
}
```
