---
layout: default
title: Software Impersonation Infrastructure
description: "Confirmed payload delivery infrastructure — the domains that served malicious binaries, the redirect chains that led users there, and the operator patterns that link campaigns."
permalink: /trends/masq-infra/
---

<style>
.cg-sidenav {
  position: fixed;
  left: 0;
  top: 80px;
  width: 200px;
  padding: 1rem 0;
}
@media (max-width: 767px) {
  .cg-sidenav { display: none; }
}

.cg-sidenav ul {
  list-style: none;
  padding: 0;
  margin: 0;
}

.cg-sidenav li {
  border-left: 2px solid var(--border);
  margin: 0;
}

.cg-sidenav a {
  display: block;
  padding: .6rem 1rem;
  color: var(--text-muted);
  font-size: .82rem;
  text-decoration: none;
  border-left: 2px solid transparent;
  margin-left: -2px;
  transition: color .15s;
}

.cg-sidenav a:hover { color: var(--text); }

.cg-sidenav a.active {
  color: var(--accent);
  border-left-color: var(--accent);
}

@media (min-width: 768px) {
  .cg-main {
    margin-left: 220px;
    max-width: 860px;
    padding: 2rem 1.5rem 4rem;
  }
}
@media (max-width: 767px) {
  .cg-main {
    margin-left: 0;
    max-width: 860px;
    padding: 2rem 1.5rem 4rem;
  }
}

.cg-metrics {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
  margin: 1.25rem 0 2rem;
}

.cg-metric {
  flex: 1 1 160px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: .85rem 1rem;
}

.cg-metric-val {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--text);
  font-family: monospace;
  line-height: 1.2;
}

.cg-metric-lbl {
  font-size: .75rem;
  color: var(--text-muted);
  margin-top: .2rem;
}

.cg-class-stealer,
.cg-class-c2,
.cg-class-rmm,
.cg-class-loader,
.cg-class-unknown {
  font-size: .72rem;
  font-weight: 600;
  padding: .15rem .5rem;
  border-radius: 3px;
  font-family: monospace;
  text-transform: uppercase;
  letter-spacing: .04em;
  white-space: nowrap;
}

.cg-class-stealer {
  background: #ef444420;
  color: #ef4444;
  border: 1px solid #ef444440;
}

.cg-class-c2 {
  background: #f9731620;
  color: #f97316;
  border: 1px solid #f9731640;
}

.cg-class-rmm {
  background: #8b5cf620;
  color: #8b5cf6;
  border: 1px solid #8b5cf640;
}

.cg-class-loader {
  background: #06b6d420;
  color: #06b6d4;
  border: 1px solid #06b6d440;
}

.cg-class-unknown {
  background: #6b728020;
  color: #6b7280;
  border: 1px solid #6b728040;
}

.cg-chain-notice {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-left: 3px solid #6b7280;
  border-radius: 6px;
  padding: .75rem 1rem;
  font-size: .82rem;
  color: var(--text-muted);
  margin: .75rem 0;
}

.cg-campaign {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem 1.25rem;
  margin-bottom: 1rem;
}

.cg-campaign-signal {
  font-family: monospace;
  font-size: .78rem;
  color: var(--text-muted);
  margin-bottom: .5rem;
}

.cg-campaign-meta {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
  font-size: .78rem;
  color: var(--text-muted);
  margin: .5rem 0;
}

.cg-campaign-narrative {
  font-style: italic;
  color: var(--text-muted);
  font-size: .85rem;
  margin: .5rem 0;
  padding-left: .75rem;
  border-left: 2px solid var(--border);
}

.cg-campaign-families {
  display: flex;
  gap: .4rem;
  flex-wrap: wrap;
  margin-top: .5rem;
}

.cg-methodology {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  border-radius: 6px;
  padding: .75rem 1rem;
  margin: 1rem 0 1.5rem;
  font-size: .82rem;
  color: var(--text-muted);
}

.cg-bar-wrap {
  display: flex;
  align-items: center;
  gap: .75rem;
  margin: .35rem 0;
}

.cg-bar {
  height: 18px;
  border-radius: 3px;
  min-width: 4px;
  transition: width .3s;
}

.cg-bar-label {
  font-size: .78rem;
  color: var(--text-muted);
  min-width: 120px;
}

.cg-bar-count {
  font-size: .78rem;
  color: var(--text-muted);
  font-family: monospace;
}
</style>

<div class="cg-sidenav">
  <ul>
    <li><a href="#overview">Overview</a></li>
    <li><a href="#chains">Delivery Chains</a></li>
    <li><a href="#payloads">Payloads</a></li>
    <li><a href="#campaigns">Campaigns</a></li>
    <li><a href="#infrastructure">Infrastructure</a></li>
    <li><a href="#samples">Samples</a></li>
    <li><a href="#chokepoints">Chokepoints</a></li>
  </ul>
</div>

<div class="cg-main">

<section id="overview">
<h1>Software Impersonation Infrastructure</h1>
<p class="cg-meta">
Coverage: T1036 Masquerading · T1583.001 Domains · T1608.001 Upload Malware &nbsp;·&nbsp;
Updated: {{ site.data.masq_infra.meta.last_updated | default: "not yet run" }}
{% if site.data.masq_infra.meta.record_count > 0 %}
&nbsp;·&nbsp; n={{ site.data.masq_infra.meta.record_count }},
{{ site.data.masq_infra.meta.lookback_days }}-day lookback
{% endif %}
</p>

<div class="cg-methodology">
<strong>Methodology:</strong> IOC-first pipeline.
Records sourced from confirmed malicious payload reports (MalwareBazaar, ThreatFox, URLhaus)
and infrastructure hunts (Shodan, URLScan). Every record has a confirmed payload hash.
Delivery chains shown only when URLScan captured the redirect sequence — chain coverage is
partial and expected to be incomplete.
</div>

{% if site.data.masq_infra.meta.record_count > 0 %}
<div class="cg-metrics">
  <div class="cg-metric">
    <div class="cg-metric-val">{{ site.data.masq_infra.meta.record_count }}</div>
    <div class="cg-metric-lbl">Confirmed records</div>
  </div>
  <div class="cg-metric">
    <div class="cg-metric-val">{{ site.data.masq_infra.payload_summary.top_families | size }}</div>
    <div class="cg-metric-lbl">Payload families</div>
  </div>
  <div class="cg-metric">
    <div class="cg-metric-val">{{ site.data.masq_infra.payload_summary.chain_observed_count }}
      <span style="font-size:.9rem;color:var(--text-muted)">({{ site.data.masq_infra.payload_summary.chain_observed_pct }}%)</span></div>
    <div class="cg-metric-lbl">Chains observed</div>
  </div>
  <div class="cg-metric">
    <div class="cg-metric-val">{{ site.data.masq_infra.campaigns | size }}</div>
    <div class="cg-metric-lbl">Active campaigns</div>
  </div>
</div>
{% else %}
<div class="cg-chain-notice">
Pipeline has not been run yet. Use the Streamlit app to collect data and export masq_infra.json.
</div>
{% endif %}
</section>

<section id="chains">
<h2>Delivery Chains</h2>
<p>Redirect sequences captured by URLScan at the moment of scanning. A chain shows the full path
from initial URL through any redirectors to the lure page and payload download. Coverage is
best-effort — only available when the URL was submitted to URLScan while the infrastructure
was active.</p>

{% assign chain_records = site.data.masq_infra.records | where: "chain_observed", true %}

{% if chain_records.size > 0 %}
<p class="cg-meta">{{ chain_records.size }} chains observed of
{{ site.data.masq_infra.meta.record_count }} total records
({{ site.data.masq_infra.payload_summary.chain_observed_pct }}%)</p>

{% for rec in chain_records limit:5 %}
<div class="cg-campaign">
  <div class="cg-campaign-signal">{{ rec.domain }}</div>
  <div class="cg-campaign-meta">
    <span>{{ rec.first_seen | date: "%Y-%m-%d" }}</span>
    <span class="cg-class-{{ rec.payload_class }}">{{ rec.payload_class }}</span>
    {% if rec.payload_family %}
    <code>{{ rec.payload_family }}</code>
    {% endif %}
  </div>
  {% if rec.chain %}
  <div style="margin:.5rem 0;font-size:.82rem;font-family:monospace">
    {% for node in rec.chain %}
    <span style="color:{% if node.role == 'payload' %}#ef4444{% elsif node.role == 'lure' %}#f59e0b{% elsif node.role == 'cdn' %}#3b82f6{% else %}var(--text-muted){% endif %}">{{ node.role }}:{{ node.domain }}</span>
    {% unless forloop.last %} → {% endunless %}
    {% endfor %}
  </div>
  {% endif %}
</div>
{% endfor %}
{% else %}
<div class="cg-chain-notice">
No delivery chains observed yet. Chains are captured when URLScan scans a URL while the
infrastructure is active.
</div>
{% endif %}

{% assign no_chain = site.data.masq_infra.records | where: "chain_observed", false %}
{% if no_chain.size > 0 %}
<div class="cg-chain-notice">
{{ no_chain.size }} confirmed records have no observed delivery chain. These appear in Payloads
and Samples. Absence of chain data does not affect payload confirmation.
</div>
{% endif %}
</section>

<section id="payloads">
<h2>Payloads</h2>

{% if site.data.masq_infra.payload_summary %}
{% assign ps = site.data.masq_infra.payload_summary %}

<h3>Payload Class Breakdown</h3>
{% assign max_class = 1 %}
{% assign cb = ps.class_breakdown %}
{% for item in cb %}
  {% if item[1] > max_class %}
    {% assign max_class = item[1] %}
  {% endif %}
{% endfor %}

{% assign classes = "stealer,c2,rmm,loader,unknown" | split: "," %}
{% for cls in classes %}
{% assign cls_count = cb[cls] | default: 0 %}
{% assign bar_pct = cls_count | times: 100 | divided_by: max_class %}
<div class="cg-bar-wrap">
  <span class="cg-bar-label">
    <span class="cg-class-{{ cls }}">{{ cls }}</span>
  </span>
  <div class="cg-bar" style="width:{{ bar_pct | times: 3 }}px;background:{% if cls == 'stealer' %}#ef4444{% elsif cls == 'c2' %}#f97316{% elsif cls == 'rmm' %}#8b5cf6{% elsif cls == 'loader' %}#06b6d4{% else %}#6b7280{% endif %}80"></div>
  <span class="cg-bar-count">{{ cls_count }}</span>
</div>
{% endfor %}

{% if ps.top_families.size > 0 %}
<h3>Top Families</h3>
<table class="cg-table">
  <thead>
    <tr>
      <th>Family</th><th>Class</th><th>Count</th><th>Share</th>
    </tr>
  </thead>
  <tbody>
    {% for fam in ps.top_families limit:15 %}
    <tr>
      <td><code>{{ fam.family }}</code></td>
      <td><span class="cg-class-{{ fam.class }}">{{ fam.class }}</span></td>
      <td>{{ fam.count }}</td>
      <td class="muted">{% assign share = fam.count | times: 100 | divided_by: site.data.masq_infra.meta.record_count %}{{ share }}%</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

{% if ps.lure_payload_matrix.size > 0 %}
<h3>Lure Type → Payload Class</h3>
<p>Which impersonated brands deliver which payload types.</p>
<table class="cg-table">
  <thead>
    <tr>
      <th>Lure type</th><th>Payload class</th><th>Count</th>
    </tr>
  </thead>
  <tbody>
    {% for row in ps.lure_payload_matrix %}
    <tr>
      <td>{{ row.lure_type | replace: "_"," " }}</td>
      <td><span class="cg-class-{{ row.payload_class }}">{{ row.payload_class }}</span></td>
      <td>{{ row.count }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}
{% else %}
<div class="cg-chain-notice">
No payload data yet. Run the collection pipeline.
</div>
{% endif %}
</section>

<section id="campaigns">
<h2>Campaigns</h2>
<div class="cg-methodology">
Only campaigns with a confirmed hard signal — shared favicon hash, shared IP address, shared
payload hash, or matching certificate pattern — and confidence score ≥ 70 are shown. Clusters
below this threshold are excluded. Hard signal requirement ensures every campaign has at least
one infrastructure-level link between domains, not just temporal or hosting coincidence.
</div>

{% if site.data.masq_infra.campaigns.size > 0 %}
<p class="cg-meta">{{ site.data.masq_infra.campaigns | size }} confirmed campaigns</p>

{% for camp in site.data.masq_infra.campaigns %}
<div class="cg-campaign">
  <div class="cg-campaign-signal">{{ camp.hard_signal | replace: "_"," " }}: <code>{{ camp.hard_signal_value | truncate: 32 }}</code></div>
  <div class="cg-campaign-meta">
    <span>{{ camp.domain_count }} domains</span>
    <span>{{ camp.first_seen | date: "%Y-%m-%d" }} → {{ camp.last_seen | date: "%Y-%m-%d" }}</span>
    <span style="{% if camp.confidence >= 70 %}color:#22c55e{% else %}color:#f59e0b{% endif %}">{{ camp.confidence_label | upcase }} ({{ camp.confidence }})</span>
  </div>
  {% if camp.narrative %}
  <div class="cg-campaign-narrative">{{ camp.narrative }}</div>
  {% endif %}
  <div class="cg-campaign-families">
    {% for fam in camp.payload_families %}
    <code class="cg-family-tag">{{ fam }}</code>
    {% endfor %}
    {% for cls in camp.payload_classes %}
    <span class="cg-class-{{ cls }}">{{ cls }}</span>
    {% endfor %}
  </div>
  {% if camp.domains.size > 0 %}
  <details style="margin-top:.75rem">
    <summary style="font-size:.82rem;color:var(--text-muted);cursor:pointer">
      Show {{ camp.domains.size }} domain(s)
    </summary>
    <ul class="cg-domain-list">
      {% for d in camp.domains %}
      <li class="mono">{{ d }}</li>
      {% endfor %}
    </ul>
  </details>
  {% endif %}
</div>
{% endfor %}

{% else %}
<div class="cg-chain-notice">
No campaigns identified yet. Campaigns require confirmed delivery records with shared
infrastructure signals.
</div>
{% endif %}
</section>

<section id="infrastructure">
<h2>Infrastructure</h2>

{% assign records = site.data.masq_infra.records %}
{% if records.size > 0 %}

<h3>Confirmed Delivery Domains</h3>
<table class="cg-table">
  <thead>
    <tr>
      <th>Domain</th><th>IP</th><th>ASN</th><th>Cert issuer</th><th>First seen</th>
    </tr>
  </thead>
  <tbody>
    {% assign sorted = records | sort: "last_seen" | reverse %}
    {% for rec in sorted limit:20 %}
    <tr>
      <td class="mono">{{ rec.domain }}</td>
      <td class="mono muted">{{ rec.ip | default: "—" }}</td>
      <td class="muted">{{ rec.asn | default: "—" }}</td>
      <td class="muted">{{ rec.cert_issuer | default: "—" }}</td>
      <td class="muted">{{ rec.first_seen | date: "%Y-%m-%d" }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>

{% assign fav_clusters = site.data.masq_infra.infrastructure_summary.favicon_clusters %}
{% if fav_clusters.size > 0 %}
<h3>Favicon Clusters</h3>
<p>Domains sharing a favicon hash are likely operated by the same actor.</p>
<table class="cg-table">
  <thead>
    <tr>
      <th>Favicon hash</th><th>Domains</th><th>Sample domain</th>
    </tr>
  </thead>
  <tbody>
    {% for fc in fav_clusters %}
    <tr>
      <td class="mono">
        <a href="https://www.shodan.io/search?query=http.favicon.hash:{{ fc.favicon_hash }}" target="_blank" rel="noopener">{{ fc.favicon_hash }}</a>
      </td>
      <td>{{ fc.count }}</td>
      <td class="mono muted">{{ fc.sample_domain }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

{% assign top_asns = site.data.masq_infra.infrastructure_summary.top_asns %}
{% if top_asns.size > 0 %}
<h3>Hosting Distribution</h3>
<p class="muted" style="font-size:.82rem">CDN providers excluded. Shows adversary-controlled or abuse-tolerant hosting only.</p>
{% assign max_asn = top_asns.first.count | default: 1 %}
{% for asn in top_asns limit:10 %}
{% assign bar_w = asn.count | times: 300 | divided_by: max_asn %}
<div class="cg-bar-wrap">
  <span class="cg-bar-label muted" style="font-size:.78rem">{{ asn.asn | truncate: 30 }}</span>
  <div class="cg-bar" style="width:{{ bar_w }}px;background:var(--accent);opacity:.6"></div>
  <span class="cg-bar-count">{{ asn.count }}</span>
</div>
{% endfor %}
{% endif %}

{% else %}
<div class="cg-chain-notice">
No infrastructure data yet.
</div>
{% endif %}
</section>

<section id="samples">
<h2>Samples</h2>

{% assign samples = site.data.masq_infra.records | sort: "last_seen" | reverse %}
{% if samples.size > 0 %}
<table class="cg-table cg-samples-table">
  <thead>
    <tr>
      <th>First seen</th><th>Domain</th><th>Family</th><th>Class</th>
      <th>Lure</th><th>Chain</th><th>Conf.</th><th>Scan</th>
    </tr>
  </thead>
  <tbody>
    {% for rec in samples limit:20 %}
    <tr>
      <td class="muted">{{ rec.first_seen | date: "%Y-%m-%d" }}</td>
      <td class="mono">{{ rec.domain }}</td>
      <td><code>{{ rec.payload_family | default: "—" }}</code></td>
      <td><span class="cg-class-{{ rec.payload_class }}">{{ rec.payload_class }}</span></td>
      <td class="muted">{{ rec.lure_type | replace: "_"," " | default: "—" }}</td>
      <td>{% if rec.chain_observed %}
        <span title="Chain observed" style="color:#22c55e">✓</span>
        {% else %}
        <span title="Chain not observed in available URLScan data" style="color:var(--text-muted)">—</span>
        {% endif %}</td>
      <td class="mono">{{ rec.confidence }}</td>
      <td>{% if rec.urlscan_uuid %}
        <a href="https://urlscan.io/result/{{ rec.urlscan_uuid }}/" target="_blank" rel="noopener">↗</a>
        {% else %}—{% endif %}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}
<div class="cg-chain-notice">
No samples yet. Run the collection pipeline.
</div>
{% endif %}
</section>

<section id="chokepoints">
<h2>Detection Chokepoints</h2>
<p>Perfect visual impersonation neutralizes every user-facing trust signal. These chokepoints
survive it because they operate at the execution layer — after the user has already been
deceived and run the file.</p>

<div class="cg-rec">
  <div class="cg-rec-tier">
    <span class="cg-tier-badge cg-tier-t1" style="display:block;text-align:center;padding:.25rem .5rem;">TIER 1</span>
  </div>
  <div class="cg-rec-body">
    <strong>PE OriginalFilename mismatch (T1036.005)</strong>
    <p>Alert when a process OriginalFilename from PE version resource does not match its running
    filename. Adversaries rename existing malicious binaries — they rarely recompile with
    matching resources.</p>
<pre><code>detection:
  selection:
    Image|endswith:
      - '\7-Zip.exe'
      - '\VLC.exe'
      - '\DiscordSetup.exe'
      - '\NordVPN.exe'
      - '\ZoomInstaller.exe'
    CurrentDirectory|contains:
      - '\Downloads\'
      - '\AppData\Local\Temp\'
  filter_legit:
    OriginalFileName|contains:
      - '7-Zip'
      - 'VLC'
      - 'Discord'
      - 'NordVPN'
      - 'Zoom'
condition: selection and not filter_legit</code></pre>
  </div>
</div>

<div class="cg-rec">
  <div class="cg-rec-tier">
    <span class="cg-tier-badge cg-tier-t1" style="display:block;text-align:center;padding:.25rem .5rem;">TIER 1</span>
  </div>
  <div class="cg-rec-body">
    <strong>Signed binary executing from user download path</strong>
    <p>A signed binary running from Downloads is more anomalous than an unsigned one in managed
    environments. Legitimate signed software is deployed via package manager or IT tooling, not
    user download directories.</p>
<pre><code>detection:
  selection:
    ParentImage|contains:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
    Image|endswith:
      - '\setup.exe'
      - '\installer.exe'
      - '\install.exe'
    CurrentDirectory|contains: '\Downloads\'
    Signed: 'true'
condition: selection</code></pre>
  </div>
</div>

<div class="cg-rec">
  <div class="cg-rec-tier">
    <span class="cg-tier-badge" style="display:block;text-align:center;padding:.25rem .5rem;background:var(--bg-card);border:1px solid var(--border)">INFRA</span>
  </div>
  <div class="cg-rec-body">
    <strong>Favicon hash pivoting for infrastructure clustering</strong>
    <p>From one confirmed fake domain: fetch favicon, compute Murmur3 hash, query Shodan.
    Campaigns reusing the same stolen favicon across dozens of domains surface immediately.</p>
<pre><code>http.favicon.hash:-469815234
http.favicon.hash:991727625
http.favicon.hash:9732861
http.favicon.hash:-1899664115</code></pre>
  </div>
</div>
</section>

</div>

<script>
(function() {
  var links = document.querySelectorAll('.cg-sidenav a');
  var sections = Array.from(links).map(function(l) {
    return document.querySelector(l.getAttribute('href'));
  });
  function onScroll() {
    var scrollY = window.scrollY + 120;
    var current = sections[0];
    sections.forEach(function(s) {
      if (s && s.offsetTop <= scrollY) current = s;
    });
    links.forEach(function(l) {
      l.classList.toggle('active',
        l.getAttribute('href') === '#' + current.id);
    });
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
})();
</script>
