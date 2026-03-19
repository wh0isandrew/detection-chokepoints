---
layout: default
title: Software Impersonation Infrastructure
description: "How to fingerprint masquerading software infrastructure — domain patterns, favicon clusters, delivery chains, campaign clustering, and the detection chokepoints that survive perfect visual impersonation."
permalink: /trends/masq-infra/
---

<style>
/* ── Page layout ────────────────────────────────────────────────────────── */
.cg-page { max-width: 900px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }
.cg-page h1 { font-size: 1.6rem; font-weight: 700; color: var(--text); margin-bottom: .25rem; }
.cg-page h2 { font-size: 1.15rem; font-weight: 600; color: var(--text); margin: 2.5rem 0 .75rem; border-bottom: 1px solid var(--border); padding-bottom: .4rem; }
.cg-page h3 { font-size: 1rem; font-weight: 600; color: var(--text); margin: 1.5rem 0 .5rem; }
.cg-page p, .cg-page li { color: var(--text-muted); font-size: .9rem; line-height: 1.7; }
.cg-page a { color: var(--link); }
.cg-page strong { color: var(--text); }
.cg-page code { font-family: ui-monospace, monospace; font-size: .85rem; background: var(--bg-card); border: 1px solid var(--border); border-radius: 3px; padding: .1rem .3rem; color: var(--text); }
.cg-page pre { background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; overflow-x: auto; margin: .75rem 0 1.25rem; }
.cg-page pre code { background: none; border: none; padding: 0; font-size: .82rem; }
.cg-page hr { border: none; border-top: 1px solid var(--border); margin: 2rem 0; }
.cg-meta { color: var(--text-muted); font-size: .8rem; margin-bottom: 1.75rem; }

/* ── Stats row ──────────────────────────────────────────────────────────── */
.cg-stats { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1.25rem 0 2rem; }
.cg-stat  { flex: 1 1 140px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: .85rem 1rem; }
.cg-stat-val { font-size: 1.5rem; font-weight: 700; color: var(--text); font-family: ui-monospace, monospace; line-height: 1.2; }
.cg-stat-lbl { font-size: .72rem; color: var(--text-muted); margin-top: .2rem; text-transform: uppercase; letter-spacing: .04em; }

/* ── Framework chain map ────────────────────────────────────────────────── */
.cg-chain { display: flex; align-items: flex-start; gap: 0; flex-wrap: wrap; margin: 1.5rem 0 2rem; }
.cg-chain-stage {
  flex: 1 1 90px; min-width: 80px;
  border: 1px solid var(--border); border-radius: 6px;
  padding: .6rem .5rem; text-align: center; background: var(--bg-card);
  position: relative;
}
.cg-chain-stage + .cg-chain-stage { margin-left: -1px; border-radius: 0; }
.cg-chain-stage:first-child { border-radius: 6px 0 0 6px; }
.cg-chain-stage:last-child  { border-radius: 0 6px 6px 0; }
.cg-chain-stage--blind { border-top: 3px solid var(--border); }
.cg-chain-stage--t1    { border-top: 3px solid var(--high); }
.cg-chain-stage--t2    { border-top: 3px solid var(--accent); }
.cg-chain-stage--t3    { border-top: 3px solid var(--critical); }
.cg-chain-label { font-size: .72rem; font-weight: 600; color: var(--text); line-height: 1.3; display: block; }
.cg-chain-sub   { font-size: .62rem; color: var(--text-muted); margin-top: .25rem; display: block; }
.cg-tier-badge  { display: inline-block; font-size: .6rem; font-weight: 700; padding: .1rem .35rem; border-radius: 3px; margin-top: .35rem; letter-spacing: .03em; }
.cg-tier-blind  { background: var(--bg-input); color: var(--text-muted); }
.cg-tier-t1     { background: rgba(227,179,65,.15);  color: var(--high); }
.cg-tier-t2     { background: rgba(240,136,62,.15);  color: var(--accent); }
.cg-tier-t3     { background: rgba(218,54,51,.15);   color: var(--critical); }
.cg-chain-arrow {
  align-self: center; flex: 0 0 auto;
  color: var(--border); font-size: 1.2rem; padding: 0 .1rem; margin-top: -2px;
}

/* ── Callout boxes ──────────────────────────────────────────────────────── */
.cg-callout { border-radius: 6px; padding: .85rem 1rem; margin: .75rem 0; font-size: .875rem; border-left: 3px solid; }
.cg-callout--warn  { background: rgba(227,179,65,.08);  border-color: var(--high);     color: var(--text); }
.cg-callout--alert { background: rgba(218,54,51,.08);   border-color: var(--critical); color: var(--text); }
.cg-callout--info  { background: rgba(56,139,253,.08);  border-color: var(--low);      color: var(--text); }
.cg-callout--tip   { background: rgba(63,185,80,.08);   border-color: var(--medium);   color: var(--text); }
.cg-callout strong { color: var(--text); }

/* ── Tables ─────────────────────────────────────────────────────────────── */
.cg-table { width: 100%; border-collapse: collapse; font-size: .85rem; margin: .75rem 0 1.5rem; }
.cg-table th { text-align: left; color: var(--text-muted); font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; border-bottom: 1px solid var(--border); padding: .4rem .6rem; font-weight: 600; }
.cg-table td { padding: .45rem .6rem; border-bottom: 1px solid var(--border); color: var(--text); font-size: .85rem; }
.cg-table tr:last-child td { border-bottom: none; }
.cg-table td.mono { font-family: ui-monospace, monospace; font-size: .82rem; }
.cg-table td.muted { color: var(--text-muted); font-family: inherit; }

/* ── Recommendation list ────────────────────────────────────────────────── */
.cg-rec { display: flex; gap: .75rem; align-items: flex-start; padding: .6rem 0; border-bottom: 1px solid var(--border); }
.cg-rec:last-child { border-bottom: none; }
.cg-rec-tier { flex: 0 0 62px; }
.cg-rec-body { flex: 1; font-size: .875rem; color: var(--text-muted); }
.cg-rec-body strong { color: var(--text); display: block; margin-bottom: .2rem; }

/* ── Favicon hash example ───────────────────────────────────────────────── */
.cg-fav-demo {
  display: flex; gap: 1rem; flex-wrap: wrap;
  background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px;
  padding: 1rem 1.25rem; margin: 1rem 0 1.5rem; align-items: flex-start;
}
.cg-fav-hash {
  font-family: ui-monospace, monospace; font-size: .78rem; color: var(--text-muted);
  background: var(--bg-input); border: 1px solid var(--border); border-radius: 4px;
  padding: .5rem .75rem; flex: 1 1 280px; word-break: break-all;
}
.cg-fav-hash strong { color: var(--accent); display: block; font-size: .65rem; letter-spacing: .05em; text-transform: uppercase; margin-bottom: .35rem; }

/* ── Delivery chain diagram ──────────────────────────────────────────────── */
.cg-delivery { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0 1.5rem; font-family: ui-monospace, monospace; font-size: .82rem; color: var(--text-muted); line-height: 2; }
.cg-delivery span.node { color: var(--text); font-weight: 600; }
.cg-delivery span.label { color: var(--accent); font-size: .75rem; }
</style>

<div class="cg-page">

<h1>Software Impersonation Infrastructure</h1>
<p class="cg-meta">
  Coverage: T1036 Masquerading · T1583.001 Domains · T1608.001 Upload Malware
  &nbsp;·&nbsp; Updated: {{ site.data.masq_infra.meta.last_updated }}{% if site.data.masq_infra.meta.sample_size > 0 %} &nbsp;·&nbsp; n={{ site.data.masq_infra.meta.sample_size }}, {{ site.data.masq_infra.meta.lookback_days }}-day lookback{% endif %}
</p>

<div class="cg-callout cg-callout--info">
  <strong>Page focus:</strong> Software impersonation is always the lure. A user must believe they are downloading legitimate software — the voluntary execution is required for the attack to succeed. This constraint makes the infrastructure fingerprint consistent and detectable. This page documents how to identify, cluster, and hunt that infrastructure, and what payloads it delivers.
</div>

<!-- ── Page anchor nav ───────────────────────────────────────────────── -->
<nav class="page-anchors" aria-label="Page sections">
  <ul>
    <li><a href="#arrival">Arrival</a></li>
    <li><a href="#fingerprinting">Fingerprinting</a></li>
    <li><a href="#lure-payload">Lure→Payload</a></li>
    <li><a href="#campaigns">Campaigns</a></li>
    <li><a href="#chokepoints">Chokepoints</a></li>
    <li><a href="#samples">Samples</a></li>
  </ul>
</nav>

<!-- ── Stats ─────────────────────────────────────────────────────────── -->
<div class="cg-stats">
  <div class="cg-stat">
    <div class="cg-stat-val">{% if site.data.masq_infra.stats.tls_lets_encrypt_pct > 0 %}{{ site.data.masq_infra.stats.tls_lets_encrypt_pct }}%{% else %}99%+{% endif %}</div>
    <div class="cg-stat-lbl">Sites with Let's Encrypt TLS</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{% if site.data.masq_infra.stats.domain_to_resolution_hours_median > 0 %}{{ site.data.masq_infra.stats.domain_to_resolution_hours_median }}h{% else %}&lt;48h{% endif %}</div>
    <div class="cg-stat-lbl">Cert issuance → live domain (median)</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">{% if site.data.masq_infra.stats.favicon_clusters_found > 0 %}{{ site.data.masq_infra.stats.favicon_clusters_found }}{% else %}—{% endif %}</div>
    <div class="cg-stat-lbl">Brand favicon clusters found (Shodan)</div>
  </div>
  <div class="cg-stat">
    <div class="cg-stat-val">T1036.005</div>
    <div class="cg-stat-lbl">PE OriginalFilename mismatch — primary chokepoint</div>
  </div>
</div>

<!-- ── How Users Arrive ───────────────────────────────────────────────── -->
<h2 id="arrival">How Users Arrive: Traffic Sources</h2>
<p>Understanding how users reach lure pages determines which detection layer can intercept them. The same fake download page may be delivered via four distinct vectors, each with different detection surface.</p>

<table class="cg-table">
  <thead>
    <tr><th>Vector</th><th>Mechanism</th><th>Domain pattern</th><th>Detection surface</th></tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>combosquat</strong></td>
      <td class="muted">Brand name + action word in domain; ranks well for "download X free" queries</td>
      <td class="mono">7zip-download.com · get-vlc.net</td>
      <td class="muted">DNS / crt.sh monitoring for brand + action-word combos</td>
    </tr>
    <tr>
      <td><strong>typosquat</strong></td>
      <td class="muted">User mistyped URL or clicked near-miss from autocomplete</td>
      <td class="mono">7-z1p.org · vIc-media.org</td>
      <td class="muted">Unicode normalization check; edit-distance alerting on cert transparency</td>
    </tr>
    <tr>
      <td><strong>seo_bait</strong></td>
      <td class="muted">Brand buried in longer domain string; SEO-optimised content</td>
      <td class="mono">free-discord-nitro24.top · best7zipalternative.click</td>
      <td class="muted">URLScan / passive DNS monitoring for brand-substring domains with generic TLDs</td>
    </tr>
    <tr>
      <td><strong>redirected</strong></td>
      <td class="muted">Malvertising via Google/Bing Ads; submitted URL is ad-tracker, landing is lure</td>
      <td class="muted">Landing domain differs from submitted URL (ad tracking redirect)</td>
      <td class="muted">Browser proxy logs; URLScan task.url vs page.url mismatch</td>
    </tr>
  </tbody>
</table>

{% if site.data.masq_infra.traffic_sources.size > 0 %}
<details>
  <summary>Show: Observed Traffic Source Distribution</summary>
<h3>Observed Traffic Source Distribution</h3>
<table class="cg-table">
  <thead>
    <tr><th>Source</th><th>Domains</th><th>Share</th></tr>
  </thead>
  <tbody>
    {% for src in site.data.masq_infra.traffic_sources %}
    <tr>
      <td>{{ src.source }}</td>
      <td>{{ src.count }}</td>
      <td class="muted">{{ src.pct }}%</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
</details>
{% endif %}

<!-- ── The Lure ───────────────────────────────────────────────────────── -->
<h2>The Lure</h2>
<p>Software impersonation is uniquely suited to drive-by malware delivery because the user must voluntarily execute the payload. That requirement means the attacker must maintain the illusion long enough for the user to click through a download prompt and run a file. No other lure type — phishing pages, document macros, browser exploits — imposes the same constraint. The result is a consistent infrastructure pattern: a convincing download page, a real-looking binary, and an execution moment the attacker can count on.</p>

<p>Other lure types exist but use different infrastructure patterns and are out of scope here. Document/macro lures and phishing pages don't need the download-page illusion. This page covers only software-impersonation download infrastructure.</p>

<h3>Lure Taxonomy</h3>
<details>
  <summary>Show: Lure Taxonomy (7 categories)</summary>
<table class="cg-table">
  <thead>
    <tr><th>Category</th><th>Targets</th><th>Typical payload</th></tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>fake_software</strong></td>
      <td class="muted">7-Zip, WinRAR, VLC, Notepad++, Audacity, GIMP, LibreOffice</td>
      <td class="muted">Lumma, Vidar, RedLine, StealC — general-purpose infostealers</td>
    </tr>
    <tr>
      <td><strong>fake_ai_tool</strong></td>
      <td class="muted">ChatGPT, Midjourney, Claude, Gemini desktop apps</td>
      <td class="muted">Lumma, AMOS (macOS) — credential + crypto theft focus</td>
    </tr>
    <tr>
      <td><strong>crypto_wallet</strong></td>
      <td class="muted">MetaMask, Ledger Live, Exodus, Phantom, Electrum</td>
      <td class="muted">Atomic Stealer, MetaStealer, Clipbanker — wallet seed theft</td>
    </tr>
    <tr>
      <td><strong>vpn_tool</strong></td>
      <td class="muted">NordVPN, ProtonVPN, Mullvad, ExpressVPN</td>
      <td class="muted">AsyncRAT, Remcos — persistent access; privacy-seeking targets</td>
    </tr>
    <tr>
      <td><strong>remote_work</strong></td>
      <td class="muted">Zoom, Slack, Teams, Webex</td>
      <td class="muted">CobaltStrike, AsyncRAT — corporate targeting</td>
    </tr>
    <tr>
      <td><strong>fake_update</strong></td>
      <td class="muted">Browser update prompts, Windows update lures</td>
      <td class="muted">Varied; often paired with ClickFix delivery chains</td>
    </tr>
    <tr>
      <td><strong>game_crack</strong></td>
      <td class="muted">Steam, Roblox, Minecraft — cheat tools, "free" versions</td>
      <td class="muted">RedLine, Raccoon — credential theft from younger user base</td>
    </tr>
  </tbody>
</table>
</details>

{% if site.data.masq_infra.lure_types.size > 0 %}
<details>
  <summary>Show: Observed Lure Types ({{ site.data.masq_infra.meta.lookback_days }}-day window)</summary>
<h3>Observed Lure Types ({{ site.data.masq_infra.meta.lookback_days }}-day window)</h3>
<table class="cg-table">
  <thead>
    <tr><th>Category</th><th>Domains</th><th>Share</th></tr>
  </thead>
  <tbody>
    {% for lure in site.data.masq_infra.lure_types %}
    <tr>
      <td>{{ lure.tag | replace: "_", " " }}</td>
      <td>{{ lure.count }}</td>
      <td class="muted">{{ lure.pct }}%</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
</details>
{% endif %}

<!-- ── Infrastructure Fingerprinting ─────────────────────────────────── -->
<h2 id="fingerprinting">Infrastructure Fingerprinting</h2>
<p>Because the attacker's operational constraints don't change — fast deployment, low cost, abuse-resistant hosting — the infrastructure patterns are remarkably consistent across campaigns and operators. These signals survive tool rotation and can be queried proactively.</p>

<!-- 3a. Domain naming patterns -->
<h3>Domain Naming Patterns</h3>
<p>Three naming strategies dominate. Combosquatting (brand + action word) is the most common because it satisfies the user's search intent — the extra keyword is not a mistake, it's SEO strategy.</p>

<table class="cg-table">
  <thead>
    <tr><th>Strategy</th><th>Example (target: 7-zip.org)</th><th>Detection angle</th></tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Typosquatting</strong></td>
      <td class="mono">7-z1p.org · 7ziip.org · 7-zip.net</td>
      <td class="muted">crt.sh substring query; edit-distance ≤ 2 from official domain</td>
    </tr>
    <tr>
      <td><strong>Combosquatting</strong></td>
      <td class="mono">7zip-download.com · get-7zip.org · 7zip-free.net</td>
      <td class="muted">Brand + {download, get, free, install, setup, official, latest} pattern</td>
    </tr>
    <tr>
      <td><strong>Homoglyph substitution</strong></td>
      <td class="mono">7‑zip.org (en-dash) · vlc-mediа.org (Cyrillic а)</td>
      <td class="muted">Unicode normalization check — visually identical but distinct bytes</td>
    </tr>
  </tbody>
</table>

{% if site.data.masq_infra.domain_patterns.size > 0 %}
<details>
  <summary>Show: Observed Naming Patterns (live data)</summary>
<h3>Observed Naming Patterns (live data)</h3>
<p>Recurring structural skeletons across collected samples. <code>{brand}</code> = brand name substituted; <code>{N}</code> = digit sequence.</p>
<table class="cg-table">
  <thead>
    <tr><th>Pattern</th><th>Count</th><th>Example</th></tr>
  </thead>
  <tbody>
    {% for pat in site.data.masq_infra.domain_patterns %}
    <tr>
      <td class="mono">{{ pat.pattern }}</td>
      <td>{{ pat.count }}</td>
      <td class="mono muted">{{ pat.example }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>

<p><strong>URLScan hunting query:</strong></p>
<pre><code>page.domain:*7-zip*download* AND date:&gt;now-30d
page.domain:*vlc*install* AND date:&gt;now-30d</code></pre>
</details>
{% endif %}

<!-- 3b. TLS / Certificate signals -->
<h3>TLS &amp; Certificate Signals</h3>
<p>Let's Encrypt certificates appear on effectively all active delivery sites. The HTTPS padlock no longer signals trust — it signals only that TLS is configured, which is free and automated. Certificate transparency gives defenders a detection window: new impersonation infrastructure almost always acquires a certificate within hours of domain registration, before the site is weaponized or before users encounter it.</p>

<p><strong>crt.sh monitoring query:</strong></p>
<pre><code># New certificates containing brand name — run on a schedule
https://crt.sh/?q=%25.7-zip.%25&amp;output=json
https://crt.sh/?q=%25discord%25download%25&amp;output=json

# CertStream filter (Python)
# Alert: domain matches /(7-?zip|winrar|vlc|discord|telegram)/i
#        AND issuer == "Let's Encrypt"
#        AND not_before within last 48h</code></pre>

<!-- 3c. Hosting -->
<h3>Hosting &amp; ASN Clustering</h3>
<p>Adversaries prefer hosting where domain reputation is initially clean and abuse reports take days to process. Cloudflare's infrastructure is particularly common — not because of Cloudflare abuse specifically, but because legitimate sites use Cloudflare, so <code>pages.dev</code> and Cloudflare-proxied domains inherit clean reputation signals that bypass many filters.</p>

{% if site.data.masq_infra.meta.sample_size > 0 %}
<table class="cg-table">
  <thead>
    <tr><th>Provider / ASN</th><th>Domains</th><th>Share</th></tr>
  </thead>
  <tbody>
    {% for provider in site.data.masq_infra.hosting_providers %}
    <tr>
      <td>{{ provider.name }}</td>
      <td>{{ provider.count }}</td>
      <td class="muted">{{ provider.pct }}%</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- 3d. Favicon hash pivoting -->
<h3>Favicon Hash Pivoting</h3>
<p>Favicons are trivially stolen — a single HTTP request retrieves the bytes that brand a fake site with a recognizable logo. What makes this useful for defenders: <strong>the same bytes hash to the same value across all infrastructure reusing that favicon</strong>. Shodan indexes HTTP response favicon hashes, enabling bulk infrastructure discovery from a single known-malicious domain.</p>

<div class="cg-fav-demo">
  <div class="cg-fav-hash">
    <strong>Shodan query format</strong>
    http.favicon.hash:&lt;murmur3_int32&gt;
  </div>
  <div class="cg-fav-hash">
    <strong>Censys query format</strong>
    services.http.response.favicons.md5_hash:&lt;md5hex&gt;
  </div>
  <div class="cg-fav-hash">
    <strong>Compute hash locally (Python)</strong>
    import mmh3, requests, base64<br>
    r = requests.get('https://target.com/favicon.ico')<br>
    h = mmh3.hash(base64.encodebytes(r.content))<br>
    print(h)  # paste into Shodan
  </div>
</div>

{% if site.data.masq_infra.favicon_clusters.size > 0 %}
<h3>Active Favicon Clusters (Shodan)</h3>
<table class="cg-table">
  <thead>
    <tr><th>Brand</th><th>Hash</th><th>Impersonator hosts</th><th>Sample host</th></tr>
  </thead>
  <tbody>
    {% for cluster in site.data.masq_infra.favicon_clusters %}
    <tr>
      <td>{{ cluster.brand }}</td>
      <td class="mono">{{ cluster.hash }}</td>
      <td>{{ cluster.count }}</td>
      <td class="mono muted">{{ cluster.sample_hosts | first }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ── IOK Rules ───────────────────────────────────────────────────────── -->
<h2>IOK Rules — Lure Page Fingerprinting</h2>
<p>Indicators of Kit (IOK) rules identify lure pages by their structural patterns — URL shape, HTML content, and TLS signals — before a binary is ever downloaded. These rules can be applied to URLScan results, proxy logs, or crawl pipelines.</p>

<div class="iok-tabs">
  <input type="radio" name="iok-tab" id="iok-tab-1" checked>
  <input type="radio" name="iok-tab" id="iok-tab-2">
  <input type="radio" name="iok-tab" id="iok-tab-3">
  <div class="iok-tab-bar" role="tablist">
    <label for="iok-tab-1" role="tab">Generic download lure</label>
    <label for="iok-tab-2" role="tab">Crypto wallet</label>
    <label for="iok-tab-3" role="tab">Fast-deploy typosquat</label>
  </div>
  <div class="iok-tab-panel iok-panel-1">
<pre><code># IOK rule: fake software download page (generic)
rule: fake_software_download_lure
meta:
  description: Masquerading software download page with brand impersonation
  mitre: [T1036, T1583.001, T1608.001]
  author: detection-chokepoints
indicators:
  url:
    - pattern: "(7zip|winrar|vlc|notepad|discord|telegram|chatgpt|zoom|nordvpn).*(download|install|setup|free|get)"
    - pattern: "(get|download|free)-(7zip|vlc|discord|telegram|chatgpt)\\.(com|net|org|top|click)"
  html:
    - pattern: "&lt;title&gt;.*(?:download|free|official).*(?:7-?zip|winrar|vlc|discord|telegram).*&lt;/title&gt;"
    - pattern: "(?:btn-download|download-btn|dl-button|downloadNow)"
  tls:
    - issuer_cn_contains: "Let's Encrypt"</code></pre>
  </div>
  <div class="iok-tab-panel iok-panel-2">
<pre><code># IOK rule: crypto wallet impersonation
rule: crypto_wallet_lure
meta:
  description: Fake crypto wallet installer — wallet seed theft
  mitre: [T1036, T1583.001]
indicators:
  url:
    - pattern: "(metamask|ledger|exodus|phantom|electrum).*(download|install|desktop|app|wallet)"
    - pattern: "(get|install|official)-(metamask|ledger|exodus|phantom)\\."
  html:
    - pattern: "&lt;title&gt;.*(?:metamask|ledger live|exodus|phantom).*(?:download|wallet|app).*&lt;/title&gt;"
    - pattern: "(?:connect-wallet|wallet-connect|seed-phrase)"
  tls:
    - not_before_age_hours_max: 72</code></pre>
  </div>
  <div class="iok-tab-panel iok-panel-3">
<pre><code># IOK rule: fast-deployed brand typosquat (infrastructure signal)
rule: fast_deploy_brand_typosquat
meta:
  description: Brand-name domain with Let's Encrypt cert issued &lt;48h ago
  note: High-signal for newly weaponized infrastructure before URLScan coverage
indicators:
  tls:
    - issuer_cn_contains: "Let's Encrypt"
    - not_before_age_hours_max: 48
  url:
    - pattern: "(7-?zip|winrar|vlc|notepad|discord|telegram|chatgpt|zoom|nordvpn)"
    - tld_in: [".top", ".click", ".xyz", ".pw", ".cam", ".life", ".shop"]</code></pre>
  </div>
</div>

<!-- ── Delivery Chain ──────────────────────────────────────────────────── -->
<h2>Delivery Chain</h2>
<p>Where does the payload actually come from? The binary is often <strong>not</strong> hosted on the same domain as the lure page. Single-domain blocklisting misses the binary when it's staged on a CDN or separate bulletproof host.</p>

<div class="cg-chain" role="list" aria-label="Victim arrival path">
  <div class="cg-chain-stage cg-chain-stage--blind" role="listitem">
    <span class="cg-chain-label">SEO / ad delivers user</span>
    <span class="cg-chain-sub">Search result or malvertising redirect</span>
    <span class="cg-tier-badge cg-tier-blind">NOT DETECTABLE</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--blind" role="listitem">
    <span class="cg-chain-label">Visual trust satisfied</span>
    <span class="cg-chain-sub">TLS padlock, stolen favicon, cloned UI</span>
    <span class="cg-tier-badge cg-tier-blind">PRE-EXEC</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--blind" role="listitem">
    <span class="cg-chain-label">File lands</span>
    <span class="cg-chain-sub">Binary in %Downloads%; MotW applied by browser</span>
    <span class="cg-tier-badge cg-tier-blind">PRE-EXEC</span>
  </div>
</div>

<p>The entire arrival path generates <strong>no endpoint process-creation events</strong> — the browser performs an HTTP GET and the OS writes the file to disk. Defender chokepoints here are infrastructure-level: certificate transparency monitoring for brand-substring domains, URLScan/passive-DNS alerting on new registrations, and favicon hash pivoting to surface related infrastructure before users encounter it. The Mark of the Web flag is applied by Windows at file landing; it gates SmartScreen and UAC prompts, but is not a detection signal in EDR telemetry.</p>

{% if site.data.masq_infra.payload_hosting.offhost_count > 0 %}
<p>In the current dataset: <strong>{{ site.data.masq_infra.payload_hosting.offhost_count }} payloads ({{ site.data.masq_infra.payload_hosting.offhost_pct }}%)</strong> are hosted on a different domain than the lure page.</p>

{% if site.data.masq_infra.payload_hosting.top_payload_hosts.size > 0 %}
<h3>Top Off-Domain Payload Hosts</h3>
<table class="cg-table">
  <thead>
    <tr><th>Host</th><th>Payloads</th><th>Share of off-host</th></tr>
  </thead>
  <tbody>
    {% for host in site.data.masq_infra.payload_hosting.top_payload_hosts %}
    <tr>
      <td class="mono">{{ host.name }}</td>
      <td>{{ host.count }}</td>
      <td class="muted">{{ host.pct }}%</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}
{% endif %}

{% if site.data.masq_infra.delivery_chains.size > 0 %}
<h3>Sample Delivery Chains</h3>
<table class="cg-table">
  <thead>
    <tr><th>Lure domain</th><th>Payload host</th><th>Off-host?</th><th>File type</th><th>Family</th></tr>
  </thead>
  <tbody>
    {% for chain in site.data.masq_infra.delivery_chains %}
    <tr>
      <td class="mono">{{ chain.lure_domain }}</td>
      <td class="mono">{{ chain.payload_host }}</td>
      <td class="muted">{% if chain.offhost %}yes{% else %}same domain{% endif %}</td>
      <td class="muted">{{ chain.file_type | default: "—" }}</td>
      <td>{{ chain.malware_family | default: "—" }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ── Lure → Payload Analysis ────────────────────────────────────────── -->
<h2 id="lure-payload">Lure→Payload Analysis</h2>
{% if site.data.masq_infra.lure_payload_matrix.size > 0 %}
<table class="cg-table">
  <thead>
    <tr><th>Lure Type</th><th>Domains</th><th>Top Payload Families</th></tr>
  </thead>
  <tbody>
    {% for row in site.data.masq_infra.lure_payload_matrix %}
    <tr>
      <td>{{ row.lure_type | replace: "_", " " }}</td>
      <td>{{ row.domain_count }}</td>
      <td>
        {% if row.top_families.size > 0 %}
          {% for fam in row.top_families %}<code class="cg-family-tag">{{ fam }}</code> {% endfor %}
        {% else %}
          <span class="muted">— enrichment pending</span>
        {% endif %}
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}
<p class="muted">No lure–payload correlations yet — run the enrichment pipeline to populate.</p>
{% endif %}

<!-- ── Active Campaigns ───────────────────────────────────────────────── -->
<h2 id="campaigns">Active Campaigns</h2>
{% if site.data.masq_infra.campaigns.size > 0 %}
{% assign sorted_camps = site.data.masq_infra.campaigns | sort: "domain_count" | reverse %}
{% assign gen_ts = site.data.masq_infra.generated_at | date: "%s" | plus: 0 %}
<div class="cg-campaign-list">
  {% for camp in sorted_camps limit:10 %}
  {% assign last_ts = camp.last_seen | date: "%s" | plus: 0 %}
  {% assign age_days = gen_ts | minus: last_ts | divided_by: 86400 %}
  <div class="cg-campaign-card">
    <div class="cg-campaign-header">
      <span class="cg-campaign-id mono">{{ camp.id }}</span>
      {% if age_days <= 7 %}<span class="cg-badge cg-badge--active">ACTIVE</span>{% endif %}
      <span class="cg-campaign-domains">{{ camp.domain_count }} domain{% if camp.domain_count != 1 %}s{% endif %}</span>
    </div>
    <div class="cg-campaign-meta">
      {% if camp.lure_type %}<span class="cg-meta-item"><span class="muted">lure:</span> {{ camp.lure_type | replace: "_", " " }}</span>{% endif %}
      {% if camp.brand %}<span class="cg-meta-item"><span class="muted">brand:</span> {{ camp.brand }}</span>{% endif %}
      <span class="cg-meta-item"><span class="muted">asn:</span> {{ camp.asn }}</span>
      {% if camp.countries.size > 0 %}<span class="cg-meta-item"><span class="muted">countries:</span> {{ camp.countries | join: ", " }}</span>{% endif %}
      <span class="cg-meta-item"><span class="muted">first seen:</span> {{ camp.first_seen }}</span>
      <span class="cg-meta-item"><span class="muted">last seen:</span> {{ camp.last_seen }}</span>
      {% if camp.favicon_hash %}<span class="cg-meta-item"><span class="muted">favicon:</span> <a href="https://www.shodan.io/search?query=http.favicon.hash%3A{{ camp.favicon_hash }}" target="_blank" rel="noopener" class="mono">{{ camp.favicon_hash }}</a></span>{% endif %}
    </div>
    <div class="cg-campaign-families">
      {% if camp.families.size > 0 %}
        {% for fam in camp.families %}<code class="cg-family-tag">{{ fam }}</code> {% endfor %}
      {% else %}
        <span class="muted">payload: enrichment pending</span>
      {% endif %}
    </div>
    {% if camp.domains.size > 0 %}
    <details>
      <summary>Show {{ camp.domains.size }} domain{% if camp.domains.size != 1 %}s{% endif %}</summary>
      <ul class="cg-domain-list">
        {% for d in camp.domains %}<li class="mono">{{ d }}</li>{% endfor %}
      </ul>
    </details>
    {% endif %}
  </div>
  {% endfor %}
</div>
{% else %}
<p class="muted">No campaign clusters identified yet — run the enrichment pipeline to populate.</p>
{% endif %}

<!-- ── Detection Chokepoints ──────────────────────────────────────────── -->
<h2 id="chokepoints">Detection Chokepoints</h2>
<p>Perfect visual impersonation neutralizes every user-facing trust signal. These are the stages where adversaries run out of room to maintain the illusion, with concrete rule examples and matched payload observations.</p>

<div class="cg-chain" role="list" aria-label="Post-execution detection chain">
  <div class="cg-chain-stage cg-chain-stage--t1" role="listitem">
    <span class="cg-chain-label">User execution</span>
    <span class="cg-chain-sub">Installer spawns from Downloads / Temp</span>
    <span class="cg-tier-badge cg-tier-t1">TIER 1</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t1" role="listitem">
    <span class="cg-chain-label">PE metadata exposed</span>
    <span class="cg-chain-sub">OriginalFilename ≠ displayed name</span>
    <span class="cg-tier-badge cg-tier-t1">TIER 1</span>
  </div>
  <span class="cg-chain-arrow" aria-hidden="true">›</span>
  <div class="cg-chain-stage cg-chain-stage--t2" role="listitem">
    <span class="cg-chain-label">C2 callback</span>
    <span class="cg-chain-sub">Payload fetches stage 2 or phones home</span>
    <span class="cg-tier-badge cg-tier-t2">TIER 2</span>
  </div>
</div>

<p>Execution is where the impersonation runs out of room. <strong>PE OriginalFilename mismatch (T1036.005) is the primary Tier 1 chokepoint</strong> — adversaries rename existing malicious binaries, but rarely recompile with matching version resources. Every software-impersonation payload that runs from a user download path will generate this signal if process-creation telemetry is collected. The Tier 1 signals are unavoidable regardless of which brand is impersonated or how the lure page is styled. The C2 callback is Tier 2: dependent on knowing or behaviorally recognising the staging infrastructure, but catches the payload at the network boundary after the file executes.</p>

<div class="cg-rec">
  <div class="cg-rec-tier"><span class="cg-tier-badge cg-tier-t1" style="display:block;text-align:center;padding:.25rem .5rem;">TIER 1</span></div>
  <div class="cg-rec-body">
    <strong>PE OriginalFilename mismatch at execution (T1036.005)</strong>
    <p>Alert when a process's <code>OriginalFilename</code> (from PE version resource) does not match its running filename. Adversaries rename existing malicious binaries — they rarely recompile with matching resources. This is one of the most reliable signals in the framework.</p>
<pre><code># Sigma — PE OriginalFilename mismatch from download path
detection:
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
condition: selection and not filter_legit

# Matched example: 7zip-download.com served 7-Zip.exe
#   OriginalFileName: LummaC.exe  → ALERT</code></pre>
  </div>
</div>

<div class="cg-rec">
  <div class="cg-rec-tier"><span class="cg-tier-badge cg-tier-t1" style="display:block;text-align:center;padding:.25rem .5rem;">TIER 1</span></div>
  <div class="cg-rec-body">
    <strong>Signed binary executing from user download path</strong>
    <p>Adversaries increasingly code-sign malware to bypass reputation checks. A <em>signed</em> binary running from <code>%Downloads%</code> is more anomalous than an unsigned one in managed environments — legitimate signed software is deployed via package manager or IT tooling, not user download directories.</p>
<pre><code># Sigma — signed binary spawned by browser from Downloads
detection:
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
  <div class="cg-rec-tier"><span class="cg-tier-badge cg-tier-t2" style="display:block;text-align:center;padding:.25rem .5rem;">TIER 2</span></div>
  <div class="cg-rec-body">
    <strong>Certificate transparency monitoring for brand typosquats</strong>
    <p>Subscribe to crt.sh or CertStream and alert on certificates issued for domains containing monitored brand names. New impersonation infrastructure acquires a TLS certificate within hours of registration — cert transparency gives you a detection window before users encounter the site.</p>
<pre><code># CertStream monitor (Python — certstream library)
# Alert on: domain matches brand pattern AND Let's Encrypt AND issued &lt;48h

WATCH_BRANDS = re.compile(
    r'(7-?zip|winrar|vlc|notepad|discord|telegram|chatgpt|zoom|nordvpn)',
    re.IGNORECASE
)
def on_cert(message, context):
    domains = message['data']['leaf_cert']['all_domains']
    for domain in domains:
        if WATCH_BRANDS.search(domain):
            alert(domain, message['data']['leaf_cert']['subject']['CN'])</code></pre>
  </div>
</div>

<div class="cg-rec">
  <div class="cg-rec-tier"><span class="cg-tier-badge cg-tier-t2" style="display:block;text-align:center;padding:.25rem .5rem;">INFRA</span></div>
  <div class="cg-rec-body">
    <strong>Favicon hash pivoting for infrastructure clustering</strong>
    <p>From one confirmed fake domain: fetch favicon → compute Murmur3 hash → query Shodan. Campaigns reusing the same stolen favicon across dozens of domains will surface immediately. Blocklist the entire cluster, not just the single known URL.</p>
<pre><code># Known impersonator favicon hashes (Shodan)
http.favicon.hash:-469815234   # Telegram favicon on non-Telegram infrastructure
http.favicon.hash:991727625    # 7-Zip favicon
http.favicon.hash:9732861      # VLC favicon
http.favicon.hash:-1899664115  # Notepad++ favicon</code></pre>
  </div>
</div>

<!-- ── Recent Samples ─────────────────────────────────────────────────── -->
{% if site.data.masq_infra.meta.sample_size > 0 and site.data.masq_infra.recent_samples.size > 0 %}
<h2 id="samples">Recent Samples</h2>
<table class="cg-table cg-samples-table">
  <thead>
    <tr><th>First seen</th><th>Domain</th><th>Lure type</th><th>Traffic source</th><th>Payload host</th><th>Family</th><th>URLScan</th></tr>
  </thead>
  <tbody>
    {% for sample in site.data.masq_infra.recent_samples limit:10 %}
    <tr>
      <td class="muted">{{ sample.first_seen | date: "%Y-%m-%d" }}</td>
      <td class="mono">{{ sample.domain }}</td>
      <td>{{ sample.lure_type | replace: "_", " " }}</td>
      <td class="muted">{{ sample.traffic_source | default: "—" }}</td>
      <td class="mono muted">{{ sample.payload_host | default: "—" }}</td>
      <td>{{ sample.malware_family | default: "—" }}</td>
      <td><a href="https://urlscan.io/search/#page.domain:{{ sample.domain }}" target="_blank" rel="noopener" class="muted" style="font-size:.78rem">search</a></td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% assign overflow_count = site.data.masq_infra.recent_samples.size | minus: 10 %}
{% if overflow_count > 0 %}
<details>
  <summary>Show {{ overflow_count }} more samples</summary>
  <table class="cg-table cg-samples-table">
    <thead>
      <tr><th>First seen</th><th>Domain</th><th>Lure type</th><th>Traffic source</th><th>Payload host</th><th>Family</th><th>URLScan</th></tr>
    </thead>
    <tbody>
      {% for sample in site.data.masq_infra.recent_samples offset:10 %}
      <tr>
        <td class="muted">{{ sample.first_seen | date: "%Y-%m-%d" }}</td>
        <td class="mono">{{ sample.domain }}</td>
        <td>{{ sample.lure_type | replace: "_", " " }}</td>
        <td class="muted">{{ sample.traffic_source | default: "—" }}</td>
        <td class="mono muted">{{ sample.payload_host | default: "—" }}</td>
        <td>{{ sample.malware_family | default: "—" }}</td>
        <td><a href="https://urlscan.io/search/#page.domain:{{ sample.domain }}" target="_blank" rel="noopener" class="muted" style="font-size:.78rem">search</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</details>
{% endif %}
{% endif %}
<script>
(function () {
  var tables = document.querySelectorAll('.cg-samples-table');
  tables.forEach(function (table) {
    var rows = Array.from(table.querySelectorAll('tbody tr'));
    if (!rows.length) return;
    var headers = Array.from(table.querySelectorAll('thead th'));
    headers.forEach(function (th, colIdx) {
      var label = th.textContent.trim().toLowerCase();
      if (label !== 'payload host' && label !== 'family') return;
      var emptyCount = rows.filter(function (row) {
        var cell = row.cells[colIdx];
        var text = cell ? cell.textContent.trim() : '';
        return !text || text === '—';
      }).length;
      if (emptyCount / rows.length > 0.8) {
        th.style.display = 'none';
        rows.forEach(function (row) {
          if (row.cells[colIdx]) row.cells[colIdx].style.display = 'none';
        });
      }
    });
  });
})();
</script>

<!-- ── Infrastructure Charts ────────────────────────────────────────────── -->
<style>
.cg-chart-wrap  { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1rem .5rem; margin: 1rem 0 1.75rem; overflow-x: auto; }
.cg-chart-title { font-size: .75rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: .05em; margin-bottom: .5rem; }
canvas { max-width: 100%; }
</style>

<!-- ── Chart 1 — Lure Types ──────────────────────────────────────────── -->
<h2>Crypto Wallets Lead Identified Lure Categories</h2>
<p>Half of sampled domains remain unclassified pending content analysis; among those identified, crypto wallet impersonation (22.8%) dominates — consistent with seed-phrase theft campaigns targeting MetaMask, Ledger, and Exodus users. Remote work tools (9.2%) and fake AI tools (5.6%) follow. The unclassified share will shrink as the enrichment pipeline processes more samples.</p>

<div class="cg-chart-wrap">
  <div class="cg-chart-title">Lure type share — {{ site.data.masq_infra.meta.lookback_days }}-day sample, n={{ site.data.masq_infra.meta.sample_size }}</div>
  <canvas id="chartLureTypes" height="220"></canvas>
</div>

<!-- ── Chart 2 — Traffic Sources ─────────────────────────────────────── -->
<h2>SEO Bait Outnumbers Typosquatting Two-to-One</h2>
<p>Over half of masquerading infrastructure (54.4%) uses SEO-optimised keyword-stuffed domains targeting "download X free" queries — the extra keywords are not a mistake, they are SEO strategy. Typosquatting (32.8%) relies on user entry error or autocomplete near-misses. Together these two vectors account for 87%+ of lure-page arrivals and produce domain names that are fingerprintable at cert issuance via crt.sh and passive DNS.</p>

<div class="cg-chart-wrap">
  <div class="cg-chart-title">Traffic source share — {{ site.data.masq_infra.meta.lookback_days }}-day sample</div>
  <canvas id="chartTrafficSources" height="180"></canvas>
</div>

<!-- ── Chart 3 — ASN / Hosting ───────────────────────────────────────── -->
<h2>Hosting Concentration: Cloudflare Handles a Third of Lure Infrastructure</h2>
<p>Cloudflare (33.7%) dominates, primarily via <code>pages.dev</code> subdomains and Cloudflare-proxied custom domains — legitimate-looking infrastructure that inherits clean reputation signals and bypasses many domain-reputation blocklists. Amazon (6.7%) and Confluence Networks / ACE (5.3%, 4.8%) follow. ASN-level blocking produces collateral disruption to legitimate traffic from the same networks before it meaningfully reduces adversary coverage.</p>

<div class="cg-chart-wrap">
  <div class="cg-chart-title">Hosting provider share by domain count — top 10</div>
  <canvas id="chartAsn" height="260"></canvas>
</div>

<!-- ── Chart 4 — Domain Age ──────────────────────────────────────────── -->
<h2>Domain Age at Observation: Infrastructure Deploys Fast</h2>
<p>The 30-day lookback captures observed domains primarily in the 7–30-day age bucket — consistent with fast-deploy adversary operations: register a domain, acquire a Let's Encrypt certificate within hours, then weaponise within days. Certificate transparency monitoring (crt.sh, CertStream) provides a detection window at cert issuance, before any victim encounters the site. See the cert monitoring queries in the <a href="#fingerprinting">Infrastructure Fingerprinting</a> section above.</p>

<div class="cg-chart-wrap">
  <div class="cg-chart-title">Domain age at time of observation (days since registration)</div>
  <canvas id="chartAge" height="180"></canvas>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js" integrity="sha256-oVuCFVMwB7ZMZZnVcBIl5PtP6a5BrMzpLNB4KJXI5mU=" crossorigin="anonymous"></script>
<script>
(function () {
  'use strict';

  /* ── Colour palette ─────────────────────────────────────────────────── */
  const PALETTE = [
    '#6366f1','#f59e0b','#10b981','#ef4444','#3b82f6',
    '#ec4899','#14b8a6','#f97316','#8b5cf6','#84cc16',
  ];

  /* ── Helpers ────────────────────────────────────────────────────────── */
  function darkMode() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }
  function gridColor() { return darkMode() ? 'rgba(255,255,255,.08)' : 'rgba(0,0,0,.07)'; }
  function textColor() { return darkMode() ? '#c9d1d9' : '#374151'; }

  const baseFont    = { family: 'ui-monospace, monospace', size: 11 };
  const baseFontSm  = { family: 'ui-monospace, monospace', size: 10 };

  /* ── Chart 1 — Lure type distribution (horizontal bar) ─────────────── */
  function renderLureTypes(data) {
    const items = data.lure_types || [];
    const el = document.getElementById('chartLureTypes');
    if (!items.length || !el) return;

    new Chart(el, {
      type: 'bar',
      data: {
        labels: items.map(d => d.tag.replace(/_/g, ' ')),
        datasets: [{
          data: items.map(d => d.count),
          backgroundColor: PALETTE.slice(0, items.length),
          borderRadius: 3,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const item = items[ctx.dataIndex];
                return ` ${item.count} domains (${item.pct}%)`;
              },
            },
          },
        },
        scales: {
          x: { grid: { color: gridColor() }, ticks: { color: textColor(), font: baseFont } },
          y: { grid: { display: false }, ticks: { color: textColor(), font: baseFont } },
        },
      },
    });
  }

  /* ── Chart 2 — Traffic source distribution (horizontal bar) ─────────── */
  function renderTrafficSources(data) {
    const items = data.traffic_sources || [];
    const el = document.getElementById('chartTrafficSources');
    if (!items.length || !el) return;

    new Chart(el, {
      type: 'bar',
      data: {
        labels: items.map(d => d.source.replace(/_/g, ' ')),
        datasets: [{
          data: items.map(d => d.count),
          backgroundColor: ['#f59e0b', '#6366f1', '#10b981', '#3b82f6'],
          borderRadius: 3,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const item = items[ctx.dataIndex];
                return ` ${item.count} domains (${item.pct}%)`;
              },
            },
          },
        },
        scales: {
          x: { grid: { color: gridColor() }, ticks: { color: textColor(), font: baseFont } },
          y: { grid: { display: false }, ticks: { color: textColor(), font: baseFont } },
        },
      },
    });
  }

  /* ── Chart 3 — ASN / hosting distribution (horizontal bar, top 10) ─── */
  function renderAsn(data) {
    const items = (data.hosting_providers || []).slice(0, 10);
    const el = document.getElementById('chartAsn');
    if (!items.length || !el) return;

    new Chart(el, {
      type: 'bar',
      data: {
        labels: items.map(d => d.name.substring(0, 35)),
        datasets: [{
          data: items.map(d => d.count),
          backgroundColor: '#6366f1',
          borderRadius: 3,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const item = items[ctx.dataIndex];
                return ` ${item.count} domains (${item.pct}%)`;
              },
            },
          },
        },
        scales: {
          x: { grid: { color: gridColor() }, ticks: { color: textColor(), font: baseFont } },
          y: { grid: { display: false }, ticks: { color: textColor(), font: baseFontSm } },
        },
      },
    });
  }

  /* ── Chart 4 — Domain age histogram ────────────────────────────────── */
  function renderAge(data) {
    const items = data.domain_age_histogram || [];
    const el = document.getElementById('chartAge');
    if (!items.length || !el) return;

    new Chart(el, {
      type: 'bar',
      data: {
        labels: items.map(d => d.bucket),
        datasets: [{
          data: items.map(d => d.count),
          backgroundColor: '#8b5cf6',
          borderRadius: 3,
        }],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { color: textColor(), font: baseFont } },
          y: { grid: { color: gridColor() }, ticks: { color: textColor(), font: baseFont } },
        },
      },
    });
  }

  /* ── Bootstrap ──────────────────────────────────────────────────────────
     Data injected at Jekyll build time via Liquid — no runtime fetch needed.
  ─────────────────────────────────────────────────────────────────────── */
  try {
    const data = {{ site.data.masq_infra | jsonify }};
    renderLureTypes(data);
    renderTrafficSources(data);
    renderAsn(data);
    renderAge(data);
  } catch (e) {
    console.error('masq-infra chart init failed:', e);
  }
}());
</script>

</div><!-- /.cg-page -->
