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
</section>

<section id="chains">
<h2>Delivery Chains</h2>
</section>

<section id="payloads">
<h2>Payloads</h2>
</section>

<section id="campaigns">
<h2>Campaigns</h2>
</section>

<section id="infrastructure">
<h2>Infrastructure</h2>
</section>

<section id="samples">
<h2>Samples</h2>
</section>

<section id="chokepoints">
<h2>Detection Chokepoints</h2>
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
