---
layout: default
title: Attack Chains
description: "Mapped attack chains for ransomware and infostealer operators. Shows how every actor converges on the same prerequisite chokepoints regardless of tooling."
permalink: /attack-chains/
---

<section class="ac-index-hero">
  <div class="ac-index-hero-inner">
    <h1>Attack Chains</h1>
    <p>
      Tools change constantly. Loaders, C2 frameworks, ransomware brands, stealer families, all of it rotates.
      The <strong>prerequisite conditions</strong> at each stage don't.
      These mapped chains show how every actor converges on the same chokepoints regardless of toolset. Detect the chokepoint, catch any actor.
    </p>
  </div>
</section>

<div style="max-width:1100px;margin:0 auto;padding:2.5rem 1.5rem 4rem;">

  <!-- Section 1: Why Map Attack Chains -->
  <div class="ac-why-section">
    <h2>Why Map Attack Chains?</h2>
    <p>
      Map enough threat actors against the same kill chain and a pattern falls out fast. Independent groups with different tools, different infrastructure, and different affiliations all <em>converge on the same techniques</em> at each stage.
    </p>
    <p>
      That convergence isn't coincidence. It's architecture. Lateral movement requires authentication and remote process creation. File encryption requires stopping backup services and deleting shadow copies. The OS and the network dictate those prerequisites, not the attacker. The tools rotate. The requirements don't.
    </p>
    <p>
      That's where the ROI is. Techniques that show up under every actor in the matrix are universal chokepoints. One detection rule covers every group.
    </p>
    <p class="ac-why-attribution">
      Methodology adapted from Kaspersky's <a href="https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/06/23093553/Common-TTPs-of-the-modern-ransomware_low-res.pdf" target="_blank" rel="noopener">Common TTPs of Modern Ransomware Groups (2022)</a>.
    </p>
  </div>

  <!-- Section 2: Cross-Chain Ecosystem Flow -->
  <div class="ac-ecosystem">
    <h2>Cross-Chain Ecosystem</h2>
    <p style="font-size:.875rem;color:var(--text-muted);margin-bottom:1.25rem;">
      No chain runs in isolation. Infostealers harvest the credentials that fund ransomware. AiTM kits steal the sessions that enable account takeover and BEC.
    </p>
    <div class="ac-ecosystem-flow">
      <div class="ac-flow-row">
        <a class="ac-flow-box" href="{{ '/attack-chains/infostealers/' | relative_url }}">
          <span class="ac-flow-icon" aria-hidden="true">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </span>
          Infostealer Chain
        </a>
        <span class="ac-flow-arrow">&rarr;</span>
        <span class="ac-flow-label">credentials sold to IABs</span>
        <span class="ac-flow-arrow">&rarr;</span>
        <a class="ac-flow-box" href="{{ '/attack-chains/ransomware/' | relative_url }}">
          <span class="ac-flow-icon" aria-hidden="true">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M6 14h12"/></svg>
          </span>
          Ransomware Chain
        </a>
      </div>
      <div class="ac-flow-row">
        <a class="ac-flow-box" href="{{ '/attack-chains/aitm/' | relative_url }}">
          <span class="ac-flow-icon" aria-hidden="true">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/><line x1="3" y1="3" x2="21" y2="21" stroke-dasharray="2 2"/></svg>
          </span>
          AiTM / Phish Chain
        </a>
        <span class="ac-flow-arrow">&rarr;</span>
        <span class="ac-flow-label">session tokens &rarr; account takeover</span>
        <span class="ac-flow-arrow">&rarr;</span>
        <span class="ac-flow-box">
          <span class="ac-flow-icon" aria-hidden="true">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
          </span>
          BEC / Double Extortion
        </span>
      </div>
      <div class="ac-flow-example">
        <strong>Real-world examples.</strong>
        Snowflake breach (2024): infostealer creds led to 165+ orgs compromised. &middot;
        RansomHub: ClickFix &rarr; stealer &rarr; IAB &rarr; ransomware. &middot;
        Scattered Spider: AiTM &rarr; Okta session &rarr; lateral movement &rarr; ransomware.
      </div>
    </div>
  </div>

  <!-- Section 4: How to read guide -->
  <details class="ac-guide">
    <summary class="ac-guide-toggle">
      <span class="badge-legend-icon">?</span>
      How to read an attack chain
    </summary>
    <div class="ac-guide-body">
      <div class="ac-guide-row">
        <span class="ac-guide-term">Stages</span>
        <span class="ac-guide-def">Kill chain phases from initial access to impact</span>
      </div>
      <div class="ac-guide-row">
        <span class="ac-guide-term">Actors</span>
        <span class="ac-guide-def">Threat groups or families tracked in this chain</span>
      </div>
      <div class="ac-guide-row">
        <span class="ac-guide-term">TTP Overlap</span>
        <span class="ac-guide-def">Color-coded cells show which actors use each technique</span>
      </div>
      <div class="ac-guide-row">
        <span class="ac-guide-term">Convergence</span>
        <span class="ac-guide-def">Techniques used by ALL actors = highest detection ROI</span>
      </div>
      <div class="ac-guide-row">
        <span class="ac-guide-term">Chokepoint</span>
        <span class="ac-guide-def">Links to the Detection Chokepoints page for that stage</span>
      </div>
      <div class="ac-guide-row">
        <span class="ac-guide-term">Ecosystem</span>
        <span class="ac-guide-def">Arrows show how chains feed into each other</span>
      </div>
    </div>
  </details>

  <div class="ac-index-grid">

    <a class="ac-index-card" href="{{ '/attack-chains/ransomware/' | relative_url }}">
      <span class="ac-card-badge ransomware">Ransomware</span>
      <div class="ac-card-title">Ransomware Attack Chain</div>
      <p class="ac-card-desc">
        Initial Access &rarr; Credential Access &rarr; Lateral Movement &rarr; Defense Evasion &rarr; Impact.
        BlackBasta, LockBit 3.0, Akira, Alphv/BlackCat, and Play mapped against the same five chokepoints to show where every group converges.
      </p>
      <div class="ac-card-meta">
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
          5 actors tracked
        </span>
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
          5 chokepoints
        </span>
        <span class="ac-card-meta-item">Avg TTR &lt;24 hrs</span>
        <span class="ac-card-cta">
          View chain
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
        </span>
      </div>
    </a>

    <a class="ac-index-card" href="{{ '/attack-chains/infostealers/' | relative_url }}">
      <span class="ac-card-badge infostealer">Infostealer</span>
      <div class="ac-card-title">Infostealer Attack Chain</div>
      <p class="ac-card-desc">
        Distribution &rarr; Execution &rarr; Collection &rarr; Exfiltration &rarr; Monetization.
        RedLine, LummaC2, Vidar, StealC, and Raccoon mapped through the full chain, including how harvested credentials feed the RaaS ecosystem downstream.
      </p>
      <div class="ac-card-meta">
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
          5 families tracked
        </span>
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
          5 chokepoints
        </span>
        <span class="ac-card-meta-item">15M+ infections/yr</span>
        <span class="ac-card-cta">
          View chain
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
        </span>
      </div>
    </a>

    <a class="ac-index-card" href="{{ '/attack-chains/aitm/' | relative_url }}">
      <span class="ac-card-badge aitm">AiTM</span>
      <div class="ac-card-title">AiTM / Phishing Kit Attack Chain</div>
      <p class="ac-card-desc">
        Lure Delivery &rarr; Proxy Interception &rarr; Token Harvest &rarr; Account Takeover &rarr; Persistence &amp; Objectives.
        Tycoon 2FA, Evilginx, EvilProxy, Sneaky 2FA, and Device Code Flow. Every kit bypasses MFA the same way: by stealing the session token, not the password.
      </p>
      <div class="ac-card-meta">
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
          5 kits tracked
        </span>
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
          5 chokepoints
        </span>
        <span class="ac-card-meta-item">MFA bypass focus</span>
        <span class="ac-card-cta">
          View chain
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
        </span>
      </div>
    </a>

    <a class="ac-index-card" href="{{ '/attack-chains/hypervisor-compromise/' | relative_url }}">
      <span class="ac-card-badge ransomware">Hypervisor</span>
      <div class="ac-card-title">Hypervisor Compromise Attack Chain</div>
      <p class="ac-card-desc">
        Initial Access &rarr; Mgmt Plane Takeover &rarr; Credential Theft &rarr; Persistence &rarr; Lateral Movement &rarr; Impact.
        BRICKSTORM/UNC5221, UNC3886, Scattered Spider, Play, and ALPHV. All operating beneath the guest OS, where EDR cannot see them.
      </p>
      <div class="ac-card-meta">
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
          5 actors tracked
        </span>
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
          6 stages
        </span>
        <span class="ac-card-meta-item">VMware vSphere focus</span>
        <span class="ac-card-cta">
          View chain
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
        </span>
      </div>
    </a>

    <a class="ac-index-card" href="{{ '/attack-chains/identity-domination/' | relative_url }}">
      <span class="ac-card-badge aitm">Identity</span>
      <div class="ac-card-title">AD &amp; Identity Domination Attack Chain</div>
      <p class="ac-card-desc">
        Initial Access &rarr; Credential Access &rarr; Privilege Escalation &rarr; Lateral Movement &rarr; Persistence &rarr; Impact.
        APT29, Storm-0501, Storm-2372, Scattered Spider, and ransomware operators. All exploiting the same protocol-level invariants from Kerberos through to Entra ID.
      </p>
      <div class="ac-card-meta">
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
          5 actors tracked
        </span>
        <span class="ac-card-meta-item">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
          6 stages
        </span>
        <span class="ac-card-meta-item">AD + Entra ID</span>
        <span class="ac-card-cta">
          View chain
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24"
               fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"
               stroke-linejoin="round" aria-hidden="true">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
        </span>
      </div>
    </a>

  </div>

</div>
