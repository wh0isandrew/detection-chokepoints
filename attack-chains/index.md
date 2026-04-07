---
layout: default
title: Attack Chains
description: "Mapped attack chains for ransomware and infostealer operators — showing how every actor converges on the same prerequisite chokepoints regardless of tooling."
permalink: /attack-chains/
---

<div class="max-w-[1280px] mx-auto px-6 py-10">

  <div class="ac-index-hero">
    <h1>Attack Chains</h1>
    <p>
      Threat actors change their tools constantly — loaders, C2 frameworks, ransomware brands, stealer families.
      But the <strong>prerequisite conditions</strong> they must satisfy at each stage never change.
      These mapped attack chains show how every actor, regardless of affiliation or toolset,
      converges on the same chokepoints. Detect the chokepoint; catch any actor.
    </p>
  </div>

  <!-- Section 1: Why Map Attack Chains -->
  <div class="ac-why-section">
    <h2>Why Map Attack Chains?</h2>
    <p>
      When you map multiple threat actors against the same kill chain, a pattern emerges:
      independent groups — different tools, different infrastructure, different affiliations —
      all <em>converge on the same techniques</em> at each stage.
    </p>
    <p>
      This isn't coincidence. Each stage has prerequisite conditions dictated by the OS and
      network architecture, not by attacker choice. An attacker who needs to move laterally
      <em>must authenticate</em> and <em>must create a remote process</em>. An attacker who wants
      to encrypt files <em>must stop backup services</em> and <em>must delete shadow copies</em>.
      The tooling varies. The prerequisites don't.
    </p>
    <p>
      Mapping this convergence identifies the highest-ROI detection targets: techniques where
      every actor overlaps are universal chokepoints — one detection rule covers every group
      in the matrix.
    </p>
    <p class="ac-why-attribution">
      Methodology adapted from Kaspersky's
      <a href="https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/06/23093553/Common-TTPs-of-the-modern-ransomware_low-res.pdf" target="_blank" rel="noopener">"Common TTPs of Modern Ransomware Groups"</a>
      (2022), which demonstrated that 8 independent ransomware operations shared &gt;50% of their kill chain techniques.
    </p>
  </div>

  <!-- Section 2: Cross-Chain Ecosystem Flow -->
  <div class="ac-ecosystem">
    <h2>Cross-Chain Ecosystem</h2>
    <p style="font-size:.875rem;color:var(--text-muted);margin-bottom:1.25rem;">
      No chain exists in isolation. Infostealers harvest credentials that fund ransomware.
      AiTM kits steal sessions that enable account takeover and BEC.
    </p>
    <div class="ac-ecosystem-flow">
      <div class="ac-flow-row">
        <a class="ac-flow-box" href="{{ '/attack-chains/infostealers/' | relative_url }}">Infostealer Chain</a>
        <span class="ac-flow-arrow">&rarr;</span>
        <span class="ac-flow-label">credentials sold to IABs</span>
        <span class="ac-flow-arrow">&rarr;</span>
        <a class="ac-flow-box" href="{{ '/attack-chains/ransomware/' | relative_url }}">Ransomware Chain</a>
      </div>
      <div class="ac-flow-row">
        <a class="ac-flow-box" href="{{ '/attack-chains/aitm/' | relative_url }}">AiTM / Phish Chain</a>
        <span class="ac-flow-arrow">&rarr;</span>
        <span class="ac-flow-label">session tokens &rarr; account takeover</span>
        <span class="ac-flow-arrow">&rarr;</span>
        <span class="ac-flow-box">BEC / Double Extortion</span>
      </div>
      <div class="ac-flow-example">
        <strong>Real-world examples:</strong>
        Snowflake breach (2024): infostealer creds &rarr; 165+ orgs compromised &middot;
        RansomHub: ClickFix &rarr; stealer &rarr; IAB &rarr; ransomware &middot;
        Scattered Spider: AiTM &rarr; Okta session &rarr; lateral movement &rarr; ransomware
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
        Initial Access → Credential Access → Lateral Movement → Defense Evasion → Impact.
        Covers BlackBasta, LockBit 3.0, Akira, Alphv/BlackCat, and Play with a convergence
        matrix showing how each group hits the same five chokepoints.
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
        Distribution → Execution → Collection → Exfiltration → Monetization.
        Covers RedLine, LummaC2, Vidar, StealC, and Raccoon — including how
        infostealer-harvested credentials fuel the RaaS ecosystem downstream.
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
        Lure Delivery → Proxy Interception → Token Harvest → Account Takeover → Persistence &amp; Objectives.
        Covers Tycoon 2FA, Evilginx, EvilProxy, Sneaky 2FA, and Device Code Flow — showing how
        every kit bypasses MFA by stealing session tokens, not passwords.
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
        Initial Access → Mgmt Plane Takeover → Credential Theft → Persistence → Lateral Movement → Impact.
        Covers BRICKSTORM/UNC5221, UNC3886, Scattered Spider, Play, and ALPHV — showing how actors
        operate beneath the guest OS where EDR cannot see them.
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
        Initial Access → Credential Access → Privilege Escalation → Lateral Movement → Persistence → Impact.
        Covers APT29, Storm-0501, Storm-2372, Scattered Spider, and ransomware operators —
        exploiting protocol-level invariants from Kerberos to Entra ID.
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

  <div class="mt-12 p-5 rounded-lg" style="background:var(--bg-card);border:1px solid var(--border);">
    <p style="font-size:.875rem;color:var(--text-muted);margin:0;">
      <strong style="color:var(--text);">More attack chains coming soon.</strong>
      BEC / business email compromise and initial access broker (IAB) operations — the handoff
      mechanisms shown in the ecosystem flow above — are in development. See <a href="https://github.com/{{ site.github_username }}/{{ site.github_repo }}/blob/main/CONTRIBUTING.md">CONTRIBUTING.md</a> to propose or draft a new chain.
    </p>
  </div>

</div>
