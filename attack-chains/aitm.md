---
layout: attack-chain
title: AiTM / Phishing Kit Attack Chain
subtitle: "AiTM kits bypass MFA by stealing session tokens - the same chokepoints regardless of kit or lure."
last_updated: 2026-04-14
permalink: /attack-chains/aitm/
show_ttp_overlap: true
ttp_data_key: aitm_ttp_overlap

stages:
  - id: lure_delivery
    label: Lure Delivery
    detection_status: detected
    attacker_action: "Phishing link / device code email"
    systems: "Email GW · Endpoint · Browser"
    detection_signals:
      - "Link to newly registered domain (<30 days) delivered via email or Teams message"
      - "Redirect chain ending at a lookalike Microsoft / Google login page"
      - "Device code authentication request from unexpected IP or user-agent"
      - "Browser navigating to domain mimicking login.microsoftonline.com or accounts.google.com"
    chokepoint_links:
      - label: "ClickFix Techniques"
        slug: "clickfix-techniques"

  - id: proxy_interception
    label: Proxy Interception
    detection_status: exploited
    attacker_action: "Reverse proxy relays real IdP traffic"
    systems: "Network · IdP · Browser"
    detection_signals:
      - "MFA prompt satisfied from IP that issued no prior authentication request to IdP"
      - "Authentication token issued to a domain that is not a registered app redirect URI"
      - "TLS certificate on login page issued to non-Microsoft/Google CA for IdP lookalike domain"
      - "Concurrent authentication sessions for same account from two geographically distinct IPs"

  - id: token_harvest
    label: Token Harvest
    detection_status: exploited
    attacker_action: "Session cookie / OAuth token extracted at proxy"
    systems: "IdP · Browser"
    detection_signals:
      - "Session cookie replayed from IP different from original authentication IP"
      - "OAuth refresh token exchange from unfamiliar device fingerprint or user-agent"
      - "Access token issued for broad Microsoft Graph scopes (Mail.Read, Files.ReadWrite) to unrecognized app"
      - "Device code token grant without matching device registration in Entra ID"
    chokepoint_links:
      - label: "Browser Credential Theft"
        slug: "browser-credential-theft"

  - id: account_takeover
    label: Account Takeover
    detection_status: exploited
    attacker_action: "Token replay from new IP/device without re-auth challenge"
    systems: "SaaS · M365 · Google Workspace"
    detection_signals:
      - "Impossible travel: session re-used from country different from prior authentication within minutes"
      - "Sign-in from new ASN or hosting provider with no prior user activity"
      - "CAE (Continuous Access Evaluation) token re-use after IP change without re-authentication"
      - "First-time access to sensitive mailbox folders (e.g., Sent Items, Inbox search) from session token"

  - id: persistence_objectives
    label: Persistence & Objectives
    detection_status: detected
    attacker_action: "OAuth app consent · email rules · device registration"
    systems: "M365 · Entra ID · Google Workspace"
    detection_signals:
      - "New OAuth application consent granted with Mail.Read or Files.ReadWrite permissions"
      - "Inbox rule created to forward or delete mail containing keywords (invoice, payment, wire)"
      - "New device registered to Entra ID from unfamiliar IP immediately after session token use"
      - "Admin role assigned to recently-created or newly-compromised account"
      - "Service principal credential added outside normal provisioning workflow"

actors:
  - name: Tycoon 2FA
    status: Active
    lure_delivery: "Mass-phishing email with O365 / M365 login lure link; targets org domains at scale"
    proxy_interception: "JavaScript-heavy Cloudflare-fronted reverse proxy relays real Microsoft IdP"
    token_harvest: "Captures session cookie in real time; strips MFA token from relay stream"
    account_takeover: "Replays harvested cookie from attacker infrastructure; no re-auth required"
    persistence_objectives: "Inbox forwarding rules; OAuth app consent for persistent mail access"
  - name: Evilginx
    status: Active
    lure_delivery: "Targeted spearphishing link; operator configures phishlet per IdP target"
    proxy_interception: "Open-source Go-based reverse proxy; intercepts full session including MFA"
    token_harvest: "Extracts session cookies and tokens from proxied responses via phishlets"
    account_takeover: "Exports cookie for direct browser import; used by operator in targeted campaigns"
    persistence_objectives: "Operator-driven post-access: OAuth consent, new credentials, lateral phishing"
  - name: EvilProxy
    status: Active
    lure_delivery: "Phishing-as-a-service platform; delivers links via email or Telegram bot"
    proxy_interception: "Commercial reverse proxy service; supports Microsoft, Google, Apple IdPs"
    token_harvest: "Real-time cookie interception; dashboard shows captured tokens per campaign"
    account_takeover: "Automated token replay; BEC-focused buyer use cases"
    persistence_objectives: "Email hiding rules; exfiltration of financial email content for BEC fraud"
  - name: Sneaky 2FA
    status: Active
    lure_delivery: "Phishing kit with dark-themed Microsoft 365 lure pages; targets enterprise users"
    proxy_interception: "Kit-based AiTM with partial relay approach. Less automated than EvilProxy."
    token_harvest: "Session cookie capture from proxied Microsoft authentication flow"
    account_takeover: "Manual or semi-automated token replay; operator-controlled timing"
    persistence_objectives: "Inbox rules for BEC follow-on; selective data access for financial fraud"
  - name: Device Code Flow
    status: Active
    lure_delivery: "Email delivers device code with social engineering (IT helpdesk, Teams invite)"
    proxy_interception: "No reverse proxy. Victim authenticates to real IdP. Device code polling captures the token."
    token_harvest: "OAuth refresh token obtained via device authorization grant; long-lived access"
    account_takeover: "Refresh token used for persistent API-level access to M365 Graph endpoints"
    persistence_objectives: "Service principal or app registration with delegated permissions; sustained access"

chokepoints:
  lure_delivery: "Victim clicks a link or opens an attachment that initiates an authentication flow to an attacker-controlled endpoint"
  proxy_interception: "Active session passes through adversary-controlled infrastructure OR device code is presented to victim"
  token_harvest: "Session token or OAuth access/refresh token extracted before or after MFA completion"
  account_takeover: "Token replayed from unfamiliar IP/device without triggering re-authentication challenge"
  persistence_objectives: "Attacker holds an authenticated session with sufficient privilege to modify account configuration"

---

## Research Methodology

Source: [Kitsune](https://github.com/christina23/kitsune) pipeline over [ORKL](https://orkl.eu/) + vendor reports - 11 reports / 5 AiTM kit families. Convergent techniques only.

## Related Attack Chains

- [Infostealers]({{ '/attack-chains/infostealers/' | relative_url }}) - Harvested credentials are often used as AiTM lure pre-text
- [Ransomware]({{ '/attack-chains/ransomware/' | relative_url }}) - AiTM-compromised accounts are sold to ransomware initial access brokers
