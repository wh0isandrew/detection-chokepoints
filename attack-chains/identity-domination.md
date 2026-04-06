---
layout: attack-chain
title: Active Directory & Identity Domination Attack Chain
subtitle: "How threat actors compromise on-prem AD, hybrid identity, and cloud Entra ID — exploiting protocol-level invariants that haven't changed since Kerberos was designed."
last_updated: 2026-04-03
permalink: /attack-chains/identity-domination/
show_ttp_overlap: true
ttp_data_key: identity_domination_ttp_overlap

stages:
  - id: initial_access
    label: Initial Access
    mitre_tactic: "TA0001"
    mitre_techniques:
      - id: "T1566.002"
        name: "Spearphishing Link"
      - id: "T1078"
        name: "Valid Accounts"
      - id: "T1199"
        name: "Trusted Relationship"
    detection_status: detected
    attacker_action: "Phishing / stolen creds / partner trust abuse"
    systems: "Email GW · VPN · Entra ID · AD FS"
    detection_signals:
      - "Sign-in from unfamiliar ASN or hosting provider with valid credentials"
      - "MFA fatigue: repeated push notifications followed by acceptance from new device"
      - "Device code authentication request from unexpected IP or user-agent"
      - "Delegated admin access from partner tenant to sensitive resources"

  - id: credential_access
    label: Credential Access
    mitre_tactic: "TA0006"
    mitre_techniques:
      - id: "T1003.001"
        name: "LSASS Memory"
      - id: "T1003.006"
        name: "DCSync"
      - id: "T1558.003"
        name: "Kerberoasting"
      - id: "T1528"
        name: "Steal Application Access Token"
    detection_status: exploited
    attacker_action: "LSASS dump / DCSync / Kerberoast / token theft"
    systems: "Domain Controllers · Entra ID · Endpoints"
    detection_signals:
      - "LSASS process access by non-system process (Sysmon EID 10)"
      - "DRSUAPI replication request from non-DC source IP (DCSync)"
      - "Kerberos TGS-REQ spike for service accounts with RC4 encryption (Kerberoasting)"
      - "OAuth token exchange from unfamiliar device fingerprint or user-agent"
      - "Service principal credential added outside normal provisioning workflow"
    chokepoint_links:
      - label: "Browser Credential Theft"
        slug: "browser-credential-theft"

  - id: privilege_escalation
    label: Privilege Escalation
    mitre_tactic: "TA0004"
    mitre_techniques:
      - id: "T1134"
        name: "Access Token Manipulation"
      - id: "T1484.001"
        name: "Group Policy Modification"
      - id: "T1098.001"
        name: "Additional Cloud Credentials"
    detection_status: exploited
    attacker_action: "Golden Ticket / GPO abuse / OAuth app consent"
    systems: "Domain Controllers · Entra ID · Group Policy"
    detection_signals:
      - "Kerberos TGT with anomalous lifetime or issued for non-existent user (Golden Ticket)"
      - "Group Policy Object modified outside change management window"
      - "OAuth application consent granted with Mail.Read, Files.ReadWrite, or Directory.ReadWrite.All"
      - "Admin role assigned to recently-created or newly-compromised account"
    chokepoint_links:
      - label: "EDR Bypass Techniques"
        slug: "edr-bypass-techniques"

  - id: lateral_movement
    label: Lateral Movement
    mitre_tactic: "TA0008"
    mitre_techniques:
      - id: "T1021.002"
        name: "SMB/Windows Admin Shares"
      - id: "T1021.001"
        name: "Remote Desktop Protocol"
      - id: "T1021.006"
        name: "Windows Remote Management"
    detection_status: exploited
    attacker_action: "PsExec / RDP / WMI / cross-cloud pivot"
    systems: "Domain · Servers · Azure resources"
    detection_signals:
      - "Network logon Type 3 + service creation across multiple hosts in short window"
      - "AD Connect Sync account authenticating to Azure from unexpected source"
      - "Cross-tenant access from partner account to sensitive SharePoint/OneDrive"
      - "Unusual admin account authenticating to 5+ hosts within 30 minutes"
    chokepoint_links:
      - label: "Remote Execution Tools"
        slug: "remote-execution-tools"

  - id: persistence
    label: Persistence
    mitre_tactic: "TA0003"
    mitre_techniques:
      - id: "T1098.005"
        name: "Device Registration"
      - id: "T1098.003"
        name: "Additional Cloud Roles"
      - id: "T1136.003"
        name: "Cloud Account"
      - id: "T1564.008"
        name: "Email Hiding Rules"
    detection_status: detected
    attacker_action: "Rogue OAuth apps / device registration / inbox rules / service principal secrets"
    systems: "Entra ID · M365 · Exchange Online"
    detection_signals:
      - "New OAuth application registered with broad Graph API permissions"
      - "New device registered to Entra ID from unfamiliar IP after token use"
      - "Inbox rule created to forward or delete mail containing keywords (invoice, payment, wire)"
      - "Service principal credential (secret or certificate) added outside normal workflow"
      - "New federated domain or trust relationship added to tenant"

  - id: impact
    label: Impact / Objectives
    mitre_tactic: "TA0040"
    mitre_techniques:
      - id: "T1486"
        name: "Data Encrypted for Impact"
      - id: "T1530"
        name: "Data from Cloud Storage"
      - id: "T1114.002"
        name: "Remote Email Collection"
    detection_status: detected
    attacker_action: "Ransomware via GPO / BEC / email exfil / cloud data theft"
    systems: "All domain hosts · M365 · SharePoint · OneDrive"
    detection_signals:
      - "GPO-deployed scheduled task or startup script across multiple OUs (ransomware deployment)"
      - "Mass email forwarding to external address (BEC exfil)"
      - "Large download from SharePoint/OneDrive by service principal or compromised account"
      - "vssadmin delete shadows / bcdedit recovery disable (pre-encryption)"

actors:
  - name: APT29 / Midnight Blizzard
    status: Espionage
    initial_access: "Spearphishing + partner trust abuse (StellarParticle, SolarWinds supply chain)"
    credential_access: "DCSync via DSInternals Get-ADReplAccount + Chrome cookie theft via Cookie Editor extension"
    privilege_escalation: "Service principal hijack (Microsoft StaffHub) + ApplicationImpersonation role abuse"
    lateral_movement: "Cross-tenant delegated admin access + credential hopping (different creds per hop)"
    persistence: "Rogue OAuth apps with Mail.Read/Files.ReadWrite + federated domain trust manipulation"
    impact: "Long-term espionage — email collection, cloud storage exfil, source code theft"
  - name: Storm-0501
    status: Active
    initial_access: "Exploited public-facing apps + IAB-purchased access + weak credentials"
    credential_access: "LSASS dump via Impacket SecretsDump + DCSync across domain"
    privilege_escalation: "AD Connect Sync account abuse to pivot on-prem → cloud"
    lateral_movement: "On-prem → Azure pivot via compromised Entra Connect Sync account + RDP"
    persistence: "Cloud session hijacking of on-prem user with cloud admin role (MFA disabled)"
    impact: "Embargo ransomware deployment across hybrid environment"
  - name: Storm-2372
    status: Active
    initial_access: "Device code phishing via email — IT helpdesk / Teams invite pretext"
    credential_access: "OAuth refresh token obtained via device authorization grant"
    privilege_escalation: "Token used for persistent API-level access to M365 Graph endpoints"
    lateral_movement: "Internal spearphishing from compromised account to additional targets"
    persistence: "App registration with delegated permissions + device registration in Entra ID"
    impact: "Email collection via Graph API + lateral expansion via internal phishing"
  - name: Scattered Spider
    status: Active
    initial_access: "Social engineering helpdesk → Okta/Entra password reset + MFA fatigue bombing"
    credential_access: "AD credential theft via compromised endpoints + MFA bypass tokens + session cookies"
    privilege_escalation: "Okta admin escalation + Entra ID role assignment"
    lateral_movement: "RDP/SSH from management network + cross-IdP pivot (Okta → Azure → AWS)"
    persistence: "SSH key persistence + OAuth app consent + Entra device registration"
    impact: "Data exfiltration + ransomware deployment (Alphv/BlackCat affiliate)"
  - name: Ransomware Operators
    status: Active
    initial_access: "IAB-purchased creds / VPN exploit / phishing → Cobalt Strike"
    credential_access: "LSASS dump + DCSync + Kerberoasting — universal across all tracked families"
    privilege_escalation: "Golden Ticket / GPO modification for domain-wide deployment"
    lateral_movement: "PsExec + WMI + RDP — same techniques documented across every DFIR Report intrusion"
    persistence: "Minimal — ransomware operators prioritize speed over stealth"
    impact: "GPO-deployed ransomware + vssadmin delete + bcdedit recovery disable"

chokepoints:
  initial_access: "Valid credential presented to authentication endpoint (AD, Entra ID, or federated IdP)"
  credential_access: "DRSUAPI replication call (DCSync) OR elevated process reading LSASS memory OR token grant from OAuth endpoint"
  privilege_escalation: "Kerberos TGT forged or GPO modified OR OAuth app consent with admin-level permissions"
  lateral_movement: "Authenticated session established to remote host via SMB/RDP/WinRM OR cross-tenant token used"
  persistence: "Service principal credential added OR inbox rule created OR device registered to Entra ID"
  impact: "Mass file encryption via GPO deployment OR bulk email/cloud data exfiltration via Graph API"

---

## The Protocol Invariant

Unlike other attack chains where convergence stems from OS-level constraints, identity domination
converges because of **protocol-level invariants**. Kerberos, LDAP, SAML, OAuth 2.0, and OpenID
Connect are the only authentication and authorization protocols available. Every actor — from
nation-state espionage to commodity ransomware — must use one of these protocols to authenticate,
escalate, and move laterally. The protocol is the chokepoint.

**On-prem AD:** Must call DRSUAPI to replicate credentials (DCSync). Must request a TGS to access
any kerberized service (Kerberoasting). Must modify GPO to deploy domain-wide (ransomware).

**Hybrid identity:** Must authenticate through AD Connect Sync account to pivot from on-prem
to cloud. The sync account is the bridge — and the chokepoint.

**Cloud Entra ID:** Must obtain a valid OAuth token to access any resource. Must modify
servicePrincipal credentials for persistent access. Must register a device or app for
long-term persistence.

## References

- [CrowdStrike: StellarParticle Campaign — APT29 AD/Cloud TTPs](https://www.crowdstrike.com/en-us/blog/observations-from-the-stellarparticle-campaign/)
- [Microsoft: Storm-0501 Ransomware Expanding to Hybrid Cloud (Sept 2024)](https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/)
- [Microsoft: Storm-2372 Device Code Phishing Campaign (Feb 2025)](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
- [Microsoft: Token Theft Playbook](https://learn.microsoft.com/en-us/security/operations/token-theft-playbook)
- [Microsoft: Compromised and Malicious App Investigation](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app)
- [SpecterOps: BloodHound — AD Attack Path Mapping](https://github.com/BloodHoundAD/BloodHound)
- [The DFIR Report: Consistent AD TTPs Across Ransomware Intrusions](https://thedfirreport.com/)

## Related Attack Chains

- [Ransomware]({{ '/attack-chains/ransomware/' | relative_url }}) — Ransomware operators rely on AD credential access and GPO abuse for domain-wide deployment
- [AiTM / Phishing Kits]({{ '/attack-chains/aitm/' | relative_url }}) — AiTM-stolen session tokens feed directly into the identity domination chain at the credential access stage
- [Infostealers]({{ '/attack-chains/infostealers/' | relative_url }}) — Infostealer-harvested credentials sold via IABs provide initial access for identity-based attacks
- [Hypervisor Compromise]({{ '/attack-chains/hypervisor-compromise/' | relative_url }}) — VM clone of domain controllers for offline NTDS.dit extraction bridges hypervisor and AD chains
