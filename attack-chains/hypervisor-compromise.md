---
layout: attack-chain
title: Hypervisor Compromise Attack Chain
subtitle: "How threat actors target VMware vSphere to operate beneath the guest OS, where EDR cannot see them, achieving persistence, credential theft, and total infrastructure control."
last_updated: 2026-04-14
permalink: /attack-chains/hypervisor-compromise/
show_ttp_overlap: true
ttp_data_key: hypervisor_ttp_overlap

stages:
  - id: initial_access
    label: Initial Access & Recon
    detection_status: detected
    attacker_action: "Exploit edge appliance / stolen creds"
    systems: "VCSA · ESXi · vSphere API"
    detection_signals:
      - "VCSA firewall audit: SSH_BLOCKED_NEW, WEB_BLOCKED_NEW, VAMI_BLOCKED_NEW from non-PAW IP"
      - "Failed authentication from unauthorized internal IP in auth.log or vCenter UserLoginSessionEvent"
      - "Tomcat audit log showing requests to /manager/text/deploy (WAR file deployment)"

  - id: mgmt_takeover
    label: Mgmt Plane Takeover
    detection_status: exploited
    attacker_action: "VAMI SSH enable → shell pivot"
    systems: "VCSA · Photon OS"
    detection_signals:
      - "VAMI log: POST /rest/com/vmware/cis/session followed by SSH enablement via PUT on port 5480"
      - "SSO audit: membership change to BashShellAdministrators group (PrincipalManagement event)"
      - "vCenter event: HostSshEnabledEvent"
      - "VCSA shell command log: interactive commands like whoami, netstat"

  - id: credential_theft
    label: Credential Theft
    detection_status: exploited
    attacker_action: "BRICKSTEAL: Tomcat memory + PostgreSQL creds"
    systems: "VCSA · vCenter SSO · Active Directory"
    detection_signals:
      - "auditd key privileged: sudo usage to scrape Tomcat memory or PostgreSQL config files"
      - "HTTP requests to /web/saml2/sso/* from VCSA itself (BRICKSTEAL harvesting)"
      - "vCenter events: VmClonedEvent targeting domain controllers (offline NTDS.dit theft)"
      - "VmDiskHotPlugEvent (attacker mounting cloned DC disk)"

  - id: persistence
    label: Persistence
    detection_status: detected
    attacker_action: "Init script injection + transient SSO accounts"
    systems: "VCSA · ESXi · SSO"
    detection_signals:
      - "auditd key startup_scripts: sed commands modifying /etc/sysconfig/init or /opt/vmware/etc/init.d/"
      - "auditd key perm_mod: chmod +x on init script directories"
      - "auditd key ssh_key_tamper: write to /root/.ssh/authorized_keys"
      - "AIDE integrity alert (AIDE_TRAP): differences found for /lib64 or /root/.ssh"
      - "SSO audit: transient account created and deleted within ~13 minutes"

  - id: lateral_movement
    label: Lateral Movement
    detection_status: exploited
    attacker_action: "vpxuser shell pivot + Ghost NIC bridging"
    systems: "ESXi · Management VLAN · Guest VMs"
    detection_signals:
      - "vCenter event: VmNetworkAdapterAddedEvent (8.0u3+), high-fidelity Ghost NIC signal"
      - "Legacy: VmReconfiguredEvent with NIC addition to management port group"
      - "ESXi hostd.log: vpxuser shell login from VCSA IP"
      - "Windows Event 4624 (Type 3) from appliance IP using stolen service account creds"

  - id: exfil_impact
    label: Exfiltration & Impact
    detection_status: detected
    attacker_action: "C2 tunneling / VMDK theft / datastore encryption"
    systems: "VCSA · Datastores · Network egress"
    detection_signals:
      - "VCSA firewall audit: INTERNET_BLOCKED, ZT_OUTBOUND_DENIED"
      - "VCSA egress to non-whitelisted destination (DoH resolvers, SOCKS proxy ports)"
      - "vCenter events: VmClonedEvent on Tier-0 VMs"
      - "Ransomware: vim-cmd vmsvc/power.off across multiple VMs followed by datastore encryption"

actors:
  - name: BRICKSTORM / UNC5221
    status: Espionage
    initial_access: "Edge appliance exploit → WAR file (SLAYSTYLE)"
    mgmt_takeover: "VAMI SSH enable → BashShellAdmins pivot"
    credential_theft: "BRICKSTEAL: Tomcat memory scrape + PostgreSQL creds"
    persistence: "sed inject into init scripts + transient SSO accounts (13-min lifecycle)"
    lateral_movement: "vpxuser shell pivot + Ghost NIC bridging"
    exfil_impact: "SOCKS/DoH C2 tunneling + VM clone of DCs for NTDS.dit"
  - name: UNC3886
    status: Espionage
    initial_access: "Zero-day exploitation of vCenter (CVE-2023-34048)"
    mgmt_takeover: "vCenter shell access + custom VIB deployment"
    credential_theft: "VMCI socket credential interception"
    persistence: "Malicious VIBs + modified /etc/rc.local.d scripts"
    lateral_movement: "Custom backdoor via VMCI sockets (guest-to-host)"
    exfil_impact: "Long-term espionage; data staging via encrypted channels"
  - name: UNC3944 / Scattered Spider
    status: Active
    initial_access: "Social engineering helpdesk → vSphere creds via Okta"
    mgmt_takeover: "vSphere web client → SSH enable on ESXi"
    credential_theft: "AD credential theft via VM access + MFA bypass tokens"
    persistence: "SSH key persistence on ESXi hosts"
    lateral_movement: "RDP/SSH from management network to guest VMs"
    exfil_impact: "Data exfiltration + ransomware deployment via ESXi"
  - name: Play Ransomware
    status: Active
    initial_access: "N-day exploits (FortiOS, ESXi OpenSLP)"
    mgmt_takeover: "ESXi shell access via stolen root creds"
    credential_theft: "Credential harvest from compromised AD"
    persistence: "rc.local.d script modification on ESXi"
    lateral_movement: "SSH lateral between ESXi hosts"
    exfil_impact: "ESXi datastore encryption (selective VM targeting)"
  - name: Alphv/BlackCat
    status: Legacy
    initial_access: "Stolen VPN/RDP creds → vCenter access"
    mgmt_takeover: "vSphere web client with admin creds"
    credential_theft: "LSASS dump + AD enumeration (BloodHound)"
    persistence: "ESXi shell persistence + custom Linux encryptor"
    lateral_movement: "PsExec + WMI + ESXi SSH"
    exfil_impact: "Cross-platform Rust encryptor targeting VMFS datastores"

chokepoints:
  initial_access: "Management interface (VAMI 5480, SSH 22, vSphere API 443) reachable from untrusted network zone"
  mgmt_takeover: "VAMI-to-shell pivot requires BashShellAdministrators membership"
  credential_theft: "Elevated process reads credential store or Tomcat memory"
  persistence: "Init script write + chmod to survive reboot"
  lateral_movement: "vpxuser shell access OR Ghost NIC into management VLAN"
  exfil_impact: "VCSA outbound to C2 OR datastore read for VMDK theft"

---

<div class="ac-dwell-callout">
  <div class="ac-dwell-stat">
    <span class="ac-dwell-num">393</span>
    <span class="ac-dwell-label">days average dwell time</span>
  </div>
  <p class="ac-dwell-desc">
    Most enterprise EDR has zero visibility into VCSA (Photon OS) or ESXi.
    Attackers who compromise the hypervisor layer operate beneath every guest VM.
    Credential theft, lateral movement, and persistence all occur in a blind spot
    where traditional endpoint detection cannot reach.
  </p>
</div>

## Research Methodology

Procedure-level data in this attack chain was extracted and corroborated using
[Kitsune](https://github.com/christina23/kitsune), an AI-driven threat intelligence pipeline.
12 vendor and government reports were analyzed across 5 actors targeting VMware vSphere and ESXi,
with cross-report corroboration used to validate convergence patterns. Reports were sourced from
[ORKL](https://orkl.eu/) and direct vendor publications including Mandiant / Google Threat Intelligence,
CISA, Trend Micro, Varonis, and Sygnia. Only techniques observed in two or more actors appear in the
TTP diagram above. Actor-specific procedures are recorded in the source data but filtered from the
convergence view.

## Broader ESXi Ransomware Landscape

The two ransomware actors in this chain (Play, Alphv/BlackCat) represent a pattern shared by 10+ additional groups. SentinelOne documented that leaked Babuk source code spawned ESXi encryptors for RansomHub, LockBit, Akira, Cactus, RTM Locker, Conti successors, REvil/Revix, Rorschach/BabLock, and others. All use identical tradecraft: SSH to ESXi &rarr; `vim-cmd vmsvc/power.off` &rarr; encrypt `/vmfs/volumes`. The detection chokepoints in this chain cover all of them because the underlying prerequisites are identical regardless of which encryptor binary is deployed.

**Source:** [SentinelOne: Multiple groups build ESXi lockers from leaked Babuk code](https://www.sentinelone.com/labs/hypervisor-ransomware-multiple-threat-actor-groups-hop-on-leaked-babuk-code-to-build-esxi-lockers/)

## Related Attack Chains

- [Ransomware]({{ '/attack-chains/ransomware/' | relative_url }}) - ESXi-targeting ransomware reuses identical vSphere access patterns; 8 groups tracked in the ransomware chain
- [Infostealers]({{ '/attack-chains/infostealers/' | relative_url }}) - Stolen VPN/RDP creds from infostealer logs provide initial vSphere access
- [AiTM / Phishing Kits]({{ '/attack-chains/aitm/' | relative_url }}) - AiTM-compromised Okta sessions enable vSphere web client access
