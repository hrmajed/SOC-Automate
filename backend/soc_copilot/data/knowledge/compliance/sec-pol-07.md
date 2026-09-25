---
id: SEC-POL-07
title: SEC-POL-07 Privileged access and network segmentation policy
type: policy
source: compliance
hosts: JMP-ADM-01, WKS-FIN-023, PAM-GW-01
summary: Privileged sessions to Management hosts such as JMP-ADM-01 must originate from the PAM gateway 10.10.1.2; RDP from the Finance VLAN to Management is explicitly prohibited, so such a session is a policy violation by definition.
---
# SEC-POL-07: Privileged access

## Rules
1. Interactive sessions to the Management segment (10.10.1.0/24) must originate from PAM-GW-01 (10.10.1.2).
2. The Finance VLAN (10.20.4.0/24) must never initiate RDP (3389) or SMB (445) to Management.
3. Privileged accounts (for example `m.chen`) must not log on interactively to user workstations; if they do, the
   workstation must be treated as holding reusable privileged credentials.
4. Cloud administrator credentials must not be stored on disk (see INC-2026-0033 remediation).

## Severity guidance
A privileged logon to Management from a non-PAM source is a **high** severity event.
