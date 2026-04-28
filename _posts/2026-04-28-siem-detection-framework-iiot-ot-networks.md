---
title: "Building a Purdue-Aware SIEM for IIoT/OT Networks"
date: 2026-04-28 12:00:00 -0400
categories: [Capstone, ICS/OT Security]
tags: [siem, ics, ot, purdue, mitre-attack, iec-62443, zeek, ton-iot, detection-engineering]
pin: true
math: false
mermaid: false
description: A walkthrough of the SIEM detection framework I built for my MS capstone — Purdue Reference Architecture asset modeling, MITRE ATT&CK for ICS rule design, two-tier detection, and multi-stage kill chain correlation against the TON_IoT testbed. Sponsored by Cummins Inc.
---

> This was my MS Cybersecurity capstone at Northeastern University, sponsored by **Cummins Inc.** and built with three teammates: Manav Jariwala, Neha Bhende, and SelvaKumar Selvaraj Anand. I focused on the AI Analyst integration and detection engine refinement; the design and rule authoring were a team effort.
{: .prompt-info }

## The problem

OT environments break most assumptions IT SIEMs are built on. Devices live for fifteen years, can't be patched on a Tuesday-night maintenance window, and run protocols (Modbus, S7Comm, DNP3, EtherNet/IP) that show up in zero rule packs from your average commercial vendor. Plant networks are loud — broadcast traffic, periodic polling, legacy clear-text everything — and the things that look anomalous to an IT analyst are usually fine, while the things that look fine to an IT analyst can be the start of a kill chain.

The ask from our sponsor was: **what would a SIEM that understands an OT plant actually look like?** Not a product replacement — a blueprint and a working detection engine, grounded in real ICS architecture standards, that a SOC team could adopt for an IIoT manufacturing site.

## Architecture: Purdue Reference Model + L3.5 IDMZ

We anchored the design to the **Purdue Enterprise Reference Architecture** (ISA-95 / IEC 62443) because it's still the canonical way OT environments are conceived in industry. Six levels, two firewalls, one buffer zone:

| Level | Zone | Examples |
|-------|------|----------|
| L0 | Physical Processes | Sensors, actuators, robots |
| L1 | Local Control | PLCs, RTUs, IoT gateway controllers |
| L2 | Supervisory Controls | HMIs, SCADA workstations |
| **— Firewall — L2 ↔ L3 —** | | |
| L3 | Operations Management | Historian, passive OT sensor (Zeek) |
| L3.5 | Industrial DMZ | SIEM collector, security gateway |
| **— Firewall — L3.5 ↔ L4 —** | | |
| L4 | Enterprise Business | SOC platform, ERP, business servers |

The interactive view below is from our final demo. Toggle between OT telemetry flow, the SIEM alert pipeline, and asset classification by zone:

<iframe src="/assets/html/PurdueDemo.html"
        width="100%" height="950"
        style="border: 1px solid #21262d; border-radius: 8px; background: #0a0e14;"
        title="Interactive Purdue Reference Model — Data Flow and Asset Classification">
</iframe>

Every host in our testbed got mapped to a Purdue level in an asset registry. That registry is the foundation of every detection decision the engine makes downstream. A network event isn't just `192.168.1.193 → 192.168.1.180`. It's `[L2 HMI: Win7 client] → [L3 passive OT sensor]`, and that context drives everything.

We used the **TON_IoT dataset** (Moustafa, 2021) as the testbed. It includes a documented industrial network with attacker systems on `192.168.1.20–.39` running scanning, DoS/DDoS, ransomware, injection, and password attacks against a small but realistic OT topology. Real Zeek `conn.log` data, real attacker-to-victim flows, no synthetic noise.

## The asset registry

Every detection the engine makes is grounded in an asset registry that encodes Purdue level, zone, OS, role, and architectural function for each host. Lookups against the registry are what catch traffic crossing firewall boundaries or skip-jumping Purdue levels. L2 to L3 is a normal upward path. L1 to L4 is a red flag that something is bypassing inspection. The registry is what turns a raw flow record into a contextually-meaningful event.

## Multi-factor severity scoring

A single alert means almost nothing in OT. Severity is context. We built a multi-factor weighted model that combines three things: how critical the destination asset is (mostly a function of its Purdue level), how confident the detection itself is (known indicator versus protocol anomaly versus behavioural heuristic), and the zone context (whether the event crosses firewalls, targets the OT field zone, or violates Purdue adjacency). The factors combine into a single severity score that maps to the usual CRITICAL / HIGH / MEDIUM / LOW / INFO tiers.

The point of weighting Purdue level into asset criticality is that an attacker port-scanning an L4 vulnerable web app is a HIGH; the same scan against an L1 PLC is a CRITICAL because that PLC is what's actually keeping a turbine spinning. Most flat-threshold detection engines can't make this distinction.

The full alert pipeline, from raw Zeek `conn.log` to enriched `SIEMAlert` and correlated `Incident`, looks like this:

<iframe src="/assets/html/Normalization_Pipeline.html"
        width="100%" height="1500"
        style="border: 1px solid #252a38; border-radius: 8px; background: #0c0e14;"
        title="SIEM Log Normalization Pipeline">
</iframe>

## Two-tier detection: stateless rules + correlation

The engine has 18 rules total, in two tiers.

### Tier 1 — Stateless rules

Each Tier 1 rule looks at a single Zeek connection record and asks one structural question. Categories include known-indicator hits, architectural violations (skip-jump Purdue traversals, firewall crossings), protocol-zone mismatches (OT protocols showing up at the enterprise tier, IT admin ports showing up in the field zone), volumetric anomalies, recon heuristics from connection-state patterns, risky cleartext protocols, and known ransomware delivery vectors.

OT protocol coverage is port-based, recognising Modbus, S7Comm, OPC-UA, DNP3, EtherNet/IP, MQTT, BACnet, CoAP, and Node-RED on their standard ports. We chose port-based identification because it matches how passive OT monitoring tools deploy in real networks: full protocol parsing is the next iteration but not strictly required to catch the patterns Tier 1 is looking for.

### Tier 2 — Correlated rules

Tier 2 is multi-field correlation for the post-exploitation phase of a ransomware attack. Three behaviours, each one a separate rule: the exploit payload itself (EternalBlue-style SMB delivery), the C2 callback that follows successful exploitation (Meterpreter reverse-shell handlers), and the post-compromise lateral movement that ransomware uses to spread between internal hosts (worm-style SMB propagation).

The interesting thing about Tier 2 is that `conn.log` alone, without any payload inspection, gives you enough signal to flag exploit delivery. You need to know the protocol, the direction, the rough size, and that the handshake completed. That's it.

## Kill chain correlation

The KillChainTracker is what stitches atomic alerts into incidents. Two correlation profiles run in parallel: a multi-stage ransomware chain mapping the path from recon through weaponisation, exploitation, C2, and lateral movement; and a shorter DDoS chain capturing recon, targeting, and flooding behaviour. Tracking is grouped by attacker IP, with time-windowed stage requirements. If the window expires before the minimum stage count is hit, the candidate incident is dropped. If the chain is met, it emits as an Incident with attacker, victim list, stages reached, and a generated narrative. That narrative is what the analyst actually sees, not the hundreds of raw alerts that fed it.

This is the highest-value piece of the framework, in my opinion. Most SIEMs drown analysts in atomic alerts; we wanted the dashboard to show *attacks*, not events.

## AI Analyst (my contribution)

The dashboard has a chat interface backed by Claude Haiku, with a custom RAG layer that injects four context blocks into every prompt:

1. **Alert statistics** — counts by rule, severity, zone
2. **Detection report** — recent triggered rules with descriptions
3. **Kill chain incidents** — active incident profiles with stage progression
4. **Asset registry** — full Purdue/zone metadata

A SOC analyst can ask "what's happening on `192.168.1.193`?" or "which assets are involved in the active ransomware incident?" and get a coherent answer grounded in actual current state. No hallucinated IPs, no invented rules. Every claim the model can make is anchored to the injected context.

## Honest scope notes

If you're reading this evaluating whether the framework would translate to your environment, the things I'd want to know:

- **conn.log only.** All rules read from Zeek `conn.log` enriched with Purdue metadata. Protocol-specific parsing is the next iteration. For network-level OT detection, port-based identification gets you most of the value Tier 1 is targeting.
- **Static asset registry.** No automated discovery — assets are hand-mapped. For a real deployment, this would need to integrate with an OT asset management platform.
- **Tested against TON_IoT, not a live plant.** The dataset is documented and well-cited but it's a testbed. Real plant traffic has different baselines.
- **Estimated 40% false positive reduction** vs. flat-threshold detection is a design estimate from the severity model, not a measured A/B against a production SIEM.

The framework is meant as a blueprint, not a drop-in replacement.

## What I'd build next

If I had another semester:

1. **Modbus / DNP3 / S7Comm log parsing** — move from port-based to function-code-aware detection (e.g., flag unauthorized "write coil" function codes from non-engineer hosts).
2. **Behavioral baselining** — compute per-asset traffic profiles and alert on deviation rather than fixed thresholds.
3. **STIX/TAXII export** — make incidents shareable across organizations and ISACs.
4. **Active asset discovery** — passive fingerprinting from observed traffic to keep the registry current.

## What's not on this page

Everything above is a glimpse, not the full reveal. The detection rules, the source code, the asset registry logic, the dashboard internals, and the specific scoring weights stay private out of respect for the sponsor. If you're hiring or collaborating and want a deeper walkthrough, get in touch and we can talk under NDA.

---

*If you're working on OT detection engineering, ICS-aware SIEM, or just want to argue about the right way to score severity in IIoT, I'd be glad to hear from you. Contact details are on the [About](/about) page.*