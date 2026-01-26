---
title: "Hack The Box: Jeeves Walkthrough"
date: 2026-01-26 12:00:00 +0530
categories: [Walkthrough, HackTheBox]
tags: [Windows, Jenkins, KeePass, Hashcat, PowerShell, ADS]
image:
  path: /assets/img/jeeves_thumb.jpg
  alt: HTB Jeeves Thumbnail
---

In this walkthrough, we tackle the Windows machine **Jeeves**. This box demonstrates the importance of thorough enumeration on non-standard ports and dealing with Alternate Data Streams (ADS) for flag retrieval.

### Tools Used
- **Nmap**: Network discovery
- **Jenkins Script Console**: For Remote Code Execution (RCE)
- **Hashcat**: For cracking KeePass database hashes
- **PowerShell**: For shell upgrades and enumeration

### Video Walkthrough

<iframe width="560" height="315" src="https://www.youtube.com/embed/BlOosrIm5fU" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

### Timestamps

| Time | Topic |
| :--- | :--- |
| **00:00** | Intro |
| **01:11** | Nmap Scanning Methodology |
| **03:27** | Going over Nmap Results |
| **05:06** | Testing NULL/Guest Logins (MSRPC & SMB) |
| **06:30** | Port 80 Enum |
| **13:09** | Port 50000 Enum |
| **24:21** | RCE and Reverse Shell using Jenkins |
| **32:44** | Shell as user and Host Enumeration |
| **35:08** | Upgrading to a PowerShell session |
| **42:13** | Resume Enum |
| **43:13** | Cracking KeePass DB using Hashcat |
| **49:52** | Username/Password/Hash Spraying |
| **57:21** | PWNED! |
| **01:06:00** | GETTING ROOT FLAG (ADS) |