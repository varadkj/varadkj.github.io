---
layout: post
title: "HTB Postman Walkthrough - Redis Misconfigs & SSH Cracking"
date: 2026-01-19 01:00:00 -0500
categories: [Walkthrough, HackTheBox]
tags: [linux, redis, ssh, privesc, ctf, cybersecurity]
image:
  path: /assets/img/postman-thumb.jpg 
  alt: HTB Postman Thumbnail
---

Welcome to my latest walkthrough! In this video, we tackle the **Postman** machine from Hack The Box. 

We explore standard enumeration, find a hidden Webmin instance, and exploit a Redis misconfiguration to write SSH keys directly to the server. Finally, we crack a protected backup key to gain root access.

### Watch the Walkthrough

<iframe width="560" height="315" src="https://www.youtube.com/embed/NAHX8QVYXnU" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

### Timestamps

| Time | Topic |
| :--- | :--- |
| **00:00** | Intro and connecting to HTB |
| **01:53** | NMAP Scan Techniques |
| **05:00** | Going over NMAP Output |
| **07:15** | Port 80 Enumeration |
| **10:36** | Port 10000 Enumeration |
| **12:00** | Redis Overview & Theory |
| **18:29** | Back to Port 80 |
| **18:52** | Port 10000 Revisit |
| **22:09** | Exploiting Redis Misconfigurations |
| **33:55** | Redis SSH Enumeration |
| **39:45** | Cracking id_rsa.bak |
| **41:55** | SSH as Matt / Privesc to Root |

### Key Concepts
* **NMAP Scanning:** Advanced techniques for service discovery.
* **Redis Exploitation:** Using remote command execution to drop SSH keys.
* **Privilege Escalation:** Cracking `id_rsa` passphrases.

---
*Check out more of my work on [YouTube](https://www.youtube.com/@mr_y2kj) or connect with me on [LinkedIn](https://www.linkedin.com/in/varad-vithal-kj-094390201/).*
