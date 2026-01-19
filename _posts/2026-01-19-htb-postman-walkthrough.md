---
layout: post
title: "HTB Postman Walkthrough - Redis Misconfigs & SSH Cracking"
date: 2026-01-19 12:00:00 -0500
categories: [Walkthrough, HackTheBox]
tags: [linux, redis, ssh, privesc, ctf, cybersecurity]
image:
  path: /assets/img/postman-thumb.jpg 
  alt: HTB Postman Thumbnail
---

Welcome to my latest walkthrough! In this video, we tackle the **Postman** machine from Hack The Box. 

We explore standard enumeration, find a hidden Webmin instance, and exploit a Redis misconfiguration to write SSH keys directly to the server. Finally, we crack a protected backup key to gain root access.

### Watch the Walkthrough

<iframe width="560" height="315" src="https://youtu.be/NAHX8QVYXnU" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

### Key Concepts
* **NMAP Scanning:** Advanced techniques for service discovery.
* **Redis Exploitation:** Using remote command execution to drop SSH keys.
* **Privilege Escalation:** Cracking `id_rsa` passphrases.

---
*Check out more of my work on [YouTube](https://www.youtube.com/@mr_y2kj) or connect with me on [LinkedIn](https://www.linkedin.com/in/varad-vithal-kj-094390201/).*