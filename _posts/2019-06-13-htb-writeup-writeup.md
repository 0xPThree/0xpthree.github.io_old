---
layout: single
title: Writeup - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2019-06-13
classes: wide
header:
  teaser: /assets/images/htb-writeup-writeup/writeup_logo.png
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

![](/assets/images/htb-writeup-writeup/writeup_logo.png)

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."

----------------


1.  Using pspy64 I can see that run-parts is triggered on login.

2.  Find the PATH of order the scripts are executed:
    jkr@writeup:~$ echo $PATH
    /usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

3.  Look at the path for run-parts to see if I can exploit the order:
    jkr@writeup:~$ which run-parts
    /bin/run-parts

4.  Noticed that both /usr/local/bin and /usr/bin is before /bin in order of script execution. So I made a reverse-shell script called run-parts and placed it in the /usr/local/bin dir.

5.  Start nc on local host, log out and in again from jkr@writeup to trigger scripts and boom - reverse root shell.


ÖVRIG INFO OM PATH:
Q: If there are multiple executable files in PATH with the same name which one is preferred?
A: It stops at the first one it finds, reading $PATH left to right.

Q: Is current directory included in the search when file is executed?
A: If the current directory is in PATH then it is searched. Remember that an empty directory in PATH includes the current directory. e.g. PATH=:/usr/bin (leading empty) PATH=/usr/bin: (trailing empty) and PATH=/usr/bin::/bin (middle empty) will all effectively include current working directory.
