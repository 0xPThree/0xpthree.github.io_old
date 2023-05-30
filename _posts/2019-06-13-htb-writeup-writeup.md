---
layout: single
title: Writeup - Hack The Box
excerpt: "Partial writeup for root only."
date: 2019-06-13
classes: wide
header:
  teaser: /assets/images/htb-writeup-writeup/writeup_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
  unreleased: false
categories:
  - hackthebox
tags:  
  - linux
  - easy
  - pspy64
  - path hijacking
---

![](/assets/images/htb-writeup-writeup/writeup_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

N/A<br><br><br><br><br><br><br>

----------------

# ROOT

Using `pspy64` we can see that `run-parts` is triggered on login.

Find the PATH order the scripts are executed:
```bash
jkr@writeup:~$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

Look at the path for `run-parts` to see if we can exploit the order:
```bash
jkr@writeup:~$ which run-parts
/bin/run-parts
```

Noticed that both `/usr/local/bin` and `/usr/bin` is before `/bin` in order of script execution. So I made a reverse-shell script called `run-parts` and placed it in the `/usr/local/bin` dir.

Start `nc` on local host, log out and in again from `jkr@writeup` to trigger scripts and boom - reverse root shell.


> **INFO ABOUT PATH:**<br>
> **Q:** If there are multiple executable files in PATH with the same name which one is preferred?<br>
> **A:** It stops at the first one it finds, reading $PATH left to right.<br>
>
> **Q:** Is current directory included in the search when file is executed?<br>
> **A:** If the current directory is in PATH then it is searched. Remember that an empty directory in PATH includes the current directory. e.g. PATH=:/usr/bin (leading empty) PATH=/usr/bin: (trailing empty) and PATH=/usr/bin::/bin (middle empty) will all effectively include current working directory.
