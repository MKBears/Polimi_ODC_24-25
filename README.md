# PoliMi ODC course ay 2024/25 #

## by Or505 ##

This repo contains all the exploits I've been able to create for the CTF challenges in the ODC course. I tried my best to document them in a clear way, so I hope to be useful for future students.

## Fancy exploits and where to find them ##

### Shellcoding ###

+ **Back to Shell**: basic ways of writing a simple shellcode
+ **Open Read Write**: basic way of writing a simple open-read-write ctf code
+ **Multistage**: exploit read syscall to get real shellcode from stdin to the memory (used when buffer space is limited)
+ **Tiny**: how to write a shellcode with maximum instruction size 2 Bytes
+ **Gimme3Bytes**: how to exploit multistage to exploit only 3 Bytes of buffer
+ **Lost in Memory**: nothing new
+ **Benchmarking Service**:
+ **Forking Server**:

### Reverse engineering ###

+ **CrackMe**: very basic way of decrypting a flag from static program data
+ **Leaked License**: how to substitute register values where needed
+ **RevMeM**: very simple dynamic flag encryption
+ **RevMeMP**: anti anti-debug techniques
+ **Baby Keycheck**: a bit fancier flag encryption
+ **Provola**: basic way of locally cracking a flag with libdebug
+ **Slow (Food) Provola**: making sleep syscall fail, when a new character is found, bp.hit_count decrements

### Mitigations ###

+ **Leakers**: leak addresses helped by ELF python class
+ **One Write**: exploit exit jump address to execute hidden function (there is no ret from main)
+ **PTR Protection**: ret addr is xored with canary, exploit last canary Byte (\0) and brute force on second last ret addr Byte
+ **The Adder**: break scanf to leak stuff
+ **Forking Server++**:

### Return Oriented Programming ###

+ **ROPasaurusrex**: exploit plt to leak got addresses, 32 bit rop chain, call to _start
+ **EasyROP**: 64 bit rop chain not directly put on stack (each 4-byte word is the sum of two previous reads), read used to put "/bin/sh" in a global variable (to have its pointer for name arg of exevce)
+ **Empty Spaces**: 64 bit rop chain created by navigating a huge number of (almost useless) gadgets, read used to overwrite random stuff blocking exploit
+ **Positive Leak**:
+ **Byte Flipping**:

### Symbolic execution ###

+ **Prodkey**, **CrackSymb**: use z3 solver to crack input flag by exploiting constraint satisfacion (find constraints with ida)
+ **100%**: like the previous ones but also including angr scripts (not working on my pc because they fill the ram before snding)
+ **NotSoHandy**:

### Heap Exploitation ###

+ **Fastbin Dup**: Free twice a block to make change malloc hook with a onegadget (fastbin dup attach ~ duh)
+ **PKM**: Basic 1 Byte overflow combined with fastbin dup to overwrite malloc hook with a onegadget
+ **Santa's Letter**: harder 1 Byte overflow exploit to leak libc base address and then overwrite addresses to modify GOT entries
+ **Playground**: Basic fastbin dup attack with T-cache
+ **ASCII Gallery**:
+ **Master of Notes**:

### Kernel Exploitation ###

+ **Baby Kernel**: Basic kernel exploitation, use of ioctl
+ **K-ROP**: Another basic kernel exploitation, but this time using a ROP chain

### Packing ###

+ **John the Packer**: Analyze with ida the packer source code and unpack the function code recursively until it becomes """only""" a reverse engineering challenge to extract the flag (combine z3 solver with libdebug brute force)
+ **Dynamism**: Analyze with ida the packer source code and get the missing functions from remote, then analyze them with ghidra and execute ./dynamism with gdb to get the encrypted flag and the key
+ **Packing Bizarre Adventure**: The packer code is in a NX page, which is changed to rwx at runtime, so you cannot decompile it with ida (but you can with ghidra), then you have to retrieve the unpacked code from memory before the program jumps to it. In the end, half of the flag is taken Byte by Byte during a xor instr. (as usual). The other half is got by dumping again the packed code before jumping to it and taking again the Bytes form the xor (with another address w.r.t. the first half)

### Race Conditions ###

+ **Pretty LSTAT**: Change the content of a file after a space equal to its previous size has been allocated into the stack to overflow and call an hidden function (win). Also, a bit of bash scripting and how to port it in python to use it in remote
+ **Underprivileged**: Symultaneous logout from two different threads logged in as the same user, how to deal with tokens for authentication on training.offensivedefensive.it server
+ **Swiss**: Similar to underprivileged, connect with two threads and make the second one execute the cmds before the first one finishes to create them

## Commands and other useful stuff ##

### Linux Tools ###

+ **Linux Task Manager**: `htop`
+ **Change file permissions**: `sudo chmod [+|-] [r|w|x] <file path>`
+ **Change file ownership**: `sudo chown <usr>:<group> <file path>`
+ **List errors**: `sudo dmesg` reports errors, faults and security failures
+ **File info**: `file <executable>` and `ls -l [opt <directory>]` (this one shows for each file present in the specified directory the file permissions, the number of links, owner name, owner group, file size, time of last modification, and the file or directory name)
+ **Runtime info**: [while the program is running]
  + _pid_: `ps aux | grep  <executable>`
  + _pages map_: `sudo cat /proc/<pid>/maps` [same as vmmap in gdb]
  + _symbols known to the kernel_: `sudo cat /proc/callsyms | grep <name of program you need>`
+ **Change ELF libraries**: [better to make a copy of the executable before, with `cp <old name> <new name>`]
  + _loader_: `patchelf --set-interpreter ~/<...>/<new ld file> <executable>`
  + _get needed_: `patchelf --print-needed <executable>`
  + _replace needed_: `patchelf --replace-needed <old needed lib> ~/<...>/<new needed lib> <executable>`
  + _ensure positions have not been changed_: `readelf -a <patched executable> | grep main` _VS_ `readelf -a <original executable> | grep main` [if they are not the same, you have to shorten the strings locating new libraries, moving them to the excutable directory]
+ **List Dynamic Dependencies**: `ldd <executable>`
+ **List gadgets**: `ropper --nocolor -f <executable> > gadgets.txt`
+ **List of gadgets spawning a shell**: `one_gadget ./libc-<version>`

### GDB + pnwdbg ###

+ **Run the binary**: `run` [does not stop execution until a breakpoint is reached] or `start` [sets a breakpoint to the first instruction and runs]
+ **Run with args**: `set args <arg1> <arg2> ...` + `run` or `run <arg1> <arg2> ...`
+ **Breakpoints**:
  + _Set breakpoints_: `break [<function + offset> | *<address>]` or `b [<function + offset> | *<address>]`
  + _Hardware breakpoints_: `hbreak  [<function + offset> | *<address>]`
  + _Watchpoints_: `watch [<function + offset> | *<address>]` breaks when the specified location is modified
  + _Info_: `info breakpoints` shows all the set breakpoits
  + _Delete breakpoints_: `clear` deletes all breakpoints, otherwise `del <n1> <n2> ...` deletes only breakpoints n1, n2, and so on...
+ **Virtual address breakpoints**: `brva <address>` very useful for PIE binaries [e.g. brva 0x6d42 sets a breakpoint at 0x6d42 + the offset of the elf]
+ **Execute instructions**: `si` step instruction, steps into the next instruction (if it is a function call steps into it); `ni` next instruction, executes the whole instr. (if it's a function call does not step into it)
+ **Virtual memory mapping**: `vmmap` shows each group of pages, its start and end virtual address, its size and its permissions (rwxp)
+ **Info about registers**: `info all-registers` prints all registrers content, and `info registers $<reg>` prints the content of the specified register
+ **Symbols**:
  + _Info about a symbol_: `info symbol <address>`
  + _Address of symbol_: `p &<symbol>`
  + _Content of symbol_: `p <symbol>`
+ **Print memory**: `x/<n><f> [<function> + <offset> | $<register> + <offset> | *<address> + <offset>]`, n is the number of elements to print, f is how to print (format):
  + _Hexadecimal Bytes_: `xb` or `bx`
  + _Hexadecimal half words_: `xh` or `hx` [2 Bytes, word]
  + _Hexadecimal words_: `xw` or `wx` [4 Bytes, dword]
  + _Hexadecimal giant words_: `xg` or `gx` [8 Bytes, qword]
  + _Instructions_: `i`
  + _Characters_: `c`
  + _Strings_: `s` (like chars)
+ **Stack**: `stack <len>` [len is the number of locations of the stack gdb has to print]
+ **Heap**: `heap` shows all the allocated and freed (but not reallocated) chunks
+ **Bins**: `bins` shows the dynamic list of fastbins, smallbins, largebins and the unsortedbin
+ **Change values**: `set [opt {<base type>}][$<reg> | *<addr> + <offset> | <sumbol>] = <value>`

### Python ###

+ **Python venv**:
  + _Creation_: `mkvirtualenv <venv name>`
  + _Activation_: `workon <venv name>`
  + _Deactivation_: `deactivate`
+ **Python Debug**: `python x.py DEBUG` (prints sent and recieved bytes)
+ ****: `cyclic(0x200)` to get 0x200 = 512 Bytes of cyclic chars, `cyclic -l <retrieved ret addr>` to get how many Bytes away is the srip
+ **Security check**: `checksec <executable>`
+ **Python type conversions**:
  + int == hex
  + _int -> char and bytes_: `chr(n)`
  + _int -> bytes_: `n.to_bytes(num_bytes, "little")` [num_bytes is 4 for 32 bit architectures and 8 for 64 bit ones]
  + _int -> string_: `str(n)`
  + string type has function `s.replace(<some string part>, <with something else>)`
  + string has no .contains() function, but the check is performed with `if <substr> in str: ...`
  + _int -> hex_: `hex(n)` [data does not change, it only prints the hexadecimal representation of the number]
  + _char -> int_: `ord(n)`
  + _bytes -> string_: `b.decode("utf-8")`
  + _string -> int_: `int(<str>)`
  + _string -> bytes_: `s.encode("utf-8")` or `bytes(s, "utf-8")` [also `b"<something>"`]
  + _string -> hex_: `b"<str>"[::-1].hex()` ([::-1] is to revert the string for little endian machines) returns a string without 0x before, so if you want an hexadecimal int you have to do `hex(int(b"<str>"[::-1].hex(), 16))`
  + _pack int_: `p32(n)` or `p64(n)`
  + _unpack int_: `u32(n)` or `u64(n)`
+ **Python ELF class**:
  + _constructor_: `elf = ELF(<executable>, [opt checksec = False])`
  + _base address_: `elf.address = <addr>`
  + _symbols_: `elf.symbols[<symbol name>]` !!Works only for some symbols
  + _plt_: `elf.plt[<symbol name>]` !!Works only for some symbols
  + _plt_: `elf.got[<symbol name>]` !!Works only for some symbols

### Kernel exploitation tools ###

+ **Unpack image**: in the same folder of the initramfs archive (initramfs.cpio.gz) run `./unpack_initramfs`
+ **Pack image**: in the same folder of the initramfs archive (initramfs.cpio.gz) run `./pack_initramfs`
+ **Convert a compressed Linux kernel image into an ELF**: `vmlinux-to-elf <compressed_kernel_image> <elf_kernel_name>`
+ **Debug with gdb**:
  + in the run.sh file add the option `-s` to enable remote connection on port 1234
  + run `sudo gdb`
  + digit the command `target remote :1234`
+ **upload exploit**: in a virtualenv where there is installed pwntools, run `ipython3` and then `%run upload_exploit.py initramfs/<xploit name> <challenge>.training.offensivedefensive.it 8080 --ssl -e /home/user/exploit` (some packets may be lost, so it may be necessary to run this again)

### Docker ###

+ **Compose**: after creating a docker-compose.yml file, run `docker compose up --build`
+ **List running containers**: `docker ps`
+ **Stop containers**: `docker stop <cont1> <cont2> ...`
+ **Log into a container**: `docker exec -it <container> <command>`, command is usually `/bin/bash`
+ **Fuzz a program**:
  + _Compile with address sanitizer_: `afl-gcc-fast AFL_USE_ASAN=1 <usual gcc args>` !!Beware of the actual folder, the one where the source code to compile is located and where will the executable be [e.g. if you are in the root of the container and you want to compile /challenge/chall.c into /challenge/challenge, either you have to move to /challenge before or you have to specify the path in the gcc command for thos two args]
  + _Fuzz_: after creating the example seeds in the /seed directory and compiling the source code, run `afl-fuzz -i /seed -o /output -- <executable path>`
  + _See fuzzer outputs_: `cd /output/default/crashes`, then `ls` (each crash info is stored into a file), and `cat <crash file name>` to read the report
  + _See asan results_: `./<path to executable> < <crash file name>`
