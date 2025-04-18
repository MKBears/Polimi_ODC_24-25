from libdebug import debugger
from pwn import *

def get_mem(t, b) :
    print(f"bp@{hex(b.address)} hit count: {b.hit_count}")

    if b.hit_count == 6 or b.hit_count == 12 :
        d.step()

        address = t.regs.rip
        offset = address - base
        len = 0x1488 - offset

        print(f"\tAddress: {hex(address)}")
        print(f"\tOffset: {hex(offset)}")
        print(f"\tLen: {len}\n")

        hidden = t.memory[address, len, "absolute"]
        new_content = content[:offset] + hidden + content[offset + len:]

        if b.hit_count == 6 :
            hidden_name = "hidden" + str(b.hit_count)
            unpacked_name = "unpacked" + str(b.hit_count)
        else :
            hidden_name = "hidden_final"
            unpacked_name = "unpacked_final"

        with open(hidden_name, "wb") as h :
            h.write(hidden)

        with open(unpacked_name, "wb") as r :
            r.write(new_content)

def get_rax1(t, _) :
    global rax
    rax = get_rax(t)

def get_rax2(t, _) :
    global rax
    global flag
    flag += xor(get_rax(t), rax).decode("utf-8")

def get_rax(t) :
    return t.regs.eax.to_bytes(1, "little")

def hijack(t, _) :
    t.mem[t.regs.rbp - 0x64, 4] = p32(0x1)
    t.step()

exe = "chall"

with open(exe, "rb") as f :
    content = f.read()

rax = ''
flag = ''

d = debugger(exe, escape_antidebug=True, kill_on_exit=False, aslr=False)
r = d.run()

base = d.maps.filter("binary")[0].base
bp = []
bp.append(d.bp(0x1365, file="binary", hardware=True, callback=get_mem))

d.cont()
r.recvuntil(b"enter!\n")
r.sendline(b"flag{y0ur_n3xt_s" + b'A'*0xf + b"}")

d.wait()

# gdb_event = d.gdb(open_in_new_process=False)
# gdb_event.join()

bp.append(d.bp(0x13EA, file="binary", hardware=True, callback=get_rax1))
bp.append(d.bp(0x13F9, file="binary", hardware=True, callback=get_rax2))

d.cont()
d.wait()
# d.kill()

print("First half of the flag: " + flag)

bp.append(d.bp(0x13EF, file="binary", callback=get_rax1))
bp.append(d.bp(0x13FE, file="binary", callback=get_rax2))

# d = debugger(exe, escape_antidebug=True, kill_on_exit=False, aslr=False)
# r = d.run()

# gdb_event = d.gdb(open_in_new_process=False)
# gdb_event.join()

d.cont()
d.wait()

print("Flag: " + flag)

# gdb_event = d.gdb(open_in_new_process=False)
# gdb_event.join()

# bp.append(d.bp(0x1365, file="binary", hardware=True, callback=get_mem))

# d.cont()
# d.wait()

# gdb_event = d.gdb(open_in_new_process=False)
# gdb_event.join()

d.kill()

# print(c1)
# print(c2)
# print(content)

# 0x1557 is call decode in main