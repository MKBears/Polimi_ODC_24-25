# from libdebug import debugger

# def step_funct(t, _) :
#     rdx = t.regs.rdx
#     print(f"rdx: {hex(rdx)}")

#     for i in range(0x10) :
#         t.step()
#         rip = t.regs.rip
#         print(f"rip: {hex(rip)}")

#         r10 = t.regs.r10
#         r11 = t.regs.r11
#         print(f"rip - rdx = {hex(rdx - rip)}")

#         print(f"""r10:
# \tint: {r10}
# \thex: {hex(r10)}
# \tstr: {r10.to_bytes(8, "little")}""")
    
#         print(f"""r11:
# \tint: {r11}
# \thex: {hex(r11)}
# \tstr: {r11.to_bytes(8, "little")}""")
    
#     input("Press any key to go on")
    
# exe = "dynamism"

# d = debugger([exe, 'A'*9])
# r = d.run()
# bp1 = d.bp(0x1A48, hardware=True, callback=step_funct)

# d.cont()
# d.wait()
# d.kill()

# Way simpler to do it manually with gdb

from pwn import xor

# As usual it requires the flag as argument, then it connects to the upstream server and asks for 3 functions (executing them one at a time before asking for the next one):
# 1. data: places the key and the encrypted flag into memory
# 2. prepareinput: encrypts the provided argument with the key
# 3. check: checks if the encrypted input is the same as the encrypted flag

# The steps to solve it were:
# 1. get the three functions from the server and save them into three files (retriever.py)
# 2. analyze only prepareinput and check (data was almost impossible to do this way) each at a time with ghidra (ida requires a full ELF file)
# 3. execute ./dynamism with gdb and get the data vector (data[0] = key, data[0:] = encrypted flag)
# 4. understand that flag[0:7] = data[0] ^ data[1]
# 5. understand that flag[0+i*8:7+i*8] = data[0] ^ data[i + 1] foreach i in [1, 8]

flag = ''

data = [
    0x4827c3baaa35c7cc,
    0x2648a0c1cd54abaa,
    0x3c46afcfde54b5ab,
    0x3178e2e5d05ba8a5,
    0x3c78b7d5cd6ab2a3,
    0x1740a2d6cc6aa2a4,
    0x265ea7e5c75ab5aa,
    0x3c4e9cc9cb4298ed,
    0x35189cded854af93
]

for i in range(1, 9) :
    flag += xor(data[0].to_bytes(8, "little"), data[i].to_bytes(8, "little")).decode("utf-8")

print(flag)