from pwn import xor

f = open("./john", "rb")
address = 0x804970e
content = f.read()
base = 0x8048000
keys = [b"\x04\x03\x02\x01", b"\x40\x30\x20\x10", b"B00B", b"DEAD", b"\xff\xff\xff\xff"]

def unpack(address, size, key) :
    unpacked = b''
    offset = address - base

    for i in range(0, size*4, 4) :
        unpacked += xor(content[offset+i:offset+i+4], key)

    return unpacked

key = keys[address % 5]
unpacked = unpack(address, 83, key)

with open("john_unpacked", "wb") as f:
    new_content = content[:address-base] + unpacked + content[address-base+len(unpacked):]
    f.write(new_content)

# After executing this script, we can open the file john_unpacked in ida and analize it

# An alternative of unpacking it with this script is to open the malware with gdb and make a breakpoint to the start of the packed function, so when the debugger stops, we can print the next instructions (x/100i 0x804970e) and then dump them to a file (dump memory dump.txt 0x804970e 0x804970e+83*4 ~ dump memory file initial_addr final_addr)