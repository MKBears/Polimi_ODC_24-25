from libdebug import debugger

def unpack(t, b) :
    global content
    address = int.from_bytes(t.memory[t.regs.esp, 4], "little")
    size = int.from_bytes(t.memory[t.regs.esp + 4, 4], "little")
    new_content = t.memory[address, size*4, "absolute"]
    offset = address - base
    content = content[:offset] + new_content + content[offset + size*4:]

with open("./john", "rb") as f :
    content = f.read()

d = debugger(["./john", "flag{provola}"])
d.run()
base = d.maps.filter("binary")[0].base
d.bp(0x08049295, hardware=True, callback=unpack, file="absolute")

d.cont()
d.wait()
d.kill()

with open("unpacked", "wb") as f :
    f.write(content)