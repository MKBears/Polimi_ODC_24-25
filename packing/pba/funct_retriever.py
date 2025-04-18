from libdebug import debugger

decode_start = 0x11b9
decode_end = 0x137E

d = debugger("./chall")
r = d.run()

content = bytes(0)
i = 0
finish = False

while not finish:
    content += d.memory[decode_start + i, 0x10, "binary"]

    if decode_start + i >  decode_end :
        finish = True

    i += 8

d.kill()

with open("decode", "wb") as f :
    f.write(content)