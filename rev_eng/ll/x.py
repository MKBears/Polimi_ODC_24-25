from libdebug import debugger

# starts from a precomputed "hashed" version of a fixed license (obviously not the one we want) and outputs its serial number

def substitute(t, bp) :
    t.regs.rax = license[0]     # every time an "hashed" part of the license has to be passed to the rax, substitute it with the first 4 bytes of the license we want to genereate a serial number from

    if bp.hit_count % 28 == 0 :
        license.pop(0)          # every 28 bp hits, the program goes to the next 4 bytes of the license

    pass

# prints the produced 4 bytes of the serial number, separating them with a '-'
def magic(t, bp) :
    print(str(hex(t.regs.rax)).replace("0x", ''), end = '-')
    pass

# prints the last 4 bytes of the serial number, ending the flag with '}'
def magix(t, bp) :
    print(str(hex(t.regs.rax)).replace("0x", '') + '}')

# fai partire e sostituisci la license a runtime, il serial code verra' generato automaticamente
license = [0x726cfc2d, 0x26c6defe, 0xdb065621, 0x99f5c7d0, 0xda4f4930]
# license = [0xf3ed47e2, 0x6e4de24a, 0x41498194, 0x5c7da2db, 0x1ac93d5]
# int_license = [int.from_bytes(license[i], "little") for i in range(5)]
# print(int_license)

d = debugger( "./leaked_license" )
d.run()

bp0 = d.bp( 0x12EE, file = "leaked_license", callback = substitute )
bp1 = d.bp( 0x140C, file = "leaked_license", callback = magic )
bp2 = d.bp( 0x1435, file = "leaked_license", callback = magix )

# bpx = d.bp( 0x1213, file = "leaked_license", callback = substitute )
# bpy = d.bp( 0x1217, file = "leaked_license", callback = magic )

print("flag{", end = '')
d.cont()
d.kill()

# flag{a43a6199-dbf6bdd7-838f2787-6257b482-c32a8c10}