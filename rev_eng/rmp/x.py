from libdebug import debugger

# enhanced version of revmem: asks for the flag and compares it with its crypted version (before the comparation it is decrypted, so we take it directly form memory right before the comparation, even sending a completely random string)

# rax contains a pointer to the decrypted flag
def getKey(t, bp) :
    print(t.memory[t.regs.rax, 0x21])
    pass

# makes debug symbol check fail (avoids anti-debugging)
def bypass(t, bp) :
    t.regs.rax = 0
    pass
    
flag = "A" * 32
d = debugger( ["./revmemp", flag], escape_antidebug = True )
r = d.run()
bp0 = d.bp( 0x1342, file = "revmemp", callback = getKey )
bp1 = d.bp( 0x11CE, file = "revmemp", callback = bypass )
d.cont()
d.kill()