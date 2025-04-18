from libdebug import debugger

# d = debugger(["./challenge", <other args>])
# d.run() starts gdb
#
# d = debugger()
# d.attach("")
#
# d.memory[0x1337] accesses memory at the ABSOLUTE address 0x1337 (if it does not infet that it is an offset)
# d.memory[0x1337, 10, "binary"] accesses the relative address 0x1337 w.r.t. the binary start
# => 0x1337 is considered as an offset

def provolino(t, bp) :
    print(t.regs.rax)

def force_fail(t, hs) :
    t.syscall_number = 0
    t.syscall_arg0 = 0
    t.syscall_arg1 = 0
    t.syscall_arg2 = 0
    t.syscall_arg3 = 0

def mod_ret_val(t, hs) :
    t.regs.rax = 0x10

d = debugger("./provola")
r = d.run()
bp = d.bp(0x1a55, file = "provola", callback = provolino)
hs = d.handle_syscall("read", on_enter = force_fail, on_exit = mod_ret_val)
cs = d.catch_signal(11, callback = provolino)
d.hijack_signal(11)
d.hijack_syscall("read", "write")
d.cont()
d.wait()

if bp.hit_on(d) :
    d.gdb()

print(r.recvline())
r.sendline(b"Provolone")

if bp.hit_on(d.threads[0]) :
    print(d.regs.rax)
    d.cont()

if hs.hit_on_enter(d) :
    print("read")
    d.cont()

if hs.hit_on_exit(d) :
    print("read")
    d.cont()

d.wait()
d.kill()