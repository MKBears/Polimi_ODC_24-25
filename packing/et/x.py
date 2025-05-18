from libdebug import debugger

# The program allocates three memory pages and them uses them to store the functions to read and check the flag.
# The difficult part is that the function which really writes on the new pages is a signal handler (in this case for SIGSEGV), so we have to let the signal be forwarded from the debugger to the program thread.
# Then some decryption magic is performed, but it's useless to understand it to get the flag: we simply have to wait the read instruction, get the needed part of the flag from the next one, and send it.

# The instruction just next to the read syscall loads an immediate to r13, which is exactly the flag part that is going to be checked
def get_flag_piece(t, _):
    global flag
    global r
    f = t.memory[t.regs.rip + 4, 8]
    flag += f
    # print(flag) -> debug
    r.send(f)

# The signal has to be forwarded to the program thread and the debugger has to go on with the xecution
def proceed(t, _):
    # print('SIGSEGV') -> debug
    pass

d = debugger('./estatea')
r = d.run()

d.catch_signal(11, callback=proceed)
addresses = []

# Getting the pages where there will be written the check functions
for i in range(3):
    d.step_until(0x157C, file='binary')     # After mmap in main
    addresses.append(d.regs.rax)
    # print('Added page address ' + hex(d.regs.rax)) -> debug

# Addresses of the read syscalls (got with gdb, one at a time)
addresses[0] += 0x2a
addresses[1] += 0x19
addresses[2] += 0x19

b = [d.bp(addresses[i], True, callback=get_flag_piece) for i in range(3)]
flag = b''

d.cont()
print(r.recvline().decode())
print(flag.decode())
