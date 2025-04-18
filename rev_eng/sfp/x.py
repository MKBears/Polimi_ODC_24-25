from libdebug import debugger
import string

# exactly like provola, we have to crack the flag. However this time we have to face sleeps whch make the prcess of cracking way slower.
# Also, inserting a correct char makes the program skip some sections, so whe have to check if the hit_count is lower than the minimum saved value

LEN1 = 51
LEN2 = 17
flag = b'-' * (LEN1 + LEN2)
max_counter = LEN1 + LEN2

def callback(_, __):
    # This will automatically issue a continue when the breakpoint is hit
    pass

def on_enter_nanosleep(t, _):
    # This sets every argument to NULL to make the syscall fail
    t.syscall_arg0 = 0
    t.syscall_arg1 = 0
    t.syscall_arg2 = 0
    t.syscall_arg3 = 0

for i in range(LEN1 + LEN2) :
    for c in string.printable :
        new_flag = flag[:i] + c.encode() + flag[i+1:]
        # print(new_flag)
        count = 0
        d = debugger("./slow_provola")
        r = d.run()
        bp1 = [d.bp(0x1a55+j*0xa8, file = "slow_provola", callback = callback) for j in range(LEN1)]
        bp2 = [d.bp(0x3bc4+j*0x99, file = "slow_provola", callback = callback) for j in range(LEN2)]
        d.handle_syscall("clock_nanosleep", on_enter = on_enter_nanosleep)
        d.cont()
        r.recvuntil(b"password.\n")
        r.sendline(new_flag)
        r.recvline()
        d.kill()

        for j in range(LEN1) :
            # print(bp1[j], ": ", bp1[j].hit_count)
            count += bp1[j].hit_count

        for j in range(LEN2) :
            # print(bp2[j], ": ", bp2[j].hit_count)
            count += bp2[j].hit_count

        # print(count)

        if count < max_counter :
            max_counter = count
            print("max_counter = " + str(max_counter))
            flag = new_flag
            print(b"New flag: " + flag)
            break
        