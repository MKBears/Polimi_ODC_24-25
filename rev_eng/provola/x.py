from libdebug import debugger
import string

# asks for a password, which is the flag => we have to brute force it

# apparently, without a callback funct, the execution does not stop at a bp
def hey(t, bp) :
    pass

flag = b'$'*37
max_counter = 0

# len(flag) = 38
for i in range(37) :
    # try a new char for position i until the bp count increases (=> the char is correct)
    for c in string.printable :
        new_flag = flag[:i] + c.encode() + flag[i+1:]   # python shit for substituting a single char of a string
        # print(new_flag)
        d = debugger("./provola")
        r = d.run()
        bp = d.bp(0x1a0f, file = "provola", callback = hey)
        d.cont()
        r.recvuntil(b"password.")
        r.sendline(new_flag)
        d.kill()

        # if bp.hit_count increased, the current char is correct, so we fix it and go on with the next one
        if bp.hit_count > max_counter :
            max_counter = bp.hit_count
            print("max_counter = " + str(max_counter))
            flag = new_flag
            print(b"New flag: " + flag)
            break
