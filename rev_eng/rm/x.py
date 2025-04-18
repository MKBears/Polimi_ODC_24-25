from pwn import *

# asks for the flag in input

cypher = [
    0x66,
    0x0A,
    0x0D,
    0x6,
    0x1C,
    0x0F,
    0x1C,
    0x1,
    0x1A,
    0x2C,
    0x28,
    0x16,
    0x12,
    0x2C,
    0x3E,
    0x0F,
    0x31,
    0x3A,
    0x4,
    0x12,
    0x0A,
    0x26,
    0x2D,
    0x17,
    0x13,
    0x13,
    0x17,
    0x1,
    0x16,
    0x18,
    0x6A,
    0x17
]

# the first char of the flag is the first byte of cypher
flag = xor(cypher[0], 0).decode("utf-8")

# all the other chars of the flag are the xor of current cypher position with last computed flag char
for i in range(1, 30) :
    flag += xor(cypher[i], flag[i-1]).decode("utf-8")

print(flag)