from pwn import xor

# key += input[i]
# magic1 = [input[0] + key, magic1[0] + input[1] + magic1[1] + input[2] + ...]

magic0 = [0x1B, 0x51, 0x17, 0x2A, 0x1E, 0x4E, 0x3D, 0x10, 0x17, 0x46, 0x49, 0x14, 0x3D]
kkk = "babuzz"
magic1 = [0xEB, 0x51, 0xB0, 0x13, 0x85, 0xB9, 0x1C, 0x87, 0xB8, 0x26, 0x8D, 0x07]
key = 187

half1 = xor(magic0, kkk+kkk).decode("utf-8")
half2 = chr((magic1[0] - key) % 256)

for i in range(1, 12) :
    half2 += chr((magic1[i] - magic1[i-1]) % 256)

print("flag{" + half1 + half2 + "}")
