import z3
from libdebug import debugger
import string
from decimal import Decimal

def cont(_, __) :
    pass

def strunz(_, __) :
    print("Struuuuuunz")
    pass

def f1(_, __) :
    print(f"0 on {hex(0x080496F1)}")
    pass

def f2(_, __) :
    print(f"0 on {hex(0x0804965F)}")
    pass

def f3(_, __) :
    print(f"0 on {hex(0x080495AF)}")
    pass

flag_len = 33
missing_len = flag_len - 6      # flag length - len("flag{}")
# flagset = string.ascii_letters + string.digits + '_' + '-'
flagset = string.printable
found = ''
# dict = []
hit = 1
print("Brute forcing characters from index 5 to 21...")

for i in range(5, 22) :
    for c in flagset :
        if i != 17 or ord(c)&1 != 0:
            f = "flag{" + found + c + "A"*(missing_len - 1) + '}'
            # print(f)
            d = debugger(["./neutralised", f])
            r = d.run()

            if i < 10 :
                bp = d.bp(0x08049385, hardware=True, callback=cont)
            elif i == 10 :
                bp = d.bp(0x080496F1, hardware=True, callback=cont)
            elif i != 21 :
                bp = d.bp(0x08049491, hardware=True, callback=cont)
                # s = d.bp(0x0804967C, hardware=True, callback=strunz)
            else :
                bp = d.bp(0x0804965F, hardware=True, callback=cont)

            d.cont()
            r.recvline()
            d.kill()
            # print("#Hits: " + str(bp.hit_count))

            if i != 10 and i != 21 :
                if (bp.hit_count > hit) :
                    last_good = c
                    # dict += (c, i)
                    found += c
                    # print(f"Eureka [{i}]")
                    hit += 1
                    missing_len -= 1
                    print(f"Found character #{i}: {c}")
                    break
            else :
                if bp.hit_count == 0 :
                    # dict += (c, i)
                    # last_good = c
                    found += c
                    hit = 1
                    missing_len -= 1
                    print(f"Found character #{i}: {c}")
                    break

    # found += last_good 

# print("Found: " + found)
# print(dict)

print("\nStarting solver...")

flag = [z3.BitVec(f"c_{i}", 32) for i in range(flag_len)]
solver = z3.Solver()

for i in range(flag_len) :
    solver.add(flag[i] >= 0x20, flag[i] < 0x7f)

solver.add(
    flag[0] == ord('f'),
    flag[1] == ord('l'),
    flag[2] == ord('a'),
    flag[3] == ord('g'),
    flag[4] == ord('{'),
    flag[flag_len - 1] == ord('}')
    )

# for j in range(5, 11) :
#     i = Decimal(j)
#     c0 = i**Decimal(5) * Decimal(0.5166666688)
#     c1 = c0 - i**Decimal(4) * Decimal(8.125000037)
#     c2 = i**Decimal(3) * Decimal(45.83333358) + c1
#     c3 = c2 - i**Decimal(2) * Decimal(109.8750007) + i * Decimal(99.65000093) + Decimal(83.99999968)
#     c = int(c3) % 0x80
#     print(hex(c))
#     solver.add(flag[j] == c)

# solver.add((flag[17] & 1) != 0) useless after getting out of the 5th check

# found = "packer-4a3-1337&-"

for i in range(len(found)) :
    solver.add(flag[i + 5] == ord(found[i]))

vec = [0x0B, 0x4C, 0x0F, 0x0, 0x1, 0x16, 0x10, 0x7, 0x9, 0x38, 0x0]
# print(vec)

for i in range(1, 11) :
    # print(f"Setting constraint on chars at index {i + 20} and {i + 21}")
    solver.add((vec[i] ^ flag[i + 20]) == flag[i + 21])

check = solver.check()
print(check)
f = ''

for i in range(flag_len) :
    f += chr(solver.model()[flag[i]].as_long())

print('\t' + f)
print("\nChecking result on true packer...")

d = debugger(["./john", f])
r = d.run()
bp = [d.bp(0x080496F1, hardware=True, callback=f1), d.bp(0x0804965F, hardware=True, callback=f2), d.bp(0x080495AF, hardware=True, callback=f3), d.bp(0x08049546, hardware=True, callback=cont)]
d.cont()
r.recvline()
d.kill()
print(f"{hex(0x080496F1)} (1st ret 0) hit {bp[0].hit_count} times")
print(f"{hex(0x0804965F)} (2nd ret 0) hit {bp[1].hit_count} times")
print(f"{hex(0x080495AF)} (3rd ret 0) hit {bp[2].hit_count} times")
print(f"{hex(0x08049546)} hit {bp[3].hit_count}/12 times")
print("\nDone")

# flag{packer-4a3-1337&-annoying_J}
# 0x08049546