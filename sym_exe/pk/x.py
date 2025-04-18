import z3

# create symbolic input (although each position of the array is a char, we use 32 bits to store it in order to avoid overflow)
a1 = [z3.BitVec(f"c_{i}", 32) for i in range(29)]

solver = z3.Solver()

for i in range(29) :
    # this way, all the caracters are printable and passable to the applocation
    solver.add(a1[i] >= 0x20, a1[i] < 0x7f)

# check_01
solver.add(a1[5] == 45, a1[11] == 45, a1[17] == 45, a1[23] == 45)

# check_02
solver.add((a1[1] - 48) <= 9)
solver.add((a1[4] - 48) <= 9)
solver.add((a1[6] - 48) <= 9)
solver.add((a1[9] - 48) <= 9)
solver.add((a1[15] - 48) <= 9)
solver.add((a1[18] - 48) <= 9)
solver.add((a1[22] - 48) <= 9)
solver.add((a1[27] - 48) <= 9)
solver.add((a1[28] - 48) <= 9)

# check_03
solver.add(a1[4] - 48 == 2 * (a1[1] - 48) + 1, a1[4] - 48 > 7, a1[9] == a1[4] - (a1[1] - 48) + 2)

# check_04
solver.add((a1[27] + a1[28]) % 13 == 8)

# check_05
solver.add((a1[27] + a1[22]) % 22 == 18)

# check_06
solver.add((a1[18] + a1[22]) % 11 == 5)

# check_07
solver.add((a1[22] + a1[28] + a1[18]) % 26 == 4)

# check_08
solver.add((a1[1] + a1[4] * a1[6]) % 41 == 5)

# check_09
solver.add((a1[15] - a1[28]) % 4 == 1)

# check_0a
solver.add((a1[22] + a1[4]) % 4 == 3)

# check_0b
solver.add(a1[20] == 66, a1[21] == 66)

# check_0c
solver.add((a1[6] + a1[15] * a1[9]) % 10 == 1)

# check_0d
solver.add((a1[15] + a1[4] + a1[27] - 18) % 16 == 8)

# check_0e
v1 = z3.If(a1[28] < a1[9], z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
solver.add(((v1 + a1[28] - a1[9]) & 1) - v1 == 1)

# check_0f
solver.add(a1[0] == 77)

check = solver.check()
print(check)

for i in range(29) :
    print(chr(solver.model()[a1[i]].as_long()), end = '')

print()