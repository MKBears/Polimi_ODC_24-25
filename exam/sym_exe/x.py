import z3
from pwn import *

len = 9

grid = [z3.BitVec(f"d_{i}", 32) for i in range(len * len)]      # Sudoku
s = [z3.BitVec(f"s_{i}", 32) for i in range(len * len)]         # Squares

solver = z3.Solver()

for i in range(len * len) :
    solver.add(grid[i] > 0, grid[i] < 10)

# all the cells of a row have different digits
for i1 in range(len) :
    for j1 in range(len - 1) :
        for c1 in range(j1 + 1, len) :
            # print(f"grid[{len * i1 + j1}] != grid[{len * i1 + c1}]")
            solver.add(grid[len * i1 + j1] != grid[len * i1 + c1])

# all the cells of a column have different digits
for i2 in range(len) :
    for j2 in range(len - 1) :
        for c2 in range(j2 + 1, len) :
            # print(f"grid[{len * j2 + i2}] != grid[{len * c2 + i2}]")
            solver.add(grid[len * j2 + i2] != grid[len * c2 + i2])

# all the cells of a square have different digits
for i3 in range(len) :
    for j3 in range(len) :
        # print(27 * int(i3 / 3) + 9 * int(j3 / 3) + 3 * (i3 % 3) + j3 % 3, end=' ')
        solver.add(s[len * i3 + j3] == grid[27 * int(i3 / 3) + 9 * int(j3 / 3) + 3 * (i3 % 3) + j3 % 3])


for i4 in range(len) :
    for j4 in range(len - 1) :
        for c4 in range(j4 + 1, len) :
            # print(f"s[{len * i4 + j4}] != s[{len * i4 + c4}]")
            solver.add(s[len * i4 + j4] != s[len * i4 + c4])


check = solver.check()
print(check)

sol = ""
exe = "./kudos2u"
COMMANDS = """
brva 0x12C9
"""
# c = gdb.debug(exe, gdbscript = COMMANDS)
c = process(exe)

for i in range(len) :
    for j in range(len) :
        print(chr(solver.model()[grid[len * i + j]].as_long() + 48), end = '')
        sol += chr(solver.model()[grid[len * i + j]].as_long() + 48)

    print()

# c.send(sol.encode("utf-8"))
for i in range(len * len) :
    try :
        c.send(b'0')
    except :
        print(f"Exited at iteration {i}")
        break

c.interactive()

# 149735268876924315523681479368279154714358692952146783481563927295417836637892541