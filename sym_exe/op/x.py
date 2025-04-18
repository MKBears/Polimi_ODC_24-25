import z3

symbols = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
values = [z3.BitVec(f"c_{i}", 32) for i in range(30)]
solver = z3.Solver()

for i in range (30) :
    solver.add(values[i] >= 0x00, values[i] < 0x3d)

solver.add(-26 * values[14] + 4 * values[10] + values[8] + 6 * values[0] - 10 * values[18] == -891,
       -10 * values[17]
       + -70 * values[12]
       + -70 * values[6]
       + values[1]
       - values[2]
       - 4 * values[7]
       - 10 * values[23]
       - values[26]
       - values[28] == -4135,
       values[26]
       + 10 * values[17]
       + 4 * values[7]
       + 70 * values[6]
       + values[2]
       + 70 * values[12]
       + 10 * values[23]
       + values[28] == 4183,
       27 * values[14] + 4 * (3 * values[3] + values[7]) - 12 * values[29] == 1250,
       -72 * values[21] + -10 * values[18] + values[14] - (6 * values[4] - values[8] + values[13]) + values[24] == -3687,
       values[24]
       + 10 * values[17]
       + 4 * values[7]
       + 70 * values[6]
       + values[0]
       - values[1]
       + 5 * values[5]
       + 70 * values[12]
       - 6 * values[13]
       - values[14]
       + 10 * values[18]
       - 72 * values[21]
       + 10 * values[23]
       + values[26] == 1423,
       2 * values[14]
       + values[13]
       + 70 * values[12]
       + 4 * values[10]
       + 70 * values[6]
       - 10 * values[0]
       - 20 * values[18]
       + 72 * values[21]
       - values[24]
       - 10 * values[29] == 4738,
       values[7] == 5,
       values[8] == 21,
       values[14] + values[9] - 6 * values[4] - 10 * values[18] == -450,
       values[14] + 4 * values[10] - 10 * values[18] == -348,
       72 * values[21]
       + 9 * values[17]
       + 7 * values[11]
       + 69 * values[6]
       + -values[1]
       - values[3]
       + 66 * values[12]
       - 3 * values[14]
       + 10 * values[23]
       + values[26]
       - values[27]
       - values[28]
       + values[29] == 7181,
       -10 * values[18]
       + values[13]
       + values[7]
       + 3 * values[12]
       + values[14]
       - values[15]
       + 72 * values[21]
       - values[24]
       + values[25] == 2923,
       73 * values[13]
       + 504 * values[12]
       + 72 * values[7]
       + 504 * values[6]
       + 216 * values[14]
       - values[19]
       + 72 * values[23]
       - values[24]
       + 72 * values[25] == 35723,
       values[14] == 34,
       values[15] - values[7] - values[25] == 12,
       -72 * values[23]
       + -10 * values[18]
       + 8 * values[16]
       + -72 * values[13]
       + values[8]
       + -72 * values[7]
       + 6 * values[0]
       - 504 * values[6]
       + 4 * values[10]
       - 504 * values[12]
       - 242 * values[14]
       - 8 * values[15]
       - 72 * values[25] == -36811,
       90 * values[17] + 630 * (values[6] + values[12]) + 90 * values[23] == 36270,
       -72 * values[21] + -values[13] - values[14] + 10 * values[18] + values[24] == -2836,
       values[19] - values[13] + values[24] == 61,
       values[24] + values[19] + 3 * values[3] - values[13] + 9 * values[20] - 3 * values[29] == 589,
       -30 * values[18]
       + 3 * values[14]
       + 3 * values[13]
       + 2 * (-6 * values[4] + values[9])
       + 216 * values[21]
       - 3 * values[24] == 8360,
       6 * values[4] - values[12] + values[22] == 131,
       7 * (values[12] + values[6]) - 27 * values[14] + values[23] == -564,
       values[26]
       + values[24]
       + 10 * values[23]
       - (values[13]
        + -70 * values[12]
        - (4 * values[7]
         + values[2]
         - values[1]
         + 70 * values[6])
        - 10 * values[17])
       + values[28] == 4163,
       6 * values[14]
       + -68 * values[12]
       + -69 * values[6]
       + values[1]
       + values[3]
       - 6 * values[4]
       + values[7]
       - values[8]
       - 9 * values[17]
       - 72 * values[21]
       - values[22]
       - 10 * values[23]
       + values[25]
       - values[26]
       + values[27]
       + values[28]
       - values[29] == -7030,
       values[27]
       + -72 * values[21]
       + 411 * values[17]
       + 2871 * values[6]
       + values[3]
       - 41 * values[1]
       + 2871 * values[12]
       + 3 * values[14]
       + 410 * values[23]
       + 41 * values[26]
       + values[28]
       - values[29] == 162666,
       80 * values[18]
       + -9 * values[17]
       + -5 * values[14]
       + -69 * values[12]
       + values[1]
       + 48 * values[4]
       - 69 * values[6]
       - 8 * values[8]
       + 8 * values[13]
       + 504 * values[21]
       - 10 * values[23]
       - 8 * values[24]
       - values[26]
       + values[27] == 22429,
       -72 * values[21]
       + 3 * values[14]
       + -69 * values[6]
       + values[3]
       + values[1]
       - 69 * values[12]
       - 9 * values[17]
       - 10 * values[23]
       - values[26]
       + values[27]
       + values[28]
       - values[29] == -7014,
       values[29] == 24)

check = solver.check()
print(check)

for i in range(30) :
    print(symbols[solver.model()[values[i]].as_long()], end = '')

print()