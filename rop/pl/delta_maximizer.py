def magic_formula(n:int):
    return ((4*n + 23) // 16) * 16

max = 0
index = -1

for i in range(500):        # 500 is the maximum to avoid overflowing into a non-writable page
    n_bytes = magic_formula(i)
    n_slots = n_bytes // 8
    delta = n_slots - i
    print(f'{i}:\t{n_bytes} Bytes\t=> {n_slots} slots\t=> delta = {delta}')

    if delta > max:
        max = delta
        index = i

print(f'max: {max} for index {index}')
n_bytes = input('How many Bytes do you need? ')
n_bytes = int(n_bytes)

if n_bytes > 0:
    n_slots = (n_bytes/16 - 1) * 4 + 2
    approx = n_slots // 1

    if n_slots - approx > 0:
        n_slots = approx + 1

    print(f'You need {n_slots} slots ({magic_formula(n_slots)} Bytes)')

n_slots = input('For which number of slots do you need to calculate the corresponding number of Bytes? ')
n_slots = int(n_slots)
n_bytes = magic_formula(n_slots)

if n_bytes < 0:
    n_bytes +=  2**64   # 2's complement

print(f'There will be allocated {hex(n_bytes)} Bytes')

# From the result we can see that inserting 0 when asked "How many would you add?" gives the maximum number of surplus slots: 2. Then that "magic" formula eats the more slots the higher the inserted number is. Only 2 stack locations of overflow does not allow us to overwrite the srip
# This is true until you request up to 4095 slots, then the & leaves only the last three nibbles. So, if we ask for 1019 slots => 0x1000 & 0xfff = 0 => the allocated buffer is 0 Bytes long, but we can add up to 1019 numbers.
# In fact the program checks if the number of Bytes (let's say nb) is more than 0xfff, if so it decrements the stack pointer by nb & 0xfffffffffffff000, but 0x1000 at a time.