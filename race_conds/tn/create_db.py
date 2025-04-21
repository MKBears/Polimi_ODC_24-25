import random
import string

NAME_LEN = 31
NAMES = 50000

def random_string():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=NAME_LEN))

# create a set with 1000 unique random strings
random_strings = {random_string() for _ in range(NAMES)}

assert len(random_strings) == NAMES

# create a file with lines "str1 1", "str2 2", ...
with open('db.txt', 'w') as f:
    for i, s in enumerate(random_strings):
        f.write(f'{s} {i+1}\n')