# Completely unrolling a round of xhashe(j, 4, 0), maybe it cound be useful for creating the model for z3 (spoiler, it wouldn't)

def xhashe(i):
    if i == 0:
        return '0'
    else:
        prev = xhashe(i-1)
        res = 'precomputed_table['

        if prev != '0':
            res += 'HIBYTE(' + prev + ')^'

        # res += f'argv[1][j+{i-1}]]'
        res += 'vec[j' 
        
        if i != 1:
            res += '+' + str(i-1)
            
        res += ']]'

        if prev != '0':
            # res +=  '^' + prev + '<<8'
            res += '^' + 'LShR(' + prev + ', 8)'

        return res

# Printing the extended formula for one run of xhashe(j, 4, 0)
print(xhashe(4))