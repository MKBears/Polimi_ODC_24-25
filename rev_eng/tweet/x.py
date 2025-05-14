from libdebug import debugger
import string

# The program asks for a string and returns. The only way to access the checks is to overflow the input buffer, overwriting the canary, to make the program call __stack_chk_fail, which has been modified to check the flag.
# The check is simple: it incrementally hashes with MD5 the input, adding one character each iteration and comparing the result with the string pointed by the corresponding position in the vector elon_musk_tweet.
# The comparison is made through strcmp, so the result may be both positive and negative. The results are summed together in a variable, so it may happen that the final result is 0 (and the program prints "You've tweeted like Elon Musk! Good job! Go and submit the flag!") even if the flag is not correct. Thus it's crucial to continue the cracking even if the program told you that you've won.

def get_rax(t, _):
    global num

    if t.regs.rax != 0:
        num += 1

chars = string.ascii_letters + string.digits + string.punctuation
flag = b'flag{' + b'_' * 60 + b'}'
min = 61
finish = False

for i in range(5, 65):
    prefix = flag[:i]
    suffix = flag[i+1:]

    for c in chars:
        num = 0
        b = c.encode('utf-8')
        msg = prefix + b + suffix
        d = debugger('./tweet', escape_antidebug=True)
        r = d.run()
        bp = d.bp(0x135F, file='tweet', callback=get_rax)
        d.cont()
        r.recvuntil(b'Insert your tweet: \n')
        r.sendline(msg)

        try:
            print(r.recvline().decode('utf-8'))
        except:
            pass
        finally:
            if num < min:
                print(f'Not passed checks: {num}')
                print('New Flag: ' + msg.decode('utf-8'))
                flag = msg
                min = num
                d.kill()
                break

            d.kill()
