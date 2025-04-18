from libdebug import debugger
import string

def cont(t, br) :
    # print(f"Hit on {hex(br.address-base)}")
    pass

exe = "ocheck"
len = 39
found = 5
cracked = ''

for i in range(len - found) :
    for c in range(0x20, 0x7f) :
        flag = "flag{" + cracked + chr(c) + 'a' * (len - found - 2) + '}'
        # flag = 'A' * 39
        # print(flag)
        # flag = "flag{__________________________________}"

        d = debugger(exe, escape_antidebug=True)
        r = d.run()

        bad1 = d.bp(0x263f, file="binary", callback=cont)
        strange = d.bp(0x239f, file="binary", callback=cont)
        bad2 = d.bp(0x24be, file="binary", callback=cont)
        bp = [
        d.bp(0x2694, file="binary", callback=cont),
        d.bp(0x25e5, file="binary", callback=cont),
        d.bp(0x22e1, file="binary", callback=cont),
        d.bp(0x27b2, file="binary", callback=cont),
        d.bp(0x2210, file="binary", callback=cont),
        d.bp(0x2758, file="binary", callback=cont),
        d.bp(0x245d, file="binary", callback=cont),
        d.bp(0x2866, file="binary", callback=cont),
        d.bp(0x2403, file="binary", callback=cont),
        d.bp(0x28c0, file="binary", callback=cont),
        d.bp(0x2277, file="binary", callback=cont),
        d.bp(0x2531, file="binary", callback=cont),
        d.bp(0x258b, file="binary", callback=cont),
        d.bp(0x2340, file="binary", callback=cont),
        d.bp(0x26ee, file="binary", callback=cont),
        d.bp(0x280c, file="binary", callback=cont)
        ]

        base = d.maps.filter("binary")[0].base
        d.cont()
        r.recvuntil(b"it!\n")
        r.send(flag.encode("utf-8"))

        r.recvline()
        # d.wait()

        k = 0

        # print(f"Bad: {bad.hit_count}")

        # if bad == 0 :
        # print("Bad1 : ", bad1.hit_count)
        # print("Bad2 : ", bad2.hit_count)

        for b in bp :
            print(f"{hex(b.address - base)}: {b.hit_count}")
            k += b.hit_count

        if (k > found) :
        # if (bad1.hit_count == 0) :
            found += 1
            # cracked += chr(c)
            print("Found " + flag)
            print(f"Total: {k}")
            print("Bad1 : ", bad1.hit_count)
            print("Bad2 : ", bad2.hit_count)
            break

        d.kill()
        # input("wait")