from pwn import *

functs = ["data", "prepareinput", "check"]

for f in functs :
    c = remote("dynamism.training.offensivedefensive.it", 8080, ssl=True)
    s = struct.pack('Q', int(len(f)))
    c.send(s)
    print(f"Size of {f} sent ({s})")
    c.send(f.encode("utf-8"))
    print(f"{f} sent")
    payload = c.recv()
    print("Payload recieved")

    with open(f, "wb") as f :
        f.write(payload)

    print(f"Created file {f}")
    c.close()

# b 0x1A48
# b [rdx + 0x2c] => r10, r11