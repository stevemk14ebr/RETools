bytes = bytearray()
for i in range(0, 0x1000):
    byt = Byte(here() + i)
    bytes.append(byt)

with open(".\dump", "wb") as f:
    f.write(bytes)