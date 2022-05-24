new = [0x00, 0x00] # whatever

base = 0x140000000
for i in range(0, len(new)):
    patch_byte(base + i, new[i])