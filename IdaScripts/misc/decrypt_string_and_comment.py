import idaapi
import idc

def get_string_bytes(addr, len):
    out = bytearray()
    for i in range(0, len):
        out.append(Byte(addr))
        addr += 1
    return out

def decrypt(string, len):
    out = ""
    ignoreNext = False
    for i in range(0, len):
        if ignoreNext:
            ignoreNext = False
            continue
        
        cur = chr(string[i] ^ 0x94)
        if cur == '\\':
            next = chr(string[i + 1] ^ 0x94)
            if next == '\\':
                ignoreNext = True
            elif next == 'r':
                cur = '\r'
                ignoreNext = True
            elif next == 'n':
                cur = '\n'
                ignoreNext = True
            elif next == 't':
                cur = '\t'
                ignoreNext = True
            elif next == '"':
                cur = '"'
                ignoreNext = True
        out += cur
    return out
    
DecryptStubVA = 0x10010D9D

segBase = idaapi.get_segm_base(idaapi.getseg(DecryptStubVA))

xref = idaapi.get_first_cref_to(DecryptStubVA)
while xref != BADADDR:
    pencrypted_string = xref - 4
    encrypted_string_va = idaapi.get_32bit(pencrypted_string)
    
    first_push_va = idc.FindBinary(pencrypted_string, idc.SEARCH_UP, '6A ??')
    if first_push_va == BADADDR:
        continue
    
    size = idaapi.get_byte(first_push_va + 1)
    enc_str = get_string_bytes(encrypted_string_va, size) 
    print 'XREF:', hex(xref),' pEnc:', hex(pencrypted_string), ' DEC:', decrypt(enc_str, size)
    idaapi.set_cmt(pencrypted_string - 1, decrypt(enc_str, size),0) 
    xref = idaapi.get_next_cref_to(DecryptStubVA, xref)