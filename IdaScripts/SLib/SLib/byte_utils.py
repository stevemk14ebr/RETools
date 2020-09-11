def hexstr_tobytes(s):
    return bytes.fromhex(s)
    
def str_tobytes(s):
    return s.encode()

def bytes_tohexstr(byts, escape = False):
    if escape:
        return "{}".format(''.join('\\x{:02x}'.format(b) for b in byts))
    else:
        return "{}".format(''.join('{:02x}'.format(b) for b in byts))