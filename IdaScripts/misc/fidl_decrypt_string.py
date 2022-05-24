import itertools
from idaapi import *
from idautils import *
from idc import *
import ida_hexrays
import FIDL.decompiler_utils as du
import base64

def read_ida_string(ea):
    print(ea)
    s = ''
    idx = 0
    b = ida_bytes.get_byte(ea)
    while b != 0:
        s += chr(b)
        idx += 1
        b = ida_bytes.get_byte(ea + idx)
    return s
    
def get_func_start(xref):
    try:
        if len(get_func_name(xref.frm)) > 0:#get_func_start will crash IDA without this additional check
            if xref.iscode:
                func = get_func(xref.frm)
                find_func_bounds(func, idaapi.FIND_FUNC_DEFINE)
                return func.start_ea
        return 0
    except:
        return 0


def get_all(addr, callback):
    func_list = []
    if addr is not None:
        for xref in XrefsTo(addr, ida_xref.XREF_ALL):
            f = get_func_start(xref)
            if f == 0:
                print('xref outside of defined function %x' % xref.frm)
            else:
                func_list.append(f)
    func_list = set(func_list)
    count = 0
    for f in func_list:
        c = du.controlFlowinator(ea=f)
        for co in c.calls:
            if co.call_ea == addr:
                try:
                    t = callback(co.ea, co.args)
                    du.create_comment(co.c,co.ea,'%s' % (t))
                    count+=1
                except:
                    pass
                    
    print('calls found %d' % (count))


def string_decoder1(co_ea, args):
    a0 = args[0].val
    a2 = args[2].val
    if isinstance(a0, ida_hexrays.cexpr_t) or isinstance(a2, ida_hexrays.cexpr_t):
        elements = list(du.blowup_expression(a0.cexpr))
        arrayp = elements[0].obj_ea
        print("str @{:X}".format(arrayp))
    else:
        encoded = a0
        key = a2
        decoded = base64.b64decode(encoded).decode('utf-8')
        
        final = '';
        for i in range(len(decoded)):
            final += chr(ord(decoded[i]) ^ ord(key[i % len(key)]))
        print(hex(co_ea), final)
    return final

def main():
    get_all(0x005FA810, string_decoder1)
    
if __name__ == '__main__':
    main()













