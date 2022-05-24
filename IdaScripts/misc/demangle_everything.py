import idaapi
import idautils
import ida_funcs
import ida_name
import demumble

def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text

def filter_demangled(name):
    name_only = str(name.split("(")[0])
    name_only = name.replace("::~", "_dtor_")
    return str(name_only)

def demangle_functions(seg):
    funcs=idautils.Functions(seg.start_ea, seg.end_ea)
    for f_ea in funcs:
        f_name= ida_funcs.get_func_name(f_ea)
        f_name = remove_prefix(f_name, "j_j")
        f_name = remove_prefix(f_name, "j")
        status, demangled = demumble.demangle(f_name)
        if status:
            name_only = filter_demangled(demangled)
            print(name_only, "Resolved")
            idaapi.set_name(f_ea, name_only, idaapi.SN_NOWARN | idaapi.SN_FORCE)

def demangle_globals(seg):
    # iterate EAs in range
    for seg_ea in range(seg.start_ea, seg.end_ea):
        # iretate xrefs to specific ea
        for xref in idautils.XrefsTo(seg_ea):
            if XrefTypeName(xref.type) != 'Data_Offset':
                continue
                
            global_name = ida_name.get_name(xref.to)


for i in range(0,10):
    seg=idaapi.getnseg(i)
    if seg is None:
        break
    
    demangle_functions(seg)
    #demangle_globals(seg)