import sys
import idaapi
import idc
import os
import idautils
import pprint
import struct
import binascii

myfunc=0
jump_table = dict()
switch_map = {}

text_seg = idaapi.get_segm_by_name('.text')
print('text segment base @ ', hex(text_seg.start_ea))

for func in idautils.Functions():
    if 'IumInvokeSecureService' == idc.get_func_name(func):
        print('function found')
        myfunc = func
        break

print(hex(myfunc))

for (startea, endea) in Chunks(myfunc):
    for head in Heads(startea, endea):
        switch_info = ida_nalt.get_switch_info(head)
        if (switch_info and switch_info.jumps != 0):
            num_cases = switch_info.get_jtable_size()
            print('good jump table found yeet')
            results = idaapi.calc_switch_cases(head, switch_info)
            for idx in range(results.cases.size()):
                cur_case = results.cases[idx]
                for cidx in range(len(cur_case)):
                    print("case: %d" % cur_case[cidx])
                    print("  goto 0x%x" % results.targets[idx])
                    try:
                        for insn in range(results.targets[idx], results.targets[idx+1]):
                            inst = idautils.DecodeInstruction(insn)
                            if not inst:
                                continue
                            if ida_idp.is_call_insn(inst) == True:
                                print(GetDisasm(insn))
                    except IndexError:
                        break
        else:
            continue