from idautils import *
from idaapi import *
from idc import *
import sark

bad = []
for segea in Segments():
    for funcea in Functions(segea, get_segm_end(segea)):
        try:
            f = idaapi.get_func(funcea)
            idaapi.decompile(f)
        except:
            pass