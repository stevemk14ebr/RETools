from __future__ import print_function
import idc
import idaapi
import idautils
import flare_emu

def decrypt(argv):
    myEH = flare_emu.EmuHelper()
    myEH.emulateRange(idc.get_name_ea_simple("DecryptStub"), registers={"eax":argv[0], "edx":argv[1]}, stack=[0,argv[2], argv[3]])
    return myEH.getEmuString(argv[0])
    
def iterateCallback(eh, address, argv, userData):
    argv.insert(0, eh.getRegVal("edx"))
    argv.insert(0, eh.getRegVal("eax"))
    s = decrypt(argv)
    print("%016X: %s" % (address, s))
    idaapi.set_cmt(address - 5, s,0) 
    
if __name__ == '__main__':   
    eh = flare_emu.EmuHelper()
    eh.iterate(idc.get_name_ea_simple("DecryptStub"), iterateCallback)