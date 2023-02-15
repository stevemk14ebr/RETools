from __future__ import print_function
import idc
import idautils
import flare_emu

cur_callsite = 0x0

# simulate new
def call_hook(address, arguments, functionName, userData):
    alloc_size = arguments[0]
    print(functionName, hex(alloc_size))
    eh = userData["EmuHelper"]
    eh.uc.reg_write(eh.regs["eax"], eh.allocEmuMem(alloc_size))

def decrypt(address, encrypted_str):
    eh = flare_emu.EmuHelper()
    
    # load byte array into memory
    enc_mem = eh.loadBytes(encrypted_str)
    
    # alloc ptr to hold the ptr from new
    pdec_mem = eh.allocEmuMem(4)
    
    # ecx holds encrypted str, next stack argument is dec mem (after return slot)
    eh.emulateRange(address, registers = {"ecx": enc_mem}, stack=[0,pdec_mem], skipCalls=True, callHook=call_hook)
    
    # read the memory pointer that got allocated
    dec_mem = eh.getEmuPtr(pdec_mem)
    
    # get the string there
    return eh.getEmuString(dec_mem)

# executes all the ASM up to our target call, which will include the built up encoded stack string
def iterateCallback(eh, address, argv, userData):
    global cur_callsite
    print("callsite %s callback %s" % (hex(cur_callsite), hex(address)))
    
    # ecx holds pointer to the stack memory of encrypted string
    val = eh.getRegVal("ecx")
    
    # flare emu initializes memory to zero, so we can read as null terminated string
    encrypted = eh.getEmuString(val)
    
    # run the decryptor (as a second emu instance) with those encrypted bytes
    print(decrypt(cur_callsite, encrypted))
    
def emulate_decoder(address):
    global cur_callsite
    cur_callsite = address
    
    # iterate will force execution down the parent function up to this function
    eh = flare_emu.EmuHelper()
    eh.iterate(address, iterateCallback)
        
if __name__ == '__main__':
    emulate_decoder(0x10001510)