import os
import re
import sys
import json
import lief
import argparse

from collections import defaultdict
from capstone import *
from binascii import hexlify

sys.path.insert(0,'..')
from utils import round_to_n
from binary_utils import str2bool, printv, display_functions, Unikernel, Segment, Section, process_symbols, sectionInd, Symbol, Instruction, process_file, get_symbols, JSON_MAPS_FILE

VERBOSE=True
TMP_PREFIX = "__tmp__"

WORKSPACE   = "/home/unikraft/versioning/"
APPS        = "apps/"
UKS_INCLUDED=[WORKSPACE+APPS+"applambda@v1/build/unikernel_kvmfc-x86_64_local_align.dbg", WORKSPACE+APPS+"applambda@v2/build/unikernel_kvmfc-x86_64_local_align.dbg", WORKSPACE+APPS+"applambda@v3/build/unikernel_kvmfc-x86_64_local_align.dbg", WORKSPACE+APPS+"applambda@v4/build/unikernel_kvmfc-x86_64_local_align.dbg"]

def disassemble(uk, uk_sect):
    
    bt = bytearray()
    start_rodata = 0x0
    
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    
    for ins in md.disasm(uk_sect.content, uk_sect.virtual_address):
            
            btt = patch_tmp_symbols(uk, ins, md, uk_sect)
            if btt != None:
                bt.extend(btt)
            else:
                bt.extend(ins.bytes)
            
            if ins.mnemonic == "int1" and ins.bytes[0] == 0xF1:
                # RODATA
                start_rodata = ins.address
                break

    if start_rodata > 0:
        offset = start_rodata - uk_sect.virtual_address
        bt.extend(uk.binary.get_section(uk_sect.name).content[offset+1:])
    
    uk.binary.get_section(uk_sect.name).content = bt

def patch_tmp_symbols(uk, ins, m, uk_sect):
    
    barray = bytearray()
    x = re.search("0x[A-Fa-f0-9]{4,}", ins.op_str)
    if x == None:
        return None
    
    m = x.group()
    if m.lower() == "0xffffffff":
        return None
        
    int_addr = int(m, 16)
    if int_addr in uk.map_symbols:
        for s in uk.map_symbols_tmp[int_addr]:
            if s.name.endswith(TMP_PREFIX):
                print("{} -> \t{} --> call to {}".format(uk_sect.name, m, s.name))
                patched_symbol = uk.map_symbols_name[s.name.replace("__tmp__", "")]
                for ps in patched_symbol:
                    if uk_sect.virtual_address < ps.address <= uk_sect.virtual_address+uk_sect.end:
                        print("- PATCH: {} --> to call to  0x{:x}".format(m, ps.address))
                        print("- 0x%x:\t%s\t%s" %(ins.address, ins.mnemonic, ins.op_str))

                        diff = ps.address - ins.address - 0x5
                        barray.append(0xe8)
                        barray.extend(diff.to_bytes(4, byteorder = 'little', signed=True))
                        
                        #print(hexlify(ins.bytes))
                        #print(hexlify(barray))
                        return barray
    return None                             

def patcher_uks(l_uks):

    nb_patches = 0
    uks = list()
    sections = dict()
    for i, uk_path in enumerate(l_uks):
        uk = Unikernel(uk_path)
        process_file(uk)
        get_symbols(uk)
        uks.append(uk)
        for _, s in enumerate(uk.sections):
            if ".text" in s.name and "lib-lambda" in s.name and s.name not in sections:
                uk_sect = uk.dict_sections[s.name]
                disassemble(uk, uk_sect)
                print("UK: lambda@v{} - Section: {}".format(i+1, uk_sect.name))
            
        print("Writing {}".format(uk.name))
        uk.binary.write(uk.name)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--uks',      help='Unikernels to align as a list (-l uks1 uks2 ...)', nargs='+', default=UKS_INCLUDED)
    parser.add_argument('-v', '--verbose',  help='verbose mode', type=bool,  default=VERBOSE)
    args = parser.parse_args()

    patcher_uks(args.uks)

if __name__ == "__main__":
    main()