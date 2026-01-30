import os
import re
import sys
import lief
import argparse

from collections import defaultdict
from capstone import *

sys.path.insert(0,'..')
from utils import round_to_n
from binary_utils import str2bool, printv, Unikernel, sectionInd, process_file, get_symbols, JSON_MAPS_FILE

VERBOSE=True

WORKSPACE   = "/home/unikraft/versioning/"
APPS        = "apps/"
UKS_INCLUDED=[WORKSPACE+APPS+"applambda@v1/build/unikernel_kvmfc-x86_64_local_align.dbg", WORKSPACE+APPS+"applambda@v2/build/unikernel_kvmfc-x86_64_local_align.dbg", 
              WORKSPACE+APPS+"applambda@v3/build/unikernel_kvmfc-x86_64_local_align.dbg"]#, WORKSPACE+APPS+"applambda@v4/build/unikernel_kvmfc-x86_64_local_align.dbg"]

map_zero_called_address = defaultdict(list)
map_resolved_addr = defaultdict(list)
map_uk_lib_addr = defaultdict(list)

def remove_diff_addr(diff_addr, size, address):
    for i in range(0, size):
        if address + i in diff_addr:
            diff_addr.remove(address + i)

    # In other function:
    #for d in diff_addr:
    #    if d < start_rodata:
    #        print("[WARNING] Still value: 0x{:x}".format(d))

def add_to_map_zero_called_address(uk, ins, s, used_addr):
    if used_addr == -1 and int(ins.op_str) == 0x0:
        map_zero_called_address[ins.address].append(uk.name + ":" + s.name)
        map_uk_lib_addr[uk.name + ":" + s.name].append(ins.address)
        print("[WARNING] - Address: 0x{:x} {:<32}{:<20}{:<32}".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str))
        return None
    elif used_addr == -1:
        print("[WARNING] - Address is different than 0: 0x{:x} {:<32}{:<20}{:<32}".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str))
        return None

    if ins.address in map_zero_called_address:
        map_resolved_addr[ins.address].append(ins.bytes)
        return None

def extract_offset_rip(ins):
    x = re.search("rip\s+(?P<op>\+|\-)\s+(?P<addr>0x[A-Fa-f0-9]{2,})", ins.op_str)
    if x != None:
        op = x.group("op")
        if op == "+":
            current_addr_rip = ins.address + int(x.group("addr"), 16)
        elif op == "-":
            current_addr_rip = ins.address - int(x.group("addr"), 16)
            
    # print("0x{:x} + 0x{:x} = 0x{:x}".format(ins.address, int(x.group("addr"), 16), current_addr_rip))
    return current_addr_rip

def process_instruction(uk, ins, s, optimized_suit):
    
    used_addr=-1
    x = re.search("0x[A-Fa-f0-9]{4,}", ins.op_str)
    if x != None:
        m = x.group()
        if m.lower() != "0xffffffff":
            used_addr = m

    if used_addr == -1:
        print("[WARNING] - Address is different: 0x{:x} {:<32}{:<20}{:<32}".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str))
        return ins.bytes

    if ins.bytes[0] == 0xe8:
        printv("- CALL: 0x{:x} {:<32}{:<20}{:<32}".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str))

        #if add_to_map_zero_called_address(uk, ins, s, used_addr) == None:
        #    return None

        addrInt= int(used_addr, 16)
        barray = bytearray()

        t = ins.mnemonic + " " + ins.op_str
        addr = s.sectionInd.addr
        if t not in s.data_target:
            s.sectionInd.addIndBytes(addrInt, ins.address, ins.bytes, optimized_suit)
            s.data_target[t] = (1, addr)
        else:
            (v1, v2) = s.data_target[t]
            s.data_target[t] = (v1+1, v2)
            addr = v2

        if ins.mnemonic == "push":
            barray.append(0xe9)
        else:
            barray.append(0xe8)
        if optimized_suit > 0:
            diff = addr - ins.address - 0x5
        else:
            diff = addr - ins.address - 0x5

        barray.extend(diff.to_bytes(4, byteorder = 'little', signed=True))
        return barray
    else:
        #print("[WARNING] Other Instruction: 0x{:x} {:<32}{:<20}{:<32}".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str))
        
        # Complex instructions
        addr = s.sectionInd.addr
        addrInt= int(used_addr, 16)
        if "rip" in ins.op_str:
            
            if ins.bytes[0] == 0x48 and ins.bytes[1] == 0xc7 and ins.bytes[2] == 0x05:
                print("Found pattern at 0x{:x}".format(ins.address))
                pass
            else:
                for tt in [".rodata", ".data.bss"]:
                    sect_name = s.name.replace(".text", tt)
                    if sect_name in uk.dict_sections:
                        tt_sect = uk.dict_sections[sect_name]
                        offset_rip = extract_offset_rip(ins)
                        if tt_sect.virtual_address <= offset_rip < round_to_n(tt_sect.end, 0x1000):
                            print("None")
                            return None

            printv("RIP Other: 0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
            s.sectionInd.addIndBytesBiggerRip(ins, optimized_suit)
        else:
            
            printv("Other: 0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
            s.sectionInd.addIndBytesBigger(addrInt, ins.address, ins.bytes, optimized_suit)

        # print("> Jump to {:x} {:x} {}\n----------------".format(addr- 0x5, ins.address, ins.size))
        # Add the jmp in the current address
        barray = bytearray()
        barray.append(0xe8)
        if optimized_suit > 0:
            diff = addr - ins.address - 0x5 - 0x5
        else:
            diff = addr - ins.address - 0x5

        #print("DIFF: {:x}".format(diff))
        barray.extend(diff.to_bytes(4, byteorder = 'little', signed=True))

        # padding with Nops
        for _ in range(len(ins.bytes) - 5):
            barray.append(0x90)

        return barray

def disassemble(uk, md, uk_sect, diff_addr):

    bt = bytearray()
    optimized_suit = 0
    start_rodata = 0x0

    for ins in md.disasm(uk_sect.content, uk_sect.virtual_address):
        printv("0x{:x} {:<32}{:<20}{:<32}".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str))
        if any(ins.address + offset in diff_addr for offset in range(ins.size)):
            ind_bytes = process_instruction(uk, ins, uk_sect, optimized_suit)
            if ind_bytes:
                bt.extend(ind_bytes)
                optimized_suit = 0
            else:
                bt.extend(ins.bytes)
                optimized_suit = 0
        else:
            # NO problematic instruction
            bt.extend(ins.bytes)
            optimized_suit = 0

        if ins.mnemonic == "int1" and ins.bytes[0] == 0xF1:
            # RODATA
            start_rodata = ins.address
            break

    if start_rodata > 0:
        print("RODATA found at 0x{:x}".format(start_rodata))
        offset = start_rodata - uk_sect.virtual_address
        bt.extend(uk.binary.get_section(uk_sect.name).content[offset+1:])

    return bt

def diff_compare_bytes(uks, sect_name):

    diff_addr = list()
    same_sects = list()
    for uk in uks:
        same_sects.append(uk.binary.get_section(sect_name))
    
    if len(same_sects) == 0 or any(x is None for x in same_sects):
        print("[WARNING] Section {} not found or one section is None".format(sect_name))
        return diff_addr

    # Check for all sections if they have identical size
    for index_sect in range(0, len(same_sects)-1):
        
        print("Comparing section {} between Uk{} and Uk{}".format(sect_name, index_sect, index_sect+1))
        if same_sects[index_sect].size != same_sects[index_sect+1].size:
            print("[WARNING] Section {} has different size".format(sect_name))
            return

        if same_sects[index_sect].virtual_address != same_sects[index_sect+1].virtual_address:
            print("[WARNING] Section {} has different virtual_address".format(sect_name))
            return

        vaddr = same_sects[index_sect].virtual_address
        for i in range(0, same_sects[index_sect].size):
            #print("content 0x{:x} - 0x{:x} - 0x{:x}".format(vaddr, same_sects[index_sect].content[i], same_sects[index_sect+1].content[i]))
            if same_sects[index_sect].content[i] != same_sects[index_sect+1].content[i]:
                #print("[WARNING] Section {} has different content at address 0x{:x}".format(sect_name, vaddr))
                diff_addr.append(vaddr-1)
            vaddr += 1

    return diff_addr

def rewrite_zero_calls(uk, sect_name, all_offset_address):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    uk_sect = uk.dict_sections[sect_name]

    bt = bytearray()
    for ins in md.disasm(uk_sect.content, uk_sect.virtual_address):

        if ins.address in map_resolved_addr:
            b_array = map_resolved_addr[ins.address]
            if len(b_array) > 1 and all_equal(b_array) == False:
                print("[WARNING] More than one address: 0x{:x} - {}".format(ins.address, b_array))

            bt.extend(b_array[0])
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

def disassemble_sect(uks, sect_name, diff_addr):
    
    if diff_addr == None or len(diff_addr) == 0:
        print("[WARNING] Diff address is None for section {}".format(sect_name))
        return

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    if "rodata" in sect_name:
        nameInd = sect_name.replace(".text.rodata", ".ind")
    else:
        nameInd = sect_name.replace(".text", ".ind")
        if nameInd == ".ind":
            nameInd = ".ind.text"    

    for i,uk in enumerate(uks):
        
        printv("Disassemble {} - {}".format(uk.name, sect_name))

        uk_sect = uk.dict_sections[sect_name]
        uk_sect.sectionInd = sectionInd(uk.binary.get_section(nameInd).virtual_address)
        print("Uk{} - {}: 0x{:x} - 0x{:x} (size: {}/0x{:x})".format(i, sect_name, uk_sect.virtual_address, uk_sect.virtual_address+uk_sect.size, uk_sect.size, uk_sect.size))

        bt = disassemble(uk, md, uk_sect, diff_addr)
        if len(bt) != len(uk_sect.content):
            print("[WARNING] Different size for section {}: 0x{:x} - 0x{:x}".format(sect_name, len(bt), len(uk_sect.content)))

        uk.binary.get_section(uk_sect.name).content = bt
        uk.binary.get_section(nameInd).content = uk_sect.sectionInd.bt

def rewrite_uk_v(l_uks, use_aslr=False):

    uks = list()
    uks_sect = list()
    map_uks = dict()
    sections = dict()
    for uk_path in l_uks:
        uk = Unikernel(uk_path)
        process_file(uk)
        get_symbols(uk)
        uks.append(uk)
        uks_sect.append(uk)
        map_uks[uk_path] = uk
        for _, s in enumerate(uk.sections):
            if ".text" in s.name and "lib-lambda" in s.name and s.name not in sections:
                sections[s.name]=s
            elif ".text" in s.name and "applambda" in s.name and s.name not in sections:
                sections[s.name]=s

    for sect_name, s in sections.items():
        
        # check if sect name is in all unikernel if not remove the uk from uks_sect
        for unikernel in uks:
            if sect_name not in unikernel.dict_sections:
                print("Remove {}".format(unikernel.name))
                uks.remove(unikernel)

        diff_addr = diff_compare_bytes(uks, sect_name)
        disassemble_sect(uks, sect_name, diff_addr)

    for uk in uks_sect:
        print("Writing {}".format(uk.name))
        uk.binary.write(uk.name)

    return
    ## second pass to fix error of zero calls
    for uklib, all_offset_address in map_uk_lib_addr.items():
        (ukname, section_name) = uklib.split(":")
        rewrite_zero_calls(map_uks[ukname], section_name, all_offset_address)
        print("Re-Writing {}".format(map_uks[ukname].name))
        map_uks[ukname].binary.write(map_uks[ukname].name)

def all_equal(iterator):
    iterator = iter(iterator)
    try:
        first = next(iterator)
    except StopIteration:
        return True
    return all(first == x for x in iterator)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--uks',           help='Unikernels to align as a list (-l uks1 uks2 ...)', nargs='+', default=UKS_INCLUDED)
    parser.add_argument('-v', '--verbose',  help='verbose mode', type=bool,  default=VERBOSE)
    parser.add_argument('-r', '--rewrite',  help='rewrite all sections', type=str2bool, nargs='?', const=True, default=False)
    parser.add_argument('-j', '--json',     help="Path to the json file which contains size (ind)", type=str, default=JSON_MAPS_FILE)
    args = parser.parse_args()

    rewrite_uk_v(args.uks, use_aslr=False)

if __name__ == "__main__":
    main()