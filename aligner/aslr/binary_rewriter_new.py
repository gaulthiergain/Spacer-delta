import os
import re
import sys
import lief
import json
import argparse

from collections import defaultdict
from capstone import *

sys.path.insert(0,'..')
from utils import round_to_n
from binary_utils import str2bool, printv, Unikernel, sectionInd, process_file, get_symbols, JSON_MAPS_FILE, verbose

WORKSPACE   = "/home/unikraft/versioning/"
APPS        = "apps/"
UKS_INCLUDED=[WORKSPACE+APPS+"lib-dns-perf/build/unikernel_kvmfc-x86_64_local_align_aslr.dbg", WORKSPACE+APPS+"lib-mandelbrot-perf/build/unikernel_kvmfc-x86_64_local_align_aslr.dbg", WORKSPACE+APPS+"lib-helloworld/build/unikernel_kvmfc-x86_64_local_align_aslr.dbg"]

map_zero_called_address = defaultdict(list)
map_resolved_addr = defaultdict(list)
map_uk_lib_addr = defaultdict(list)

def add_to_map_zero_called_address(uk, ins, s, used_addr):
    if used_addr == -1 and int(ins.op_str) == 0x0:
        map_zero_called_address[ins.address].append(uk.name + ":" + s.name)
        map_uk_lib_addr[uk.name + ":" + s.name].append(ins.address)
        printv("[WARNING] - Address: 0x{:x} {:<32}{:<20}{:<32}".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str))
        return None
    elif used_addr == -1:
        printv("[WARNING] - Address is different than 0: 0x{:x} {:<32}{:<20}{:<32}".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str))
        return None

    if ins.address in map_zero_called_address:
        map_resolved_addr[ins.address].append(ins.bytes)
        return None

def use_absolute_value(addrInt, ins_bytes):
    bstr = ""
    for i, b in enumerate(reversed(ins_bytes)):
        if b == 0x0 and i == 0:
            continue
        bstr = bstr + '{:02x}'.format(b)

        if "{:02x}".format(addrInt) in bstr:
            return True
    return False

def check_addr(uk, addrInt, current_section, ins):
    
    if len(ins.bytes) == 5 and 0x25 == ins.bytes[0]:
        return False

    # Check first if it is an absolute value (in bytes)
    if use_absolute_value(addrInt, ins.bytes):
        return True

    # Check if it is within the same microlib (short relative call)
    if current_section.virtual_address <= addrInt < current_section.end:
        return False

    # Check if it is used addres from other section
    for s in uk.sections:
        if s.virtual_address != 0 and s.virtual_address <= addrInt <= s.end:
            return True

    # RIP Addressing mode
    if "rip" in ins.op_str:
        return True
    
    if check_special_case(s, ins):
        return True

    return False

def check_special_case(s,ins):
    
    if 0x64 == ins.bytes[0] and 0x48 == ins.bytes[1] and 0x04 == ins.bytes[3] and 0x25 == ins.bytes[4]:
        return True

def extract_offset_rip(ins):
    x = re.search("rip\s+(?P<op>\+|\-)\s+(?P<addr>0x[A-Fa-f0-9]{2,})", ins.op_str)
    if x != None:
        op = x.group("op")
        if op == "+":
            current_addr_rip = ins.address + int(x.group("addr"), 16)
        elif op == "-":
            current_addr_rip = ins.address - int(x.group("addr"), 16)
            
    # printv("0x{:x} + 0x{:x} = 0x{:x}".format(ins.address, int(x.group("addr"), 16), current_addr_rip))
    return current_addr_rip

def process_instruction(uk, ins, s, used_addr, optimized_suit):
    
    addrInt= int(used_addr, 16)
    # printv("0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
    if "rip" not in ins.op_str and len(used_addr) < 8:
        return None

    if addrInt == 0xffffff or len(used_addr) > 8:
        if len(ins.bytes) > 5 and check_special_case(s, ins):
            #printv("0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
            pass
        else:
            return None

    # Check range of address and addressing mode
    if check_addr(uk, addrInt, s, ins) == False:
        return None

    t = ins.mnemonic + " " + ins.op_str
    if len(ins.bytes) == 5:
        # Call or jmp instructions
        printv("(process_instructions) Instruction: 0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
        addr = s.sectionInd.addr
        if t not in s.data_target:
            s.sectionInd.addIndBytes(addrInt, ins.address, ins.bytes, optimized_suit)
            s.data_target[t] = (1, addr)
        else:
            (v1, v2) = s.data_target[t]
            s.data_target[t] = (v1+1, v2)
            addr = v2
            
        barray = bytearray()
        if ins.mnemonic == "push":
            barray.append(0xe9)
        else:
            barray.append(0xe8)
        if optimized_suit > 0:
            diff = addr - ins.address - 0x5
        else:
            diff = addr - ins.address - 0x5
        barray.extend(diff.to_bytes(4, byteorder = 'little', signed=True))
    elif len(ins.bytes) > 5:
        printv("(process_instructions 2) Instruction: 0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
        
        # Complex instructions
        addr = s.sectionInd.addr
        if t not in s.data_target:
            s.data_target[t] = (1, addr)
            if "rip" in ins.op_str:
                
                if ins.bytes[0] == 0x48 and ins.bytes[1] == 0xc7 and ins.bytes[2] == 0x05:
                    pass
                else:
                    for tt in [".rodata", ".data.bss"]:
                        sect_name = s.name.replace(".text", tt)
                        if sect_name in uk.dict_sections:
                            tt_sect = uk.dict_sections[sect_name]
                            offset_rip = extract_offset_rip(ins)
                            if tt_sect.virtual_address <= offset_rip < round_to_n(tt_sect.end, PAGE_SIZE):
                                return None

                #TODO compute the nops here, to jump outside the nop
                printv("RIP Other: 0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
                s.sectionInd.addIndBytesBiggerRip(ins, optimized_suit)
            else:
                #TODO compute the nops here, to jump outside the nop
                printv("Other: 0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
                if ins.bytes[0] == 0x48 and ins.bytes[1] == 0xc7 and ins.bytes[2] == 0xc4:
                    s.sectionInd.addIndBytesBiggerJMP(addrInt, ins.address, ins.bytes, optimized_suit)
                else:
                    s.sectionInd.addIndBytesBigger(addrInt, ins.address, ins.bytes, optimized_suit)
                
            if optimized_suit > 0:
                diff = addr - ins.address - 0x5 - 0x1
            else:
                diff = addr - ins.address - 0x5
        else:
            (v1, v2) = s.data_target[t]
            s.data_target[t] = (v1+1, v2)
            if optimized_suit > 0:
                diff = v2 - ins.address - 0x5 - 0x1
            else:
                diff = v2 - ins.address - 0x5

        # printv("> Jump to {:x} {:x} {}\n----------------".format(addr- 0x5, ins.address, ins.size))
        # Add the jmp in the current address
        barray = bytearray()
        if ins.bytes[0] == 0x48 and ins.bytes[1] == 0xc7 and ins.bytes[2] == 0xc4:
            barray.append(0xe9)
        else:
            barray.append(0xe8)

        #printv("DIFF: {:x}".format(diff))
        barray.extend(diff.to_bytes(4, byteorder = 'little', signed=True))

        # padding with Nops
        for _ in range(len(ins.bytes) - 5):
            barray.append(0x90)
    else:
        return None

    return barray

def disassemble(uk, md, uk_sect, diff_addr):

    bt = bytearray()
    optimized_suit = 0
    start_rodata = 0x0
    
    # Add first address to each element of diff_addr
    diff_addr = {offset + uk_sect.virtual_address for offset in diff_addr}
    
    content = uk_sect.content
    if uk_sect.name == ".text":
        bt.extend(uk_sect.content[0:0x9000])
        content = uk_sect.content[0x9000:]
        uk_sect.virtual_address += 0x9000

    for ins in md.disasm(content, uk_sect.virtual_address):
        if any(ins.address + offset in diff_addr for offset in range(ins.size)):
            x = re.search("0x[A-Fa-f0-9]{4,}", ins.op_str)
            if x != None:
                m = x.group()
                if m.lower() != "0xffffffff":
                    used_addr = m
                    ind_bytes = process_instruction(uk, ins, uk_sect, used_addr, optimized_suit)
                    if ind_bytes:
                        bt.extend(ind_bytes)
                        optimized_suit = 0
                    else:
                        bt.extend(ins.bytes)
                        optimized_suit = 0
                else:
                    print("[0xffffffff]: 0x{:x} {:<32}{:<20}{:<32}".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str))
                    bt.extend(ins.bytes)
                    optimized_suit = 0
            else:
                if "libvfscore" in uk_sect.name and len(ins.bytes) > 5 and 0x48 == ins.bytes[0] and 0x8d == ins.bytes[1] and (0x88 == ins.bytes[2] or 0x90 == ins.bytes[2]) and 0xFF == ins.bytes[5]:
                    bt.extend(bytes([0x48, 0x8d, 0x90, 0xd8, 0xff, 0xff, 0xff]))
                    continue
                print("[X IS NONE]: 0x{:x} {:<32}{:<20}{:<32}".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str))
                bt.extend(ins.bytes)
        else:
            # NO problematic instruction
            bt.extend(ins.bytes)
            optimized_suit = 0

        if ins.mnemonic == "int1" and ins.bytes[0] == 0xF1:
            # RODATA
            start_rodata = ins.address
            break

    if start_rodata > 0:
        offset = start_rodata - uk_sect.virtual_address
        bt.extend(uk.binary.get_section(uk_sect.name).content[offset+1:])

    return bt

def diff_compare_bytes(uks, sect_name):

    diff_addr = defaultdict(set)
    same_sects = list()
    for uk in uks:
        sect = uk.binary.get_section(sect_name)
        if sect is not None and sect.size > 1:
            same_sects.append(sect)

    if len(same_sects) == 0 or any(x is None for x in same_sects):
        print("[WARNING] Section {} not found or one section is None".format(sect_name))

    # Check for all sections if they have identical size
    for index_sect in range(0, len(same_sects)-1):
        if same_sects[index_sect].size != same_sects[index_sect+1].size:
            print("[WARNING] Section {} has different size".format(sect_name))

        # Save the offset of the different bytes (compute it after with the virtual address)
        v1 = same_sects[index_sect].virtual_address
        vaddr1 = v1
        for i in range(0, same_sects[index_sect].size):
            if same_sects[index_sect].content[i] != same_sects[index_sect+1].content[i]:
                offset = vaddr1 - v1
                printv("[WARNING] Section {} has different content '0x{:x} - 0x{:x}' at address 0x{:x} -  offset 0x{:x}".format(sect_name, same_sects[index_sect].content[i], same_sects[index_sect+1].content[i], vaddr1, offset))
                diff_addr[sect_name].add(offset)
            vaddr1 += 1

    return diff_addr

def update_map(maps_size_libs, s):
    len_ind=len(s.sectionInd.bt)
    if len_ind > 0:
        if s.name in maps_size_libs:
            old_value = int(maps_size_libs[s.name], 16)
            if len_ind != old_value:
                maps_size_libs[s.name] = "0x{:x}".format(len_ind)
                print("Update {} with new value 0x{:x} (old: 0x{:x})".format(s.name,len_ind,old_value))
        else:    
            maps_size_libs[s.name] = "0x{:x}".format(len_ind)

def disassemble_sect(uks, sect_name, diff_addr, maps_size_libs):
    
    if diff_addr == None or len(diff_addr) == 0:
        printv("[WARNING] Diff address is None for section: {}".format(sect_name))
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

        if sect_name not in uk.dict_sections:
            printv("[WARNING] Section {} not found in {}".format(sect_name, uk.name))
            continue

        uk_sect = uk.dict_sections[sect_name]
        uk_sect.sectionInd = sectionInd(uk.binary.get_section(nameInd).virtual_address)
        printv("Uk{} - {}: 0x{:x} - 0x{:x} (size: {}/0x{:x})".format(i, sect_name, uk_sect.virtual_address, uk_sect.virtual_address+uk_sect.size, uk_sect.size, uk_sect.size))

        bt = disassemble(uk, md, uk_sect, diff_addr[uk_sect.name])
        if len(bt) != len(uk_sect.content):
            print("[WARNING] Sections {} have different size: {} - {}".format(uk_sect.name, len(bt), len(uk_sect.content)))

        uk.binary.get_section(uk_sect.name).content = bt
        uk.binary.get_section(nameInd).content = uk_sect.sectionInd.bt
        
        update_map(maps_size_libs, uk_sect)

def rewrite_uk_v(l_uks, json_file, v, workspace, rewrite_all=False):

    uks = list()
    map_uks = dict()
    sections = dict()
    
    maps_size_libs = dict()
    if os.path.isfile(json_file):
        with open(json_file, 'r') as json_data:
            maps_size_libs = json.load(json_data)
    
    for uk_path in l_uks:
        if workspace not in uk_path:
            uk_path = os.path.join(workspace, uk_path, "build", "unikernel_kvmfc-x86_64_local_align_aslr.dbg")

        uk = Unikernel(uk_path)
        process_file(uk)
        get_symbols(uk)
        uks.append(uk)
        map_uks[uk_path] = uk
        excluded = list()
        for _, s in enumerate(uk.sections):
            if "initrd" in s.name:
                excluded.append(".text.rodata.libvfscore")
                break
        for _, s in enumerate(uk.sections):

            if s.name in excluded or "lambda" in s.name:
                print("[INFO] SKIP section: {}".format(s.name))
                continue

            if s.size == 0:
                printv("[WARNING] Section {} has size 0 -> SKIP".format(s.name))
            elif rewrite_all and "app" in s.name:
                print("[INFO] Rewrite all sections: {}".format(s.name))
                sections[s.name]=s
            elif s.name.startswith(".text") and s.name not in sections:# and "app" not in s.name:
                 sections[s.name]=s

    for sect_name, s in sections.items():
        print("Processing section: {}".format(sect_name))
        diff_addr = diff_compare_bytes(uks, sect_name)
        disassemble_sect(uks, sect_name, diff_addr, maps_size_libs)

    for uk in uks:
        print("Writing {}".format(uk.name))
        uk.binary.write(uk.name)
    
    with open(json_file, 'w') as fp:
        json.dump(maps_size_libs, fp, indent=4)
    return

def all_equal(iterator):
    iterator = iter(iterator)
    try:
        first = next(iterator)
    except StopIteration:
        return True
    return all(first == x for x in iterator)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--uks',      help='Unikernels to align as a list (-l uks1 uks2 ...)', nargs='+', default=UKS_INCLUDED)
    parser.add_argument('-w', '--workspace', help="Workspace", type=str, default=WORKSPACE)
    parser.add_argument('-v', '--verbose',  help='verbose mode', type=str2bool, nargs='?', const=True,  default=True)
    parser.add_argument('-r', '--rewrite',  help='rewrite all sections', type=str2bool, nargs='?', const=True, default=False)
    parser.add_argument('-j', '--json',     help="Path to the json file which contains size (ind)", type=str, default=JSON_MAPS_FILE)
    args = parser.parse_args()

    rewrite_uk_v(args.uks, args.json, args.verbose, args.workspace, args.rewrite)

if __name__ == "__main__":
    main()