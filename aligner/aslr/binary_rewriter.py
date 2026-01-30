import os
import re
import sys
import json
import lief
import argparse

from collections import defaultdict
from capstone import *
from binascii import hexlify
from subprocess import run, PIPE
sys.path.insert(0,'..')
from utils import round_to_n

VERBOSE = False
verbose = False

WORKDIR="/Users/gaulthiergain/Documents/developer/code/disassembler/elf/"
FILE="lib-sqlite_plt.bak"#"unikernel_kvm-x86_64_aslr_plt.dbg"
WORKDIR="/home/unikraft/versioning/apps/lib-helloworld-remove/build"
FILE="unikernel_kvmfc-x86_64_local_align_aslr.dbg"
JSON_MAPS_FILE='ind_map.json'
PAGE_SIZE=0x1000

def printv(*args, **kwargs):
    if verbose:
        print(*args, **kwargs)

def toSigned(signed_int):
    return signed_int + 2**32

class Unikernel:
    def __init__(self, name):
        self.name = name
        self.binary = None
        self.segments = list()
        self.sections = list()
        self.dict_sections = dict()
        self.symbols = list()
        self.map_symbols = defaultdict(list)
        self.dump = None

class Segment:
    def __init__(self, address, offset, size):
        self.address = address
        self.offset = offset
        self.size = size

class Section:
    def __init__(self, name, virtual_address, offset, size, alignment):
        self.name = name
        self.virtual_address = virtual_address
        self.start_align = self.round_mult()
        self.offset = offset
        self.size = size
        self.alignment = alignment
        self.end = virtual_address+size
        self.pages = list()
        self.sectionInd = None
        self.content = None

    def round_mult(self, base=PAGE_SIZE):
        if self.virtual_address % PAGE_SIZE != 0:
            return base * round(self.virtual_address / base)
        return self.virtual_address

class sectionInd:
    def __init__(self, addr):
        self.IndInst = dict()
        self.start_addr = addr
        self.addr = addr
        self.bt = bytearray()

    def addInsBytes(self, op, addr , offset=0x0):
        barray = bytearray()
        diff = -(self.addr-addr)-offset

        printv("(addInsBytes): 0x{:x}- 0x{:x}= 0x{:x} -> {:x}".format(self.addr, addr, diff, toSigned(diff)))
        barray.append(op)
        barray.extend(diff.to_bytes(4, byteorder = 'little', signed=True))

        self.IndInst[self.addr]=barray
        self.addr += 5
        self.bt.extend(barray)

    def optimize_addrs(self):

        printv("(optimize_addrs): Addr before: {:x} - Addr now: {:x}".format(self.addr, self.addr-5))
        #printv(len(self.bt))
        #for i, v in enumerate(list(self.bt)):
        #        printv("{:x}".format(v), end=", ")
        #printv("\n----")

        self.addr -= 5 #remove the previous jump
        self.bt = self.bt[:-5] #remove the previous jump

        #    #printv(len(self.bt))
        #    #for i, v in enumerate(list(self.bt)):
        #    #        printv("{:x}".format(v), end=", ")
        #    printv("\n{:x}".format(self.addr))

    def addIndBytes(self, next_addr, current_addr, ins_bytes, optimized_suit):

        if optimized_suit > 0:
            self.optimize_addrs()

        op = ins_bytes[0]
        if op == 0xe8:
            #print("call 0x{:x} :".format(op), end=" ")
            #print(ins_bytes)
            self.addInsBytes(op, next_addr, 0x5)
            self.addInsBytes(0xe9, current_addr)
        elif op == 0xe9:
            #print("jmp 0x{:x} :".format(op), end=" ")
            #print(ins_bytes)
            self.addInsBytes(op, next_addr, 0x5)
            self.addInsBytes(0xe9, current_addr+0x5)
        elif op == 0xba or 0xbe or 0xbf:
            #print("mov 0x{:x} :".format(op), end=" ")
            #print(ins_bytes)
            self.bt.extend(ins_bytes)
            self.addr += 5
            self.addInsBytes(0xe9, current_addr)
        else:
            printv("(addIndBytes) 0x{:x} :".format(op), end=" ")
            printv(ins_bytes)

        if len(self.bt) > 0 and len(self.bt) % PAGE_SIZE == 0:
            printv("(addIndBytes) EXCEED SIZE {}".format(len(self.bt)))

        return self.addr 

    def addIndBytesBigger(self, next_addr, current_addr, ins_bytes, optimized_suit):

        if optimized_suit > 0:
            self.optimize_addrs()

        self.bt.extend(ins_bytes)
        self.addr += len(ins_bytes)
        self.addInsBytes(0xe9, current_addr)

        if len(self.bt) > 0 and len(self.bt) % PAGE_SIZE == 0:
            printv("(addIndBytesBigger) EXCEED SIZE {}".format(len(self.bt)))

    def debug(self, barray):
        md = Cs(CS_ARCH_X86, CS_MODE_64)  
        md.detail = True
        for new_ins in md.disasm(barray, self.addr):
            printv("(addIndBytesBigger) Other: 0x{:x} {:<32}{:<20}{:<32}\n".format(new_ins.address, ' '.join(re.findall('..',new_ins.bytes.hex())), new_ins.mnemonic, new_ins.op_str), end="")

    def addIndBytesBiggerRip(self, ins, optimized_suit):

        if optimized_suit > 0:
            self.optimize_addrs()

        x = re.search("rip\s+(?P<op>\+|\-)\s+(?P<addr>0x[A-Fa-f0-9]{2,})", ins.op_str)
        if x != None:
            op = x.group("op")
            if op == "+":
                addr = ins.address + int(x.group("addr"), 16)
            elif op == "-":
                addr = ins.address - int(x.group("addr"), 16)

        # Compute the (old) offset from rip
        previous_offset = addr-ins.address
        previous_offset_bt = previous_offset.to_bytes(4, byteorder = 'little', signed=True)

        # Compute the (new) offset from rip (in the ind)
        offset = addr-self.addr

        # Rewrite the instructions with the new offset
        barray = bytearray()
        index_find = ins.bytes.find(previous_offset_bt)
        barray.extend(ins.bytes[0:index_find])
        barray.extend(offset.to_bytes(4, byteorder = 'little', signed=True))
        reminder = ins.bytes[index_find+len(previous_offset_bt):]
        if len(reminder) > 0:
            barray.extend(reminder)

        #self.debug(barray)

        # Add the jump instruction
        self.IndInst[self.addr]=barray
        self.addr += len(ins.bytes)
        self.bt.extend(barray)
        self.addInsBytes(0xe9, ins.address)

        if len(self.bt) > 0 and len(self.bt) % PAGE_SIZE == 0:
            printv("(addIndBytesBiggerRip) EXCEED SIZE {}".format(len(self.bt)))

class Symbol:
    def __init__(self, address, name, info):
        self.address = address
        self.name = name
        self.info = info

class Instruction:
    def __init__(self, address, mnemonic, op_str, _bytes):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.bytes = self.cut(hexlify(_bytes).decode())

    def cut(self, line, n=2):
        return ' '.join([line[i:i+n] for i in range(0, len(line), n)])

def display_functions(ins, uk, int_addr, m=None):

    if int_addr in uk.map_symbols:
        printv(">> FCT: ", end="")
        for s in uk.map_symbols[int_addr]:
            printv(s.name, end="")
        printv(":", end="-  ")
    printv("0x{:x} {:<32}{:<20}{:<32}".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")

    if m != None:
        found = False
        int_addr = int(m, 16)
        if int_addr in uk.map_symbols:
            # Call to a function
            for s in uk.map_symbols[int_addr]:
                printv("\t{} --> call to {}".format(m, s.name))
                found = True
        else:
            # Another section
            for s in uk.sections:
                if s.virtual_address < int_addr < s.end:
                    printv("\t{} --> refer to {}".format(m, s.name))
                    found = True

        if not found:
            printv("")
    else:
        printv("")


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
            
    # print("0x{:x} + 0x{:x} = 0x{:x}".format(ins.address, int(x.group("addr"), 16), current_addr_rip))
    return current_addr_rip

def process_instructions(uk, ins, s, used_addr, optimized_suit):
    
    addrInt= int(used_addr, 16)
    # print("0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
    if "rip" not in ins.op_str and len(used_addr) < 8:
        return None

    if addrInt == 0xffffff or len(used_addr) > 8:
        if len(ins.bytes) > 5 and check_special_case(s, ins):
            #print("0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
            pass
        else:
            return None

    # Check range of address and addressing mode
    if check_addr(uk, addrInt, s, ins) == False:
        printv("(process_instructions) 0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
        return None

    if len(ins.bytes) == 5:
        # Call or jmp instructions
        printv("(process_instructions) Instruction: 0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
        addr = s.sectionInd.addr
        s.sectionInd.addIndBytes(addrInt, ins.address, ins.bytes, optimized_suit)
        barray = bytearray()
        barray.append(0xe9)
        if optimized_suit > 0:
            diff = addr - ins.address - 0x5 - 0x5
        else:
            diff = addr - ins.address - 0x5
        barray.extend(diff.to_bytes(4, byteorder = 'little', signed=True))
    elif len(ins.bytes) > 5:

        # Complex instructions
        addr = s.sectionInd.addr
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
            #print("RIP Other: 0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
            s.sectionInd.addIndBytesBiggerRip(ins, optimized_suit)
        else:
            #TODO compute the nops here, to jump outside the nop
            #print("Other: 0x{:x} {:<32}{:<20}{:<32}\n".format(ins.address, ' '.join(re.findall('..',ins.bytes.hex())), ins.mnemonic, ins.op_str), end="")
            s.sectionInd.addIndBytesBigger(addrInt, ins.address, ins.bytes, optimized_suit)

        # print("> Jump to {:x} {:x} {}\n----------------".format(addr- 0x5, ins.address, ins.size))
        # Add the jmp in the current address
        barray = bytearray()
        barray.append(0xe9)
        if optimized_suit > 0:
            diff = addr - ins.address - 0x5 - 0x5
        else:
            diff = addr - ins.address - 0x5

        #print("DIFF: {:x}".format(diff))
        barray.extend(diff.to_bytes(4, byteorder = 'little', signed=True))

        # padding with Nops
        for _ in range(len(ins.bytes) - 5):
            barray.append(0x90)
    else:
        return None

    return barray

def disassemble(uk, s, use_new_rep):

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    if "rodata" in s.name:
        nameInd = s.name.replace(".text.rodata", ".ind")
    else:
        nameInd = s.name.replace(".text", ".ind")
        if nameInd == ".ind":
            nameInd = ".ind.text"    
    
    #print("0x{:x} {}".format(uk.binary.get_section(nameInd).virtual_address, nameInd))

    # Add Ind section to current section
    s.sectionInd = sectionInd(uk.binary.get_section(nameInd).virtual_address)
    bt = bytearray()
    optimized_suit = 0 # Incremented if several instructions are follow up (optimize)
    
    content = s.content
    if s.name == ".text":
        bt.extend(s.content[0:0x9000])
        content = s.content[0x9000:]
        s.virtual_address += 0x9000
        
    start_rodata=0
    for ins in md.disasm(content, s.virtual_address):
        int_addr = int(ins.address)    
        
        if use_new_rep and ins.mnemonic == "int1" and ins.bytes[0] == 0xF1:
            start_rodata = ins.address
            break

        x = re.search("0x[A-Fa-f0-9]{4,}", ins.op_str)
        if x != None:
            m = x.group()
            if m.lower() != "0xffffffff":
                # display_functions(ins, uk, int_addr, m)
                ind_bytes = process_instructions(uk, ins, s, m, optimized_suit)
                if ind_bytes:
                    bt.extend(ind_bytes)
                    optimized_suit += 1
                else:
                    bt.extend(ins.bytes)
                    optimized_suit = 0
            else:
                bt.extend(ins.bytes)
                optimized_suit = 0
        else:
            if s.name == ".text.libvfscore" and len(ins.bytes) > 5 and 0x48 == ins.bytes[0] and 0x8d == ins.bytes[1] and (0x88 == ins.bytes[2] or 0x90 == ins.bytes[2]) and 0xFF == ins.bytes[5]:
                bt.extend(bytes([0x48, 0x8d, 0x90, 0xd8, 0xff, 0xff, 0xff]))
                continue
            # display_functions(ins, uk, int_addr)
            bt.extend(ins.bytes)
            optimized_suit = 0
    if start_rodata > 0:
        offset = start_rodata - s.virtual_address
        bt.extend(s.content[offset:])

    uk.binary.get_section(s.name).content = bt
    uk.binary.get_section(nameInd).content = s.sectionInd.bt

    len_ind=len(s.sectionInd.bt)
    if len_ind > 0:
        if s.name in uk.maps_size_libs:
            old_value = int(uk.maps_size_libs[s.name], 16)
            if len_ind != old_value:
                uk.maps_size_libs[s.name] = "0x{:x}".format(len_ind)
                print("Update {} with new value 0x{:x} (old: 0x{:x})".format(s.name,len_ind,old_value))
        else:    
            uk.maps_size_libs[s.name] = "0x{:x}".format(len_ind)
    
    return

def process_symbols(uk, lines):
    for l in lines:
        group = l.split()
        if len(group) == 3:
            symbol = Symbol(int(group[0],16), group[2], group[1])
            uk.map_symbols[symbol.address].append(symbol)
            uk.symbols.append(symbol)
            printv("{} - 0x{:x} - ({} bytes)".format(symbol.name, symbol.address, symbol.info))
        else:
            printv("[WARNING] Ignoring symbol {}".format(l))

def get_symbols(uk):
    p = run( ['nm', '--no-demangle',uk.name], stdout=PIPE, stderr=PIPE, universal_newlines=True)

    if p.returncode == 0 and len(p.stdout) > 0:
        process_symbols(uk, p.stdout.splitlines())
    elif len(p.stderr) > 0:
        printv("[WARNING] stderr:", p.stderr)
    else:
        printv("[ERROR] Failure to run NM")
        sys.exit(1)

def update_uk(uk, filename):
    uk.binary.write(filename)

def process_file(uk):

    uk.binary = lief.parse(uk.name)

    for segment in uk.binary.segments:
        uk.segments.append(Segment(segment.virtual_address, segment.file_offset, segment.virtual_size))

    for section in uk.binary.sections:
        uk_sect = Section(section.name , section.virtual_address, section.offset, section.size, section.alignment)
        bt = bytearray()
        bt.extend(section.content)
        uk_sect.content = bt
        uk.sections.append(uk_sect)
        uk.dict_sections[uk_sect.name] = uk_sect

def rewrite_uk_old(file, json_file, v, rewrite_all, use_new_rep, section):
    global verbose
    
    verbose = False
    if v:
        verbose=True
        
    uk = Unikernel(file)
    process_file(uk)
    get_symbols(uk)
    
    if os.path.isfile(json_file):
        with open(json_file, 'r') as json_data:
            uk.maps_size_libs = json.load(json_data)
    
    if rewrite_all:
        for _, s in enumerate(uk.sections):
            if s.name.startswith(section):
                if "libuklock" in s.name or "liblambda" in s.name:
                    continue
                disassemble(uk, s, use_new_rep)
    else:
        for _, s in enumerate(uk.sections):
            if s.name.startswith(section) and "app" not in s.name:
                if "libuklock" in s.name or "liblambda" in s.name:
                    continue
                printv("Update " + s.name)
                disassemble(uk, s, use_new_rep)
            elif s.name.startswith(".text."):
                print("- Ignore " + s.name)

    update_uk(uk, file)
    with open(json_file, 'w') as fp:
        json.dump(uk.maps_size_libs, fp, indent=4)

def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')
     
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file',     help='Path to ELF file to analyse', type=str,
                        default=os.path.join(WORKDIR, FILE))
    parser.add_argument('-v', '--verbose',  help='verbose mode', type=bool,  default=VERBOSE)
    parser.add_argument('-r', '--rewrite',  help='rewrite all sections', type=str2bool, nargs='?', const=True, default=False)
    parser.add_argument('-n', '--new_rep',  help='Use new representation (.text and .rodata aggregated)', type=str2bool, nargs='?', const=True, default=True)
    parser.add_argument('-j', '--json',     help="Path to the json file which contains size (ind)", type=str, default=JSON_MAPS_FILE)
    parser.add_argument('-s', '--section',  help="Section to disassemble", type=str, default=".text")
    args = parser.parse_args()

    rewrite_uk_old(args.file, args.json, args.verbose, args.rewrite, args.new_rep, args.section)

if __name__ == "__main__":
    main()