import re
import lief
import sys
import argparse

from subprocess import run, PIPE
from collections import defaultdict
from binascii import hexlify
from capstone import *

JSON_MAPS_FILE='ind_map.json'
PAGE_SIZE=0x1000

verbose = False

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
        self.map_symbols_tmp = defaultdict(list)
        self.map_symbols_name = defaultdict(list)
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
        self.data_target = dict()
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
        
    def addInsBytesRet(self, op, addr , offset=0x0):
        barray = bytearray()
        diff = -(self.addr-addr)-offset

        printv("(addInsBytesRet): 0x{:x}- 0x{:x}= 0x{:x} -> {:x}".format(self.addr, addr, diff, toSigned(diff)))
        barray.append(op)
        #barray.extend([0x90, 0x90, 0x90, 0x90])
        
        self.IndInst[self.addr]=barray
        self.addr += 1
        self.bt.extend(barray)

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

        self.addr -= 1 #remove the previous jump
        self.bt = self.bt[:-1] #remove the previous jump

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
            self.addInsBytes(0xe9, next_addr, 0x5)
            #self.addInsBytesRet(0xc3, current_addr)
        elif op == 0x68:
            self.bt.extend(ins_bytes)
            self.addr += 5
            self.addInsBytes(0xe9, current_addr)
        elif op == 0xe9:
            #print("jmp 0x{:x} :".format(op), end=" ")
            #print(ins_bytes)
            self.addInsBytes(op, next_addr, 0x5)
            self.addInsBytesRet(0xc3, current_addr)
        elif op == 0xba or 0xbe or 0xbf:
            #print("mov 0x{:x} :".format(op), end=" ")
            #print(ins_bytes)
            self.bt.extend(ins_bytes)
            self.addr += 5
            self.addInsBytesRet(0xc3, current_addr)
        else:
            printv("(addIndBytes) 0x{:x} :".format(op), end=" ")
            printv(ins_bytes)

        if len(self.bt) > 0 and len(self.bt) % PAGE_SIZE == 0:
            printv("(addIndBytes) EXCEED SIZE {}".format(len(self.bt)))

        return self.addr 
    
    def addIndBytesBiggerJMP(self, next_addr, current_addr, ins_bytes, optimized_suit):

        if optimized_suit > 0:
            self.optimize_addrs()

        self.bt.extend(ins_bytes)
        self.addr += len(ins_bytes)
        self.addInsBytes(0xe9, current_addr)

        if len(self.bt) > 0 and len(self.bt) % PAGE_SIZE == 0:
            printv("(addIndBytesBigger) EXCEED SIZE {}".format(len(self.bt)))

    def addIndBytesBigger(self, next_addr, current_addr, ins_bytes, optimized_suit):

        if optimized_suit > 0:
            self.optimize_addrs()

        self.bt.extend(ins_bytes)
        self.addr += len(ins_bytes)
        self.addInsBytesRet(0xc3, current_addr)

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
        self.addInsBytesRet(0xc3, ins.address)

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
    global verbose
    verbose = True
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
    verbose = False

def process_symbols(uk, lines):
    for l in lines:
        group = l.split()
        if len(group) == 3:
            symbol = Symbol(int(group[0],16), group[2], group[1])
            uk.map_symbols[symbol.address].append(symbol)
            uk.map_symbols_name[symbol.name].append(symbol)
            if symbol.name.endswith("__tmp__"):
                uk.map_symbols_tmp[symbol.address].append(symbol)
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

def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')
