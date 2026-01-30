#!/usr/bin/python3

#Script allowing to show common sections and micro libs between several unikernels
import os
import sys
import json
import hashlib
import argparse

sys.path.insert(0,'..')

from collections import defaultdict
from aligner import WORKSPACE, UKS_INCLUDED, LIBS_NAME, LIBS_NAME_ASLR
from elftools.elf.elffile import ELFFile
from uk_sharing_class import Section, Unikernel

PAGE_SIZE   = 0x1000
UKS_INCLUDED=["applambda@v1/build/unikernel_kvmfc-x86_64_local_align.dbg", "applambda@v2/build/unikernel_kvmfc-x86_64_local_align.dbg", "applambda@v3/build/unikernel_kvmfc-x86_64_local_align.dbg"]

def process_file(path, ukname, use_aslr):
    
    if use_aslr:
        use_aslr="_aslr"
    else:
        use_aslr=""
    
    unikernel = Unikernel(ukname)
    if os.path.exists(os.path.join(path, ukname, "build/libkvmfcplat.o")):
        path = os.path.join(path, ukname, "build", "unikernel_kvmfc-x86_64_local_align" + use_aslr)
    else:
        path = os.path.join(path, ukname, "build", "unikernel_kvmq-x86_64_local_align" + use_aslr)
    with open(path, 'rb') as f:
        elf =  ELFFile(f)
        for sec in elf.iter_sections():
            uk_sect = Section(sec.name, sec["sh_addr"], sec["sh_offset"], sec["sh_size"], sec["sh_addralign"], ukname, sec.data())
            unikernel.sections.append(uk_sect)
            unikernel.map_sections[sec.name] = uk_sect

    return unikernel

def process_spacer(args, unikernels):
    map_section = defaultdict(list)
    map_name_section = defaultdict(list)
    dict_libs = defaultdict(list)
    for uk in unikernels:
        for s in uk.sections:
            map_section[s.start].append(s)
            map_name_section[s.name].append(s)
    green = '\033[92m'
    red = "\x1b[31;20m"
    reset = "\x1b[0m"
    size = None

    track_name = list()
    for k,values in sorted(map_section.items()):

        if k == 0x0:
            continue
        items = list()
        print("0x%x  -> [%d] " % (k, len(values)), end="")
        if len(values) > 1:
            identical = 1
            old = None
            for v in values:
                size = v.size
                items.append(v.name)
                if old == None:
                    old = v.data
                else:
                    if old == v.data:
                        identical = identical+1
            if all(x == items[0] for x in items):
                print("{:<28}".format(items[0]), end=" ")
            else:
                print("{}".format(', '.join(items)), end=" ")
            print(" - 0x{:x} ".format(size), end=" ")
            if identical == len(values):
                if len(unikernels) == len(values):
                    dict_libs["common_to_all"].append({"name":items[0], "addr":"{:x}".format(k), "occurence":len(values)})
                else:
                    dict_libs["common_to_subset"].append({"name":items[0], "addr":"{:x}".format(k), "occurence":len(values)})
                print(green + "[SAME]" + reset)
            else:
                for item in items:
                    if item not in track_name:
                        dict_libs["not_common"].append({"name":item, "addr":"{:x}".format(k), "occurence":len(values)})
                        track_name.append(item)
                print(red + "[DIFF] (" + str(identical) + ")" + reset)
        else:
            dict_libs["not_common"].append({"name":values[0].name, "addr":"{:x}".format(k), "occurence":len(values)})
            print(values[0].name)
            
    dict_libs["common_to_all"]=sorted(dict_libs["common_to_all"], key=lambda x:x["name"].lower())
    dict_libs["common_to_subset"]=sorted(dict_libs["common_to_subset"], key=lambda x:x["name"].lower())
    dict_libs["not_common"]=sorted(dict_libs["not_common"], key=lambda x:x["name"].lower())
    with open(LIBS_NAME, 'w') as f:
        json.dump(dict_libs, f, indent=1, sort_keys=True)


def process_spacer_aslr(args, unikernels):
    map_section = defaultdict(list)
    map_name_section = defaultdict(list)
    map_size_section = defaultdict(list)
    map_hex_section = defaultdict(list)
    
    for uk in unikernels:
        for s in uk.sections:
            hex = hashlib.sha224(s.data).hexdigest()
            map_section[hex].append(s)
            map_name_section[hex].append(s.name)
            map_size_section[hex].append(s.size)
            map_hex_section[s.name].append(hex)
            
    green = '\033[92m'
    red = "\x1b[31;20m"
    reset = "\x1b[0m"
    
   
    dict_libs = defaultdict(list)
    for k, values in map_hex_section.items():
        
        if k in ["", " ", ".comment", ".shstrtab"]:
            continue
        if len(set(values)) <= 1 and ".app" not in k and ".data" not in k and k not in [".intrstack", ".tbss", ".comment"]:
            dict_libs["common_to_all"].append(k)
        else:
            dict_libs["not_common"].append(k)
    
    dict_libs["common_to_all"]=sorted(dict_libs["common_to_all"], key=lambda x:x.lower())
    dict_libs["not_common"]=sorted(dict_libs["not_common"], key=lambda x:x.lower())
    with open(LIBS_NAME_ASLR, 'w') as f:
        json.dump(dict_libs, f, indent=4, sort_keys=True)

    for k,values in map_section.items():

        if k == 0x0:
            continue
        items = list()
        
        if len(values) > 1:
            print("{:<28}  -> [{}] ".format(map_name_section[k][0], len(values)), end="")
            identical = 1
            old = None
            size = None
            for v in values:
                items.append(v.name)
                size = v.size
                if old == None:
                    old = v.data
                else:
                    if old == v.data:
                        identical = identical+1
            if all(x == items[0] for x in items):
                print("{:<28}".format(items[0]), end=" ")
            else:
                print("{}".format(', '.join(items)), end=" ")
            print(" - 0x{:x} ".format(size), end=" ")
            if identical == len(values):
                print(green + "[SAME]" + reset)
            else:
                print(red + "[DIFF]" + reset)
        #else:
        #    print(values[0].name)


def main():

    parser = argparse.ArgumentParser(description='Check common mapping')
    parser.add_argument('-w', '--workspace',    help='Workspace Directory', type=str, default=WORKSPACE)
    parser.add_argument('-u', '--uks',          help='Unikernels to align as a list (-l uks1 uks2 ...)', nargs='+', default=UKS_INCLUDED)
    parser.add_argument('-a', '--aslr',         help="Use aslr (0: disabled - 1: enabled)", type=int, default=0)

    args = parser.parse_args()

    unikernels = list()
    workspace = os.path.join(args.workspace, "apps")
    for uk in os.listdir(workspace):
        if uk in args.uks:
            unikernels.append(process_file(workspace, uk, args.aslr))

    if args.aslr:
        process_spacer_aslr(args, unikernels)
    else:
        process_spacer(args, unikernels)
            
if __name__== "__main__":
    main()
