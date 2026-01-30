#!/usr/bin/python3

import os
import sys
import json
import argparse

sys.path.insert(0,'..')

from aligner import str2bool, LIBS_NAME, LIBS_NAME_ASLR
from collections import defaultdict
from elftools.elf.elffile import ELFFile

UK      = "/home/unikraft/versioning/apps/applambda@v1/build/unikernel_kvmfc-x86_64_local_align"
verbose = False

def printv(*args, **kwargs):
    if verbose:
        print(*args, **kwargs)

def extract(section, b):
    #check if the section is full of zeros
    if all(v == 0 for v in section.data()):
        printv("[ZERO]: " + section.name)
        return False

    b.extend(len(section.name).to_bytes(2, byteorder='little'))
    b.extend(str.encode(section.name))
    b.extend(section["sh_size"].to_bytes(8, byteorder='little'))
    b.extend(section["sh_addr"].to_bytes(8, byteorder='little'))
    b.extend(section.data())

    printv(" - Written {:<28} (len={:<3}): size: (0x{:x}=0x{:x}, vaddr: 0x{:x})".format(section.name, len(section.name), section["sh_size"], len(section.data()), section["sh_addr"]))
    return True

def process_file_aslr(uk_path, included):

    data = defaultdict(list)
    with open(LIBS_NAME_ASLR, "r") as json_in:
        data = json.load(json_in)

    with open(uk_path, 'rb') as f:
        elffile = ELFFile(f)
        b = bytearray()
        nb_sections = 0            
        for _, section in enumerate(elffile.iter_sections()):
            
            if "initrd" in section.name:
                included.append(".text.rodata.libvfscore")
                break
        
        for _, section in enumerate(elffile.iter_sections()):
            if ".data" in section.name or section.name in included or ".ind" in section.name or section.name.startswith(".rodata."):
                if extract(section, b):
                    nb_sections = nb_sections+1
    if nb_sections == 0:
        print("-> No section: skip minify ELF {}".format(uk_path))
        return

    uk_path = uk_path.replace(".dbg", "") + "_update"
    with open(uk_path, 'wb') as f:
        f.write(nb_sections.to_bytes(1, byteorder='little'))
        f.write(b)

def process_file(uk_path, included):

    with open(uk_path, 'rb') as f:
        elffile = ELFFile(f)

        for _, section in enumerate(elffile.iter_sections()):
            b = bytearray()
            if section.name.startswith(".data") or section.name.startswith(".ind") or section.name in included:
                if not all(v == 0 for v in section.data()):
                    b.extend(section.data())
                    printv("MMAP: {:<28} (len={:<3}): size: (0x{:x}=0x{:x}, vaddr: 0x{:x})".format(section.name, len(section.name), section["sh_size"], len(section.data()), section["sh_addr"]))

                    path = uk_path.replace(".dbg", "") + section.name
                    with open(path, 'wb') as f:
                        f.write(b)

def process_file_minimal(uk_path):
    print("Not implemented yet")
    return 

def main():
    
    global verbose
    parser = argparse.ArgumentParser(description='Reduce a unikernel app with individual app only')
    parser.add_argument('-k', '--uk',  help='Unikernel', type=str, default=UK)
    parser.add_argument('-a', '--add', help='Sections to minify as a list (-a sec1 sec2 ...)', nargs='+')
    parser.add_argument('-v', '--verbose', help='Verbose mode', type=str2bool, nargs='?', const=True, default=True)
    parser.add_argument('-m', '--minimal', help='Use minimal config for snapshoting', type=str2bool, nargs='?', const=True, default=False)
    args = parser.parse_args()
    
    verbose = args.verbose
    included = [".bss", ".tbss", ".intrstack"]
    if args.add and len(args.add) > 0:
        included = included + args.add
    
    use_aslr = False
    if "aslr" in args.uk:
        use_aslr = True
        i = [".uk_ctortab", ".uk_inittab", ".uk_eventtab", ".uk_fs_list", ".uk_thread_inittab", "netdev__param_arg", "vfs__param_arg"]
        for ex in i:
            included.append(ex)
            printv("-> ASLR mode enabled")
        
    if args.minimal and use_aslr:
        printv("Cannot use minimal and aslr at the same time")
        return
    
    printv("---" * 30)
    printv("Create {}".format(args.uk))
    if args.minimal:
        process_file_minimal(args.uk)
    elif use_aslr:
        process_file_aslr(args.uk, included)
    else:
        process_file(args.uk, included)

if __name__ == '__main__':
    main()