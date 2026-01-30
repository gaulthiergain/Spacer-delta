#!/usr/bin/python3

from elftools.elf.elffile import ELFFile
import argparse
import json
import sys

sys.path.insert(0,'..')
from aligner import str2bool, LIBS_NAME, LIBS_NAME_ASLR
from collections import defaultdict

UK      = "/home/unikraft/versioning/apps/lib-helloworld/build/unikernel_kvmfc-x86_64_local_align"

verbose=False

def printv(*args, **kwargs):
    if verbose:
        print(*args, **kwargs)

def write_file(uk_path, b):
    
    uk_path = uk_path + ".sec"
    with open(uk_path, 'wb') as f:
        f.write(b)

    printv("Written {}".format(uk_path))
    
def process_file(ukpath, b, excluded):
    all_sect = list()
    data_libs = defaultdict(list)
    is_aslr = False
    if "aslr" in ukpath:
        e = [".uk_ctortab", ".uk_inittab", ".uk_eventtab", ".uk_fs_list", ".uk_thread_inittab", "netdev__param_arg", "vfs__param_arg"]
        for ex in e:
            excluded.append(ex)
            is_aslr = True

    with open(ukpath, 'rb') as f:
        elffile = ELFFile(f)
        for i, section in enumerate(elffile.iter_sections()):
            if "initrd" in section.name and is_aslr:
                #excluded.append("initrd")
                excluded.append(".text.rodata.libvfscore")
                break
        
        for i, section in enumerate(elffile.iter_sections()):
            if section['sh_size'] == 0:
                printv("[ZERO]: " + section.name)
                continue
            
            if len(section.name) == 0 or section.name in excluded:
                #print("[SKIP]: " + section.name)
                continue
            
            if section.name.startswith(".rodata.") and is_aslr:
                printv("[ASLR-IGNORE]: " + section.name)
                continue 
            
            if section['sh_addr'] % 0x1000 != 0:
                continue
            
            if i > 0 and section['sh_addr'] == 0:
                break
            all_sect.append(section)
    
    b.extend(len(all_sect).to_bytes(2, byteorder='little'))
    b.extend(bytearray(6))
    for section in all_sect:
        b.extend(len(section.name).to_bytes(2, byteorder='little'))
        b.extend(bytearray(6))
        b.extend(str.encode(section.name))
        b.extend(section["sh_addr"].to_bytes(8, byteorder='little'))
        b.extend(section["sh_size"].to_bytes(8, byteorder='little'))
        b.extend(bytearray(1))
        printv(" - Written {:<28} (len={:<3}): size: 0x{:x}, vaddr: 0x{:x})".format(section.name, len(section.name), section["sh_size"], section["sh_addr"]))
    
    return ukpath

def main():
    
    global verbose
    parser = argparse.ArgumentParser(description='Generate sec files from unikernel')
    parser.add_argument('-k', '--uk',  help='Unikernel', type=str, default=UK)
    parser.add_argument('-i', '--ignore', help='Sections to ignore as a list (-i sec1 sec2 ...)', nargs='+')
    parser.add_argument('-v', '--verbose', help='Verbose mode', type=str2bool, nargs='?', const=True, default=True)
    args = parser.parse_args()
    
    ukpath = args.uk.replace(".dbg", "")
    
    verbose = args.verbose
    excluded = [ ".bss", ".tbss", ".intrstack"]
    if args.ignore and len(args.ignore) > 0:
        excluded = excluded + args.ignore

    b = bytearray()
    
    ukpath = process_file(ukpath, b, excluded)
    write_file(ukpath, b)
    printv("---" * 30)

if __name__ == '__main__':
    main()