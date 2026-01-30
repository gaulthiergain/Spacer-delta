#!/usr/bin/python3
import os
import math
import sys
import diff_match_patch as dmp_module
import argparse

sys.path.insert(0,'..')

from capstone import *
from subprocess import run, PIPE
from uk_sharing_class import *
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from utils import round_to_n
from aligner import WORKSPACE, UKS_INCLUDED

VERBOSE         = True
DIFF            = True
RENDER          = True
SAVE_TO_PAGE    = False

SECTION_NAMES = ['.text.*', '.data', '.bss', '.uk_fs_list', '.uk_ctortab', '.uk_inittab'] 
#SECTION_NAMES = ['.text.*']

def get_unikernels(workspace, included, use_aslr):
    
    if use_aslr:
        use_aslr="_aslr"
    else:
        use_aslr=""

    print("\n-----[{}]-------".format(get_unikernels.__name__.upper()))
    
    unikernels = list()
    
    for d in os.listdir(workspace):
        if d in included:
            if os.path.exists(os.path.join(workspace, d, "build", "libkvmfcplat.o")):
                path = os.path.join(workspace, d, "build", "unikernel_kvmfc-x86_64_local_align" + use_aslr +".dbg")
            else:
                path = os.path.join(workspace, d, "build", "unikernel_kvmq-x86_64_local_align"+ use_aslr +".dbg")
            print("- Analyse unikernel: {}".format(d))
            unikernels.append(Unikernel(path))

    return unikernels

def disassemble(uk, page):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    #md.detail = True
    for i in md.disasm(page.content, page.start):
        page.instructions.append(Instruction(i.address, i.mnemonic, i.op_str, i.bytes))
    
    page.instructions_to_string(uk.map_symbols)

def compare_pages(a, b, size):
    for i in range(size):
        if a[i] != b[i]:
            return False
    return True

def process_symbols(uk, lines):
    for l in lines:
        group = l.split()
        if len(group) == 3:
            symbol = Symbol(int(group[0],16), group[2], group[1])
            uk.map_symbols[symbol.address].append(symbol)
        else:
            print("- [WARNING] Ignoring symbol {}".format(l))

def get_symbols(uk):
    p = run( ['nm', '--no-demangle',uk.name], stdout=PIPE, stderr=PIPE, universal_newlines=True)

    if p.returncode == 0 and len(p.stdout) > 0:
        process_symbols(uk, p.stdout.splitlines())
    elif len(p.stderr) > 0:
        print("- [WARNING] stderr:", p.stderr)
    else:
        print("- [ERROR] Failure to run NM")
        sys.exit(1)

def process_file_aslr_dce(uk):

    with open(uk.name, 'rb') as f:
        elffile = ELFFile(f)

        for segment in elffile.iter_segments():
            uk.segments.append(Segment(segment['p_vaddr'], segment['p_offset'], segment['p_memsz']))

        first = None
        last = None
        for section in elffile.iter_sections():

            uk_sect = Section(section.name , section['sh_addr'], section['sh_offset'], section['sh_size'], section['sh_addralign'])
            if section.name == '.text':
                # Add it to the beginning before other ".text" sections
                uk.sections.insert(1, uk_sect)
            elif len(section.name) == 0:
                ## Empty section
                uk.sections.insert(0, uk_sect)
            elif uk_sect.start == 0:
                ## No loadable section (ignore)
                continue
            elif section.name.startswith(".text.") and first==None:
                first = uk_sect
                continue
            elif section.name.startswith(".text."):
                last = uk_sect
                continue
            else:
                uk.sections.append(uk_sect)             

            uk.map_addr_section[section['sh_addr']] = uk_sect
        
        uk_sect = Section(".text.code" , first.start, first.offset, last.start-first.start+last.size, first.alignment)
        uk.sections.append(uk_sect)
        uk.map_addr_section[section['sh_addr']] = uk_sect
            
def process_file(uk):

    with open(uk.name, 'rb') as f:
        elffile = ELFFile(f)

        for segment in elffile.iter_segments():
            uk.segments.append(Segment(segment['p_vaddr'], segment['p_offset'], segment['p_memsz']))

        for section in elffile.iter_sections():

            uk_sect = Section(section.name , section['sh_addr'], section['sh_offset'], section['sh_size'], section['sh_addralign'], uk.name)
            if section.name == '.text':
                # Add it to the beginning before other ".text" sections
                uk.sections.insert(1, uk_sect)
            elif len(section.name) == 0:
                ## Empty section
                uk.sections.insert(0, uk_sect)
            elif uk_sect.start == 0:
                ## No loadable section (ignore)
                continue
            else:
                uk.sections.append(uk_sect)

            uk.map_addr_section[section['sh_addr']] = uk_sect

def page_to_file(s, i, page, args, path):

    name = path + s.name.replace(".", "") + "_page_" + str(i)
    if args.verbose:
        print("- Save page {} into file {}.bin-txt".format(page.number, name))

    with open((name + ".bin"), "wb") as f:
        f.write(page.content)

    with open((name + ".txt"), "w") as f:
        f.write(page.instructions_string)

def process_pages(uk, args, path):

    for s in uk.sections:
        if s.name in args.list:
            for i, p in enumerate(range(0, len(s.data), PAGE_SIZE)):
                page = Page("", i, s.start+p, PAGE_SIZE, uk.shortname, s.name, s.data[p:p+PAGE_SIZE])
                disassemble(uk, page)
                s.pages.append(page)
                if args.pages:
                    page_to_file(s, i, page, args, path)
                
            if args.verbose:
                    print("- #Pages: {} ".format(len(s.pages)))

def process_data_sections(uk, all_text_section, args):

    print("\n-----[{}]-------".format(process_data_sections.__name__.upper()))
    addresses = list()
    with open(uk.name, 'rb') as f:
        elffile = ELFFile(f)
        
        for s in uk.sections:
            
            if all_text_section and s.name.startswith(".text"):
                args.list.insert(0, s.name )

            if s.name in args.list:
                s.data = elffile.get_section_by_name(s.name).data()
                
                # Add to list for minimize
                addresses.append((s.start, s.size))

                if args.verbose:
                    print("- [{}] Start: 0x{:02x} (size: 0x{:02x}/0x{:02x}) End: 0x{:02x} (roundup: 0x{:02x})".format(s.name, s.start, len(s.data), s.size, s.start+s.size, round_to_n(s.start+s.size, PAGE_SIZE)))

    return addresses

def process_stats(same_pages, unikernels, args):
    
    #print("\n-----[{}]-------".format(process_stats.__name__.upper()))
    total_pages = 0
    for uk in unikernels:
        for s in uk.sections:
            if s.name in args.list:
                for i, p in enumerate(s.pages):
                    #if args.verbose:
                    #    print("  Page {}: 0x{:02x} - 0x{:02x} [#0: {}] ({}:{})".format(p.number, p.start, p.end, p.zeroes, uk.shortname, s.name))
                    if p.hash in same_pages:
                        m = same_pages[p.hash]
                        same = compare_pages(m[0].content, p.content, PAGE_SIZE)
                        if same:
                            same_pages[p.hash].append(p)
                        else:
                            print("- [WARNING] False positive " + str(i))
                    else:
                        same_pages[p.hash].append(p)
                    
                    total_pages += 1
    return total_pages

def process_diff(workdir, map_same_pages, args):

    print("\n-----[{}]-------".format(process_diff.__name__.upper()))
    map_distinct_pages = defaultdict(list) # used when two pages of a same section are different
    for _,v in map_same_pages.items():
        if len(v) == 1:
            map_distinct_pages[v[0].sect_name+str(v[0].number)].append(v[0])
    
    path = os.path.join(workdir, DIFF_FOLDER)
    if not os.path.exists(path):
        os.makedirs(path)

    for k,v in map_distinct_pages.items():
        
        
        if len(v) > 1:

            if args.verbose:
                print("- Compare {} between {} instances".format(k, len(v)))

            dmp = dmp_module.diff_match_patch()
            diff = dmp.diff_main(v[0].instructions_string, v[1].instructions_string)
            html = dmp.diff_prettyHtml(diff)

            current_function = ""
            if args.render:
                body = ""
                for h in html.split("<br>"):
                    if "== " in h:
                        current_function = (h + "<br>").replace(";", "")
                    if "del" in h or "ins" in h:
                        body += current_function.replace("&para", "<br>")
                        body += h.replace("&para", "<br>").replace(";", "")
                        current_function = ""
                html = body
            else:
                html = html.replace("&para", "").replace(";", "")

            with open(("{}{}_page_{}_{}.html".format(path, k.replace(".", ""), v[0].number, v[1].number)), "w") as f:
                f.write(html)

def display_stats(map_same_pages, totalPages, args, totalZeroes):

    reduction = list()
    print("-----[{}]-------".format(display_stats.__name__.upper()))
    pages_sharing = 0
    pages_shared = 0
    total_frames = 0
    
    for k,v in map_same_pages.items():
        if len(v) > 1:
            pages_shared += 1
            total_frames += 1
            pages_sharing += len(v)
            reduction.append(len(v))
            #if args.verbose:
            #    print("   {}: {} -> 1".format(k[0:10], len(v)))
        else:
            total_frames += 1
            p = v[0]
            if args.verbose:
                print("   {}: {} -> Page {}: 0x{:02x}  - 0x{:02x}  [{}] ({}:{})".format(k[0:10], len(v), p.number, p.start, p.end, p.zeroes, p.uk_name, p.sect_name))
    
    print("- TOTAL PAGES: %d" % totalPages)
    print("- TOTAL PAGES SHARED: %d" % pages_shared)
    print("- TOTAL PAGES SHARING: %d" % pages_sharing)
    print("- TOTAL ZEROES PAGES: {}".format(totalZeroes))
    print("- TOTAL NO-ZEROES PAGES: {}".format(totalPages-totalZeroes))
    print("- SHARING: %.2f (%d/%d)" % ((pages_sharing/totalPages) * 100, pages_sharing, totalPages))
    print("- TOTAL FRAMES: {}".format(total_frames))
    print("- TOTAL MB: {}".format((total_frames * PAGE_SIZE)/(1024*1024)))
    return reduction
def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-w', '--workspace',help='Workspace directory', type=str, default=WORKSPACE)
    parser.add_argument('-l','--list',      help='Sections names to consider as a list (-l sect1 sect2 ...)', nargs='+', default=SECTION_NAMES)
    parser.add_argument('-p','--pages',     help='Save pages to bin file', default=SAVE_TO_PAGE)
    parser.add_argument('-m','--minimize',  help='Minimize the size (remove leading zero to binary file)', default=False)
    parser.add_argument('-u', '--uks',      help='Unikernels to align as a list (-l uks1 uks2 ...)', nargs='+', default=UKS_INCLUDED)
    parser.add_argument('-s','--stats',     help='Stats on pages sharing', default=True)
    parser.add_argument('-v','--verbose',   help='verbose mode', default=VERBOSE)
    parser.add_argument('-d','--diff',      help='Perform diff between pages', default=DIFF)
    parser.add_argument('-r','--render',    help='view diff only in html', default=RENDER)
    parser.add_argument('-a', '--aslr',     help="Use aslr (0: disabled - 1: enabled)", type=int, default=0)
    args = parser.parse_args()

    unikernels = get_unikernels(os.path.join(args.workspace, "apps"), args.uks, args.aslr)

    # Create pages folder
    if args.pages and not os.path.exists(os.path.join(args.workspace,PAGE_FOLDER)):
        os.makedirs(os.path.join(args.workspace,PAGE_FOLDER))

    
    #filter '.text.*' in 
    all_text_section = False
    if '.text.*' in args.list:
        all_text_section = True
    
    for uk in unikernels:

        get_symbols(uk)

        # Get the full folder path name for exporting pages
        path = os.path.join(args.workspace,PAGE_FOLDER, uk.shortname) + os.sep
        if args.pages and not os.path.exists(path):
            os.makedirs(path)
        
        # Process the elf file
        process_file(uk)
        
        addresses = process_data_sections(uk, all_text_section, args)

        process_pages(uk, args, path)
    
    map_same_pages = defaultdict(list)    
    total_pages = process_stats(map_same_pages, unikernels, args)
    if args.diff:
        process_diff(args.workspace, map_same_pages, args)
    
    if args.stats:
        display_stats(map_same_pages, total_pages, args, 0)
    
if __name__ == "__main__":
    main()