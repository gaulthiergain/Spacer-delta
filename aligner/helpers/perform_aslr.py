#!/usr/bin/python3
import re
import sys
import lief
import argparse
import logging
import random
import subprocess

sys.path.insert(0,'..')
from utils import SUCCESS, LDS_VFSCORE, LDS_NETDEV, CustomFormatter, logger
from unikernels import *
from aligner import str2bool, WORKSPACE
from collections import defaultdict
from stringBuilder import StringBuilder

APP="apps"
UKS_INCLUDED=["applambda@v1", "applambda@v2"]
MIN_RANDOM=int(0x100)
MAX_RANDOM=int(0x1000)

class AslrManager:
    def __init__(self, args):
        self.uks = list()
        self.uks_included = args.uks
        self.is_dce = args.is_dce
        self.offset = args.offset
        self.same_mapping = args.same_mapping
        self.workspace = os.path.join(args.workspace + args.app_folder)
        self.unikraft_path = os.path.join(args.workspace + "unikraft")
        self.sb_link = dict()
        self.min_random=args.min
        self.max_random=args.max
        
        self.libs_order_app = defaultdict(list)
        self.offset_app = defaultdict(list)

    def process_nm(self, lines, lib, uk):
        for l in lines:
            group = l.split()
            if len(group) == 3:
                symbol = group[2] #  , group[1])
                key = ".text." + symbol
                if key in uk.map_symbols:
                    l = uk.map_symbols[key]
                    if lib not in l:
                        uk.map_symbols[key].append(lib)
                else:
                    uk.map_symbols[key].append(lib)
                #print("- [INFO] SYMBOL  {}".format(symbol))
            #else:
            #    print("- [WARNING] Ignoring symbol {}".format(l))

    def get_symbols(self, uk, lib):
        
        obj_file = os.path.join(self.workspace, uk.name, "build", lib + OBJ_EXT)
        p = subprocess.run(['nm', '--no-demangle', obj_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if p.returncode == 0 and len(p.stdout) > 0:
            self.process_nm(p.stdout.splitlines(), ".text." + lib, uk)
        elif len(p.stderr) > 0:
            print("- [WARNING] stderr:", p.stderr)
        else:
            if "libnginx.o" in obj_file:
                print("- [WARNING] Ignoring libnginx.o")
                return
            print("- [ERROR] Failure to run NM")
            sys.exit(1)
                
    def process_symbols(self):
        if not self.is_dce:
            return

        for uk in self.uks:
            for lib in uk.objects:
                self.get_symbols(uk, lib)
                
    def process_folder(self):
        for d in os.listdir(self.workspace):
            if d in self.uks_included:
                uk = Unikernel(d, os.path.join(self.workspace, d))
                logger.info("Process {} ".format(d))
                uk.process_build_folder(os.path.join(self.workspace, d, "build/"),dict(), dict(), False)
                self.uks.append(uk)

        if len(self.uks) == 0:
            logger.fatal("At least 1 unikernel is required. Found: 0")
            sys.exit(1)
                
    def relink(self, path, use_vfscore, kvm_plat):           
        os.chdir(path)
        linker_add=""
        if use_vfscore:
            linker_add="-Wl,-T,{}/lib/vfscore/extra_out64_aslr.ld".format(self.unikraft_path)
        
        if os.path.isfile("{}/libvfscore/libparam.lds".format(path)):
            linker_add += " -Wl,-T,{}/libvfscore/libparam.lds".format(path)
            with open("{}/libvfscore/libparam.lds".format(path), "w") as f:
                f.write(LDS_VFSCORE)
        if os.path.isfile("{}/libuknetdev/libparam.lds".format(path)):
            linker_add += " -Wl,-T,{}/libuknetdev/libparam.lds".format(path)
            with open("{}/libuknetdev/libparam.lds".format(path), "w") as f:
                f.write(LDS_NETDEV)
        suffix=""
        cmd = 'gcc -nostdlib -Wl,--omagic -Wl,--build-id=none -nostdinc -no-pie -Wl,-m,elf_x86_64 -Wl,-m,elf_x86_64 -Wl,-dT,{}/lib{}plat/link64_aslr.lds -Wl,-T,{}/lib/uksched/extra_aslr.ld {} -o app-lambda_{}-x86_64_aslr'.format(path, kvm_plat, self.unikraft_path, linker_add, kvm_plat)
        if self.is_dce:
            suffix="_dce"
            cmd = 'gcc  -nostdlib -Wl,--omagic -Wl,--build-id=none  -nostdinc -Wl,--gc-sections -no-pie -Wl,-m,elf_x86_64 -Wl,-m,elf_x86_64 -Wl,-dT,{}/lib{}plat/link64{}_aslr.lds -Wl,-T,{}/lib/uksched/extra_aslr.ld {} -o app-lambda_{}-x86_64{}_aslr'.format(path, kvm_plat, suffix, self.unikraft_path, linker_add, kvm_plat, suffix)
        
        print(cmd)
        p = subprocess.run(cmd, shell=True)
        if p.returncode == 0:
            p = subprocess.run("strip app-lambda_{}-x86_64{}_aslr".format(kvm_plat, suffix), shell=True)
            logger.info("Relinking {:<32} {}".format(path.split("/")[5], SUCCESS))
        else:
            logger.error("Relinking failed ({})".format(path.split("/")[5]))

    def process_link64_aslr(self, lines):
        done = False
        sb = StringBuilder()
        for l in lines:
            if  "*(.text)" in l:
                sb.append(" }\n")
                continue
            elif "*(.text.*)" in l:
                sb.append(self.sb_link[".text"])
                done = True
                continue
            elif done and "}" in l:
                done = False
                continue
            if ".initrd_start = .;" in l:
                sb.append(l).append("\n")
                sb.append("initrd : {\nQUAD(0x0);\n. = . + 108954112 - 8;\n}\n")
                continue
            sb.append(l).append("\n")
        return sb.to_str()

    def get_libs_order(self, uk_name, offsets):
        
        libs = list()
        with open(uk_name) as file:
            lines = [line.rstrip() for line in file]
            
        for line in lines:
            if ".text." in line and ".boot)" not in line:
                splitted = line.split(":")
                regexp = re.compile(r"\.\s=\s\.\s\+\s0[xX][0-9a-fA-F]+;")
                if regexp.search(line):
                    line = splitted[0].split(";")
                    offsets.append(line[0] + ";")
                    line = line[1].strip().replace(".text.", "")
                else:
                    offsets.append("")
                    line = splitted[0].strip().replace(".text.", "")
                libs.append(line)
        return libs

    def process_linking(self):
        
        for uk in self.uks:
            libs = list()
            self.sb_link[".text"] = ""
            suffix=""
            if self.is_dce and self.same_mapping:
                suffix="_dce"
                offsets = list()
                # For DCE, use the same lib order than normal and spacer
                ukname = os.path.join(self.workspace.replace("_size", ""), uk.name, "build/lib{}plat/link64_aslr.lds".format(uk.kvm_plat)) 
                for app_lib in self.get_libs_order(ukname, offsets):
                    libs.append(".text.{} : {{ {}{}(.text); }}\n".format(app_lib, app_lib, OBJ_EXT))
                    self.libs_order_app[uk.name].append(app_lib)
                    
                self.offset_app[uk.name] = offsets
            else:
                offset=""
                for app_lib in uk.objects:
                    addend=""
                    if 'liblambda' in app_lib:
                        addend = "{}{}(.text.*);".format(app_lib, OBJ_EXT)

                    if self.offset:
                        offset_nb = random.randint(self.min_random,self.max_random)
                        offset = ". = . + 0x{:x};".format(offset_nb)
                        
                    libs.append("{}.text.{} : {{ {}{}(.text);{} }}\n".format(offset,app_lib, app_lib, OBJ_EXT, addend))
                libs = random.sample(libs, len(libs))
            
            self.sb_link[".text"] = ''.join(libs)
        
            plat = "lib" + uk.kvm_plat + "plat"
            path = os.path.join(self.workspace, uk.name, "build")
            with open(os.path.join(path, plat, "link64.lds"), "r") as file_in, open(os.path.join(path, plat, "link64{}_aslr.lds".format(suffix)), "w") as file_out:
                file_out.write(self.process_link64_aslr(file_in.read().splitlines()))
                logger.info("Written link64{}_aslr.lds in {}/ ".format(suffix, path + "/" + plat))
            self.relink(path, uk.use_vfscore, uk.kvm_plat)
            
    def second_pass_dce(self):
        
        if not self.is_dce:
            return
        
        suffix="_dce"
        logger.info("Performing second pass linking (compact symbols)")
        for uk in self.uks:
            self.sb_link[".text"] = ""
            maps_sections = defaultdict(set)
            binary  = lief.parse("{}/app-lambda_{}-x86_64{}_aslr".format(os.path.join(self.workspace, uk.name, "build"), uk.kvm_plat, suffix))
            for section in binary.sections:
                fct = section.name
                if fct in uk.map_symbols:
                    libs = uk.map_symbols[fct]
                    for lib in libs:
                        maps_sections[lib].add("\t{}{}({});\n".format(lib.replace(".text.", ""), OBJ_EXT, fct))

            sb = StringBuilder()
            for o, lib in enumerate(self.libs_order_app[uk.name]): # maps_sections.keys():
                lib = ".text." + lib 
                values = maps_sections[lib]
                if len(values) > 0:
                    res = dict.fromkeys(values, 0)
                    l_val = {k:res[k] for k in random.sample(list(res.keys()), len(res))}
                    sb.append("{}{} : ".format(self.offset_app[uk.name][o],lib)).append("{\n")
                    for kk, v in enumerate(l_val):
                    #    if kk == len(l_val) - 1:
                    #        sb.append(". = ALIGN(0x1000);\n")
                        sb.append("{}".format(v))
                    sb.append("}\n")

            self.sb_link[".text"] = sb.to_str()
            plat = "lib" + uk.kvm_plat + "plat"
            path = os.path.join(self.workspace, uk.name, "build")
            with open(os.path.join(path, plat, "link64.lds".format(suffix)), "r") as file_in, open(os.path.join(path, plat, "link64{}_aslr.lds".format(suffix)), "w") as file_out:
                file_out.write(self.process_link64_aslr(file_in.read().splitlines()))
                logger.info("[2] Written link64{}_aslr.lds in {}/ ".format(suffix, path + "/" + plat))
            self.relink(path, uk.use_vfscore, uk.kvm_plat)
                
def main():

    parser = argparse.ArgumentParser(description='Aligner')
    parser.add_argument('-w', '--workspace',     help='Workspace Directory', type=str, default=WORKSPACE)
    parser.add_argument('-a', '--app_folder',    help='App folder Directory', type=str, default=APP)
    parser.add_argument('-c', '--compact_dce',   help='Compact DCE symbols into lib', type=str2bool, nargs='?', const=True, default=True)
    parser.add_argument('-v', '--verbose',       help='Verbose', type=str2bool, nargs='?', const=True, default=True)
    parser.add_argument('-o', '--offset',        help='Use offset for aslr (0x1 - 0x1000)', type=str2bool, nargs='?', const=True, default=True)
    parser.add_argument('-s', '--same_mapping',  help='Use same mapping that Normal uks (libs order - for DCE)', type=str2bool, nargs='?', const=True, default=True)
    parser.add_argument('-u', '--uks',           help='Unikernels to align as a list (-l uks1 uks2 ...)', nargs='+', default=UKS_INCLUDED)
    parser.add_argument('--is_dce',              help='ASLR for dce', type=str2bool, nargs='?', const=True, default=False)
    parser.add_argument('--min',                 help='Min value for random offset', type=int, default=MIN_RANDOM)
    parser.add_argument('--max',                 help='Max value for random offset', type=int, default=MAX_RANDOM)
    
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.ERROR)
        ch = logging.StreamHandler()
        ch.setLevel(logging.ERROR)

    # create console handler with a higher log level
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
        
    aslrManager = AslrManager(args)
    aslrManager.process_folder()
    if aslrManager.is_dce:
        aslrManager.process_symbols()

    aslrManager.process_linking()
    
    if aslrManager.is_dce and args.compact_dce:
        aslrManager.second_pass_dce()

if __name__ == '__main__':
    main()