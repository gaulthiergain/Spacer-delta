import os
import re
import sys
import json
import time
import shlex
import random
import shutil
import subprocess

JSON_MAPS_FILE='aslr/ind_map.json'

from unikernels import *
from aslr import binary_rewriter_version
from utils import round_to_n, logger, SUCCESS, LDS_VFSCORE, LDS_NETDEV, LDS_UKS
from stringBuilder import StringBuilder

exclude_app_lwip = ["lib-helloworld", "lib-sqlite-perf", "lib-sqlite","lib-hanoi-perf","lib-lambda-perf","lib-matrix-perf","lib-read-perf","lib-write-perf"]

class UkManager:
    def __init__(self, args):
        self.uks = list()
        self.workspace = os.path.join(args.workspace + "apps")
        self.unikraft_path = os.path.join(args.workspace + "unikraft")
        self.must_relink = args.rel
        self.loc_counter = args.loc
        self.uks_included = args.uks
        self.dce = args.dce
        self.copy_objs = args.copy_objs
        self.aslr = args.aslr
        self.aslr_map = args.aslr_map
        self.snapshot = args.snapshot
        self.same_mapping = args.aslr_same_mapping
        self.group_common = args.group
        self.rewrite_all = args.rewrite
        self.use_id = args.use_id
        self.use_initrd = args.use_initrd
        self.use_ind = args.use_ind
        self.dyn_version_offset = args.dyn_version_offset
        self.common_to_all = dict()
        self.common_subset = dict()
        self.objs_files = dict()
        self.indivial = dict()
        self.global_maps = dict()
        self.loc_sect = dict()
        self.sb_link = dict()
        self.nb_version = 0

    def process_folder(self):
        for d in os.listdir(self.workspace):
            if d in self.uks_included:
                uk = Unikernel(d, os.path.join(self.workspace, d))
                logger.info("Process {} ".format(d))
                uk.process_build_folder(os.path.join(self.workspace, d, "build/"), self.global_maps, self.objs_files, True, self.dce)
                self.uks.append(uk)
        
        if len(self.uks) <= 1 and self.aslr == 0:
            logger.fatal("At least 2 unikernels instances are required. Found: {}".format(len(self.uks)))
            sys.exit(1)

    def process_maps(self):
        for k,v in self.global_maps.items():
            if v.occurence == len(self.uks):
                self.common_to_all[k] = v
            elif v.occurence > 1:
                self.common_subset[k] = v
            else:
                self.indivial[k] = v
    
    def compute_common_loc(self, ukLib, sb, array_sect):
        
            ct_el1 = "/* 0x{:x} + 0x{:x} = 0x{:x} */".format(self.loc_counter, ukLib.total_size[array_sect[0]], ukLib.total_size[array_sect[0]] + self.loc_counter)
            ct_el2 = "/* 0x{:x} + 0x{:x} = 0x{:x} */".format(ukLib.total_size[array_sect[0]] + self.loc_counter, ukLib.total_size[array_sect[1]], ukLib.total_size[array_sect[1]] + ukLib.total_size[array_sect[0]] + self.loc_counter)
            
            byte_ins=""
            if "lambda-v" in ukLib.name or "applambda" in ukLib.name:
                byte_ins="\nBYTE(0xF1);\n"
                ukLib.total_size[".text"] += 1

            if self.group_common:
                sb.append("\n\t{}{}({}); {}\n\t{}{}({}.*);".format(ukLib.name, OBJ_EXT, array_sect[0], ct_el1, ukLib.name, OBJ_EXT, array_sect[0]))
                sb.append(byte_ins)
                sb.append("\n\t{}{}({});\n\t{}{}({}.*); {}\n".format(ukLib.name, OBJ_EXT, array_sect[1], ukLib.name, OBJ_EXT, array_sect[1], ct_el2))
            else:
                sb.append("{}.{} 0x{:x} : {{\n\t{}{}({}); {}\n\t{}{}({}.*);\n".format(''.join(array_sect), ukLib.name, self.loc_counter, ukLib.name, OBJ_EXT, array_sect[0], ct_el1, ukLib.name, OBJ_EXT, array_sect[0]))
                sb.append(byte_ins)
                sb.append("\t{}{}({}); \n\t{}{}({}.*); {}\n}}\n".format(ukLib.name, OBJ_EXT, array_sect[1], ukLib.name, OBJ_EXT, array_sect[1], ct_el2))

            for type_sect in array_sect:
                
                if ukLib.total_size[type_sect] == 0:
                    logger.warning("Skip {} has a size of 0".format(ukLib.name + "(" + type_sect + ")"))
                    continue
            
                self.loc_counter += ukLib.total_size[type_sect]
            
            if not self.group_common:
                self.loc_counter = round_to_n(self.loc_counter, PAGE_SIZE)

    def process_common_to_all(self):
        sb = StringBuilder()
        
        if self.group_common:
            sb.append(".text.rodata.common 0x{:x} : {{\n".format(self.loc_sect["_ectors"] + PAGE_SIZE))
        
        appLib = None
        ukLibsLambda = list()
        for _, ukLib in self.common_to_all.items():
            if "app" in ukLib.name and "lambda" in ukLib.name:
                appLib = ukLib
                logger.info("Skip {}".format(ukLib.name))
                continue
            self.dyn_version_offset = 1
            if "lib-lambda" in ukLib.name and self.dyn_version_offset > 0:
                logger.info("Skip {}".format(ukLib.name))
                self.nb_version += 1
                ukLibsLambda.append(ukLib)
                continue
            self.compute_common_loc(ukLib, sb, [".text", ".rodata"])
            if self.snapshot:
                self.compute_common_loc(ukLib, sb, [".data", ".bss"])
            
        if self.group_common:
            sb.append("}\n")
        
        # Only for test 23
        #self.loc_counter += PAGE_SIZE
        
        if appLib is not None:
            self.loc_counter = round_to_n(self.loc_counter, PAGE_SIZE)
            ind_size = 0x1000
            sb.append(".ind.{} : ALIGN(0x1000) {{ BYTE(1);. += 0x{:x}-1; }}\n".format("applambda", ind_size))
            self.loc_counter += ind_size
            sb.append(".text.rodata.applambda 0x{:x} : {{\n".format(self.loc_counter))
            self.compute_common_loc(appLib, sb, [".text", ".rodata"])
            sb.append("}\n")

        self.loc_counter = round_to_n(self.loc_counter, PAGE_SIZE)
        for i, ukLib in enumerate(ukLibsLambda):
            ind_size = 0x2000
            sb.append(".ind.{} : ALIGN(0x1000) {{ BYTE(1);. += 0x{:x}-1; }}\n".format("lib-lambda-v"+str(i+1), ind_size))
            self.loc_counter += ind_size
            sb.append(".text.rodata.lib-lambda-v{} 0x{:x} : {{\n".format(i+1, self.loc_counter))
            self.compute_common_loc(ukLib, sb, [".text", ".rodata"])
            sb.append("}\n")

        return sb.to_str()

    def compute_loc(self, subset, type_maps):
        if len(subset) == 0:
            return
        
        self.loc_counter = round_to_n(self.loc_counter, PAGE_SIZE)

        for uk in self.uks:
            
            uk.loc_counter = self.loc_counter
            uk.update_loc_counter(subset, type_maps, self.dce, self.snapshot)

        self.loc_counter = max(uk.loc_counter for uk in self.uks)
            
    def update_link_file(self):
        if (self.aslr == 0):
            self.update_link_file_spacer()
        elif (self.aslr == 1 or self.aslr == 2):
            self.update_link_file_aslr()
        else:
            logger.fatal("aslr must either be 0, 1 or 2. Found: {}".format(len(self.uks)))
            sys.exit(1)    
    
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
    
    def update_link_file_aslr(self):

        maps_size_libs = dict()
        try:
            with open(JSON_MAPS_FILE) as json_file:
                maps_size_libs = json.load(json_file)
                print(maps_size_libs)
        except:
            logger.warning("No json file found. Continue with empty map size.")
        logger.info("Processing the mapping for {} unikernels".format(len(self.uks)))

        # uk ctor
        for s in ["_ctors", ".init_array", "_ectors"]:
            self.loc_sect[s] = self.loc_counter
            self.loc_counter += PAGE_SIZE 

        app = ""
        lambda_libs = defaultdict(list)
        for uk in self.uks:
            libs = list()
            map_libs = dict()
            for ukLib in uk.objects:

                print("Found lib: {}".format(ukLib))
                if "lambda" in ukLib:
                    print("-> Lambda lib: {}".format(ukLib))
                    lambda_libs[uk].append(ukLib)

                size_ind = PAGE_SIZE
                if '.text.' + ukLib in maps_size_libs:
                    size_ind=int(maps_size_libs['.text.' + ukLib], 16)
                elif '.text.rodata.' + ukLib in maps_size_libs:
                    size_ind=int(maps_size_libs['.text.rodata.' + ukLib], 16)
                else:
                    logger.debug("No size found for {}".format(ukLib))

                if ("liblwip" in ukLib and uk.name in exclude_app_lwip):
                    logger.warning("Ignore {} in {}".format(ukLib, uk.name))
                    continue

                if "app" in ukLib and self.rewrite_all == False:
                    
                        dict_sect = {"text":"(.text);", "rodata":"(.rodata);"}
                        if self.dce:
                            dict_sect = {"text":"(.text);\n\t{}{}(.text.*)".format(ukLib, OBJ_EXT), "rodata":"(.rodata);\n\t{}{}(.rodata.*)".format(ukLib, OBJ_EXT)}
                        
                        app = ".text.rodata.{} : ALIGN(0x1000) {{\n\t{}{}{};\n\tBYTE(0xF1);\n\t{}{}{};\n}}".format(ukLib, ukLib, OBJ_EXT, dict_sect["text"], ukLib, OBJ_EXT, dict_sect["rodata"])  
                        app += ".data.bss.{} : ALIGN(0x1000) {{\n\t{}{}(.data);\n\t{}{}(.bss);\n}}\n".format(ukLib, ukLib, OBJ_EXT, ukLib, OBJ_EXT)
                        
                        map_libs[ukLib] = app
                        
                elif "app" in ukLib and self.rewrite_all == True:
                    
                        dict_sect = {"text":"(.text);", "rodata":"(.rodata);"}
                        if self.dce:
                            dict_sect = {"text":"(.text);\n\t{}{}(.text.*)".format(ukLib, OBJ_EXT), "rodata":"(.rodata);\n\t{}{}(.rodata.*)".format(ukLib, OBJ_EXT)}
                        
                        app ="\n.ind.{} : ALIGN(0x1000) {{ BYTE(1);. += 0x{:x}-1; }}\n.text.rodata.{} : ALIGN(0x1000) {{\n\t{}{}{};BYTE(0xF1);\n\t{}{}{};\n}}\n".format(ukLib, size_ind, ukLib, ukLib, OBJ_EXT, dict_sect["text"], ukLib, OBJ_EXT, dict_sect["rodata"])
                        app += ".data.bss.{} : ALIGN(0x1000) {{\n\t{}{}(.data);\n\t{}{}(.bss);\n}}\n".format(ukLib, ukLib, OBJ_EXT, ukLib, OBJ_EXT)
                        map_libs[ukLib] = app
                        
                else:
                    
                    if ukLib not in ["libkvmvirtionet","libukdebug","libvfscore","libuklibparam","libukargparse","libkvmfcplat","libnewlibm","libkvmvirtio","libnewlibc","libuktimeconv", "liblwip", "libscamper", "libsqlite", "libnginx"]:
                        if ukLib == "libuklock":
                            w ="\n.text.rodata.{} : ALIGN(0x1000) {{\n\t{}{}(.text);\n\tBYTE(0xF1);\n\t{}{}(.rodata);\n}}\n".format(ukLib, ukLib, OBJ_EXT, ukLib, OBJ_EXT)
                        else:
                            w ="\n.ind.{} : ALIGN(0x1000) {{ BYTE(1);. += 0x{:x}-1; }}\n.text.rodata.{} : ALIGN(0x1000) {{\n\t{}{}(.text);\n\t{}{}(.text.*);\n\tBYTE(0xF1);\n\t{}{}(.rodata);\n\t{}{}(.rodata.*);\n\n}}\n".format(ukLib, size_ind, ukLib, ukLib, OBJ_EXT, ukLib, OBJ_EXT, ukLib, OBJ_EXT, ukLib, OBJ_EXT)
                    else:
                        w ="\n.ind.{} : ALIGN(0x1000) {{ BYTE(1);. += 0x{:x}-1; }}\n.text.rodata.{} : ALIGN(0x1000) {{\n\t{}{}(.text);\n\t{}{}(.text.*);\n\n}}\n".format(ukLib, size_ind, ukLib, ukLib, OBJ_EXT, ukLib, OBJ_EXT)
                        w +=".rodata.{} : ALIGN(0x1000) {{\n\t{}{}(.rodata);\n\t{}{}(.rodata.*);\n}}\n".format(ukLib, ukLib, OBJ_EXT, ukLib, OBJ_EXT)
                        
                    w += ".data.bss.{} : ALIGN(0x1000) {{\n\t{}{}(.data);\n\t{}{}(.data.*);\n\t{}{}(.bss);\n\t{}{}(.bss.*);\n}}\n".format(ukLib, ukLib, OBJ_EXT, ukLib, OBJ_EXT, ukLib, OBJ_EXT, ukLib, OBJ_EXT)
                    
                    
                    libs.append(w)
                
                    map_libs[ukLib] = libs[-1] #indent to left when app is moved

            libs.append(app)
            
            if self.aslr == 2:
                if self.same_mapping:
                    # Keep the same mapping than normal and DCE unikernels (for testing purpose)
                    libs_normal = list()
                    offsets = list()
                    ukname = os.path.join(self.workspace, uk.name, "build/lib{}plat/link64_aslr.lds".format(uk.kvm_plat)) 
                    
                    i = 0
                    for lib in self.get_libs_order(ukname, offsets):
                        if ("liblwip" in lib and uk.name in exclude_app_lwip):
                            continue
                        if "app" in lib and self.use_id > 0:
                            map_libs[lib] = map_libs[lib].replace(lib, "{}{}".format(lib,self.use_id), 1)
                            #print(map_libs[lib])
                        
                        if "lambda" in lib:
                            print("Skip lambda lib: {}".format(lib))
                            continue

                        libs_normal.append(map_libs[lib])
                        #libs_normal.append(offsets[i] + map_libs[lib]) #remove
                        i = i + 1
                        
                    for lib in lambda_libs[uk]:
                        print("Lambda lib: {}".format(lib))
                        libs_normal.append(map_libs[lib])

                    libs = libs_normal
                else:
                    libs = random.sample(libs, len(libs))
                
            self.sb_link["common"] = '. = 0x{:x};\n'.format(self.loc_counter) + ''.join(libs)
            
            plat = "lib" + uk.kvm_plat + "plat"
            path = os.path.join(self.workspace, uk.name, "build")
            
            with open(os.path.join(path, plat, "link64.lds"), "r") as file_in, open(os.path.join(path, plat, "link64_out_aslr.lds"), "w") as file_out:
                file_out.write(self.process_link64_spacer_aslr(file_in.read().splitlines(), uk))
                logger.info("Written link64_out_aslr.lds in {}/ ".format(path + "/" + plat))
            if self.must_relink:
                self.relink(path, uk.use_vfscore, uk.kvm_plat)
    
    def binary_rewrite_version(self, use_aslr):
        
        uks_path = list()
        suffix=""
        if use_aslr:
            suffix="_aslr"
        for uk in self.uks:
            uks_path.append(os.path.join(uk.workspace, "build/unikernel_kvmfc-x86_64_local_align" + suffix + ".dbg"))
        start = time.time()
        
        binary_rewriter_version.rewrite_uk_v(uks_path, use_aslr)
        
        end = time.time()
        logger.info("Binary rewritting of {} uks (time: {}) {} ".format(len(self.uks), end-start, SUCCESS))
                
    def binary_rewrite(self):
        
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        for uk in self.uks:
            logger.info("Perform Binary rewriting of {}_aslr".format(uk.name))
            ukname = os.path.join(uk.workspace, "build/unikernel_kvmfc-x86_64_local_align_aslr.dbg")
            try:
                start = time.time()
                binary_rewriter_new.rewrite_uk(ukname, os.path.join("aslr",JSON_MAPS_FILE) , False, self.rewrite_all, True)
                end = time.time()
                logger.info("Binary rewritting {:<32} (time: {}) {} ".format(uk.name + "_aslr", end-start, SUCCESS))
            except Exception as e:
                logger.error("Binary rewritting failed ({}) - {}".format(uk.name, e))

    def relink_only(self):
        for uk in self.uks:
            plat = "lib" + uk.kvm_plat + "plat"
            path = os.path.join(self.workspace, uk.name, "build")
            self.relink(path, uk.use_vfscore, uk.kvm_plat)

    def update_link_file_spacer(self):

        logger.info("Processing the mapping for {} unikernels".format(len(self.uks)))
        
        # uk ctor
        for s in ["_ctors", ".init_array", "_ectors"]:
            self.loc_sect[s] = self.loc_counter
            self.loc_counter += PAGE_SIZE 
        
        # Common libs (.text)
        self.sb_link["common"] = self.process_common_to_all()
        
        sorted_x = sorted(self.common_subset.items(), key=lambda kv: kv[1].occurence, reverse=True)
        self.common_subset = dict(sorted_x)
    
        # Subset libs (.text) and then indivial lib (.text)
        self.compute_loc(self.common_subset, "subset")
        self.compute_loc(self.indivial, "individual")
        
        self.loc_counter = round_to_n(self.loc_counter, PAGE_SIZE)
        
        # For .data and .bss
        if not self.snapshot:
            max_size_sect = dict()
            for k in [".data", ".bss"]:
                #if self.dce and k == ".bss":
                #    self.loc_counter += PAGE_SIZE
                self.loc_sect[k] = self.loc_counter
                # Compute next address for next section
                max_size_sect[k] = max(uk.total_size[k] for uk in self.uks)
                self.loc_counter += round_to_n(max_size_sect[k] , PAGE_SIZE)
            
            self.loc_counter = round_to_n(self.loc_counter, PAGE_SIZE)
        
        # For .intrstack
        self.loc_sect[".intrstack"] = self.loc_counter

        # Read and write to files
        for uk in self.uks:
            plat = "lib" + uk.kvm_plat + "plat"
            path = os.path.join(self.workspace, uk.name, "build")
            with open(os.path.join(path, plat, "link64.lds"), "r") as file_in, open(os.path.join(path, plat, "link64_out.lds"), "w") as file_out:
                file_out.write(self.process_link64_spacer(file_in.read().splitlines(), uk))
                logger.info("Written link64_out.lds in {}/ ".format(path + "/" + plat))
            if self.must_relink:
                self.relink(path, uk.use_vfscore, uk.kvm_plat)

    def relink(self, path, use_vfscore, kvm_plat):           
        os.chdir(path)
        
        aslr = ""
        if self.aslr != 0:
            aslr = "_aslr"

        linker_add=""
        if use_vfscore:
            linker_add="-Wl,-T,{}/lib/vfscore/extra_out64{}.ld".format(self.unikraft_path, aslr)
        
        if os.path.isfile("{}/libvfscore/libparam.lds".format(path)):
            linker_add += " -Wl,-T,{}/libvfscore/libparam.lds".format(path)
            with open("{}/libvfscore/libparam.lds".format(path), "w") as f:
                f.write(LDS_VFSCORE)
        if os.path.isfile("{}/libuknetdev/libparam.lds".format(path)):
            linker_add += " -Wl,-T,{}/libuknetdev/libparam.lds".format(path)
            with open("{}/libuknetdev/libparam.lds".format(path), "w") as f:
                f.write(LDS_NETDEV)
        dce_gcc=""
        if self.dce:
            dce_gcc="--data-sections -Wl,--gc-sections"
        
        cmd = 'gcc -nostdlib {} -Wl,--omagic -Wl,--build-id=none -nostdinc -no-pie -Wl,-m,elf_x86_64 -Wl,-m,elf_x86_64 -Wl,-dT,{}/lib{}plat/link64_out{}.lds -Wl,-T,{}/lib/uksched/extra{}.ld {} -o unikernel_{}-x86_64_local_align{}.dbg'.format(dce_gcc, path, kvm_plat, aslr, self.unikraft_path, aslr, linker_add, kvm_plat, aslr)
        logger.info(cmd)
        p = subprocess.run(shlex.split(cmd))
        if p.returncode == 0:
            logger.info("Relinking {:<32} {}".format(path.split("/")[5], SUCCESS))
        else:
            logger.error("Relinking failed ({})".format(path.split("/")[5]))
            sys.exit(1)

    def add_str(self, i, elem):
        other=""
        if len(elem) == 2:
            other="\n\tlib-lambda-v{}".format(i) + OBJ_EXT + "({});\n\tlib-lambda-v{}".format(elem[1],i) + OBJ_EXT + "({}*);".format(elem[1],i)
        return "{}.lib-lambda-v{} : {{".format(''.join(elem),i) + "\n\tlib-lambda-v{}".format(i) + OBJ_EXT + "({});\n\tlib-lambda-v{}".format(elem[0],i) + OBJ_EXT + "({}.*);\n".format(elem[0],i) + other + "}\n";

    def process_link64_spacer(self, lines, uk):
        done = False
        sb = StringBuilder()
        str_sb = StringBuilder()
        
        regex = (r" \. = ALIGN\(\(1 << 12\)\);\n"
                r" _rodata = \.;\n"
                r" \.rodata :\n"
                r" {\n"
                r"  \*\(\.rodata\)\n"
                r"  \*\(\.rodata\.\*\)\n"
                r" }\n"
                r" _erodata = \.;")
        
        filtered_lines = list()
        for i,l in enumerate(lines):
            if "_etext = .;" in l:
                done = True
                continue
            elif "_data = .;" in l:
                filtered_lines.append(" . = ALIGN((1 << 12));\n")
                done = False
            elif "_ctors = .;" in l or "_ectors = .;" in l:
                
                str_sb.append(" . = ").append("0x{:x}".format(self.loc_sect[l.split("=")[0].strip()])).append(";\n")
                self.loc_sect[".intrstack"] = 0xF50000
                if self.use_initrd:
                    self.loc_sect[".intrstack"] = 0x2800000

            elif self.aslr == 0 and l in [" .init_array : {"]:

                x = re.findall(r"[a-z]+", l)

                if len(x) > 1 and "start" not in x:
                    x = '.'+'_'.join(x)
                else:
                    x = '.'+''.join(x[0])
                str_sb.append(" . = ").append("0x{:x}".format(self.loc_sect[x])).append(";\n")
            if done:
                str_sb.append(l + "\n")
                continue
            filtered_lines.append(l)
        
        str_sb = re.sub(regex, "", str_sb.to_str(), 0, re.MULTILINE)
        
        done = False
        for l in filtered_lines:
            
            if  "*(.text)" in l or "*(.rodata)" in l or "*(.data)" in l or "*(.bss)" in l:
                sb.append("}\n")
                continue
            elif " .text :" in l:
                sb.append("\n_rodata = .;\n")
                if self.snapshot == 1:
                    sb.append("_data = .;\n__bss_start  = .;\n")
            elif "*(COMMON)" in l:
                continue
            elif "*(.text.*)" in l:
                
                if self.aslr != 0:
                    sb.append(".ind.text : { BYTE(1);. += 0x47-1; }\n")
                sb.append(str_sb)
                sb.append(self.sb_link["common"])
                if "subset" in uk.sb_link:
                    sb.append(uk.sb_link["subset"].to_str())
                if "individual" in uk.sb_link:
                    sb.append(uk.sb_link["individual"].to_str())
                if ".intrstack" in self.loc_sect:
                    if self.snapshot == 1:
                        sb.append(". = 0x{:x};\n_etext = .;\n_erodata = .;\n_edata = .;\n.intrstack\n".format(self.loc_sect[".intrstack"]))
                    else:
                        sb.append(". = 0x{:x};".format(self.loc_sect[".data"]) + "\n_etext = .;\n_erodata = .;\n_data = .;\n.data :{\n*(.data)\n*(.data.*)\n}\n" +  ". = 0x{:x};".format(self.loc_sect[".bss"]) + "\n_edata = .;\n__bss_start  = .;\n.bss :\n{\n*(.bss)\n*(.bss.*)\n*(COMMON)\n. = ALIGN((1 << 12));\n}\n" + ". = 0x{:x};\n.intrstack".format(self.loc_sect[".intrstack"]))
                else:
                    rodata=""
                    sb.append(". = ALIGN((1 << 12));{}\n".format(rodata)).append("_etext = .;\n_erodata = .;\n_data = .;\n.data :{\n*(.data)\n*(.data.*)\n}\n_edata = .;\n. = ALIGN((1 << 12));\n__bss_start  = .;\n.bss :\n{\n*(.bss)\n*(.bss.*)\n*(COMMON)\n. = ALIGN((1 << 12));\n}\n.intrstack")
                sb.append(" :\n{\n*(.intrstack)\n. = ALIGN((1 << 12));\n}\n")
                if self.use_initrd:
                    initrd="\n. = ALIGN(0x1000);initrd_start = .;\n.initrd_start = .;\n\ninitrd : {QUAD(0x0); . = . + 108954112 - 8;}\ninitrd_end = .;\n.initrd_end = .;\n"
                    sb.append(initrd)
                sb.append("_end = .;\n.comment 0 : { *(.comment) }\n.debug 0 : { *(.debug) } .line 0 : { *(.line) } .debug_srcinfo 0 : { *(.debug_srcinfo) } .debug_sfnames 0 : { *(.debug_sfnames) } .debug_aranges 0 : { *(.debug_aranges) } .debug_pubnames 0 : { *(.debug_pubnames) } .debug_info 0 : { *(.debug_info .gnu.linkonce.wi.*) } .debug_abbrev 0 : { *(.debug_abbrev) } .debug_line 0 : { *(.debug_line .debug_line.* .debug_line_end ) } .debug_frame 0 : { *(.debug_frame) } .debug_str 0 : { *(.debug_str) } .debug_loc 0 : { *(.debug_loc) } .debug_macinfo 0 : { *(.debug_macinfo) } .debug_weaknames 0 : { *(.debug_weaknames) } .debug_funcnames 0 : { *(.debug_funcnames) } .debug_typenames 0 : { *(.debug_typenames) } .debug_varnames 0 : { *(.debug_varnames) } .debug_pubtypes 0 : { *(.debug_pubtypes) } .debug_ranges 0 : { *(.debug_ranges) } .debug_macro 0 : { *(.debug_macro) } .gnu.attributes 0 : { KEEP (*(.gnu.attributes)) }\n /DISCARD/ : { *(.note.gnu.build-id) }\n}\n")
                done = True
                return sb.to_str()
            elif done and "}" in l:
                done = False
                continue
            sb.append(l).append("\n")

    def process_link64_spacer_aslr(self, lines, uk):
        done = False
        sb = StringBuilder()
        str_sb = StringBuilder()
        
        regex = (r" \. = ALIGN\(\(1 << 12\)\);\n"
                r" _rodata = \.;\n"
                r" \.rodata :\n"
                r" {\n"
                r"  \*\(\.rodata\)\n"
                r"  \*\(\.rodata\.\*\)\n"
                r" }\n"
                r" _erodata = \.;")
        
        filtered_lines = list()
        for i,l in enumerate(lines):
            if "_etext = .;" in l:
                done = True
                continue
            elif "_data = .;" in l:
                filtered_lines.append(" . = ALIGN((1 << 12));\n")
                done = False
            elif "_ctors = .;" in l or "_ectors = .;" in l:
                str_sb.append(" . = ").append("0x{:x}".format(self.loc_sect[l.split("=")[0].strip()])).append(";\n")
            elif self.aslr == 0 and l in [" .init_array : {"]:

                x = re.findall(r"[a-z]+", l)

                if len(x) > 1 and "start" not in x:
                    x = '.'+'_'.join(x)
                else:
                    x = '.'+''.join(x[0])
                str_sb.append(" . = ").append("0x{:x}".format(self.loc_sect[x])).append(";\n")
            if done:
                str_sb.append(l + "\n")
                continue
            filtered_lines.append(l)
        
        str_sb = re.sub(regex, "", str_sb.to_str(), 0, re.MULTILINE)
        
        done = False
        for l in filtered_lines:
            
            if  "*(.text)" in l or "*(.rodata)" in l or "*(.data)" in l or "*(.bss)" in l:
                sb.append("}\n")
                continue
            elif " .text :" in l:
                sb.append("\n_rodata = .;\n")
                if self.snapshot == 1:
                    sb.append("_data = .;\n__bss_start  = .;\n")
            elif "*(COMMON)" in l:
                continue
            elif "*(.text.*)" in l:
                initrd=""
                if self.use_initrd:
                    initrd="\ninitrd_start = .;\n.initrd_start = .;\n\ninitrd : {QUAD(0x0); . = . + 108954112 - 8;}\ninitrd_end = .;\n.initrd_end = .;\n"

                if self.aslr != 0:
                    sb.append(".ind.text : { BYTE(1);. += 0x47-1; }\n")
                sb.append(str_sb)
                sb.append(self.sb_link["common"])
                if "subset" in uk.sb_link:
                    sb.append(uk.sb_link["subset"].to_str())
                if "individual" in uk.sb_link:
                    sb.append(uk.sb_link["individual"].to_str())
                if ".intrstack" in self.loc_sect:
                    sb.append("\n_etext = .;" + initrd + "\n_erodata = .;\n_data = .;\n.data :{\n*(.data)\n*(.data.*)\n}\n" +  ". = 0x{:x};".format(self.loc_sect[".bss"]) + "\n_edata = .;\n__bss_start  = .;\n.bss :\n{\n*(.bss)\n*(.bss.*)\n*(COMMON)\n. = ALIGN((1 << 12));\n}\n" + ". = 0x{:x};\n.intrstack".format(self.loc_sect[".intrstack"]))
                else:
                    rodata=""
                    sb.append(". = ALIGN((1 << 12));{}\n".format(rodata)).append("_etext = .;" + initrd + "\n_erodata = .;\n_data = .;\n.data :{\n*(.data)\n*(.data.*)\n}\n_edata = .;\n. = ALIGN((1 << 12));\n__bss_start  = .;\n.bss :\n{\n*(.bss)\n*(.bss.*)\n*(COMMON)\n. = ALIGN((1 << 12));\n}\n.intrstack")
                sb.append(" :\n{\n*(.intrstack)\n. = ALIGN((1 << 12));\n}\n_end = .;\n.comment 0 : { *(.comment) }\n.debug 0 : { *(.debug) } .line 0 : { *(.line) } .debug_srcinfo 0 : { *(.debug_srcinfo) } .debug_sfnames 0 : { *(.debug_sfnames) } .debug_aranges 0 : { *(.debug_aranges) } .debug_pubnames 0 : { *(.debug_pubnames) } .debug_info 0 : { *(.debug_info .gnu.linkonce.wi.*) } .debug_abbrev 0 : { *(.debug_abbrev) } .debug_line 0 : { *(.debug_line .debug_line.* .debug_line_end ) } .debug_frame 0 : { *(.debug_frame) } .debug_str 0 : { *(.debug_str) } .debug_loc 0 : { *(.debug_loc) } .debug_macinfo 0 : { *(.debug_macinfo) } .debug_weaknames 0 : { *(.debug_weaknames) } .debug_funcnames 0 : { *(.debug_funcnames) } .debug_typenames 0 : { *(.debug_typenames) } .debug_varnames 0 : { *(.debug_varnames) } .debug_pubtypes 0 : { *(.debug_pubtypes) } .debug_ranges 0 : { *(.debug_ranges) } .debug_macro 0 : { *(.debug_macro) } .gnu.attributes 0 : { KEEP (*(.gnu.attributes)) }\n /DISCARD/ : { *(.note.gnu.build-id) }\n}\n")
                done = True
                return sb.to_str()
            elif done and "}" in l:
                done = False
                continue
            sb.append(l).append("\n")
        

    def copy_all_objs(self):
        
        logger.info("Uniformise objects for {} unikernels".format(len(self.uks)))

        use_params = False
        # Check first if one unikernel is using libparam
        for uk in self.uks:
            if uk.use_uklibparam:
                use_params = True
                break

        for uk in self.uks:
            if use_params:
                # Copy libparam.lds
                for l in ["libvfscore", "libuknetdev"]:
                    p, _ = self.objs_files[l]
                    uk.create_param_files(l, p)
            
            # Copy objects files
            for obj in uk.objects:
                if obj in self.objs_files:
                    
                    oldsrc = os.path.join(uk.workspace, "build", obj + OBJ_EXT)
                    newsrc, _ = self.objs_files[obj]
                    
                    if os.path.samefile(newsrc, oldsrc):
                        continue
                    shutil.copyfile(newsrc, oldsrc)