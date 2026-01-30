#!/usr/bin/python3

from elftools.elf.elffile import ELFFile
import argparse
import hashlib
import json
import operator
import os

WORKSPACE    = "/home/unikraft/versioning/apps/"
UKS_INCLUDED = ["lib-helloworld", "lib-hanoi", "lib-helloworld-perf", "lib-hanoi-perf", "lib-nginx", "lib-nginx-perf", "lib-dns", "lib-dns-perf", "lib-proxy", "lib-ntp", "lib-ftp", "lib-echoreply", "lib-httpreply", "lib-sqlite", "lib-sqlite-perf", "lib-lambda-perf"]
UKNAME       ="build/unikernel_kvmfc-x86_64_local_align_aslr"

maps_md5=dict()
lib_instances=dict()

class ukSections:
    def __init__(self, name, size):
        self.name = name
        self.used_by = list()
        self.size = size
        self.total_instances=0
        
    def __str__(self) -> str:
        return "name: {}, ratio: {}/{}".format(self.name, len(self.used_by), self.total_instances)

    def __repr__(self) -> str:
        return "name: {}, ratio: {}/{}".format(self.name, len(self.used_by), self.total_instances)
    
    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4)

def process_file(uk_name):
    ind_sec = list()
    with open(uk_name, 'rb') as f:
        elffile = ELFFile(f)

        for _, section in enumerate(elffile.iter_sections()):

            if ".ind" in section.name:
                ind_sec.append(section)
            elif ".rodata" in section.name:
                data_sec = section.data()
                result = hashlib.md5(data_sec)
                result = result.hexdigest()
                
                if section.name not in lib_instances:
                    lib_instances[section.name] = 1
                else:
                    lib_instances[section.name] += 1
                    
                if result not in maps_md5:
                    ukSec = ukSections(section.name, len(data_sec))
                    ukSec.used_by.append(uk_name.split("/")[5])
                    ukSec.total_instances = lib_instances[section.name]
                    maps_md5[result]=ukSec
                else:
                    ukSec = maps_md5[result]
                    ukSec.used_by.append(uk_name.split("/")[5])
                    ukSec.total_instances = lib_instances[section.name]
                #print("{}: len={} md5={}".format(section.name, len(data_sec), ))
    
def main():
    
    parser = argparse.ArgumentParser(description='Compare unikernels (ALSR) libraries with md5')
    parser.add_argument('-w', '--workspace',     help='Workspace Directory', type=str, default=WORKSPACE)
    parser.add_argument('-u', '--uks',           help='Unikernels to align as a list (-l uks1 uks2 ...)', nargs='+', default=UKS_INCLUDED)
    parser.add_argument('-n', '--name',          help='Unikernel name', type=str, default=UKNAME)
    args = parser.parse_args()

    for uk in args.uks:
        uk = os.path.join(args.workspace, uk, args.name)
        #print(uk)
        process_file(uk)
    
    map_json = dict()
    no_relocation = list()
    have_relocation = list()
    
    marklist = sorted(maps_md5.values(), key=operator.attrgetter('total_instances'), reverse=True)
    
    for v in marklist:
        name = v.name.replace(".rodata.", "")
        if len(v.used_by) == v.total_instances and v.total_instances > 1:
            #print(name)
            no_relocation.append(name)
        else:
            if name not in have_relocation:
                have_relocation.append(name)
    
    map_json["no_relocation"]=no_relocation
    map_json["have_relocation"]=have_relocation
    
    with open("rodata_maps.json", "w") as json_out:
        json.dump(dict(map_json), json_out, indent=2)

    '''
    with open("rodata_maps_debug.json", "w") as json_out:
        _ = json.dump(maps_md5, json_out, default=vars, indent=2)
    '''
    
    print("Written {}".format("rodata_maps.json"))

if __name__ == '__main__':
    main()