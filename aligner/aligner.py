#!/usr/bin/python3
import sys
import argparse
import logging

from ukManager import UkManager
from utils import CustomFormatter, logger

WORKSPACE   = "/home/unikraft/versioning/"
LIBS_NAME   = 'dict_libs.json'
LIBS_NAME_ASLR = 'dict_libs_aslr.json'

LOC_COUNTER = 0x10b000
DCE_ALONE   = False
USE_SNAPSHOT= False
LINK        = True
AGGREGATE   = True
GROUP       = True
COPY_OBJS   = False
USE_ID      = -1

UKS_INCLUDED = ["lib-helloworld-remove", "lib-hanoi-remove"]

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

    parser = argparse.ArgumentParser(description='Aligner')
    parser.add_argument('-w', '--workspace',     help='Workspace Directory', type=str, default=WORKSPACE)
    parser.add_argument('-l', '--loc',           help='Location counter', type=int, default=LOC_COUNTER)
    parser.add_argument('-d', '--dce',           help='Apply DCE on standalone lib', type=str2bool, nargs='?', const=True, default=DCE_ALONE)
    parser.add_argument('-r', '--rel',           help='Relink with the new mapping', type=str2bool, nargs='?', const=True, default=LINK)
    parser.add_argument('-v', '--verbose',       help='Verbose', type=str2bool, nargs='?', const=True, default=True)
    parser.add_argument('-u', '--uks',           help='Unikernels to align as a list (-l uks1 uks2 ...)', nargs='+', default=UKS_INCLUDED)
    parser.add_argument('-g', '--group',         help='Group common libraries to an aggregated section', type=str2bool, nargs='?', const=True, default=GROUP)
    parser.add_argument('-o', '--copy_objs',     help="Copy object files to keep consistency", type=str2bool, nargs='?', const=True, default=COPY_OBJS)
    
    parser.add_argument('--aggregate',           help="Aggregate rodata with text in a common sections", type=int, default=AGGREGATE)
    parser.add_argument('--use-id',              help="Add id to app name (sqlite1, sqlite2)", type=int, default=USE_ID)
    parser.add_argument('--relink-only',         help="Relink only", type=str2bool, nargs='?', const=True, default=False)
    parser.add_argument('--aslr',                help="Use aslr (0: disabled - 1: fixed indirection table - 2: with ASLR support)", type=int, default=0)
    parser.add_argument('--use_ind',             help="Add indirection table for versionning.", type=int, default=0)
    parser.add_argument('--use_initrd',          help="Use initrd", type=str2bool, nargs='?', const=True, default=False)
    
    parser.add_argument('--aslr_map',            help="Use a map of rodata for aslr (increase the sharing)", type=str2bool, nargs='?', const=True, default=True)
    parser.add_argument('--aslr_same_mapping',   help='Use same mapping than normal uks (libs order)', type=str2bool, nargs='?', const=True, default=True)
    parser.add_argument('--rewrite',             help='rewrite all sections', type=str2bool, nargs='?', const=True, default=True)
    parser.add_argument('--snapshot',            help='align for snapshoting', type=str2bool, nargs='?', const=True, default=USE_SNAPSHOT)
    parser.add_argument('--dyn_version_offset',  help='Offset to support the dynamic version', type=int, default=0x0)
    args = parser.parse_args()
  
    if args.aslr == 1:
        args.aslr = 2
        args.loc += 0x2000
        args.group = False
        
    if args.snapshot:
        args.group = False

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

    ukManager = UkManager(args)
    ukManager.process_folder()
    ukManager.process_maps()

    if ukManager.copy_objs:
        ukManager.copy_all_objs()
        
    if args.relink_only:
        ukManager.relink_only()
        sys.exit(0)

    ukManager.update_link_file()
    #if ukManager.use_ind and args.aslr == 0:
    ukManager.binary_rewrite_version(args.aslr != 0)

if __name__ == '__main__':
    main()