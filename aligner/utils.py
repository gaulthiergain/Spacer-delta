import math
import logging

SUCCESS = '\033[92m' + "[SUCCESS]" + "\x1b[0m"
logger  = logging.getLogger("Aligner")

LDS_VFSCORE="SECTIONS\n{\n __start_vfs__param_arg = LOADADDR(\n vfs__param_arg);\n vfs__param_arg : {\n  KEEP (*(vfs__param_arg))\n }\n __stop_vfs__param_arg = LOADADDR(\n vfs__param_arg) +\n SIZEOF(\n vfs__param_arg);\n}\nINSERT AFTER .uk_thread_inittab;\n"
LDS_NETDEV="SECTIONS\n{\n__start_netdev__param_arg = LOADADDR(\n netdev__param_arg);\n netdev__param_arg : {\n  KEEP (*(netdev__param_arg))\n }\n __stop_netdev__param_arg = LOADADDR(\n netdev__param_arg) +\n SIZEOF(\n netdev__param_arg);\n}INSERT AFTER .uk_thread_inittab;\n"
LDS_UKS=". = ALIGN((1 << 12)); __eh_frame_start = .; .eh_frame : { *(.eh_frame) *(.eh_frame.*) } __eh_frame_end = .; __eh_frame_hdr_start = .; .eh_frame_hdr : { *(.eh_frame_hdr) *(.eh_frame_hdr.*) } __eh_frame_hdr_end = .;\n. = ALIGN((1 << 12)); uk_ctortab_start = .;"\
        ".uk_ctortab : { KEEP(*(SORT_BY_NAME(.uk_ctortab[0-9]))) } uk_ctortab_end = .;\nuk_inittab_start = .; .uk_inittab : { KEEP(*(SORT_BY_NAME(.uk_inittab[1-6][0-9]))) } uk_inittab_end = .;\n. = ALIGN(0x8); .uk_eventtab : { KEEP(*(SORT_BY_NAME(.uk_event_*))) }"

class CustomFormatter(logging.Formatter):

    blue = '\033[94m'
    green = '\033[92m'
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    #format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    format = "[%(levelname)s]"
    body = " %(message)s" # (%(filename)s:%(lineno)d)

    FORMATS = {
        logging.DEBUG: green + format + reset + body,
        logging.INFO: blue + format + reset+ body,
        logging.WARNING: yellow + format + reset+ body,
        logging.ERROR: red + format + reset+ body,
        logging.CRITICAL: bold_red + format + reset+ body
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def round_to_n(x, base):
    if base == 0:
        return 0
    return base * math.ceil(x/base)

def global_maps_display(global_maps):
    for k,v in global_maps.items():
        print(k + " (" + str(v.occurence) + "): " + str(v.ukLib.total_size))