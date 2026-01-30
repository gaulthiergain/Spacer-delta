import re
import os
from io import StringIO

class StringBuilder:
     _file_str = None

     def __init__(self):
        self._file_str = StringIO()

     def Append(self, str):
        if len(str) == 0:
            return
        if len(str) == 1 and str == "\n":
            return    
        self._file_str.write(str)

     def getvalue(self):
        return self._file_str.getvalue()

WORKDIR = "/home/unikraft/versioning/acmp"

def withPlt(filename):
    
    with open(filename + ".txt") as f:
        lines = [line.rstrip('\n') for line in f]

    sb = StringBuilder()
    previous = ".text"
    
    for l in lines:
        x = re.search("[0-9a-fA-F]{6}:", l)
        if x != None and "pthread_embedded" not in l:
            y = re.search("([0-9a-fA-F]{2}\s){1,}\s", l)
            if y != None:
                sb.Append(" " + y.group()+"\n")
        else:
            
            if l.lstrip().startswith("# "):
                continue
            
            x = re.search("[0-9a-fA-F]{16}", l)
            if x != None:
                sb.Append(l.split()[1] + "\n")
            else:
                if "Disassembly" in l:
                    
                    spt = l.split(".text.")
                    if len(spt) > 1:
                        spt[1] = spt[1].replace(":", "")
                    else:
                        sb.Append("========================" + l+ "========================\n")
                        continue
                    with open(os.path.join(WORKDIR, "with_plt", previous + ".txt"), "w") as f:
                        f.write(sb.getvalue())
                    
                    previous = spt[1]
                    sb = StringBuilder()
                    sb.Append("========================" + l+ "========================\n")
                else:
                    sb.Append(l + "\n")
    
    with open(os.path.join(WORKDIR, "with_plt", previous + ".txt"), "w") as f:
        f.write(sb.getvalue())
                    
def withoutPlt(filename):
    
    is_plt = False
    with open(filename + ".txt") as f:
        lines = [line.rstrip('\n') for line in f]
        
    sb = StringBuilder()
    previous = ".text"
    for l in lines:
        x = re.search("[0-9a-fA-F]{6}:", l)
        if x != None and "pthread_embedded" not in l:
            y = re.search("([0-9a-fA-F]{2}\s){1,}\s", l)
            if y != None:
                if not is_plt:
                    sb.Append(" " + y.group()+"\n")
        else:
            
            if l.lstrip().startswith("# "):
                continue
            
            x = re.search("[0-9a-fA-F]{16}", l)
            if x != None:
                if not is_plt:
                    sb.Append(l.split()[1] + "\n")
            else:
                if ".plt." in l:
                    is_plt = True
                    continue
                elif ".text." in l:
                    is_plt = False
                
                if "Disassembly" in l:
                    
                    spt = l.split(".text.")
                    if len(spt) > 1:
                        spt[1] = spt[1].replace(":", "")
                    else:
                        continue
                    with open(os.path.join(WORKDIR, "without_plt", previous + ".txt"), "w") as f:
                        f.write(sb.getvalue())
                    
                    previous = spt[1]
                    sb = StringBuilder()
                    sb.Append("========================" + l+ "========================\n")
                else:
                    sb.Append(l + "\n")
    
    with open(os.path.join(WORKDIR, "without_plt", previous + ".txt"), "w") as f:
        f.write(sb.getvalue())
          
def main():
    if not os.path.exists(os.path.join(WORKDIR, "without_plt")):
        os.makedirs(os.path.join(WORKDIR, "without_plt"))
    if not os.path.exists(os.path.join(WORKDIR, "with_plt")):
        os.makedirs(os.path.join(WORKDIR, "with_plt"))
    
    obj = os.path.join(WORKDIR, "objdump")
    withoutPlt(obj)
    withPlt(obj)
                        
if __name__ == "__main__":
    main()