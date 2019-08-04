from __future__ import print_function
from triton import *
from pintool import *

import os
import re

tainted_instrs = {}
def record_taint(instr):
    global tainted_instrs
    if instr.isTainted():
        tainted_instrs[instr.getAddress()] = instr
    return

main_modules = []
def apply_taint(img_path, img_base, img_size):
    global main_modules
    print("apply_taint: {}, {:#x}, {:#x}".format(img_path, img_base, img_size))
    if main_module_name in img_path:
        with open('/proc/self/maps', 'r') as f:
            data = f.read()

        regex = re.compile(r'(?P<start>[a-f0-9]+)-(?P<end>[a-f0-9]+) ..(?P<exec>.). ([a-f0-9]+) (\d\d:\d\d) (\d+)([ \t]+(?P<path>.*)$)?', re.MULTILINE)
        for match in re.finditer(regex, data):
            if main_module_name not in match.group('path'):
                continue
            
            if match.group('exec') != 'x':
                continue
            start_addr = int(match.group('start'), base=16)
            end_addr = int(match.group('end'), base=16)
            print('tainting {:#x} - {:#x}'.format(start_addr, end_addr))
            main_modules.append((start_addr, end_addr))
            taint_size = 64
            for i in range(start_addr, end_addr, taint_size):
                ctx.taintMemory(MemoryAccess(i, taint_size))

def execution_done():
    global tainted_instrs
    tainted_instrs = {addr : inst for addr, inst in tainted_instrs.items()
        if main_modules[0][0] <= addr < main_modules[0][1]}
    print('[*] filtered tainted addresses to only contain main module locations')
    
    print('[+] tainted addresses:')
    for addr in sorted(tainted_instrs):
        inst = tainted_instrs[addr]
        print('  {:#018x}'.format(addr))


def main():
    global ctx, main_module_name
    ctx = getTritonContext()
    ctx.enableSymbolicEngine(False)
    ctx.enableTaintEngine(True)

    startAnalysisFromEntry()

    real_args_start = os.sys.argv.index('--') + 1
    main_module_name = os.sys.argv[real_args_start]
    insertCall(record_taint, INSERT_POINT.BEFORE)
    insertCall(apply_taint, INSERT_POINT.IMAGE_LOAD)
    insertCall(execution_done, INSERT_POINT.FINI)

    runProgram()

if __name__ == '__main__':
    main()