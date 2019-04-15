#!/usr/bin/env python2
import r2pipe
import sys
import os
import shutil
from binascii import hexlify

def patch_program(fpath, data):
    cmds = []
    for addr, bin_data, cmd_str in data:
        cmds.append('wx {} @ {:#x}'.format(hexlify(bin_data), addr))
    
    r2 = r2pipe.open(fpath, ['-w'])
    for cmd in cmds:
        r2.cmd(cmd)
    r2.quit()

def main():
    data = [(4196963, '\xeb\t', 'jmp 0x400a6e'), (4197392, '\xe9\x85\x00\x00\x00', 'jmp 0x400c9a'), (4196987, '\x90\x90', 'nop * 2')]
    try:
        input_path = sys.argv[1]
        if not os.path.exists(input_path):
            print('input path invalid')
            return 1
    except IndexError:
        print('usage: {} path_to_program'.format(__file__))
        return 1
    
    in_path, ext = os.path.splitext(input_path)
    patched_path = '{}_patched{}'.format(in_path, ext)
    try:
        shutil.copyfile(input_path, patched_path)
    except IOError:
        print('could not copy input file to {}'.format(patched_path))
        return 1

    patch_program(patched_path, data)

if __name__ == '__main__':
    main()