#!/usr/bin/env python2
import r2pipe
import sys
import os
import shutil
from binascii import hexlify

def apply_patch(fpath, data):
    cmds = []
    for addr, bin_data, cmd_str in data:
        cmds.append('wx {} @ {:#x}'.format(hexlify(bin_data), addr))
    
    r2 = r2pipe.open(fpath, ['-w'])
    for cmd in cmds:
        r2.cmd(cmd)
    r2.quit()

def patch_program(input_path, output_path, data):
    try:
        shutil.copyfile(input_path, output_path)
    except IOError:
        print('could not copy input file to {}'.format(output_path))
        return False
    apply_patch(output_path, data)
    return True


def main():
    data = [(4199926, '\xeb\x15', 'jmp 0x40160d')]
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
    return patch_program(input_path, patched_path, data)


if __name__ == '__main__':
    main()
