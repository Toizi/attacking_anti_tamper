#!/usr/bin/env python2
import r2pipe
import sys
import os
import shutil
import argparse
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

def crack_function(input_path, fname, check_func_exists=True):
    r2 = r2pipe.open(input_path, ['-w'])
    r2_fname = 'sym.{}'.format(fname)

    if check_func_exists:
        r2.cmd('aa')
        funcs = r2.cmdj('aflj')
        fnames = [func['name'] for func in funcs]
        if r2_fname not in fnames:
            print('function {} not in list of functions {}'.format(r2_fname, fnames))
            return False
    r2.cmd('"wa xor eax, eax; ret" @ {}'.format(r2_fname))
    r2.quit()
    return True


def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging information",
                        action="store_true")
    parser.add_argument("-cf", "--crack-function", help="function to crack",
                        required=True)
    parser.add_argument("-o", "--output", help="output path", required=False)
    parser.add_argument("input_file", type=str)

    args = parser.parse_args(argv)

    # create output dir from input dir if no output was specified
    if not args.output:
        inpath, inext = os.path.splitext(os.path.abspath(args.input_file))
        args.output = os.path.join(inpath + '_cracked' + inext)

    return args

def main(argv):
    args = parse_args(argv)
    
    try:
        shutil.copyfile(args.input_file, args.output)
    except IOError:
        print('could not copy input file to {}'.format(args.output))
        return False

    return crack_function(args.output, args.crack_function)


if __name__ == '__main__':
    main(os.sys.argv[1:])
