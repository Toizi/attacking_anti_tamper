#!/usr/bin/env python2

import os
import sys
import pickle
import argparse
from keystone import *
from binascii import hexlify

from triton import *
try:
    from triton_autocomplete import *
except ImportError:
    pass

class SavedInstruction:

    def __init__(self, ctx, inst):
        self.addr = inst.getAddress()
        self.opcode = inst.getOpcode()
        self.trace_next = ctx.getConcreteRegisterValue(ctx.registers.rip)

def l2b(l):
    '''converts list of byte-sized integers to str/bytes'''
    return ''.join((chr(c) for c in l))

def l2h(l):
    '''converts list of byte-sized integers to str as hex representation'''
    return hexlify(l2b(l))

def create_from_path(fpath, dbg_output):
    with open(fpath, 'rb') as f:
        saved_insts = pickle.load(f)
    return create(saved_insts, dbg_output)
    
def create(saved_insts, dbg_output):
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)

    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    patches = []
    for inst in saved_insts:
        tinst = Instruction(inst.opcode)
        tinst.setAddress(inst.addr)
        ctx.processing(tinst)

        if dbg_output:
            print('{0: <60} => {1:#x}'.format(tinst, inst.trace_next))
        if tinst.isBranch():
            dest = tinst.getOperands()[0]
            # skip indirect branches
            if dest.getType() == OPERAND.REG:
                continue
            # extract target address
            dest = dest.getValue()

            if dbg_output:
                print('  is branch')
            if dest == inst.trace_next:
                asm_str = 'jmp {:#x}'.format(dest)
                encoding, count = ks.asm(asm_str, tinst.getAddress())
                # print('{} = {}'.format(tinst, l2h(encoding)))
                if count > len(inst.opcode):
                    print('patch {} for {} is too big'.format(l2h(encoding), tinst))
                    return None
                patches.append((tinst.getAddress(), l2b(encoding), asm_str))
            else:
                patches.append((tinst.getAddress(), len(inst.opcode) * '\x90', 'nop * {}'.format(len(inst.opcode))))
    return patches


def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging information",
        action="store_true")
    parser.add_argument("-o", "--output",
        help="output path of the patch data, stdout if empty",
        required=False)
    parser.add_argument("tainted_locations_path", type=str,
        help="path to tainted_locs.bin created by taint analysis")
    
    args = parser.parse_args(argv)

    return args

def main(argv):
    args = parse_args(argv)
    patches = create_from_path(args.tainted_locations_path, args.verbose is True)
    if patches is None:
        return False
    
    if not args.output:
        print(repr(patches))
    else:
        with open(args.output, 'w') as f:
            f.write(repr(patches))
    return True

if __name__ == '__main__':
    main(sys.argv[1:])