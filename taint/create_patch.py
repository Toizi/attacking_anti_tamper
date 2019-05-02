#!/usr/bin/env python2

import os
import sys
import pickle
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

def create_from_path(fpath):
    with open(fpath, 'rb') as f:
        saved_insts = pickle.load(f)
    return create_patch(saved_insts)
    
def create(saved_insts):
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)

    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    patches = []
    for inst in saved_insts:
        tinst = Instruction(inst.opcode)
        tinst.setAddress(inst.addr)
        ctx.processing(tinst)

        # print('{0} '.format(tinst, inst.trace_next))
        if tinst.isBranch():
            dest = tinst.getOperands()[0]
            # skip indirect branches
            if dest.getType() == OPERAND.REG:
                continue
            # extract target address
            dest = dest.getValue()

            print('{:#x}: inst.trace_next = {:x}'.format(inst.addr, inst.trace_next))
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


def main(argv):
    if len(argv) > 1:
        input_path = argv[1]
    else:
        this_dir = os.path.dirname(__file__)
        input_path = os.path.join(this_dir, '../samples/instrace_logs/tainted_locs.bin')
    patches = create_from_path(input_path)
    if patches is None:
        return
    
    print(repr(patches))

if __name__ == '__main__':
    main(sys.argv)