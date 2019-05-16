#!/usr/bin/env python2
from __future__ import print_function
import struct
import sys
from .run_taint import registers, Trace, Module, saved_context_t, saved_memory_t
from .create_patch import SavedInstruction

from triton import *
try:
    from triton_autocomplete import *
except ImportError:
    pass

# MAIN_END = 0x1400038A8 # test_tamper_debug
# MAIN_END = 0x140001C6A # test_tamper
# MAIN_END = 0x140001818 # test_medium
# MAIN_END = 0x1400020B8 # test_large_debug
# MAIN_END = 0x0001400012CA
# MAIN_END = 0x000000000040062a # test_tamper_no_relro
# MAIN_END = 0x400bac # test_tamper_sc
# MAIN_END = 0

DEBUG = False
def set_debug(dbg):
    global DEBUG
    DEBUG = dbg

def dprint(*args, **kargs):
    if DEBUG:
        print('[D] ', *args, **kargs)

def u64(val):
    return struct.unpack("Q", val)[0]

def p64(val):
    return struct.pack("Q", val)

def set_triton_context(ctx, state, set_rip=False):
    dprint("[*] set_triton_context at {:#x}".format(ctx.getConcreteRegisterValue(ctx.registers.rip)))
    for reg in registers:
        if reg == 'rflags' or not set_rip and reg == 'rip': #(reg == 'rip' or reg == 'rsp'):
            continue
        reg_val = getattr(state, reg)
        triton_reg = getattr(ctx.registers, reg)
        if DEBUG:
            dprint('{: <3}: {:#018x} => {:#018x}'.format(reg, ctx.getConcreteRegisterValue(triton_reg), reg_val))
        ctx.setConcreteRegisterValue(triton_reg, reg_val)
    
def print_triton_context(ctx):
    for reg in [r for r in registers if r != 'rflags']:
        print("[C] {: <3}: {:#018x}".format(reg, ctx.getConcreteRegisterValue(getattr(ctx.registers, reg))))
    rsp = ctx.getConcreteRegisterValue(ctx.registers.rsp)
    print("\n[C] Stack:")
    for i in range(0, 0x20, 8):
        print("[C] {:#018x} : {:#018x}".format(rsp + i, struct.unpack("Q", ctx.getConcreteMemoryAreaValue(rsp + i, 8))[0]))


def print_triton_memory(ctx, addr, size):
    for i in range(addr, addr + size, 8):
        print("[C] {:#018x} : {:#018x}".format(i, u64(ctx.getConcreteMemoryAreaValue(i, 8))))

def print_triton_memory_at_register(ctx, reg, size=0x40):
    reg_val = ctx.getConcreteRegisterValue(getattr(ctx.registers, reg))
    print("[C] {}".format(reg))
    print_triton_memory(ctx, reg_val - size, 2*size)


skipped_opcodes = { OPCODE.X86.XGETBV, OPCODE.X86.RDTSCP, OPCODE.X86.RDRAND,
    OPCODE.X86.VPCMPEQB,
    # OPCODE.X86.VPMOVMSKB,
    OPCODE.X86.VZEROUPPER,
    OPCODE.X86.XSAVE, OPCODE.X86.XRSTOR, OPCODE.X86.PSLLD, OPCODE.X86.PSLLQ,
    OPCODE.X86.VMOVD, OPCODE.X86.VPXOR, OPCODE.X86.VPBROADCASTB }
def emulate(ctx, trace, saved_contexts, saved_memories):
    # type: (TritonContext, List[Trace], List[], List[]) -> Union[None, Dict[int, SavedInstruction]]
    old_pc = 0
    pc = trace[0]
    set_triton_context(ctx, saved_contexts[0], set_rip=True)

    print('[*] trace length {}'.format(len(trace)))
    next_saved_memory = 0
    next_saved_context = 1
    print('[*] starting emulation at {:#x}'.format(pc))
    count = 0
    # monitored_addr = 0x000000000034a000
    # monitored_val = ctx.getConcreteMemoryAreaValue(monitored_addr, 8)
    # print("[D] Monitored val start: {:#x}".format(u64(monitored_val)))
    tainted_addrs = dict()
    while pc:
        opcodes = ctx.getConcreteMemoryAreaValue(pc, 16)

        cond = True
        while cond:
            inst = Instruction()
            inst.setOpcode(opcodes)
            inst.setAddress(pc)

            skip_inst = False
            if ctx.processing(inst) == False:
                if inst.getType() in skipped_opcodes:
                    dprint('skipping next inst')
                    skip_inst = True
                else:
                    print('instruction not supported: {}'.format(inst))
                    break

            dprint("{0:07} {1} {2}".format(count, inst, 'tainted' if inst.isTainted() else ''))

            if len(saved_contexts) > next_saved_context and count == saved_contexts[next_saved_context].instr_num:
                dprint("[*] saved_context {}".format(next_saved_context))
                if pc != saved_contexts[next_saved_context].rip:
                    print("[-] saved context wrong pc: {:#x} != {:#x}".format(pc, saved_contexts[next_saved_context].rip))
                    return
                set_triton_context(ctx, saved_contexts[next_saved_context])
                next_saved_context += 1
            while len(saved_memories) > next_saved_memory and count == saved_memories[next_saved_memory].trace_addr:
                saved_memory = saved_memories[next_saved_memory]
                dprint("[*] saved_memory {}: {:#x} - {:#x}".format(next_saved_memory, saved_memory.start_addr, saved_memory.start_addr + saved_memory.size))
                ctx.setConcreteMemoryAreaValue(saved_memory.start_addr, saved_memory.data.tobytes())
                next_saved_memory += 1

            if skip_inst:
                ctx.setConcreteRegisterValue(ctx.registers.rip, inst.getNextAddress())
                
            old_pc = pc
            pc = ctx.getConcreteRegisterValue(ctx.registers.rip)

            cond = pc == old_pc

        if inst.isTainted():
            tainted_addrs[inst.getAddress()] = SavedInstruction(ctx, inst)
            print(len(tainted_addrs))
            sys.stdout.flush()

        # cur_val = ctx.getConcreteMemoryAreaValue(monitored_addr, 8)
        # if cur_val != monitored_val:
        #     print("[D] Monitored value changed: {:#x} => {:#x}".format(u64(monitored_val), u64(cur_val)))
        #     monitored_val = cur_val
        count += 1
        # if pc == 0x7ffccbb56e1c:
        #     print_triton_context(ctx)
        #     print_triton_memory_at_register(ctx, "rcx")
        #     print_triton_memory_at_register(ctx, "r9")
        # if pc == 0x7ffee9eb5f5a:
        #     print_triton_context(ctx)
        #     print_triton_memory_at_register(ctx, "rax")

        # if pc == 0x7FFF9E494245:
        #     print_triton_context(ctx)
        # if count >= 20876:
        #     print_triton_context(ctx)
        #     if pc == 0x7fff9e494224:
        #         print_triton_memory_at_register(ctx, "rax")
        # if pc == MAIN_END:
        #     print('[+] Reached end of main {:#x}. Emulation done'.format(MAIN_END))
        #     return tainted_addrs
        if len(trace) <= count:
            print('[+] reached end of trace. stopping emulation')
            return tainted_addrs


        if pc != trace[count]:
            print('[-] Execution diverged at {:#x}, trace {:#x}'.format(pc, trace[count]))
            print_triton_context(ctx)
            print('[*] Next trace instr')
            for i in range(10):
                print('{:#018x}'.format(trace[count+i]))
            # set_triton_context(ctx, saved_contexts[next_saved_context])
            # print('[D] monitored addr/value from last memory dump')
            # for saved_mem in reversed(saved_memories[:next_saved_memory-1]):
            #     if saved_mem.contains_addr(monitored_addr):
            #         print('[D] {:#018x} : {:#x}'.format(monitored_addr, u64(saved_mem.get_value(monitored_addr))))
            #         break
            # print('[D] monitored addr/value currently')
            # print('[D] {:#018x} : {:#x}'.format(monitored_addr, u64(ctx.getConcreteMemoryAreaValue(monitored_addr, 8))))
            break

    return None


def setup_triton(modules):

    # context boilerplate
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    ctx.enableSymbolicEngine(False)
    ctx.enableTaintEngine(True)

    # segment values seem to be addresses instead of offsets into GDT
    # ctx.setConcreteRegisterValue(ctx.registers.gs, 0x2b)
    # ctx.setConcreteRegisterValue(ctx.registers.fs, 0x53)

    main_mem_tainted = False
    # set up modules
    for module in modules:
        with open(module.path, 'rb') as f:
            data = f.read()
            ctx.setConcreteMemoryAreaValue(module.start, data)
            if module.is_main:
                print('[*] Tainting main module memory {:#x} - {:#x}'.format(module.start, module.end))
                main_mem_tainted = True
                taint_size = 64
                for i in range(module.start, module.end, taint_size):
                    ctx.taintMemory(MemoryAccess(i, taint_size))
    
    # print('[DDD] TESTING. REMOVE LATER')
    # for i in range(0, 515):
    #     ctx.taintMemory(MemoryAccess(0x603080, 1))

    if not main_mem_tainted:
        print("[-] No main module for tainting found")
        return
    # ctx.concretizeAllMemory()
    # ctx.concretizeAllRegister()

    # set up stack
    # ctx.setConcreteRegisterValue(ctx.registers.rbp, BASE_STACK)
    # ctx.setConcreteRegisterValue(ctx.registers.rsp, BASE_STACK)

    return ctx

def main(argv):
    print("This file is not meant to be run directly")
    exit(1)


if __name__ == '__main__':
    main(sys.argv[1:])
