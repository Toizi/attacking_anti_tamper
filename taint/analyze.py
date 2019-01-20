from __future__ import print_function
import struct
import re
import os
import sys
import cstruct
from glob import glob
from collections import namedtuple

from triton import *
try:
    from triton_autocomplete import *
except ImportError:
    pass


DEBUG = True
BASE_STACK = 0x9f000000

def dprint(*args, **kargs):
    if DEBUG:
        print('[D] ', *args, **kargs)

def u64(val):
    return struct.unpack("Q", val)[0]

def p64(val):
    return struct.pack("Q", val)

def set_triton_context(ctx, state, set_rip=False):
    print("[*] set_triton_context at {:#x}".format(ctx.getConcreteRegisterValue(ctx.registers.rip)))
    for reg in registers:
        if reg == 'rflags' or not set_rip and (reg == 'rip' or reg == 'rsp'):
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


def emulate(ctx, trace, saved_contexts, saved_memories):
    # type: (TritonContext, List[Trace], List[], List[]) -> None
    old_pc = 0
    pc = trace[0].addr
    set_triton_context(ctx, saved_contexts[0], set_rip=True)

    next_saved_memory = 0
    next_saved_context = 1
    print('[*] Starting emulation at {:#x}'.format(pc))
    count = 0
    monitored_addr = 0x000000000014fd98
    monitored_val = ctx.getConcreteMemoryAreaValue(monitored_addr, 8)
    print("[D] Monitored val start: {:#x}".format(u64(monitored_val)))
    while pc:
        opcodes = ctx.getConcreteMemoryAreaValue(pc, 16)

        cond = True
        while cond:
            inst = Instruction()
            inst.setOpcode(opcodes)
            inst.setAddress(pc)

            skip_inst = False
            if ctx.processing(inst) == False:
                if inst.getType() == OPCODE.XGETBV:
                    print('skipping xgetbv')
                    skip_inst = True
                else:
                    print('Instruction not supported: {}'.format(inst))
                    break

            print("{0:06} {1}".format(count, inst))

            if len(saved_contexts) > next_saved_context and pc == saved_contexts[next_saved_context].rip:
                print("[*] saved_context {}".format(next_saved_context))
                set_triton_context(ctx, saved_contexts[next_saved_context])
                next_saved_context += 1
            if len(saved_memories) > next_saved_memory and pc == saved_memories[next_saved_memory].trace_addr:
                print("[*] saved_memory {}".format(next_saved_memory))
                ctx.setConcreteMemoryAreaValue(saved_memories[next_saved_memory].start_addr, saved_memories[next_saved_memory].data)
                next_saved_memory += 1

            if skip_inst:
                ctx.setConcreteRegisterValue(ctx.registers.rip, inst.getNextAddress())
                
            old_pc = pc
            pc = ctx.getConcreteRegisterValue(ctx.registers.rip)

            cond = pc == old_pc

        cur_val = ctx.getConcreteMemoryAreaValue(monitored_addr, 8)
        if cur_val != monitored_val:
            print("[D] Monitored value changed: {:#x} => {:#x}".format(u64(monitored_val), u64(cur_val)))
            monitored_val = cur_val
        count += 1
        # if pc == 0x7FFF9E494245:
        #     print_triton_context(ctx)
        if count >= 20876:
            print_triton_context(ctx)
            if pc == 0x7fff9e494224:
                print_triton_memory_at_register(ctx, "rax")


        if pc != trace[count].addr:
            print('[-] Execution diverged at {:#x}, trace {:#x}'.format(pc, trace[count].addr))
            print_triton_context(ctx)
            # set_triton_context(ctx, saved_contexts[next_saved_context])
            break
        # if count > 5000:
        #     break

def get_modules(modules_path):
    module_paths = glob(modules_path + '*')
    modules = []
    Module = namedtuple('Module', 'start end name path')
    mod_re = re.compile(r'0x(?P<start_addr>.*?)-0x(?P<end_addr>.*?)_(?P<name>.*?)$')
    for module_path in module_paths:
        module = os.path.basename(module_path) 
        match = mod_re.match(module)
        if not match:
            print('[-] Could not match module name {} with {}'.format(module, mod_re.pattern))
            return None
        modules.append(Module(start=int(match.group('start_addr'), base=16), path=module_path,
            end=int(match.group('end_addr'), base=16), name=match.group('name')))
    return modules


def setup_triton(modules_path):

    modules = get_modules(modules_path)    
    if not modules:
        return

    # context boilerplate
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    ctx.enableSymbolicEngine(False)

    # segment values seem to be addresses instead of offsets into GDT
    # ctx.setConcreteRegisterValue(ctx.registers.gs, 0x2b)
    # ctx.setConcreteRegisterValue(ctx.registers.fs, 0x53)

    # set up modules
    for module in modules:
        with open(module.path, 'rb') as f:
            data = f.read()
            ctx.setConcreteMemoryAreaValue(module.start, data)

    # ctx.concretizeAllMemory()
    # ctx.concretizeAllRegister()

    # set up stack
    # ctx.setConcreteRegisterValue(ctx.registers.rbp, BASE_STACK)
    # ctx.setConcreteRegisterValue(ctx.registers.rsp, BASE_STACK)

    return ctx

registers = ['rdi', 'rsi', 'rbp', 'rsp', 'rbx', 'rdx', 'rcx', 'rax',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'rflags',
    'rip']

class saved_context_t(cstruct.CStruct):
    __byte_order__ = cstruct.LITTLE_ENDIAN
    __struct__ = '\n'.join(['uint64_t {};'.format(reg) for reg in registers])

def read_saved_contexts(fpath):
    # (str) -> Union[None, List[saved_context_t]]
    with open(fpath, 'rb') as f:
        state_data = f.read()

    state = saved_context_t()
    state_len = len(state)
    del state
    states = []
    for i in range(0, len(state_data), state_len):
        s = saved_context_t()
        s.unpack(state_data[i:i+state_len]) 
        states.append(s)

    return states

class saved_memory_t():
    struct_size = 4*8

    def __init__(self):
        self.trace_addr = -1
        self.start_addr = -1
        self.size = -1
        self.data = None
    
    def unpack(self, data):
        self.trace_addr, self.start_addr, self.size, _ = struct.unpack("QQQQ", data[:self.struct_size])
        self.data = data[self.struct_size:self.struct_size + self.size]
        consumed_bytes = self.struct_size + self.size
        return consumed_bytes


def read_saved_memories(fpath):
    # (str) -> Union[None, List[saved_context_t]]
    with open(fpath, 'rb') as f:
        memory_data = f.read()

    memories = []
    cur_offset = 0
    while cur_offset < len(memory_data):
        m = saved_memory_t()
        consumed_bytes = m.unpack(memory_data[cur_offset:]) 
        cur_offset += consumed_bytes
        memories.append(m)

    return memories

def read_trace(fpath):
    # (str) -> Union[None, List[Tuple[int, int]]]
    logs = glob(fpath + '*.log')
    if not logs:
        print("[-] Could not find log file at {}".format(fpath))
        return None
    trace_path = logs[0]
    print('[*] Using trace file {}'.format(trace_path))
    with open(trace_path, 'rb') as f:
        raw_trace = f.read()
    trace = []
    Trace = namedtuple('Trace', 'addr opcode')
    for i in range(0, len(raw_trace), 16):
        addr = struct.unpack('Q', raw_trace[i:i+8])[0]
        opcode = raw_trace[i+8:i+16]
        trace.append(Trace(addr, opcode))

    return trace


def main():
    if len(sys.argv) > 1:
        input_path = sys.argv[1]
    else:
        this_dir = os.path.dirname(__file__)
        input_path = os.path.join(this_dir, '../samples/instrace_logs/')
    
    if not os.path.exists(input_path):
        print("[-] input path does not exists: {}".format(input_path))
        exit(1)

    saved_contexts = read_saved_contexts(os.path.join(input_path, 'saved_contexts.bin'))
    if not saved_contexts:
        return
    if saved_contexts[0].rip != (-1 & 0xffffffffffffffff):
        print("[-] saved states do not have initial state with xip = -1")
        return

    trace = read_trace(input_path)
    if not trace:
        return
    
    saved_memories = read_saved_memories(os.path.join(input_path, 'saved_memories.bin'))
    if saved_memories is None:
        return

    ctx = setup_triton(os.path.join(input_path, 'modules/'))
    emulate(ctx, trace, saved_contexts, saved_memories)


if __name__ == '__main__':
    main()
