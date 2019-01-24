from __future__ import print_function
import struct
import re
import os
import sys
import cstruct
import pickle
from glob import glob
from collections import namedtuple
from create_patch import SavedInstruction

from triton import *
try:
    from triton_autocomplete import *
except ImportError:
    pass


DEBUG = True
# MAIN_END = 0x1400038A8 # test_tamper_debug
MAIN_END = 0x140001B58 # test_tamper

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
    # type: (TritonContext, List[Trace], List[], List[]) -> Union[None, List[int, Instruction]]
    old_pc = 0
    pc = trace[0].addr
    set_triton_context(ctx, saved_contexts[0], set_rip=True)

    print('[*] Trace length {}'.format(len(trace)))
    next_saved_memory = 0
    next_saved_context = 1
    print('[*] Starting emulation at {:#x}'.format(pc))
    count = 0
    monitored_addr = 0x7FFCCBC5D070
    monitored_val = ctx.getConcreteMemoryAreaValue(monitored_addr, 8)
    print("[D] Monitored val start: {:#x}".format(u64(monitored_val)))
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
                t = inst.getType()
                if t == OPCODE.X86.XGETBV:
                    print('skipping xgetbv')
                    skip_inst = True
                elif t == OPCODE.X86.RDTSCP:
                    print('skipping rdtscp')
                    skip_inst = True
                elif t == OPCODE.X86.RDRAND:
                    print('skipping rdrand')
                    skip_inst = True
                else:
                    print('Instruction not supported: {}'.format(inst))
                    break

            print("{0:07} {1} {2}".format(count, inst, 'tainted' if inst.isTainted() else ''))

            if len(saved_contexts) > next_saved_context and count == saved_contexts[next_saved_context].instr_num:
                print("[*] saved_context {}".format(next_saved_context))
                if pc != saved_contexts[next_saved_context].rip:
                    print("[-] saved context wrong pc: {:#x} != {:#x}".format(pc, saved_contexts[next_saved_context].rip))
                    return
                set_triton_context(ctx, saved_contexts[next_saved_context])
                next_saved_context += 1
            while len(saved_memories) > next_saved_memory and count == saved_memories[next_saved_memory].trace_addr:
                saved_memory = saved_memories[next_saved_memory]
                print("[*] saved_memory {}: {:#x} - {:#x}".format(next_saved_memory, saved_memory.start_addr, saved_memory.start_addr + saved_memory.size))
                ctx.setConcreteMemoryAreaValue(saved_memory.start_addr, saved_memory.data.tobytes())
                next_saved_memory += 1

            if skip_inst:
                ctx.setConcreteRegisterValue(ctx.registers.rip, inst.getNextAddress())
                
            old_pc = pc
            pc = ctx.getConcreteRegisterValue(ctx.registers.rip)

            cond = pc == old_pc

        if inst.isTainted():
            tainted_addrs[inst.getAddress()] = SavedInstruction(ctx, inst)


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
        if pc == MAIN_END:
            print('[+] Reached end of main {:#x}. Emulation done'.format(MAIN_END))
            return tainted_addrs


        if pc != trace[count].addr:
            print('[-] Execution diverged at {:#x}, trace {:#x}'.format(pc, trace[count].addr))
            print_triton_context(ctx)
            print('[*] Next trace instr')
            for i in range(10):
                print('{:#018x}'.format(trace[count+i].addr))
            # set_triton_context(ctx, saved_contexts[next_saved_context])
            print('[D] monitored addr/value from last memory dump')
            for saved_mem in reversed(saved_memories[:next_saved_memory-1]):
                if saved_mem.contains_addr(monitored_addr):
                    print('[D] {:#018x} : {:#x}'.format(monitored_addr, u64(saved_mem.get_value(monitored_addr))))
                    break
            print('[D] monitored addr/value currently')
            print('[D] {:#018x} : {:#x}'.format(monitored_addr, u64(ctx.getConcreteMemoryAreaValue(monitored_addr, 8))))
            break

    return None


def setup_triton(modules_path):

    modules = get_modules(modules_path)    
    if not modules:
        return

    # context boilerplate
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    ctx.enableSymbolicEngine(False)
    ctx.enableTaintEngine(True)

    # segment values seem to be addresses instead of offsets into GDT
    # ctx.setConcreteRegisterValue(ctx.registers.gs, 0x2b)
    # ctx.setConcreteRegisterValue(ctx.registers.fs, 0x53)

    # set up modules
    for module in modules:
        with open(module.path, 'rb') as f:
            data = f.read()
            ctx.setConcreteMemoryAreaValue(module.start, data)
            if module.start == 0x140001000:
                print('[*] Tainting main module memory {:#x} - {:#x}'.format(module.start, module.end))
                taint_size = 64
                for i in range(module.start, module.end, taint_size):
                    ctx.taintMemory(MemoryAccess(i, taint_size))

    # ctx.concretizeAllMemory()
    # ctx.concretizeAllRegister()

    # set up stack
    # ctx.setConcreteRegisterValue(ctx.registers.rbp, BASE_STACK)
    # ctx.setConcreteRegisterValue(ctx.registers.rsp, BASE_STACK)

    return ctx


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



registers = ['rdi', 'rsi', 'rbp', 'rsp', 'rbx', 'rdx', 'rcx', 'rax',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'rflags',
    'rip']

class saved_context_t(cstruct.CStruct):
    __byte_order__ = cstruct.LITTLE_ENDIAN
    __struct__ = 'uint64_t instr_num;\n' + '\n'.join(['uint64_t {};'.format(reg) for reg in registers])

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
    
    def contains_addr(self, addr):
        return self.start_addr <= addr and (addr - self.start_addr) < self.size
    
    def get_value(self, addr):
        data_start = addr - self.start_addr
        return self.data[data_start:data_start + 8].tobytes()


def read_saved_memories(fpath):
    # (str) -> Union[None, List[saved_memory_t]]
    with open(fpath, 'rb') as f:
        memory_data = f.read()

    view = memoryview(memory_data)
    memories = []
    cur_offset = 0
    while cur_offset < len(view):
        m = saved_memory_t()
        consumed_bytes = m.unpack(view[cur_offset:]) 
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
    print('[+] start reading')
    sys.stdout.flush()

    saved_contexts = read_saved_contexts(os.path.join(input_path, 'saved_contexts.bin'))
    if not saved_contexts:
        return
    if saved_contexts[0].rip != (-1 & 0xffffffffffffffff):
        print("[-] saved states do not have initial state with xip = -1")
        return
    print('[+] read saved contexts')
    sys.stdout.flush()

    trace = read_trace(input_path)
    if not trace:
        return
    print('[+] read trace')
    sys.stdout.flush()
    
    saved_memories = read_saved_memories(os.path.join(input_path, 'saved_memories.bin'))
    if saved_memories is None:
        return
    print('[+] read memories')
    sys.stdout.flush()

    ctx = setup_triton(os.path.join(input_path, 'modules/'))
    print('[+] setup triton context')
    sys.stdout.flush()
    tainted_locs = emulate(ctx, trace, saved_contexts, saved_memories)
    if tainted_locs is None:
        return
    
    print('[+] Tainted addresses:')
    for addr in sorted(tainted_locs):
        inst = tainted_locs[addr]
        print('{:#018x}: {}'.format(addr, inst))
    
    tainted_loc_fpath = os.path.join(input_path, 'tainted_locs.bin')
    print('[+] Saving tainted locations as {}'.format(tainted_loc_fpath))
    with open(tainted_loc_fpath, 'wb') as f:
        pickle.dump(tainted_locs.values(), f, pickle.HIGHEST_PROTOCOL)


if __name__ == '__main__':
    main()
