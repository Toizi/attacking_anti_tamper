#!/usr/bin/env python2

# run from parent dir:
# python -m taint.run {args}

from __future__ import print_function
import struct
import re
import os
import sys
import cstruct
import pickle
import argparse
from glob import glob
from collections import namedtuple
from pprint import pprint

from . import create_patch
from . import r2_apply_patches
from . import analyze


Trace = namedtuple('Trace', 'addr')
Module = namedtuple('Module', 'start end is_main name path')

registers = ['rdi', 'rsi', 'rbp', 'rsp', 'rbx', 'rdx', 'rcx', 'rax',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'rflags',
    'rip',
    'fs']


# MAIN_END = 0x1400038A8 # test_tamper_debug
# MAIN_END = 0x140001C6A # test_tamper
# MAIN_END = 0x140001818 # test_medium
# MAIN_END = 0x1400020B8 # test_large_debug
# MAIN_END = 0x0001400012CA
# MAIN_END = 0x000000000040062a # test_tamper_no_relro
# MAIN_END = 0x400bac # test_tamper_sc
# MAIN_END = 0

DEBUG = False
def dprint(*args, **kargs):
    if DEBUG:
        print('[D] ', *args, **kargs)

def u64(val):
    return struct.unpack("Q", val)[0]

def p64(val):
    return struct.pack("Q", val)


def get_modules(modules_path):
    module_paths = glob(modules_path + '*')
    modules = []
    main_module = None
    mod_re = re.compile(r'0x(?P<start_addr>.*?)-0x(?P<end_addr>.*?)-(?P<is_main>main|other)_(?P<name>.*?)$')
    for module_path in module_paths:
        module = os.path.basename(module_path) 
        match = mod_re.match(module)
        if not match:
            print('[-] Could not match module name {} with {}'.format(module, mod_re.pattern))
            return None
        is_main_module = match.group('is_main') == 'main'
        mod = Module(start=int(match.group('start_addr'), base=16), path=module_path,
            end=int(match.group('end_addr'), base=16), name=match.group('name'), is_main=is_main_module)
        if is_main_module:
            main_module = mod
        modules.append(mod)
    return modules, main_module



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
    if fpath[-1] != os.path.sep:
        fpath += os.path.sep
    logs = glob(fpath + '*.log')
    if not logs:
        print("[-] could not find log file at {}".format(fpath))
        return None
    trace_path = logs[0]
    print('[*] using trace file {}'.format(trace_path))
    with open(trace_path, 'rb') as f:
        raw_trace = f.read()
    trace = []
    for i in range(0, len(raw_trace), 8):
        addr = struct.unpack('Q', raw_trace[i:i+8])[0]
        trace.append(Trace(addr))

    return trace


def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--compile", help="compile only and produce an object file",
                        action="store_true")
    parser.add_argument("-v", "--verbose", help="print debugging information",
                        action="store_true")
    parser.add_argument("-o", "--output", help="output path", required=False)
    parser.add_argument("-b", "--binary", help="input binary that will be patched", required=False)
    parser.add_argument("log_dir", help="directory of logdir arg passed to instrace")
    
    args = parser.parse_args(argv)
    global DEBUG
    DEBUG = args.verbose is True

    if args.output and not args.binary:
        print("error: output file specified without input binary")
        return None
    if args.binary and not args.output:
        fname, ext = os.path.splitext(args.binary)
        args.output = '{}_patched{}'.format(fname, ext)
    
    return args


def main(argv):
    args = parse_args(argv)
    
    input_path = args.log_dir
    if not os.path.exists(input_path):
        print("[-] input path does not exists: {}".format(input_path))
        return
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

    modules, main_module = get_modules(os.path.join(input_path, 'modules/'))    
    if not modules:
        return
    print('[+] read modules')

    analyze.set_debug(DEBUG)
    ctx = analyze.setup_triton(modules)
    if ctx is None:
        return
    print('[+] setup triton context')
    sys.stdout.flush()
    tainted_locs = analyze.emulate(ctx, trace, saved_contexts, saved_memories)
    if tainted_locs is None:
        return

    tainted_locs = {addr : inst for addr, inst in tainted_locs.items()
        if main_module.start <= addr < main_module.end}
    print('[*] filtered tainted addresses to only contain main module locations')
    
    print('[+] tainted addresses:')
    for addr in sorted(tainted_locs):
        inst = tainted_locs[addr]
        print('  {:#018x}'.format(addr))
    
    tainted_loc_fpath = os.path.join(input_path, 'tainted_locs.bin')
    print('[+] saving tainted locations as {}'.format(tainted_loc_fpath))
    with open(tainted_loc_fpath, 'wb') as f:
        pickle.dump(tainted_locs.values(), f, pickle.HIGHEST_PROTOCOL)
    
    patches = create_patch.create(tainted_locs.values())
    if not patches:
        print('[-] created patch failed')
        return
    print('[+] created patch')
    pprint(patches)

    if not args.binary:
        print('[*] no input binary specified. will not apply patch')
        return True

    print('[+] applying patches\n {} => {}'.format(args.binary, args.output))
    if not r2_apply_patches.patch_program(args.binary, args.output, patches):
        print('[-] r2_apply_patches failed')
        return

    return True


if __name__ == '__main__':
    main(sys.argv[1:])
