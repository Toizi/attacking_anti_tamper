#include <taint/analysis.h>
#include <taint/utils.h>
#include <fmt/format.h>

#include <unordered_map>

std::vector<triton::arch::x86::instruction_e> TaintAnalysis::skipped_instructions =
    {
        triton::arch::x86::ID_INS_XGETBV,
        triton::arch::x86::ID_INS_RDTSCP,
        triton::arch::x86::ID_INS_RDRAND,
        triton::arch::x86::ID_INS_XSAVE,
        triton::arch::x86::ID_INS_XSTORE,
        triton::arch::x86::ID_INS_XRSTOR,
};

void TaintAnalysis::set_context(const saved_context_t *context, bool set_ip)
{
    if (set_ip)
        api.setConcreteRegisterValue(api.registers.x86_rip, context->xip);

    api.setConcreteRegisterValue(api.registers.x86_fs, context->fs);

    // set x86 regs
    api.setConcreteRegisterValue(api.registers.x86_rdi, context->xdi);
    api.setConcreteRegisterValue(api.registers.x86_rsi, context->xsi);
    api.setConcreteRegisterValue(api.registers.x86_rbp, context->xbp);
    api.setConcreteRegisterValue(api.registers.x86_rsp, context->xsp);
    api.setConcreteRegisterValue(api.registers.x86_rbx, context->xbx);
    api.setConcreteRegisterValue(api.registers.x86_rdx, context->xdx);
    api.setConcreteRegisterValue(api.registers.x86_rcx, context->xcx);
    api.setConcreteRegisterValue(api.registers.x86_rax, context->xax);

    // set amd64 regs
    api.setConcreteRegisterValue(api.registers.x86_r8, context->r8);
    api.setConcreteRegisterValue(api.registers.x86_r9, context->r9);
    api.setConcreteRegisterValue(api.registers.x86_r10, context->r10);
    api.setConcreteRegisterValue(api.registers.x86_r11, context->r11);
    api.setConcreteRegisterValue(api.registers.x86_r12, context->r12);
    api.setConcreteRegisterValue(api.registers.x86_r13, context->r13);
    api.setConcreteRegisterValue(api.registers.x86_r14, context->r14);
    api.setConcreteRegisterValue(api.registers.x86_r15, context->r15);
}

void TaintAnalysis::print_context()
{
    fmt::print("[C] {: <3} = {:#018x}\n", "rip", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_rip));
    fmt::print("[C] {: <3} = {:#018x}\n", "rsp", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_rsp));

    fmt::print("[C] {: <3} = {:#018x}\n", "rdi", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_rdi));
    fmt::print("[C] {: <3} = {:#018x}\n", "rsi", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_rsi));
    fmt::print("[C] {: <3} = {:#018x}\n", "rbp", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_rbp));
    fmt::print("[C] {: <3} = {:#018x}\n", "rbx", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_rbx));
    fmt::print("[C] {: <3} = {:#018x}\n", "rdx", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_rdx));
    fmt::print("[C] {: <3} = {:#018x}\n", "rcx", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_rcx));
    fmt::print("[C] {: <3} = {:#018x}\n", "rax", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_rax));

    fmt::print("[C] {: <3} = {:#018x}\n", "r8", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_r8));
    fmt::print("[C] {: <3} = {:#018x}\n", "r9", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_r9));
    fmt::print("[C] {: <3} = {:#018x}\n", "r10", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_r10));
    fmt::print("[C] {: <3} = {:#018x}\n", "r11", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_r11));
    fmt::print("[C] {: <3} = {:#018x}\n", "r12", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_r12));
    fmt::print("[C] {: <3} = {:#018x}\n", "r13", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_r13));
    fmt::print("[C] {: <3} = {:#018x}\n", "r14", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_r14));
    fmt::print("[C] {: <3} = {:#018x}\n", "r15", (uint64_t)api.getConcreteRegisterValue(api.registers.x86_r15));
}

bool TaintAnalysis::setup_context(const std::vector<saved_module_t> &modules)
{
    api.reset();
    api.setArchitecture(triton::arch::ARCH_X86_64);
    api.enableSymbolicEngine(false);
    api.enableTaintEngine(true);

    bool main_mem_tainted = false;
    for (auto &mod : modules)
    {
        std::vector<char> mod_data;
        if (!read_whole_file(mod.path.c_str(), mod_data))
            return false;

        api.setConcreteMemoryAreaValue(mod.start, reinterpret_cast<triton::uint8 *>(mod_data.data()), mod_data.size());

        if (mod.is_main)
        {
            main_mem_tainted = true;
            fmt::print("[*] Taining main module memory {:#x} - {:#x}\n", mod.start, mod.end);
            size_t taint_size = 64;
            for (size_t i = mod.start; i < mod.end; i += taint_size)
            {
                api.setTaintMemory(triton::arch::MemoryAccess(i, taint_size), true);
            }
        }
    }
    if (!main_mem_tainted)
    {
        fmt::print(stderr, "[-] No main module for tainting found\n");
    }

    return main_mem_tainted;
}

saved_instructions_t *TaintAnalysis::emulate(const std::vector<uint64_t> &trace, std::vector<saved_context_t *> &contexts, std::vector<saved_memory_t *> &memories, bool print_dbg)
{
    size_t trace_pos = 0;
    auto pc = trace[0];
    auto last_pc = pc;

    set_context(contexts[0], true);
    size_t context_pos = 1;
    size_t memory_pos = 0;

    auto tainted_instrs_p = std::make_unique<saved_instructions_t>();
    // better syntax
    auto &tainted_instrs = *tainted_instrs_p;
    auto inst = triton::arch::Instruction();
    while (true)
    {
        do
        {
            // set instruction to emulate
            inst.clear();
            auto opcodes = api.getConcreteMemoryAreaValue(pc, 16, false);
            inst.setOpcode(opcodes.data(), opcodes.size());
            inst.setAddress(pc);

            bool skip_instruction = false;
            // execute the instruction
            if (!api.processing(inst))
            {
                // in case it is not a known instruction to skip, error out
                if (std::find(skipped_instructions.begin(), skipped_instructions.end(), inst.getType()) == skipped_instructions.end())
                {
                    fmt::print("[-] unsupported instruction {}\n", inst.getDisassembly());
                    return nullptr;
                }

                skip_instruction = true;
            }

            if (print_dbg)
            {
                fmt::print("[D] {0:07} {3:#x} {1} {2}\n", trace_pos, inst.getDisassembly(), inst.isTainted() ? "tainted" : "", inst.getAddress());
            }

            // check if we need to restore the register context
            if (context_pos < contexts.size() && trace_pos == contexts[context_pos]->instr_num)
            {
                auto ctx = contexts[context_pos];
                if (print_dbg)
                    fmt::print("[D] saved context {}\n", context_pos);
                // sanity check
                if (pc != ctx->xip)
                {
                    fmt::print(stderr, "[-] saved context wrong pc: {:#x} != {:#x}\n", pc, ctx->xip);
                    return nullptr;
                }
                set_context(ctx);
                ++context_pos;
            }

            // check if we need to restore memory
            while (memory_pos < memories.size() && trace_pos == memories[memory_pos]->instr_num)
            {
                saved_memory_t &mem = *memories[memory_pos];
                if (print_dbg)
                    fmt::print("[D] saved memory {}: {:#x} - {:#x}\n",
                               memory_pos, mem.start_addr, mem.start_addr + mem.size);
                api.setConcreteMemoryAreaValue(mem.start_addr, (uint8_t *)mem.data, mem.size);
                ++memory_pos;
            }

            // rip is not restored through context
            if (skip_instruction)
                api.setConcreteRegisterValue(api.registers.x86_rip, inst.getNextAddress());

            last_pc = pc;
            pc = static_cast<uint64_t>(api.getConcreteRegisterValue(api.registers.x86_rip));

            // there are instructions with e.g. rep prefix that are executed multiple times
            // in triton but are counted as single instruction in the trace
        } while (last_pc == pc);

        // save tainted instruction
        if (inst.isTainted())
        {
            tainted_instrs[inst.getAddress()] = inst;
        }

        // check if we are done
        ++trace_pos;
        if (trace.size() <= trace_pos)
        {
            fmt::print("[+] reached end of trace. emulation done\n");
            return tainted_instrs_p.release();
        }

        if (pc != trace[trace_pos])
        {
            fmt::print(stderr, "[-] execution diverged at {:#x}, trace {:#x}\n",
                       pc, trace[trace_pos]);
            print_context();
            fmt::print("[*] next trace instructions:\n");
            for (int i = 0; i < 10; ++i)
            {
                if (trace.size() <= (trace_pos + i))
                    break;
                fmt::print("{:#018x}\n", trace[trace_pos + i]);
            }
            return nullptr;
        }
    }

    return nullptr;
}