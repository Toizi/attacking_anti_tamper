#include <taint/analysis.h>
#include <taint/utils.h>
#include <fmt/format.h>
#include <keystone/keystone.h>

#include <signal.h>

#include <unordered_map>
#include <sstream>

std::string Patch::repr() {
    std::stringstream ss;
    ss << fmt::format("({:#x}, \"{}\", \"", address, asm_string);
        for (auto val : data) {
            ss << fmt::format("\\x{:0>2x}", (uint8_t)val);
        }
    ss << "\")";
    return ss.str();
}

std::string Patch::json() {
    std::stringstream ss;
    ss << fmt::format("{{ \"address\": {}, \"asm_string\": \"{}\", \"data_hex\": \"", address, asm_string);
        for (auto val : data) {
            ss << fmt::format("{:0>2x}", (uint8_t)val);
        }
    ss << "\" }";
    return ss.str();
}

std::vector<triton::arch::x86::instruction_e> TaintAnalysis::skipped_instructions =
    {
        triton::arch::x86::ID_INS_XGETBV,
        triton::arch::x86::ID_INS_RDTSCP,
        triton::arch::x86::ID_INS_RDRAND,
        triton::arch::x86::ID_INS_XSAVE,
        triton::arch::x86::ID_INS_XSTORE,
        triton::arch::x86::ID_INS_XRSTOR,
        triton::arch::x86::ID_INS_FNSTCW,
        triton::arch::x86::ID_INS_CVTSD2SS,
};

void TaintAnalysis::set_debug(bool dbg)
{
    this->debug = dbg;
}

void TaintAnalysis::set_context(const saved_context_t *context, bool set_ip)
{
    api.setTaintRegister(api.registers.x86_rip, false);
    if (set_ip) {
        api.setConcreteRegisterValue(api.registers.x86_rip, context->xip);
    }

    if (api.getConcreteRegisterValue(api.registers.x86_fs) != context->fs)
        api.setTaintRegister(api.registers.x86_fs, false);
    api.setConcreteRegisterValue(api.registers.x86_fs, context->fs);

    // if (api.getConcreteRegisterValue(api.registers.x86_eflags) != context->xflags)
    // always clear taint of eflags since it probably happens too often that
    // they didn't change but they were assigned to
    fmt::print("clearing eflags taint\n");
    api.setTaintRegister(api.registers.x86_eflags, false);
    api.setTaintRegister(api.registers.x86_zf, false);
    api.setTaintRegister(api.registers.x86_cf, false);
    api.setConcreteRegisterValue(api.registers.x86_eflags, context->xflags);

    // set x86 regs
    if (api.getConcreteRegisterValue(api.registers.x86_rdi) != context->xdi)
        api.setTaintRegister(api.registers.x86_rdi, false);
    api.setConcreteRegisterValue(api.registers.x86_rdi, context->xdi);

    if (api.getConcreteRegisterValue(api.registers.x86_rsi) != context->xsi)
        api.setTaintRegister(api.registers.x86_rsi, false);
    api.setConcreteRegisterValue(api.registers.x86_rsi, context->xsi);

    if (api.getConcreteRegisterValue(api.registers.x86_rbp) != context->xbp)
        api.setTaintRegister(api.registers.x86_rbp, false);
    api.setConcreteRegisterValue(api.registers.x86_rbp, context->xbp);

    if (api.getConcreteRegisterValue(api.registers.x86_rsp) != context->xsp)
        api.setTaintRegister(api.registers.x86_rsp, false);
    api.setConcreteRegisterValue(api.registers.x86_rsp, context->xsp);

    if (api.getConcreteRegisterValue(api.registers.x86_rbx) != context->xbx)
        api.setTaintRegister(api.registers.x86_rbx, false);
    api.setConcreteRegisterValue(api.registers.x86_rbx, context->xbx);

    if (api.getConcreteRegisterValue(api.registers.x86_rdx) != context->xdx)
        api.setTaintRegister(api.registers.x86_rdx, false);
    api.setConcreteRegisterValue(api.registers.x86_rdx, context->xdx);

    if (api.getConcreteRegisterValue(api.registers.x86_rcx) != context->xcx)
        api.setTaintRegister(api.registers.x86_rcx, false);
    api.setConcreteRegisterValue(api.registers.x86_rcx, context->xcx);

    if (api.getConcreteRegisterValue(api.registers.x86_rax) != context->xax)
        api.setTaintRegister(api.registers.x86_rax, false);
    api.setConcreteRegisterValue(api.registers.x86_rax, context->xax);

    // set amd64 regs
    if (api.getConcreteRegisterValue(api.registers.x86_r8) != context->r8)
        api.setTaintRegister(api.registers.x86_r8, false);
    api.setConcreteRegisterValue(api.registers.x86_r8, context->r8);

    if (api.getConcreteRegisterValue(api.registers.x86_r9) != context->r9)
        api.setTaintRegister(api.registers.x86_r9, false);
    api.setConcreteRegisterValue(api.registers.x86_r9, context->r9);

    if (api.getConcreteRegisterValue(api.registers.x86_r10) != context->r10)
        api.setTaintRegister(api.registers.x86_r10, false);
    api.setConcreteRegisterValue(api.registers.x86_r10, context->r10);

    if (api.getConcreteRegisterValue(api.registers.x86_r11) != context->r11)
        api.setTaintRegister(api.registers.x86_r11, false);
    api.setConcreteRegisterValue(api.registers.x86_r11, context->r11);

    if (api.getConcreteRegisterValue(api.registers.x86_r12) != context->r12)
        api.setTaintRegister(api.registers.x86_r12, false);
    api.setConcreteRegisterValue(api.registers.x86_r12, context->r12);

    if (api.getConcreteRegisterValue(api.registers.x86_r13) != context->r13)
        api.setTaintRegister(api.registers.x86_r13, false);
    api.setConcreteRegisterValue(api.registers.x86_r13, context->r13);

    if (api.getConcreteRegisterValue(api.registers.x86_r14) != context->r14)
        api.setTaintRegister(api.registers.x86_r14, false);
    api.setConcreteRegisterValue(api.registers.x86_r14, context->r14);

    if (api.getConcreteRegisterValue(api.registers.x86_r15) != context->r15)
        api.setTaintRegister(api.registers.x86_r15, false);
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

bool TaintAnalysis::addr_in_main_module(uint64_t addr)
{
    for (auto &mod : main_modules)
    {
        if (mod.start <= addr && addr < mod.end)
        {
            return true;
        }
    }
    return false;
}

// underapproximate the mem access
static size_t align_mem_access(size_t access_size) {
    if (access_size <= 2)
        return access_size;
    if (access_size < 4)
        return 2;
    if (access_size < 8)
        return 4;
    if (access_size < 16)
        return 8;
    if (access_size < 32)
        return 16;
    if (access_size < 64)
        return 32;
    return 64;
}

bool TaintAnalysis::setup_context(std::vector<saved_module_t> &modules, size_t text_section_start, size_t text_section_end)
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
            size_t taint_start = mod.start;
            size_t taint_end = mod.end;
            if (mod.start <= text_section_start && text_section_start < mod.end) {
                taint_start = text_section_start;
                taint_end = text_section_end;
                fmt::print("[*] Tainting only text section\n");
            }
            fmt::print("[*] Tainting main module memory {:#x} - {:#x}\n", taint_start, taint_end);
            size_t taint_size = 64;
            for (size_t i = taint_start; i < taint_end; i += taint_size)
            {
                api.setTaintMemory(triton::arch::MemoryAccess(i, align_mem_access(std::min(taint_size, taint_end - i))), true);
            }
            main_modules.push_back(mod);
        }
    }
    if (!main_mem_tainted)
    {
        fmt::print(stderr, "[-] No main module for tainting found\n");
    }
    this->modules.swap(modules);

    return main_mem_tainted;
}

bool stop_requested = false;
bool TaintAnalysis::emulate(const std::vector<uint64_t> &trace, std::vector<saved_context_t *> &contexts, std::vector<saved_memory_t *> &memories)
{
    size_t trace_pos = 0;
    auto pc = trace[0];
    auto last_pc = pc;

    contexts[0]->xip = pc;
    set_context(contexts[0], true);
    size_t context_pos = 1;
    size_t memory_pos = 0;

    this->saved_instructions = std::make_unique<saved_instructions_t>();
    // better syntax
    auto &tainted_instrs = *this->saved_instructions;
    // std::unordered_map<uint64_t, std::unique_ptr<triton::arch::Instruction>> cached_instructions;
    auto inst = triton::arch::Instruction();
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = [](int sig) {
        fmt::print("Caught signal {:d}\n", sig);
        stop_requested = true;
    };
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    while (true)
    {
        // auto cached_inst = cached_instructions.find(pc);
        // bool reuse_inst = cached_inst != cached_instructions.end();
        // triton::arch::Instruction *instp;
        // if (reuse_inst) {
        //     instp = cached_inst->second.get();
        // } else {
        //     instp = new triton::arch::Instruction();
        //     // set instruction to emulate
        //     instp->clear();
        //     auto opcodes = api.getConcreteMemoryAreaValue(pc, 16, false);
        //     instp->setOpcode(opcodes.data(), opcodes.size());
        //     instp->setAddress(pc);
        //     cached_instructions[pc] = std::unique_ptr<triton::arch::Instruction>{instp};
        // }
        // triton::arch::Instruction &inst = *instp;
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
                if (false) {
                    // in case it is not a known instruction to skip, error out
                    if (std::find(skipped_instructions.begin(), skipped_instructions.end(), inst.getType()) == skipped_instructions.end())
                    {
                        fmt::print("[-] unsupported instruction {}\n", inst.getDisassembly());
                        return false;
                    }
                }

                skip_instruction = true;
            }

            if (this->debug)
            {
                fmt::print("[D] {0:07} {3:#x} {1} {2}\n", trace_pos, inst.getDisassembly(), inst.isTainted() ? "tainted" : "", inst.getAddress());
            }

            // check if we need to restore the register context
            if (context_pos < contexts.size() && trace_pos == contexts[context_pos]->instr_num)
            {
                auto ctx = contexts[context_pos];
                if (this->debug)
                    fmt::print("[D] saved context {}\n", context_pos);
                // sanity check
                if (pc != ctx->xip)
                {
                    fmt::print("[-] saved context wrong pc: {:#x} != {:#x}\n", pc, ctx->xip);
                    // auto rsp_mem = api.getConcreteMemoryAreaValue(
                    //     (uint64_t)api.getConcreteRegisterValue(api.registers.x86_rsp), 8, false);
                    // fmt::print("[D] rsp[0]: {:#x}\n", *(size_t*)rsp_mem.data());
                    return false;
                }
                set_context(ctx);
                ++context_pos;
            }

            // check if we need to restore memory
            while (memory_pos < memories.size() && trace_pos == memories[memory_pos]->instr_num)
            {
                saved_memory_t &mem = *memories[memory_pos];
                if (this->debug)
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
            tainted_instrs[inst.getAddress()] = SavedInstruction{
                (uint64_t)api.getConcreteRegisterValue(api.registers.x86_rip),
                inst};
        }

        // check if we are done
        ++trace_pos;
        if (trace.size() <= trace_pos)
        {
            fmt::print("[+] reached end of trace. emulation done\n");
            // this->saved_instructions = std::move(tainted_instrs_p);
            return true;
        }

        if (stop_requested)
        {
            fmt::print("[*] Stop requested. Stopping emulation\n");
            return true;
        }

        if (pc != trace[trace_pos])
        {
            if (false) {
                fmt::print("[-] execution diverged at {:#x}, trace {:#x}\n",
                        pc, trace[trace_pos]);
                print_context();
                fmt::print("[*] next trace instructions:\n");
                for (int i = 0; i < 10; ++i)
                {
                    if (trace.size() <= (trace_pos + i))
                        break;
                    fmt::print("{:#018x}\n", trace[trace_pos + i]);
                }
                return false;
            }
            else {
                fmt::print("[*] execution diverged at {:#x}, trace {:#x}\n",
                        pc, trace[trace_pos]);
                pc = trace[trace_pos];
                api.setConcreteRegisterValue(api.registers.x86_rip, pc);
            }
        }
    }

    return false;
}

std::vector<std::unique_ptr<Patch>>
TaintAnalysis::create_patch()
{
    std::vector<std::unique_ptr<Patch>> patches;
    ks_engine *ks;
    auto err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
    if (err != KS_ERR_OK)
    {
        fmt::print(stderr, "ks_open failed\n");
        return {};
    }
    for (std::pair<const uint64_t, SavedInstruction> &saved_inst : *saved_instructions)
    {
        // only interested in instructions from the main module
        if (!addr_in_main_module(saved_inst.first))
            continue;

        // easier access
        auto &trace_next_addr = saved_inst.second.next_address;
        auto &instr = saved_inst.second.instr;

        if (this->debug)
            fmt::print("{0:#018x}: {1: <40} => {2:#x}\n",
                       instr.getAddress(), instr.getDisassembly(), trace_next_addr);

        if (instr.isBranch())
        {
            for (int i = 0; i < instr.operands.size(); ++i)
            {
                auto dest = instr.operands[i];
                // skip indirect branches
                if (dest.getType() == triton::arch::OP_REG)
                    goto loop_end;
            }

            if (this->debug)
                fmt::print("  is branch\n");

            auto patch = std::make_unique<Patch>();
            patch->address = instr.getAddress();
            if (instr.isConditionTaken())
            {
                patch->asm_string = fmt::format("jmp {:#x}", trace_next_addr);

                unsigned char *data;
                size_t data_len, stat_count;
                if (ks_asm(ks, patch->asm_string.c_str(), instr.getAddress(), &data, &data_len, &stat_count))
                {
                    fmt::print(stderr, "ks_asm failed:\n {}\n", ks_errno(ks));
                    goto cleanup;
                }
                for (int i = 0; i < instr.getSize(); ++i)
                {
                    if (i < data_len)
                        patch->data.push_back(data[i]);
                    else
                        patch->data.push_back('\x90');
                }
                free(data);
            }
            else
            {
                patch->asm_string = "nop";
                for (int i = 0; i < instr.getSize(); ++i)
                {
                    patch->data.push_back('\x90');
                }
            }
            patches.push_back(std::move(patch));
        }
        // cmov
        else {
            std::string instr_disas = instr.getDisassembly();
            if (instr_disas.find("cmov") != std::string::npos){
                if (this->debug)
                    fmt::print("  is conditional move\n");

                auto patch = std::make_unique<Patch>();
                patch->address = instr.getAddress();
                if (instr.isConditionTaken())
                {
                    std::string operands_str = instr_disas.substr(instr_disas.find(' ') + 1);
                    patch->asm_string = fmt::format("mov {}", operands_str);

                    unsigned char *data;
                    size_t data_len, stat_count;
                    if (ks_asm(ks, patch->asm_string.c_str(), instr.getAddress(), &data, &data_len, &stat_count))
                    {
                        fmt::print(stderr, "ks_asm failed:\n {}\n", ks_errno(ks));
                        goto cleanup;
                    }
                    for (int i = 0; i < instr.getSize(); ++i)
                    {
                        if (i < data_len)
                            patch->data.push_back(data[i]);
                        else
                            patch->data.push_back('\x90');
                    }
                    free(data);
                }
                else
                {
                    patch->asm_string = "nop";
                    for (int i = 0; i < instr.getSize(); ++i)
                    {
                        patch->data.push_back('\x90');
                    }
                }
                patches.push_back(std::move(patch));
            }
        }

    loop_end:
        continue;
    }
cleanup:
    ks_close(ks);
    return patches;
}