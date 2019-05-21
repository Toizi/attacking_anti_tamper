#include <fmt/format.h>

#include <taint/serialization.h>
#include <taint/cmdline.h>
#include <taint/utils.h>
#include <taint/analysis.h>

#include <iostream>
#include <fstream>

int main(int argc, char **argv)
{

    // parse command line args
    cmd_args args;
    if (!parse_args(argc, argv, args))
        return 1;

    // reading saved contexts
    auto contexts_path = args.log_dir + "saved_contexts.bin";
    fmt::print(stdout, "[*] reading contexts\n");
    std::vector<char> contexts_data;
    if (!read_whole_file(contexts_path.c_str(), contexts_data))
    {
        fmt::print(stderr, "[-] failed reading contexts\n");
        return 1;
    }
    std::vector<saved_context_t *> saved_contexts =
        saved_context_t::get_all(contexts_data.data(), contexts_data.size());
    if (args.verbose)
        fmt::print("[D] number of contexts: {}\n", saved_contexts.size());

    // reading trace
    auto trace_path = args.log_dir + "instrace.log";
    fmt::print(stdout, "[*] reading trace\n");
    std::vector<uint64_t> trace;
    if (!read_trace_from_file(trace_path.c_str(), trace))
    {
        fmt::print(stderr, "[-] failed reading trace\n");
        return 1;
    }
    if (args.verbose)
        fmt::print("[D] trace length: {}\n", trace.size());

    // reading saved memories
    auto memories_path = args.log_dir + "saved_memories.bin";
    fmt::print(stdout, "[*] reading memories\n");
    std::vector<char> memories_data;
    if (!read_whole_file(memories_path.c_str(), memories_data))
    {
        fmt::print(stderr, "failed reading memories\n");
        return 1;
    }
    std::vector<saved_memory_t *> saved_memories =
        saved_memory_t::get_all(memories_data.data(), memories_data.size());
    if (args.verbose)
        fmt::print("[D] number of memories: {}\n", saved_memories.size());

    // reading modules
    fmt::print(stdout, "[*] reading modules\n");
    // module names are in a file modules.txt, one per line
    auto modules_names_path = args.log_dir + "modules.txt";
    std::ifstream modules_names_file(modules_names_path);
    if (!modules_names_file)
    {
        fmt::print(stderr, "cannot open module names path\n  '{:s}'\n", modules_names_path);
        return 1;
    }
    auto modules_path = args.log_dir + "modules/";
    std::vector<saved_module_t> modules;
    std::string mod_name;
    // read one by one and parse the name for the info
    while (std::getline(modules_names_file, mod_name))
    {
        if (args.verbose)
            fmt::print("module: {:s}\n", mod_name);
        auto mod_path = modules_path + mod_name;
        saved_module_t mod;
        if (!mod.init(mod_name, mod_path.c_str()))
        {
            fmt::print(stderr, "failed initializing module from path\n  '{:s}'\n", mod_path);
            return 1;
        }
        if (args.verbose)
        {
            fmt::print("module: 0x{:#x} - 0x{:#x}, main = {}\n",
                       mod.start, mod.end, mod.is_main);
        }
        modules.push_back(std::move(mod));
    }

    std::vector<saved_module_t> main_modules;
    std::copy_if(modules.begin(), modules.end(), std::back_inserter(main_modules),
                 [](const saved_module_t &mod) {
                     return mod.is_main;
                 });

    TaintAnalysis analysis;
    // setup the memory/taint
    fmt::print("[*] setting up the context\n");
    if (!analysis.setup_context(modules))
    {
        fmt::print(stderr, "failed setting up the context\n");
        return 1;
    }

    // running the emulation
    fmt::print("[*] running the emulation\n");
    saved_instructions_t *emu_result = analysis.emulate(trace, saved_contexts, saved_memories, args.verbose);
    if (!emu_result)
    {
        fmt::print(stderr, "failed emulation\n");
        return 1;
    }
    std::unique_ptr<saved_instructions_t> tainted_instrs{emu_result};

    // we are only interested in the instructions from the main module
    std::vector<triton::arch::Instruction> main_exe_tainted_instrs;
    for (const std::pair<uint64_t, triton::arch::Instruction> &saved_instr : *tainted_instrs)
    {
        if (args.verbose)
            fmt::print("[D] tainted instruction: {:#x} {}\n", saved_instr.first, saved_instr.second.getDisassembly());
        for (auto &mod : main_modules)
        {
            if (mod.start <= saved_instr.first && saved_instr.first < mod.end)
            {
                main_exe_tainted_instrs.push_back(saved_instr.second);
                break;
            }
        }
    }

    fmt::print("[*] tainted instructions (main modules only)\n");
    for (auto &inst : main_exe_tainted_instrs)
    {
        fmt::print("  {:#018x}: {}\n", inst.getAddress(), inst.getDisassembly());
    }

    return 0;
}
