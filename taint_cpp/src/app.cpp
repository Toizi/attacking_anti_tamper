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


    TaintAnalysis analysis;
    analysis.set_debug(args.verbose);
    // setup the memory/taint
    fmt::print("[*] setting up the context\n");
    if (!analysis.setup_context(modules)) // modules are now owned by analysis
    {
        fmt::print(stderr, "failed setting up the context\n");
        return 1;
    }

    // running the emulation
    fmt::print("[*] running the emulation\n");
    if (!analysis.emulate(trace, saved_contexts, saved_memories))
    {
        fmt::print(stderr, "failed emulation\n");
        return 1;
    }

    // get patch instructions from analysis
    fmt::print("[*] creating patch\n");
    std::vector<std::unique_ptr<Patch>> patches = analysis.create_patch();
    if (patches.empty()) {
        fmt::print(stderr, "create patch failed\n");
        return 1;
    }
    if (args.verbose)
    {
        fmt::print("[D] patches:\n");
        for (auto &patch : patches)
        {
            fmt::print("  {}\n", patch->repr());
        }
    }

    // write json 
    fmt::print("[*] writing json file\n");
    std::ofstream json_file(args.json_output_path);
    if (!json_file)
    {
        fmt::print(stderr, "cannot open json output path\n  '{:s}'\n", args.json_output_path);
        return 1;
    }
    json_file << "{\n \"patches\": [\n";
    bool first = true;
    for (auto &patch : patches) {
        if (first) {
            first = false;
        } else
            json_file << ',';
        json_file << '\n';
        json_file << patch->json();
    }
    json_file << "]}\n";


    return 0;
}
