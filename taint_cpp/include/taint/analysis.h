#pragma once
#include <triton/api.hpp>
#include <keystone/keystone.h>
#include <triton/x86Specifications.hpp>
#include <vector>
#include <taint/serialization.h>

struct Patch {
    std::vector<char> data;
    std::string asm_string;
    uint64_t address;

    std::string repr();
    std::string json();
};

struct SavedInstruction {
    uint64_t next_address;
    triton::arch::Instruction instr;
};

using saved_instructions_t = std::unordered_map<uint64_t, SavedInstruction>;
class TaintAnalysis
{
private:
    bool debug = false;
    triton::API api;
    std::vector<saved_module_t> modules;
    std::vector<saved_module_t> main_modules;
    std::unique_ptr<saved_instructions_t> saved_instructions;

    static std::vector<triton::arch::x86::instruction_e> skipped_instructions;

    bool addr_in_main_module(uint64_t addr);
    void set_context(const saved_context_t *context, bool set_ip = false);
    void print_context();

public:
    void set_debug(bool dbg);
    // saved_instructions_t &get_tainted_instructions() { return *saved_instructions; }
    bool setup_context(std::vector<saved_module_t> &modules);
    bool emulate(const std::vector<uint64_t> &trace, std::vector<saved_context_t *> &contexts,
                                  std::vector<saved_memory_t *> &memories);
    std::vector<std::unique_ptr<Patch>> create_patch();
};