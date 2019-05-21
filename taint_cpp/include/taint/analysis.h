#pragma once
#include <triton/api.hpp>
#include <triton/x86Specifications.hpp>
#include <vector>
#include <taint/serialization.h>

using saved_instructions_t = std::unordered_map<uint64_t, triton::arch::Instruction>;
class TaintAnalysis
{
private:
    static std::vector<triton::arch::x86::instruction_e> skipped_instructions;
    triton::API api;

    void set_context(const saved_context_t *context, bool set_ip = false);
    void print_context();

public:
    bool setup_context(const std::vector<saved_module_t> &modules);
    saved_instructions_t *emulate(const std::vector<uint64_t> &trace, std::vector<saved_context_t *> &contexts,
                                  std::vector<saved_memory_t *> &memories, bool print_dbg = false);
};