/* ******************************************************************************
 * Copyright (c) 2011-2018 Google, Inc.  All rights reserved.
 * Copyright (c) 2010 Massachusetts Institute of Technology  All rights reserved.
 * ******************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Code Manipulation API Sample:
 * instrace_x86.c
 *
 * Collects a dynamic instruction trace and dumps it to a file.
 * This is an x86-specific implementation of an instruction tracing client.
 * For a simpler (and slower) arch-independent version, please see instrace_simple.c.
 *
 * Illustrates how to create generated code in a local code cache and
 * perform a lean procedure call to that generated code.
 *
 * (1) Fills a buffer and dumps the buffer when it is full.
 * (2) Inlines the buffer filling code to avoid a full context switch.
 * (3) Uses a lean procedure call for clean calls to reduce code cache size.
 *
 * The OUTPUT_TEXT define controls the format of the trace: text or binary.
 * Creating a text trace file makes the tool an order of magnitude (!) slower
 * than creating a binary file; thus, the default is binary.
 */

#include <cstdio>
#include <cstring> /* for memset */
#include <cstddef> /* for offsetof */
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "dr_tools.h"
// #include "droption.h"
#include "utils.h"

#include <string>
#include <sstream>
#include <vector>
#include <iomanip>

#include <unistd.h>
#include <asm/ldt.h>   
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <asm/prctl.h>

// static droption_t<std::string> op_logdir
// (DROPTION_SCOPE_CLIENT, "logdir", "", "Directory where log files and other artifacts will be written to",
//  "");

static std::string logdir = "";
/* Each ins_ref_t describes an executed instruction. */
typedef struct _ins_ref_t {
    app_pc pc;
    // int opcode;
} ins_ref_t;

/* Max number of ins_ref a buffer can have */
#define MAX_NUM_INS_REFS 8192
/* The size of the memory buffer for holding ins_refs. When it fills up,
 * we dump data from the buffer to the file.
 */
#define MEM_BUF_SIZE (sizeof(ins_ref_t) * MAX_NUM_INS_REFS)

/* Thread-private data */
typedef struct {
    char *buf_ptr;
    char *buf_base;
    /* buf_end holds the negative value of real address of buffer end. */
    ptr_int_t buf_end;
    file_t log;
#ifdef OUTPUT_TEXT
    FILE *logf;
#endif
} per_thread_t;

typedef struct {
    size_t instr_num;

    size_t xdi;
    size_t xsi;
    size_t xbp;
    size_t xsp;
    size_t xbx;
    size_t xdx;
    size_t xcx;
    size_t xax;

    size_t r8;
    size_t r9;
    size_t r10;
    size_t r11;
    size_t r12;
    size_t r13;
    size_t r14;
    size_t r15;

    size_t xflags;

    size_t xip;

    size_t fs;
} saved_context_t;

typedef struct {
    size_t trace_addr;
    size_t start_addr;
    size_t size;
    // must be freed with dr_global_free(data, len)
    const char *data;
} saved_memory_t;

static size_t global_instr_count = 0;
static size_t page_size;
static client_id_t client_id;
static int tls_index;
static file_t saved_contexts_file = INVALID_FILE;
static file_t saved_memories_file = INVALID_FILE;
static std::vector<saved_context_t> saved_contexts;
static std::vector<saved_memory_t> saved_memories;
static bool initial_state_recorded = false;
static size_t saved_stack_start = -1;
static size_t saved_stack_end = -1;
static app_pc main_entry_pc = 0;

static void
event_exit(void);
static void
event_module_load(void *drcontext, const module_data_t * info, bool loaded);
static void
event_thread_init(void *drcontext);
static void
event_thread_exit(void *drcontext);

static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                bool for_trace, bool translating, void *user_data);

static void
save_context(void*, dr_mcontext_t*);
static void
flush_saved_memories();
static void
flush_saved_contexts();
static void
clean_call_save_memory(size_t);
static void
clean_call_save_context(size_t);
static void
clean_call_xgetbv_callback(size_t pc);
static void
clean_call_cpuid_callback_before(size_t pc);
static void
clean_call_cpuid_callback_after(size_t pc);
static void
clean_call_trace(size_t);
static void
flush_saved_traces(void *drcontext);


DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_fprintf(STDERR, "parsing args\n");
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        dr_fprintf(STDERR, "%s\n", arg);
        if (strcmp("-logdir", arg) == 0) {
            if (i + 1 < argc) {
                logdir = std::string{ argv[i+1] };
                if (logdir[logdir.size() - 1] != PATHSEP)
                    logdir += PATHSEP;
                ++i;
            } else {
                dr_fprintf(STDERR, "-logdir specified but no directory specified\n");
                dr_abort();
            }
        } else {
            dr_fprintf(STDERR, "argument ignored: '%s'\n", *arg);
        }
        dr_fprintf(STDERR, "loop end\n");
    }
    // // droption_parser_t::parse_argv crashes...
    // std::string parse_err;
    // int last_idx = 0;
    // if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, &last_idx)) {
    //     dr_fprintf(STDERR, "Usage error: %s\n", parse_err.c_str());
    //     dr_abort();
    // }
    dr_fprintf(STDERR, "parsing args done\n");
    if (logdir.empty()) {
        dr_fprintf(STDERR, "fatal error: missing argument -logdir {path}\n");
        dr_abort();
    }
    // if (!op_logdir.get_value().empty()) {
    //     dr_printf("logdir: %s\n", op_logdir.get_value().c_str());
    // }
    /* We need 2 reg slots beyond drreg's eflags slots => 3 slots */
    // TODO: set third option, drreg_options_t.conservative to false for better performance
    // set to true right now to turn off lazy restores of registers which leads to
    // wrong values in the save_context clean call
    drreg_options_t ops = { sizeof(ops), 3, false, NULL };
    /* Specify priority relative to other instrumentation operations: */
    drmgr_priority_t priority = { sizeof(priority), /* size of struct */
                                  "instrace",       /* name of our operation */
                                  NULL, /* optional name of operation we should precede */
                                  NULL, /* optional name of operation we should follow */
                                  0 };  /* numeric priority */
    dr_set_client_name("DynamoRIO Sample Client 'instrace'",
                       "http://dynamorio.org/issues");
    disassemble_set_syntax(DR_DISASM_INTEL);
    page_size = dr_page_size();
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS)
        DR_ASSERT(false);
    client_id = id;
    dr_register_exit_event(event_exit);
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_bb_instrumentation_event(NULL /*analysis func*/, event_bb_insert,
                                                 &priority) ||
        !drmgr_register_module_load_event(event_module_load)) {
        /* something is wrong: can't continue */
        DR_ASSERT(false);
        return;
    }
    tls_index = drmgr_register_tls_field();
    DR_ASSERT(tls_index != -1);

    module_data_t *main_module = dr_get_main_module();
    main_entry_pc = main_module->entry_point;
    dr_free_module_data(main_module);


    dr_log(NULL, DR_LOG_ALL, 1, "Client 'instrace' initializing\n");
#ifdef SHOW_RESULTS
    if (dr_is_notify_on()) {
#    ifdef WINDOWS
        /* Ask for best-effort printing to cmd window.  Must be called at init. */
        dr_enable_console_printing();
#    endif
        dr_fprintf(STDERR, "Client instrace is running\n");
    }
#endif
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    (void)drcontext;
    std::string name = dr_module_preferred_name(info);
    if (name.find("ntdll") == std::string::npos) {
        return;
    }
    size_t start_addr = (size_t)info->start;
    size_t end_addr = (size_t)info->end;
    // size_t mon_addr = 0x00007ffccbc5d070;
    // if (start_addr <= mon_addr && mon_addr < end_addr) {
    //     dr_printf("monitored_value at module_load : %#zx = %#zx\n", mon_addr, *(size_t*)mon_addr);
    // }
    dr_printf("module_load: %s, loaded %d, from %#zx to %#zx\n", name.c_str(), loaded, start_addr, end_addr);
    dr_flush_file(STDOUT);
    std::stringstream ss;
    // ss << op_logdir.get_value() << '\\';
    ss << logdir << "modules" << PATHSEP;
    ss << "0x" << std::setfill('0') << std::setw(16) << std::hex << start_addr;
    ss << "-";
    ss << "0x" << std::setfill('0') << std::setw(16) << std::hex << end_addr;
    ss << "_" << name.c_str();
    std::string fname { ss.str() };
    file_t f = dr_open_file(fname.c_str(), DR_FILE_WRITE_OVERWRITE);
    if (f == INVALID_FILE) {
        dr_fprintf(STDERR, "Could not open file %s\n", fname.c_str());
        return;
    }
    size_t buf_size = end_addr - start_addr;
    size_t num_written = dr_write_file(f, (void*)start_addr, buf_size);
    if (num_written != buf_size) {
        dr_fprintf(STDERR, "Failed writing to file %s (%#zx/%#zx)\n", fname.c_str(), num_written, buf_size);
    }
    dr_close_file(f);
}

static void
event_exit()
{
#ifdef SHOW_RESULTS
    char msg[512];
    int len;
    len = dr_snprintf(msg, sizeof(msg) / sizeof(msg[0]),
                      "Instrumentation results:\n"
                      "  saw %llu memory references\n",
                      num_refs);
    DR_ASSERT(len > 0);
    NULL_TERMINATE_BUFFER(msg);
    DISPLAY_STRING(msg);
#endif /* SHOW_RESULTS */

    if (!drmgr_unregister_tls_field(tls_index) ||
        !drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit) ||
        !drmgr_unregister_bb_insertion_event(event_bb_insert) ||
        !drmgr_unregister_module_load_event(event_module_load) ||
        drreg_exit() != DRREG_SUCCESS)
        DR_ASSERT(false);
    dr_fprintf(STDERR, "tracer_run_success\n");

    drmgr_exit();
}

#ifdef WINDOWS
#    define IF_WINDOWS(x) x
#else
#    define IF_WINDOWS(x) /* nothing */
#endif

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data;

    /* allocate thread private data */
    data = (per_thread_t*)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    drmgr_set_tls_field(drcontext, tls_index, data);
    data->buf_base = (char*)dr_thread_alloc(drcontext, MEM_BUF_SIZE);
    data->buf_ptr = data->buf_base;
    /* set buf_end to be negative of address of buffer end for the lea later */
    data->buf_end = -(ptr_int_t)(data->buf_base + MEM_BUF_SIZE);

    /* We're going to dump our data to a per-thread file.
     * On Windows we need an absolute path so we place it in
     * the same directory as our library. We could also pass
     * in a path as a client argument.
     */
    data->log = log_file_open(client_id, drcontext,
        logdir.c_str(),
        // op_logdir.get_value().empty()
        // ? NULL /* using client lib path */
        // : op_logdir.get_value().c_str(),
        "instrace",
#ifndef WINDOWS
                      DR_FILE_CLOSE_ON_FORK |
#endif
                          DR_FILE_ALLOW_LARGE);
#ifdef OUTPUT_TEXT
    data->logf = log_stream_from_file(data->log);
    fprintf(data->logf, "Format: <instr address>,<opcode>\n");
#endif
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data;

    flush_saved_traces(drcontext);
    data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_index);

    // write mcontext structs
    flush_saved_contexts();
    if (saved_contexts_file != INVALID_FILE)
        dr_close_file(saved_contexts_file);

    // write memory snapshots
    flush_saved_memories();
    if (saved_memories_file != INVALID_FILE)
        dr_close_file(saved_memories_file);

#ifdef OUTPUT_TEXT
    log_stream_close(data->logf); /* closes fd too */
#else
    log_file_close(data->log);
#endif
    dr_thread_free(drcontext, data->buf_base, MEM_BUF_SIZE);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static size_t get_thread_base() {
    unsigned long addr;
    int ret = syscall(SYS_arch_prctl, ARCH_GET_FS, &addr);
    if (ret != 0) {
        dr_fprintf(STDERR, "arch_prctl failed: %s\n", strerror(errno));
        return -1;
    }
    return addr;
}

static void
dump_mapped_memory()
{
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mcontext = { 0 };
    mcontext.size = sizeof(dr_mcontext_t);
    mcontext.flags = DR_MC_ALL;
    
    if (!dr_get_mcontext(drcontext, &mcontext)) {
        dr_printf("dr_get_mcontext failed\n");
        dr_abort();
    }

    byte *addr = 0;
    dr_mem_info_t mem_info = { 0 };
    while (dr_query_memory_ex(addr, &mem_info) && mem_info.type != DR_MEMTYPE_ERROR_WINKERNEL && addr != (byte*)-1) {
        // dr_printf("dr_query_memory_ex = %#zx, type %x,  prot %x, internal %d\n", addr, mem_info.type, mem_info.prot, dr_memory_is_dr_internal(addr));
        addr = mem_info.base_pc + mem_info.size;
        // only interested in data that can be read and written
        if ((mem_info.prot & (DR_MEMPROT_GUARD)) != 0 || (mem_info.prot & DR_MEMPROT_READ) == 0 || dr_memory_is_dr_internal(addr))
            continue;
        
        size_t size = (size_t)mem_info.size;
        size_t start_addr = (size_t)mem_info.base_pc;
        size_t end_addr = start_addr + size;

        // might be too naive to only save it at start since it could grow during runtime
        if (start_addr < mcontext.xsp && mcontext.xsp < end_addr) {
            saved_stack_start = start_addr;
            saved_stack_end = end_addr;
        }

        if (!dr_memory_is_readable((byte*)start_addr, size)) {
            // dr_printf("Memory is not readable, won't dump. Protections: %x\n", mbi.Protect);
            continue;
        }

        std::string full_name { "" };
        module_data_t *module = dr_lookup_module((byte*)start_addr);
        if (module) {
            full_name = dr_module_preferred_name(module);
            dr_free_module_data(module);
            module = nullptr;
        }

        size_t last_backslash_pos = full_name.rfind('\\');
        std::string short_name = full_name.substr(last_backslash_pos + 1);
        if (short_name.find("ntdll") != std::string::npos) {
            // size_t *addr_to_read = (size_t*)0x00007ffccbb9aff0;
            // dr_printf("dump_mapped_memory: monitored_addr: %#zx = %#zx\n", addr_to_read, *addr_to_read);
            // return;
            continue;
        }

        dr_printf("%#018zx - %#018zx, %s\n", start_addr, end_addr, short_name.c_str());

        // dump memory
        std::stringstream ss;
        // ss << op_logdir.get_value() << '\\';
        ss << logdir << "modules" << PATHSEP;
        ss << "0x" << std::setfill('0') << std::setw(16) << std::hex << start_addr;
        ss << '-';
        ss << "0x" << std::setfill('0') << std::setw(16) << std::hex << end_addr;
        ss << '-';
        // mark main module
        if (start_addr <= (size_t)main_entry_pc && (size_t)main_entry_pc < end_addr)
            ss << "main";
        else
            ss << "other";
        
        ss << '_' << short_name;
        std::string fname { ss.str() };
        file_t f = dr_open_file(fname.c_str(), DR_FILE_WRITE_OVERWRITE);
        if (f == INVALID_FILE) {
            dr_fprintf(STDERR, "Could not open file %s\n", fname.c_str());
            dr_abort();
        }
        size_t buf_size = end_addr - start_addr;
        dr_switch_to_app_state(drcontext);
        size_t num_written = dr_write_file(f, (void*)start_addr, buf_size);
        dr_switch_to_dr_state(drcontext);
        if (num_written != buf_size) {
            dr_fprintf(STDERR, "Failed writing to file %s (%#zx/%#zx)\n", fname.c_str(), num_written, buf_size);
        }
        dr_close_file(f);
    }
}

static void
insert_save_memory(void *drcontext, instrlist_t *ilist, instr_t *where, app_pc pc)
{
    dr_insert_clean_call(drcontext, ilist, where, (void *)clean_call_save_memory, false,
        // pass as argument the PC of the instruction
        1, OPND_CREATE_INTPTR(pc));
}

static void
insert_save_context(void *drcontext, instrlist_t *ilist, instr_t *where, app_pc pc)
{
    dr_insert_clean_call(drcontext, ilist, where, (void *)clean_call_save_context, false,
        // pass as argument the PC of the instruction
        1, OPND_CREATE_INTPTR(pc));
}


static app_pc context_save_instr_pc = 0;
static app_pc memory_save_instr_pc = 0;
static app_pc xgetbv_instr_pc = 0;
static app_pc cpuid_instr_pc = 0;
static int instr_count = 0;
/* event_bb_insert calls instrument_instr to instrument every
 * application memory reference.
 */
static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                bool for_trace, bool translating, void *user_data)
{
    (void)user_data; (void)tag; (void)for_trace; (void)translating;

    app_pc pc = instr_get_app_pc(instr);
    if (pc == NULL || !instr_is_app(instr))
        return DR_EMIT_DEFAULT;
    
    // dump state at entry point
    // DO NOT RETURN EARLY HERE. We still need to instrument every basic block
    if (!initial_state_recorded && pc == main_entry_pc) {
        initial_state_recorded = true;

        dr_insert_clean_call(drcontext, bb, instr, (void *)dump_mapped_memory, false,
            0, NULL);
        insert_save_context(drcontext, bb, instr, (app_pc)-1);
    }
    
    // insert context/memory save call in case e.g. the last instruction was
    // unsupported by the analysis tool
    if (context_save_instr_pc) {
        insert_save_context(drcontext, bb, instr, context_save_instr_pc);
        context_save_instr_pc = 0;
    }
    if (memory_save_instr_pc) {
        insert_save_memory(drcontext, bb, instr, memory_save_instr_pc);
        memory_save_instr_pc = 0;
    }
    if (xgetbv_instr_pc) {
        dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call_xgetbv_callback, false,
            // pass as argument the PC of the instruction
            1, OPND_CREATE_INTPTR(pc));
        xgetbv_instr_pc = 0;
    }
    if (cpuid_instr_pc) {
        dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call_cpuid_callback_after, false,
            // pass as argument the PC of the instruction
            1, OPND_CREATE_INTPTR(pc));
        cpuid_instr_pc = 0;
    }

    // determine whether a context/memory save is required and signal it by
    // setting context_save_instr_pc/memory_save_instr_pc to save the state
    // after the current instruction
    int opc = instr_get_opcode(instr);
    bool dbg_dump = false; // pc == (app_pc)0x7ffccbb56e16;
    if (opc == OP_cpuid || opc == OP_xgetbv //|| uses_tls_segment || writes_tls_segment
        || opc == OP_syscall || opc == OP_sysenter
        || opc == OP_rdtsc || opc == OP_rdtscp
        || opc == OP_rdrand
        // || opc == OP_vpmovmskb
        || opc == OP_xsave32
        || opc == OP_xrstor32
        // || opc == OP_pslld
        // || opc == OP_psllq
        || opc == OP_vmovd
        || opc == OP_vpxor
        || opc == OP_vpbroadcastb
        || dbg_dump) {
        if (opc == OP_xgetbv)
            xgetbv_instr_pc = pc;
        if (opc == OP_cpuid) {
            dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call_cpuid_callback_before, false,
                // pass as argument the PC of the instruction
                1, OPND_CREATE_INTPTR(pc));
            cpuid_instr_pc = pc;
        }
        char buf[128];
        instr_disassemble_to_buffer(drcontext, instr, buf, sizeof(buf));
        context_save_instr_pc = pc;
        memory_save_instr_pc = opc == OP_syscall || opc == OP_sysenter || instr_writes_memory(instr) || dbg_dump ? pc : 0;
        dr_printf("context%s_save_instr %#zx %d %s\n",
            memory_save_instr_pc != 0 ? "/memory" : "", context_save_instr_pc, instr_count, buf);
    }

    dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call_trace, false,
        // pass as argument the PC of the instruction
        1, OPND_CREATE_INTPTR(pc));

    ++instr_count;
    return DR_EMIT_DEFAULT;
}

static void
save_context(void *drcontext, dr_mcontext_t *mcontext)
{
    saved_context_t s;
    s.instr_num = global_instr_count - 1;

    s.xdi = (size_t)mcontext->xdi;
    s.xsi = (size_t)mcontext->xsi;
    s.xbp = (size_t)mcontext->xbp;
    s.xsp = (size_t)mcontext->xsp;
    s.xbx = (size_t)mcontext->xbx;
    s.xdx = (size_t)mcontext->xdx;
    s.xcx = (size_t)mcontext->xcx;
    s.xax = (size_t)mcontext->xax;

    s.r8 = (size_t)mcontext->r8;
    s.r9 = (size_t)mcontext->r9;
    s.r10 = (size_t)mcontext->r10;
    s.r11 = (size_t)mcontext->r11;
    s.r12 = (size_t)mcontext->r12;
    s.r13 = (size_t)mcontext->r13;
    s.r14 = (size_t)mcontext->r14;
    s.r15 = (size_t)mcontext->r15;

    s.xflags = mcontext->xflags;

    s.xip = (size_t)mcontext->xip;

    dr_switch_to_app_state(drcontext);
    size_t tb = get_thread_base();
    // size_t tb_val = ((size_t*)tb)[0x28/sizeof(size_t)];
    dr_switch_to_dr_state(drcontext);
    // dr_printf("fs addr %#zx [0x28] = %#zx, rax = %#zx\n", tb, tb_val, mcontext->rax);
    s.fs  = tb;

    saved_contexts.push_back(s);
}

static void
flush_saved_memories()
{
    if (saved_memories.empty())
        return;

    std::string fname = logdir + "saved_memories.bin";
    if (saved_memories_file == INVALID_FILE) {
        file_t f = dr_open_file(fname.c_str(), DR_FILE_WRITE_OVERWRITE);
        if (f == INVALID_FILE) {
            dr_fprintf(STDERR, "Could not open file %s\n", fname.c_str());
            return;
        }
        saved_memories_file = f;
    }

    for (saved_memory_t &saved_memory : saved_memories) {
        size_t buf_size = sizeof(saved_memory);
        size_t num_written = dr_write_file(saved_memories_file, &saved_memory, buf_size);
        if (num_written != buf_size) {
            dr_fprintf(STDERR, "Failed writing to file %s (%#zx/%#zx)\n", fname.c_str(), num_written, buf_size);
        }
        buf_size = saved_memory.size;
        num_written = dr_write_file(saved_memories_file, saved_memory.data, buf_size);
        if (num_written != buf_size) {
            dr_fprintf(STDERR, "Failed writing to file %s (%#zx/%#zx)\n", fname.c_str(), num_written, buf_size);
        }
        dr_global_free((void*)saved_memory.data, saved_memory.size);
    }
    saved_memories.clear();
}

static void
flush_saved_contexts()
{
    if (saved_contexts.empty())
        return;

    std::string fname = logdir + "saved_contexts.bin";
    if (saved_contexts_file == INVALID_FILE) {
        file_t f = dr_open_file(fname.c_str(), DR_FILE_WRITE_OVERWRITE);
        if (f == INVALID_FILE) {
            dr_fprintf(STDERR, "Could not open file %s\n", fname.c_str());
            return;
        }
        saved_contexts_file = f;
    }
    size_t buf_size = saved_contexts.size() * sizeof(saved_contexts[0]);
    size_t num_written = dr_write_file(saved_contexts_file, saved_contexts.data(), buf_size);
    if (num_written != buf_size) {
        dr_fprintf(STDERR, "Failed writing to file %s (%#zx/%#zx)\n", fname.c_str(), num_written, buf_size);
    }
    saved_contexts.clear();
}

static void
flush_saved_traces(void *drcontext)
{
    per_thread_t *data;
    ins_ref_t *ins_ref;
#ifdef OUTPUT_TEXT
    int i;
    int num_refs;
#endif

    data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_index);
    ins_ref = (ins_ref_t *)data->buf_base;

#ifdef OUTPUT_TEXT
    num_refs = (int)((ins_ref_t *)data->buf_ptr - ins_ref);
    /* We use libc's fprintf as it is buffered and much faster than dr_fprintf
     * for repeated printing that dominates performance, as the printing does here.
     */
    for (i = 0; i < num_refs; i++) {
        /* We use PIFX to avoid leading zeroes and shrink the resulting file. */
        fprintf(data->logf, PIFX ",%s\n", (ptr_uint_t)ins_ref->pc,
                decode_opcode_name(ins_ref->opcode));
        ++ins_ref;
    }
#else
    dr_write_file(data->log, data->buf_base, (size_t)(data->buf_ptr - data->buf_base));
#endif

    memset(data->buf_base, 0, MEM_BUF_SIZE);
    data->buf_ptr = data->buf_base;
}

static void
clean_call_trace(size_t pc)
{
    // only record traces once the entry point has been reached
    if (!initial_state_recorded)
        return;

    per_thread_t *data;

    void *drcontext = dr_get_current_drcontext();
    data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_index);

    global_instr_count += 1;
    *(size_t*)(data->buf_ptr) = pc;
    data->buf_ptr += sizeof(ins_ref_t);
    if ((size_t)data->buf_ptr >= (size_t)-data->buf_end)
        flush_saved_traces(drcontext);
}

static void
clean_call_save_memory(size_t pc)
{
    (void)pc;
    // only save memory once the entry point has been reached
    if (!initial_state_recorded)
        return;

    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mcontext = { 0 };
    mcontext.size = sizeof(dr_mcontext_t);
    mcontext.flags = DR_MC_ALL;
    if (!dr_get_mcontext(drcontext, &mcontext)) {
        dr_printf("dr_get_mcontext failed\n");
        return;
    }

#ifndef MEMORY_SAVE_STACK_ONLY
    // query the entire address space and save anything that looks like data
    byte *addr = 0;
    dr_mem_info_t mem_info = { 0 };
    while (dr_query_memory_ex(addr, &mem_info) && mem_info.type != DR_MEMTYPE_ERROR_WINKERNEL && addr != (byte*)-1) {
        // dr_printf("dr_query_memory_ex = %#zx, type %x,  prot %x, internal %d\n", addr, mem_info.type, mem_info.prot, dr_memory_is_dr_internal(addr));
        addr = mem_info.base_pc + mem_info.size;
        // only interested in data that can be written to since read only data should not change
        // if (mem_info.type != DR_MEMTYPE_DATA || mem_info.prot != (DR_MEMPROT_READ | DR_MEMPROT_WRITE) || dr_memory_is_dr_internal(addr))
        if ((mem_info.prot & (DR_MEMPROT_GUARD | DR_MEMPROT_EXEC | DR_MEMPROT_VDSO)) != 0 || (mem_info.prot & DR_MEMPROT_READ) == 0 || dr_memory_is_dr_internal(addr))
            continue;
        
        saved_memory_t saved_memory = { 0 };
        saved_memory.trace_addr = global_instr_count - 1;
        saved_memory.start_addr = (size_t)mem_info.base_pc;
        saved_memory.size = mem_info.size;
        saved_memory.data = (const char*)dr_global_alloc(saved_memory.size);

        dr_switch_to_app_state(drcontext);
        memcpy((void*)saved_memory.data, (void*)saved_memory.start_addr, saved_memory.size);
        dr_switch_to_dr_state(drcontext);

        saved_memories.push_back(saved_memory);
    }
#else
    if (saved_stack_start == -1 || saved_stack_end == -1) {
        dr_printf("saved_stack bounds invalid: %#zx - %#zx\n", saved_stack_start, saved_stack_end);
    }

    saved_memory_t saved_memory = { 0 };
    saved_memory.trace_addr = global_instr_count - 1;
    saved_memory.start_addr = saved_stack_start;
    saved_memory.size = saved_stack_end - saved_stack_start;
    saved_memory.data = (const char*)dr_global_alloc(saved_memory.size);

    memcpy((void*)saved_memory.data, (void*)saved_memory.start_addr, saved_memory.size);

    saved_memories.push_back(saved_memory);
#endif

    if (!dr_set_mcontext(drcontext, &mcontext)) {
        dr_printf("dr_set_mcontext failed\n");
        dr_abort();
    }
}

static void
clean_call_save_context(size_t pc)
{
    if (!initial_state_recorded)
        return;

    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mcontext = { 0 };
    mcontext.size = sizeof(dr_mcontext_t);
    mcontext.flags = DR_MC_ALL;
    
    if (!dr_get_mcontext(drcontext, &mcontext)) {
        dr_printf("%s: dr_get_mcontext failed\n", __FUNCTION__);
        return;
    }

    // mcontext seems to contain a wrong value so set it manually
    mcontext.xip = (byte*)pc;
    save_context(drcontext, &mcontext);
}

static void
clean_call_xgetbv_callback(size_t pc)
{
    // if (!initial_state_recorded)
    //     return;

    (void)pc;
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mcontext = { 0 };
    mcontext.size = sizeof(dr_mcontext_t);
    mcontext.flags = DR_MC_INTEGER;
    
    if (!dr_get_mcontext(drcontext, &mcontext)) {
        dr_printf("%s: dr_get_mcontext failed\n", __FUNCTION__);
        return;
    }

    if ((mcontext.rax & 0x6) == 0x6) {
        dr_printf("eax & 0x6, removing bit\n");
        mcontext.rax = mcontext.rax & ~0x6;
        dr_set_mcontext(drcontext, &mcontext);
    }
}

static uint32_t cpuid_eax_arg = 0;
static void
clean_call_cpuid_callback_before(size_t pc)
{
    (void)pc;
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mcontext = { 0 };
    mcontext.size = sizeof(dr_mcontext_t);
    mcontext.flags = DR_MC_INTEGER;
    
    if (!dr_get_mcontext(drcontext, &mcontext)) {
        dr_printf("%s: dr_get_mcontext failed\n", __FUNCTION__);
        return;
    }

    cpuid_eax_arg = (uint32_t)mcontext.rax;
}

#define SSE2_BIT (1 << 26)
static void
clean_call_cpuid_callback_after(size_t pc)
{
    (void)pc;
    // if (!initial_state_recorded)
    //     return;
    if (cpuid_eax_arg != 1)
        return;

    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mcontext = { 0 };
    mcontext.size = sizeof(dr_mcontext_t);
    mcontext.flags = DR_MC_INTEGER;
    
    if (!dr_get_mcontext(drcontext, &mcontext)) {
        dr_printf("%s: dr_get_mcontext failed\n", __FUNCTION__);
        return;
    }

    if ((mcontext.rdx & SSE2_BIT) == SSE2_BIT) {
        dr_printf("SSE2_BIT set, removing it\n");
        mcontext.rdx = mcontext.rdx & ~SSE2_BIT;
        dr_set_mcontext(drcontext, &mcontext);
    }
}
