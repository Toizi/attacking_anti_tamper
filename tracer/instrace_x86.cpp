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
#include "droption.h"
#include "utils.h"

#include <string>
#include <sstream>

// arg parsing crashes... use hardcoded path for now
static droption_t<std::string> op_logdir
(DROPTION_SCOPE_CLIENT, "logdir", "", "Directory where log files and other artifacts will be written to",
 "");
static std::string logdir = "";
/* Each ins_ref_t describes an executed instruction. */
typedef struct _ins_ref_t {
    app_pc pc;
    int opcode;
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
    void *cache;
    file_t log;
#ifdef OUTPUT_TEXT
    FILE *logf;
#endif
    uint64 num_refs;
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
static app_pc code_cache;
static void *mutex;     /* for multithread support */
static uint64 num_refs; /* keep a global memory reference count */
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
save_context(dr_mcontext_t*);
static void
flush_saved_memories();
static void
flush_saved_contexts();
static void
call_save_memory(size_t);
static void
clean_call_save_context(size_t);
static void
clean_call_trace(size_t);
static void
clean_call(void);
static void
instrace(void *drcontext);
static void
code_cache_init(void);
static void
code_cache_exit(void);
static void
instrument_instr(void *drcontext, instrlist_t *ilist, instr_t *where);


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
    drreg_options_t ops = { sizeof(ops), 3, true };
    /* Specify priority relative to other instrumentation operations: */
    drmgr_priority_t priority = { sizeof(priority), /* size of struct */
                                  "instrace",       /* name of our operation */
                                  NULL, /* optional name of operation we should precede */
                                  NULL, /* optional name of operation we should follow */
                                  0 };  /* numeric priority */
    dr_set_client_name("DynamoRIO Sample Client 'instrace'",
                       "http://dynamorio.org/issues");
    page_size = dr_page_size();
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS)
        DR_ASSERT(false);
    client_id = id;
    mutex = dr_mutex_create();
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


    // code_cache_init();
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
    // info->names
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
    code_cache_exit();

    if (!drmgr_unregister_tls_field(tls_index) ||
        !drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit) ||
        !drmgr_unregister_bb_insertion_event(event_bb_insert) ||
        !drmgr_unregister_module_load_event(event_module_load) ||
        drreg_exit() != DRREG_SUCCESS)
        DR_ASSERT(false);

    dr_mutex_destroy(mutex);
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
    data->num_refs = 0;

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

    instrace(drcontext);
    data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_index);
    dr_mutex_lock(mutex);
    num_refs += data->num_refs;
    dr_mutex_unlock(mutex);

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

static void
dump_mapped_memory()
{
    // dr_memory_dump_spec_t spec = { 0 };
    // spec.flags = DR_MEMORY_DUMP_LDMP;
    // spec.label = "dump_mapped_memory";
    // // std::string fpath = logdir + "ldmp.bin";
    // // spec.ldmp_path = fpath.c_str();
    // char fpath[512] = { 0 };
    // spec.ldmp_path = fpath;
    // spec.ldmp_path_size = 512;
    // if (dr_create_memory_dump(&spec)) {
    //     dr_printf("Created dump at %s\n", spec.ldmp_path);
    // } else {
    //     dr_printf("Could not create memory dump\n");
    // }
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
        ss << "-";
        ss << "0x" << std::setfill('0') << std::setw(16) << std::hex << end_addr;
        ss << "_" << short_name;
        std::string fname { ss.str() };
        file_t f = dr_open_file(fname.c_str(), DR_FILE_WRITE_OVERWRITE);
        if (f == INVALID_FILE) {
            dr_fprintf(STDERR, "Could not open file %s\n", fname.c_str());
            break;
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
    // if (!dr_set_mcontext(drcontext, &mcontext)) {
    //     dr_printf("dr_set_mcontext failed\n");
    //     dr_abort();
    // }
}

static void
insert_save_memory(void *drcontext, instrlist_t *ilist, instr_t *where, app_pc pc)
{
    dr_insert_clean_call(drcontext, ilist, where, (void *)call_save_memory, false,
        // pass as argument the PC of the instruction
        1, OPND_CREATE_INTPTR(pc));
}

static void
insert_save_context(void *drcontext, instrlist_t *ilist, instr_t *where, app_pc pc)
{
    // reg_id_t reg1, reg2;
    // drvector_t allowed;

    // drreg_init_and_fill_vector(&allowed, false);
    // drreg_set_vector_entry(&allowed, DR_REG_XCX, true);
    // if (drreg_reserve_register(drcontext, ilist, where, &allowed, &reg2) !=
    //         DRREG_SUCCESS ||
    //     drreg_reserve_register(drcontext, ilist, where, NULL, &reg1) != DRREG_SUCCESS) {
    //     DR_ASSERT(false); /* cannot recover */
    //     drvector_delete(&allowed);
    //     return;
    // }
    // drvector_delete(&allowed);
    // if (drreg_get_app_value(drcontext, ilist, where, DR_REG_RCX, DR_REG_RCX) != DRREG_SUCCESS) {
    //     dr_printf("drreg_get_app_value failed\n");
    // }
    // if (drreg_get_app_value(drcontext, ilist, where, DR_REG_RAX, DR_REG_RAX) != DRREG_SUCCESS) {
    //     dr_printf("drreg_get_app_value failed\n");
    // }

    // if (!drreg_set_bb_properties(drcontext, DRREG_CONTAINS_SPANNING_CONTROL_FLOW)) {
    //     dr_printf("drreg_set_bb_properties failed\n");
    // }
    // drreg_restore_app_values(drcontext, ilist, where, )
    dr_insert_clean_call(drcontext, ilist, where, (void *)clean_call_save_context, false,
        // pass as argument the PC of the instruction
        1, OPND_CREATE_INTPTR(pc));
    
    // if (drreg_unreserve_register(drcontext, ilist, where, reg1) != DRREG_SUCCESS ||
    //     drreg_unreserve_register(drcontext, ilist, where, reg2) != DRREG_SUCCESS)
    //     DR_ASSERT(false);
}


static app_pc context_save_instr_pc = 0;
static app_pc memory_save_instr_pc = 0;
static int instr_count = 0;
static bool disassembled_once = false;
/* event_bb_insert calls instrument_instr to instrument every
 * application memory reference.
 */
static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                bool for_trace, bool translating, void *user_data)
{

    if (instr_get_app_pc(instr) == NULL || !instr_is_app(instr))
        return DR_EMIT_DEFAULT;
    
    // start tracing at module entry point
    if (!initial_state_recorded && instr_get_app_pc(instr) != main_entry_pc)
        return DR_EMIT_DEFAULT;

    // store state for first instr of application
    if (!initial_state_recorded) {
        initial_state_recorded = true;
        // dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call_save_context, false,
        //     // pass as argument the PC of the instruction
        //     1, OPND_CREATE_INTPTR(-1));
        dr_insert_clean_call(drcontext, bb, instr, (void *)dump_mapped_memory, false,
            // pass as argument the PC of the instruction
            0, NULL);
        insert_save_context(drcontext, bb, instr, (app_pc)-1);
        // return DR_EMIT_DEFAULT;
    }
    
    // instr_t *prev_app_instr = instr_get_prev_app(instr);
    // if (prev_app_instr != NULL && instr_get_app_pc(prev_app_instr) != NULL && instr_is_app(prev_app_instr)) {
    //     int opc = instr_get_opcode(prev_app_instr);
    //     opnd_t op = instr_get_src(prev_app_instr, 0);
    //     if (opc == OP_cpuid || opc == OP_xgetbv || opnd_get_segment(op) == DR_SEG_GS
    //         || opc == OP_syscall || opc == OP_sysenter) { // || opc == OP_rep_stos) {
    //         char buf[128];
    //         instr_disassemble_to_buffer(drcontext, prev_app_instr, buf, 128);
    //         dr_printf("context_save_instr %#zx %d %s\n", instr_get_app_pc(prev_app_instr), instr_count, buf);
    //         instr_t *prev_instr = instr_get_next(prev_app_instr);
    //         insert_save_context(drcontext, bb, prev_instr, instr_get_app_pc(prev_app_instr));
    //         // dr_insert_clean_call(drcontext, bb, prev_instr, (void *)clean_call_save_context, false,
    //         //     // pass as argument the PC of the instr
    //         //     1, OPND_CREATE_INTPTR(instr_get_app_pc(prev_app_instr)));
            
    //         // if (!disassembled_once && opnd_get_segment(op) == DR_SEG_GS) {
    //         //     disassembled_once = true;

    //         //     std::string fname = logdir + "bb.disass";
    //         //     file_t f = dr_open_file(fname.c_str(), DR_FILE_WRITE_OVERWRITE);
    //         //     if (f == INVALID_FILE) {
    //         //         dr_fprintf(STDERR, "Could not open file %s\n", fname.c_str());
    //         //     } else {
    //         //         dr_printf("Wrote disassembly to %s\n", fname.c_str());
    //         //         instrlist_disassemble(drcontext, (app_pc)tag, bb, f);
    //         //         dr_close_file(f);
    //         //     }
    //         // }
    //         // return DR_EMIT_DEFAULT;
    //     }
    // }
    if (context_save_instr_pc) {
        insert_save_context(drcontext, bb, instr, context_save_instr_pc);
        context_save_instr_pc = 0;
    }
    if (memory_save_instr_pc) {
        insert_save_memory(drcontext, bb, instr, memory_save_instr_pc);
        memory_save_instr_pc = 0;
    }

    int opc = instr_get_opcode(instr);
    bool uses_gs_segment = false;
    if (instr_num_srcs(instr) > 0) {
        opnd_t op = instr_get_src(instr, 0);
        uses_gs_segment = opnd_is_far_memory_reference(op) && opnd_get_segment(op) == DR_SEG_GS;
    }
    bool dbg_dump = false;//instr_get_app_pc(instr) == (app_pc)0x7ffccbb56e16;
    if (opc == OP_cpuid || opc == OP_xgetbv || uses_gs_segment
        || opc == OP_syscall || opc == OP_sysenter
        || opc == OP_rdtsc || opc == OP_rdtscp
        || opc == OP_rdrand
        || opc == OP_vpmovmskb
        || dbg_dump) { // || opc == OP_rep_stos) {
        char buf[128];
        instr_disassemble_to_buffer(drcontext, instr, buf, sizeof(buf));
        context_save_instr_pc = instr_get_app_pc(instr);
        memory_save_instr_pc = opc == OP_syscall || opc == OP_sysenter || dbg_dump ? context_save_instr_pc : 0;
        dr_printf("context%s_save_instr %#zx %d %s\n",
            memory_save_instr_pc != 0 ? "/memory" : "", context_save_instr_pc, instr_count, buf);
    }

    instrument_instr(drcontext, bb, instr);
    ++instr_count;
    return DR_EMIT_DEFAULT;
}

static void
save_context(dr_mcontext_t *mcontext)
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

    size_t start_addr = (size_t)saved_contexts.data();
    size_t end_addr = start_addr + (size_t)(saved_contexts.size() * sizeof(saved_contexts[0]));
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
clean_call_trace(size_t pc)
{
    per_thread_t *data;

    void *drcontext = dr_get_current_drcontext();
    data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_index);
    /* The following assembly performs the following instructions
     * buf_ptr->pc = pc;
     * buf_ptr->opcode = opcode;
     * buf_ptr++;
     * if (buf_ptr >= buf_end_ptr)
     *    clean_call();
     */
    // dr_printf("data->buf_ptr %#zx = 1, data->buf_end %#zx\n", data->buf_ptr, -data->buf_end);
    // size_t *addr_to_read = (size_t*)0x00007ffccbb9aff0;
    // if (pc == (size_t)0x7ffccbb56e1c) {
    //     dr_printf("%#018zx: monitored_addr: %#zx = %#zx\n", pc, addr_to_read, *addr_to_read);
    // }

    // if (global_instr_count == 0) {
    //     dr_printf("%#018zx: monitored_addr: %#zx = %#zx\n", pc, addr_to_read, *addr_to_read);
    // }

    global_instr_count += 1;
    *(size_t*)(data->buf_ptr) = pc;
    data->buf_ptr += sizeof(ins_ref_t);
    if ((size_t)data->buf_ptr >= (size_t)-data->buf_end)
        clean_call();
}

static void
call_save_memory(size_t pc)
{
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
        if ((mem_info.prot & (DR_MEMPROT_GUARD | DR_MEMPROT_EXEC)) != 0 || (mem_info.prot & DR_MEMPROT_WRITE) == 0 || dr_memory_is_dr_internal(addr))
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
    // if (pc == -1) {
    //     dump_mapped_memory();
    // }
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mcontext = { 0 };
    mcontext.size = sizeof(dr_mcontext_t);
    mcontext.flags = DR_MC_ALL;
    
    if (!dr_get_mcontext(drcontext, &mcontext)) {
        dr_printf("dr_get_mcontext failed\n");
        return;
    }
    // size_t gs_val = 0;
    // if (!reg_get_value_ex(DR_SEG_GS, &mcontext, (byte*)&gs_val)) {
    //     dr_printf("get_reg_value_ex failed\n");
    // } else {
    //     dr_printf("gs_val %#zx\n", gs_val);
    // }
    mcontext.xip = (byte*)pc;
    // TODO: seems to return the wrong value :(
    // dr_printf("dump addr: %#zx, mcontext.rcx %#zx\n", pc, mcontext.rcx);
    save_context(&mcontext);
}

static void
instrace(void *drcontext)
{
    per_thread_t *data;
    int num_refs;
    ins_ref_t *ins_ref;
#ifdef OUTPUT_TEXT
    int i;
#endif

    data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_index);
    ins_ref = (ins_ref_t *)data->buf_base;
    num_refs = (int)((ins_ref_t *)data->buf_ptr - ins_ref);

#ifdef OUTPUT_TEXT
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
    data->num_refs += num_refs;
    data->buf_ptr = data->buf_base;
}

/* clean_call dumps the memory reference info to the log file */
static void
clean_call(void)
{
    // dr_printf("clean_call\n");
    void *drcontext = dr_get_current_drcontext();
    instrace(drcontext);
}

static void
code_cache_init(void)
{
    void *drcontext;
    instrlist_t *ilist;
    instr_t *where;
    byte *end;

    drcontext = dr_get_current_drcontext();
    code_cache =
        (app_pc)dr_nonheap_alloc(page_size, DR_MEMPROT_READ | DR_MEMPROT_WRITE | DR_MEMPROT_EXEC);
    ilist = instrlist_create(drcontext);
    /* The lean procecure simply performs a clean call, and then jumps back. */
    /* Jump back to DR's code cache. */
    where = INSTR_CREATE_jmp_ind(drcontext, opnd_create_reg(DR_REG_XCX));
    instrlist_meta_append(ilist, where);
    /* Clean call */
    dr_insert_clean_call(drcontext, ilist, where, (void *)clean_call, false, 0);
    /* Encode the instructions into memory and clean up. */
    end = instrlist_encode(drcontext, ilist, code_cache, false);
    DR_ASSERT((size_t)(end - code_cache) < page_size);
    instrlist_clear_and_destroy(drcontext, ilist);
    /* Set the memory as just +rx now. */
    dr_memory_protect(code_cache, page_size, DR_MEMPROT_READ | DR_MEMPROT_EXEC);
}

static void
code_cache_exit(void)
{
    dr_nonheap_free(code_cache, page_size);
}

/* instrument_instr is called whenever a memory reference is identified.
 * It inserts code before the memory reference to to fill the memory buffer
 * and jump to our own code cache to call the clean_call when the buffer is full.
 */
static void
instrument_instr(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    app_pc pc = instr_get_app_pc(where);
    dr_insert_clean_call(drcontext, ilist, where, (void *)clean_call_trace, false,
        // pass as argument the PC of the instruction
        1, OPND_CREATE_INTPTR(pc));

    return;
    instr_t *instr, *call, *restore;
    opnd_t opnd1, opnd2;
    reg_id_t reg1, reg2;
    drvector_t allowed;
    per_thread_t *data;
    // app_pc pc;

    data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_index);

    /* Steal two scratch registers.
     * reg2 must be ECX or RCX for jecxz.
     */
    drreg_init_and_fill_vector(&allowed, false);
    drreg_set_vector_entry(&allowed, DR_REG_XCX, true);
    if (drreg_reserve_register(drcontext, ilist, where, &allowed, &reg2) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg1) != DRREG_SUCCESS) {
        DR_ASSERT(false); /* cannot recover */
        drvector_delete(&allowed);
        return;
    }
    drvector_delete(&allowed);

    /* The following assembly performs the following instructions
     * buf_ptr->pc = pc;
     * buf_ptr->opcode = opcode;
     * buf_ptr++;
     * if (buf_ptr >= buf_end_ptr)
     *    clean_call();
     */
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg2);
    /* Load data->buf_ptr into reg2 */
    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_MEMPTR(reg2, offsetof(per_thread_t, buf_ptr));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Store pc */
    pc = instr_get_app_pc(where);
    /* For 64-bit, we can't use a 64-bit immediate so we split pc into two halves.
     * We could alternatively load it into reg1 and then store reg1.
     * We use a convenience routine that does the two-step store for us.
     */
    opnd1 = OPND_CREATE_MEMPTR(reg2, offsetof(ins_ref_t, pc));
    instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)pc, opnd1, ilist, where, NULL,
                                     NULL);

    /* Store opcode */
    opnd1 = OPND_CREATE_MEMPTR(reg2, offsetof(ins_ref_t, opcode));
    opnd2 = OPND_CREATE_INT32(instr_get_opcode(where));
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Increment reg value by pointer size using lea instr */
    opnd1 = opnd_create_reg(reg2);
    opnd2 = opnd_create_base_disp(reg2, DR_REG_NULL, 0, sizeof(ins_ref_t), OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Update the data->buf_ptr */
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, reg1);
    opnd1 = OPND_CREATE_MEMPTR(reg1, offsetof(per_thread_t, buf_ptr));
    opnd2 = opnd_create_reg(reg2);
    instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* We use the lea + jecxz trick for better performance.
     * lea and jecxz won't disturb the eflags, so we won't need
     * code to save and restore the application's eflags.
     */
    /* lea [reg2 - buf_end] => reg2 */
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_MEMPTR(reg1, offsetof(per_thread_t, buf_end));
    instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    opnd1 = opnd_create_reg(reg2);
    opnd2 = opnd_create_base_disp(reg1, reg2, 1, 0, OPSZ_lea);
    instr = INSTR_CREATE_lea(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jecxz call */
    call = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(call);
    instr = INSTR_CREATE_jecxz(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* jump restore to skip clean call */
    restore = INSTR_CREATE_label(drcontext);
    opnd1 = opnd_create_instr(restore);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* clean call */
    /* We jump to our generated lean procedure which performs a full context
     * switch and clean call invocation. This is to reduce the code cache size.
     */
    instrlist_meta_preinsert(ilist, where, call);
    /* mov restore DR_REG_XCX */
    opnd1 = opnd_create_reg(reg2);
    /* This is the return address for jumping back from the lean procedure. */
    opnd2 = opnd_create_instr(restore);
    /* We could use instrlist_insert_mov_instr_addr(), but with a register
     * destination we know we can use a 64-bit immediate.
     */
    instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(ilist, where, instr);
    /* jmp code_cache */
    opnd1 = opnd_create_pc(code_cache);
    instr = INSTR_CREATE_jmp(drcontext, opnd1);
    instrlist_meta_preinsert(ilist, where, instr);

    /* Restore scratch registers */
    instrlist_meta_preinsert(ilist, where, restore);
    if (drreg_unreserve_register(drcontext, ilist, where, reg1) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg2) != DRREG_SUCCESS)
        DR_ASSERT(false);
}
