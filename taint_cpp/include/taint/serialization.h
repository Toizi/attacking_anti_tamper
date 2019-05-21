#pragma once
#include <stddef.h>
#include <vector>
#include <string>

struct saved_context_t {
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
    static std::vector<saved_context_t*> get_all(char *buf, size_t len);
};

struct saved_memory_t {
    size_t instr_num;
    size_t start_addr;
    size_t size;
    const char *data;

    static saved_memory_t *from_buf(char **buf);
    static std::vector<saved_memory_t*> get_all(char *buf, size_t len);
};

struct saved_module_t {
    size_t start;
    size_t end;
    std::string path;
    bool is_main;

    bool init(const std::string &name, const char *path);
};

bool read_trace_from_file(const char *filename, std::vector<uint64_t> &output);