#include <taint/serialization.h>
#include <taint/utils.h>
#include <memory>
#include <fstream>
#include <fmt/format.h>

std::vector<saved_context_t *>
saved_context_t::get_all(char *buf, size_t len)
{
    std::vector<saved_context_t *> ctxs;
    saved_context_t *end = reinterpret_cast<saved_context_t *>(
        buf + len);
    for (saved_context_t *ctx = reinterpret_cast<saved_context_t *>(buf);
         ctx < end; ++ctx)
    {
        ctxs.push_back(ctx);
    }
    return ctxs;
}

/// creates a saved_memory_t on the heap and returns the pointer to it
/// buf will be modified to point to the memory immediately after the memory
/// used to create the struct
saved_memory_t *saved_memory_t::from_buf(char **buf)
{
    char *struct_begin = static_cast<char *>(*buf);
    saved_memory_t *mem = reinterpret_cast<saved_memory_t *>(struct_begin);
    mem->data = struct_begin + sizeof(saved_memory_t);
    *buf = (char *)(mem->data + mem->size);
    return mem;
}

std::vector<saved_memory_t *>
saved_memory_t::get_all(char *buf, size_t len)
{
    if (len == 0)
        return {};
    char *cur = buf;
    char *end = buf + len;
    std::vector<saved_memory_t *> result;
    do
    {
        saved_memory_t *mem = from_buf(&cur);
        if (!mem)
            break;
        result.push_back(mem);
    } while (cur < end);
    return result;
}

bool saved_module_t::init(const std::string &name, const char *path)
{
    this->path = path;

    // get start
    size_t delim_pos = name.find('-');
    if (delim_pos == std::string::npos)
        return false;
    this->start = std::stoull(name.substr(0, delim_pos), nullptr, 16);

    // get end
    std::string leftover = name.substr(delim_pos + 1);
    delim_pos = leftover.find('-');
    if (delim_pos == std::string::npos)
        return false;
    this->end = std::stoull(leftover.substr(0, delim_pos), nullptr, 16);
    leftover = leftover.substr(delim_pos + 1);

    // get is_main
    delim_pos = leftover.find('_');
    if (delim_pos == std::string::npos)
        return false;

    this->is_main = leftover.substr(0, delim_pos).find("main") == 0;

    return true;
}

bool read_trace_from_file(const char *filename, std::vector<uint64_t> &output)
{
    std::ifstream file(filename, std::ifstream::binary);
    if (!file)
    {
        fmt::print(stderr, "could not open file for reading\n  '{:s}'\n", filename);
        return false;
    }

    file.seekg(0, file.end);
    size_t len = file.tellg();
    file.seekg(0, file.beg);

    auto buffer = std::vector<uint64_t>(len / sizeof(uint64_t));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), len))
    {
        fmt::print(stderr, "could not fully read file\n  '{:s}'\n", filename);
        return false;
    }
    output.swap(buffer);
    file.close();

    return true;
}