#pragma once
#include <string>

struct cmd_args {
    bool verbose = false;
    // std::string output_path;
    // std::string input_binary;
    std::string log_dir;
    std::string json_output_path;
};

bool parse_args(int argc, char **argv, cmd_args &args);