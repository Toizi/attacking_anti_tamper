#include <taint/cmdline.h>
#include <clipp.h>
#include <fmt/format.h>

#include <iostream>

bool parse_args(int argc, char **argv, cmd_args &args) {
    auto cli = (
        clipp::option("-v", "--verbose").set(args.verbose)
            .doc("print debugging output"),
        (clipp::option("-o", "--output") & clipp::value("outfile", args.output_path))
            .doc("output path"),
        (clipp::option("-b", "--binary") & clipp::value("binary", args.input_binary))
            .doc("input binary that will be used to create a patched version"),
        clipp::value("log input dir", args.log_dir)
            .blocking(false) // non-positional
            .doc("directory of logdir arg passed to instrace")
    );

    if (!clipp::parse(argc, argv, cli)) {
        std::cerr << clipp::make_man_page(cli, argv[0]);
        return false;
    }

    if (!args.output_path.empty() && args.input_binary.empty()) {
        fmt::print(stderr, "error: output file specified without input binary\n");
        return false;
    }

    if (!args.input_binary.empty() && args.output_path.empty()) {
        args.output_path = args.input_binary;
        args.output_path += "_patched";
    }

    // make sure the logdir path ends with a slash
    if (args.log_dir.back() != '/')
        args.log_dir += '/';

    if (args.verbose) {
        fmt::print("arguments:\n");
        fmt::print("verbose      {}\n", args.verbose);
        fmt::print("output_path  {:s}\n", args.output_path);
        fmt::print("input_binary {:s}\n", args.input_binary);
        fmt::print("log_dir      {:s}\n", args.log_dir);
    }
    return true;
}