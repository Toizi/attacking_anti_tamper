## Setup

### Docker
```bash
cd docker_build
docker build -t aat .
```

### Manual setup
```bash
# clone this repo
git clone --recursive https://github.com/Toizi/attacking_anti_tamper.git

# to build applications with self-checking,
# clone the self-checking repo and check out the right branch
cd attacking_anti_tamper
git clone https://github.com/Toizi/self-checksumming.git
cd self-checksumming && git checkout guard_obfuscation
```
# Building the c++ modules
Prerequisites:
- cmake
- ninja
- gcc/clang
- g++/clang++

On debian: `sudo apt update -y && sudo apt install -y clang clang++ ninja-build cmake`


## Build the tracer

1. Download current DynamoRIO release from their [release page](https://github.com/DynamoRIO/dynamorio/releases), [link to tested version](https://github.com/DynamoRIO/dynamorio/releases/download/release_8.0.0-1/DynamoRIO-Linux-8.0.0-1.tar.gz)
2. Extract to parent directory
3. Adjust `DynamoRIO_DIR` path in `tracer/build.sh` to fit downloaded package version [here](https://github.com/Toizi/attacking_anti_tamper/blob/4839aa42296648800b5daeb50666fa4e33fbb977/tracer/build.sh#L19-L24) when using a different version than the one tested
4. Build desired configuration with `tracer/build.sh {Release|Debug|RelWithDebInfo}`
5. Resulting files will be put into `build_tracer_{CONFIG}/linux`

## Build the taint module
1. Install [Triton's dependencies](https://triton.quarkslab.com/documentation/doxygen/#install_sec) (required version might be lower)
2. Build desired configuration with `taint_cpp/build.sh {Release|Debug|RelWithDebInfo}`
3. Resulting files will be put into `build_taint_cpp_{CONFIG}/linux`

# Usage

## Tracer
Use the `run.sh` (deletes and create directories in the `$(pwd)` and `run_manual.sh` scripts to run an executable while collecting trace data.
Example:
`./run.sh ls -la`
Will print some info about the trace, print `tracer_run_success` and exit.
The directory `instrace_logs/` contains the resulting artifacts used by the taint module.

```bash
instrace_logs
├── instrace.log                                        <== the instruction trace
├── modules                                             <== modules at the entry point (binary)
│   ├── 0x00007fefa6403000-0x00007fefa6422000-main_ls   <== main module
│   ├── 0x00007fefa6621000-0x00007fefa6623000-other_ls
│   ├── 0x00007fefa6623000-0x00007fefa6624000-other_ls
│   ├── 0x00007fefa6624000-0x00007fefa6625000-other_ls
│   ├── 0x00007fefa6626000-0x00007fefa6a26000-other_
│   .................................................
│   └── 0xffffffffff600000-0xffffffffff601000-other_
├── modules.txt                                         <== list of modules + address (txt)
├── saved_contexts.bin                                  <== saved context dumps
└── saved_memories.bin                                  <== saved memory dumps
```

## Taint Attack
Get help `src/taint_main -h`
Run attack using previously generated `instrace_logs` directory
`src/taint_main --json-output-path patches.json instrace_logs`
This creates `patches.json` with a simple format.
```json
{
 "patches": [

{ "address": 140667263185782, "asm_string": "jmp 0x7fefa640f3d0", "data_hex": "eb58" },
{ "address": 140667263200819, "asm_string": "mov rdx, r15", "data_hex": "4c89fa90" },
...
]
}
```
Put `data_hex` at `address` to place the `asm_string` instruction there.

## Helper Scripts
### `./run.py`
`./run.py` is the main entry point for manual execution of the attack.
If you built the `taint_cpp` and `tracer` modules in `Release` mode it should
work out of the box, otherwise you might have to adjust some paths in
the `setup_environment` function.
The only arguments that are needed for execution are
- the binary to be executed (positional arg)
- `--args` arguments that will be passed to the program
- `-i/--input` data that will be written to stdin of the process

There are a lot more arguments but most are fairly specific to the evaluation
process used in the thesis.

### `./eval.py`
`./eval.py` is a script to run the attack on a whole batch of programs at once.
Since it is unpractical to specify the characteristics of each program, i.e.
which files and arguments it needs or what return code signals success, this
is specified in a json file using the `--cmdline-input` switch.

To evaluate the mibench samples, the following command was used.
See [self-checksumming](https://github.com/Toizi/self-checksumming/tree/guard_obfuscation)
README on how to compile them.
```bash
# build dir is good to have in case the process is interrupted, otherwise /tmp is used
mkdir eval_build_dir
./eval.py self-checksumming/samples/protection_dataset_bin/seed_2 --crack-function mibench_dummy --cmdline-input self-checksumming/samples/cmdline-args/cmdline.json -j 3 --build-dir ./eval_build_dir --use-existing-results -o full_report.json`
```

Some interesting observations:
- the files in the input directory are expected to have the format
`file_name+{obfuscation}.{coverage}`. If multiple obfuscations are used, they
can be combined with a dash `-` such as `file_name+indir.10-virt.20`.
Additionally it is expected that a `file_name+none.0` file exists for each
`file_name`
- `--crack-function` is used to specify the function that will be tampered to
trigger tamper responses in protected binaries and after the patches from the
attack have been applied to check that they are disabled. In this case, the
dummy function that is inserted by the self-checking is used.
- `-j 3` allows to specify how many processes to spawn in parallel. While the
memory requirements are fairly low, the disk space requirements can get pretty
high, depending on the samples that are evaluated. Therefore a low count is used
despite having a lot more cores available
- `--use-existing-results` allows to rerun some experiments or add new files to
the input directory and just restart with the same command line as used before.
Note that the script is not able to determine whether a run was interrupted.
Thus you might have to clean up some directories in your `build-dir` manually
in case you interrupted an execution where a report file was generated.

### `./eval_report.py`
To generate graphs from a report file from `./eval.py`, use `./eval_report.py`
and supply the report path as argument. If no output directory was specified
with `-o/--output`, an `eval` directory will be created in the directory of the
input report.
The generated reports will have two groupings. One is grouped by obfuscation
configuration and the other by sample.
