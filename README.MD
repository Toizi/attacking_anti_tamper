## Setup
```bash
# clone this repo
git clone --recursive https://github.com/Toizi/attacking_anti_tamper.git

# clone the self-checking repo and check out the right branch
cd attacking_anti_tamper
git clone https://github.com/Toizi/self-checksumming.git
cd self-checksumming && git checkout guard_obfuscation
```
# Building the c++ modules
Prerequisites:
- clang/clang++
- cmake
- ninja

On debian: `sudo apt update -y && sudo apt install -y clang clang++ ninja-build cmake`


## Build the tracer

1. Download current DynamoRIO release from their [release page](https://github.com/DynamoRIO/dynamorio/releases), DynamoRIO-Linux-7.91.XXXXX.tar.gz (for tested version, see `tracer/build.sh`)
2. Extract to parent directory
3. Adjust `DynamoRIO_DIR` path in `tracer/build.sh` to fit downloaded package version [here](https://github.com/Toizi/attacking_anti_tamper/blob/4839aa42296648800b5daeb50666fa4e33fbb977/tracer/build.sh#L19-L24)
4. Build desired configuration with `tracer/build.sh {Release|Debug|RelWithDebInfo}`
5. Resulting files will be put into `build_tracer_{CONFIG}/linux`

## Build the taint module
1. Build desired configuration with `taint_cpp/build.sh {Release|Debug|RelWithDebInfo}`
2. Resulting files will be put into `build_taint_cpp_{CONFIG}/linux`

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
