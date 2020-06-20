#!/usr/bin/env python3

import subprocess
import tempfile
import os
import shutil
import json
from glob import glob

test_commands = {
    'ls -lah /bin': ['/bin/ls', '-lah', '/bin'],
    'grep Hello hello_world.c': ['/bin/grep', 'Hello', 'count_instructions_samples/hello_world.c'],
    'Hello World!': ['count_instructions_samples/hello_world'],
    'Fibonacci to 1000': ['count_instructions_samples/fibonacci', '1000'],
    'FizzBuzz to 1000': ['count_instructions_samples/fizz_buzz', '1000'],
    'Count to 2^24': ['count_instructions_samples/count_to', '16777216'],
}

friendly_names_map = {
    'search_small.x': 'search_small',
    'fft.x': 'fft',
    'toast.x': 'toast',
    'rijndael.x': 'rijndael',
    'tetris_predet': 'tetris',
    '2048_game': '2048 (game)',
    'bf.x': 'blowfish',
    'basicmath_small.x': 'basicmath_small',
    'qsort_large.x': 'qsort_large',
    'basicmath_large.x': 'basicmath_large',
    'susan': 'susan',
    'patricia.x': 'patricia',
    'sha': 'sha',
    'crc.x': 'crc',
    'dijkstra_small.x': 'dijkstra_small',
    'qsort_small.x': 'qsort_small',
    'rawcaudio.x': 'rawcaudio',
    'rawdaudio.x': 'rawdaudio',
    'dijkstra_large.x': 'dijkstra_large',
    'search_large.x': 'search_large',
    'bitcnts.x': 'bitcnts',
    'say.x': 'say',
    'snake_predet': 'snake',
    'cjpeg.x': 'cjpeg',
}

def main():
    build_dir = tempfile.mkdtemp()
    print(f'using build dir: {build_dir}')
    ret = 0
    try:
        my_dir = os.path.dirname(os.path.abspath(__file__))
        tracer_path = os.path.join(my_dir, 'build_tracer_Release/linux/run.sh')

        cmdline_args_dir = os.path.join(my_dir, 'self-checksumming/samples/cmdline-args')
        with open(os.path.join(cmdline_args_dir, 'cmdline.json'), 'r') as f:
            cmdline_args = json.load(f)
        
        samples_dir = os.path.join(my_dir,
            'self-checksumming/samples/protection_dataset_nocheck/seed_1')
        if samples_dir[-1] != os.path.sep:
            samples_dir += '/'
        samples = glob(samples_dir + '*')

        # copy input files to build dir
        build_dir_args = os.path.join(build_dir, 'args')
        shutil.copytree(cmdline_args_dir, build_dir_args)
        execution_trace_path = os.path.join(build_dir_args, 'instrace_logs/instrace.log')

        results = []
        print(f'{"command": <20} | {"trace size": >15}')
        print('-' * (20 + 3 + 15))
        for sample in samples:
            name = os.path.basename(sample).partition('+')[0]
            cmd_info = cmdline_args[name]
            cmd = [tracer_path, os.path.abspath(sample)]
            args = cmd_info['args']
            stdin = None
            for arg in args:
                if '<' in arg:
                    stdin = arg.partition('<')[2].strip()
                    stdin = open(os.path.join(build_dir_args, stdin), 'rb')
                else:
                    cmd.append(arg)
            p = subprocess.run(cmd, cwd=build_dir_args,
                stdin=stdin,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT)
            if stdin:
                stdin.close()
            if p.returncode != cmd_info.get('success_exit_code', 0) and 'bf.x' not in name:
                print(f'error running {cmd}')
                ret = -1
                continue
            stat = os.stat(execution_trace_path)
            instr_count = stat.st_size // 8
            friendly_name = friendly_names_map[name]
            results.append((friendly_name, instr_count))
            print(f'{friendly_name: <20} | {instr_count: >15}')


        execution_trace_path = os.path.join(build_dir, 'instrace_logs/instrace.log')
        for name, cmd in test_commands.items():
            final_cmd = [tracer_path]
            for c in cmd:
                if os.path.exists(c):
                    c = os.path.abspath(c)
                final_cmd.append(c)
            subprocess.check_output(
                final_cmd,
                cwd=build_dir,
                stderr=subprocess.STDOUT)
            stat = os.stat(execution_trace_path)
            instr_count = stat.st_size // 8
            print(f'{name: <24} & {instr_count//1000: >15,} \\\\')

        results.sort(key=lambda x: x[1]) 
        median = results[len(results) // 2]
        average = sum((r[1] for r in results)) // len(results)
        print(f'median:  {median}')
        print(f'average: {average}')
        print('results formatted as latex table')
        for result in results:
            name = result[0].replace("_", "\\_")
            print(f'{name: <20} & {result[1]//1000: >15,} \\\\')
        

    except Exception as e:
        print(e)
        shutil.rmtree(build_dir)

    exit(ret)


if __name__ == "__main__":
    main()