#!/usr/bin/env python
from __future__ import print_function
import argparse
import tempfile
import os
import subprocess
import shlex
import time
import traceback
import json
import shutil
from pprint import pprint

from taint.run import main as taint_main
from taint.r2_apply_patches import crack_function

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging information",
        action="store_true")
    parser.add_argument("-o", "--output",
        help="output path of the patched (checking removed) binary",
        required=False)
    parser.add_argument("-i", "--input",
        help="message that will be supplied to stdin of the binary when run",
        required=False)
    parser.add_argument("-b", "--build-dir", required=False,
        help="directory that will be used for intermediate results")
    parser.add_argument("-r", "--report-time", required=False,
        help="path to a file that will contain a json report of the elapsed time")
    parser.add_argument("--crack-only-output", type=str,
        help="path of cracked but not patched input binary")
    parser.add_argument("--crack-function", type=str)
    parser.add_argument("input_file")
    
    args = parser.parse_args(argv)

    if not args.output:
        fname, ext = os.path.splitext(args.input_file)
        cracked_suffix = '' if not args.crack_function else '_cracked'
        args.output = '{}_patched{}{}'.format(fname, cracked_suffix, ext)
    
    return args

def setup_environment():
    global TRACER_PATH
    mydir   = os.path.dirname(os.path.abspath(__file__))
    TRACER_PATH = os.path.join(mydir, 'build_tracer_Release', 'linux', 'run_manual.sh')
    # analyze_path = os.path.join(mydir, 'taint', 'analyze.py')
    return True

def run_cmd(cmd):
    try:
        subprocess.check_call(shlex.split(cmd))
    except subprocess.CalledProcessError:
        traceback.print_exc()
        return False
    return True

def run_binary(input_file, input_msg):
    cmd = '"{input}"'.format(input=input_file)
    try:
        proc = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        _ = proc.communicate(input=input_msg)
    except subprocess.CalledProcessError:

        return False
    return True

def run_tracer(input_file, input_msg, log_dir):
    os.mkdir(log_dir)
    os.mkdir(os.path.join(log_dir, 'modules'))
    cmd = '"{tracer}" -logdir {logdir} -- "{binary}"'.format(
        tracer=TRACER_PATH,
        logdir=log_dir,
        binary=input_file)
    
    proc = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    stdout_data, stderr_data = proc.communicate(input=input_msg)
    # terminated = False
    # while True:
    #     if proc.poll():
    #         terminated = True
    #     out_data, _ = proc.communicate() 
    #     output += out_data
    #     if terminated:
    #         break
    #     time.sleep(1) 
    success = 'tracer_run_success' in stderr_data
    if not success:
        print('[-] tracer_run_success not found in stderr output')
        print(stdout_data)
        print(stderr_data)
    return success

def run_taint_attack(input_file, build_dir, output_file, log_dir):
    cmd = '"{log_dir}" --binary "{binary}" --output "{out}"'.format(
        log_dir=log_dir,
        binary=input_file,
        out=output_file)
    return taint_main(shlex.split(cmd))


def run(args, build_dir, track_time, elapsed_time):
    log_dir = os.path.join(build_dir, 'instrace_logs')

    if track_time:
        print('[*] run_binary')
        start_time = time.clock()
        run_binary(args.input_file, args.input)
        elapsed_time['execution'] = time.clock() - start_time

    print('[*] run_tracer')
    start_time = time.clock()
    ret = run_tracer(args.input_file, args.input, log_dir)
    elapsed_time['tracer'] = time.clock() - start_time
    if not ret:
        print('[-] run_tracer')
        return False

    print('[*] run_taint_attack')
    start_time = time.clock()
    ret = run_taint_attack(args.input_file, build_dir, args.output, log_dir)
    elapsed_time['taint'] = time.clock() - start_time
    if not ret:
        print('[-] run_taint_attack')
        return False
    
    if args.crack_function:
        print('[*] crack_function {} of "{}"'.format(args.crack_function, args.output))
        if not crack_function(args.output, args.crack_function):
            print('[-] crack_function')
            return False

        if args.crack_only_output:
            print('[*] crack_function {} of "{}"'.format(args.crack_function, args.crack_only_output))
            try:
                shutil.copyfile(args.input_file, args.crack_only_output)
            except IOError:
                print('could not copy output file to {}'.format(args.crack_ouput))
                return False
            if not crack_function(args.crack_only_output, args.crack_function):
                print('[-] crack_function')
                return False
        
    return True

def main(argv):
    args = parse_args(argv)
    if not setup_environment():
        return False
    
    # create build dir as tmp dir if none was specified
    if not args.build_dir:
        build_dir  = tempfile.mkdtemp()
    else:
        if not os.path.exists(args.build_dir):
            os.mkdir(args.build_dir)
        build_dir = args.build_dir

    elapsed_time = dict()
    success = run(args, build_dir, args.report_time is not None, elapsed_time)
    if args.report_time:
        if args.report_time == 'stdout':
            pprint(elapsed_time)
        with open(args.report_time, 'w') as f:
            json.dump(elapsed_time, f)

    print('[*] intermediate results: {}'.format(build_dir))
    print('[{}] Done, {}'.format(
        success and '+' or '-',
        success and 'success' or 'failed'))
    return True

if __name__ == '__main__':
    main(os.sys.argv[1:])