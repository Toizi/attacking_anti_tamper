#!/usr/bin/env python
from __future__ import print_function
import argparse
import tempfile
import os
import subprocess
import shlex
import time

from taint.run import main as taint_main

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging information",
                        action="store_true")
    parser.add_argument("-o", "--output", help="output path", required=False)
    parser.add_argument("-i", "--input",
        help="message that will be supplied to stdin of the binary when run",
        required=False)
    parser.add_argument("input_file")
    
    args = parser.parse_args(argv)

    if not args.output:
        fname, ext = os.path.splitext(args.input_file)
        args.output = '{}_cracked{}'.format(fname, ext)

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
        return False
    return True

def run_tracer(input_file, build_dir, input_msg):
    log_dir = os.path.join(build_dir, 'instrace_logs')
    os.mkdir(log_dir)
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

def run(args, build_dir):
    if args.verbose:
        print('[*] run_tracer')
    if not run_tracer(args.input_file, build_dir, args.input):
        print('[-] run_tracer')
        return False
    return True

def main(argv):
    args = parse_args(argv)
    if not setup_environment():
        return False
    build_dir  = tempfile.mkdtemp()
    run(args, build_dir)

    if args.verbose:
        print('Done')
        print('Intermediate results in\n{}'.format(build_dir))
    return True

if __name__ == '__main__':
    main(os.sys.argv[1:])