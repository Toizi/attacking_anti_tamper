#!/usr/bin/env python

# sequence diagram
# https://sequencediagram.org/index.html#initialData=C4S2BsFMAIENmLAxgaxAOwObQM6XAGYC0SAFpKhpgFDXLAD2ATtAApMOZOwC2PkTOklAA3eDHadufAdUlde-JkQB8TAK7oAdAAcAngC4N6ABQYd64AH0CIKABpo5y1Z45M9gDrpo4EEkh0PBtNYRAGdABKIVFxaGNdPWoE-VUUw2MrACMMWCY9M3QLa1sHJyKXN0xo5M1E1WBuAKYAegScUgNIAA8KS0hC4ps7SEdnayro+hAxYBhG5AE2uo7qBebl7Q6GpqX2zqYKZgATKx6+0AjBl1LR8qHJ2u19AB4iInW9lc7Pxxx0WA6DoMYA4aAmfg8Zh6FpICJzbrAaLHSDTWbzXatfa0dINWAYYCbRIGGIzOKIAlE-RrfHoQm4lQUulUwxM4DQOEommUhlslqwAHgPQAL0gxMgPHU4HEJl+uABQNIIJwUzC6OgfIFsCFosS3OZ6TeH1phK1OrF+gMbMgx3KOEa6jCERw1BRaPJJv5gpFFqS+vpdVSjM9SEO4isOngZGJodRc1lJptdodTqCjk+qticw1IbDcwjUdIer5hvefNj4cjwGjlqrZEgYJMhyhInmvB0AniDZ0zsgyNRao9lIr+brRep-pZeJ5ACYrICdEKC9XyDhiWOIxwFDxriURo4xw3M2TsyW5wul4e19SS4G9Eaz-OdIu9Mv69fDIfbTkAflXQOszbWcnxfN9Vz1UtjR5O8DC-aAfzyJI3UHU9PXSHE72nA1z2fS9CwbGMmhQTcpF4Ew4IQ-JHD8AIgkgEJ0FTY91UfC9XyvCC7wfNCcNAjjLVDZAUBtABqCjcj-ZDAJzYC2LAgiJzkLdpCUI10iMSBgHUJh0H-d1s3QqST1RAg5hYeQVIEIA

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
import stat
from pprint import pprint

from taint.run import main as taint_main
from taint.r2_apply_patches import crack_function

RESULT_KEY = 'attack_result'
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
    parser.add_argument("-r", "--report-path", required=False,
        help="path to a file that will contain a json report of the execution " +\
            "contains execution time and if crack options are specified whether " +\
            "the crack+patch was successful")
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
        return proc.communicate(input=input_msg)
    except subprocess.CalledProcessError:
        traceback.print_exc()
    except OSError:
        traceback.print_exc()
    return False

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
    cmd = '"{log_dir}" --binary "{binary}" --output "{out}" -v'.format(
        log_dir=log_dir,
        binary=input_file,
        out=output_file)
    return taint_main(shlex.split(cmd))

def check_patch_success(crack_only_path, patched_path, input_msg, report_dict):
    # run binary that has been cracked but not patched to see if self-checking
    # triggers
    os.chmod(crack_only_path, 0766)
    ret = run_binary(crack_only_path, input_msg)
    if ret is False:
        print('[-] error running crack_only_path')
        return False
    # check that tampered message is in stdout
    report_dict['self_check_triggered'] = 'Tampered binary!' in ret[0]

    # run the patched and cracked version to make sure no self-checking triggers
    os.chmod(patched_path, 0766)
    ret = run_binary(patched_path, input_msg)
    if ret is False:
        print('[-] error running patched_path')
        return False
    report_dict[RESULT_KEY] = 'success' if 'Tampered binary!' not in ret[0] else 'detected'

    return True


def run(args, build_dir, track_time, report_dict):
    log_dir = os.path.join(build_dir, 'instrace_logs')

    # run the binary without tracer and record the time to be able to
    # report the overhead of the obfuscation
    if track_time:
        print('[*] run_binary')
        start_time = time.clock()
        ret = run_binary(args.input_file, args.input)
        if ret is False:
            print('[-] run_binary')
            return False
        report_dict['execution'] = time.clock() - start_time

    print('[*] run_tracer')
    start_time = time.clock()
    ret = run_tracer(args.input_file, args.input, log_dir)
    report_dict['tracer'] = time.clock() - start_time
    if not ret:
        report_dict[RESULT_KEY] = 'tracer_failed'
        print('[-] run_tracer')
        return False

    print('[*] run_taint_attack')
    start_time = time.clock()
    ret = run_taint_attack(args.input_file, build_dir, args.output, log_dir)
    report_dict['taint'] = time.clock() - start_time
    if not ret:
        report_dict[RESULT_KEY] = 'taint_failed'
        print('[-] run_taint_attack')
        return False
    
    if args.crack_function:
        print('[*] crack_function {} of "{}"'.format(args.crack_function, args.output))
        if not crack_function(args.output, args.crack_function):
            report_dict[RESULT_KEY] = 'crack_failed'
            print('[-] crack_function')
            return False

        if args.crack_only_output:
            print('[*] crack_function {} of "{}"'.format(args.crack_function, args.crack_only_output))
            try:
                shutil.copyfile(args.input_file, args.crack_only_output)
            except IOError:
                report_dict[RESULT_KEY] = 'crack_failed'
                print('could not copy output file to {}'.format(args.crack_ouput))
                return False
            if not crack_function(args.crack_only_output, args.crack_function):
                report_dict[RESULT_KEY] = 'crack_failed'
                print('[-] crack_function')
                return False
            
            print('[*] check_patch_success')
            if not check_patch_success(args.crack_only_output, args.output, args.input, report_dict):
                report_dict[RESULT_KEY] = 'crack_check_failed'
                print('[-] check_patch_success')
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

    report_dict = dict()
    success = run(args, build_dir, args.report_path is not None, report_dict)
    if args.report_path:
        if args.report_path == 'stdout':
            pprint(report_dict)
        with open(args.report_path, 'w') as f:
            json.dump(report_dict, f)

    print('[*] intermediate results: {}'.format(build_dir))
    print('[{}] Done, {}'.format(
        success and '+' or '-',
        success and 'success' or 'failed'))
    return True

if __name__ == '__main__':
    main(os.sys.argv[1:])