#!/usr/bin/env python

# sequence diagram
# https://sequencediagram.org/index.html#initialData=C4S2BsFMAIENmLAxgaxAOwObQM6XAGYC0SAFpKhpgFDXLAD2ATtAApMOZOwC2PkTOklAA3eDHadufAdUlde-JkQB8TAK7oAdAAcAngC4N6ABQYd64AH0CIKABpo5y1Z45M9gDrpo4EEkh0PBtNYRAGdABKIVFxaGNdPWoE-VUUw2MrACMMWCY9M3QLa1sHJyKXN0xo5M1E1WBuAKYAegScUgNIAA8KS0hC4ps7SEdnayro+hAxYBhG5AE2uo7qBebl7Q6GpqX2zqYKZgATKx6+0AjBl1LR8qHJ2u19AB4iInW9lc7Pxxx0WA6DoMYA4aAmfg8Zh6FpICJzbrAaLHSDTWbzXatfa0dINWAYYCbRIGGIzOKIAlE-RrfHoQm4lQUulUwxM4DQOEommUhlslqwAHgPQAL0gxMgPHU4HEJl+uABQNIIJwUzC6OgfIFsCFosS3OZ6TeH1phK1OrF+gMbMgx3KOEa6jCERw1BRaPJJv5gpFFqS+vpdVSjM9SEO4isOngZGJodRc1lJptdodTqCjk+qticw1IbDcwjUdIer5hvefNj4cjwGjlqrZEgYJMhyhInmvB0AniDZ0zsgyNRao9lIr+brRep-pZeJ5ACYrICdEKC9XyDhiWOIxwFDxriURo4xw3M2TsyW5wul4e19SS4G9Eaz-OdIu9Mv69fDIfbTkAflXQOszbWcnxfN9Vz1UtjR5O8DC-aAfzyJI3UHU9PXSHE72nA1z2fS9CwbGMmhQTcpF4Ew4IQ-JHD8AIgkgEJ0FTY91UfC9XyvCC7wfNCcNAjjLVDZAUBtABqCjcj-ZDAJzYC2LAgiJzkLdpCUI10iMSBgHUJh0H-d1s3QqST1RAg5hYeQVIEIA

from __future__ import print_function
import argparse
import tempfile
import os
import subprocess
import shlex
from timeit import default_timer as timer
import traceback
import json
import shutil
import stat
import binascii
import filecmp
import re
import threading
import signal
from pprint import pprint

from taint.r2_apply_patches import crack_function, patch_program

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
    parser.add_argument("--args",
        help="arguments that will be supplied to the program",
        required=False)
    parser.add_argument("--env",
        help="additional environment variables that will be set",
        required=False)
    parser.add_argument("--success-exit-code",
        help="the code the program exits with when it was successful",
        default=0,
        type=int,
        required=False)
    parser.add_argument("--eval-stdout",
        help="python code that will be called on the output of the binary to make the comparison of several executions deterministic (should transform variable 's')",
        type=str,
        required=False)
    parser.add_argument("--app-result-output",
        help="the file produced by the application that can be used to check for correctness",
        default="stdout")
    parser.add_argument("--use-build-working-dir",
        help="execute the input_file with the build directory as the working dir. " \
            "Note: arguments are then relative to the build dir",
        action='store_true')
    parser.add_argument("-b", "--build-dir", required=False,
        help="directory that will be used for intermediate results")
    parser.add_argument("-r", "--report-path", required=False,
        help="path to a file that will contain a json report of the execution " +\
            "contains execution time and if crack options are specified whether " +\
            "the crack+patch was successful")
    parser.add_argument("--crack-only-output", type=str,
        help="path of cracked but not patched input binary")
    parser.add_argument("--taint-backend", type=str, choices=["python", "cpp"],
        default="cpp",
        help="which implementation for the taint analysis should be used")
    parser.add_argument("--crack-function", type=str)
    parser.add_argument("--cleanup", required=False, action="store_true",
        help="removes tracer fragments after executing the attack")
    parser.add_argument("input_file")
    
    args = parser.parse_args(argv)

    args.input_file = os.path.abspath(args.input_file)
    if not args.output:
        fname, ext = os.path.splitext(args.input_file)
        cracked_suffix = '' if not args.crack_function else '_cracked'
        args.output = '{}_patched{}{}'.format(fname, cracked_suffix, ext)
    
    
    return args

def setup_environment():
    global TRACER_PATH, TAINT_CPP_PATH, LIBMINM_PATH
    mydir   = os.path.dirname(os.path.abspath(__file__))
    TRACER_PATH = os.path.abspath(os.path.join(mydir, 'build_tracer_Release', 'linux', 'run_manual.sh'))
    TAINT_CPP_PATH = os.path.abspath(os.path.join(mydir, 'build_taint_cpp_Release', 'linux/src', 'taint_main'))
    # unused
    LIBMINM_PATH = os.path.abspath(os.path.join(mydir, 'self-checksumming', 'hook/build', 'libminm_env.so'))
    # analyze_path = os.path.join(mydir, 'taint', 'analyze.py')
    return True

def run_cmd(cmd, log_file=None):
    try:
        subprocess.check_call(shlex.split(cmd) if cmd is str else cmd,
            stdout=log_file,
            stderr=log_file)
        return True
    except subprocess.CalledProcessError:
        traceback.print_exc()
    except OSError:
        traceback.print_exc()
        print("  command {}".format(cmd))
    return False

def run_binary(input_file, input_msg, args, success_exit_code, cwd, env):
    cmd = [os.path.abspath(input_file)]
    if args:
        cmd.extend(shlex.split(args))

    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=env)
    except OSError:
        traceback.print_exc()
        print("  binary: {}".format(cmd))
        return False
    
    ret = False
    # set 15 min timeout which should be more than enough for simple binaries to finish
    timer = threading.Timer(60 * 15, proc.kill)
    try:
        timer.start()
        output = proc.communicate(input=input_msg)
        if not timer.isAlive():
            print('run_binary timed out')
            print('cmd: {}'.format(' '.join(cmd)))
        elif proc.returncode != success_exit_code:
            print('[-] run_binary return code was {}, expected {}'.format(
                proc.returncode, success_exit_code))
            print('cmd: {}'.format(' '.join(cmd)))
        else:
            ret = output
    finally:
        timer.cancel()
    return ret

def run_tracer(input_file, input_msg, log_dir, args, success_exit_code, cwd, env):
    os.mkdir(log_dir)
    os.mkdir(os.path.join(log_dir, 'modules'))
    cmd = '"{tracer}" -logdir {logdir} -- "{binary}" {args}'.format(
        tracer=TRACER_PATH,
        logdir=log_dir,
        binary=input_file,
        args=args)
    try:
        proc = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=env)

        stdout_data, stderr_data = proc.communicate(input=input_msg)

        if proc.returncode != success_exit_code:
            # special case since blowfish crashes dynamorio on exit
            if 'bf.x' in input_file and 'Segmentation fault' in stderr_data:
                pass
            else:
                print('[-] tracer return code was {}, expected {}'.format(
                    proc.returncode, success_exit_code))
                print(stdout_data)
                print(stderr_data)
                return False
    except OSError:
        traceback.print_exc()
        print('error running command:\n"{}"'.format(cmd))
        raise
    except subprocess.CalledProcessError:
        traceback.print_exc()
        raise
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

def run_taint_attack(input_file, build_dir, output_file, log_dir, taint_backend, text_section, report_dict):

    text_section_arg = '--text-section {},{}'.format(text_section[0], text_section[1]) if text_section else ''
    if taint_backend == "python":
        cmd = [
            log_dir,
            "--binary", input_file,
            "--output", output_file,
            "-v",
        ]
        from taint.run import main as taint_main
        return taint_main(cmd)

    patches_path = os.path.join(build_dir, 'patches.json')
    cmd = [
        TAINT_CPP_PATH,
        log_dir,
        "--fail-emulation-allowed",
        "--json-output", patches_path,
        "-v",
        # "-vv"
    ]
    if text_section_arg:
        cmd.append(text_section_arg)
    
    # if run_cmd(cmd) is not True:
    #     return False

    try:
        proc = subprocess.Popen(cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
    except OSError:
        traceback.print_exc()
        return False

    def stop_taint_cpp():
        # if we get really unlucky, this might happen exactly when the emulation
        # is done and the signal is not being caught but the probability should
        # be very low
        proc.send_signal(signal.SIGINT)
        # mark that we timed out
        report_dict['timeout'] = True
    
    timer = threading.Timer(36 * 60 * 60, stop_taint_cpp)
    try:
        timer.start()
        proc.wait()
    finally:
        timer.cancel()

    with open(patches_path, 'r') as f:
        patches = json.load(f)
    
    # "address", "asm_string", "data_hex"
    patches = patches['patches']

    # save number of detected checkers
    # (assuming each guard takes at most one patch since only cmovs/cjmps are patched)
    report_dict['checkers_patched'] = len(patches)

    # address, binary data, cmd_string
    patches_r2_format = [
        (entry['address'],
        binascii.unhexlify(entry['data_hex']),
        entry['asm_string'])
        for entry in patches
    ]

    # cpp backend doesn't know how to apply patches
    print('[*] applying patches\n {} => {}'.format(input_file, output_file))
    if not patch_program(input_file, output_file, patches_r2_format):
        print('[-] r2_apply_patches failed')
        return False

    return True


def check_patch_success(args, report_dict, cwd, build_dir, stdout_eval_str):
    # run binary that has been cracked but not patched to see if self-checking
    # triggers
    os.chmod(args.crack_only_output, 0766)
    ret = run_binary(args.crack_only_output, args.input, args.args, args.success_exit_code, cwd, args.env)
    if ret is False:
        print('[-] error running args.crack_only_output')
        return False
    # check how many unique checkers triggered a response
    tamper_response_ids = set()
    for match in re.finditer(r'Tampered binary \(id = (\d+)\)', ret[0]):
        tamper_response_ids.add(match.group(1))
    report_dict['self_check_triggered'] = len(tamper_response_ids)

    # get path of file created by the application
    if args.app_result_output != 'stdout':
        result_output_path = os.path.join(cwd or os.getcwd(), args.app_result_output)
    else:
        result_output_path = None

    # run the original version to get output that can be compared for correct program execution
    os.chmod(args.output, 0766)
    ret_org = run_binary(args.input_file, args.input, args.args, args.success_exit_code, cwd, args.env)
    if ret_org is False:
        print('[-] error running original binary')
        return False

    # move file to compare it later
    if result_output_path:
        shutil.move(result_output_path, result_output_path + "_org")

    # run the patched and cracked version to make sure no self-checking triggers
    os.chmod(args.output, 0766)
    ret = run_binary(args.output, args.input, args.args, args.success_exit_code, cwd, args.env)
    
    # if it returned false we either got a timeout or a wrong exit code
    # either way we can file it under broken program
    if ret is False:
        report_dict[RESULT_KEY] = 'broken_program'

    elif 'Tampered binary!' not in ret[0]:
        # if an output file exists, check those for equality
        if result_output_path:
            # check if files differ
            if not filecmp.cmp(result_output_path + "_org", result_output_path, shallow=False):
                report_dict[RESULT_KEY] = 'broken_program'
            else:
                # files do not differ
                report_dict[RESULT_KEY] = 'success'

        else:
            stdout_org = ret_org[0].strip()
            stdout_cracked = ret[0].strip()
            if stdout_eval_str:
                print('using eval on stdout: {}'.format(stdout_eval_str))
                stdout_org = eval(stdout_eval_str, {}, {'s': stdout_org})
                stdout_cracked = eval(stdout_eval_str, {}, {'s': stdout_cracked})

            # debugging
            with open(os.path.join(build_dir, 'expected_stdout'), 'w') as f:
                f.write(stdout_org)
            with open(os.path.join(build_dir, 'cracked_stdout'), 'w') as f:
                f.write(stdout_cracked)

            if stdout_org == stdout_cracked:
                report_dict[RESULT_KEY] = 'success'
            else:
                report_dict[RESULT_KEY] = 'broken_program'
    else:
        report_dict[RESULT_KEY] = 'detected'

        tamper_response_ids = set()
        for match in re.finditer(r'Tampered binary \(id = (\d+)\)', ret[0]):
            tamper_response_ids.add(match.group(1))
        report_dict['detected_count'] = len(tamper_response_ids)

    return True

from elftools.elf.elffile import ELFFile
def get_text_section(binary_path):
    with open(binary_path, 'rb') as f:
        e = ELFFile(f)
        for section in e.iter_sections():
            if section.name == '.text':
                return (section['sh_addr'], section['sh_size'])
    return None


def run(args, build_dir, track_time, report_dict):
    log_dir = os.path.join(build_dir, 'instrace_logs')

    # not longer needed: obfuscation overhead is measured independently
    # # run the binary without tracer and record the time to be able to
    # # report the overhead of the obfuscation
    # if track_time:
    #     print('[*] run_binary')
    #     start_time = timer()
    #     ret = run_binary(args.input_file, args.input)
    #     if ret is False:
    #         print('[-] run_binary')
    #         return False
    #     report_dict['execution'] = timer() - start_time

    print('[*] run_tracer')
    start_time = timer()
    ret = run_tracer(args.input_file, args.input, log_dir, args.args, args.success_exit_code, args.use_build_working_dir and build_dir or None, args.env)
    report_dict['tracer'] = timer() - start_time
    if not ret:
        report_dict[RESULT_KEY] = 'tracer_failed'
        print('[-] run_tracer')
        return False

    print('[*] run_taint_attack')
    text_section = get_text_section(args.input_file)
    start_time = timer()
    ret = run_taint_attack(args.input_file, build_dir, args.output, log_dir, args.taint_backend, text_section, report_dict)
    report_dict['taint'] = timer() - start_time

    # save trace size in report
    stat = os.stat(os.path.join(log_dir, 'instrace.log'))
    report_dict['trace_size'] = float(stat.st_size)

    if args.cleanup:
        shutil.rmtree(log_dir, ignore_errors=True)
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
            if not check_patch_success(args, report_dict, args.use_build_working_dir and build_dir or None, build_dir, args.eval_stdout):
                report_dict[RESULT_KEY] = 'crack_check_failed'
                print('[-] check_patch_success')
                return False
        
    return True

def main(argv):
    # workaround for mperf bug where __file__ is not set
    # if 'run.py' not in __file__:
    #     global __file__
    #     __file__ = os.path.join(os.getcwd(), 'run.py')

    args = parse_args(argv)
    if not setup_environment():
        return False
    
    # setup environment, i.e. LD_PRELOAD hook for input interception + name of intercept file
    if args.env:
        environ = os.environ
        environ['LD_PRELOAD'] = '{} {}'.format(
            environ.get('LD_PRELOAD', ''),
            LIBMINM_PATH).strip()
        for key, val in [s.split('=') for s in args.env.split(' ')]:
            environ[key] = val
        args.env = environ
    else:
        args.env = os.environ
    
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