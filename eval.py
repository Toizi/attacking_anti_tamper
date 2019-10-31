#!/usr/bin/env python
from __future__ import print_function
import argparse
import os
import subprocess
import traceback
import tempfile
import shutil
import json
from glob import glob
from collections import namedtuple
from pprint import pformat, pprint
from multiprocessing import cpu_count
from multiprocessing.pool import Pool, Process
class KeyboardInterruptError(Exception): pass

class EvalSample:

    def __init__(self, base_path, obfuscations, build_dir, cmd_info):
        self.base_path = base_path
        self.original_path = '{}+none'.format(base_path)
        self.build_path = os.path.join(build_dir, os.path.basename(self.base_path))
        self.obfuscations = [ Obfuscation(obf, self.build_path, self.base_path) for obf in obfuscations ]
        self.cmd_info = cmd_info
    
    def __str__(self):
        # s = """base_path: {}\noriginal_path: {}\nobfuscations: {}""".format(
        #     self.base_path, self.original_path, self.obfuscations)
        lines = ["EvalSample:"]
        lines.extend(["  {}: {}".format(name, value) for name, value in vars(self).items()])
        return '\n'.join(lines)
        return s
    
    def __repr__(self):
        return self.__str__()
    

class Obfuscation:

    def __init__(self, options, base_build_path, base_path):
        self.options = options
        self.options_str = '-'.join(self.options)
        self.build_path = os.path.join(base_build_path, self.options_str)
        self.original_path = '{}+{}'.format(base_path, self.options_str)
        self.report_path = os.path.join(self.build_path, 'report.json')
        self.cracked_path = os.path.join(self.build_path, 'bin_cracked')
        self.patched_path = os.path.join(self.build_path, 'bin_patched_cracked')
        self.log_path = os.path.join(self.build_path, 'log.txt')
        self.cmdline_path = os.path.join(self.build_path, 'cmdline.txt')
    
    def __str__(self):
        # s = """{}""".format()
        lines = ["\nObfuscation:"]
        lines.extend(["  {}: {}".format(name, value) for name, value in vars(self).items()])
        return '\n'.join(lines)
    
    def __repr__(self):
        return self.__str__()

analysis_values = ['tracer', 'taint']
Analysis = namedtuple('Analysis', 'sample_path ' + ' '.join(analysis_values))

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging information",
        action="store_true")
    parser.add_argument("-o", "--output",
        help="output path of the report, stdout by default",
        required=False)
    parser.add_argument("-i", "--input",
        help="message that will be supplied to stdin of the binary when run",
        required=False)
    parser.add_argument("--build-dir",
        help="directory used to store temporary files (/tmp by default)",
        required=False)
    parser.add_argument("--cmdline-input", type=str, required=False,
        help="path to json file containing cmdline arguments/required files. " \
             "The directory of the file is where the required files will be expected")
    parser.add_argument("-j", "--process-count", type=int)
    dbg_group = parser.add_mutually_exclusive_group()
    dbg_group.add_argument("--print-only", action="store_true",
        help="only create required tmp dirs and print the commands to run")
    dbg_group.add_argument("--analyze-dir", type=str,
        help="if supplied, don't create directories or run any commands, " +\
            "only read reports from existing directory and create consolidated report")
    parser.add_argument("--crack-function", type=str, required=True,
        help="name of the function that will be cracked to check for successful patching")
    parser.add_argument("input_dir", type=str)

    args = parser.parse_args(argv)

    # make sure directory ends with separator to allow globbing
    if args.input_dir[-1] != os.path.sep:
        args.input_dir += os.path.sep
    
    # parallel run by default
    if args.process_count is None:
        args.process_count = cpu_count()
    
    # set directory of cmdline as additional arg
    if args.cmdline_input:
        args.cmdline_dir = os.path.dirname(args.cmdline_input)
    
    return args

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
        print("  command: {}".format(cmd))
    return False


def setup_environment():
    global RUN_PATH
    mydir = os.path.dirname(os.path.abspath(__file__))
    RUN_PATH = os.path.join(mydir, 'run.py')
    return True

def get_samples(input_dir, build_dir, cmdline_input_path):
    input_files = glob(input_dir + '*')
    # get the base path of the different binaries
    # the files have the form binary_name+obfuscation1-obfuscation2-...
    base_files = set((f.rpartition('+')[0] for f in input_files))

    cmdline_input = {}
    if cmdline_input_path:
        with open(cmdline_input_path, 'r') as f:
            cmdline_input = json.load(f)
    samples = []
    # sanity check that a non-obfuscated binary exists for all inputs
    for base_file in base_files:
        none_path = '{}+none.0'.format(base_file)
        if not os.path.exists(none_path):
            print('[-] no non-obfuscated file found for base file\n  {}'.format(base_file))
            return False

        obfuscations = [ f.rpartition('+')[2].split('-') for f in input_files
            # get files that have the common base
            if (base_file + '+') in f]
        if cmdline_input:
            base_file_basename = os.path.basename(base_file)
            if base_file_basename not in cmdline_input:
                print('[-] file not present in cmdline input: {}'.format(base_file_basename))
                return False
            sample_cmd_info = cmdline_input[base_file_basename]
        else:
            sample_cmd_info = None
        samples.append(EvalSample(base_file, obfuscations, build_dir, sample_cmd_info))
    return samples

def run_obfuscation(obfuscation, cmd_info):
    # args has been made global in pool
    try:
        # create build dir for obfuscation
        os.mkdir(obfuscation.build_path)
        # create symlink for easier debugging
        os.symlink(os.path.abspath(obfuscation.original_path), os.path.join(obfuscation.build_path, 'bin'))

        # run the taint attack to patch and crack the binary
        input_arg = None if not args.input else ['--input', args.input]
        cmd = [ RUN_PATH,
            "--crack-function", args.crack_function,
            "--report-path", obfuscation.report_path,
            "-o", obfuscation.patched_path,
            "--crack-only-output", obfuscation.cracked_path,
            "--build-dir", obfuscation.build_path,
            "--taint-backend", "cpp",
            "--cleanup",
            '--use-input-working-dir',
            obfuscation.original_path
        ]
        if input_arg:
            cmd.extend(input_arg)
        
        # put required files into working directory and append commands
        # if --cmdline-input argument was supplied
        if cmd_info:
            # copy required files to tmp dir
            for req_file in cmd_info['required_files']:
                shutil.copy(os.path.join(args.cmdline_dir, req_file), obfuscation.build_path)
            if cmd_info['args']:
                cmd.append('--args')
                cmd.append(' '.join(cmd_info['args']))
            success_exit_code = cmd_info.get('success_exit_code', 0)
            cmd.append('--success-exit-code')
            cmd.append(str(success_exit_code))


        # store cmdline for easier debugging
        with open(obfuscation.cmdline_path, 'w') as f:
            f.write("{} > {}\n".format(' '.join(cmd), obfuscation.log_path))

        if args.verbose or args.print_only:
            print("running {} > {}".format(' '.join(cmd), obfuscation.log_path))
            if args.print_only:
                return True
        with open(obfuscation.log_path, 'w') as log:
            success = run_cmd(cmd, log)
            if not success:
                print('[-] error running cmd {}, see {} for output'.format(cmd, obfuscation.log_path))
                return False
        return True
    except KeyboardInterrupt:
        raise KeyboardInterruptError()
    return False

def run_sample(sample, pool):

    # create build dir for sample
    os.mkdir(sample.build_path)

    results = []
    # run each obfuscation in a process from the pool
    for obfuscation in sample.obfuscations:
        results.append(pool.apply_async(run_obfuscation, (obfuscation, sample.cmd_info)))
    return results

    
def get_sample_report(sample):
    reports = dict()
    for obfuscation in sample.obfuscations:
        try:
            with open(obfuscation.report_path, 'r') as f:
                reports[obfuscation.options_str] = json.load(f)
                reports[obfuscation.options_str]['build_path'] = obfuscation.build_path
        except KeyboardInterrupt:
            raise
        except:
            print("exception in get_sample_report. continuing regardless")
            continue
    

    return reports


def analyze_reports(args, reports):
    # dict{ obf_str => List{ Analysis } }
    result = dict()
    for sample, sample_report in reports:
        # sample_report: dict{ obf_str => dict(times) }
        ref_report = sample_report['none']
        for obf_str, report in sample_report.items():
            # report: dict{ exec_id => exec_time }
            if obf_str == 'none':
                continue

            analysis = {
                'sample_base'          : sample.base_path,
                'build_path'           : report.get('build_path'),
                'attack_result'        : report.get('attack_result'),
                'self_check_triggered' : report.get('self_check_triggered'),
            }
            for val in analysis_values:
                analysis[val + '_time'] = report.get(val)
                analysis[val + '_rel_overhead'] = report.get(val) / ref_report[val]
                analysis[val + '_abs_overhead'] = report.get(val) - ref_report[val]

            time_list = result.get(obf_str, list())
            time_list.append(analysis)
            result[obf_str] = time_list
    return result


def run(args, build_dir):

    print('[*] get_samples')
    samples = get_samples(args.input_dir, build_dir, args.cmdline_input)
    if not samples:
        print('[-] get_samples')
        return False
        
    if args.verbose:
        print('samples:')
        for sample in samples:
            pprint(sample)
    
    print('[*] run_samples (process count = {})'.format(args.process_count))
    results = []

    def child_init(_args):
        global args
        args = _args
    pool = Pool(processes=args.process_count, initializer=child_init, initargs=(args,))
    try:
        if not args.analyze_dir:
            results = []
            # get apply_async results from all of the obfuscations in all samples
            for sample in samples:
                results.extend(run_sample(sample, pool))
            pool.close()

            # make sure all of them executed
            for result in results:
                if not result.get(999999999):
                    print('[-] run_sample')
                    return False
        else:
            pool.close()

    except KeyboardInterrupt:
        pool.terminate()
        return False
    except Exception, e:
        traceback.print_exc()
        pool.terminate()
        return False
    finally:
        pool.join()

    if args.print_only:
        print('[*] print_only mode. exiting')
        return True

    reports = []
    for sample in samples:
        report = get_sample_report(sample)
        reports.append((sample, report))
        
    print('[*] analyze_reports')
    analysis = analyze_reports(args, reports)
    if not analysis:
        print('[-] analyze_reports')
        return False
    
    if args.output:
        if args.verbose:
            print('[*] creating report {}'.format(args.output))
        with open(args.output, 'w') as f:
            json.dump(analysis, f, indent=2)
    else:
        pprint(analysis)
    
    return True


def main(argv):
    args = parse_args(argv)
    if not setup_environment():
        return False

    # use a tmp directory if build dir is not specified
    # or use a previously created build dir if analyze_dir is specified
    build_dir  = (tempfile.mkdtemp() if args.build_dir is None else args.build_dir)\
        if args.analyze_dir is None else args.analyze_dir
    success = run(args, build_dir)

    print('[*] intermediate results: {}'.format(build_dir))
    print('[{}] Done, {}'.format(
        success and '+' or '-',
        success and 'success' or 'failed'))
    return True

if __name__ == '__main__':
    if main(os.sys.argv[1:]) is not True:
        exit(1)
