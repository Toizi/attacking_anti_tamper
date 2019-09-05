#!/usr/bin/env python

"""creates evaluations of voglperf benchmark logs"""

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
from multiprocessing.pool import Pool
class KeyboardInterruptError(Exception): pass

class EvalSample:

    def __init__(self, base_path, obfuscations, build_dir):
        self.base_path = base_path
        self.original_path = '{}+none'.format(base_path)
        self.build_path = os.path.join(build_dir, os.path.basename(self.base_path))
        self.obfuscations = [ Obfuscation(obf, self.build_path, self.base_path) for obf in obfuscations ]
    
    def __str__(self):
        s = """base_path: {}\noriginal_path: {}\nobfuscations: {}""".format(
            self.base_path, self.original_path, self.obfuscations)
        return s
    

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
        s = pformat(self)
        return s
games = {
    'sauerbraten': {
        'binary_name': 'sauer-client'
    },
    'crispy-doom': {
        'binary_name': 'crispy-doom'
    }
}
analysis_values = ['execution', 'tracer', 'taint']
Analysis = namedtuple('Analysis', 'sample_path ' + ' '.join(analysis_values))

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging information",
        action="store_true")
    parser.add_argument("-o", "--output",
        help="output directory of the report",
        required=False)
    parser.add_argument("--build-dir",
        help="directory used to store temporary files (/tmp by default)",
        required=False)
    parser.add_argument("-g", "--game", choices=['sauerbraten', 'crispy-doom'])
    parser.add_argument("--binary-dir",
        help="directory where the binaries reside that were used to create the benchmarks",
        required=True)
    parser.add_argument("-j", "--process-count", type=int)
    parser.add_argument("input_dir", type=str)

    args = parser.parse_args(argv)

    # make sure directory ends with separator to allow globbing
    if args.input_dir[-1] != os.path.sep:
        args.input_dir += os.path.sep
    
    # parallel run by default
    if args.process_count is None:
        args.process_count = cpu_count()
    
    # create input_eval directory if no output specified
    if not args.output:
        args.output = os.path.abspath(args.input_dir) + '_eval'
    
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

def get_samples(input_dir, game):
    input_files = glob(input_dir + 'voglperf.{}*.csv'.format(game['binary_name']))

    samples = {}
    # original binary name is binary-name+obfuscation
    # but voglperf changes the + in the path to a -
    # the original path is still in the first line of each binary
    for fpath in input_files:
        with open(fpath, 'r') as f:
            l = f.readline()
        # example line: # Aug 20 09:59:38 - sauer_client+indir
        # get the right part after the +
        obf_str = l.rpartition('+')[2].strip()
        samples[obf_str] = {
            'log_path': fpath,
            'binary_name': '{}+{}'.format(game['binary_name'], obf_str)
        }
        
    return samples


def run_obfuscation(obfuscation):
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
            obfuscation.original_path
        ]
        if input_arg:
            cmd.extend(input_arg)

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
        results.append(pool.apply_async(run_obfuscation, (obfuscation,)))
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

def compute_basic_numbers(sample_dict):
    fpath = sample_dict['log_path']
    with open(fpath, 'r') as f:
        # discard first line (info string)
        f.readline()
        # all other lines are floats specifying the time it took for a frame
        # to execute
        frame_times = [float(s) for s in f.readlines()]
    
    frame_times.sort()
    sample_dict['average'] = sum(frame_times) / len(frame_times)
    sample_dict['maximum'] = frame_times[-1]
    sample_dict['minimum'] = frame_times[0]
    sample_dict['median'] = frame_times[len(frame_times)//2]
    
    frame_times_99pctl_idx = int(len(frame_times) * 0.99)
    sample_dict['average_99pctl'] = sum(frame_times[:frame_times_99pctl_idx]) / frame_times_99pctl_idx
    sample_dict['maximum_99pctl'] = frame_times[frame_times_99pctl_idx - 1]

def analyze_samples(args, samples):
    # Dict{obfuscation_str: Dict{'path': path_to_csv}}
    for obf_str, sample in samples.items():
        sample['binary_path'] = os.path.join(args.binary_dir, sample['binary_name'])
        stat = os.stat(sample['binary_path'])
        sample['binary_size'] = stat.st_size
        compute_basic_numbers(sample)

    return True


def run(args):

    print('[*] get_samples')
    game = games[args.game]
    samples = get_samples(args.input_dir, game)
    if not samples:
        print('[-] get_samples')
        return False
    
        
    if args.verbose:
        print('samples:')
        for sample in samples.items():
            print('{}\n'.format(sample))
    
        
    print('[*] analyze_samples')
    analysis = analyze_samples(args, samples)
    if not analysis:
        print('[-] analyze_samples')
        return False
    
    pprint(samples)
    
    # if args.output:
    #     if args.verbose:
    #         print('[*] creating report {}'.format(args.output))
    #     with open(args.output, 'w') as f:
    #         json.dump(analysis, f, indent=2)
    # else:
    #     pprint(analysis)
    
    return True


def main(argv):
    args = parse_args(argv)
    if not setup_environment():
        return False

    success = run(args)

    # print('[*] intermediate results: {}'.format(build_dir))
    print('[{}] Done, {}'.format(
        success and '+' or '-',
        success and 'success' or 'failed'))
    return True

if __name__ == '__main__':
    if main(os.sys.argv[1:]) is not True:
        exit(1)
