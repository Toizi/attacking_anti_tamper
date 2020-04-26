#!/usr/bin/env python3

"""creates graphs from self-checksumming/batch_benchmark_mibench.py results"""

from __future__ import print_function
import argparse
import os
import traceback
import tempfile
import shutil
import json
from glob import glob
from collections import namedtuple, defaultdict
from pprint import pformat, pprint
import matplotlib.pyplot as plt
import numpy as np
import numbers

compare_sc_names = ['nocheck', 'targeted', 'full']

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
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--compare-sc", action="store_true",
        help="set mode of evaluation to compare-sc. Expects different input directory structure")
    group.add_argument("--binary-dir",
        help="directory where the binaries reside that were used to create the benchmarks")

    parser.add_argument("input_dir", type=str)

    args = parser.parse_args(argv)

    # make sure directory ends with separator to allow globbing
    if args.input_dir[-1] != os.path.sep:
        args.input_dir += os.path.sep
    
    # create input_eval directory if no output specified
    if not args.output:
        args.output = os.path.abspath(args.input_dir) + '_eval'
    
    return args


def get_samples(input_dir):
    """
    returns dict of binary_names to dict of obfuscation str to dict of log_paths
    Dict{binary_name:
    Dict{obfuscation_str:
        Dict{log_paths: List()}
    }}
    """

    if input_dir[-1] != os.sep:
        input_dir = input_dir + os.sep
    glob_arg = input_dir + 'result_*'
    input_files = glob(glob_arg)

    samples = {}
    for fpath in input_files:
        # original binary name is result_{binary-name}+{obfuscation}_{iteration}
        log_name = os.path.basename(fpath)
        # get only the {obfuscation}_{iteration} part
        binary_name, _, obf_str = log_name.rpartition('+')
        # remove the _{iteration} part
        obf_str = obf_str.rpartition('_')[0]
        # remove the result_ from the binary name
        binary_name = binary_name.replace('result_', '', 1)

        # get dict holding info about binary_name
        if binary_name not in samples:
            samples[binary_name] = {}
        sample = samples[binary_name]
        # append logpath to it
        if not obf_str in sample:
            sample[obf_str] = {
                'log_paths': []
            }
        sample[obf_str]['log_paths'].append(fpath)
        
    return samples


def compute_basic_numbers(obf_info):
    for key in ('cputime', 'memory'):
        obf_info[key] = []

    for fpath in obf_info['log_paths']:
        with open(fpath, 'r') as f:
            log_result = json.load(f)
        
        obf_info['cputime'].append(log_result['cputime'])
        obf_info['memory'].append(log_result['memory'])


def compute_comparison(obf_info, base_sample):
    for measurement in ('cputime', 'memory', 'binary_size'):
        new_measurement_key = measurement + '_relative'
        obf_info[new_measurement_key] = []
        for sample_measurement in obf_info[measurement]:
            obf_info[new_measurement_key].append(sample_measurement / (sum(base_sample[measurement]) / len(base_sample[measurement])) - 1.0)


def analyze_samples_sc_compare(args, samples):
    # Dict{obfuscation_str: Dict{'path': path_to_csv}}

    # get basic numbers for each sample
    for checked_str, sample in samples.items():
        sample['binary_path'] = os.path.join(args.input_dir, checked_str, 'seed_1', sample['binary_name'])
        stat = os.stat(sample['binary_path'])
        sample['binary_size'] = [float(stat.st_size)]
        compute_basic_numbers(sample)
    
    # compare it to the baseline of no obfuscation
    base_sample = samples['nocheck']
    for sample in samples.values():
        compute_comparison(sample, base_sample)
    
    # compute average of all measurement instances
    for sample in samples.values():
        for key, value in sample.items():
            if isinstance(value, list) and len(value) > 0 and isinstance(value[0], numbers.Number):
                sample[key] = sum(value) / len(value)

    return True

def analyze_samples(args, samples):
    # Dict{binary_name:
    #   Dict{obfuscation_str:
    #       Dict{log_paths: List()}
    # }}

    for binary_name, binary_info in samples.items():
        # get basic numbers for each obf_info
        for obf_str, obf_info in binary_info.items():
            obf_info['binary_path'] = os.path.join(args.binary_dir, '{}+{}'.format(binary_name, obf_str))
            stat = os.stat(obf_info['binary_path'])
            obf_info['binary_size'] = [float(stat.st_size)]
            compute_basic_numbers(obf_info)
        
        # compare it to the baseline of no obfuscation
        base_info = binary_info['none.0']
        for obf_str, obf_info in binary_info.items():
            compute_comparison(obf_info, base_info)
        
        # compute average of all measurement instances
        for obf_info in binary_info.values():
            # iterate through all measurements and check if there are lists of items
            # that can be averaged
            for key, value in obf_info.items():
                if isinstance(value, list) and len(value) > 0 and isinstance(value[0], numbers.Number):
                    obf_info[key] = sum(value) / len(value)

    return True

def generate_graphs_sc_compare(args, samples):
    figures = {}

    # how wide the bars should be. bar_width * len(coverages) should be less
    # than 1 to avoid overlapping
    bar_width = 0.15

    # checked_types = set(samples.keys())
    # set them directly since the order should be right
    checked_types = ('nocheck', 'targeted', 'full')

    # map checked_types to positions on the chart
    x_start_pos = np.arange(len(checked_types))
    # xticks = [r + bar_width for r in range(len(checked_types))]

    # performance graphs
    for label_name, measurement in [('maximum 99pctl', 'maximum_99pctl_relative'),
        ('median', 'median_relative'), ('binary size', 'binary_size_relative'),
        ('median', 'median')]:
        fig = plt.figure()
        fig.suptitle('{} frame times'.format(label_name))
        ax = fig.add_subplot(111,
            yscale='linear',
            xlabel='applied self-checking type',
            ylabel='overhead',
            xticks=x_start_pos,
            xticklabels=checked_types)
        # ax.set_xticks(, checked_types)
        # ax.set_ylim(bottom=0)

        y = [samples[checked_type][measurement] for checked_type in checked_types]
        ax.bar([x for x in x_start_pos],
            y,
            width=bar_width)
            # label='{} {}%'.format(label_name, coverage))
        # fig.legend()
        # figures['performance_' + measurement] = fig

        fig.legend()
        figures['performance_' + measurement] = fig

    # # do virt on its own since the measurements are so much higher
    # for label_name, measurement in [('maximum 99pctl', 'maximum_99pctl_relative'),
    #     ('median', 'median_relative')]:
    #     fig = plt.figure()
    #     fig.suptitle('frame times overhead relative to no obfuscation')
    #     ax = fig.add_subplot(111)

    #     x = ['virt']
    #     for coverage in ('0', '10', '20'):
    #         y = [samples[obf_str + '.' + coverage][measurement] for obf_str in x]
    #         ax.bar(x, y, label='{} {}%'.format(label_name, coverage))
    #     fig.legend()
    #     figures['performance_virt_' + measurement] = fig

    return figures

def generate_graphs(args, samples):
    # Dict{binary_name:
    #   Dict{obfuscation_str:
    #       Dict{measurement_name: measurement_value}
    # }}
    """we want to generate a separate graph for each obfuscation.
    these graphs have the benchmark name on the x axis and the overhead on the y axis.
    additionally each x axis entry contains multiple coverages"""
    figures = {}

    # collect the different coverages by obfuscation
    coverages = defaultdict(set)
    for obf_info in samples.values():
        for obf_str in obf_info:
            base_obf, _, coverage = obf_str.partition('.')
            coverages[base_obf].add(int(coverage))
    
    # sort coverages and convert them to string
    for base_obf_str in coverages:
        # convert to list for sorting
        coverage = list(coverages[base_obf_str])
        coverage.sort()
        # convert back to string for labelling
        coverage = [str(c) for c in coverage]
        coverages[base_obf_str] = coverage

    # maybe add more than one measurement in the future
    measurement_str = 'cputime_relative'
    # each obfuscation is handled in its own graph
    for base_obf_str in coverages:
        # don't create graph for no protection relative to itself
        if base_obf_str == 'none' and '_relative' in measurement_str:
            continue
        obf_coverages = coverages[base_obf_str]

        fig = plt.figure()
        fig.suptitle('{} overhead'.format(base_obf_str))

        # how much space a single group (in this case a sample) should occupy
        group_width = 1.0
        margin = 0.01
        # how wide the bars should be.
        # bar_width * len(coverages) should be less than 1 to avoid overlapping
        # bar_width < 1.0/len(coverages)
        bar_width = (group_width - 0.1) / len(obf_coverages) # -0.1 to allow for margin
        # map sample names to positions on the chart
        xticks = [r * group_width for r in range(len(samples.keys()))]

        ax = fig.add_subplot(111,
            yscale='linear',
            ylabel='Overhead in percent',
            xticks=xticks)
        ax.set_xticklabels(samples.keys(), rotation=90)
    
        # go through all of the samples and collect the values for the coverages
        for i, sample_name in enumerate(samples):
            obf_info = samples[sample_name]
            x_start_pos = np.arange(len(obf_coverages))
            y = []
            for coverage in obf_coverages:
                obf_coverage_str = base_obf_str + '.' + coverage
                measurements = obf_info.get(obf_coverage_str)
                if not measurements:
                    print('[-] no measurements found for obfuscation {}, sample {}'.format(
                        obf_coverage_str, sample_name))
                    return False
                y.append(measurements[measurement_str])


            x = []
            start_pos = i - (group_width/2) + (bar_width/2)
            for j, _ in enumerate(x_start_pos):
                x.append(start_pos + j * bar_width)
            ax.bar(x, y,
                width=bar_width - margin,
                label='{}%'.format(sample_name))
        figures[base_obf_str] = fig

    return figures


def run(args):

    print('[*] get_samples')
    if args.compare_sc:
        samples = {}
        for name in compare_sc_names:
            name_input_dir = os.path.join(args.input_dir, name, 'benchmarks/seed_1')
            # we only expect a single value to come out of this
            sample = get_samples(name_input_dir, game)
            if not sample:
                print('[-] get_samples')
                return False
            samples[name] = sample['none.0']
    else:
        samples = get_samples(args.input_dir)
    if not samples:
        print('[-] get_samples')
        return False
    
        
    if args.verbose:
        print('samples:')
        for sample in samples.items():
            pprint(sample)
        
    print('[*] analyze_samples')
    if args.compare_sc:    
        analysis = analyze_samples_sc_compare(args, samples)
    else:
        analysis = analyze_samples(args, samples)
    if not analysis:
        print('[-] analyze_samples')
        return False

    if args.verbose:
        print('samples:')
        for sample in samples.items():
            pprint(sample)
    
    print('[*] generate_graphs')
    if args.compare_sc:
        graphs = generate_graphs_sc_compare(args, samples)
    else:
        graphs = generate_graphs(args, samples)
    if not graphs:
        print('[-] generate_graphs')
        return False
    
    if not os.path.exists(args.output):
        os.mkdir(args.output)
    print('[*] saving figures at {:s}'.format(args.output))
    for name, figure in graphs.items():
        figure_path = os.path.join(args.output, name + '.pdf')
        if args.verbose:
            print('[*] creating figure {}'.format(figure_path))
        figure.savefig(figure_path)
    
    return True


def main(argv):
    args = parse_args(argv)
    success = run(args)

    # print('[*] intermediate results: {}'.format(build_dir))
    print('[{}] Done, {}'.format(
        success and '+' or '-',
        success and 'success' or 'failed'))
    return True

if __name__ == '__main__':
    if main(os.sys.argv[1:]) is not True:
        exit(1)
