#!/usr/bin/env python3

"""creates evaluations of voglperf benchmark logs"""

from __future__ import print_function
import argparse
import os
import traceback
import tempfile
import shutil
import json
from glob import glob
from collections import namedtuple
from pprint import pformat, pprint
import matplotlib.pyplot as plt
import numpy as np
import numbers

games = {
    'sauerbraten': {
        'binary_name': 'sauer-client'
    },
    'crispy-doom': {
        'binary_name': 'crispy-doom'
    }
}

compare_sc_names = ['nocheck', 'targeted', 'full']

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging information",
        action="store_true")
    parser.add_argument("-o", "--output",
        help="output directory of the report",
        required=False)
    # parser.add_argument("--build-dir",
    #     help="directory used to store temporary files (/tmp by default)",
    #     required=False)
    parser.add_argument("-g", "--game", choices=['sauerbraten', 'crispy-doom'])
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


def get_samples(input_dir, game):
    if input_dir[-1] != os.sep:
        input_dir = input_dir + os.sep
    glob_arg = input_dir + 'voglperf.{}*.csv'.format(game['binary_name'])
    input_files = glob(glob_arg)

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
        if not obf_str in samples:
            samples[obf_str] = {
                'log_path': [],
                'binary_name': '{}+{}'.format(game['binary_name'], obf_str)
            }
        samples[obf_str]['log_path'].append(fpath)
        
    return samples


def compute_basic_numbers(sample_dict):
    for key in ('frame_times_len', 'average', 'maximum', 'minimum', 'median', 'average_99pctl', 'maximum_99pctl'):
        sample_dict[key] = []

    for fpath in sample_dict['log_path']:
        with open(fpath, 'r') as f:
            # discard first line (info string)
            f.readline()
            # all other lines are floats specifying the time it took for a frame
            # to execute
            frame_times = [float(s) for s in f.readlines()]
        
        frame_times.sort()
        sample_dict['frame_times_len'].append(len(frame_times))
        sample_dict['average'].append(sum(frame_times) / len(frame_times))
        sample_dict['maximum'].append(frame_times[-1])
        sample_dict['minimum'].append(frame_times[0])
        sample_dict['median'].append(frame_times[len(frame_times)//2])
        
        frame_times_99pctl_idx = int(len(frame_times) * 0.95)
        sample_dict['average_99pctl'].append(sum(frame_times[:frame_times_99pctl_idx]) / frame_times_99pctl_idx)
        sample_dict['maximum_99pctl'].append(frame_times[frame_times_99pctl_idx - 1])

def compute_comparison(sample_dict, base_sample):
    for measurement in ('average', 'maximum', 'minimum', 'median', 'average_99pctl', 'maximum_99pctl', 'binary_size'):
        new_measurement_key = measurement + '_relative'
        sample_dict[new_measurement_key] = []
        for sample_measurement in sample_dict[measurement]:
            sample_dict[new_measurement_key].append(sample_measurement / (sum(base_sample[measurement]) / len(base_sample[measurement])) - 1.0)

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
    # Dict{obfuscation_str: Dict{'path': path_to_csv}}

    # get basic numbers for each sample
    for obf_str, sample in samples.items():
        sample['binary_path'] = os.path.join(args.binary_dir, sample['binary_name'])
        stat = os.stat(sample['binary_path'])
        sample['binary_size'] = [float(stat.st_size)]
        compute_basic_numbers(sample)
    
    # old notation didn't have the 0 for no coverage so just patch it up here
    if 'none' in samples and 'none.0' not in samples:
        samples['none.0'] = samples['none']
        del samples['none']

    # compare it to the baseline of no obfuscation
    base_sample = samples['none.0']
    del samples['none.0']
    for obf_str, sample in samples.items():
        compute_comparison(sample, base_sample)
    
    # compute average of all measurement instances
    for sample in samples.values():
        for key, value in sample.items():
            if isinstance(value, list) and len(value) > 0 and isinstance(value[0], numbers.Number):
                sample[key] = sum(value) / len(value)

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
    figures = {}

    # how wide the bars should be. bar_width * len(coverages) should be less
    # than 1 to avoid overlapping
    bar_width = 0.15

    # the coverages and obfuscations to plot
    # coverages = ['0', '10', '20']
    # obfuscations = ['opaque', 'subst', 'indir', 'flatten']#, 'virt']
    coverages = set((obf_str.split('.')[1] for obf_str in samples))
    coverages = list(coverages)
    coverages.sort()
    obfuscations = set((obf_str.split('.')[0] for obf_str in samples))
    has_virt = 'virt' in obfuscations
    if 'virt' in obfuscations:
        obfuscations.remove('virt')
    
    obfuscations = list(obfuscations)
    obfuscations.sort()

    # map obfuscations to positions on the chart
    x_start_pos = np.arange(len(obfuscations))
    xticks = [r + bar_width for r in range(len(obfuscations))]
    xticks_virt = [r + bar_width for r in range(1)]

    # performance graphs
    for label_name, measurement in [('maximum 99pctl', 'maximum_99pctl_relative'),
        ('median', 'median_relative'), ('binary size', 'binary_size_relative'),
        ('real_median', 'median')]:
        fig = plt.figure()
        fig.suptitle('{} frame times'.format(label_name))
        ax = fig.add_subplot(121 if has_virt else 111,
            yscale='linear',
            xlabel='applied obfuscation',
            ylabel='relative overhead',
            xticks=xticks,
            xticklabels=obfuscations)
        # ax.set_xticks(, obfuscations)
        # ax.set_ylim(bottom=0)

        for i, coverage in enumerate(coverages):
            y = [samples[obf_str + '.' + coverage][measurement] for obf_str in obfuscations]
            ax.bar([x + (i * bar_width) for x in x_start_pos],
                y,
                width=bar_width,
                label='{}% coverage'.format(coverage))
                # label='{} {}%'.format(label_name, coverage))
        # fig.legend()
        # figures['performance_' + measurement] = fig

        if has_virt:
            ax = fig.add_subplot(122,
                xticks=xticks_virt,
                xticklabels=['virt'])
            for i, coverage in enumerate(coverages):
                y = [samples[obf_str + '.' + coverage][measurement] for obf_str in ['virt']]
                ax.bar([i* bar_width],
                    y,
                    width=bar_width,
                    )
                    # already created due to first graph
                    #label='{}% coverage'.format(coverage))
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


def run(args):

    print('[*] get_samples')
    game = games[args.game]
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
        samples = get_samples(args.input_dir, game)
    if not samples:
        print('[-] get_samples')
        return False
    
        
    if args.verbose:
        print('samples:')
        for sample in samples.items():
            print('{}\n'.format(sample))
        
    print('[*] analyze_samples')
    if args.compare_sc:    
        analysis = analyze_samples_sc_compare(args, samples)
    else:
        analysis = analyze_samples(args, samples)
    if not analysis:
        print('[-] analyze_samples')
        return False
    
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
