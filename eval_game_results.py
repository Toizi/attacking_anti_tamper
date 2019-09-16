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

def compute_comparison(sample_dict, base_sample):
    for measurement in ('average', 'maximum', 'minimum', 'median', 'average_99pctl', 'maximum_99pctl', 'binary_size'):
        sample_dict[measurement + '_relative'] = sample_dict[measurement] / base_sample[measurement] - 1.0

def analyze_samples(args, samples):
    # Dict{obfuscation_str: Dict{'path': path_to_csv}}

    # get basic numbers for each sample
    for obf_str, sample in samples.items():
        sample['binary_path'] = os.path.join(args.binary_dir, sample['binary_name'])
        stat = os.stat(sample['binary_path'])
        sample['binary_size'] = float(stat.st_size)
        compute_basic_numbers(sample)
    
    # compare it to the baseline of no obfuscation
    base_sample = samples['none']
    for obf_str, sample in samples.items():
        compute_comparison(sample, base_sample)

    return True

def generate_graphs(args, samples):
    figures = {}

    # how wide the bars should be. bar_width * len(coverages) should be less
    # than 1 to avoid overlapping
    bar_width = 0.15

    # the coverages and obfuscations to plot
    coverages = ['0', '10', '20']
    obfuscations = ['opaque', 'subst', 'indir', 'flatten']#, 'virt']

    # map obfuscations to positions on the chart
    x_start_pos = np.arange(len(obfuscations))
    xticks = [r + bar_width for r in range(len(obfuscations))]
    xticks_virt = [r + bar_width for r in range(1)]

    # performance graphs
    for label_name, measurement in [('maximum 99pctl', 'maximum_99pctl_relative'),
        ('median', 'median_relative')]:
        fig = plt.figure()
        fig.suptitle('{} frame times'.format(label_name))
        ax = fig.add_subplot(111,
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

        # ax = fig.add_subplot(122,
        #     xticks=xticks_virt,
        #     xticklabels=['virt'])
        # for i, coverage in enumerate(coverages):
        #     y = [samples[obf_str + '.' + coverage][measurement] for obf_str in ['virt']]
        #     ax.bar([i* bar_width],
        #         y,
        #         width=bar_width,
        #         label='{} {}%'.format(label_name, coverage))
        fig.legend()
        figures['performance_virt_' + measurement] = fig

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

    print('[*] generate_graphs')
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
