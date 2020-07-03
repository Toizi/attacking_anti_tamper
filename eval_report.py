#!/usr/bin/env python3

"""creates graphs from the eval.py result json"""

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
import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
import numbers
import math
from typing import List, Dict, Any
# from adjustText import adjust_text

compare_sc_names = ['nocheck', 'targeted', 'full']

# disable warning about too many figures open
plt.rcParams.update({'figure.max_open_warning': 0})

def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging information",
        action="store_true")
    parser.add_argument("-o", "--output",
        help="output directory of the graphs",
        required=False)

    parser.add_argument("input_report", type=str)

    args = parser.parse_args(argv)

    # create input_eval directory if no output specified
    if not args.output:
        args.output = os.path.join(os.path.dirname(args.input_report), 'eval')
    
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

friendly_names = {
    'virt': 'virtualization',
    'flatten': 'control flow flattening',
    'opaque': 'opaque predicates',
    'indir': 'control flow indirection',
    'subst': 'instruction subsitution'
}
def get_friendly_config_name(name):
    """transforms a string that looks like obfuscation.coverage to something
    more friendly that can be read without knowing the notation"""
    if 'none.0' in name:
        return 'without obfuscation'
    
    obf_name, coverage = name.split('.')
    return 'checkers + {coverage}% of functions protected with {obf:s}'.format(
        coverage=coverage, obf=friendly_names[obf_name]
    )

def generate_graphs(args, report: Dict[str, List[Dict[str, Any]]], scale):
    """we want to generate a separate graph for each configuration
    (same obfuscation + coverage).
    x axis is size of trace, y axis is attack time, color is attack result
    additionally each x axis entry contains multiple coverages"""
    figures = {}

    success_color = '#03fc3d'
    failure_color = '#fc6f03'
    colors = [success_color, failure_color]
    cmap = mpl.colors.ListedColormap(colors)

    data_by_config = {
        'virt': {},
        'indir': {},
        'flatten': {},
        'opaque': {},
        'subst': {},
    }

    # create all of the figures grouped by configuration
    for config_name, config in report.items():
        legend_descriptions = ['success', 'failure']
        x = []
        y = []
        z = []
        c = []


        fig = plt.figure(num=f'{config_name}_{scale}', figsize=(20/2.54, 15/2.54))
        # fig.suptitle(get_friendly_config_name(config_name))
        ax = fig.add_subplot(111,
            xscale=scale,
            yscale=scale,
            xlabel='number of instructions',
            ylabel='attack time in seconds')

        # collect maximum trace size in case we have a failed tracer/taint
        # entry that we need to put somewhere
        max_trace_size = -1
        max_attack_time = -1
        min_attack_time = 2 ** 16
        timeout_value = None
        for result in config:
            trace_size = result.get('trace_size') or -1
            if trace_size > max_trace_size:
                max_trace_size = trace_size
            attack_time = (result.get('tracer_time', 0) + result.get('taint_time', 0)) - 1
            if attack_time > max_attack_time:
                max_attack_time = attack_time
            if attack_time < min_attack_time:
                min_attack_time = attack_time
            if result.get('timeout') is True:
                timeout_value = result.get('taint_time')

        ax.set_ylim(bottom=0.65 * min_attack_time, top=max_attack_time*1.4)

        for result in config:
            # print(result)
            # ispell is broken and does not even trigger any checkers
            if '/ispell.x/' in result['build_path']:
                continue

            if result['attack_result'] in ('tracer_failed', 'taint_failed'):
                # the failed entries are ones where we ran out of disk space
                # so we put these at the maximum number of instructions
                # with a close to zero (since log, 1) attack time
                x.append(max_trace_size)
                y.append(1 if scale == 'log' else 0)
                c.append('#404040')
            else:
                x.append(result['trace_size'] // 8)
                y.append(result['tracer_time'] + result['taint_time'])
                # z.append(result['checkers_patched'] / result['self_check_triggered'])
                c.append(colors.index(success_color) if result['attack_result'] == 'success'
                        else colors.index(failure_color))

        scatter = ax.scatter(x, y, c=c, cmap=cmap,
            alpha=0.5,
            edgecolors='black')
        
        obf_name, _, coverage = config_name.partition('.')
        if obf_name != 'none':
            data_by_config[obf_name][coverage] = (x, y, c)
        
        # put annotation that shows where the timeout threshold is
        handles = scatter.legend_elements()[0]
        if timeout_value:
            axhline = ax.axhline(y=timeout_value, linestyle='dashed', alpha=0.5)
            handles.append(axhline)
            legend_descriptions.append('timeout threshold')

        # if scale == 'linear' and 'none.0' in config_name:
        if 'none.0' in config_name:
            max_x = max(x)
            max_y = max(y)
            # plot a line from 0 to max to demonstrate that scaling appears to
            # be linear
            # handles.append(
            ax.plot([0, max_x, max_x * 1.3], [0, max_y, max_y * 1.3],
                    linestyle='dotted', color='gray', label='linear scaling')
                    # )
                    #[1])
            # legend_descriptions.append('linear scaling')


        ax.legend(handles=handles, labels=legend_descriptions)
        figures[f'{config_name}_{scale}'] = fig
    
    # create one figure for each config. each figure contains all 3 coverages
    # side by side
    # pprint(data_by_config)
    cov_styles = {
        '0': "o",
        '10': "X",
        '20': "D",
    }
    cov_colors = {
        '0': "black",
        '10': "blue",
        '20': "violet",
    }
    for config_name, coverages in data_by_config.items():
        fig = plt.figure(num=f'combined_{config_name}_{scale}', figsize=(20/2.54, 15/2.54))
        ax = fig.add_subplot(1, 1, 1,
            xscale=scale, yscale=scale,
            xlabel='number of instructions',
            ylabel='attack time in seconds')
            # title=f'{cov}%')
        for cov in ('0', '10', '20'):
            x, y, c = coverages[cov]
            scatter = ax.scatter(x, y, c=c, cmap=cmap,
                alpha=0.5,
                marker=cov_styles[cov],
                edgecolors=cov_colors[cov])
        figures[f'combined_{config_name}_{scale}'] = fig



    # create all non-virt obfuscations in one
    fig = plt.figure(num=f'combined_non-virt_{scale}', figsize=(20/2.54, 15/2.54))
    num_added = 0
    for config_name, config in report.items():
        if config_name not in ('indir.0', 'flatten.0', 'opaque.0', 'subst.0'):
            continue

        x = []
        y = []
        z = []
        c = []


        num_added += 1
        ax = fig.add_subplot(2, 2, num_added,
            xscale=scale,
            yscale=scale,
            xlabel='number of instructions' if num_added == 3 else None,
            ylabel='attack time in seconds' if num_added == 3 else None,
            title=friendly_names[config_name.partition('.')[0]])

        # collect maximum trace size in case we have a failed tracer/taint
        # entry that we need to put somewhere
        max_trace_size = -1
        max_attack_time = -1
        min_attack_time = 2 ** 16
        timeout_value = None
        for result in config:
            trace_size = result.get('trace_size') or -1
            if trace_size > max_trace_size:
                max_trace_size = trace_size
            attack_time = (result.get('tracer_time', 0) + result.get('taint_time', 0)) - 1
            if attack_time > max_attack_time:
                max_attack_time = attack_time
            if attack_time < min_attack_time:
                min_attack_time = attack_time
            if result.get('timeout') is True:
                timeout_value = result.get('taint_time')

        ax.set_ylim(bottom=0.65 * min_attack_time, top=max_attack_time*1.4)

        for result in config:
            # print(result)
            # ispell is broken and does not even trigger any checkers
            if '/ispell.x/' in result['build_path']:
                continue

            if result['attack_result'] in ('tracer_failed', 'taint_failed'):
                # the failed entries are ones where we ran out of disk space
                # so we put these at the maximum number of instructions
                # with a close to zero (since log, not 0 but 1) attack time
                x.append(max_trace_size)
                y.append(1 if scale == 'log' else 0)
                c.append('#404040')
            else:
                x.append(result['trace_size'] // 8)
                y.append(result['tracer_time'] + result['taint_time'])
                # z.append(result['checkers_patched'] / result['self_check_triggered'])
                c.append(colors.index(success_color) if result['attack_result'] == 'success'
                        else colors.index(failure_color))

        scatter = ax.scatter(x, y, c=c, cmap=cmap,
            alpha=0.5,
            edgecolors='black')
        
        # texts = []
        # # add the success rate in the middle
        # for i in range(len(z)):
        #     texts.append(ax.text(x[i], y[i], '{}'.format(z[i])))

        # adjust_text(texts, arrowprops={'arrowstyle': '->', 'color': 'red'})
        # fig.show()
        # put annotation that shows where the timeout threshold is
        handles = scatter.legend_elements()[0]
        if timeout_value:
            axhline = ax.axhline(y=timeout_value, linestyle='dashed', alpha=0.5)
            handles.append(axhline)

        if num_added == 3:
            ax.legend(handles=handles, labels=legend_descriptions)
    figures[f'combined_non-virt_{scale}'] = fig

    # group results by sample_name
    sample_names = defaultdict(list)
    for config_name, config in report.items():
        for result in config:
            sample_name = os.path.basename(result['sample_base'])
            sample_names[sample_name].append(result)

    # create all figures grouped by sample
    for sample_name, results in sample_names.items():
        if sample_name == 'ispell.x':
            continue

        x = []
        y = []
        z = []
        c = []

        fig = plt.figure(num=f'{sample_name}_{scale}', figsize=(20/2.54, 15/2.54))
        # fig.suptitle(sample_name)
        ax = fig.add_subplot(111,
            xscale=scale,
            yscale=scale,
            xlabel='number of instructions',
            ylabel='attack time in seconds')

        # collect maximum trace size in case we have a failed tracer/taint
        # entry that we need to put somewhere
        max_trace_size = -1
        max_attack_time = -1
        min_attack_time = 2 ** 16
        # whether the batch has a timeout
        timeout_value = None
        for result in results:
            trace_size = result.get('trace_size') or -1
            if trace_size > max_trace_size:
                max_trace_size = trace_size
            attack_time = (result.get('tracer_time', 0) + result.get('taint_time', 0)) - 1
            if attack_time > max_attack_time:
                max_attack_time = attack_time
            if attack_time < min_attack_time:
                min_attack_time = attack_time
            if result.get('timeout') is True:
                timeout_value = result.get('taint_time')

        ax.set_ylim(bottom=0.65 * min_attack_time, top=max_attack_time*1.4)

        for result in results:
            if result['attack_result'] in ('tracer_failed', 'taint_failed'):
                # the failed entries are ones where we ran out of disk space
                # so we put these at the maximum number of instructions
                # with a close to zero (since log, 1) attack time
                x.append(max_trace_size)
                y.append(1 if scale == 'log' else 0)
                c.append('#404040')
            else:
                x.append(result['trace_size'] // 8)
                y.append(result['tracer_time'] + result['taint_time'])
                # z.append(result['checkers_patched'] / result['self_check_triggered'])
                # c.append(success_color if result['attack_result'] == 'success' else failure_color)
                c.append(colors.index(success_color) if result['attack_result'] == 'success'
                    else colors.index(failure_color))


        scatter = ax.scatter(x, y, c=c, cmap=cmap,
            # s=mpl.rcParams['lines.markersize'] ** 3,
            alpha=0.5,
            # linewidth=5,
            edgecolors='black')

        # put annotation that shows where the timeout threshold is
        handles = scatter.legend_elements()[0]
        if timeout_value:
            axhline = ax.axhline(y=timeout_value, linestyle='dashed', alpha=0.5)
            handles.append(axhline)

        ax.legend(handles=handles, labels=legend_descriptions)
        figures[f'{sample_name}_{scale}'] = fig


    return figures


def run(args):

    with open(args.input_report, 'r') as f:
        report = json.load(f)

    print('[*] generate_graphs')
    graphs_log = generate_graphs(args, report, 'log')
    if not graphs_log:
        print('[-] generate_graphs(log)')
        return False

    graphs_linear = generate_graphs(args, report, 'linear')
    if not graphs_linear:
        print('[-] generate_graphs(linear)')
        return False
    
    graphs = {**graphs_log, **graphs_linear}
    
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
