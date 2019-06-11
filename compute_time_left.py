#!/usr/bin/env python3
import os
import re
import datetime
from subprocess import check_output

def main():
    try:
        tmp_dir = os.sys.argv[1]
    except:
        print("usage: {} tmp_dir".format(__file__))
        return 1
    
    instrace_path = os.path.join(tmp_dir, 'instrace_logs/instrace.log')
    log_path = os.path.join(tmp_dir, 'log.txt')

    ps_output = check_output(['ps', 'a']).decode().splitlines()
    for line in ps_output:
        if tmp_dir in line and __file__ not in line:
            match = re.match(r'\s*(\d+)', line)
            if not match:
                print('could not match pid in output of ps a')
            pid = int(match.group(1))
            break
    else:
        print('could not find process with tmp_dir in cmdline')
        return 1
    
    ps_etimes_output = check_output(['ps', '-o', 'etimes=', '-p', str(pid)]).decode()
    elapsed_time = int(ps_etimes_output)

    cur_log_data = check_output(['tail', log_path]).decode().splitlines()
    log_line = cur_log_data[-2]
    match = re.match(r'\[D\]\s*(\d+)', log_line)
    if not match:
        print('could not match instruction count in log file')
        return 1
    cur_instr_count = int(match.group(1))

    total_instr_count = int(os.path.getsize(instrace_path)/8)
    instr_done_rate = float(cur_instr_count)/total_instr_count
    # elapsed_time = instr_done_rate * total_time
    expected_time_left = int(elapsed_time / instr_done_rate)

    print('pid:                     {:15}'.format(pid))
    print('elapsed_time:            {:14}s'.format(elapsed_time))
    print('                         {: >15}'.format(str(datetime.timedelta(seconds=elapsed_time))))
    print('cur_instr_count:         {:15}'.format(cur_instr_count))
    print('total_instr_count:       {:15}'.format(total_instr_count))
    print('percentage done:         {:14.2f}%'.format(instr_done_rate * 100))
    print('expected time left:      {:14}s'.format(expected_time_left))
    print('')
    print('computed time remaining: {: >15}'.format(str(datetime.timedelta(seconds=expected_time_left))))

    return 0


if __name__ == '__main__':
    exit(main())