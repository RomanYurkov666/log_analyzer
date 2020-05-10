#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import gzip
from collections import Counter,defaultdict
from datetime import datetime
import logging
import argparse
import shutil
from time import time

logger = logging.getLogger('DefaultLogger')
logger_config = {}

def logger_setup(config_file):
    """logger initialization function.
    Args:
        config_file (dict): dict with parameters for logger.
    Returns:
        logger instance.
    """
    file = config_file.get('LOG_FILENAME')
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logging.basicConfig(filename=file, format='[%(asctime)s] %(levelname)s - %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    return logger


def parse_log(file):
    """function of parsing the specified nginx access log file.
    Args:
        file (str): parsing file path.
    Returns:
        data: tuple with ip,date,urls.
        summary_lines: count of lines in file
    """
    # line_format = re.compile(
    #     r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<dateandtime>\d{2}\/[a-zA-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2})\ .* (?P<url>[\"][http://].*/[\"])', re.IGNORECASE)
    line_format = re.compile(
       r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<dateandtime>\d{2}\/[a-zA-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2})\ .*(?!((GET|POST))).*(?P<uri> /.* )(HTTP\/1\.1\")')
    logger.info(f'starting to parse the file {file}')
    opener = gzip.open if file.endswith('.gz') else open
    with opener(file, 'r') as f:
        parsed_lines = 0
        summary_lines = 0
        for line in f:
            #print(line)
            summary_lines += 1
            data = re.findall(line_format, line)
            if data:
                parsed_lines += 1
                yield data, summary_lines, parsed_lines
    logger.info(f'file {file} parsing complete for {round(time() - start_time, 2)} seconds')

def analyze_parsed_log(log_parser,top):
    """function for analyzing parsed data.
    Args:
        log_parser (dict): dict with parsed data.
        top (int): number of most common values
    Returns:
        1) Top IPs by hits
        2) Top URLs by hits
        3) Total hits per month sorted by month
        4) Unique visits (by ip) per month sorted by month
        5) Top IPs barchart per month
    """
    ip_counter = Counter()
    url_counter = Counter()
    data_counter = Counter()
    ip = defaultdict(list)
    for data, summary_lines, parsed_lines in log_parser:
        for i in data:
            #print(i)
            dm = datetime.strptime(i[1], '%d/%b/%Y:%H:%M:%S').date().strftime('%b %Y')
            ip_counter[i[0]] += 1
            url_counter[i[4]] += 1
            data_counter[dm] += 1
            ip[dm].append(i[0])
    dropped = round((summary_lines - parsed_lines) / summary_lines * 100, 3)
    logger.info(f'Sum lines: {summary_lines} Pased lines: {parsed_lines} Dropped: {dropped}% \n')
    print(f'Top {top} IP Addresses by hits')
    for k,v in ip_counter.most_common(top):
        print('{k:<{k_width}}{between}{v:<{v_width}}'.format(
            k=k, k_width=len(k),
            between=' ' * (3 + (15 - len(k))),
            v=v, v_width=len(str(v)) ))
    print()
    print(f'Top {top} URLs by hits')
    for k,v in url_counter.most_common(top):
        print('{v:<{v_width}}{between}{k:<{k_width}}'.format(
            k=k, k_width=len(k),
            between=' ' * (3 + (5 - len(str(v)))),
            v=v, v_width=len(str(v))))
    print()
    for k,v in sorted(data_counter.items(), key = lambda pair: datetime.strptime(pair[0],'%b %Y').timestamp(), reverse = True):
        print(f'{k} hits count: {v}')
    print()
    for k,v in sorted(ip.items(), key = lambda pair: datetime.strptime(pair[0],'%b %Y').timestamp(), reverse = True):
        print(f'{k} unique visits: {len(set(v))}')
    print(f'Top {top} IPs by month')
    for k,v in ip.items():
        print(k)
        print('Total Hits      Ip Address       Graph')
        for i,j in Counter(ip[k]).most_common(top):
            print('{j:<{j_width}}    {i:>{i_width}}{between}{c:<{c_width}}'.format(
                j=j , j_width=len('Total hits'),
                i=i , i_width=len('IP Address'), between=' '*(3+(15-len(i))),
                c='#' * int((1+(collums / 2 ) * (round(j/(len(ip[k])),3)))), c_width=len('Graph') ))
    logger.info(f'file {args.file} analyze complete for {round(time() - start_time, 2)} seconds')


if __name__ == '__main__':
    start_time = time()
    parser = argparse.ArgumentParser(description='Input log file full path AND number of TOP')
    parser.add_argument(
        '--file',
        type=str,
        default='access.log',
        help='Input full log path'
    )
    parser.add_argument(
        '--top',
        type=int,
        default=10,
        help='Input number of top'
    )
    args = parser.parse_args()
    collums, rows = shutil.get_terminal_size((80, 20))
    logger = logger_setup(logger_config)
    try:
        log_parser = parse_log(file=args.file)
    except Exception as e:
        logger.exception(f"Exception occurred during program execution, reason: {e}")
    urls = analyze_parsed_log(log_parser,top=args.top)