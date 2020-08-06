#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/8/6 15:54
# @Author  : Baiyu
# @File    : extract_feature.py


import time

from modules import banner
from modules import argv
from modules import run
from modules import output

import sys
from utils.file_util import get_path_lastpart


def get_feature_batch(dir_path_list: list):
    for i, dir_path in enumerate(dir_path_list):
        start_time = time.perf_counter()
        if i == 0:
            if len(sys.argv) < 2:
                sys.argv.append(dir_path)
        else:
            sys.argv[1] = dir_path

        csv_name = f'{get_path_lastpart(dir_path)}.csv'
        start_task(csv_name=csv_name)

        # 记录运行整体耗时
        end_time = time.perf_counter()
        print(f'Counting [{dir_path}] elapsed {(end_time - start_time) // 60}m {(end_time - start_time) % 60:.2f}s')


def start_task(csv_name: str = 'output.csv'):
    argv.get()
    banner.get()
    csv = open(csv_name, 'w')
    csv.write("id,susp_entrop_ratio,susp_name_ratio,susp_code_size,imphash,n_exports,n_antidbg,n_antivm,n_susp_api,"
              "has_cfg,has_dep,has_aslr,has_seh,has_gs,has_tls,has_code_integrity,susp_dbg_ts,n_url,n_ip,has_manifest,has_version,"
              # "n_susp_strings,"
              "is_packed,"
              "has_certificate,"
              "susp_virustotal_ratio,n_yara_rules")
    try:
        run.get(sys.argv[1], csv)
    except Exception as e:
        print("Throw: ", str(e))
    finally:
        csv.close()
    output.get(csv_name)


