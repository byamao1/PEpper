#!/usr/bin/env python
import time

from modules import banner
from modules import argv
from modules import run
from modules import output

import sys


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
    output.get()


def main(dir_name_list: list):
    for i, dir_name in enumerate(dir_name_list):
        start_time = time.perf_counter()
        if i == 0 and len(sys.argv) < 2:
            sys.argv.append(f"./samples/{dir_name}")

        start_task(csv_name=f'{dir_name}.csv')

        # 记录运行整体耗时
        end_time = time.perf_counter()
        print(f'Counting [{dir_name}] elapsed {(end_time - start_time) // 60}m {(end_time - start_time) % 60:.2f}s')


if __name__ == "__main__":
    main(['data', 'data_'])
