#!/usr/bin/env python
import time

from steps.extract_feature import get_feature_batch
from steps.repair_PE import repair_batch


def main(dir_dict: dict):
    for src_dir_path, dst_dir_path in dir_dict.items():
        repair_batch(src_dir_path, dst_dir_path)
        get_feature_batch([dst_dir_path])


if __name__ == "__main__":
    dir_dict = {r"E:\Workshop\AIIT\比赛\DataConf 2020\4初赛附加赛\tmp": r'./samples/data_'}
    main(dir_dict)

