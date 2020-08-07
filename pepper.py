#!/usr/bin/env python
import time

from steps.extract_feature import get_feature_batch

if __name__ == "__main__":
    get_feature_batch([r'./samples/black',
                       r'./samples/white'
                       ])
