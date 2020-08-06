#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/6/24 11:46
# @Author  : AIIT
# @File    : file_util.py
import os


def get_path_lastpart(path: str):
    """
    获取路径中最后一个部分。
    例如： "/a/b/c" -> "c"   "/a/b/c/"  -> "c"
    @param path:
    @return:
    """
    head, tail = os.path.split(path)
    if tail in [None, ""]:
        head, tail = os.path.split(head)
        return tail
    else:
        return tail


if __name__ == "__main__":
    print(get_path_lastpart(r"C:\a\b"))
    print(get_path_lastpart(r"C:\a\b\\"))
    print(get_path_lastpart("/a/b/c"))
    print(get_path_lastpart("/a/b/c/"))
