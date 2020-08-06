import os
import shutil
import time


def repair_batch(src_dir_path, dst_dir_path):
    """
    Repair PE files in directory
    :param src_dir_path:
    :param dst_dir_path:
    """
    # Check
    if not os.path.exists(dst_dir_path):
        os.makedirs(dst_dir_path)

    start_time = time.perf_counter()
    files = os.listdir(src_dir_path)
    black_num = 0
    for file_i, filename in enumerate(files):
        print(f"Handling {file_i}th: [{filename}]")

        src_file_path = os.path.join(src_dir_path, filename)
        dst_file_path = os.path.join(dst_dir_path, filename)
        repair(src_file_path, dst_file_path)

        black_num += 1
        print(black_num)

    # 记录运行整体耗时
    end_time = time.perf_counter()
    print(f'Repairing [{src_dir_path}] elapsed {(end_time - start_time) // 60}m {(end_time - start_time) % 60:.2f}s')


def repair(src_file_path, dst_file_path):
    # Read offset value in source PE
    with open(src_file_path, "rb") as file_pe_r:
        file_pe_r.seek(0x3c, 0)
        a_offset = file_pe_r.read(1)
        print(a_offset)
        file_pe_r.seek(0x3d, 0)
        b_offset = file_pe_r.read(1)
        print(b_offset)
        print(int.from_bytes(b_offset, 'little') * 256 + int.from_bytes(a_offset, 'little'))

    # Copy source PE to dest PE
    shutil.copyfile(src_file_path, dst_file_path)

    # Modify dest PE
    with open(dst_file_path, "rb+") as file_pe_w:
        file_pe_w.seek(0x0, 0)
        file_pe_w.write(b'\x4D')
        file_pe_w.seek(0x1, 0)
        file_pe_w.write(b'\x5A')

        file_pe_w.seek(int.from_bytes(b_offset, 'little') * 256 + int.from_bytes(a_offset, 'little'), 0)
        file_pe_w.write(b'\x50')
        file_pe_w.seek(int.from_bytes(b_offset, 'little') * 256 + int.from_bytes(a_offset, 'little') + 1, 0)
        file_pe_w.write(b'\x45')


if __name__ == '__main__':
    src_dir_path = r"E:\Workshop\AIIT\比赛\DataConf 2020\4初赛附加赛\tmp"
    dst_dir_path = r"E:\Workshop\AIIT\比赛\DataConf 2020\4初赛附加赛\tmp_dst"

    repair_batch(src_dir_path, dst_dir_path)
