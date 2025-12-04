#!/usr/bin/env python3
import os
import sys
import struct
import traceback
import shutil
import re
import mmap
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor
import ext4
import string
import time
EXT4_HEADER_MAGIC = 0xED26FF3A
EXT4_SPARSE_HEADER_LEN = 28
EXT4_CHUNK_HEADER_SIZE = 12


class ext4_file_header(object):
    def __init__(self, buf):
        (self.magic,
         self.major,
         self.minor,
         self.file_header_size,
         self.chunk_header_size,
         self.block_size,
         self.total_blocks,
         self.total_chunks,
         self.crc32) = struct.unpack('<I4H4I', buf)


class ext4_chunk_header(object):
    def __init__(self, buf):
        (self.type,
         self.reserved,
         self.chunk_size,
         self.total_size) = struct.unpack('<2H2I', buf)


class Extractor(object):
    def __init__(self):
        self.FileName = ""
        self.BASE_DIR = ""
        self.OUTPUT_IMAGE_FILE = ""
        self.EXTRACT_DIR = ""
        self.BLOCK_SIZE = 4096
        self.context = []
        self.fsconfig = []
        self.extraction_tasks = []

    def add_context(self, path, con, is_dir):
        safe = path
        for c in "\\^$.|?*+(){}[]":
            safe = safe.replace(c, '\\' + c)
        if is_dir:
            self.context.append(f'/{safe} {con}')
            self.context.append(f'/{safe}(/.*)? {con}')
        else:
            self.context.append(f'/{safe} {con}')

    def __remove(self, path):
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
        else:
            raise ValueError("file {} is not a file or dir.".format(path))

    def __logtb(self, ex, ex_traceback=None):
        if ex_traceback is None:
            ex_traceback = ex.__traceback__
        tb_lines = [line.rstrip('\n') for line in
                    traceback.format_exception(ex.__class__, ex, ex_traceback)]
        return '\n'.join(tb_lines)

    def __file_name(self, file_path):
        name = os.path.basename(file_path).rsplit('.', 1)[0]
        return name

    def __appendf(self, msg, log_file):
        if not os.path.isfile(log_file):
            open(log_file, 'tw', encoding='utf-8').close()
        with open(log_file, 'a', newline='\n') as file:
            print(msg, file=file)

    def __getperm(self, arg):
        if len(arg) < 9 or len(arg) > 10:
            return
        if len(arg) > 8:
            arg = arg[1:]
        oor, ow, ox, gr, gw, gx, wr, ww, wx = list(arg)
        o, g, w, s = 0, 0, 0, 0
        if oor == 'r': o += 4
        if ow == 'w': o += 2
        if ox == 'x': o += 1
        if ox == 'S': s += 4
        if ox == 's': s += 4; o += 1
        if gr == 'r': g += 4
        if gw == 'w': g += 2
        if gx == 'x': g += 1
        if gx == 'S': s += 2
        if gx == 's': s += 2; g += 1
        if wr == 'r': w += 4
        if ww == 'w': w += 2
        if wx == 'x': w += 1
        if wx == 'T': s += 1
        if wx == 't': s += 1; w += 1
        return str(s) + str(o) + str(g) + str(w)
                
    def scan_and_collect(self, root_inode, root_path=""):
        fuking_symbols = "\\^$.|?*+(){}[]"
        for entry_name, entry_inode_idx, entry_type in root_inode.open_dir():
            if (
                entry_name in ['.', '..']
                or entry_name.endswith(" (2)")
                or entry_name == "lost+found"
                ):
                continue

            entry_inode = root_inode.volume.get_inode(entry_inode_idx, entry_type)
            entry_inode_path = root_path + '/' + entry_name

            mode = self.__getperm(entry_inode.mode_str)
            uid = entry_inode.inode.i_uid
            gid = entry_inode.inode.i_gid

            con = ''
            cap = ''

            for xattr_key, xattr_val in entry_inode.xattrs():
                if xattr_key == "security.selinux":
                    con = xattr_val.decode("utf-8")[:-1]
                elif xattr_key == "security.capability":
                    raw = struct.unpack("<5I", xattr_val)
                    if raw[1] > 65535:
                        hexv = hex(int("%04x%04x" % (raw[3], raw[1]), 16))
                    else:
                        hexv = hex(int("%04x%04x%04x" % (raw[3], raw[2], raw[1]), 16))
                    cap = " capabilities=%s" % hexv

            tmppath=self.FileName + entry_inode_path
            if (tmppath).find(' ',1,len(tmppath))>0:
                self.__appendf(tmppath, spaces_file)
                tmppath=tmppath.replace(' ', '_')

            if entry_inode.is_dir:
                target = self.EXTRACT_DIR + entry_inode_path.replace(" ", "_")
                if not os.path.isdir(target):
                    os.makedirs(target)

                if os.name == "posix":
                    os.chmod(target, int(mode, 8))
                    try:
                        os.chown(target, uid, gid)
                    except PermissionError:
                        pass

                if cap:
                    self.fsconfig.append("%s %s %s %s%s" % (tmppath, uid, gid, mode, cap))
                else:
                    self.fsconfig.append("%s %s %s %s" % (tmppath, uid, gid, mode))

                if con:
                    self.add_context(tmppath, con, True)

                self.scan_and_collect(entry_inode, entry_inode_path)
                continue

            if entry_inode.is_file:
                self.extraction_tasks.append((entry_inode_path, entry_inode_idx, entry_type, uid, gid, mode))

                if cap:
                    self.fsconfig.append("%s %s %s %s%s" % (tmppath, uid, gid, mode, cap))
                else:
                    self.fsconfig.append("%s %s %s %s" % (tmppath, uid, gid, mode))

                if con:
                    self.add_context(tmppath, con, False)
                continue

            if entry_inode.is_symlink:
                try:
                    link_target = entry_inode.open_read().read().decode("utf8")
                except PermissionError:
                    continue  # Skip invalid symlinks

                target = self.EXTRACT_DIR + entry_inode_path.replace(" ", "_")
                if os.path.islink(target) or os.path.exists(target):
                    try:
                        os.remove(target)
                    except PermissionError:
                        pass

                if os.name == 'posix':
                    os.symlink(link_target, target)
                elif os.name == 'nt':
                    with open(target.replace('/', os.sep), 'wb') as out:
                        tmp = bytes.fromhex('213C73796D6C696E6B3EFFFE')
                        for index in list(link_target):
                            tmp = tmp + struct.pack('>sx', index.encode('utf-8'))
                        out.write(tmp + struct.pack('xx'))
                    os.system(f'attrib +s "{target.replace("/", os.sep)}"')

                if cap:
                    self.fsconfig.append("%s %s %s %s%s %s" % (tmppath, uid, gid, mode, cap, link_target))
                else:
                    self.fsconfig.append("%s %s %s %s %s" % (tmppath, uid, gid, mode, link_target))

                if con:
                    self.add_context(tmppath, con, False)

                # Still collect for parallel (though creation is simple, for consistency)
                self.extraction_tasks.append((entry_inode_path, entry_inode_idx, entry_type, uid, gid, mode))
                continue

    @staticmethod
    def extract_worker(extract_dir, image_file, tasks):
        try:
            with open(image_file, 'rb') as f:
                volume = ext4.Volume(f)
                for entry_path, inode_idx, entry_type, uid, gid, mode in tasks:
                    try:
                        inode = volume.get_inode(inode_idx, entry_type)
                        clean_path = entry_path.replace(' ', '_')
                        target_path = os.path.join(extract_dir, clean_path.lstrip('/'))

                        if inode.is_file:
                            os.makedirs(os.path.dirname(target_path), exist_ok=True)
                            raw = inode.open_read().read()
                            with open(target_path, 'wb') as out:
                                out.write(raw)
                            if os.name == 'posix':
                                os.chmod(target_path, int(mode, 8))
                                try:
                                    os.chown(target_path, uid, gid)
                                except:
                                    pass

                        elif inode.is_symlink:
                            link_target = inode.open_read().read().decode('utf-8')
                            os.makedirs(os.path.dirname(target_path), exist_ok=True)
                            if os.path.islink(target_path) or os.path.exists(target_path):
                                try:
                                    os.remove(target_path)
                                except:
                                    pass
                            if os.name == 'posix':
                                os.symlink(link_target, target_path)
                            elif os.name == 'nt':
                                with open(target_path.replace('/', os.sep), 'wb') as out:
                                    tmp = bytes.fromhex('213C73796D6C696E6B3EFFFE')
                                    for index in list(link_target):
                                        tmp = tmp + struct.pack('>sx', index.encode('utf-8'))
                                    out.write(tmp + struct.pack('xx'))
                                os.system(f'attrib +s "{target_path.replace("/", os.sep)}"')

                    except:
                        pass
        except:
            pass


    def __ext4extractor(self):
        config_dir = os.path.dirname(self.EXTRACT_DIR) + os.sep + "config" + os.sep
        if not os.path.isdir(config_dir):
            os.makedirs(config_dir)
        fs_config_file = config_dir + self.FileName + "_fs_config"
        contexts = config_dir + self.FileName + "_file_contexts"
        size = config_dir + self.FileName + "_size.txt"
        name = config_dir + self.FileName + "_name.txt"
        spaces_file = config_dir  + self.FileName + "_space.txt"

        self.__appendf(os.path.getsize(self.OUTPUT_IMAGE_FILE), size)
        self.__appendf(os.path.basename(self.OUTPUT_IMAGE_FILE).rsplit('.', 1)[0], name)
        def dedupe_keep_order(seq):
            seen = set()
            out = []
            for x in seq:
                if x not in seen:
                    seen.add(x)
                    out.append(x)
            return out
        print("🔍 Scanning filesystem (single-threaded metadata)...")

        with open(self.OUTPUT_IMAGE_FILE, 'rb') as file:
            root = ext4.Volume(file).root
            self.scan_and_collect(root)
        if hasattr(self, 'USER_THREADS') and self.USER_THREADS:
            num_workers = max(1, int(self.USER_THREADS))
        else:
            num_workers = min(mp.cpu_count(), 8)
        print("🚀 Parallel extraction using Threads : ", num_workers)
        batch_size = max(1, len(self.extraction_tasks) // num_workers)
        batches = [self.extraction_tasks[i:i + batch_size] for i in range(0, len(self.extraction_tasks), batch_size)]
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(self.extract_worker,self.EXTRACT_DIR,self.OUTPUT_IMAGE_FILE,batch)for batch in batches]
            for future in futures:
                future.result()
        self.fsconfig = dedupe_keep_order(self.fsconfig)
        self.context = dedupe_keep_order(self.context)

        print("💾 Writing configs...")
        root_line = "/ 0 0 0755"
        partition_line = self.FileName + " 0 0 0755"
        final_fs = [root_line, partition_line]
        for line in sorted(self.fsconfig):
            if line not in final_fs:
                final_fs.append(line)
        self.__appendf("\n".join(final_fs), fs_config_file)
        self.fsconfig.sort()

        self.__appendf('\n'.join(self.context), contexts)
        self.context.sort()

    def __converSimgToImg(self, target):
        with open(target, "rb") as img_file:
            if hasattr(self, 'sign_offset') and self.sign_offset > 0:
                img_file.seek(self.sign_offset, 0)
            header = ext4_file_header(img_file.read(28))
            total_chunks = header.total_chunks
            if header.file_header_size > EXT4_SPARSE_HEADER_LEN:
                img_file.seek(header.file_header_size - EXT4_SPARSE_HEADER_LEN, 1)

            raw_img_path = target.rsplit('.', 1)[0] + ".raw.img"
            with open(raw_img_path, "wb") as raw_img_file:
                sector_base = 82528
                while total_chunks > 0:
                    chunk_header = ext4_chunk_header(img_file.read(EXT4_CHUNK_HEADER_SIZE))
                    sector_size = (chunk_header.chunk_size * header.block_size) >> 9
                    chunk_data_size = chunk_header.total_size - header.chunk_header_size
                    if chunk_header.type == 0xCAC1:  # RAW
                        if header.chunk_header_size > EXT4_CHUNK_HEADER_SIZE:
                            img_file.seek(header.chunk_header_size - EXT4_CHUNK_HEADER_SIZE, 1)
                        data = img_file.read(chunk_data_size)
                        raw_img_file.write(data)
                    else:
                        raw_img_file.write(b'\0' * (sector_size << 9))
                    total_chunks -= 1
        os.remove(target)
        os.rename(raw_img_path, target)
        self.OUTPUT_IMAGE_FILE = target

    def checkSignOffset(self, file):
        size = os.stat(file.name).st_size
        if size <= 52428800:
            mm = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
        else:
            mm = mmap.mmap(file.fileno(), 52428800, access=mmap.ACCESS_READ)
        offset = mm.find(struct.pack('<L', EXT4_HEADER_MAGIC))
        mm.close()
        return offset

    def __getTypeTarget(self, target):
        with open(target, "rb") as img_file:
            self.sign_offset = self.checkSignOffset(img_file)
            if self.sign_offset > 0:
                img_file.seek(self.sign_offset, 0)
            header = ext4_file_header(img_file.read(28))
            return 'simg' if header.magic == EXT4_HEADER_MAGIC else 'img'

    def main(self, target, output_dir):
        self.BASE_DIR = os.path.realpath(os.path.dirname(target)) + os.sep
        self.OUTPUT_IMAGE_FILE = os.path.join(self.BASE_DIR, os.path.basename(target))
        self.FileName = self.__file_name(os.path.basename(target))

        output_base = os.path.realpath(output_dir)
        self.EXTRACT_DIR = os.path.join(output_base, self.FileName)

        os.makedirs(self.EXTRACT_DIR, exist_ok=True)

        start = time.time()
        target_type = self.__getTypeTarget(target)
        if target_type == 'simg':
            self.__converSimgToImg(target)
        self.__ext4extractor()
        end = time.time()          # end time
        elapsed = end - start      # seconds as float
        print(f"⏱ Time taken: {elapsed:.3f} seconds")

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Ext4 image extractor with multiprocessing")

    parser.add_argument(
        "-i", "--input",
        required=False,
        help="Path to input ext4 image"
    )

    parser.add_argument(
        "-o", "--output",
        required=False,
        help="Output directory for extraction"
    )

    parser.add_argument(
        "-T", "--threads",
        required=False,
        type=int,
        default=None,
        help="Number of parallel workers (default: auto)"
    )

    # For backward compatibility, allow old syntax: imgextractor.py input.img outdir
    args, leftovers = parser.parse_known_args()

    if args.input is None and len(leftovers) >= 1:
        args.input = leftovers[0]

    if args.output is None and len(leftovers) >= 2:
        args.output = leftovers[1]

    if not args.input:
        print("❌ Error: No input image provided.")
        print("Use: python imgextractor.py -i system.img -o out_dir [-T 8]")
        sys.exit(1)

    Extractor.USER_THREADS = args.threads

    outdir = args.output if args.output else (
        os.path.realpath(os.path.dirname(args.input)) + os.sep + os.path.basename(args.input)
    )

    Extractor().main(args.input, outdir)
