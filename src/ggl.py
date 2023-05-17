#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2023 John Serock
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import csv
import os.path
import re
import sys
import tarfile
import tempfile
from binascii import crc32

class MemberHelper:
    FILETYPE_BIN         = "bin"
    FILETYPE_FW          = "fw"
    FILETYPE_HW_VERSION  = "hw_version"
    FILETYPE_PARAMCONFIG = "paramconfig"
    FILETYPE_PCFG        = "pcfg"

    def find(self, members):
        flags = re.A | re.I
        for m in members:
            match = re.match(self.pattern, m.name, flags)
            if match:
                return m
        raise Exception(self.filetype + " file not found")

class PcfgHelper(MemberHelper):
    def __init__(self):
        self.filetype = MemberHelper.FILETYPE_PCFG
        self.pattern = r"^pcfg\.\d{4,6}\.csv$"

class HwVersionHelper(MemberHelper):
    def __init__(self):
        self.filetype = MemberHelper.FILETYPE_HW_VERSION
        self.pattern = r"^hw_version\.txt$"

class BinaryMemberHelper(MemberHelper):
    def _crc(self, data):
        return crc32(data, self.crc_init)

    def _check_field(embedded, calculated):
        return "(good)" if embedded == calculated else "(not good)"

    def _to_uint(data):
        assert len(data) <= 7
        assert len(data) > 0
        return int.from_bytes(data, byteorder="little", signed=False)

    def _show_file_info(self, pathname):
        print("File:", os.path.basename(pathname))

    def _show_version(self):
        pass

    def _check_header_crc(self):
        header_crc_calculated = self._crc(self.header_bytes[0:28])
        print("\nCalculated Header CRC:", hex(header_crc_calculated))
        header_crc_embedded = BinaryMemberHelper._to_uint(self.header_bytes[28:32])
        print("Embedded Header CRC: ", hex(header_crc_embedded), BinaryMemberHelper._check_field(header_crc_embedded, header_crc_calculated))

    def _check_image_crc(self):
        image_crc_calculated = self._crc(self.image_bytes)
        print("\nCalculated Image CRC:", hex(image_crc_calculated))
        image_crc_embedded = BinaryMemberHelper._to_uint(self.header_bytes[12:16])
        print("Embedded Image CRC: ", hex(image_crc_embedded), BinaryMemberHelper._check_field(image_crc_embedded, image_crc_calculated))

    def _check_image_len(self):
        image_len_calculated = len(self.image_bytes)
        print("\nCalculated Image Length:", image_len_calculated)
        image_len_embedded = BinaryMemberHelper._to_uint(self.header_bytes[4:8])
        print("Embedded Image Length: ", image_len_embedded, BinaryMemberHelper._check_field(image_len_embedded, image_len_calculated))

    def check(self, pathname):
        with open(pathname, "rb") as f:
            self.header_bytes = f.read(32)
            self.image_bytes  = f.read()

        self._show_file_info(pathname)
        self._check_header_crc()
        self._check_image_crc()
        self._check_image_len()
        self._show_version()

class BinHelper(BinaryMemberHelper):
    def __init__(self):
        self.crc_init = 0
        self.filetype = MemberHelper.FILETYPE_BIN
        self.pattern  = r"^bin_upgrade[A-Z0-9_.]+$"

class FwHelper(BinaryMemberHelper):
    def __init__(self):
        self.crc_init = 0xffffffff
        self.filetype = MemberHelper.FILETYPE_FW
        self.pattern  = r"^fw_upgrade[A-Z0-9_.]+$"

class ParamConfigHelper(BinaryMemberHelper):
    def __init__(self):
        self.crc_init = 0
        self.filetype = MemberHelper.FILETYPE_PARAMCONFIG
        self.pattern  = r"^paramconfig[A-Z0-9_.]+$"

    def dump(self, pathname, pcfg_pathname):
        with open(pathname, "rb") as f:
            self.header_bytes = f.read(32)
            self.image_bytes  = f.read()

        with open(pcfg_pathname, newline="") as pcfg_file:
            reader = csv.reader(pcfg_file, delimiter=";")
            reader.__next__()
            print("Descriptor;Value")
            for param_fields in reader:
                descriptor = param_fields[0]
                length = int(param_fields[3])
                size = int(param_fields[4]) >> 3
                flash_offset = int(param_fields[5], 16)
                if length == 1:
                    if size == 1:
                        value = "%#04x" % BinaryMemberHelper._to_uint(self.image_bytes[flash_offset:flash_offset + size])
                    elif size == 2:
                        value = "%#06x" % BinaryMemberHelper._to_uint(self.image_bytes[flash_offset:flash_offset + size])
                    elif size == 4:
                        value = "%#010x" % BinaryMemberHelper._to_uint(self.image_bytes[flash_offset:flash_offset + size])
                    else:
                        raise "Bad field size"
                elif length == 7 and descriptor.endswith("_nid"):
                    value = "%#016x" % BinaryMemberHelper._to_uint(self.image_bytes[flash_offset:flash_offset + length])
                elif descriptor.endswith("_string") or descriptor.endswith("_hfid"):
                    value = '"' + self.image_bytes[flash_offset:flash_offset + length].decode(encoding="ascii").rstrip("\x00\x0a") + '"'
                else:
                    value = self.image_bytes[flash_offset:flash_offset + length].hex()
                print(descriptor, ";", value, sep="")

    def _show_version(self):
        print("\nParamConfig Version:", BinaryMemberHelper._to_uint(self.header_bytes[16:20]))

def _get_helper(filetype):
    if filetype == MemberHelper.FILETYPE_PARAMCONFIG:
        return ParamConfigHelper()
    elif filetype == MemberHelper.FILETYPE_BIN:
        return BinHelper()
    elif filetype == MemberHelper.FILETYPE_FW:
        return FwHelper()
    elif filetype == MemberHelper.FILETYPE_PCFG:
        return PcfgHelper()
    elif filetype == MemberHelper.FILETYPE_HW_VERSION:
        return HwVersionHelper()
    else:
        return None

def _check(args):
    with tarfile.open(name=args.ggl_file, mode="r") as ggl_file:
        members = ggl_file.getmembers()
        helper  = _get_helper(args.file_type)
        member  = helper.find(members)
        with tempfile.TemporaryDirectory() as tmpdir:
            ggl_file.extractall(path=tmpdir, members=[member])
            pathname = os.path.join(tmpdir, member.name)
            helper.check(pathname)

def _dump(args):
    with tarfile.open(name=args.ggl_file, mode="r") as ggl_file:
        members     = ggl_file.getmembers()
        helper      = _get_helper("paramconfig")
        member      = helper.find(members)
        pcfg_helper = _get_helper("pcfg")
        
        try:
            pcfg_member = pcfg_helper.find(members)
        except:
            pcfg_member = None

        with tempfile.TemporaryDirectory() as tmpdir:
            pathname     = os.path.join(tmpdir, member.name)
            extractables = [member]
            if pcfg_member == None:
                if args.pcfg == None:
                    raise Exception("No pcfg .csv file found")
                else:
                    pcfg_pathname = args.pcfg
            else:
                pcfg_pathname = os.path.join(tmpdir, pcfg_member.name)
                extractables.append(pcfg_member)

            ggl_file.extractall(path=tmpdir, members=extractables)
            helper.dump(pathname, pcfg_pathname)

def _overlay(args):
    #FIXME implement
    raise Exception("Not implemented yet")

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title="subcommands")
    parser_c = subparsers.add_parser("check", help="Check the CRCs of a file")
    parser_c.add_argument("file_type", choices=["bin", "fw", "paramconfig"], help="The type of file to check")
    parser_c.add_argument("ggl_file", help="The .ggl file to read")
    parser_c.set_defaults(func=_check);
    parser_d = subparsers.add_parser("dump", help="Dump the paramconfig to stdout")
    parser_d.add_argument("--pcfg", metavar="pcfg_file", help="Fallback pcfg .csv file")
    parser_d.add_argument("ggl_file", help="The .ggl file to read")
    parser_d.set_defaults(func=_dump);
    parser_o = subparsers.add_parser("overlay", help="Overlay some paramconfig values")
    parser_o.add_argument("--pcfg", metavar="pcfg_file", help="Fallback pcfg .csv file")
    parser_o.add_argument("csv_file", help="The paramconfig values to overlay")
    parser_o.add_argument("ggl_file", help="The .ggl file to read")
    parser_o.add_argument("out_ggl_file", help="The .ggl file to write")
    parser_o.set_defaults(func=_overlay);
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_usage()
    return 0

if __name__ == "__main__":
    sys.exit(main())
