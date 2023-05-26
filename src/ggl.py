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

class GglDialect(csv.Dialect):
    delimiter = ";"
    quotechar = '"'
    escapechar = None
    doublequote = True
    skipinitialspace = False
    lineterminator = "\n"
    quoting = csv.QUOTE_MINIMAL

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
        raise IOError(self.filetype + " file not found")

class PcfgHelper(MemberHelper):
    def __init__(self):
        self.filetype = MemberHelper.FILETYPE_PCFG
        self.pattern = r"^pcfg\.[a-z0-9_]{4,}\.csv$"

class HwVersionHelper(MemberHelper):
    def __init__(self):
        self.filetype = MemberHelper.FILETYPE_HW_VERSION
        self.pattern = r"^hw_version\.txt$"

class BinaryMemberHelper(MemberHelper):
    def _crc_header(self):
        return crc32(self.header_bytes[0:28], self.crc_init)

    def _crc_image(self):
        return crc32(self.image_bytes, self.crc_init)

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
        header_crc_calculated = self._crc_header()
        print("\nCalculated Header CRC:", hex(header_crc_calculated))
        header_crc_embedded = BinaryMemberHelper._to_uint(self.header_bytes[28:32])
        print("Embedded Header CRC: ", hex(header_crc_embedded), BinaryMemberHelper._check_field(header_crc_embedded, header_crc_calculated))

    def _check_image_crc(self):
        image_crc_calculated = self._crc_image()
        print("\nCalculated Image CRC:", hex(image_crc_calculated))
        image_crc_embedded = BinaryMemberHelper._to_uint(self.header_bytes[12:16])
        print("Embedded Image CRC: ", hex(image_crc_embedded), BinaryMemberHelper._check_field(image_crc_embedded, image_crc_calculated))

    def _check_image_len(self):
        image_len_calculated = len(self.image_bytes)
        print("\nCalculated Image Length:", image_len_calculated)
        image_len_embedded = BinaryMemberHelper._to_uint(self.header_bytes[4:8])
        print("Embedded Image Length: ", image_len_embedded, BinaryMemberHelper._check_field(image_len_embedded, image_len_calculated))

    def _read_binary_file(self, pathname):
        with open(pathname, mode="rb") as f:
            self.header_bytes = f.read(32)
            self.image_bytes  = f.read()

    def check(self, pathname):
        self._read_binary_file(pathname)
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

class PcfgItem:
    def __init__(self):
        self.descriptor   = None
        self.index        = None
        self.length       = None
        self.size         = None
        self.flash_offset = None
        self.value        = None

class ParamConfigHelper(BinaryMemberHelper):
    def __init__(self):
        self.crc_init = 0
        self.filetype = MemberHelper.FILETYPE_PARAMCONFIG
        self.pattern  = r"^paramconfig[A-Z0-9_.]+$"

    def _read_pcfg(self, pcfg_pathname):
        self.pcfg = []
        with open(pcfg_pathname, mode="rt", newline="") as f:
            reader = csv.DictReader(f, dialect="ggl")
            field_names = reader.fieldnames
            for row in reader:
                item = PcfgItem()
                item.descriptor   = row[field_names[0]]
                item.index        = int(row[field_names[2]])
                item.length       = int(row[field_names[3]])
                item.numBytes     = int(row[field_names[4]]) >> 3
                item.flash_offset = int(row[field_names[5]], 16)
                self.pcfg.append(item)

    def _read_overlay(self, overlay_pathname):
        self.overlay = {}
        with open(overlay_pathname, mode="rt", newline="") as f:
            reader = csv.DictReader(f, dialect="ggl")
            field_names = reader.fieldnames
            for row in reader:
                self.overlay[row[field_names[0]]] = row[field_names[1]]

    def _dump(self, field_names, writer):
        writer.writeheader()
        for item in self.pcfg:
            if item.length == 1:
                if item.numBytes == 1:
                    value = "{:#04x}".format(BinaryMemberHelper._to_uint(self.image_bytes[item.flash_offset:item.flash_offset + item.numBytes]))
                elif item.numBytes == 2:
                    value = "{:#06x}".format(BinaryMemberHelper._to_uint(self.image_bytes[item.flash_offset:item.flash_offset + item.numBytes]))
                elif item.numBytes == 4:
                    value = "{:#010x}".format(BinaryMemberHelper._to_uint(self.image_bytes[item.flash_offset:item.flash_offset + item.numBytes]))
                else:
                    raise ValueError("Bad " + item.descriptor + " size: " + item.numBytes + " bytes")
            elif item.length == 7 and item.descriptor.endswith("_nid"):
                value = "{:#016x}".format(BinaryMemberHelper._to_uint(self.image_bytes[item.flash_offset:item.flash_offset + item.length]))
            elif item.descriptor.endswith("_hfid"):
                value = self.image_bytes[item.flash_offset:item.flash_offset + item.length].decode(encoding="ascii").rstrip("\x00\x0a")
            else:
                value = self.image_bytes[item.flash_offset:item.flash_offset + item.length].hex()
            row = {field_names[0]: item.descriptor, field_names[1]: value}
            writer.writerow(row)

    def dump(self, paramconfig_pathname, pcfg_pathname, out_pathname):
        self._read_binary_file(paramconfig_pathname)
        self._read_pcfg(pcfg_pathname)
        field_names = ["Descriptor", "Value"]
        if out_pathname == None:
            writer = csv.DictWriter(sys.stdout, fieldnames=field_names, restval=" ", extrasaction="ignore", dialect="ggl")
            self._dump(field_names, writer)
        else:
            with open(out_pathname, mode="wt", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=field_names, restval=" ", extrasaction="ignore", dialect="ggl")
                self._dump(field_names, writer)

    def overlay(self, paramconfig_pathname, pcfg_pathname, overlay_pathname):
        self._read_binary_file(paramconfig_pathname)
        self._read_pcfg(pcfg_pathname)
        self._read_overlay(overlay_pathname)
        self.image_bytes = bytearray(self.image_bytes)
        for item in self.pcfg:
            if item.descriptor not in self.overlay:
                continue
            if item.descriptor.endswith("_nid") or item.descriptor.endswith("_nmk") or item.descriptor.startswith("plconfig_manufacturer_dak"):
                raise RuntimeError(item.descriptor + " overlay not allowed")
            value = self.overlay[item.descriptor]
            if item.length == 1:
                if item.numBytes == 1 or item.numBytes == 2 or item.numBytes == 4:
                    value_bytes = int(value, 16).to_bytes(item.numBytes, byteorder="little", signed=False)
                    self.image_bytes[item.flash_offset:item.flash_offset + item.numBytes] = value_bytes
                else:
                    raise ValueError("Bad " + item.descriptor + " size: " + item.numBytes + " bytes")
            elif item.descriptor.endswith("_string") or item.descriptor.endswith("_hfid"):
                value_len = len(value)
                if value_len > item.length:
                    raise ValueError(item.descriptor + " overlay value too long: " + value_len + " > " + item.length)
                value_bytes = bytearray(item.length)
                value_bytes[0:value_len] = value.encode(encoding="ascii")
                self.image_bytes[item.flash_offset:item.flash_offset + item.length] = value_bytes
            elif item.descriptor.startswith("connectionmgr_connection_data_"):
                value = bytes.fromhex(value)
                value_len = len(value)
                if value_len > item.length:
                    raise ValueError(item.descriptor + " overlay value too long: " + value_len + " > " + item.length)
                value_bytes = bytearray([0xff]) * item.length
                value_bytes[0:value_len] = value
                self.image_bytes[item.flash_offset:item.flash_offset + item.length] = value_bytes
            else:
                value_bytes = bytes.fromhex(value)
                value_len = len(value_bytes)
                if value_len != item.length:
                    raise ValueError(item.descriptor + " overlay value has wrong size: " + value_len + " != " + item.length)
                self.image_bytes[item.flash_offset:item.flash_offset + item.length] = value_bytes

        self.header_bytes = bytearray(self.header_bytes)
        with open(paramconfig_pathname, mode="wb") as f:
            crc = self._crc_image()
            self.header_bytes[12:16] = crc.to_bytes(length=4, byteorder="little")
            crc = self._crc_header()
            self.header_bytes[28:32] = crc.to_bytes(length=4, byteorder="little")
            f.write(self.header_bytes)
            f.write(self.image_bytes)

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
        members            = ggl_file.getmembers()
        paramconfig_helper = _get_helper(MemberHelper.FILETYPE_PARAMCONFIG)
        paramconfig_member = paramconfig_helper.find(members)
        
        try:
            pcfg_member = _get_helper(MemberHelper.FILETYPE_PCFG).find(members)
        except:
            if args.pcfg == None:
                raise IOError("No pcfg .csv file found")
            else:
                pcfg_member = None

        with tempfile.TemporaryDirectory() as tmpdir:
            paramconfig_pathname = os.path.join(tmpdir, paramconfig_member.name)
            extractables         = [paramconfig_member]
            if pcfg_member == None:
                pcfg_pathname = args.pcfg
            else:
                pcfg_pathname = os.path.join(tmpdir, pcfg_member.name)
                extractables.append(pcfg_member)

            ggl_file.extractall(path=tmpdir, members=extractables)
            paramconfig_helper.dump(paramconfig_pathname, pcfg_pathname, args.out)

def _overlay(args):
    with tarfile.open(name=args.ggl_file, mode="r") as ggl_file:
        members            = ggl_file.getmembers()
        paramconfig_helper = _get_helper(MemberHelper.FILETYPE_PARAMCONFIG)
        paramconfig_member = paramconfig_helper.find(members)
        fw_member          = _get_helper(MemberHelper.FILETYPE_FW).find(members)
        bin_member         = _get_helper(MemberHelper.FILETYPE_BIN).find(members)
        hw_version_member  = _get_helper(MemberHelper.FILETYPE_HW_VERSION).find(members)
        pcfg_member        = _get_helper(MemberHelper.FILETYPE_PCFG).find(members)
        extractables       = [paramconfig_member, fw_member, bin_member, hw_version_member, pcfg_member]

        with tempfile.TemporaryDirectory() as tmpdir:
            ggl_file.extractall(path=tmpdir, members=extractables)
            paramconfig_pathname = os.path.join(tmpdir, paramconfig_member.name)
            pcfg_pathname        = os.path.join(tmpdir, pcfg_member.name)
            paramconfig_helper.overlay(paramconfig_pathname, pcfg_pathname, args.overlay_file)
            # TODO remove overwrite of tarfile.RECORDSIZE if https://github.com/python/cpython/issues/75955 is ever implemented
            tarfile.RECORDSIZE = 10 * tarfile.BLOCKSIZE
            with tarfile.open(name=args.out_ggl_file, mode="w", format=tarfile.USTAR_FORMAT) as out_ggl_file:
                for member in extractables:
                    out_ggl_file.add(os.path.join(tmpdir, member.name), arcname=member.name)

def main():
    csv.register_dialect("ggl", GglDialect)
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title="subcommands")
    parser_c = subparsers.add_parser("check", help="Check the CRCs of a file")
    parser_c.add_argument("file_type", choices=["bin", "fw", "paramconfig"], help="The type of file to check")
    parser_c.add_argument("ggl_file", help="The .ggl file to read")
    parser_c.set_defaults(func=_check);
    parser_d = subparsers.add_parser("dump", help="Dump the paramconfig to a file or stdout")
    parser_d.add_argument("--pcfg", metavar="pcfg_file", help="Fallback pcfg CSV file")
    parser_d.add_argument("--out", metavar="out_file", help="paramconfig CSV to write")
    parser_d.add_argument("ggl_file", help="The .ggl file to read")
    parser_d.set_defaults(func=_dump);
    parser_o = subparsers.add_parser("overlay", help="Overlay some paramconfig values")
    parser_o.add_argument("overlay_file", help="A CSV file with paramconfig values to overlay")
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
