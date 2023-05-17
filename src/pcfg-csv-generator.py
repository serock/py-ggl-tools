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
from re import match

class PcfgCsvGenerator:
    def __init__(self, filename):
        self.filename = filename
        self.params   = dict()

    def _load_params(self):
        with open(self.filename, "r", encoding="ascii") as f:
            for line in f:
                line = line.strip()
                m = match(r"^(\d{1,3}) - ([0-9a-z_]+)$", line)
                if m:
                    self.params[m.group(2)] = {"Descriptor": m.group(2), "Index": int(m.group(1))}
                else:
                    m = match(r"^([0-9a-z_]+) \(byte size: ([124])\)$", line)
                    if m:
                        param = self.params[m.group(1)]
                        param["Length"] = 1
                        param["Bytes"] = int(m.group(2))
                        param["Size"] = 8 * int(m.group(2))
                    else:
                        m = match(r"^([0-9a-z_]+) \(byte size: ([124]) nitems: (\d{1,4})\)$", line)
                        if m:
                            param = self.params[m.group(1)]
                            param["Length"] = int(m.group(3))
                            param["Bytes"] = int(m.group(2))
                            param["Size"] = 8 * int(m.group(2))

    def _to_sorted_param_values(self):
        return sorted(self.params.values(), key=lambda param: param["Index"])

    def _generate_csv(self, param_values):
        print("Descriptor; ;Index;Length;Size;Flashoffset")

        flash_offset = 0

        for param in param_values:
            print(param["Descriptor"], "; ;", param["Index"], ";", param["Length"], ";", param["Size"], ";0x", "%X" % flash_offset, sep="")
            flash_offset = flash_offset + param["Length"] * param["Bytes"]

    def run(self):
        self._load_params()
        self._generate_csv(self._to_sorted_param_values())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("txt_file", help="Output from l2command.exe that lists parameters")
    args = parser.parse_args()
    generator = PcfgCsvGenerator(args.txt_file)
    generator.run()
    return 0

if __name__ == "__main__":
    exit(main())
