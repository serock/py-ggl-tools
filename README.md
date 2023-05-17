# py-ggl-tools
Python scripts for working with `.ggl` files

## Background info
Firmware updates for power line adapters with Broadcom chipsets are distributed as `.ggl` files.
A `.ggl` file is an archive in Posix tar format that typically contains the following:

* `hw_version.txt` file
* `pcfg` CSV file that describes configurable parameters[^1]
* Three binary files:
  1. `bin_upgrade` file
  2. `fw_upgrade` file
  3. `paramconfig` file that contains the parameter values

[^1]: Some older `.ggl` archives do not have a `pcfg` CSV file.
One example is the D-Link DHP-700AV 1.01.B01 firmware upgrade in the United States.

### Binary file format

Each of the three binary files consists of a binary image preceded by a 32-byte header:

| Header Bytes | Description |
|:---:|---|
| 1 &ndash; 4 | Unknown |
| 5 &ndash; 8 | Number of bytes in image only (excludes the 32 header bytes) |
| 9 &ndash; 12 | Unknown |
| 13 &ndash; 16 | CRC-32 of image only |
| 17 &ndash; 20 | `paramconfig` version (in `paramconfig` files only) |
| 21 &ndash; 24 | Unknown |
| 25 &ndash; 28 | Unknown |
| 29 &ndash; 32 | CRC-32 of header bytes 1 &ndash; 28 |

Multi-byte integers are represented in little endian format.
For `bin_upgrade` and `paramconfig` files, the CRC-32 algorithm uses an initial value of `0`.
For `fw_upgrade` files, the CRC-32 algorithm uses an initial value of `0xffffffff`.

### The paramconfig file

The `paramconfig` file is a binary file that contains parameter values only.
There are four types of parameters:

1. 8-bit integer
2. 16-bit integer
3. 32-bit integer
4. Byte array

Multi-byte integers are represented in little endian format.
Parameter values that are ASCII strings are represented as byte arrays.
The same is true for Network Identifiers (NIDs), which are 54-bit integers; they are represented as 7-byte arrays in little endian format.

Parameter values are packed. That is, parameter values immediately follow one another; there are no unused bytes within the binary image of the `paramconfig` file.

### The pcfg CSV file

The `pcfg` CSV file has the following information for each parameter:

1. Descriptor, or name, of a parameter
2. Index (a unique, relative location of a parameter)
3. Length (integers have a length of 1, byte arrays have a length greater than 1)
4. Size in bits (integers have a size of 8, 16, or 32 bits; byte array elements have a size of 8 bits)
5. Flash offset (the offset from the beginning of the image in the `paramconfig` file)

Indices are generally sequential; however, there are gaps.
For example, the 121 parameters of the D-Link DHP-700AV 1.01.B01 firmware in the United States have indices that range from 0 to 136;
no parameter has an index of 32, 66, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 91, or 102.

### D-Link PLC Utility Lite

As mentioned in the footnotes, a `pcfg` CSV file is not included with the D-Link DHP-700AV 1.01.B01 firmware upgrade in the United States.
However, D-Link provides a PLC Utility Lite download for the DHP-701AV kit.
The software can be used to obtain all of the information that would be included in a `pcfg` CSV file.

## Scripts

### pcfg-csv-generator.py

The `pcfg-csv-generator.py` script generates a `pcfg` CSV for the D-Link DHP-700AV 1.01.B01 firmware in the United States and writes the CSV to *stdout*.
The script accepts a text file as input. The text file must contain the following output from the D-Link PLC Utility Lite software:

1. List of all parameters
2. List of integer parameters
3. List of byte array parameters

The `data/param_lists.10417.txt` file contains the 3 lists of parameters along with the commands used to generate them.
The `data/pcfg.10417.csv` file contains the output of the script. The CSV file was generated with the following command:

```
pcfg-csv-generator.py param_lists.10417.txt > pcfg.10417.csv
```

### ggl.py

The `ggl.py` works on `.ggl` archives.
Thus, there is no need to extract files from a `.ggl` archive when using the script.

The `ggl.py` script accepts the following subcommands as input:

* `check` &ndash; Check CRCs within a binary file or check the `paramconfig` version
* `dump` &ndash; Dump to *stdout* in CSV format the values in the `paramconfig` file

#### Subcommand: check

* To check a `bin_upgrade` file, use: `ggl.py check bin <ggl-file>`
* To check a `fw_upgrade` file, use: `ggl.py check fw <ggl-file>`
* To check a `paramconfig` file, use: `ggl.py check paramconfig <ggl-file>`

#### Subcommand: dump

To dump the `paramconfig` file, use: `ggl.py dump <ggl-file>`

However, if the `.ggl` archive does not have a `pcfg` CSV file, use `ggl.py --pcfg <pcfg-file> dump <ggl-file>`

#### Examples

<details>
  <summary>Check paramconfig</summary>

```
ggl.py check paramconfig DHP-700AV_REVA_FW101b01_duna_.ggl
```

```
File: paramconfig.10417.BCM_CFG2.bin

Calculated Header CRC: 0xbaa94faa
Embedded Header CRC:  0xbaa94faa (good)

Calculated Image CRC: 0xb048ce1a
Embedded Image CRC:  0xb048ce1a (good)

Calculated Image Length: 2752
Embedded Image Length:  2752 (good)

ParamConfig Version: 10101
```

</details>

<details>
  <summary>Dump paramconfig</summary>

```
ggl.py dump --pcfg pcfg.10417.csv DHP-700AV_REVA_FW101b01_duna_.ggl > paramconfig_values.10417.csv
```

</details>
