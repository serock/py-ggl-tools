# py-ggl-tools
Python scripts for working with .ggl firmware update files

## Background info
Firmware updates for power line adapters with Broadcom chipsets are distributed as `.ggl` files.
A `.ggl` file is an archive that contains both binary and text files.
Some of these files contain information about firmware parameters.
The Python scripts in this project deal primarily with the firmware parameter-related files (for example, dumping and overlaying firmware parameter values).

Technical details of the `.ggl` file format are available on the [wiki](https://github.com/serock/py-ggl-tools/wiki).

## Scripts

### ggl.py

The `ggl.py` works on `.ggl` archives.
Thus, there is no need to extract files from a `.ggl` archive before using the script.

The `ggl.py` script accepts the following subcommands as input:

* `check` &ndash; Check image length and CRCs in a binary file or show the `paramconfig` version
* `dump` &ndash; Dump the values in the `paramconfig` file in CSV format
* `overlay` &ndash; Overlay values in the `paramconfig` file with new values from a CSV file

#### Subcommand: check

* To check a `bin_upgrade` file, use: `ggl.py check bin <ggl-file>`
* To check a `fw_upgrade` file, use: `ggl.py check fw <ggl-file>`
* To check a `paramconfig` file, use: `ggl.py check paramconfig <ggl-file>`

#### Subcommand: dump

To dump the `paramconfig` file, use: `ggl.py dump <ggl-file>`

However, if the `.ggl` archive does not have a `pcfg` CSV file, use `ggl.py --pcfg <pcfg-file> dump <ggl-file>`

#### Subcommand: overlay

To overlay parameter values in the `paramconfig` file, use: `ggl.py overlay <overlay_file> <ggl_file> <out_ggl_file>`

The `overlay-file` is a CSV file that has the same format as a CSV file produced by the `dump` subcommand.

:warning: **WARNING!**

Updating a power line adapter with a `.ggl` archive file that is not from the manufacturer could brick the device or break some its functionality.
This is especially true if the firmware is for the wrong chip or the wrong geographic region, or if the `paramconfig` values are incompatible with the power line adapter.

:information_source: **Note:**

It might be necessary to perform a firmware update twice.
In working with the D-Link DHP-700AV and the D-Link *PLC Utility for Windows*, it seemed that the firmware was updated during the initial update, but the `paramconfig` wasn't updated until a second update was performed.

#### Examples

<details>
  <summary>Checking paramconfig</summary>

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
  <summary>Dumping paramconfig to a file</summary>

```
ggl.py dump --pcfg pcfg.10417.csv --out paramconfig_values.10417.csv DHP-700AV_REVA_FW101b01_duna_.ggl
```

</details>

<details>
  <summary>Overlaying parameter values</summary>

```
ggl.py overlay overlay.dhp-700av.na.14050.csv BCM60500_v3.2.4_20180511_NA_14050.ggl DHP-700AVA1_FW101NAb04.ggl
```

The [overlay.dhp-700av.na.14050.csv](data/overlay.dhp-700av.na.14050.csv) file is an example of an overlay file for a North American D-Link DHP-700AV power line adapter and firmware version `svn 14050`.

</details>

### pcfg-csv-generator.py

The `pcfg-csv-generator.py` script generates a `pcfg` CSV for the D-Link DHP-700AV 1.01.B01 North American firmware and writes the CSV to a file.
The generated `pcfg` CSV file can be used with `dump` subcommand of the `ggl.py` script.

The script accepts a text file as input. The text file must contain the following output from the D-Link *PLC Utility Lite* software:

1. List of all parameters
2. List of integer parameters
3. List of byte array parameters

The [param_lists.10417.txt](data/param_lists.10417.txt) file contains the 3 lists of parameters along with the commands used to generate them.

The [pcfg.10417.csv](data/pcfg.10417.csv) file contains the output of the `pcfg-csv-generator.py` script.
The CSV file was generated with the following command:

```
pcfg-csv-generator.py param_lists.10417.txt pcfg.10417.csv
```
