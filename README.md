# py-ggl-tools
Python scripts for working with `.ggl` files

## Background info
Firmware updates for power line adapters with Broadcom chipsets are distributed as `.ggl` files.
Technical details of the `.ggl` files are available in the [wiki](https://github.com/serock/py-ggl-tools/wiki).

### D-Link PLC Utility Lite

D-Link provides a *PLC Utility Lite* download for the DHP-701AV kit.
The software, which runs on Windows, can be used to derive parameter information when a `.ggl` archive does not contain a `pcfg` CSV file.

## Scripts

### pcfg-csv-generator.py

The `pcfg-csv-generator.py` script generates a `pcfg` CSV for the D-Link DHP-700AV 1.01.B01 firmware in the United States and writes the CSV to a file.
The script accepts a text file as input. The text file must contain the following output from the D-Link *PLC Utility Lite* software:

1. List of all parameters
2. List of integer parameters
3. List of byte array parameters

The `data/param_lists.10417.txt` file contains the 3 lists of parameters along with the commands used to generate them.

The `data/pcfg.10417.csv` file contains the output of the `pcfg-csv-generator.py` script.
The CSV file was generated with the following command:

```
pcfg-csv-generator.py param_lists.10417.txt pcfg.10417.csv
```

### ggl.py

The `ggl.py` works on `.ggl` archives.
Thus, there is no need to extract files from a `.ggl` archive when using the script.

The `ggl.py` script accepts the following subcommands as input:

* `check` &ndash; Check CRCs within a binary file or check the `paramconfig` version
* `dump` &ndash; Dump the values in the `paramconfig` file in CSV format

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
  <summary>Dump paramconfig to a file</summary>

```
ggl.py dump --pcfg pcfg.10417.csv --out paramconfig_values.10417.csv DHP-700AV_REVA_FW101b01_duna_.ggl
```

</details>
