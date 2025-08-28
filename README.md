# yk-pskc

Batch-provision HOTP credentials to YubiKeys and generate corresponding RFC6030-compliant `.pskc` files.

## Description

This script:
- Writes HOTP secrets to YubiKey slot 1 or 2
- Exports each secret as a `.pskc` file (encrypted)
- Supports batch operations (e.g., provision 20 keys in a row)
- Prints the PSKC file unlock key at the end — **store this safely**

Requires YubiKey Manager CLI (`ykman`) and the `pskc` Python module.

Update the location of ykman in the script to match your environment (default locations are currently hard coded).

## Installation

```bash
pip install pskc
```

## Usage
```
python3 yk-pskc.py -n [number of keys to write] -s [slot 1 or 2]
```

## Example
```
python3 yk-pskc.py -n 20 -s 1
```
