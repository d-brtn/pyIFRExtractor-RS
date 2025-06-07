# pyIFExtractor

**pyIFExtractor** is a Python library powered by PyO3 that wraps the Rust-based [IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) utility. It provides fast and safe bindings for parsing and extracting HII (Human Interface Infrastructure) IFR (Internal Forms Representation) data from BIOS/UEFI firmware binaries.

---

## Features

- **Framework & UEFI Support**: Scan and extract both Framework HII and UEFI HII string- and form-packages.
- **Parsed Data Structures**: Work with high‑level `StringPackage` and `FormPackage` Python objects.
- **Flexible Extraction**: Dump IFR opcodes with optional verbose offsets and human‑readable formatting.
- **Zero‑Copy Bindings**: Leverage Rust performance via PyO3 with minimal data copying.

---

## Use Cases

- **Data‑mining BIOS settings**: Enumerate and inspect configuration levers and metadata embedded in firmware.
- **Offset discovery**: Locate IFR data offsets for reverse engineering or automation.

---

## Installation

You will need a Rust toolchain and [maturin](https://www.maturin.rs/) installed:

```bash
# Install maturin (if you haven't already)
pip install maturin

# From this repository root:
maturin develop --release
```

This builds the native extension and installs `pyifrextractor` into your active Python environment.

---

## Quickstart

```python
import ifrextractor_rs

# Load firmware blob
with open("firmware.bin", "rb") as f:
    data = f.read()

# 1) Framework HII
strings, forms = ifrextractor_rs.find_framework_packages(data)
print(f"Found {len(strings)} string packages and {len(forms)} form packages (Framework)")

if strings and forms:
    text = ifrextractor_rs.extract_framework_ifr(data, forms[0], strings[0], verbose=True)
    print(text)

# 2) UEFI HII
uefi_strings, uefi_forms = ifrextractor_rs.find_uefi_packages(data)
print(f"Found {len(uefi_strings)} string packages and {len(uefi_forms)} form packages (UEFI)")

if uefi_strings and uefi_forms:
    uefi_text = ifrextractor_rs.extract_uefi_ifr(data, uefi_forms[0], uefi_strings[0], verbose=False)
    print(uefi_text)
```
