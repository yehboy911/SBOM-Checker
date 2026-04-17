---
name: scanning-boost-dependencies
description: This skill should be used when the user asks to "scan Boost dependencies", "analyze CMakeLists.txt", "find Boost libraries in DLL/SO files", "convert SBOM from CSV", "generate Boost dependency report", or mentions Boost library analysis, CMake dependency scanning, or SBOM filtering.
---

# Scanning Boost Dependencies

This skill provides guidance for scanning Boost Library dependencies in CMake projects and generating formatted reports.

## Overview

`boost-scanner` is a Python CLI tool for:
- Recursively scanning CMakeLists.txt files for Boost Library dependencies
- Identifying which Boost libraries exist in .dll (Windows) or .so (Linux) files
- Generating formatted dependency reports with platform context
- SBOM filtering to match against known component lists
- Converting CSV export files to cleaned SBOM lists

### Architecture

```
src/boost_scanner/
├── scanner.py        # BoostScanner class - core scanning logic
├── sbom_converter.py # SbomConverter class - CSV → SBOM conversion
├── cli.py            # argparse entry point (boost-scanner command)
└── __init__.py       # Exports BoostScanner, SbomConverter
```

## When This Skill Applies

This skill activates when the request involves:
- Scanning CMake projects for Boost dependencies
- Analyzing which DLL/SO files contain Boost libraries
- Generating Boost dependency reports
- Filtering results against SBOM lists
- Converting CSV exports to SBOM format

## Instructions

### Installation

Ensure `boost-scanner` is installed via pipx:

```bash
# Check if installed
which boost-scanner || ~/.local/bin/boost-scanner --help

# Install if needed
pipx install -e "/Users/Yehboy/Claude Code/boost_filter"
```

### Scanning Boost Dependencies

Scan a directory for CMakeLists.txt files and extract Boost dependencies:

```bash
# Scan current directory
boost-scanner

# Scan specific directory
boost-scanner /path/to/cmake/project

# Scan with SBOM filter
boost-scanner /path/to/project --sbom /path/to/sbom.txt
```

### SBOM Filtering

Filter scan results against a known SBOM component list:

1. Prepare SBOM list file (one component per line)
2. Run scanner with `--sbom` flag
3. Results show only matching components

### Converting CSV to SBOM

Convert dependency export CSV files to cleaned SBOM lists:

```bash
# Single CSV conversion
boost-scanner convert-sbom input.csv -o sbom.txt

# Multiple CSV merge (auto-detects platform)
boost-scanner convert-sbom win.csv linux.csv -o sbom_combined.txt

# Output to stdout
boost-scanner convert-sbom input.csv
```

Platform detection:
- `.dll` files → Windows platform
- `.so` files → Linux platform

## Examples

### Example 1: Basic Project Scan

```bash
boost-scanner ~/projects/my-cmake-app
```

Output:
```
=== Boost Library Dependencies Report ===

[Target: my_app] (Windows)
  - boost_filesystem
  - boost_system
  - boost_thread

[Target: my_app] (Linux)
  - boost_filesystem
  - boost_system
```

### Example 2: SBOM Filtered Scan

```bash
boost-scanner ~/projects/my-cmake-app --sbom ~/sbom/approved-libs.txt
```

### Example 3: CSV to SBOM Conversion

```bash
# Windows DLL list
boost-scanner convert-sbom windows_deps.csv -o sbom_win.txt

# Merge Windows and Linux
boost-scanner convert-sbom win.csv linux.csv -o sbom_all.txt
```

### Example 4: Direct Python Execution

```bash
python3 src/boost_scanner/cli.py /path/to/project --sbom /path/to/sbom.txt
```

## Output Format

### Dependency Report

Reports are grouped by target and platform:

```
=== Boost Library Dependencies Report ===

[Target: <target_name>] (<Platform>)
  - boost_<library1>
  - boost_<library2>
  ...
```

### SBOM Output

Clean list of normalized library names:

```
boost_chrono
boost_container
boost_context
boost_filesystem
boost_system
boost_thread
```

## Additional Resources

- **Project CLAUDE.md**: `/Users/Yehboy/Claude Code/boost_filter/CLAUDE.md`
- **Source Code**: `/Users/Yehboy/Claude Code/boost_filter/src/boost_scanner/`
- **Commands**: `/scan-boost`, `/convert-sbom`
