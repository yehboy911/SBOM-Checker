---
name: validating-sbom-coverage
description: This skill should be used when the user asks to "validate SBOM", "check SBOM coverage", "cross-reference CMake and SBOM", "verify SBOM output and input", "compare CMakeLists.txt with SBOM", "classify SBOM differences", or mentions SBOM validation, CMake coverage checking, source reference verification, or SBOM cross-validation.
---

# Validating SBOM Coverage

This skill provides guidance for cross-validating SBOM CSV files against CMakeLists.txt outputs and automatically classifying discrepancies.

## Overview

`sbom-checker` is a Python CLI tool for SBOM CSV cross-validation:
- Verifying source references in SBOM match actual outputs
- Cross-comparing CMakeLists.txt targets with SBOM components
- Automatically classifying differences into 6 priority categories
- Generating legal-team-friendly validation reports

### Architecture

```
src/sbom_checker/
├── cli.py              # argparse entry point + subcommands (check, scan)
├── sbom_parser.py      # SBOM CSV parsing (FOSSA/Excel format support)
├── cmake_scanner.py    # CMakeLists.txt scanning (platform-aware)
├── validator.py        # Cross-validation + auto-classification logic
└── report.py           # Report formatting (legal-friendly format)
```

### Auto-Classification Categories

| Priority | Category | Rule | Description |
|:---------|:---------|:-----|:------------|
| 1 | `cmake_internal` | FortranLib, cmake_* | CMake internal tools, should not be in SBOM |
| 2 | `test_sample` | test*, sample*, *test* | Test/sample programs, development only |
| 3 | `static_lib` | .a or .lib extension | Static libraries, embedded in other targets |
| 4 | `third_party` | boost, curl, zlib, openssl, ... | Third-party dependencies, defined in SBOM |
| 5 | `platform_specific` | .exe, .dll, .so, .dylib | Platform-specific files, needs confirmation |
| 6 | `unknown` | Other items | Requires manual review |

## When This Skill Applies

This skill activates when the request involves:
- Validating SBOM CSV against source code
- Checking CMake target coverage in SBOM
- Verifying source references are correct
- Cross-comparing CMakeLists.txt outputs with SBOM components
- Classifying SBOM discrepancies
- Generating SBOM validation reports

## Instructions

### Installation

Ensure `sbom-checker` is installed via pipx:

```bash
# Check if installed
which sbom-checker || ~/.local/bin/sbom-checker --help

# Install if needed
pipx install -e "/Users/Yehboy/Claude Code/sbom_checker"
```

### Validating SBOM (Full Cross-Validation)

Run complete validation including source reference check and CMake cross-comparison:

```bash
# Linux platform validation
sbom-checker check <sbom.csv> --source-dir <source_root> --platform linux

# Windows platform validation
sbom-checker check <sbom.csv> --source-dir <source_root> --platform windows

# Auto-detect platform from CSV content
sbom-checker check <sbom.csv> --source-dir <source_root>
```

### Source Reference Only Check

Verify SBOM source references without requiring source code access:

```bash
sbom-checker check <sbom.csv> --check-refs-only
```

### Scanning CMake Targets

Scan CMakeLists.txt files to understand project structure before validation:

```bash
# Scan with Linux output format
sbom-checker scan <source_root> --platform linux

# Scan with Windows output format
sbom-checker scan <source_root> --platform windows
```

### Interpreting Results

**Source Reference Validation:**
- `PASS`: All SBOM targets have valid source references
- `FAIL`: Missing or invalid source references found

**CMake Coverage:**
- `cmake-only`: Targets built by CMake but missing from SBOM
- `sbom-only`: Components in SBOM not found in CMake targets

**Classification Statistics:**
- Items categorized as `cmake_internal`, `test_sample`, `static_lib` are typically safe to ignore
- `third_party` items are usually covered by other SBOM entries
- `platform_specific` and `unknown` require manual review

## Examples

### Example 1: Complete Validation Workflow

```bash
# Step 1: Scan CMake targets to understand the project
sbom-checker scan /path/to/OneCLI --platform linux

# Step 2: Run full SBOM validation
sbom-checker check /path/to/linux_sbom.csv \
  --source-dir /path/to/OneCLI \
  --platform linux

# Step 3: Save report for legal review
sbom-checker check /path/to/linux_sbom.csv \
  --source-dir /path/to/OneCLI \
  --platform linux > linux_validation_report.txt
```

### Example 2: Multi-Platform Validation

```bash
# Linux validation
sbom-checker check linux_sbom.csv \
  --source-dir /path/to/source \
  --platform linux > linux_report.txt

# Windows validation
sbom-checker check windows_sbom.csv \
  --source-dir /path/to/source \
  --platform windows > windows_report.txt
```

### Example 3: Quick Source Reference Check

```bash
# Check only source references (no source code needed)
sbom-checker check /path/to/sbom.csv --check-refs-only
```

### Example 4: Identifying Issues

```bash
# Run validation and filter for items needing attention
sbom-checker check sbom.csv --source-dir /path/to/src --platform linux | grep -E "(unknown|platform_specific)"

# Count items by category
sbom-checker check sbom.csv --source-dir /path/to/src --platform linux | grep -E "^\s+(cmake_internal|test_sample|static_lib|third_party|platform_specific|unknown):"
```

## Output Format

### Validation Summary

```
已解析: 573 個 Target, 4284 個 Source, 8 個區段, 平台: linux
CMake 掃描: 539 個 target

=== SBOM 驗證報告 ===

【來源參照驗證】
狀態: ✅ PASS
Target 數: 573
Source 數: 4284
問題數: 0

【CMake 交叉比對】
CMake Targets: 539
SBOM Targets: 573

分類統計:
  cmake_internal:     1 (CMake-only)
  static_lib:        93 (CMake-only)
  test_sample:       83 (CMake-only)
  linux_specific:    48 (32 CMake-only, 16 SBOM-only)
  third_party:       14 (SBOM-only)
  unknown:           58 (20 CMake-only, 38 SBOM-only)
```

### Classification Details

Each category is listed with its items for manual review:

```
【cmake_internal】(1 項)
  - FortranLib (CMake-only)

【static_lib】(93 項)
  - libfoo.a (CMake-only)
  - libbar.a (CMake-only)
  ...

【unknown】(58 項) ⚠️ 需人工審查
  - mystery_component (CMake-only)
  - unclassified_lib (SBOM-only)
  ...
```

## Additional Resources

- **Project CLAUDE.md**: `/Users/Yehboy/Claude Code/sbom_checker/CLAUDE.md`
- **Source Code**: `/Users/Yehboy/Claude Code/sbom_checker/src/sbom_checker/`
- **Reports Directory**: `/Users/Yehboy/Claude Code/sbom_checker/reports/`
- **Commands**: `/check-sbom`, `/scan-cmake`
- **GitHub**: https://github.com/yehboy911/SBOM-Checker
