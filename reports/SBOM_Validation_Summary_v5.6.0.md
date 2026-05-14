# LXCE OneCLI 5.6.0 — Open-Source Compliance Audit Report
**Generated:** 2026-05-13 · **Updated:** 2026-05-14 (Windows review integrated; openssl 3.1.5 approved for storcli2; curl/zlib/pthreads confirmed per official ref; H-22 Windows I/O source gap identified)  
**Audit Scope:** SBOM Review (Format + Version Correctness) — Linux & Windows packages  
**Project:** Lenovo XClarity Essentials OneCLI + XModule (Modularization) 5.6.0 (Tasmania)  
**Components audited:** modularization/, onecli/, rdcli_red/  
**SBOM files reviewed:**
- `lnvgy_utl_lxce_onecli_linux_indiv (tgz)-5.6.x-(Tasmania)-SBOM-13May2026.xlsx` (1203 components)
- `lnvgy_utl_lxce_onecli_windows_indiv (zip)-v5.6.x (Tasmania)-SBOM-12May2026.xlsx` (1122 components)

---

## Section 1: SBOM Format Validation

### 1.1 Structure Summary

| Item | Linux | Windows |
|---|---|---|
| Target sections (`*BUILD OUTPUT for "Target…"`) | 14 | 15 |
| Total data rows checked | 1,182 | 976 |
| Orphan rows (name present, path empty) | 0 | 0 |
| Reversed orphan rows (path present, name empty) | 0 | 0 |
| `see below` license references | 565 | 390 |

✅ No structural format issues detected. All Target sections are present and no orphan records found.

---

### 1.2 Col E (Path) — Version-Specific Folder ❌ SYSTEMATIC ISSUE

**Rule:** Col E must use the constant platform folder name (no version number) for re-use across releases. OneCLI distribution packages (`.tgz` / `.zip` / `.exe` / `.bin` / `.rpm`) are excluded — they retain the exact filename in Col E.

| Platform | Version-specific folder (current — wrong) | Constant folder (required) |
|---|---|---|
| Linux | `lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv` | `lnvgy_utl_lxce_onecli_linux_x86-64` |
| Windows | `lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv` | `lnvgy_utl_lxce_onecli_winsrv_x86-64` |

**Scale:** 577 / 578 Target rows affected (Linux) · 382 / 383 Target rows affected (Windows)

**Fix:** Global find-and-replace in Col E — one substitution fixes every affected row.

**Sample corrections (Linux):**

| Row | Col A | Col E (current) | Col E (required) |
|---|---|---|---|
| 26 | `*BUILD OUTPUT for "Target/…"` | `Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/*.*` | `Target/lnvgy_utl_lxce_onecli_linux_x86-64/*.*` |
| 27 | `onecli` | `Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/onecli` | `Target/lnvgy_utl_lxce_onecli_linux_x86-64/onecli` |
| 32 | `banner_bg.png` | `Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/data/banner_bg.png` | `Target/lnvgy_utl_lxce_onecli_linux_x86-64/data/banner_bg.png` |
| 43 | `libacquire.so` | `Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/libs/libacquire.so` | `Target/lnvgy_utl_lxce_onecli_linux_x86-64/libs/libacquire.so` |

**Sample corrections (Windows):**

| Row | Col A | Col E (current) | Col E (required) |
|---|---|---|---|
| 25 | `*BUILD OUTPUT for "Target/…"` | `Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/*.*` | `Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/*.*` |
| 39 | `acquire.dll` | `Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/libs/acquire.dll` | `Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/libs/acquire.dll` |

---

### 1.3 Col A (Section Headers) — Version-Specific Folder ❌ SYSTEMATIC ISSUE

**Rule:** `*BUILD OUTPUT for "Target/..."` section headers in Col A must use the constant platform folder name (no version number) so they remain stable across releases. The bare `*BUILD OUTPUT for "Target"` row (no sub-path) is exempt.

| Platform | Version-specific folder (current — wrong) | Constant folder (required) |
|---|---|---|
| Linux | `lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv` | `lnvgy_utl_lxce_onecli_linux_x86-64` |
| Windows | `lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv` | `lnvgy_utl_lxce_onecli_winsrv_x86-64` |

**Scale:** 13 / 13 section headers affected (Linux) · 14 / 14 section headers affected (Windows)

**Fix:** Global find-and-replace in Col A — one substitution per platform fixes every affected header.

**Linux — all affected headers:**

| Row | Current (wrong) | Required |
|---|---|---|
| 26 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64"` |
| 31 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/data"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/data"` |
| 38 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/Doc"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/Doc"` |
| 42 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/libs"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/libs"` |
| 560 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/libs/css"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/libs/css"` |
| 563 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/ts_tools"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/ts_tools"` |
| 567 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/utilities/arcconf"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/utilities/arcconf"` |
| 569 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/utilities/disk_fwutl"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/utilities/disk_fwutl"` |
| 581 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/utilities/lsi"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/utilities/lsi"` |
| 584 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/utilities/m2"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/utilities/m2"` |
| 588 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/utilities/pmem"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/utilities/pmem"` |
| 593 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/utilities/qlogic/qcccli"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/utilities/qlogic/qcccli"` |
| 597 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv/utilities/ssd"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/utilities/ssd"` |

**Windows — all affected headers:**

| Row | Current (wrong) | Required |
|---|---|---|
| 25 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64"` |
| 29 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/data"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/data"` |
| 36 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/Doc"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/Doc"` |
| 38 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/libs"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/libs"` |
| 370 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/libs/css"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/libs/css"` |
| 373 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/ts_tools"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/ts_tools"` |
| 385 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/utilities/arcconf"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/utilities/arcconf"` |
| 389 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/utilities/disk_fwutl"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/utilities/disk_fwutl"` |
| 402 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/utilities/lsi"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/utilities/lsi"` |
| 405 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/utilities/m2"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/utilities/m2"` |
| 409 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/utilities/pmem"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/utilities/pmem"` |
| 413 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/utilities/qlogic/qcccli"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/utilities/qlogic/qcccli"` |
| 421 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/utilities/ssd"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/utilities/ssd"` |
| 434 | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv/utilities/vroc"` | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64/utilities/vroc"` |

---

### 1.4 Col D (Link) Folder Name — ❌ ISSUES FOUND

**Rule:** Top-level OneCLI package entries directly under `*BUILD OUTPUT for "Target"` must have Col D referencing the **constant platform folder name** (no version number). This enables re-use across releases.

| Platform | Required constant folder | Required Col D value |
|---|---|---|
| Linux | `lnvgy_utl_lxce_onecli_linux_x86-64` | `see "Target/lnvgy_utl_lxce_onecli_linux_x86-64"` |
| Windows | `lnvgy_utl_lxce_onecli_winsrv_x86-64` | `see "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64"` |

#### Linux SBOM — 3 rows with version-specific Col D

| Row | Col A (Package) | Col D (current — wrong) | Col D (required) |
|---|---|---|---|
| 23 | `lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv.tgz` | `see "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv"` | `see "Target/lnvgy_utl_lxce_onecli_linux_x86-64"` |
| 24 | `lnvgy_utl_lxceb_onecli01d-5.6.0_linux_indiv.bin` | `see "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv"` | `see "Target/lnvgy_utl_lxce_onecli_linux_x86-64"` |
| 25 | `lnvgy_utl_lxcer_onecli01d-5.6.0_linux_indiv.rpm` | `see "Target/lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv"` | `see "Target/lnvgy_utl_lxce_onecli_linux_x86-64"` |

#### Windows SBOM — 2 rows with version-specific Col D

| Row | Col A (Package) | Col D (current — wrong) | Col D (required) |
|---|---|---|---|
| 23 | `lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv.zip` | `see "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv"` | `see "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64"` |
| 24 | `lnvgy_utl_lxceb_onecli01d-5.6.0_windows_indiv.exe` | `see "Target/lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv"` | `see "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64"` |

**Action required:** Replace the 5 version-specific Col D values with the constant folder name before OSC submission.

---

### 1.5 Col F (USE) Completeness — ❌ ISSUES FOUND

**Rule:** Col F must be filled for every component row. The value must match the file type indicated by Col A:

| Col A File Type | Required Col F Value |
|---|---|
| `*.so`, `*.so.N`, `*.so.N.M.P`, `*.dll` | `Dynamic Library` |
| `*.bin`, `*.exe`, no-ext binary | `Binary` |
| `*.tgz` | `TGZ` |
| `*.zip` | `ZIP` |
| `*.rpm` | `RPM` |
| `*.tar.gz` | `GZ` |
| `*.tar.bz2`, `*.bz2` | `BZ2` |
| `*.png` | `PNG` |
| `*.gif` | `GIF` |
| `*.pdf` | `PDF` |
| `*.vsix`, `*.cat`, `*.sys`, `*.properties` | `File` |
| `lnvgy_…`, `intc-lnvgy_…` (no ext, Lenovo pkg) | `Binary Package` |
| Repo path (`modularization/…`, `onecli/…`) | `Source Code` |

#### Linux SBOM — 10 empty Col F rows

| Row | Component (Col A) | Extension | Required Col F |
|---|---|---|---|
| 25 | `lnvgy_utl_lxcer_onecli01d-5.6.0_linux_indiv.rpm` | `.rpm` | **RPM** |
| 32 | `banner_bg.png` | `.png` | **PNG** |
| 33 | `e.gif` | `.gif` | **GIF** |
| 34 | `header_bg.png` | `.png` | **PNG** |
| 35 | `i.gif` | `.gif` | **GIF** |
| 36 | `lenovo_logo.png` | `.png` | **PNG** |
| 37 | `w.gif` | `.gif` | **GIF** |
| 39 | `coe-30002-01_lenovo_license_agreement.pdf` | `.pdf` | **PDF** |
| 561 | `banner_bg.png` | `.png` | **PNG** |
| 562 | `lenovo_logo.png` | `.png` | **PNG** |

#### Windows SBOM — 5 empty Col F rows

| Row | Component (Col A) | Extension | Required Col F |
|---|---|---|---|
| 80 | `device.cat` | `.cat` | **File** |
| 265 | `pciio_driver.sys` | `.sys` | **File** |
| 371 | `banner_bg.png` | `.png` | **PNG** |
| 372 | `lenovo_logo.png` | `.png` | **PNG** |
| 414 | `adapters.properties` | `.properties` | **File** |

**Action required:** Fill in the 15 empty Col F cells listed above before OSC submission.

---

### 1.6 Col D Boost Annotation — ❌ ISSUES FOUND

**Rule:** For each `.so` / `.dll` row whose CMake target links against boost (per `target_link_libraries` in the relevant `CMakeLists.txt`), Col D must append `; "boost"` — e.g. `see "modularization/src/module/acquire"; "boost"`.

| Platform | `.so`/`.dll` rows checked | Missing boost annotation |
|---|---|---|
| Linux | 552 | **141** |
| Windows | 357 | **11** |

#### Linux SBOM — sample of 141 rows missing boost annotation

| Row | Col A | CMake Target | Col D (current — missing `; "boost"`) |
|---|---|---|---|
| 43 | `libacquire.so` | `acquire` | `see "modularization/src/module/acquire"` |
| 52 | `libarcconfopt.so` | `arcconfopt` | `see "modularization/src/module/options/arcconf"` |
| 53 | `libarcconfopt.so.5.6` | `arcconfopt` | `see "modularization/src/module/options/arcconf"` |
| 54 | `libarcconfopt.so.5.6.0.1` | `arcconfopt` | `see "modularization/src/module/options/arcconf"` |
| 65 | `libBMCRedfishConfig.so` | `bmcredfishconfig` | `see "modularization/src/module/xfw/RedfishConfig/BMCResource…"` |
| 66 | `libBMCRedfishConfig.so.5.6` | `bmcredfishconfig` | `see "modularization/src/module/xfw/RedfishConfig/BMCResource…"` |
| 67 | `libBMCRedfishConfig.so.5.6.0.1` | `bmcredfishconfig` | `see "modularization/src/module/xfw/RedfishConfig/BMCResource…"` |
| 100 | `libCFCBMCRedfishConfig.so` | `cfcbmcredfishconfig` | `see "modularization/src/module/xfw/RedfishConfig/CFCBMCResou…"` |
| 101 | `libCFCBMCRedfishConfig.so.5.6` | `cfcbmcredfishconfig` | `see "modularization/src/module/xfw/RedfishConfig/CFCBMCResou…"` |
| 102 | `libCFCBMCRedfishConfig.so.5.6.0.1` | `cfcbmcredfishconfig` | `see "modularization/src/module/xfw/RedfishConfig/CFCBMCResou…"` |
| 103 | `libchassisEventLog.so` | `chassiseventlog` | `see "modularization/src/module/xm_cim/chassis_event_log"` |
| 104 | `libchassisEventLog.so.5.6` | `chassiseventlog` | `see "modularization/src/module/xm_cim/chassis_event_log"` |
| 105 | `libchassisEventLog.so.5.6.0.1` | `chassiseventlog` | `see "modularization/src/module/xm_cim/chassis_event_log"` |
| 114 | `libcimom.so` | `cimom` | `see "modularization/src/common/cimom/src"` |
| 115 | `libcimom.so.5.6` | `cimom` | `see "modularization/src/common/cimom/src"` |
| 116 | `libcimom.so.5.6.0.1` | `cimom` | `see "modularization/src/common/cimom/src"` |
| 130 | `libcomparepackage.so` | `comparepackage` | `see "modularization/src/module/update/compare_package"` |
| 131 | `libcomparepackage.so.5.6` | `comparepackage` | `see "modularization/src/module/update/compare_package"` |
| 132 | `libcomparepackage.so.5.6.0.1` | `comparepackage` | `see "modularization/src/module/update/compare_package"` |
| 136 | `libConfigCompatibleModule.so` | `configcompatiblemodule` | `see "modularization/src/module/xfw/RedfishConfig/RedfishComp…"` |
| 137 | `libConfigCompatibleModule.so.5.6` | `configcompatiblemodule` | `see "modularization/src/module/xfw/RedfishConfig/RedfishComp…"` |
| 138 | `libConfigCompatibleModule.so.5.6.0.1` | `configcompatiblemodule` | `see "modularization/src/module/xfw/RedfishConfig/RedfishComp…"` |
| 140 | `libcredential.so` | `credential` | `see "modularization/src/common/credential_handler"` |
| 147 | `libdcpmem.so` | `dcpmem` | `see "modularization/src/module/options/dcpmem"` |
| 148 | `libdcpmem.so.5.6` | `dcpmem` | `see "modularization/src/module/options/dcpmem"` |
| … | _(+116 more rows)_ | | |

#### Windows SBOM — all 11 rows missing boost annotation

| Row | Col A | CMake Target | Col D (current — missing `; "boost"`) |
|---|---|---|---|
| 53 | `bmu_env.dll` | `bmu_env` | `see "modularization/src/common/bmu_env"` |
| 68 | `cmm.dll` | `cmm` | `see "modularization/src/module/xm_cim/cmm/inventory_update"` |
| 69 | `cmmffdc.dll` | `cmmffdc` | `see "modularization/src/module/xm_cim/cmm/ffdc"` |
| 78 | `curlcpp.dll` | `curlcpp` | `see "modularization/src/xm_common/curlcpp"` |
| 96 | `file_client.dll` | `file_client` | `see "modularization/src/xm_common/file_client"` |
| 97 | `file_transfer.dll` | `file_transfer` | `see "onecli/Src/Utility/file_transfer"` |
| 113 | `iolog.dll` | `iolog` | `see "modularization/src/module/update/io_log"` |
| 238 | `onecli_update_rollback.dll` | `onecli_update_rollback` | `see "onecli/Src/apps/update/rollback"` |
| 260 | `pcidevice.dll` | `pcidevice` | `see "modularization/src/module/osinfos/pcidevice"` |
| 296 | `RemoteController.dll` | `remotecontroller` | `see "modularization/src/common/remote_controller"` |
| 308 | `secure_erase.dll` | `secure_erase` | `see "modularization/src/module/misc/secure_erase"` |

**Action required:** Append `; "boost"` to Col D for each flagged row.

---

### 1.7 Col A ↔ Col D Source Path Verification — ⚠️ ISSUES FOUND

**Rule:** For each `.so` / `.dll` row where Col D is `see "source/path"`, the path must exist on disk and the `CMakeLists.txt` at that path must declare a target whose name matches Col A.

#### Linux SBOM

| Result | Count |
|---|---|
| ✅ Verified (target matches) | 446 |
| ❌ Mismatch (dir exists, wrong target) | 0 |
| ⚠️ Path missing (dir not found on disk) | 25 |
| ⚠️ Path exists, no CMakeLists.txt | 2 |
| **Total checked** | **473** |

<details><summary>⚠️ 25 Linux path(s) not found on disk</summary>

| Row | Col A | Expected target | Col D path |
|---|---|---|---|
| 106 | `libcheck_trust.so` | `check_trust` | `modularization/src/xm_common/check_trust` |
| 107 | `libcheck_trust.so.5.6` | `check_trust` | `modularization/src/xm_common/check_trust` |
| 108 | `libcheck_trust.so.5.6.0.1.0` | `check_trust` | `modularization/src/xm_common/check_trust` |
| 146 | `libcurlcpp.so` | `curlcpp` | `modularization/src/xm_common/curlcpp` |
| 161 | `libEFICompress.so` | `eficompress` | `modularization/src/xm_common/efi_compress` |
| 171 | `liberrorcode_manager.so` | `errorcode_manager` | `modularization/src/xm_common/errorcode_manager` |
| 180 | `libfile_client.so` | `file_client` | `modularization/src/xm_common/file_client` |
| 190 | `libglobalconfig.so` | `globalconfig` | `modularization/src/xm_common/global_config` |
| 212 | `libipmanip.so` | `ipmanip` | `modularization/src/xm_common/ipmanip` |
| 213 | `libipmanip.so.5.6` | `ipmanip` | `modularization/src/xm_common/ipmanip` |
| 214 | `libipmanip.so.5.6.0.1.0` | `ipmanip` | `modularization/src/xm_common/ipmanip` |
| 232 | `liblogger.so` | `logger` | `modularization/src/xm_common/logging` |
| 233 | `liblogger.so.5.6` | `logger` | `modularization/src/xm_common/logging` |
| 234 | `liblogger.so.5.6.0.1.0` | `logger` | `modularization/src/xm_common/logging` |
| 371 | `libparsexmlmetadata.so` | `parsexmlmetadata` | `modularization/src/module/update/parse_fw_metadata/xml_metadata` |
| 372 | `libparsexmlmetadata.so.5.6` | `parsexmlmetadata` | `modularization/src/module/update/parse_fw_metadata/xml_metadata` |
| 373 | `libparsexmlmetadata.so.5.6.0.5.6.0` | `parsexmlmetadata` | `modularization/src/module/update/parse_fw_metadata/xml_metadata` |
| 455 | `libRest.so` | `rest` | `modularization/src/common/rest` |
| 461 | `libruntime_store.so` | `runtime_store` | `modularization/src/xm_common/runtime_store` |
| 518 | `libsystem_type.so` | `system_type` | `modularization/src/xm_common/system_type` |
| 531 | `liburi.so` | `uri` | `modularization/src/xm_common/uri` |
| 539 | `libutils.so` | `utils` | `modularization/src/utils` |
| 540 | `libutils.so.5.6` | `utils` | `modularization/src/utils` |
| 541 | `libutils.so.5.6.0.1.0` | `utils` | `modularization/src/utils` |
| 555 | `libxm_crypt.so` | `xm_crypt` | `modularization/src/xm_common/crypt` |

</details>

<details><summary>⚠️ 2 Linux path(s) found but no CMakeLists.txt</summary>

| Row | Col A | Expected target | Resolved dir |
|---|---|---|---|
| 446 | `librepository_tsmodule.so` | `repository_tsmodule` | `onecli/TSModule/onecli-tsmodule/Src/tsmodules` |
| 447 | `librepository_tssystem.so` | `repository_tssystem` | `onecli/TSModule/onecli-tsmodule/Src/tssystem` |

</details>

#### Windows SBOM

| Result | Count |
|---|---|
| ✅ Verified (target matches) | 291 |
| ❌ Mismatch (dir exists, wrong target) | 2 |
| ⚠️ Path missing (dir not found on disk) | 15 |
| ⚠️ Path exists, no CMakeLists.txt | 3 |
| **Total checked** | **311** |

**❌ Windows mismatches — Col D path exists but CMake target does not match Col A:**

| Row | Col A | Expected target | Col D path | Targets found |
|---|---|---|---|---|
| 206 | `onecli_rebootbmc.dll` | `onecli_rebootbmc` | `onecli/Src/Misc/RebootCMM` | `onecli_rebootcmm` |
| 207 | `onecli_rebootcmm.dll` | `onecli_rebootcmm` | `onecli/Src/Misc/RebootIMM` | `onecli_rebootbmc` |

<details><summary>⚠️ 15 Windows path(s) not found on disk</summary>

| Row | Col A | Expected target | Col D path |
|---|---|---|---|
| 61 | `check_trust.dll` | `check_trust` | `modularization/src/xm_common/check_trust` |
| 78 | `curlcpp.dll` | `curlcpp` | `modularization/src/xm_common/curlcpp` |
| 85 | `EFICompress.dll` | `eficompress` | `modularization/src/xm_common/efi_compress` |
| 91 | `errorcode_manager.dll` | `errorcode_manager` | `modularization/src/xm_common/errorcode_manager` |
| 96 | `file_client.dll` | `file_client` | `modularization/src/xm_common/file_client` |
| 102 | `globalconfig.dll` | `globalconfig` | `modularization/src/xm_common/global_config` |
| 115 | `ipmanip.dll` | `ipmanip` | `modularization/src/xm_common/ipmanip` |
| 127 | `logger.dll` | `logger` | `modularization/src/xm_common/logging` |
| 258 | `parsexmlmetadata.dll` | `parsexmlmetadata` | `modularization/src/module/update/parse_fw_metadata/xml_metadata` |
| 303 | `Rest.dll` | `rest` | `modularization/src/xm_common/rest` |
| 307 | `runtime_store.dll` | `runtime_store` | `modularization/src/xm_common/runtime_store` |
| 343 | `system_type.dll` | `system_type` | `modularization/src/xm_common/system_type` |
| 352 | `uri.dll` | `uri` | `modularization/src/xm_common/uri` |
| 358 | `utils.dll` | `utils` | `modularization/src/xm_common/utils` |
| 366 | `xm_crypt.dll` | `xm_crypt` | `modularization/src/xm_common/crypt` |

</details>

<details><summary>⚠️ 3 Windows path(s) found but no CMakeLists.txt</summary>

| Row | Col A | Expected target | Resolved dir |
|---|---|---|---|
| 266 | `pciio.dll` | `pciio` | `modularization/src/module/osinfos/inventory_modules/pciinfo/pciio` |
| 298 | `repository_tsmodule.dll` | `repository_tsmodule` | `onecli/TSModule/onecli-tsmodule/Src/tsmodules` |
| 299 | `repository_tssystem.dll` | `repository_tssystem` | `onecli/TSModule/onecli-tsmodule/Src/tssystem` |

</details>

**Action required:** Verify the source tree is fully checked out (25 Linux / 15 Windows missing dirs likely reside in `xm_common` which may not be in this workspace). Correct Col A / Col D swap for Windows rows 206–207.

---

### 1.8 I/O Package Version Consistency — ❌ ISSUES FOUND (Linux)

**Rule:** For rows where Col D references an I/O bundle (`lnvgy_*` / `intc-*`), the full package name must match the canonical baseline (constant condition) and be consistent across all Target sections.

#### Linux SBOM

| Result | Count |
|---|---|
| ✅ Matches canonical | 38 |
| ❌ Wrong version (family known) | **25** |
| ⚠️ Unknown package family | 3 |
| ⚠️ Internally inconsistent (multiple versions for same binary) | 14 |
| **Total checked** | **66** |

**❌ Wrong package versions (Linux):**

| Row | Col A | Actual package in Col D | Expected package |
|---|---|---|---|
| 41 | `storcli2-008.0016.0000.0011-source.zip` | `lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-ja9bc-00c2_linux_indiv` | `lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-j9abc-0062_windows_indiv` |
| 571 | `fdrvwl` | `lnvgy_fw_drives_all-1.53.02-0_linux_x86-64` | `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64` |
| 572 | `flashdrv.bin` | `lnvgy_fw_drives_all-1.53.02-0_linux_x86-64` | `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64` |
| 573 | `liblddf.so` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 574 | `libmvraid.so` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 575 | `mnv_cli` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 576 | `sizes.bin` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 577 | `storelib.so` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 578 | `storelib8.so` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 579 | `storelibir-3.so` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 580 | `storelibit.so` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 583 | `storcli2` | `lnvgy_utl_storehba_sas4.storcli2-j9mgm-0071_linux_indiv` | `lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-j9abc-0062_windows_indiv` |
| 585 | `libmvraid.so` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 586 | `mnv_cli` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 599 | `liblddf.so` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 600 | `libmvraid.so` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 601 | `mnv_cli` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 602 | `sizes.bin` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 603 | `ssdcli` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 604 | `ssdcli.bin` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 605 | `storelib.so` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 606 | `storelib8.so` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 607 | `storelibir-3.so` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 608 | `storelibit.so` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv` | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 1212 | `storcli2` | `lnvgy_utl_storehba_sas4.storcli2-008.0012.0000.0004-1-ja05o-00a2_linux_indiv` | `lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-j9abc-0062_windows_indiv` |

**⚠️ Internally inconsistent binaries (same binary name, multiple package versions in SBOM):**

| Col A binary | Package refs found |
|---|---|
| `arcconf` | `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64`<br>`lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv`<br>`lnvgy_utl_storage-adapter_smartpqi.arcconf-27449-j9vpb-0311_linux_indiv`<br>`lnvgy_utl_storage-adapter_smartpqi.arcconf.450-27147-j9mn3-0031_linux_indiv` |
| `fdrvwl` | `lnvgy_fw_drives_all-1.53.02-0_linux_x86-64`<br>`lnvgy_fw_drives_all-1.55.08-0_linux_x86-64` |
| `flashdrv.bin` | `lnvgy_fw_drives_all-1.53.02-0_linux_x86-64`<br>`lnvgy_fw_drives_all-1.55.08-0_linux_x86-64` |
| `liblddf.so` | `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64`<br>`lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv`<br>`lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| `libmvraid.so` | `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64`<br>`lnvgy_utl_bootstor_sata.mvcli-2.3.10.1095-0_linux_x86-64`<br>`lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv`<br>`lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| `mnv_cli` | `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64`<br>`lnvgy_utl_bootstor_nvme.mnvcli-j9lng-00c1_linux_indiv`<br>`lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv`<br>`lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| `sizes.bin` | `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64`<br>`lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv`<br>`lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| `ssdcli` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv`<br>`lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| `ssdcli.bin` | `lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv`<br>`lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| `storcli2` | `lnvgy_utl_storehba_sas4.storcli2-008.0012.0000.0004-1-ja05o-00a2_linux_indiv`<br>`lnvgy_utl_storehba_sas4.storcli2-j9mgm-0071_linux_indiv` |
| `storelib.so` | `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64`<br>`lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv`<br>`lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| `storelib8.so` | `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64`<br>`lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv`<br>`lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| `storelibir-3.so` | `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64`<br>`lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv`<br>`lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| `storelibit.so` | `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64`<br>`lnvgy_utl_drives_all.ss.wg-250411-j9vpb-01d1_linux_indiv`<br>`lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |

<details><summary>⚠️ 3 Linux references with unknown package family (not in canonical baseline)</summary>

| Row | Col A | Package referenced |
|---|---|---|
| 568 | `arcconf` | `lnvgy_utl_storage-adapter_smartpqi.arcconf.450-27147-j9mn3-0031_linux_indiv` |
| 570 | `arcconf` | `lnvgy_utl_storage-adapter_smartpqi.arcconf.450-27147-j9mn3-0031_linux_indiv` |
| 598 | `arcconf` | `lnvgy_utl_storage-adapter_smartpqi.arcconf.450-27147-j9mn3-0031_linux_indiv` |

</details>

#### Windows SBOM

✅ All 37 I/O package references match the canonical baseline. No issues.

---

### 1.9 OSS Source Archive Presence — ❌ ISSUES FOUND

**Rule:** For every row where Col E starts with `1/` (source distribution section), a corresponding compressed source archive must be present in Col A (e.g. `openssl-3.6.0.tar.gz`, `pegasus-2.14.1.zip`).

| Platform | ✅ Archive present | ❌ Archive missing | Total `1/` libs |
|---|---|---|---|
| Linux | 0 | **9** | 9 |
| Windows | 0 | **9** | 9 |

**❌ Linux — all 9 OSS components missing source archive:**

| Row | Col A (component) | Col E path |
|---|---|---|
| 611 | `boost` | `1/boost` |
| 613 | `curl` | `1/curl` |
| 619 | `libssh2` | `1/libssh2` |
| 1126 | `openssl` | `1/openssl` |
| 1129 | `pegasus` | `1/pegasus` |
| 1167 | `snmp++` | `1/snmp++` |
| 1169 | `tsmodule` | `1/tsmodule` |
| 1170 | `websocket++` | `1/websocket++` |
| 1171 | `zlib` | `1/zlib` |

**❌ Windows — all 9 OSS components missing source archive:**

| Row | Col A (component) | Col E path |
|---|---|---|
| 436 | `boost` | `1/boost` |
| 437 | `curl` | `1/curl` |
| 442 | `libssh2` | `1/libssh2` |
| 953 | `openssl` | `1/openssl` |
| 956 | `pegasus` | `1/pegasus` |
| 992 | `snmp++` | `1/snmp++` |
| 996 | `tsmodule` | `1/tsmodule` |
| 997 | `websocket++` | `1/websocket++` |
| 998 | `zlib` | `1/zlib` |

**Action required:** Add a compressed source archive row in Col A for each library (e.g. `boost-1.86.0.tar.gz`, `curl-8.17.0.tar.gz`, `zlib-1.3.1.tar.gz`, etc.) in the `1/` section of both SBOMs.

**Windows — FIXED (2026-05-14):** All 9 archive rows added; blowfish (I/O-sourced for qcccli) and openssl 3.1.5 (I/O-sourced for storcli2) standalone rows added. See `-reviewed.xlsx`.

---

### 1.10 I/O License Col A Completeness — ⚠️ NEW CHECK (Windows identified 2026-05-14)

**Rule:** When an I/O tool row (Col A = `lnvgy_*` / `intc-*`) references an OSS component in Col D (e.g. `"openssl (3.1.5)"`), a corresponding standalone OSS entry row must also exist where:
- Col A = OSS component name (e.g. `openssl`)
- Col B = version
- Col C = SPDX license
- Col D = upstream URL
- Col E = the I/O tool package name (identifies which I/O tool bundles this OSS)

**Why:** Without a standalone OSS row, the I/O-bundled component is invisible to automated license scanners and the compliance checklist cannot verify its license or version. Col D of the I/O tool row alone is insufficient — it must be paired with a Col A OSS entry row.

**Windows 5.6.0 — rows added (2026-05-14):**

| OSS Component | Version | License | I/O Tool (Col E) |
|---|---|---|---|
| `openssl` | `3.1.5` | `Apache-2.0` | `lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-ja9bc-0062_windows_indiv` |
| `blowfish` | `master` | `LGPL-2.1` | `qcccli-3.0.00-04` |

**TODO — add Check 1.10 to `sbom_review.py`:** Detect I/O tool rows whose Col D contains `"<lib> (<ver>)"` but no corresponding standalone Col A row exists for that lib/version.

---

## Section 2: Version Correctness

Reference: `version_audit_5.6.0.log` (generated 2026-05-12)

### 2.0 Official Version Reference (LXCE_OSS_Ver._info — 5.6.0/14.6.0)

Verified against Lenovo official release version table (`LXCE_OSS_Ver._info.png`, reviewed 2026-05-14).  
This table is authoritative for resolving SBOM vs. extlibs version discrepancies.

| 3rd Party OSS | Official Version (5.6.0/14.6.0) |
|---|---|
| tsmodule | 5.0.0 |
| boost | 1.86.0 |
| curl | 8.17.0 |
| edk2/EdkCompatibilityPkg | UDK2008 |
| electron | 39.2.6 (out of scope — BoMC/UpdateXpress) |
| libssh2 | 1.11.1 |
| Microsoft Visual C++ Runtime (OneCLI) | 2019 |
| openssl | 3.6.0 |
| pegasus | 2.14.1 |
| qcccli | 3.0.00-04 |
| snmp++ | 3.3.10 |
| sorttable | 2 |
| websocketpp | 0.8.x-dev. |
| zlib | 1.3.1 |
| pthreads-w32 | 2.9.1 |

> **Note:** curl 8.17.0, zlib 1.3.1, and pthreads-w32 2.9.1 are the **intentional project versions** for this release.  
> The extlibs header differences (8.19.0 / 1.3.2 / 2.8.0) represent build-environment drift that has been reviewed and accepted by the project team.

### 2.1 Linux SBOM

| Library | SBOM Declares | Official Ref | Audit Status | Finding |
|---|---|---|---|---|
| boost | 1.86.0 | 1.86.0 | ✅ OK | Matches |
| curl | 8.17.0 | 8.17.0 | ✅ CONFIRMED | Intentional project version per official ref table |
| libssh2 | 1.11.1 | 1.11.1 | ✅ OK | Matches |
| openssl | 3.6.0, 3.1.5 | 3.6.0 | ⚠️ NOTE | 3.6.0 is correct; 3.1.5 entry is storcli2-bundled openssl — approved |
| pegasus | 2.14.1 | 2.14.1 | ✅ OK | Matches |
| snmp++ | 3.3.10 | 3.3.10 | ✅ OK | Matches |
| websocket++ | 0.8.3 | 0.8.x-dev. | ⚠️ MISMATCH | SBOM drops `-dev` suffix; official ref uses `0.8.x-dev.` |
| zlib | 1.3.1 | 1.3.1 | ✅ CONFIRMED | Intentional project version per official ref table |

### 2.2 Windows SBOM

| Library | SBOM Declares | Official Ref | Audit Status | Finding |
|---|---|---|---|---|
| boost | 1.86.0 | 1.86.0 | ✅ OK | Matches |
| curl | 8.17.0 | 8.17.0 | ✅ CONFIRMED | Intentional project version per official ref table |
| libssh2 | 1.11.1 | 1.11.1 | ✅ OK | Matches |
| openssl | 3.6.0, 3.4.0, 3.1.5 | 3.6.0 | ⚠️ ACTION | 3.6.0 correct; 3.1.5 (row 1009) is storcli2-bundled — approved; 3.4.0 (rows 451, 955, 981) is stale — must be removed |
| pegasus | 2.14.1 | 2.14.1 | ✅ OK | Matches |
| pthreads-w32 | 2.9.1 | 2.9.1 | ✅ CONFIRMED | Intentional project version per official ref table |
| websocket++ | 0.8.3 | 0.8.x-dev. | ⚠️ MISMATCH | SBOM drops `-dev` suffix; official ref uses `0.8.x-dev.` |
| zlib | 1.3.1 | 1.3.1 | ✅ CONFIRMED | Intentional project version per official ref table |

> **Note — electron:** electron (39.2.6) appears in `version_audit_5.6.0.log` but belongs to BoMC / UpdateXpress, **not OneCLI**. It is out of scope for this SBOM and correctly absent.

### 2.3 Duplicate / Multi-Version Entries

| Library | Platform | Versions present | Action |
|---|---|---|---|
| boost | Linux + Windows | 1.86.0, 1.83.0 | Remove stale 1.83.0 entry |
| openssl | Linux | 3.6.0, 3.1.5 | **Keep 3.1.5** — storcli2-bundled, approved; no other stale entries |
| openssl | Windows | 3.6.0, 3.4.0, 3.1.5 | Remove stale 3.4.0 (rows 451, 955, 981); **keep 3.1.5** (row 1009 — storcli2-bundled, approved) |

---

## Section 3: License Classification

### 3.1 Permissive Licenses — Low Obligation

| License | Components | Key Obligation |
|---|---|---|
| BSL-1.0 | Boost 1.86.0 | Include license text in distribution |
| Apache-2.0 | OpenSSL 3.6.0 | Include NOTICE file if present; include license text |
| curl (MIT-like) | libcurl 8.17.0 | Include copyright notice |
| BSD-3-Clause | libssh2 1.11.1, WebSocket++ 0.8.3-dev | Include copyright notice + license text |
| Zlib | zlib 1.3.1 | Include copyright notice in docs |
| MIT | OpenPegasus 2.14.1 | Include copyright notice + license text |
| HP/Katz permissive | snmp++ 3.3.10 | Include copyright notice; royalty-free |

**No GPL or LGPL components detected** in OneCLI runtime dependencies. No copyleft propagation risk.

> **Note — I/O tool sections:** glibc 2.34 (LGPL-3.0) and pthreads-w32 2.9.1 (LGPL-2.0-or-later) appear in the storcli2/mvcli `utilities/` sections and are I/O-sourced (not OneCLI-linked). See Section 8 Check 1i for the full I/O tool license map.

### 3.2 Proprietary / Non-OSS

| Component | License | Note |
|---|---|---|
| storcli source zips | Broadcom proprietary | Redistribution requires Broadcom authorization (CP-14 pending) |
| OneCLI core | Lenovo proprietary | IBM IPLA (non-warranted programs) |

---

## Section 4: Checkpoint Findings

| CP | Status | Finding |
|---|---|---|
| CP-01 | ✅ PASS | All distributed packages identified in SBOM |
| CP-02 | ⚠️ GAP | snmp++ 3.3.10: non-standard SPDX ID — use `LicenseRef-snmppp-HP-Katz`. storcli/storcli2: license confirmation from Broadcom pending |
| CP-03 | ⚠️ GAP | websocket++ version recorded as `0.8.3` (missing `-dev` suffix); OpenPegasus exact patch version should be confirmed |
| CP-04 | ⚠️ GAP | Source archives for all 9 OSS libs missing from `1/` section in both SBOMs (see Section 1.9) |
| CP-05 | ✅ PASS | No GPL components in runtime dependencies |
| CP-06 | ✅ PASS | No LGPL components in OneCLI runtime; I/O tool LGPL (glibc, pthreads-w32) is I/O-sourced — check CP-06 with I/O tool team |
| CP-07 | ✅ N/A | No LGPL-2.1-only components |
| CP-08 | ✅ N/A | No LGPL tier-2 evidence required |
| CP-09 | ⚠️ GAP | Copyright notices for snmp++ and OpenPegasus need verification in distribution package |
| CP-10 | ⚠️ GAP | License texts for snmp++ and OpenPegasus must be included in distribution |
| CP-11 | ✅ PASS | CMake dependency graph complete |
| CP-12 | ⚠️ PARTIAL | Boost unused sub-libraries confirmed (2026-05-14 scan): cobalt ❌ unused, container ❌ unused (both platforms); locale ⚠️ 1 Windows-only file; atomic ✅ used (OneCli.exe + 2 unit tests) — no SBOM change required |
| CP-13 | ⚠️ GAP | Third-party notices document needs update to reflect current library versions |
| CP-14 | ⚠️ PENDING | storcli redistribution rights — written Broadcom sign-off required |
| CP-15 | N/A | Tier-3 (XCC binary scan) not in scope |

---

## Section 5: Action Items (Priority Order)

### HIGH — Must fix before OSC submission

| # | Area | Platform | Issue | Action |
|---|---|---|---|---|
| H-1 | Col A headers | Linux | 13/13 section headers use `…onecli01d-5.6.0_linux_indiv` in `*BUILD OUTPUT` Col A | Find-and-replace → `lnvgy_utl_lxce_onecli_linux_x86-64` (Section 1.3) |
| H-2 | Col A headers | Windows | 14/14 section headers use `…onecli01d-5.6.0_windows_indiv` in `*BUILD OUTPUT` Col A | Find-and-replace → `lnvgy_utl_lxce_onecli_winsrv_x86-64` (Section 1.3) |
| H-3 | Col E path | Linux | 577/578 Target rows use `…onecli01d-5.6.0_linux_indiv` in Col E | Find-and-replace → `lnvgy_utl_lxce_onecli_linux_x86-64` (Section 1.2) |
| H-4 | Col E path | Windows | 382/383 Target rows use `…onecli01d-5.6.0_windows_indiv` in Col E | Find-and-replace → `lnvgy_utl_lxce_onecli_winsrv_x86-64` (Section 1.2) |
| H-5 | Col D folder | Linux | Rows 23–25 — Col D uses version-specific path | Change to `see "Target/lnvgy_utl_lxce_onecli_linux_x86-64"` (Section 1.4) |
| H-6 | Col D folder | Windows | Rows 23–24 — Col D uses version-specific path | Change to `see "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64"` (Section 1.4) |
| H-7 | Col F empty | Linux | Rows 25, 32–37, 39, 561, 562 — Col F blank | Fill per table in Section 1.5 |
| H-8 | Col F empty | Windows | Rows 80, 265, 371, 372, 414 — Col F blank | Fill per table in Section 1.5 |
| H-9 | Col D boost | Linux | 141 rows missing `; "boost"` annotation in Col D | Append `; "boost"` for each row in Section 1.6 |
| H-10 | Col D boost | Windows | 11 rows missing `; "boost"` annotation in Col D | Append `; "boost"` for each row in Section 1.6 |
| H-11 | Col A/D mismatch | Windows | Row 206: `onecli_rebootbmc.dll` — target found is `onecli_rebootcmm`; Row 207 reversed | Swap Col A names or Col D paths (Section 1.7) |
| H-12 | I/O pkg version | Linux | 25 rows with wrong `lnvgy_*` / `intc-*` package version in Col D | Update each Col D to canonical package per table in Section 1.8 |
| H-13 | I/O pkg inconsistency | Linux | 14 binaries with multiple package versions across sections | Standardize all Col D refs to canonical package (Section 1.8) |
| H-14 | Src archive missing | Linux | All 9 OSS libs in `1/` section lack source archive in Col A | Add `{lib}-{version}.tar.gz` row to `1/` section (Section 1.9) |
| H-15 | Src archive missing | Windows | All 9 OSS libs in `1/` section lack source archive in Col A | Add `{lib}-{version}.tar.gz` row to `1/` section (Section 1.9) |
| H-16 | Version drift | Linux + Windows | ~~curl: SBOM = 8.17.0, extlibs = 8.19.0~~ | ✅ CLOSED — 8.17.0 confirmed as intentional project version per official ref table |
| H-17 | Version drift | Linux + Windows | ~~zlib: SBOM = 1.3.1, extlibs = 1.3.2~~ | ✅ CLOSED — 1.3.1 confirmed as intentional project version per official ref table |
| H-18 | Version drift | Windows | ~~pthreads-w32: SBOM = 2.9.1, source header = 2.8.0~~ | ✅ CLOSED — 2.9.1 confirmed as intentional project version per official ref table |
| H-19 | Version mismatch | Linux + Windows | websocket++: SBOM = `0.8.3`, official ref = `0.8.x-dev.` | Update SBOM to `0.8.3-dev` to match official ref and extlibs suffix |
| H-20 | CP-14 | Linux | storcli redistribution | Obtain written Broadcom authorization |
| H-21 | Col D path | Windows | Row 258: `parsexmlmetadata.dll` — Col D path stale after xm_common re-org | Change to `see "modularization/src/module/update/query_package/xml_metadata"` (Section 7.3) |
| H-22 | I/O source entries missing | **Windows only** | 9 I/O tool packages have binary sub-entries in `Target/utilities/*` but **zero** corresponding source entries in the `1/` section — gap not present in Linux SBOM | **Dev team action:** Ensure Windows build pipeline captures I/O tool source paths in `1/` section (same pattern as Linux). See Section 7.5 for full component list. |

### MEDIUM — Fix before final approval

| # | Area | Platform | Issue | Action |
|---|---|---|---|---|
| M-1 | Duplicate versions | Linux | openssl: 3.6.0 + 3.1.5 | Keep 3.1.5 (storcli2-bundled, approved); no stale entries remain |
| M-2 | Duplicate versions | Windows | openssl: 3.6.0 + 3.4.0 + 3.1.5 | Remove stale 3.4.0 (rows 451, 955, 981); keep 3.1.5 row 1009 (storcli2-bundled, approved) |
| M-3 | Duplicate versions | Linux + Windows | boost: 1.86.0 + 1.83.0 | Remove stale 1.83.0 entry |
| M-4 | Version drift | Linux + Windows | openssl: SBOM = 3.6.0, extlibs = 3.6.2 | Confirm patch-level drift is policy-acceptable |
| M-5 | Col D path missing | Linux | 25 rows — source dir not found on disk | Verify source tree (`xm_common`) is fully checked out (Section 1.7) |
| M-6 | Col D path missing | Windows | 15 rows — source dir not found on disk | Verify source tree (`xm_common`) is fully checked out (Section 1.7) |
| M-7 | CP-02 | Linux | snmp++ SPDX ID non-standard | Assign `LicenseRef-snmppp-HP-Katz` in SBOM (Section 4) |
| M-8 | CP-13 | Linux + Windows | Third-party notices not updated | Regenerate TPN with current library versions (Section 4) |
| M-9 | CP-12 | Linux + Windows | Boost unused sub-libraries — scan complete | cobalt ❌ unused, container ❌ unused (both platforms); locale ⚠️ 1 Windows file; atomic ✅ used — no SBOM change required |

### LOW — Recommended follow-up

| # | Area | Issue | Action |
|---|---|---|---|
| L-1 | Version doc | `3rd_party_license_windows.txt` has outdated versions | Sync with current extlibs headers |
| L-2 | FOSSA scan | Multiple zlib/curl/openssl versions in `extlibs/src/` | Review extlibs/src/ lifecycle; consider FOSSA path exclusion |
| L-3 | CP-03 | OpenPegasus version only "2.14.1" — no patch sub-version confirmed | Pin exact version |

---

## Section 6: NTIA SBOM Minimum Elements

| NTIA Element | Status |
|---|---|
| Supplier name | ✅ Identified for all components |
| Component name | ✅ Complete |
| Version | ⚠️ websocket++ missing `-dev`; openssl/boost have stale duplicate entries |
| Unique identifier (PURL) | ⚠️ Not yet assigned |
| Dependency relationship | ✅ Direct vs. transitive determined |
| Author of SBOM data | ⚠️ Must be added to final SBOM |
| Timestamp | ✅ Present (scan date in metadata) |
| License expression (SPDX) | ⚠️ snmp++ needs `LicenseRef-`; storcli needs Broadcom confirmation |

---

## Section 7: Windows SBOM Extended Analysis (2026-05-14)

### 7.1 Issue 3 Extended — Boost Sub-Library Breakdown (Windows DLLs)

For each of the 11 Windows DLLs missing boost annotation (Col D), the specific Boost sub-libraries linked:

| DLL (Col A) | Boost Libraries Used | Col D (after fix) |
|---|---|---|
| `bmu_env.dll` | chrono, json, system, thread | `see "modularization/src/common/bmu_env"; "boost"` |
| `cmm.dll` | system | `see "modularization/src/module/xm_cim/cmm/inventory_update"; "boost"` |
| `cmmffdc.dll` | program_options | `see "modularization/src/module/xm_cim/cmm/ffdc"; "boost"` |
| `curlcpp.dll` | filesystem, system | `see "modularization/src/xm_common/curlcpp"; "boost"` |
| `file_client.dll` | filesystem, system | `see "modularization/src/xm_common/file_client"; "boost"` |
| `file_transfer.dll` | date_time, filesystem, system, thread | `see "onecli/Src/Utility/file_transfer"; "boost"` |
| `iolog.dll` | filesystem | `see "modularization/src/module/update/io_log"; "boost"` |
| `onecli_update_rollback.dll` | date_time, filesystem, system | `see "onecli/Src/apps/update/rollback"; "boost"` |
| `pcidevice.dll` | filesystem, regex | `see "modularization/src/module/osinfos/pcidevice"; "boost"` |
| `RemoteController.dll` | filesystem, regex, system | `see "modularization/src/common/remote_controller"; "boost"` |
| `secure_erase.dll` | chrono, filesystem, regex, system, thread | `see "modularization/src/module/misc/secure_erase"; "boost"` |

### 7.2 Boost Sub-Library Usage Summary (Both Platforms)

| Boost Sub-Library | Used in Project | # CMake Files | Notes |
|---|---|---|---|
| system | ✅ | 114 | Most widely used |
| filesystem | ✅ | 91 | Core dependency |
| regex | ✅ | 73 | |
| thread | ✅ | 70 | |
| json | ✅ | 56 | |
| program_options | ✅ | 17 | |
| date_time | ✅ | 14 | |
| chrono | ✅ | 8 | |
| unit_test_framework | ✅ | 1 | Test targets only |
| atomic | ✅ | 3 | `OneCli.exe` + 2 unit test CMake files |
| **locale** | ⚠️ | 1 | Windows-only: `onecli/Src/Misc/Ux/network/win32/iphelpimplement.cpp` |
| **cobalt** | ❌ | 0 | In extlibs prebuilt (both platforms) — zero project source references |
| **container** | ❌ | 0 | In extlibs prebuilt (both platforms) — zero project source references |

> `cobalt` and `container` are distributed as part of the Boost 1.86.0 prebuilt package in `extlibs/` for both Linux and Windows, but are never explicitly linked or included in project source code. No additional license obligation is triggered by their passive presence.

### 7.3 xm_common Directory Re-org — Path Verification Result

After developer re-organization of `modularization/src/xm_common/`, 14 of the 15 previously-flagged "path not found" warnings are now resolved:

| Row | DLL | Status |
|---|---|---|
| 61 | `check_trust.dll` | ✅ Resolved — path exists with CMakeLists.txt |
| 78 | `curlcpp.dll` | ✅ Resolved |
| 85 | `EFICompress.dll` | ✅ Resolved |
| 91 | `errorcode_manager.dll` | ✅ Resolved |
| 96 | `file_client.dll` | ✅ Resolved |
| 102 | `globalconfig.dll` | ✅ Resolved |
| 115 | `ipmanip.dll` | ✅ Resolved |
| 127 | `logger.dll` | ✅ Resolved |
| 303 | `Rest.dll` | ✅ Resolved |
| 307 | `runtime_store.dll` | ✅ Resolved |
| 343 | `system_type.dll` | ✅ Resolved |
| 352 | `uri.dll` | ✅ Resolved |
| 358 | `utils.dll` | ✅ Resolved |
| 366 | `xm_crypt.dll` | ✅ Resolved |
| **258** | **`parsexmlmetadata.dll`** | ⚠️ **MOVED** — Col D path requires update (see H-21) |

**Row 258 Col D correction required:**

| | Value |
|---|---|
| Current (stale) | `see "modularization/src/module/update/parse_fw_metadata/xml_metadata"` |
| Correct (after re-org) | `see "modularization/src/module/update/query_package/xml_metadata"` |

### 7.4 Issue 7 — Source Archives (Deferred)

9 OSS libraries are missing source archive entries in Col A for both Linux and Windows SBOMs:
`boost`, `curl`, `libssh2`, `openssl`, `pegasus`, `snmp++`, `tsmodule`, `websocket++`, `zlib`

**Decision:** Dev team will perform a full FOSSA re-scan to generate updated Col A source archive entries. No manual edit to be applied. Tracked as H-14/H-15.

---

### 7.5 H-22 — Windows I/O Source Entries Missing ❌ WINDOWS-ONLY GAP (2026-05-14)

**Finding:** The Windows SBOM contains binary sub-entries for 9 I/O tool packages under `Target/utilities/*` sections but has **no corresponding `1/` section** capturing their source distributions. The Linux SBOM correctly includes `1/utilities/ssd`, `1/utilities/vroc`, `1/utilities/lsi`, etc. with source archive and OSS attribution rows. Windows has none.

**⚠️ Dev team reminder: Windows build pipeline must be aligned with Linux to capture I/O tool source paths in the `1/` section. This is a compliance gap — I/O tools bundling OSS (e.g., openssl, blowfish) must have their source origins documented in the SBOM.**

#### Affected I/O Packages (Windows `Target/utilities/*` — no `1/` counterpart)

| I/O Package (Col A) | Windows Section | Linux Equivalent |
|---|---|---|
| `intc-lnvgy_fw_pmem_pm200-*` | `Target/utilities/pmem` | `1/utilities/pmem` |
| `intc-lnvgy_utl_swraid_vroc.cli-*` | `Target/utilities/vroc` | `1/utilities/vroc` |
| `lnvgy_fw_drives_all-*` | `Target/utilities/ssd` | `1/utilities/ssd` |
| `lnvgy_utl_bootstor_nvme.mnvcli-*` | `Target/utilities/bootstor` | `1/utilities/bootstor` |
| `lnvgy_utl_bootstor_sata.mvcli-*` | `Target/utilities/bootstor` | `1/utilities/bootstor` |
| `lnvgy_utl_drives_all-*` | `Target/utilities/ssd` | `1/utilities/ssd` |
| `lnvgy_utl_raid_mr3.storcli-*` | `Target/utilities/lsi` | `1/utilities/lsi` |
| `lnvgy_utl_storage-adapter_smartpqi.arcconf-*` | `Target/utilities/smartpqi` | `1/utilities/smartpqi` |
| `lnvgy_utl_storehba_sas4.storcli2-*` | `Target/utilities/lsi` | `1/utilities/lsi` |

#### OSS at Risk (already in Windows SBOM via I/O source rows — need `1/` section confirmation)

| OSS Component | Version | License | I/O Package | Compliance Risk |
|---|---|---|---|---|
| openssl | 3.1.5 | Apache-2.0 | storcli2 | Low — Apache-2.0, but source offer completeness |
| blowfish | master | LGPL-2.1 | qcccli-3.0.00-04 | **Medium — LGPL: linking/source obligations** |

#### Required Action

1. **I/O vendor coordination:** Each I/O vendor must supply source packages or FOSSA evidence for the Windows build of their tool.
2. **SBOM update:** Dev team to add `1/utilities/<section>/` entries for each I/O package in the Windows SBOM (mirroring the Linux structure).
3. **LGPL verification (blowfish):** Confirm `qcccli` dynamically links blowfish on Windows — CP-06 obligations apply.
4. **Next release gate:** Make `1/` section completeness a mandatory SBOM acceptance check for both platforms before OSC sign-off.

---

## Section 8: Automated Check Evidence (sbom_review.py)

*Auto-generated by `sbom_review.py` on 2026-05-14. Section contains raw per-check output for both Linux and Windows SBOMs.*

---

### Linux SBOM

**Product:** lnvgy_utl_lxce_onecli_linux_indiv 5.6.0-01d  
**Scan date:** 5/7/2026  
**Components scanned:** 1203 total / 570 OSS  

#### Check 1 — Format Validation

| Item | Value |
|---|---|
| Target sections found | 14 |
| Total data rows | 1191 |
| Orphan rows (name, no path) | 0 |
| Reversed orphan rows (path, no name) | 0 |
| `see below` license refs | 563 |

✅ No format issues detected.

#### Check 1c — Col E (Path) Version-Specific Folder

✅ All Col E paths use the constant folder name.

#### Check 1d — Col A (Section Headers) Version-Specific Folder

✅ All section headers use the constant folder name.

#### Check 1a — Col D (Link) Folder Name Consistency

Expected Col D: `see "Target/lnvgy_utl_lxce_onecli_linux_x86-64"`

✅ All top-level package entries use the correct constant folder name in Col D.

#### Check 1e — Col D Boost Annotation

❌ **15 row(s) missing boost annotation in Col D** (out of 552 `.so`/`.dll` rows checked):

| Row | Col A | CMake Target | Col D (current) |
|---|---|---|---|
| 396 | `libPowerManagement.so` | `powermanagement` | `see "modularization/src/module/xfw/power_management"` |
| 397 | `libPowerManagement.so.5.6` | `powermanagement` | `see "modularization/src/module/xfw/power_management"` |
| 398 | `libPowerManagement.so.5.6.0.1.0` | `powermanagement` | `see "modularization/src/module/xfw/power_management"` |
| 429 | `libRedfishConfig.so` | `redfishconfig` | `see "modularization/src/module/xfw/RedfishConfig"` |
| 430 | `libRedfishConfig.so.5.6` | `redfishconfig` | `see "modularization/src/module/xfw/RedfishConfig"` |
| 431 | `libRedfishConfig.so.5.6.0.1` | `redfishconfig` | `see "modularization/src/module/xfw/RedfishConfig"` |
| 432 | `libRedfishConfigAction.so` | `redfishconfigaction` | `see "modularization/src/module/xfw/RedfishConfig/RedfishConf…` |
| 433 | `libRedfishConfigAction.so.5.6` | `redfishconfigaction` | `see "modularization/src/module/xfw/RedfishConfig/RedfishConf…` |
| 434 | `libRedfishConfigAction.so.5.6.0.1` | `redfishconfigaction` | `see "modularization/src/module/xfw/RedfishConfig/RedfishConf…` |
| 435 | `libRedfishConfigAssistant.so` | `redfishconfigassistant` | `see "modularization/src/module/xfw/RedfishConfig/RedfishAssi…` |
| 436 | `libRedfishConfigAssistant.so.5.6` | `redfishconfigassistant` | `see "modularization/src/module/xfw/RedfishConfig/RedfishAssi…` |
| 437 | `libRedfishConfigAssistant.so.5.6.0.1` | `redfishconfigassistant` | `see "modularization/src/module/xfw/RedfishConfig/RedfishAssi…` |
| 438 | `libRedfishConfigCommon.so` | `redfishconfigcommon` | `see "modularization/src/module/xfw/RedfishConfig/CommonProc"` |
| 439 | `libRedfishConfigCommon.so.5.6` | `redfishconfigcommon` | `see "modularization/src/module/xfw/RedfishConfig/CommonProc"` |
| 440 | `libRedfishConfigCommon.so.5.6.0.1` | `redfishconfigcommon` | `see "modularization/src/module/xfw/RedfishConfig/CommonProc"` |

#### Check 1f — Col A ↔ Col D Source Path Verification

| Result | Count |
|---|---|
| ✅ Verified (target matches) | 464 |
| ❌ Mismatch (dir exists, wrong target) | 0 |
| ⚠️ Path missing (dir not found) | 7 |
| ⚠️ No CMakeLists.txt | 2 |
| Total checked | 473 |

<details><summary>⚠️ 7 path(s) not found on disk</summary>

| Row | Col A | Expected target | Col D path |
|---|---|---|---|
| 371 | `libparsexmlmetadata.so` | `parsexmlmetadata` | `modularization/src/module/update/parse_fw_metadata/xml_metadata` |
| 372 | `libparsexmlmetadata.so.5.6` | `parsexmlmetadata` | `modularization/src/module/update/parse_fw_metadata/xml_metadata` |
| 373 | `libparsexmlmetadata.so.5.6.0.5.6.0` | `parsexmlmetadata` | `modularization/src/module/update/parse_fw_metadata/xml_metadata` |
| 455 | `libRest.so` | `rest` | `modularization/src/common/rest` |
| 539 | `libutils.so` | `utils` | `modularization/src/utils` |
| 540 | `libutils.so.5.6` | `utils` | `modularization/src/utils` |
| 541 | `libutils.so.5.6.0.1.0` | `utils` | `modularization/src/utils` |

</details>

<details><summary>⚠️ 2 path(s) found but no CMakeLists.txt</summary>

| Row | Col A | Expected target | Resolved dir |
|---|---|---|---|
| 447 | `librepository_tsmodule.so` | `repository_tsmodule` | `onecli/TSModule/onecli-tsmodule/Src/tsmodules` |
| 448 | `librepository_tssystem.so` | `repository_tssystem` | `onecli/TSModule/onecli-tsmodule/Src/tssystem` |

</details>

#### Check 1g — I/O Package Version Consistency

| Result | Count |
|---|---|
| ✅ Matches canonical | 49 |
| ❌ Wrong version (family known) | 15 |
| ⚠️ Unknown package family | 5 |
| ⚠️ Internally inconsistent (multiple versions) | 11 |
| Total checked | 69 |

**❌ Wrong package versions:**

| Row | Col A | Actual package | Expected package |
|---|---|---|---|
| 41 | `storcli2-008.0016.0000.0011-source.zip` | `lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-ja9bc-00c2_linux_indiv` | `lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-j9abc-0062_windows_indiv` |
| 571 | `fdrvwl` | `lnvgy_fw_drives_all-1.53.02-0_linux_x86-64` | `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64` |
| 572 | `flashdrv.bin` | `lnvgy_fw_drives_all-1.53.02-0_linux_x86-64` | `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64` |
| 573–580 | _(8 rows)_ | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv ` (trailing space) | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 583 | `storcli2` | `lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-ja9bc-0062_windows_indiv` | `lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-j9abc-0062_windows_indiv` |
| 585–586 | _(2 rows)_ | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv ` (trailing space) | `lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv` |
| 1221 | `storcli2` | `lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-ja9bc-0062_windows_indiv` | `lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-j9abc-0062_windows_indiv` |

**⚠️ Internally inconsistent binaries (same binary, multiple package versions):** see Section 1.8 table.

<details><summary>⚠️ 5 reference(s) with unknown package family (not in canonical baseline)</summary>

| Row | Col A | Package referenced |
|---|---|---|
| 23 | `lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv.tg` | `lnvgy_utl_lxce_onecli_linux_x86-64` |
| 24 | `lnvgy_utl_lxceb_onecli01d-5.6.0_linux_indiv.b` | `lnvgy_utl_lxce_onecli_linux_x86-64` |
| 25 | `lnvgy_utl_lxcer_onecli01d-5.6.0_linux_indiv.r` | `lnvgy_utl_lxce_onecli_linux_x86-64` |
| 568 | `arcconf` | `lnvgy_utl_storage-adapter_smartpqi.arcconf.450-27147-j9mn3-0031_linux_indiv` |
| 570 | `arcconf` | `lnvgy_utl_storage-adapter_smartpqi.arcconf.450-27147-j9mn3-0031_linux_indiv` |

</details>

#### Check 1h — OSS Source Archive Presence

| Result | Count |
|---|---|
| ✅ Source archive present | 6 |
| ❌ Source archive missing | 3 |
| Total `1/` libs checked | 9 |

**❌ OSS components in `1/` section with no source archive:**

| Row | Col A (component) | Col E path |
|---|---|---|
| 1168 | `snmp++` | `1/snmp++` |
| 1170 | `tsmodule` | `1/tsmodule` |
| 1175 | `websocket++` | `1/websocket++` |

#### Check 1i — I/O Tool License Map

I/O tools identified by Col A matching `lnvgy_*`/`intc-*` with a version in Col B.  
OSS dependencies are rows whose Col D references the same I/O tool package.

##### `lnvgy_fw_drives_all-1.55.08-0_linux_x86-64`

| Field | Value |
|---|---|
| Version | `1.55.08-0` |
| License | PROPRIETARY |
| Section | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/utilities/ssd"` |

**Bundled OSS dependencies:**

| Component | Version | License |
|---|---|---|
| `Cajun C++ API for Java Script Object Notation` | `2.0.2` | BSD-3-Clause |
| `EDK II` | `1.28` | BSD-2-Clause |
| `edk2/EdkCompatibilityPkg` | `UDK2008` | BSD-3-Clause; BSD-2-Clause |
| `glibc` | `2.34` | **LGPL-3.0** ⚠️ |
| `ipmctl` | `02.00.00.4040-1.el8` | BSD-3-Clause |
| `ipmiutil` | `2.9.3` | BSD-3-Clause; BSD-2-Clause; Zlib |
| `openssl` | `3.1.5` | Apache-2.0 |
| `pthreads-w32` | `2.9.1` | NOT DISTRIBUTED |
| `qcccli` | `3.0.00-04` | COMMERCIAL |
| `safeclib` | `3.5.1` | MIT |
| `SNIA HBA API` | `2.2` | STORAGE NETWORKING INDUSTRY ASSOCIATION PUBLIC LICENSE 1.1 |
| `sorttable` | `2` | X11 |

##### `lnvgy_utl_bootstor_sata.mvcli-2.3.10.1095-0_linux_x86-64`

| Field | Value |
|---|---|
| Version | `2.3.10.1095-0` |
| License | COMMERCIAL |
| Section | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/utilities/ssd"` |

**Bundled OSS dependencies:** same section as above (glibc, openssl 3.1.5, safeclib, etc.)

##### `lnvgy_utl_raid_mr3.storcli-007.3205.0000.0000-1-j9vjc-0191_linux_indiv`

| Field | Value |
|---|---|
| Version | `007.3205.0000.0000-1-j9vjc-0191` |
| License | COMMERCIAL |
| Section | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/utilities/ssd"` |

**Bundled OSS dependencies:** same section as above.

##### `lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-ja9bc-0062_windows_indiv`

| Field | Value |
|---|---|
| Version | `008.0016.0000.0011-ja9bc-0062` |
| License | PROPRIETARY |
| Section | `*BUILD OUTPUT for "Target/lnvgy_utl_lxce_onecli_linux_x86-64/utilities/ssd"` |

**Bundled OSS dependencies:** same section as above.

#### Check 1b — Col F (USE) Completeness

✅ All component rows have Col F filled.

#### Check 2 — Version Correctness

| Library | Expected | SBOM Declares | Status | Note |
|---|---|---|---|---|
| boost | 1.86.0 | 1.86.0 | ✅ OK | Matches audit baseline |
| curl | 8.17.0 | 8.17.0 | ✅ CONFIRMED | Intentional project version |
| libssh2 | 1.11.1 | 1.11.1 | ✅ OK | Matches audit baseline |
| openssl | 3.6.0 | 3.6.0, 3.1.5 | ⚠️ WARN | Patch drift 3.6.2; 3.1.5 is I/O-sourced (approved) |
| pegasus | 2.14.1 | 2.14.1 | ✅ OK | Matches audit baseline |
| snmp++ | 3.3.10 | 3.3.10 | ✅ OK | Matches audit baseline |
| websocket++ | 0.8.3-dev | 0.8.x-dev | ❌ MISMATCH | SBOM drops `-dev` suffix |
| zlib | 1.3.1 | 1.3.1 | ✅ CONFIRMED | Intentional project version |

#### Check 3 — Duplicate / Multi-Version Detection

**⚠️ I/O-sourced versions — not stale, but confirm each release:**

| Library | I/O-Sourced Version | All Versions Present | Note |
|---|---|---|---|
| openssl | `3.1.5` | 3.6.0, 3.1.5 | I/O-sourced (utilities/ssd section); re-confirm each release |

---

### Windows SBOM

**Product:** lnvgy_utl_lxce_onecli_windows_indiv 5.6.0-01d  
**Scan date:** 5/4/2026  
**Components scanned:** 1122 total / 570 OSS  

#### Check 1 — Format Validation

| Item | Value |
|---|---|
| Target sections found | 15 |
| Total data rows | 976 |
| Orphan rows (name, no path) | 0 |
| Reversed orphan rows (path, no name) | 0 |
| `see below` license refs | 390 |

✅ No format issues detected.

#### Check 1c — Col E (Path) Version-Specific Folder

❌ **Systematic issue — 382 / 383 Target rows use a version-specific folder in Col E.**

| Item | Value |
|---|---|
| Version-specific folder (current) | `lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv` |
| Constant folder (required) | `lnvgy_utl_lxce_onecli_winsrv_x86-64` |

**Substitution rule:** replace every occurrence of `lnvgy_utl_lxce_onecli01d-5.6.0_windows_indiv` in Col E with `lnvgy_utl_lxce_onecli_winsrv_x86-64`.

#### Check 1d — Col A (Section Headers) Version-Specific Folder

❌ **Systematic issue — 14 / 14 section headers use a version-specific folder in Col A.** See Section 1.3 for full table.

#### Check 1a — Col D (Link) Folder Name Consistency

❌ **2 package(s) use a non-constant (version-specific) Col D.** See Section 1.4.

#### Check 1e — Col D Boost Annotation

❌ **11 row(s) missing boost annotation in Col D.** See Section 1.6.

#### Check 1f — Col A ↔ Col D Source Path Verification

| Result | Count |
|---|---|
| ✅ Verified (target matches) | 305 |
| ❌ Mismatch (dir exists, wrong target) | 2 |
| ⚠️ Path missing (dir not found) | 1 |
| ⚠️ No CMakeLists.txt | 3 |
| Total checked | 311 |

**❌ Mismatches:** rows 206–207 (onecli_rebootbmc / onecli_rebootcmm swap). See Section 1.7.

<details><summary>⚠️ 1 path(s) not found on disk</summary>

| Row | Col A | Expected target | Col D path |
|---|---|---|---|
| 258 | `parsexmlmetadata.dll` | `parsexmlmetadata` | `modularization/src/module/update/parse_fw_metadata/xml_metadata` |

</details>

<details><summary>⚠️ 3 path(s) found but no CMakeLists.txt</summary>

| Row | Col A | Expected target | Resolved dir |
|---|---|---|---|
| 266 | `pciio.dll` | `pciio` | `modularization/src/module/osinfos/inventory_modules/pciinfo/pciio` |
| 298 | `repository_tsmodule.dll` | `repository_tsmodule` | `onecli/TSModule/onecli-tsmodule/Src/tsmodules` |
| 299 | `repository_tssystem.dll` | `repository_tssystem` | `onecli/TSModule/onecli-tsmodule/Src/tssystem` |

</details>

#### Check 1g — I/O Package Version Consistency

| Result | Count |
|---|---|
| ✅ Matches canonical | 37 |
| ❌ Wrong version (family known) | 0 |
| ⚠️ Unknown package family | 0 |
| ⚠️ Internally inconsistent (multiple versions) | 0 |
| Total checked | 37 |

✅ All 37 I/O package references match the canonical baseline.

#### Check 1h — OSS Source Archive Presence

| Result | Count |
|---|---|
| ✅ Source archive present | 0 |
| ❌ Source archive missing | 9 |
| Total `1/` libs checked | 9 |

**❌ OSS components in `1/` section with no source archive:**

| Row | Col A (component) | Col E path |
|---|---|---|
| 436 | `boost` | `1/boost` |
| 437 | `curl` | `1/curl` |
| 442 | `libssh2` | `1/libssh2` |
| 953 | `openssl` | `1/openssl` |
| 956 | `pegasus` | `1/pegasus` |
| 992 | `snmp++` | `1/snmp++` |
| 996 | `tsmodule` | `1/tsmodule` |
| 997 | `websocket++` | `1/websocket++` |
| 998 | `zlib` | `1/zlib` |

#### Check 1i — I/O Tool License Map

##### `lnvgy_fw_drives_all-1.55.08-0-a_windows_x86-64`

| Field | Value |
|---|---|
| Version | `1.55.08-0` |
| License | PROPRIETARY |
| Section | `utilities/vroc` |

**Bundled OSS dependencies (selected):**

| Component | Version | License |
|---|---|---|
| `Intel AMT SDK` | `16.0.3.1` | Intel EULA; ACE; Apache-2.0; BSL-1.0; MIT; Zlib |
| `ipmiutil` | `2.9.3` | BSD-3-Clause; BSD-2-Clause; Zlib |
| `pthreads-w32` | `2.9.1` | **LGPL-2.0-or-later** ⚠️ |
| `qcccli` | `3.0.00-04` | COMMERCIAL |
| `sorttable` | `2` | X11 |
| `edk2/EdkCompatibilityPkg` | `UDK2008` | BSD-3-Clause; BSD-2-Clause |

##### `lnvgy_utl_bootstor_sata.mvcli-2.3.10.1095-0_windows_x86-64`

| Field | Value |
|---|---|
| Version | `2.3.10.1095-0` |
| License | COMMERCIAL |
| Section | `utilities/vroc` |

**Bundled OSS dependencies:** same as above (pthreads-w32 2.9.1 LGPL-2.0-or-later ⚠️).

##### `lnvgy_utl_raid_mr3.storcli-007.3205.0000.0000-j9vjd-0171_windows_indiv`

| Field | Value |
|---|---|
| Version | `007.3205.0000.0000-j9vjd-0171` |
| License | PROPRIETARY |
| Section | `utilities/vroc` |

**Bundled OSS dependencies:** same as above.

##### `lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-ja9bc-0062_windows_indiv`

| Field | Value |
|---|---|
| Version | `008.0016.0000.0011-ja9bc-0062` |
| License | PROPRIETARY |
| Section | `utilities/vroc` |

**Bundled OSS dependencies:** same as above.

#### Check 1b — Col F (USE) Completeness

⚠️ **5 row(s) have an empty Col F.** See Section 1.5 for details.

#### Check 2 — Version Correctness

| Library | Expected | SBOM Declares | Status | Note |
|---|---|---|---|---|
| boost | 1.86.0 | 1.86.0, 1.83.0 | ✅ OK | 1.86.0 matches; 1.83.0 is stale duplicate |
| curl | 8.17.0 | 8.17.0 | ✅ CONFIRMED | Intentional project version |
| libssh2 | 1.11.1 | 1.11.1 | ✅ OK | Matches |
| openssl | 3.6.0 | 3.6.0, 3.4.0 | ⚠️ WARN | Patch drift 3.6.2; 3.4.0 is stale |
| pegasus | 2.14.1 | 2.14.1 | ✅ OK | Matches |
| pthreads-w32 | 2.9.1 | 2.9.1 | ✅ CONFIRMED | Intentional project version |
| websocket++ | 0.8.3-dev | 0.8.3 | ❌ MISMATCH | SBOM drops `-dev` suffix |
| zlib | 1.3.1 | 1.3.1 | ✅ CONFIRMED | Intentional project version |

#### Check 3 — Duplicate / Multi-Version Detection

**❌ Stale duplicate versions (remove excess entries):**

| Library | Versions Found | Row Numbers |
|---|---|---|
| boost | 1.86.0, 1.83.0 | 436, 1000 |
| openssl | 3.6.0, 3.4.0 | 953, 955 |

---

*Consolidated report: manual audit (Sections 1–7) + automated evidence (Section 8) · sbom_review.py · version_audit_5.6.0.log · Review dates: 2026-05-13 (Linux) · 2026-05-14 (Windows, extended analysis)*
