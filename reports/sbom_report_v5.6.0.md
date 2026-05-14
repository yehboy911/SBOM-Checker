# LXCE OneCLI 5.5.0 — Open-Source Compliance Audit Report
**Generated:** 2026-04-14  
**Audit Scope:** Tier 1 (component identification) + Tier 2 (license obligation analysis)  
**Project:** Lenovo XClarity Essentials OneCLI + XModule (Modularization) 5.5.0  
**Components audited:** modularization/, onecli/, rdcli_red/  

---

## Section 1: Project Directory Structure (Top-Level)

```
OneCLI/
├── modularization/          ← XModule shared library layer (project: XModule 5.5.0)
│   ├── src/
│   │   ├── module/          ← Hardware-domain modules (redfish, xfw, smm, fod, options, update, ...)
│   │   ├── common/          ← Protocol helpers (IPMI, SSH2, REST, credential, redfish_uri...)
│   │   └── xm_common/       ← Shared utilities (logging, curl wrapper, crypt, uri, zipfile...)
│   ├── extlibs/             ← Pre-built third-party binaries (linux_x64/, linux_aarch64/, WIN64/)
│   ├── unittests/           ← Google Test + Catch2 unit tests
│   ├── build/               ← Build scripts, CMake presets, VERSION file
│   └── doc/                 ← Developer documentation
│
├── onecli/                  ← OneCLI application (project: OneCli)
│   ├── Src/
│   │   ├── OneCli/          ← Entry point, CLI dispatch
│   │   ├── Update/          ← Firmware update commands
│   │   ├── Config/          ← Configuration commands (Redfish-based)
│   │   ├── Inventory/       ← Hardware inventory
│   │   ├── Diagnose/        ← Diagnostics
│   │   ├── Fod/             ← Features on Demand
│   │   ├── Misc/            ← 40+ sub-commands (FFDC, SecureErase, CMOS, HostInterface, ...)
│   │   ├── service/         ← Background service runners
│   │   ├── apps/            ← Derived apps (easyupdate, tui, multiconfig, deployos...)
│   │   ├── Utility/         ← Shared utilities (Log, Timer, ErrorCode, AutoCompletion, ...)
│   │   ├── repository/      ← Package repository client
│   │   ├── LightWeight/     ← Lightweight CLI variant
│   │   ├── engines/         ← Command execution engines
│   │   └── lxce_onecli_opensource/ ← Redistributed OSS sources (storcli)
│   ├── TSModule/            ← Thin-server module plugin
│   ├── Modularization/      ← Symlink/copy of XModule output
│   ├── Build/               ← CMake build scripts, presets, tools
│   └── unittests/           ← Unit tests (Google Test + Catch2)
│
└── rdcli_red/               ← Remote Disk CLI (standalone variant)
    ├── RemoteDiskCLI/
    │   ├── src/             ← rdmount, rdumount, module
    │   └── include/
    └── US/                  ← Distribution artifacts
```

---

## Section 2: SBOM — Third-Party Dependencies

### 2.1 Runtime / Production Dependencies

| # | Component | Version | SPDX License ID | Link Type | Platform | CP Findings |
|---|-----------|---------|-----------------|-----------|----------|-------------|
| 1 | Boost (aggregate) | 1.86.0 | BSL-1.0 | Dynamic (.so) / Static (.a) | Linux + Win | CP-12 ▲ |
| 2 | OpenSSL (libssl + libcrypto) | 3.6.0 | Apache-2.0 | Dynamic (.so) | Linux + Win | — |
| 3 | libcurl | 8.17.0 | curl (MIT variant) | Dynamic (.so) | Linux + Win | — |
| 4 | libssh2 | 1.11.1 | BSD-3-Clause | Dynamic (.so) | Linux + Win | — |
| 5 | zlib | 1.3.1 | Zlib | Dynamic (.so) / Static (.a) | Linux + Win | — |
| 6 | snmp++ (SNMP++-v3) | 3.3.10 | HP/Katz permissive (pseudo-BSD) | Dynamic (.so) | Linux | CP-02 ▲ |
| 7 | OpenPegasus (CIM) | 2.14.x | MIT | Dynamic (.so) | Linux + Win | CP-03 ▲ |
| 8 | WebSocket++ | 0.8.3-dev | BSD-3-Clause | Header-only | Linux + Win | CP-03 ▲ |
| 9 | storcli (source zip) | 007.3205.0000.0000 | Broadcom proprietary | Source-only (redistributed) | Linux | CP-02 ▲ |
| 10 | storcli2 (source zip) | 008.0012.0000.0004 | Broadcom proprietary | Source-only (redistributed) | Linux | CP-02 ▲ |

### 2.2 Boost Sub-Libraries Used (CP-12 Required Granularity)

Confirmed via `target_link_libraries` scan across all CMakeLists.txt:

| Boost Component | SPDX | Used In |
|---|---|---|
| `boost_filesystem` | BSL-1.0 | file_client, ipmanip, globalconfig, Update |
| `boost_system` | BSL-1.0 | file_client, ipmanip, globalconfig, curlcpp, osspecific |
| `boost_regex` | BSL-1.0 | osspecific, RedfishConfig, RedfishConfigCommon |
| `boost_program_options` | BSL-1.0 | globalconfig, ipmanip |
| `boost_json` | BSL-1.0 | RedfishConfig, RedfishConfigCommon |
| `boost_thread` | BSL-1.0 | RedfishConfig, Update |
| `boost_chrono` | BSL-1.0 | (built, used indirectly) |
| `boost_date_time` | BSL-1.0 | onecli/Src Update |
| `boost_cobalt` | BSL-1.0 | (built, usage TBD) |
| `boost_locale` | BSL-1.0 | (built, usage TBD) |
| `boost_container` | BSL-1.0 | (built, usage TBD) |
| `boost_atomic` | BSL-1.0 | (built, usage TBD) |

### 2.3 Build-Time / Test-Only Dependencies

| # | Component | Version | SPDX License ID | Scope |
|---|-----------|---------|-----------------|-------|
| 11 | Google Test (googletest) | ~1.7.0 | BSD-3-Clause | Test only |
| 12 | Google Mock (googlemock) | ~1.7.0 | BSD-3-Clause | Test only |
| 13 | Catch2 | 2.13.9 | BSL-1.0 | Test only |
| 14 | CMake | 3.16+ | BSD-3-Clause | Build only |

---

## Section 3: License Classification & Obligations

### 3.1 Permissive Licenses — Low Obligation

| License | Components | Key Obligation |
|---|---|---|
| BSL-1.0 (Boost) | Boost 1.86.0, Catch2 2.13.9 | Include license text in distribution |
| Apache-2.0 | OpenSSL 3.6.0 | Include NOTICE file if present; include license text |
| curl (MIT-like) | libcurl 8.17.0 | Include copyright notice |
| BSD-3-Clause | libssh2, WebSocket++, gtest, gmock, CMake | Include copyright notice + license text |
| Zlib | zlib 1.3.1 | Include copyright notice in docs; no advertising clause |
| MIT | OpenPegasus 2.14.x | Include copyright notice + license text |
| HP/Katz permissive | snmp++ 3.3.10 | Include copyright notice; royalty-free |

**No GPL or LGPL components detected** in runtime dependencies. No copyleft propagation risk.

### 3.2 Proprietary / Non-OSS

| Component | License | Risk |
|---|---|---|
| storcli source zips | Broadcom proprietary | Redistribution requires Broadcom authorization. Distributed via `lxce_onecli_opensource/` — confirm redistribution rights (CP-14). |
| OneCLI core | Lenovo proprietary | Internal. `lic_en.txt` = IBM IPLA (non-warranted programs) |

---

## Section 4: Checkpoint Findings

| CP | Status | Finding |
|---|---|---|
| CP-01 | ✅ PASS | All distributed packages identified |
| CP-02 | ⚠️ GAP | snmp++ 3.3.10: SPDX ID is non-standard (HP/Katz license not in SPDX list). Use `LicenseRef-snmppp-HP-Katz`. storcli/storcli2: license type needs formal confirmation from Broadcom. |
| CP-03 | ⚠️ GAP | OpenPegasus: only "2.14.x" identified — exact patch version not pinned. WebSocket++: version is `0.8.3-dev` (pre-release flag) — not a stable release tag. |
| CP-04 | ⚠️ GAP | Source archives for snmp++ 3.3.10 and OpenPegasus 2.14.x not located in repo. Must confirm internal archive location. |
| CP-05 | ✅ PASS | No GPL components detected — no GPL propagation risk |
| CP-06 | ✅ PASS | No LGPL components detected |
| CP-07 | ✅ N/A | No LGPL-2.1-only components |
| CP-08 | ✅ N/A | No LGPL tier-2 evidence required |
| CP-09 | ⚠️ GAP | Copyright notices for snmp++ and OpenPegasus should be verified in distribution package |
| CP-10 | ⚠️ GAP | License texts for snmp++, OpenPegasus must be included in distribution |
| CP-11 | ✅ PASS | CMake dependency graph complete — no FetchContent with unpinned hashes detected |
| CP-12 | ⚠️ GAP | Boost 1.86.0 cobalt/locale/container/atomic: built but usage in final binary not confirmed. Remove unused components or document usage. |
| CP-13 | ⚠️ GAP | `third_party_notices.txt` not found — needs to be generated |
| CP-14 | ⚠️ PENDING | storcli redistribution rights must have written Broadcom sign-off on file |
| CP-15 | N/A | Tier-3 (XCC binary scan) not in scope for this audit |

---

## Section 5: Recommended Actions (Priority Order)

1. **[HIGH] CP-13** — Generate `third_party_notices.txt` containing all copyright notices and license texts for: Boost, OpenSSL, libcurl, libssh2, zlib, snmp++, OpenPegasus, WebSocket++.

2. **[HIGH] CP-03/CP-04 — OpenPegasus** — Pin exact version (e.g., `2.14.3`) and confirm source archive location internally.

3. **[HIGH] CP-14 — storcli redistribution** — Obtain written authorization from Broadcom for redistributing storcli source ZIPs in the `lxce_onecli_opensource/` directory.

4. **[MEDIUM] CP-02 — snmp++ SPDX ID** — Assign `LicenseRef-snmppp-HP-Katz` in SBOM. Document that the HP/Jochen Katz license is permissive (royalty-free, no copyleft).

5. **[MEDIUM] CP-03 — WebSocket++** — Switch from `0.8.3-dev` to a stable tagged release (latest stable: 0.8.2 or confirm 0.8.3 GA).

6. **[LOW] CP-12 — Boost** — Audit which of `cobalt`, `locale`, `container`, `atomic` are actually linked in the final binary. Remove from extlibs or document if unused.

---

## Section 6: NTIA SBOM Minimum Elements Compliance

| NTIA Element | Status |
|---|---|
| Supplier name | ✅ Identified for all components |
| Component name | ✅ Complete |
| Version | ⚠️ OpenPegasus only has "2.14.x" — not exact |
| Unique identifier (PURL) | ⚠️ Not yet assigned — generate PURLs |
| Dependency relationship | ✅ Direct vs. transitive determined |
| Author of SBOM data | ⚠️ Must be added to final SBOM CSV |
| Timestamp | ⚠️ Must be added to final SBOM CSV |
| License expression (SPDX) | ⚠️ snmp++ needs LicenseRef; storcli needs confirmation |

---

*Report saved: /tmp/ctx-onecli-sbom/sbom_report.md*
