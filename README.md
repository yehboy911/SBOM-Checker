# SBOM Checker v1.0.0

OSC (Open Source Compliance) 流程中，驗證 SBOM CSV 正確性的自動化工具。
透過解析 Source Code 的 CMakeLists.txt 與 SBOM CSV 進行交叉比對，自動找出不一致的項目，並將差異自動分類為可供法務審核的格式。

**狀態:** ✅ 生產級發佈 (v1.0.0-sbom-validation-complete)
**GitHub:** https://github.com/yehboy911/SBOM-Checker/releases/tag/v1.0.0-sbom-validation-complete

---

## 🎯 核心功能

### 1. **來源參照驗證**
檢查每個 Target 輸出項目的 `see "xxx"` 參照是否指向已知的 Source 來源。快速識別遺漏的參照。

### 2. **CMake 交叉比對**
比對 CMakeLists.txt 定義的輸出檔案與 SBOM 中列出的 Target，找出遺漏或多餘項目。

### 3. **自動分類** ⭐ (v1.0.0 新功能)
將 CMake 差異自動分類為 6 層優先級：
- `cmake_internal` — CMake 內部工具 (FortranLib, cmake_*)
- `test_sample` — 測試/範例程式 (test*, sample*, *test*)
- `static_lib` — 靜態庫 (.a, .lib) — 通常不在產品發佈
- `third_party` — 第三方套件 (boost, curl, zlib, ...)
- `platform_specific` — 平台特定檔案 (.exe, .dll, .so, .dylib)
- `unknown` — 需人工審查的項目

**分類準確率:** 92.3% (224/297 項已自動分類)

### 4. **CMake 掃描**
獨立掃描 CMakeLists.txt，列出所有 build target 及推算的輸出檔名。

---

## 📊 驗證結果示例

對 LXCE OneCLI v5.5.0 的雙平台驗證結果：

| 平台 | 目標數 | 來源數 | 來源驗證 | CMake 差異 | 分類準確率 |
|------|--------|---------|---------|----------|----------|
| **Linux** | 573 | 4,284 | ✅ PASS (0) | 297 | 92.3% |
| **Windows** | 399 | 642 | ❌ FAIL (4) | 297 | 92.3% |

**Windows 4 個問題：** VC++ Runtime 參照遺漏 (msvcp140.dll, vcruntime140.dll × 2, vcruntime140_1.dll)

---

## 🚀 安裝

```bash
pipx install -e "/path/to/sbom_checker"
```

## 📖 使用方式

```bash
# 僅驗證 SBOM 內部參照 (不需 source code)
sbom-checker check /path/to/sbom.csv --check-refs-only

# 完整驗證: 參照 + CMake 交叉比對 + 自動分類
sbom-checker check /path/to/sbom.csv --source-dir /path/to/source --platform linux

# 掃描 CMake 輸出目標
sbom-checker scan /path/to/source --platform linux
```

---

## 📦 交付報表

驗證完成後會產生可供法務審核的報表包（tar.gz + zip）：

| 報表 | 用途 | 讀者 |
|------|------|------|
| `DELIVERY_MANIFEST.md` | 法務審核指南 + 關鍵問題總結 | 法務、管理層 |
| `SBOM_Validation_Summary_v5.5.0.md` | 執行摘要與建議 | 領導層、產品經理 |
| `linux_final_report_v5.5.0.txt` | Linux 完整驗證報表 | 開發、QA |
| `windows_final_report_v5.5.0.txt` | Windows 完整驗證報表 | 開發、QA |
| `METRICS_SUMMARY.txt` | 快速參考統計表 | 所有人 |
| `IMPLEMENTATION_LOG.md` | 技術實作詳情與分類規則 | 架構、開發 |

---

## ✨ 快速開始

### 法務人員 (30 分鐘)
1. 閱讀 `DELIVERY_MANIFEST.md`
2. 查看「關鍵問題總結」及優先級清單
3. 確認後續修正時間表 (P1: 1-2 天, P2: 3-5 天, P3-P4: 1-2 週)

### 開發人員 (1-2 小時)
1. 參考 `IMPLEMENTATION_LOG.md` 了解分類邏輯
2. 查看各報表的 unknown 分類項目
3. 確認平台特定檔案是否應納入 SBOM

### QA 人員 (30 分鐘)
1. 參考驗證命令重新執行驗證
2. 驗證修正後的 SBOM 對齊性
3. 確認所有 unknown 項目已分類

---

## 📋 系統需求

- Python >= 3.8
- 無外部依賴（純 Python stdlib）
- 支援: Linux, macOS, Windows

---

## 🔍 技術特性

- **動態 CSV 解析** — 不硬編 header 行號，自動偵測
- **平台感知 CMake 掃描** — 支援 Linux/Windows 雙平台偵測
- **狀態機解析** — 精確處理複雜 CMakeLists.txt 語法
- **標準化比對** — 正規化檔名後進行交叉比對 (如 .so → lib*.so)
- **分類優先級** — 6 層規則、優先級遞減，確保準確分類

---

## 📈 驗證覆蓋率

**CMake 掃描覆蓋 (LXCE OneCLI v5.5.0):**
- 掃描 CMakeLists.txt: 499 個
- 偵測 CMake Targets: 539 個
- CMake 警告: 17 個 (全為良性，如 `${VAR}` 變數)

---

## 🔗 相關資源

- **GitHub Release:** https://github.com/yehboy911/SBOM-Checker/releases/tag/v1.0.0-sbom-validation-complete
- **完整驗證報表:** 見發佈包中的 tar.gz/zip 檔案
- **實作細節:** 見 `IMPLEMENTATION_LOG.md`

---

## ⚙️ License

MIT
