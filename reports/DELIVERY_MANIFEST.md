# SBOM Checker v5.5.0 — 驗證報表交付清單

**交付日期:** 2026-02-12
**產品版本:** LXCE OneCLI v5.5.0
**驗證工具:** sbom-checker v1.0.0

---

## 📦 交付內容

### 1. 執行摘要 (讀者應從此開始)
**檔案:** `SBOM_Validation_Summary_v5.5.0.md`
- 驗證目標與範圍
- 平台驗證結果摘要 (Linux ✅ / Windows ❌)
- 分類分析與建議
- 關鍵發現與行動清單
- **適用人員:** 法務、產品、發佈團隊

### 2. 完整驗證報表

#### Linux 平台驗證報表
**檔案:** `linux_final_report_v5.5.0.txt`
- CMake 掃描摘要 (539 targets, 17 warnings)
- ✅ 來源參照驗證結果 (PASS — 0 個問題)
- CMake 交叉比對分類統計
- 按分類分組的詳細項目列表
- **統計:** 573 Targets, 4,284 Sources, 297 CMake 差異

#### Windows 平台驗證報表
**檔案:** `windows_final_report_v5.5.0.txt`
- CMake 掃描摘要 (539 targets, 17 warnings)
- ❌ 來源參照驗證結果 (FAIL — 4 個 VC++ Runtime 參照問題)
- CMake 交叉比對分類統計
- 按分類分組的詳細項目列表
- **統計:** 399 Targets, 642 Sources, 297 CMake 差異

### 3. 快速參考指標
**檔案:** `METRICS_SUMMARY.txt`
- 來源參照驗證結果概覽
- CMake 交叉比對統計表 (兩平台並列)
- 關鍵發現與優先級建議
- 驗證覆蓋率與工具版本信息
- **適用人員:** 快速掌握驗證狀況

### 4. 實作詳情
**檔案:** `IMPLEMENTATION_LOG.md`
- 實作修改清單 (validator.py, report.py)
- 分類規則詳細說明
- 驗證命令與性能指標
- 分類準確率分析
- 進一步改進機會
- **適用人員:** 開發、QA、技術審查

---

## 🎯 法務審核指南

### 第 1 步：快速瞭解 (5 分鐘)
1. 閱讀 `SBOM_Validation_Summary_v5.5.0.md` 的「執行摘要」
2. 查看「驗證結果」表格
3. 注意「關鍵發現」部分

### 第 2 步：詳細審查 (15 分鐘)
1. 閱讀「詳細驗證結果」中的相關平台章節
2. 查看「分類分析與建議」
3. 標註任何疑問

### 第 3 步：確認行動項目 (10 分鐘)
1. 複閱「進一步行動」清單
2. 確認優先級與負責人
3. 計劃後續修正時間表

### 第 4 步：驗證詳情 (選擇性)
1. 查看完整報表中的詳細列表
2. 逐一確認 unknown 分類項目
3. 驗證第三方相依授權

---

## ⚠️ 關鍵問題總結

### 🔴 必須修正 (優先級 P1)

**Windows SBOM — VC++ Runtime 參照遺失 (4 項)**

| Target | Missing Reference | 建議行動 |
|--------|-------------------|---------|
| msvcp140.dll | Microsoft Visual C++ Runtime (2019) | 新增來源或移除 |
| vcruntime140.dll × 2 | Microsoft Visual C++ Runtime (2019) | 新增來源或移除 |
| vcruntime140.dll | Microsoft Visual C++ Runtime (2017) | 新增來源或移除 |

**修正方案:**
- ✅ **方案 A (推薦):** 在 SBOM Source 區段新增 Microsoft Runtime 定義
- ✅ **方案 B:** 從 SBOM Target 中移除 VC++ DLL (由 Windows 系統提供)

### 🟡 需要審查 (優先級 P2)

**Unknown 分類項目 (73 項)**

| 平台 | 數量 | 類型 | 建議 |
|------|------|------|------|
| Linux CMake-only | 20 | 可執行檔、工具 | 確認是否應在 SBOM |
| Linux SBOM-only | 38 | 資源檔、文件 | 確認是否為最終產品 |
| Windows SBOM-only | 15 | 資源檔、驅動程式 | 確認是否為最終產品 |

### 🟢 確認正常 (優先級 P3)

**已分類為已知類別 (224 項)**
- ✅ 靜態庫 (93 項) — 編譯內部產物
- ✅ 測試程式 (83 項) — 開發相關
- ✅ CMake 工具 (1 項) — 內部工具
- ✅ 第三方套件 (17 項) — 外部相依
- ⚠️ 平台特定 (97 項) — 部分需確認

---

## 📊 驗證統計

### 來源參照驗證結果

```
┌─────────────────────┬────────┬──────────┐
│ 平台                │ 結果   │ 問題數   │
├─────────────────────┼────────┼──────────┤
│ Linux               │ ✅ PASS│    0     │
│ Windows             │ ❌ FAIL│    4     │
└─────────────────────┴────────┴──────────┘
```

### CMake 交叉比對分類統計

**Linux:**
- cmake_internal: 1 (CMake-only)
- static_lib: 93 (CMake-only)
- test_sample: 83 (CMake-only)
- linux_specific: 48 (32 CMake-only, 16 SBOM-only)
- third_party: 14 (SBOM-only)
- unknown: 58 (20 CMake-only, 38 SBOM-only)

**Windows:**
- cmake_internal: 1 (CMake-only)
- static_lib: 93 (CMake-only)
- test_sample: 83 (CMake-only)
- windows_specific: 102 (50 CMake-only, 52 SBOM-only)
- third_party: 3 (SBOM-only)
- unknown: 15 (SBOM-only)

---

## 🔄 後續步驟

### 建議時間表

| Phase | 任務 | 預期耗時 | 負責人 |
|-------|------|---------|--------|
| P1 | 修正 VC++ Runtime 參照 | 2 天 | 法務/發佈 |
| P2 | 審查 unknown 項目 (73) | 3-5 天 | 開發/產品 |
| P3 | 平台特定檔案清單確認 | 2 天 | QA |
| P4 | CMake/SBOM 對齐更新 | 3 天 | 架構/開發 |

### 重新驗證命令

完成修正後，使用以下命令重新驗證：

```bash
# Linux 驗證
sbom-checker check \
  "/path/to/lnvgy_utl_lxce_onecli_linux_indiv.csv" \
  --source-dir /path/to/OneCLI --platform linux

# Windows 驗證
sbom-checker check \
  "/path/to/lnvgy_utl_lxce_onecli_windows_indiv.csv" \
  --source-dir /path/to/OneCLI --platform windows
```

---

## 📞 聯繫資訊

**驗證工具詳情:**
- 工具名稱: sbom-checker
- 版本: v1.0.0
- 語言: Python 3.8+
- 依賴: Pure stdlib (無外部相依)

**驗證日期:** 2026-02-12
**驗證範圍:** LXCE OneCLI v5.5.0 (Linux + Windows 雙平台)
**驗證狀態:** ✅ 完成並分類

---

## 📋 文件清單與大小

| 檔案 | 大小 | 行數 | 說明 |
|------|------|------|------|
| SBOM_Validation_Summary_v5.5.0.md | 8.2K | 255 | 執行摘要與建議 |
| linux_final_report_v5.5.0.txt | 12K | 369 | Linux 完整驗證報表 |
| windows_final_report_v5.5.0.txt | 12K | 373 | Windows 完整驗證報表 |
| METRICS_SUMMARY.txt | 6K | - | 快速參考指標 |
| IMPLEMENTATION_LOG.md | 9.4K | 400+ | 實作詳情與分析 |
| **合計** | **48K** | **1000+** | |

---

**檔案格式:** UTF-8 (繁體中文)
**推薦閱讀順序:** 摘要 → 指標 → 完整報表 → 實作詳情
**交付格式:** tar.gz 或 zip 壓縮檔

---

*此報表由 SBOM Checker v1.0.0 自動生成。*
