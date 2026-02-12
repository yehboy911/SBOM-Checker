驗證 SBOM CSV 檔案的來源參照正確性。

請使用 sbom-checker 工具執行驗證：

```bash
sbom-checker check "$ARGUMENTS" --check-refs-only
```

如果使用者也提供了 source code 目錄，執行完整驗證：

```bash
sbom-checker check "$ARGUMENTS" --source-dir <source_dir> --platform <platform>
```

分析報表結果，說明每個問題的可能原因與建議修正方式。
