"""報表格式化輸出 — 繁體中文文字表格"""


class ReportFormatter:
    """格式化驗證結果為文字表格報表"""

    WIDTH = 100

    def format(self, result):
        """產生完整報表字串"""
        lines = []

        # 標題
        lines.append("")
        lines.append("=" * self.WIDTH)
        lines.append("  SBOM Checker 驗證報表")
        lines.append("=" * self.WIDTH)

        # 摘要統計
        lines.append("")
        lines.append("[ 摘要 ]")
        lines.append(f"  平台:           {result.platform or '未偵測'}")
        lines.append(f"  Target 項目數:  {result.target_count}")
        lines.append(f"  Source 項目數:  {result.source_count}")
        lines.append(f"  區段數:         {result.section_count}")
        lines.append(f"  略過 (IGNORE):  {result.ignored_count}")
        lines.append(f"  參照檢查數:     {result.refs_checked}")
        lines.append(f"  參照有效數:     {result.refs_valid}")
        lines.append(f"  參照問題數:     {len(result.ref_issues)}")

        if result.cmake_issues:
            cmake_only = sum(1 for i in result.cmake_issues if i.issue_type == "cmake_only")
            sbom_only = sum(1 for i in result.cmake_issues if i.issue_type == "sbom_only")
            lines.append(f"  CMake 獨有:     {cmake_only}")
            lines.append(f"  SBOM 獨有:      {sbom_only}")

        # Check (a) 來源參照結果
        lines.append("")
        lines.append("-" * self.WIDTH)
        lines.append("[ Check (a) 來源參照驗證 ]")
        lines.append("-" * self.WIDTH)

        if result.ref_issues:
            lines.append("")
            lines.append(f"  {'Target 檔案':<40} {'遺失參照':<40} {'區段'}")
            lines.append(f"  {'-' * 38:<40} {'-' * 38:<40} {'-' * 18}")

            for issue in result.ref_issues:
                target_display = _truncate(issue.target_name, 38)
                ref_display = _truncate(issue.missing_ref, 38)
                section_display = _truncate(issue.section, 18)
                lines.append(f"  {target_display:<40} {ref_display:<40} {section_display}")
        else:
            lines.append("")
            lines.append("  所有來源參照均有效。")

        # CMake 交叉比對結果
        if result.cmake_issues:
            lines.append("")
            lines.append("-" * self.WIDTH)
            lines.append("[ CMake 交叉比對 ]")
            lines.append("-" * self.WIDTH)

            # 分類統計表格
            lines.append("")
            lines.append("[ CMake 交叉比對 — 分類統計 ]")
            lines.append("")

            # 統計各分類數量
            category_stats = {}
            for issue in result.cmake_issues:
                cat = issue.category or "unknown"
                if cat not in category_stats:
                    category_stats[cat] = {"cmake_only": 0, "sbom_only": 0}
                category_stats[cat][issue.issue_type] += 1

            # 表頭
            lines.append(f"  {'分類':<20} {'CMake-only':<15} {'SBOM-only':<15} {'合計':<10}")
            lines.append(f"  {'-' * 18:<20} {'-' * 13:<15} {'-' * 13:<15} {'-' * 8:<10}")

            # 按分類顯示統計
            total_cmake = 0
            total_sbom = 0
            for cat in sorted(category_stats.keys()):
                stats = category_stats[cat]
                cmake_cnt = stats["cmake_only"]
                sbom_cnt = stats["sbom_only"]
                total = cmake_cnt + sbom_cnt
                total_cmake += cmake_cnt
                total_sbom += sbom_cnt
                lines.append(f"  {cat:<20} {cmake_cnt:<15} {sbom_cnt:<15} {total:<10}")

            # 合計行
            lines.append(f"  {'-' * 18:<20} {'-' * 13:<15} {'-' * 13:<15} {'-' * 8:<10}")
            total_all = total_cmake + total_sbom
            lines.append(f"  {'合計':<20} {total_cmake:<15} {total_sbom:<15} {total_all:<10}")

            # 詳細列表
            lines.append("")
            lines.append("[ CMake 交叉比對 — 詳細列表 ]")
            lines.append("")

            cmake_only = [i for i in result.cmake_issues if i.issue_type == "cmake_only"]
            sbom_only = [i for i in result.cmake_issues if i.issue_type == "sbom_only"]

            if cmake_only:
                lines.append("  CMake 定義但不在 SBOM 中:")
                # 按分類分組顯示
                cmake_by_cat = {}
                for issue in cmake_only:
                    cat = issue.category or "unknown"
                    if cat not in cmake_by_cat:
                        cmake_by_cat[cat] = []
                    cmake_by_cat[cat].append(issue)

                for cat in sorted(cmake_by_cat.keys()):
                    lines.append(f"    [{cat}]")
                    for issue in sorted(cmake_by_cat[cat], key=lambda x: x.name):
                        lines.append(f"      - {issue.name}")

            if sbom_only:
                if cmake_only:
                    lines.append("")
                lines.append("  SBOM 列出但 CMake 未定義:")
                # 按分類分組顯示
                sbom_by_cat = {}
                for issue in sbom_only:
                    cat = issue.category or "unknown"
                    if cat not in sbom_by_cat:
                        sbom_by_cat[cat] = []
                    sbom_by_cat[cat].append(issue)

                for cat in sorted(sbom_by_cat.keys()):
                    lines.append(f"    [{cat}]")
                    for issue in sorted(sbom_by_cat[cat], key=lambda x: x.name):
                        lines.append(f"      - {issue.name}")

        # 結尾
        lines.append("")
        lines.append("=" * self.WIDTH)

        ref_status = "PASS" if not result.ref_issues else "FAIL"
        cmake_status = ""
        if result.cmake_issues:
            cmake_status = " | CMake 比對: FAIL"
        elif hasattr(result, 'cmake_issues') and result.cmake_issues is not None:
            cmake_status = ""

        lines.append(f"  結果: 來源參照 {ref_status}{cmake_status}")
        lines.append("=" * self.WIDTH)
        lines.append("")

        return "\n".join(lines)


def _truncate(text, max_len):
    """截斷過長文字"""
    if len(text) <= max_len:
        return text
    return text[:max_len - 2] + ".."
