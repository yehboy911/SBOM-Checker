"""CLI 進入點 — argparse 子指令"""

import argparse
import sys
from pathlib import Path

from .sbom_parser import SbomParser
from .cmake_scanner import CmakeScanner
from .validator import SbomValidator
from .report import ReportFormatter
from .xlsx_reviewer import review_xlsx, auto_detect_platform
from .bomc_xlsx_reviewer import review_bomc


def main():
    parser = argparse.ArgumentParser(
        prog="sbom-checker",
        description="SBOM CSV 交叉驗證工具 — 比對 CMakeLists.txt 輸出與 SBOM 來源參照",
    )
    subparsers = parser.add_subparsers(dest="command", help="子指令")

    # --- check 子指令 ---
    check_parser = subparsers.add_parser("check", help="驗證 SBOM CSV")
    check_parser.add_argument("csv_path", help="SBOM CSV 檔案路徑")
    check_parser.add_argument(
        "--check-refs-only",
        action="store_true",
        help="僅驗證來源參照（不需 source code）",
    )
    check_parser.add_argument(
        "--source-dir",
        help="Source Code 根目錄（用於 CMake 交叉比對）",
    )
    check_parser.add_argument(
        "--platform",
        choices=["linux", "windows"],
        help="指定平台（預設自動偵測）",
    )

    # --- scan 子指令 ---
    scan_parser = subparsers.add_parser("scan", help="掃描 CMakeLists.txt 輸出目標")
    scan_parser.add_argument("source_dir", help="Source Code 根目錄")
    scan_parser.add_argument(
        "--platform",
        choices=["linux", "windows"],
        default="linux",
        help="輸出平台（預設 linux）",
    )

    # --- review-ux 子指令 (preferred name; review-xlsx kept as legacy alias) ---
    ux_parser = subparsers.add_parser("review-ux", help="審查 UpdateXpress Excel SBOM")
    ux_parser.add_argument("xlsx_path", help="SBOM .xlsx 檔案路徑")
    ux_parser.add_argument(
        "--platform", choices=["linux", "windows"],
        help="平台 (預設從檔名自動偵測)",
    )
    ux_parser.add_argument("--deps-info",   help="dependencies_info.json 路徑 (主要 npm 參照)")
    ux_parser.add_argument("--lock",        help="package-lock.json 路徑 (次要 npm 參照)")
    ux_parser.add_argument(
        "--fossa-json",
        help="FOSSA 匯出 JSON 路徑 (第三優先 npm 參照)",
    )
    ux_parser.add_argument("--onecli-json", help="OneCLI SBOM 資料 JSON 路徑 (覆蓋預設)")
    ux_parser.add_argument("--output",      help="輸出路徑 (預設: <原檔名>_reviewed.xlsx)")

    # --- review-xlsx 子指令 (legacy alias for review-ux) ---
    rx_parser = subparsers.add_parser("review-xlsx", help="[legacy] 同 review-ux")
    rx_parser.add_argument("xlsx_path", help="SBOM .xlsx 檔案路徑")
    rx_parser.add_argument(
        "--platform", choices=["linux", "windows"],
        help="平台 (預設從檔名自動偵測)",
    )
    rx_parser.add_argument("--deps-info",   help="dependencies_info.json 路徑 (主要 npm 參照)")
    rx_parser.add_argument("--lock",        help="package-lock.json 路徑 (次要 npm 參照)")
    rx_parser.add_argument(
        "--fossa-json",
        help="FOSSA 匯出 JSON 路徑 (第三優先 npm 參照)\n"
             "Ref: ~/.claude/skills/learned/Lenovo's Software Analysis Framework.pdf",
    )
    rx_parser.add_argument("--onecli-json", help="OneCLI SBOM 資料 JSON 路徑 (覆蓋預設)")
    rx_parser.add_argument("--output",      help="輸出路徑 (預設: <原檔名>_reviewed.xlsx)")

    # --- review-bomc 子指令 ---
    rb_parser = subparsers.add_parser("review-bomc", help="審查 BoMC Excel SBOM")
    rb_parser.add_argument("xlsx_path", help="SBOM .xlsx 檔案路徑")
    rb_parser.add_argument(
        "--platform", choices=["linux", "windows"],
        help="平台 (預設從檔名自動偵測)",
    )
    rb_parser.add_argument("--lock",   help="package-lock.json 路徑 (npm 參照)")
    rb_parser.add_argument("--output", help="輸出路徑 (預設: <原檔名>_reviewed.xlsx)")

    # --- review-onecli 子指令 (BACKLOG — stub only) ---
    ro_parser = subparsers.add_parser(
        "review-onecli",
        help="[BACKLOG] 審查 OneCLI 自己的 SBOM Excel (尚未實作)",
    )
    ro_parser.add_argument("xlsx_path", help="OneCLI SBOM .xlsx 檔案路徑")

    # --- gen-tpn 子指令 ---
    gt_parser = subparsers.add_parser(
        "gen-tpn",
        help="從 FOSSA JSON + OneCLI TPN + package-lock.json 生成 TPN draft (Approach B)",
    )
    gt_parser.add_argument("--platform",    required=True, choices=["win", "linux"],
                           help="平台: win 或 linux")
    gt_parser.add_argument("--fossa-json",  required=True,
                           help="FOSSA 匯出 JSON 路徑 (ux_win_fossa.json / ux_linux_fossa_json.json)")
    gt_parser.add_argument("--onecli-tpn",  required=True,
                           help="OneCLI TPN FINAL .txt 路徑 (C/C++ copy-forward 來源)")
    gt_parser.add_argument("--pkg-lock",    required=True,
                           help="package-lock.json 路徑 (npm 版本 + transitive stubs)")
    gt_parser.add_argument("--output",      required=True,
                           help="輸出 TPN draft .txt 路徑")
    gt_parser.add_argument("--version",     default="",
                           help="產品版本號 (用於 TPN header，例如 5.4.0)")

    # --- tpn-delta 子指令 ---
    td_parser = subparsers.add_parser(
        "tpn-delta",
        help="比對兩版本 TPN/SBOM，輸出 delta 報告 (v5.3.x → v5.4.x)",
    )
    td_parser.add_argument("--platform",    required=True, choices=["win", "linux"],
                           help="平台: win 或 linux")
    td_parser.add_argument("--old-tpn",     help="舊版 TPN FINAL .txt 路徑")
    td_parser.add_argument("--new-tpn",     help="新版 TPN FINAL/DRAFT .txt 路徑")
    td_parser.add_argument("--old-sbom",    help="舊版 SBOM .xlsx 路徑 (TPN 不存在時使用)")
    td_parser.add_argument("--new-sbom",    help="新版 SBOM .xlsx 路徑 (TPN 不存在時使用)")
    td_parser.add_argument("--old-label",   default="v5.3.x", help="舊版標籤 (預設: v5.3.x)")
    td_parser.add_argument("--new-label",   default="v5.4.x", help="新版標籤 (預設: v5.4.x)")
    td_parser.add_argument("--output",      required=True,
                           help="輸出 delta 報告 .md 路徑")

    args = parser.parse_args()

    if args.command == "check":
        cmd_check(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command in ("review-ux", "review-xlsx"):
        cmd_review_ux(args)
    elif args.command == "review-bomc":
        cmd_review_bomc(args)
    elif args.command == "review-onecli":
        cmd_review_onecli(args)
    elif args.command == "gen-tpn":
        cmd_gen_tpn(args)
    elif args.command == "tpn-delta":
        cmd_tpn_delta(args)
    else:
        parser.print_help()
        sys.exit(1)


def cmd_check(args):
    """執行 SBOM 驗證"""
    # 解析 CSV
    parser = SbomParser()
    try:
        sbom_data = parser.parse(args.csv_path)
    except FileNotFoundError:
        print(f"錯誤: 找不到檔案 {args.csv_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"錯誤: 解析 CSV 失敗: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"已解析: {len(sbom_data.targets)} 個 Target, "
          f"{len(sbom_data.sources)} 個 Source, "
          f"{len(sbom_data.sections)} 個區段, "
          f"平台: {sbom_data.platform}")

    validator = SbomValidator()

    if args.check_refs_only or not args.source_dir:
        # 僅參照驗證
        result = validator.check_source_references(sbom_data)
    else:
        # 完整驗證: 參照 + CMake 交叉比對
        scanner = CmakeScanner()
        cmake_targets = scanner.scan_directory(args.source_dir)
        print(f"CMake 掃描: {len(cmake_targets)} 個 target")

        if scanner.warnings:
            print(f"CMake 警告: {len(scanner.warnings)} 個")
            for w in scanner.warnings[:10]:
                print(f"  - {w}")
            if len(scanner.warnings) > 10:
                print(f"  ... 還有 {len(scanner.warnings) - 10} 個警告")

        platform = args.platform or sbom_data.platform
        result = validator.check_cmake_coverage(sbom_data, cmake_targets, platform)

    # 輸出報表
    formatter = ReportFormatter()
    report = formatter.format(result)
    print(report)


def cmd_scan(args):
    """掃描 CMakeLists.txt 並列出輸出目標"""
    scanner = CmakeScanner()

    try:
        targets = scanner.scan_directory(args.source_dir)
    except Exception as e:
        print(f"錯誤: 掃描失敗: {e}", file=sys.stderr)
        sys.exit(1)

    platform = args.platform

    print(f"掃描完成: {len(targets)} 個 target")
    if scanner.warnings:
        print(f"警告: {len(scanner.warnings)} 個")
        for w in scanner.warnings[:10]:
            print(f"  - {w}")
        if len(scanner.warnings) > 10:
            print(f"  ... 還有 {len(scanner.warnings) - 10} 個警告")

    # 輸出結果表格
    print()
    print("=" * 90)
    print(f"  {'Target Name':<25} {'Type':<12} {'Output Filename':<30} {'Platform'}")
    print("=" * 90)

    sorted_targets = sorted(targets, key=lambda t: (t.platform, t.target_name))
    current_platform = None

    for t in sorted_targets:
        if current_platform is not None and current_platform != t.platform:
            print("-" * 90)
        current_platform = t.platform

        output = t.get_output_filename(platform)
        print(f"  {t.target_name:<25} {t.target_type:<12} {output:<30} {t.platform}")

    print("=" * 90)


def cmd_review_ux(args):
    """執行 UpdateXpress Excel SBOM 審查 (review-ux / review-xlsx)"""
    try:
        platform = args.platform or auto_detect_platform(args.xlsx_path)
    except ValueError as e:
        print(f"錯誤: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        review_xlsx(
            sbom_path=args.xlsx_path,
            platform=platform,
            deps_info_path=args.deps_info,
            lock_path=args.lock,
            fossa_json_path=args.fossa_json,
            onecli_json_path=args.onecli_json,
            output_path=args.output,
        )
    except FileNotFoundError as e:
        print(f"錯誤: 找不到檔案 {e}", file=sys.stderr)
        sys.exit(1)
    except ImportError:
        print("錯誤: 需要 openpyxl。請執行: pip install openpyxl", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"錯誤: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_review_bomc(args):
    """執行 BoMC Excel SBOM 審查"""
    try:
        platform = args.platform or auto_detect_platform(args.xlsx_path)
    except ValueError as e:
        print(f"錯誤: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        review_bomc(
            sbom_path=args.xlsx_path,
            platform=platform,
            lock_path=args.lock,
            output_path=args.output,
        )
    except FileNotFoundError as e:
        print(f"錯誤: 找不到檔案 {e}", file=sys.stderr)
        sys.exit(1)
    except ImportError:
        print("錯誤: 需要 openpyxl。請執行: pip install openpyxl", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"錯誤: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_review_onecli(args):
    """[BACKLOG] OneCLI SBOM 審查 — 尚未實作"""
    print(
        "review-onecli 尚未實作 (BACKLOG)。\n"
        "計畫方向：OPTION-A — 審查 OneCLI 自己的 SBOM Excel，\n"
        "使用 OneCLI 的 sbom_checker review-ux 流程進行交叉驗證。",
        file=sys.stderr,
    )
    sys.exit(1)


def cmd_gen_tpn(args):
    """生成 TPN draft (Approach B: FULL + STUB)"""
    from .tpn_generator import generate_tpn
    try:
        generate_tpn(
            platform=args.platform,
            fossa_json_path=Path(args.fossa_json),
            onecli_tpn_path=Path(args.onecli_tpn),
            pkg_lock_path=Path(args.pkg_lock),
            output_path=Path(args.output),
            product_version=args.version,
        )
    except FileNotFoundError as e:
        print(f"錯誤: 找不到檔案 {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"錯誤: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_tpn_delta(args):
    """比對兩版本 TPN/SBOM delta"""
    from .tpn_delta import run_delta
    try:
        run_delta(
            platform=args.platform,
            old_tpn_path=Path(args.old_tpn) if args.old_tpn else None,
            new_tpn_path=Path(args.new_tpn) if args.new_tpn else None,
            old_sbom_path=Path(args.old_sbom) if args.old_sbom else None,
            new_sbom_path=Path(args.new_sbom) if args.new_sbom else None,
            output_path=Path(args.output),
            old_label=args.old_label,
            new_label=args.new_label,
        )
    except FileNotFoundError as e:
        print(f"錯誤: 找不到檔案 {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"錯誤: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
