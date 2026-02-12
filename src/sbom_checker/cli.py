"""CLI 進入點 — argparse 子指令"""

import argparse
import sys

from .sbom_parser import SbomParser
from .cmake_scanner import CmakeScanner
from .validator import SbomValidator
from .report import ReportFormatter


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

    args = parser.parse_args()

    if args.command == "check":
        cmd_check(args)
    elif args.command == "scan":
        cmd_scan(args)
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


if __name__ == "__main__":
    main()
