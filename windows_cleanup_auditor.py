from __future__ import annotations

import argparse
import os
import traceback

from wca.core import APP_NAME, APP_VERSION, get_local_fixed_drives, human_size, write_report
from wca.gui import run_gui
from wca.scanner import Scanner


def default_scan_roots() -> list[str]:
    system_drive = os.environ.get("SystemDrive", "C:").strip().strip('"').rstrip("\\/")
    return [system_drive + "\\"]


def normalize_scan_root(value: str) -> str:
    root = value.strip().strip('"')
    while root.endswith(':"'):
        root = root[:-1]
    if len(root) == 2 and root[0].isalpha() and root[1] == ":":
        return root.upper() + "\\"
    return os.path.abspath(root)


def run_cli(roots: list[str], thorough: bool, min_mb: float, report_dir: str) -> int:
    print(f"{APP_NAME} {APP_VERSION}")
    print("Roots:", ", ".join(roots))
    scanner = Scanner(roots, thorough=thorough, min_bytes=int(min_mb * 1024 * 1024), event_cb=lambda e, p=None: print(p) if e == "status" else None)
    candidates = scanner.run()
    meta = {"roots": roots, "thorough": thorough, "candidate_count": len(candidates),
            "candidate_bytes": sum(c.size for c in candidates),
            "visited_dirs": getattr(scanner, "_visited_dirs", 0),
            "errors": getattr(scanner, "_errors", 0),
            "aliases_skipped": getattr(scanner, "_alias_skipped", 0),
            "pruned_dirs": getattr(scanner, "_pruned_dirs", 0)}
    jp, cp = write_report(report_dir, meta, candidates)
    print(f"Found: {len(candidates)}; {human_size(sum(c.size for c in candidates))}")
    print("JSON:", jp)
    print("CSV:", cp)
    print("CLI mode does not delete anything.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} {APP_VERSION}")
    parser.add_argument("--cli", action="store_true")
    parser.add_argument("--root", action="append")
    parser.add_argument("--all-drives", action="store_true")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--min-mb", type=float, default=1.0)
    parser.add_argument("--report-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports"))
    args = parser.parse_args(argv)
    if args.cli:
        roots = args.root or (get_local_fixed_drives() if args.all_drives else default_scan_roots())
        roots = [normalize_scan_root(root) for root in roots]
        return run_cli(roots, not args.quick, args.min_mb, args.report_dir)
    run_gui()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception:
        traceback.print_exc()
        try:
            input("\nError. Press Enter to exit...")
        except Exception:
            pass
        raise
