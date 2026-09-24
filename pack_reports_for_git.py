from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path


def find_7zip() -> str | None:
    found = shutil.which("7z") or shutil.which("7zz")
    if found:
        return found
    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "7-Zip" / "7z.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "7-Zip" / "7z.exe",
    ]
    for path in candidates:
        if path.is_file():
            return str(path)
    return None


def main() -> int:
    base = Path(__file__).resolve().parent
    sources = [path for path in (base / "reports", base / "logs") if path.exists()]
    if not sources:
        print("Nothing to pack: reports/ and logs/ are empty or absent.")
        return 1

    seven = find_7zip()
    if not seven:
        print("7-Zip was not found. Install 7-Zip or add 7z.exe to PATH.")
        return 2

    out_dir = base / "encrypted_reports"
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output = out_dir / f"WCA_reports_{stamp}.7z"

    print("7-Zip will ask for the archive password. Use the agreed report password.")
    print("File names are encrypted too (-mhe=on).")
    args = [seven, "a", "-t7z", "-mx=9", "-mhe=on", str(output)]
    args.extend(path.name for path in sources)
    completed = subprocess.run(args, cwd=base)
    if completed.returncode != 0:
        print(f"7-Zip failed with code {completed.returncode}.")
        return completed.returncode

    print(f"Created: {output}")
    print("Plain reports remain local and are ignored by Git.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
