from __future__ import annotations

import csv
import ctypes
import json
import os
import re
import shutil
import stat
import threading
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

APP_NAME = "Ревизор дискового мусора"
APP_VERSION = "0.2.4"

RISK_SAFE = "Безопасно"
RISK_REBUILD = "Восстанавливаемое"
RISK_CAUTION = "Осторожно"
RISK_ORDER = {RISK_SAFE: 0, RISK_REBUILD: 1, RISK_CAUTION: 2}

CATEGORY_SYSTEM = "Системные временные файлы"
CATEGORY_IDE = "Кэши сред разработки"
CATEGORY_GRADLE = "Gradle и Android"
CATEGORY_FLUTTER = "Flutter и Dart"
CATEGORY_PYTHON = "Python"
CATEGORY_JAVA = "Java / Maven / Kotlin"
CATEGORY_NODE = "Node.js / npm / Yarn / pnpm"
CATEGORY_DOTNET = ".NET / NuGet"
CATEGORY_PROJECT = "Промежуточные файлы проектов"
CATEGORY_OTHER = "Прочие восстанавливаемые данные"
CATEGORY_IOS = "iMazing / iOS"
CATEGORY_INSTALLERS = "Установщики и архивы разработчика"

NEVER_INSIDE_NAMES = {".git", ".svn", ".hg"}


@dataclass(frozen=True)
class Candidate:
    path: str
    category: str
    kind: str
    risk: str
    reason: str
    size: int
    files: int
    dirs: int
    source: str = "scan"
    keep_root: bool = False

    @property
    def key(self) -> str:
        return os.path.normcase(os.path.abspath(self.path))


def human_size(value: int) -> str:
    n = float(max(0, value))
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"):
        if n < 1024 or unit == "ПБ":
            return f"{int(n)} {unit}" if unit == "Б" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{value} Б"


def is_windows() -> bool:
    return os.name == "nt"


def get_local_fixed_drives() -> list[str]:
    if not is_windows():
        return [os.path.abspath(os.sep)]
    k32 = ctypes.windll.kernel32
    mask = k32.GetLogicalDrives()
    result = []
    for i in range(26):
        if mask & (1 << i):
            root = f"{chr(65 + i)}:\\"
            if k32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 3:
                result.append(root)
    return result


def path_is_within(path: str, root: str) -> bool:
    p = os.path.normcase(os.path.abspath(path))
    r = os.path.normcase(os.path.abspath(root))
    try:
        return os.path.commonpath([p, r]) == r
    except ValueError:
        return False


def path_on_roots(path: str, roots: Iterable[str]) -> bool:
    return any(path_is_within(path, root) for root in roots)


def protected_install_roots() -> list[str]:
    env = os.environ
    home = env.get("USERPROFILE") or str(Path.home())
    local = env.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
    programdata = env.get("PROGRAMDATA", r"C:\ProgramData")
    roots = [
        env.get("WINDIR"),
        env.get("ProgramFiles"),
        env.get("ProgramFiles(x86)"),
        os.path.join(local, "Programs"),
        os.path.join(programdata, "miniconda3"),
        os.path.join(programdata, "anaconda3"),
        os.path.join(home, "miniconda3"),
        os.path.join(home, "anaconda3"),
    ]
    result = []
    seen = set()
    for root in roots:
        if not root:
            continue
        key = os.path.normcase(os.path.abspath(root))
        if key not in seen:
            seen.add(key)
            result.append(os.path.abspath(root))
    return result


def is_protected_installed_path(path: str) -> bool:
    full = os.path.abspath(path)
    low = full.lower().replace("/", "\\")
    if re.match(r"^[a-z]:\\python\d+(?:\.\d+)?(?:\\|$)", low):
        return True
    return any(path_is_within(full, root) for root in protected_install_roots())


def has_forbidden_component(path: str) -> bool:
    return bool({p.lower() for p in Path(path).parts} & NEVER_INSIDE_NAMES)


def is_reparse_or_link(path: str) -> bool:
    """True for symlinks, junctions and other Windows reparse points."""
    try:
        if os.path.islink(path):
            return True
        isjunction = getattr(os.path, "isjunction", None)
        if isjunction is not None and isjunction(path):
            return True
        attrs = getattr(os.lstat(path), "st_file_attributes", 0)
        flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return bool(attrs & flag)
    except OSError:
        return False


def path_has_reparse_component(path: str) -> bool:
    """Reject not only a link itself, but any path that passes through one."""
    try:
        current = Path(os.path.abspath(path))
        for item in (current, *current.parents):
            if is_reparse_or_link(str(item)):
                return True
    except (OSError, RuntimeError):
        return True
    return False


def canonical_real_path(path: str) -> str:
    """Return the physical target path without keeping a junction/symlink alias."""
    return os.path.abspath(os.path.realpath(os.path.abspath(path)))


def dir_stats(path: str, cancel: threading.Event | None = None) -> tuple[int, int, int]:
    total = files = dirs = 0
    stack = [path]
    while stack:
        if cancel and cancel.is_set():
            break
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if cancel and cancel.is_set():
                        break
                    try:
                        if is_reparse_or_link(entry.path):
                            continue
                        if entry.is_file(follow_symlinks=False):
                            files += 1
                            try:
                                total += entry.stat(follow_symlinks=False).st_size
                            except OSError:
                                pass
                        elif entry.is_dir(follow_symlinks=False) and not is_reparse_or_link(entry.path):
                            dirs += 1
                            stack.append(entry.path)
                    except OSError:
                        pass
        except OSError:
            pass
    return total, files, dirs


def file_stats(path: str) -> tuple[int, int, int]:
    try:
        return os.path.getsize(path), 1, 0
    except OSError:
        return 0, 0, 0


def _make_writable(path: str) -> None:
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass


def remove_path(path: str) -> tuple[bool, str]:
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            def onerror(func, p, exc):
                _make_writable(p)
                func(p)
            shutil.rmtree(path, onerror=onerror)
        else:
            _make_writable(path)
            os.remove(path)
        return True, ""
    except FileNotFoundError:
        return True, "Уже отсутствует"
    except Exception as exc:
        return False, str(exc)


def clear_directory_contents(path: str) -> tuple[bool, str]:
    try:
        entries = list(os.scandir(path))
    except FileNotFoundError:
        return True, "Уже отсутствует"
    except Exception as exc:
        return False, str(exc)
    errors = []
    for entry in entries:
        try:
            if entry.is_dir(follow_symlinks=False) and not entry.is_symlink():
                ok, err = remove_path(entry.path)
            else:
                ok, err = remove_path(entry.path)
            if not ok:
                errors.append(f"{entry.path}: {err}")
        except Exception as exc:
            errors.append(f"{entry.path}: {exc}")
    return not errors, "; ".join(errors[:10])


def protected_exact_paths() -> set[str]:
    env = os.environ
    result = set()
    for p in (env.get("WINDIR"), env.get("ProgramFiles"), env.get("ProgramFiles(x86)"), env.get("USERPROFILE"), env.get("PUBLIC")):
        if p:
            result.add(os.path.normcase(os.path.abspath(p)))
    for drive in get_local_fixed_drives():
        result.add(os.path.normcase(os.path.abspath(drive)))
    return result


def validate_delete_target(path: str) -> tuple[bool, str]:
    full = os.path.normcase(os.path.abspath(path))
    if full in protected_exact_paths():
        return False, "Защитный запрет на удаление корневого/системного каталога"
    env = os.environ
    allowed = {
        os.path.normcase(os.path.abspath(p))
        for p in (
            env.get("TEMP"),
            env.get("TMP"),
            os.path.join(env.get("WINDIR", r"C:\Windows"), "Temp"),
        )
        if p
    }
    if path_has_reparse_component(path):
        return False, "Защитный запрет: путь проходит через символическую ссылку, junction или другую точку повторного разбора"
    if full not in allowed and is_protected_installed_path(path):
        return False, "Защитный запрет: объект находится внутри установленной программы или системного дерева"
    if has_forbidden_component(path):
        return False, "Защитный запрет: путь внутри системы контроля версий"
    if is_reparse_or_link(path):
        return False, "Защитный запрет: ссылка или точка повторного разбора"
    return True, ""


def write_report(report_dir: str, scan_meta: dict, candidates: list[Candidate], deletion_results: list[dict] | None = None) -> tuple[str, str]:
    os.makedirs(report_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    jp = os.path.join(report_dir, f"cleanup_report_{stamp}.json")
    cp = os.path.join(report_dir, f"cleanup_report_{stamp}.csv")
    data = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "scan": scan_meta,
        "candidates": [asdict(c) for c in candidates],
        "deletion_results": deletion_results or [],
    }
    with open(jp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    fields = ["category", "kind", "risk", "size", "files", "dirs", "path", "reason", "source"]
    with open(cp, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter=";")
        w.writeheader()
        for c in candidates:
            w.writerow({k: getattr(c, k) for k in fields})
    return jp, cp
