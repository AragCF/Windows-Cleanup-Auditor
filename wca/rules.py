from __future__ import annotations

import fnmatch
import os
import re
import shutil
from pathlib import Path

from .core import (
    CATEGORY_DOTNET, CATEGORY_FLUTTER, CATEGORY_GRADLE, CATEGORY_IDE, CATEGORY_INSTALLERS,
    CATEGORY_IOS, CATEGORY_JAVA, CATEGORY_NODE, CATEGORY_OTHER, CATEGORY_PROJECT,
    CATEGORY_PYTHON, CATEGORY_SYSTEM, RISK_CAUTION, RISK_REBUILD, RISK_SAFE,
    canonical_real_path, has_forbidden_component, path_has_reparse_component, protected_install_roots,
)

def _unique_existing_dirs(paths) -> list[str]:
    """Resolve directory aliases to their physical target and return each tree once."""
    result = []
    seen = set()
    for value in paths:
        if not value:
            continue
        original = os.path.abspath(str(value))
        if not os.path.isdir(original):
            continue
        full = canonical_real_path(original) if path_has_reparse_component(original) else original
        if not os.path.isdir(full):
            continue
        key = os.path.normcase(full)
        if key in seen:
            continue
        duplicate = False
        for existing in result:
            try:
                if os.path.samefile(full, existing):
                    duplicate = True
                    break
            except OSError:
                pass
        if duplicate:
            continue
        seen.add(key)
        result.append(full)
    return result


def android_sdk_roots() -> list[str]:
    env = os.environ
    home = env.get("USERPROFILE") or str(Path.home())
    local = env.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
    return _unique_existing_dirs([
        env.get("ANDROID_SDK_ROOT"),
        env.get("ANDROID_HOME"),
        os.path.join(local, "Android", "Sdk"),
    ])


def flutter_sdk_roots() -> list[str]:
    env = os.environ
    roots = [env.get("FLUTTER_ROOT"), env.get("FLUTTER_HOME")]
    found = shutil.which("flutter") or shutil.which("flutter.bat")
    if found:
        roots.append(str(Path(found).resolve().parent.parent))
    for sdk in android_sdk_roots():
        roots.append(os.path.join(sdk, "flutter"))
    return [
        root for root in _unique_existing_dirs(roots)
        if os.path.isfile(os.path.join(root, "bin", "flutter.bat"))
    ]


def deep_scan_prune_roots() -> list[str]:
    return _unique_existing_dirs(protected_install_roots() + android_sdk_roots() + flutter_sdk_roots())


def is_tool_install_root(path: str) -> bool:
    p = Path(path)
    name = p.name.lower()
    try:
        if name == "flutter" and (p / "bin" / "flutter.bat").is_file():
            return True
        if name in {"sdk", "android-sdk", "android_tools", "android-tools"}:
            markers = sum((p / child).exists() for child in ("platform-tools", "build-tools", "platforms", "cmdline-tools"))
            if markers >= 2:
                return True
        if re.fullmatch(r"python\d+(?:\.\d+)?", name) and (p / "python.exe").is_file() and (p / "Lib").is_dir():
            return True
        if name in {"miniconda3", "anaconda3"} and (p / "python.exe").is_file():
            if (p / "Scripts" / "conda.exe").exists() or (p / "condabin" / "conda.bat").exists():
                return True
    except OSError:
        return False
    return False


def is_backup_tree_path(path: str) -> bool:
    for part in Path(path).parts:
        low = part.lower()
        if low.endswith(".bak") or ".bak." in low:
            return True
    return False


PROJECT_MARKERS = {
    "settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts", "gradlew", "gradlew.bat",
    "pubspec.yaml", "pyproject.toml", "setup.py", "requirements.txt", "package.json", "pom.xml", "CMakeLists.txt",
}


def _contains_marker_near(path: str, max_up: int = 2, markers: set[str] | None = None) -> bool:
    markers = markers or PROJECT_MARKERS
    cur = Path(path)
    for _ in range(max_up + 1):
        try:
            if {p.name for p in cur.iterdir()} & markers:
                return True
        except OSError:
            pass
        if cur.parent == cur:
            break
        cur = cur.parent
    return False


def _parent_has_any(path: str, patterns: set[str], max_up: int = 2) -> bool:
    cur = Path(path)
    pats = {x.lower() for x in patterns}
    for _ in range(max_up + 1):
        try:
            names = [p.name.lower() for p in cur.iterdir()]
        except OSError:
            names = []
        if any(any(fnmatch.fnmatch(name, pat) for pat in pats) for name in names):
            return True
        if cur.parent == cur:
            break
        cur = cur.parent
    return False


def classify_directory(path: str):
    p = Path(path)
    name = p.name.lower()
    parent = p.parent
    low = str(p).lower().replace("/", "\\")
    if has_forbidden_component(path):
        return None

    if name == "__pycache__":
        return CATEGORY_PYTHON, "Python __pycache__", RISK_SAFE, "Скомпилированные байт-коды Python; создаются заново"
    if name in {".pytest_cache", ".mypy_cache", ".ruff_cache", ".hypothesis", ".coverage_cache"}:
        return CATEGORY_PYTHON, f"Python {p.name}", RISK_SAFE, "Кэш инструмента Python; создаётся заново"

    if name in {"bin", "obj"} and _parent_has_any(str(parent), {"*.csproj", "*.sln"}, 1):
        return CATEGORY_PROJECT, f".NET {p.name}", RISK_SAFE, "Промежуточный результат сборки .NET"
    if name == ".vs" and _parent_has_any(str(parent), {"*.sln"}, 1):
        return CATEGORY_IDE, "Visual Studio .vs", RISK_SAFE, "Локальный кэш Visual Studio"

    if name == "build" and _contains_marker_near(str(parent), 2, {
        "settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts", "gradlew", "gradlew.bat", "pubspec.yaml"
    }):
        if _contains_marker_near(str(parent), 2, {"pubspec.yaml"}):
            return CATEGORY_FLUTTER, "Flutter build", RISK_SAFE, "Промежуточная сборка Flutter; создаётся заново"
        return CATEGORY_GRADLE, "Gradle build", RISK_SAFE, "Промежуточная сборка Gradle/Android; создаётся заново"
    if name in {".cxx", "captures"} and _contains_marker_near(str(parent), 3, {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}):
        return CATEGORY_GRADLE, f"Android {p.name}", RISK_SAFE, "Промежуточные Android/NDK данные"
    if name == ".gradle" and _contains_marker_near(str(parent), 1, {"settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts", "gradlew", "gradlew.bat"}):
        return CATEGORY_GRADLE, "Локальный .gradle проекта", RISK_SAFE, "Локальное состояние Gradle проекта; восстанавливается"

    if name == ".dart_tool" and _contains_marker_near(str(parent), 1, {"pubspec.yaml"}):
        return CATEGORY_FLUTTER, "Flutter .dart_tool", RISK_SAFE, "Служебные данные Flutter/Dart; создаются заново"
    if name == "build" and _contains_marker_near(str(parent), 1, {"pyproject.toml", "setup.py"}):
        return CATEGORY_PROJECT, "Python packaging build", RISK_CAUTION, "Артефакты упаковки Python; могут содержать готовые дистрибутивы"
    if name == "dist" and _contains_marker_near(str(parent), 1, {"pyproject.toml", "setup.py"}):
        return CATEGORY_PROJECT, "Python packaging dist", RISK_CAUTION, "Готовые пакеты Python; удалять только если копия не нужна"
    if name.endswith(".egg-info") and _contains_marker_near(str(parent), 1, {"pyproject.toml", "setup.py"}):
        return CATEGORY_PROJECT, "Python *.egg-info", RISK_REBUILD, "Метаданные сборки Python; обычно создаются заново"

    if name in {".venv", "venv", "env"} and _contains_marker_near(str(parent), 1, {"pyproject.toml", "requirements.txt", "setup.py"}):
        return CATEGORY_OTHER, "Виртуальная среда Python", RISK_CAUTION, "Можно пересоздать, но проект временно потеряет установленное окружение"
    if name == "node_modules" and _contains_marker_near(str(parent), 1, {"package.json"}):
        return CATEGORY_OTHER, "node_modules", RISK_CAUTION, "Зависимости проекта; потребуется npm/yarn/pnpm install"
    if name == "cmakefiles" and _contains_marker_near(str(parent), 2, {"CMakeLists.txt"}):
        return CATEGORY_PROJECT, "CMakeFiles", RISK_SAFE, "Промежуточные файлы CMake"

    if name == "cache" and parent.name.lower() == "bin" and (parent / "flutter.bat").exists():
        return CATEGORY_FLUTTER, "Flutter SDK bin\\cache", RISK_REBUILD, "Кэш Flutter SDK; компоненты будут загружены заново"

    if name in {"caches", "cache", "log", "logs", "tmp"}:
        if "\\appdata\\local\\google\\androidstudio" in low:
            return CATEGORY_IDE, f"Android Studio {p.name}", RISK_SAFE, "Кэш/журналы Android Studio"
        if "\\appdata\\local\\jetbrains\\" in low:
            return CATEGORY_IDE, f"JetBrains {p.name}", RISK_SAFE, "Кэш/журналы JetBrains"
    if name in {"cache", "cacheddata", "gpucache", "code cache", "cachestorage"} and "\\appdata\\roaming\\code\\" in low:
        return CATEGORY_IDE, f"VS Code {p.name}", RISK_SAFE, "Кэш Visual Studio Code"
    return None


def known_directory_candidates() -> list[tuple[str, str, str, str, str, bool]]:
    env = os.environ
    home = env.get("USERPROFILE") or str(Path.home())
    local = env.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
    roaming = env.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
    windir = env.get("WINDIR", r"C:\Windows")
    temp = env.get("TEMP") or env.get("TMP") or os.path.join(local, "Temp")
    items = [
        (temp, CATEGORY_SYSTEM, "TEMP пользователя", RISK_SAFE, "Временные файлы текущего пользователя", True),
        (os.path.join(windir, "Temp"), CATEGORY_SYSTEM, "Windows Temp", RISK_SAFE, "Системные временные файлы; занятые будут пропущены", True),
        (os.path.join(local, "CrashDumps"), CATEGORY_SYSTEM, "CrashDumps", RISK_REBUILD, "Дампы аварий; нужны только для диагностики", False),
        (os.path.join(home, ".gradle", "caches"), CATEGORY_GRADLE, "Gradle global caches", RISK_REBUILD, "Общий кэш Gradle; зависимости будут скачаны заново", False),
        (os.path.join(home, ".gradle", "daemon"), CATEGORY_GRADLE, "Gradle daemon", RISK_SAFE, "Состояние и журналы демонов Gradle", False),
        (os.path.join(home, ".gradle", "workers"), CATEGORY_GRADLE, "Gradle workers", RISK_SAFE, "Временное состояние Gradle workers", False),
        (os.path.join(home, ".gradle", "native"), CATEGORY_GRADLE, "Gradle native", RISK_REBUILD, "Нативный кэш Gradle", False),
        (os.path.join(home, ".gradle", "wrapper", "dists"), CATEGORY_GRADLE, "Gradle wrapper distributions", RISK_REBUILD, "Дистрибутивы Gradle Wrapper", False),
        (os.path.join(home, ".android", "cache"), CATEGORY_GRADLE, "Android cache", RISK_SAFE, "Кэш Android tooling; AVD и ключи не затрагиваются", False),
        (os.path.join(local, "pip", "Cache"), CATEGORY_PYTHON, "pip cache", RISK_REBUILD, "Кэш пакетов pip", False),
        (os.path.join(home, ".m2", "repository"), CATEGORY_JAVA, "Maven local repository", RISK_REBUILD, "Локальные Maven-зависимости", False),
        (os.path.join(home, ".nuget", "packages"), CATEGORY_DOTNET, "NuGet packages", RISK_REBUILD, "Локальные пакеты NuGet", False),
        (os.path.join(local, "npm-cache"), CATEGORY_NODE, "npm cache", RISK_REBUILD, "Кэш npm", False),
        (os.path.join(local, "Yarn", "Cache"), CATEGORY_NODE, "Yarn cache", RISK_REBUILD, "Кэш Yarn", False),
        (os.path.join(local, "pnpm", "store"), CATEGORY_NODE, "pnpm store", RISK_REBUILD, "Хранилище pnpm", False),
        (os.path.join(home, ".cargo", "registry", "cache"), CATEGORY_OTHER, "Cargo registry cache", RISK_REBUILD, "Кэш архивов Cargo", False),
    ]
    pub = env.get("PUB_CACHE") or os.path.join(local, "Pub", "Cache")
    items.append((pub, CATEGORY_FLUTTER, "Pub cache", RISK_REBUILD, "Общий кэш Dart/Flutter", False))
    for sdk in android_sdk_roots():
        items.append((os.path.join(sdk, ".temp"), CATEGORY_GRADLE, "Android SDK .temp", RISK_SAFE, "Временные файлы Android SDK Manager", False))
    for flutter in flutter_sdk_roots():
        items.append((os.path.join(flutter, "bin", "cache"), CATEGORY_FLUTTER, "Flutter SDK bin\\cache", RISK_REBUILD,
                      "Кэш Flutter SDK; компоненты будут загружены заново", False))
    return items


def targeted_file_candidates() -> list[tuple[str, str, str, str, str, bool]]:
    env = os.environ
    home = env.get("USERPROFILE") or str(Path.home())
    local = Path(env.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local")))
    roaming = Path(env.get("APPDATA", os.path.join(home, "AppData", "Roaming")))
    result = []

    imazing = roaming / "iMazing"
    if imazing.exists():
        try:
            for item in imazing.rglob("*"):
                if item.is_file() and item.suffix.lower() == ".ipa":
                    result.append((str(item), CATEGORY_IOS, "Локальный пакет iMazing (.ipa)", RISK_CAUTION,
                                   "Локальная копия приложения iOS; установленное на телефоне приложение не затрагивается", False))
        except OSError:
            pass

    for root_text in android_sdk_roots():
        root = Path(root_text)
        try:
            for item in root.iterdir():
                if item.is_file() and item.suffix.lower() in {".zip", ".7z", ".rar", ".exe", ".msi"}:
                    result.append((str(item), CATEGORY_INSTALLERS, "Архив/установщик рядом с Android SDK", RISK_CAUTION,
                                   "Отдельный скачанный архив/установщик; проверьте, что распакованная или установленная копия уже есть", False))
        except OSError:
            pass
    return result
