from __future__ import annotations

import os
import threading
import time

from .core import Candidate, RISK_CAUTION, RISK_ORDER, dir_stats, file_stats, has_forbidden_component, is_reparse_or_link, path_has_reparse_component, path_is_within, path_on_roots
from .rules import classify_directory, deep_scan_prune_roots, is_backup_tree_path, is_tool_install_root, known_directory_candidates, targeted_file_candidates

PRUNE_DIR_NAMES = {"$recycle.bin", "system volume information", "recovery", "winsxs", "windowsapps", "wpsystem"}
NEVER_INSIDE_NAMES = {".git", ".svn", ".hg"}


class Scanner:
    def __init__(self, roots: list[str], thorough: bool = True, min_bytes: int = 0, event_cb=None, cancel_event: threading.Event | None = None):
        self.roots = [os.path.abspath(r) for r in roots]
        self.thorough = thorough
        self.min_bytes = min_bytes
        self.event_cb = event_cb or (lambda *args, **kwargs: None)
        self.cancel_event = cancel_event or threading.Event()
        self._candidates: dict[str, Candidate] = {}
        self._visited_dirs = 0
        self._errors = 0
        self._alias_skipped = 0
        self._reparse_skipped = 0
        self._pruned_dirs = 0
        self._prune_roots = deep_scan_prune_roots()

    def emit(self, event: str, payload=None):
        try:
            self.event_cb(event, payload)
        except Exception:
            pass

    def add_candidate(self, path: str, category: str, kind: str, risk: str, reason: str, keep_root: bool = False, source: str = "scan") -> bool:
        if self.cancel_event.is_set():
            return False
        path = os.path.abspath(path)
        if not path_on_roots(path, self.roots) or not os.path.exists(path):
            return False
        if has_forbidden_component(path) or path_has_reparse_component(path):
            self._reparse_skipped += 1
            return False
        key = os.path.normcase(path)
        for old_key, old_candidate in list(self._candidates.items()):
            try:
                if os.path.samefile(path, old_candidate.path):
                    self._alias_skipped += 1
                    return False
            except OSError:
                pass
            try:
                common = os.path.commonpath([key, old_key])
            except ValueError:
                continue
            if common == old_key:
                return False
            if common == key:
                del self._candidates[old_key]
        if source != "deep":
            self.emit("status", f"Подсчёт: {path}")
        size, files, dirs = dir_stats(path, self.cancel_event) if os.path.isdir(path) else file_stats(path)
        if size < self.min_bytes:
            return False
        if source == "deep":
            self.emit("status", f"Найдено: {path}")
        c = Candidate(path, category, kind, risk, reason, size, files, dirs, source, keep_root)
        self._candidates[key] = c
        self.emit("candidate", c)
        return True

    def scan_known_locations(self):
        self.emit("status", "Проверяю известные системные и разработческие места…")
        for entry in known_directory_candidates() + targeted_file_candidates():
            if self.cancel_event.is_set():
                return
            self.add_candidate(*entry, source="known")

    def _covered(self, path: str) -> bool:
        p = os.path.normcase(os.path.abspath(path))
        for key in self._candidates:
            try:
                if os.path.commonpath([p, key]) == key:
                    return True
            except ValueError:
                pass
        return False

    def _pruned(self, path: str) -> bool:
        return any(path_is_within(path, root) for root in self._prune_roots) or is_tool_install_root(path)

    def scan_roots(self):
        if not self.thorough:
            return
        self.emit("status", "Начинаю тщательный обход выбранных дисков…")
        for root in self.roots:
            stack = [root]
            while stack and not self.cancel_event.is_set():
                current = stack.pop()
                self._visited_dirs += 1
                if self._visited_dirs % 250 == 0:
                    self.emit("progress", {"dirs": self._visited_dirs, "errors": self._errors, "current": current})
                try:
                    with os.scandir(current) as it:
                        for entry in it:
                            if self.cancel_event.is_set():
                                break
                            try:
                                if is_reparse_or_link(entry.path):
                                    self._reparse_skipped += 1
                                    continue
                                if not entry.is_dir(follow_symlinks=False):
                                    continue
                                low_name = entry.name.lower()
                                if low_name in PRUNE_DIR_NAMES or low_name in NEVER_INSIDE_NAMES:
                                    continue
                                if self._covered(entry.path):
                                    continue
                                if self._pruned(entry.path):
                                    self._pruned_dirs += 1
                                    continue
                                cls = classify_directory(entry.path)
                                if cls:
                                    if is_backup_tree_path(entry.path):
                                        cls = (cls[0], cls[1], RISK_CAUTION, cls[3] + "; объект находится внутри резервной копии")
                                    if self.add_candidate(entry.path, *cls, source="deep"):
                                        continue
                                low = entry.path.lower().replace("/", "\\")
                                if "\\windows\\servicing" in low or "\\windows\\installer" in low:
                                    continue
                                stack.append(entry.path)
                            except OSError:
                                self._errors += 1
                except OSError:
                    self._errors += 1

    def run(self) -> list[Candidate]:
        started = time.time()
        self.scan_known_locations()
        self.scan_roots()
        values = sorted(self._candidates.values(), key=lambda c: (RISK_ORDER.get(c.risk, 9), c.category.lower(), -c.size, c.path.lower()))
        self.emit("done", {"candidates": values, "dirs": self._visited_dirs, "errors": self._errors,
                           "aliases_skipped": self._alias_skipped, "reparse_skipped": self._reparse_skipped,
                           "pruned_dirs": self._pruned_dirs,
                           "seconds": time.time() - started, "cancelled": self.cancel_event.is_set()})
        return values
