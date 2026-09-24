from __future__ import annotations

import os
import queue
import threading
import time

from .core import (
    APP_NAME, APP_VERSION, Candidate, RISK_CAUTION, RISK_REBUILD, RISK_SAFE,
    clear_directory_contents, get_local_fixed_drives, human_size, remove_path,
    validate_delete_target, write_report,
)
from .scanner import Scanner


def run_gui() -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(f"{APP_NAME} {APP_VERSION}")
            self.geometry("1280x780")
            self.minsize(980, 620)
            self.protocol("WM_DELETE_WINDOW", self.on_close)

            self.drives = get_local_fixed_drives()
            self.drive_vars: dict[str, tk.BooleanVar] = {}
            self.events: queue.Queue = queue.Queue()
            self.cancel_event = threading.Event()
            self.scan_thread: threading.Thread | None = None
            self.candidates: list[Candidate] = []
            self.by_iid: dict[str, Candidate] = {}
            self.category_iids: dict[str, str] = {}
            self.checked: set[str] = set()
            self.scan_meta: dict = {}

            self._build_ui()
            self.after(100, self._poll_events)

        def _build_ui(self):
            top = ttk.Frame(self, padding=10)
            top.pack(fill="x")
            ttk.Label(top, text="Диски:").grid(row=0, column=0, sticky="w", padx=(0, 8))
            col = 1
            system_root = os.environ.get("SystemDrive", "C:").rstrip("\\") + "\\"
            has_system_root = any(drive.lower() == system_root.lower() for drive in self.drives)
            for index, drive in enumerate(self.drives):
                selected_by_default = drive.lower() == system_root.lower() or (index == 0 and not has_system_root)
                var = tk.BooleanVar(value=selected_by_default)
                self.drive_vars[drive] = var
                ttk.Checkbutton(top, text=drive, variable=var).grid(row=0, column=col, sticky="w", padx=4)
                col += 1
            ttk.Button(top, text="Все", command=lambda: self._set_all_drives(True)).grid(row=0, column=col, padx=(10, 3))
            ttk.Button(top, text="Ни одного", command=lambda: self._set_all_drives(False)).grid(row=0, column=col + 1, padx=3)

            self.thorough_var = tk.BooleanVar(value=True)
            ttk.Checkbutton(top, text="Тщательно обходить выбранные диски", variable=self.thorough_var).grid(row=1, column=0, columnspan=4, sticky="w", pady=(8, 0))
            ttk.Label(top, text="Минимальный размер:").grid(row=1, column=4, sticky="e", padx=(20, 6), pady=(8, 0))
            self.min_mb_var = tk.StringVar(value="1")
            ttk.Spinbox(top, from_=0, to=102400, width=8, textvariable=self.min_mb_var).grid(row=1, column=5, sticky="w", pady=(8, 0))
            ttk.Label(top, text="МБ").grid(row=1, column=6, sticky="w", pady=(8, 0))

            actions = ttk.Frame(self, padding=(10, 0, 10, 8))
            actions.pack(fill="x")
            self.scan_btn = ttk.Button(actions, text="Найти мусор", command=self.start_scan)
            self.scan_btn.pack(side="left")
            self.stop_btn = ttk.Button(actions, text="Остановить", command=self.stop_scan, state="disabled")
            self.stop_btn.pack(side="left", padx=6)
            self.safe_btn = ttk.Button(actions, text="Выбрать только безопасное", command=self.select_safe, state="disabled")
            self.safe_btn.pack(side="left", padx=(18, 6))
            self.clear_btn = ttk.Button(actions, text="Снять выбор", command=self.clear_selection, state="disabled")
            self.clear_btn.pack(side="left", padx=6)
            self.delete_btn = ttk.Button(actions, text="Удалить выбранное…", command=self.delete_selected, state="disabled")
            self.delete_btn.pack(side="left", padx=(18, 6))
            self.report_btn = ttk.Button(actions, text="Сохранить отчёт…", command=self.save_report_as, state="disabled")
            self.report_btn.pack(side="left", padx=6)

            main = ttk.Panedwindow(self, orient="vertical")
            main.pack(fill="both", expand=True, padx=10)
            table_frame = ttk.Frame(main)
            details_frame = ttk.Frame(main)
            main.add(table_frame, weight=4)
            main.add(details_frame, weight=1)

            columns = ("check", "risk", "size", "files", "kind", "path")
            self.tree = ttk.Treeview(table_frame, columns=columns, show="tree headings", selectmode="browse")
            self.tree.heading("#0", text="Категория")
            for key, title in (("check", "✓"), ("risk", "Риск"), ("size", "Размер"), ("files", "Файлы"), ("kind", "Тип"), ("path", "Путь")):
                self.tree.heading(key, text=title)
            self.tree.column("#0", width=245, stretch=False)
            self.tree.column("check", width=42, anchor="center", stretch=False)
            self.tree.column("risk", width=135, stretch=False)
            self.tree.column("size", width=100, anchor="e", stretch=False)
            self.tree.column("files", width=80, anchor="e", stretch=False)
            self.tree.column("kind", width=230)
            self.tree.column("path", width=520)
            sy = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
            sx = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
            self.tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
            self.tree.grid(row=0, column=0, sticky="nsew")
            sy.grid(row=0, column=1, sticky="ns")
            sx.grid(row=1, column=0, sticky="ew")
            table_frame.rowconfigure(0, weight=1)
            table_frame.columnconfigure(0, weight=1)
            self.tree.bind("<Double-1>", self.toggle_current)
            self.tree.bind("<space>", self.toggle_current)
            self.tree.bind("<<TreeviewSelect>>", self.show_details)

            self.details = tk.Text(details_frame, height=7, wrap="word", state="disabled")
            self.details.pack(fill="both", expand=True)

            bottom = ttk.Frame(self, padding=10)
            bottom.pack(fill="x")
            self.summary_var = tk.StringVar(value="Найдено: 0 Б · выбрано: 0 Б")
            self.status_var = tk.StringVar(value="Готово к сканированию.")
            ttk.Label(bottom, textvariable=self.summary_var).pack(anchor="w")
            ttk.Label(bottom, textvariable=self.status_var).pack(anchor="w", pady=(4, 0))

        def _set_all_drives(self, value: bool):
            for var in self.drive_vars.values():
                var.set(value)

        def start_scan(self):
            roots = [d for d, var in self.drive_vars.items() if var.get()]
            if not roots:
                messagebox.showwarning(APP_NAME, "Выберите хотя бы один диск.")
                return
            try:
                min_mb = max(0.0, float(self.min_mb_var.get().replace(",", ".")))
            except ValueError:
                messagebox.showwarning(APP_NAME, "Неверный минимальный размер.")
                return

            self.cancel_event = threading.Event()
            self.candidates.clear(); self.by_iid.clear(); self.category_iids.clear(); self.checked.clear()
            for item in self.tree.get_children(""):
                self.tree.delete(item)
            started = time.time()
            self.scan_meta = {"roots": roots, "thorough": self.thorough_var.get(), "min_mb": min_mb, "started_at": started}
            self.scan_btn.config(state="disabled"); self.stop_btn.config(state="normal")
            self.safe_btn.config(state="disabled"); self.clear_btn.config(state="disabled")
            self.delete_btn.config(state="disabled"); self.report_btn.config(state="disabled")
            self.status_var.set("Подготовка сканирования…")
            scanner = Scanner(roots, self.thorough_var.get(), int(min_mb * 1024 * 1024), lambda e, p=None: self.events.put((e, p)), self.cancel_event)
            self.scan_thread = threading.Thread(target=scanner.run, daemon=True)
            self.scan_thread.start()

        def stop_scan(self):
            self.cancel_event.set()
            self.status_var.set("Останавливаю после текущей операции…")

        def _poll_events(self):
            try:
                while True:
                    event, payload = self.events.get_nowait()
                    if event == "status":
                        self.status_var.set(str(payload))
                    elif event == "candidate":
                        self._add_candidate(payload)
                    elif event == "progress":
                        self.status_var.set(f"Проверено каталогов: {payload['dirs']:,}; недоступно: {payload['errors']:,}; сейчас: {payload['current']}")
                    elif event == "done":
                        self._scan_done(payload)
            except queue.Empty:
                pass
            self.after(100, self._poll_events)

        def _category_iid(self, category: str) -> str:
            if category not in self.category_iids:
                self.category_iids[category] = self.tree.insert("", "end", text=category, values=("☐", "", "0 Б", "0", "", ""), open=True)
            return self.category_iids[category]

        def _add_candidate(self, c: Candidate):
            self.candidates.append(c)
            parent = self._category_iid(c.category)
            iid = self.tree.insert(parent, "end", values=("☐", c.risk, human_size(c.size), f"{c.files:,}", c.kind, c.path))
            self.by_iid[iid] = c
            self._refresh_category(parent)
            self._update_summary()

        def _refresh_category(self, parent: str):
            children = [x for x in self.tree.get_children(parent) if x in self.by_iid]
            size = sum(self.by_iid[x].size for x in children)
            files = sum(self.by_iid[x].files for x in children)
            mark = "☑" if children and all(x in self.checked for x in children) else "☐"
            self.tree.set(parent, "check", mark); self.tree.set(parent, "size", human_size(size)); self.tree.set(parent, "files", f"{files:,}")

        def _scan_done(self, payload: dict):
            self.scan_btn.config(state="normal"); self.stop_btn.config(state="disabled")
            state = "normal" if self.candidates else "disabled"
            self.safe_btn.config(state=state); self.clear_btn.config(state=state); self.delete_btn.config(state=state); self.report_btn.config(state="normal")
            self.scan_meta.update({"dirs": payload["dirs"], "errors": payload["errors"], "seconds": payload["seconds"], "cancelled": payload["cancelled"], "candidate_count": len(self.candidates), "candidate_bytes": sum(c.size for c in self.candidates)})
            report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
            try:
                write_report(report_dir, self.scan_meta, self.candidates)
            except Exception:
                pass
            prefix = "Сканирование остановлено" if payload["cancelled"] else "Сканирование завершено"
            self.status_var.set(f"{prefix}: {len(self.candidates)} объектов, {human_size(sum(c.size for c in self.candidates))}; каталогов {payload['dirs']:,}, ошибок доступа {payload['errors']:,}.")

        def toggle_current(self, event=None):
            iid = self.tree.focus()
            if not iid:
                return "break"
            if iid in self.by_iid:
                if iid in self.checked:
                    self.checked.remove(iid); self.tree.set(iid, "check", "☐")
                else:
                    self.checked.add(iid); self.tree.set(iid, "check", "☑")
                self._refresh_category(self.tree.parent(iid))
            else:
                children = [x for x in self.tree.get_children(iid) if x in self.by_iid]
                check = not children or not all(x in self.checked for x in children)
                for child in children:
                    if check:
                        self.checked.add(child); self.tree.set(child, "check", "☑")
                    else:
                        self.checked.discard(child); self.tree.set(child, "check", "☐")
                self._refresh_category(iid)
            self._update_summary()
            return "break"

        def select_safe(self):
            self.checked.clear()
            for iid, c in self.by_iid.items():
                if c.risk == RISK_SAFE:
                    self.checked.add(iid); self.tree.set(iid, "check", "☑")
                else:
                    self.tree.set(iid, "check", "☐")
            for parent in self.category_iids.values():
                self._refresh_category(parent)
            self._update_summary()

        def clear_selection(self):
            self.checked.clear()
            for iid in self.by_iid:
                self.tree.set(iid, "check", "☐")
            for parent in self.category_iids.values():
                self._refresh_category(parent)
            self._update_summary()

        def _update_summary(self):
            total = sum(c.size for c in self.candidates)
            selected = sum(self.by_iid[x].size for x in self.checked if x in self.by_iid)
            self.summary_var.set(f"Найдено: {human_size(total)} · выбрано: {human_size(selected)}")

        def show_details(self, event=None):
            c = self.by_iid.get(self.tree.focus())
            self.details.config(state="normal"); self.details.delete("1.0", "end")
            if c:
                self.details.insert("1.0", f"Категория: {c.category}\nТип: {c.kind}\nРиск: {c.risk}\nРазмер: {human_size(c.size)}\nФайлов: {c.files:,}; каталогов: {c.dirs:,}\nПуть: {c.path}\nПочему найдено: {c.reason}\nИсточник: {c.source}\nСпособ очистки: {'очистить содержимое, сохранив корень' if c.keep_root else 'удалить объект целиком'}")
            self.details.config(state="disabled")

        def delete_selected(self):
            selected = [self.by_iid[x] for x in self.checked if x in self.by_iid]
            if not selected:
                messagebox.showinfo(APP_NAME, "Ничего не выбрано."); return
            total = sum(c.size for c in selected)
            caution = [c for c in selected if c.risk == RISK_CAUTION]
            rebuild = [c for c in selected if c.risk == RISK_REBUILD]
            text = f"Выбрано объектов: {len(selected)}\nОжидаемое освобождение: {human_size(total)}\n\nУдаление постоянное: Корзина не используется."
            if rebuild:
                text += f"\nВосстанавливаемых объектов: {len(rebuild)} — возможны повторные загрузки."
            if caution:
                text += f"\nОбъектов «Осторожно»: {len(caution)} — проверьте их особенно внимательно."
            if not messagebox.askyesno(APP_NAME, text + "\n\nПродолжить?", icon="warning"):
                return
            if caution and simpledialog.askstring(APP_NAME, "Для удаления объектов «Осторожно» введите слово УДАЛИТЬ:", parent=self) != "УДАЛИТЬ":
                messagebox.showinfo(APP_NAME, "Удаление отменено."); return

            results = []; freed = 0; ok_count = 0; failed = 0
            for n, c in enumerate(selected, 1):
                self.status_var.set(f"Удаление {n}/{len(selected)}: {c.path}"); self.update_idletasks()
                valid, why = validate_delete_target(c.path)
                if valid:
                    ok, err = clear_directory_contents(c.path) if c.keep_root else remove_path(c.path)
                else:
                    ok, err = False, why
                results.append({"path": c.path, "ok": ok, "error": err, "size": c.size})
                if ok:
                    ok_count += 1; freed += c.size
                    iid = next((x for x, obj in self.by_iid.items() if obj.key == c.key), None)
                    if iid:
                        parent = self.tree.parent(iid); self.checked.discard(iid); self.tree.delete(iid); del self.by_iid[iid]
                        if self.tree.get_children(parent): self._refresh_category(parent)
                        else:
                            self.tree.delete(parent)
                            self.category_iids = {k: v for k, v in self.category_iids.items() if v != parent}
                else:
                    failed += 1
            self.candidates = list(self.by_iid.values())
            self.scan_meta["estimated_freed_bytes"] = freed
            report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
            try:
                write_report(report_dir, self.scan_meta, self.candidates, results)
            except Exception:
                pass
            self._update_summary()
            self.status_var.set(f"Удаление завершено: успешно {ok_count}, ошибок {failed}; освобождено около {human_size(freed)}.")
            messagebox.showinfo(APP_NAME, f"Готово.\nУспешно: {ok_count}\nОшибок: {failed}\nОценочно освобождено: {human_size(freed)}")

        def save_report_as(self):
            directory = filedialog.askdirectory(title="Куда сохранить отчёт")
            if not directory:
                return
            try:
                paths = write_report(directory, self.scan_meta, self.candidates)
                messagebox.showinfo(APP_NAME, f"Отчёты сохранены:\n{paths[0]}\n{paths[1]}")
            except Exception as exc:
                messagebox.showerror(APP_NAME, f"Не удалось сохранить отчёт:\n{exc}")

        def on_close(self):
            if self.scan_thread and self.scan_thread.is_alive():
                if not messagebox.askyesno(APP_NAME, "Сканирование ещё идёт. Остановить и выйти?"):
                    return
                self.cancel_event.set()
            self.destroy()

    App().mainloop()
