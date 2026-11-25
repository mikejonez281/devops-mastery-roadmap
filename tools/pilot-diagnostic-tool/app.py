import tkinter
import customtkinter
from customtkinter import filedialog, CTkImage
from PIL import Image
import sys
import os
import time
from collections import Counter
import threading
from queue import Queue
from functools import partial
import itertools
from anomaly_engine import analyze_log_anomalies
from log_parser import parse_log_file, parse_log_line
from datetime import datetime

# --- UI Setup ---
customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("dark-blue")


def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller."""
    try:
        base_path = sys._MEIPASS
        return os.path.join(base_path, relative_path)
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("Pilot Diagnostic Tool")
        self.state("zoomed")
        self.update()

        try:
            icon_path = resource_path("pilot_logo.ico")
            self.iconbitmap(icon_path)
        except tkinter.TclError:
            pass

        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        self.filter_queue = Queue()
        self.is_filtering = False
        self.current_filter_id = 0

        # Sidebar
        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")

        self.sidebar_content_frame = customtkinter.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.sidebar_content_frame.pack(side="top", fill="both", expand=True)

        self.sidebar_footer_frame = customtkinter.CTkFrame(self.sidebar_frame, fg_color="black")
        self.sidebar_footer_frame.pack(side="bottom", fill="x", expand=False, pady=20, padx=20)

        self.logo_label = customtkinter.CTkLabel(
            self.sidebar_frame,
            text="Pilot Diagnostic Tool",
            font=customtkinter.CTkFont(size=20, weight="bold"),
        )
        self.logo_label.pack(in_=self.sidebar_content_frame, padx=20, pady=(20, 10), fill="x")

        self.sidebar_button_1 = customtkinter.CTkButton(
            self.sidebar_frame, command=self.on_click, text="Run Diagnostics"
        )
        self.sidebar_button_1.pack(in_=self.sidebar_content_frame, padx=20, pady=10, fill="x")

        self.sidebar_button_2 = customtkinter.CTkButton(
            self.sidebar_frame,
            command=self.browse_file,
            text="Browse Log File",
        )
        self.sidebar_button_2.pack(in_=self.sidebar_content_frame, padx=20, pady=10, fill="x")

        self.load_all_button = customtkinter.CTkButton(
            self.sidebar_frame,
            command=self.load_all_logs,
            text="Load All Logs",
        )
        self.load_all_button.pack(in_=self.sidebar_content_frame, padx=20, pady=10, fill="x")

        self.level_filter_label = customtkinter.CTkLabel(self.sidebar_frame, text="Filter by Level:", anchor="w")
        self.level_filter_label.pack(in_=self.sidebar_content_frame, padx=20, pady=(10, 0), anchor="w")

        self.level_filter_menu = customtkinter.CTkOptionMenu(
            self.sidebar_frame,
            values=["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "EXCEP", "HAL"],
            command=self.start_filter_debounce,
        )
        self.level_filter_menu.set("ALL")
        self.level_filter_menu.pack(in_=self.sidebar_content_frame, padx=20, pady=(0, 20), fill="x")

        self.keyword_frame = customtkinter.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.keyword_frame.pack(in_=self.sidebar_content_frame, padx=20, pady=(0, 10), fill="x")
        self.keyword_frame.grid_columnconfigure(0, weight=1)

        self.keyword_filter_label = customtkinter.CTkLabel(self.keyword_frame, text="Filter by Keyword:", anchor="w")
        self.keyword_filter_label.grid(row=0, column=0, padx=0, pady=(0, 2))

        self.keyword_filter_entry = customtkinter.CTkEntry(self.keyword_frame, placeholder_text="Enter keywords...")
        self.keyword_filter_entry.grid(row=1, column=0, padx=0, pady=(0, 0), sticky="ew")

        self.log_label = customtkinter.CTkLabel(self.keyword_frame, text="No log file loaded", anchor="w")
        self.log_label.grid(row=2, column=0, padx=0, pady=(5, 0), sticky="ew")

        # Logo handling
        self.logo_image = None
        try:
            logo_path = resource_path("pilot_logo.png")
            if os.path.exists(logo_path):
                original_image = Image.open(logo_path)
                original_width, original_height = original_image.size
                desired_height = 200
                aspect_ratio = original_width / original_height
                new_width = int(desired_height * aspect_ratio)
                self.logo_image = customtkinter.CTkImage(original_image, size=(new_width, desired_height))
                logo_widget = customtkinter.CTkLabel(self.sidebar_footer_frame, image=self.logo_image, text="")
                logo_widget.pack(side="top", anchor="center")
        except Exception as e:
            print(f"Logo load note: {e}")

        self.keyword_filter_entry.bind("<KeyRelease>", self.start_filter_debounce)

        # Content frame
        self.textbox_frame = customtkinter.CTkFrame(self)
        self.textbox_frame.grid(row=0, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew")
        self.textbox_frame.grid_rowconfigure(0, weight=1)
        self.textbox_frame.grid_columnconfigure(0, weight=1)

        self.content_frame = customtkinter.CTkFrame(self.textbox_frame)
        self.content_frame.grid(row=0, column=0, sticky="nsew")
        self.content_frame.grid_rowconfigure(1, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)

        # Find bar
        self.find_frame = customtkinter.CTkFrame(self.content_frame, height=30)
        self.find_frame.grid_columnconfigure(1, weight=1)

        self.find_label = customtkinter.CTkLabel(self.find_frame, text="Find:")
        self.find_label.grid(row=0, column=0, padx=(5, 2), pady=5)

        self.find_entry = customtkinter.CTkEntry(self.find_frame, placeholder_text="Search logs...")
        self.find_entry.grid(row=0, column=1, padx=2, pady=5, sticky="ew")

        self.find_next_button = customtkinter.CTkButton(self.find_frame, text="Next ↓", width=70, command=self.find_next)
        self.find_next_button.grid(row=0, column=2, padx=2, pady=5)

        self.find_prev_button = customtkinter.CTkButton(self.find_frame, text="Prev ↑", width=70, command=self.find_previous)
        self.find_prev_button.grid(row=0, column=3, padx=2, pady=5)

        self.close_find_button = customtkinter.CTkButton(self.find_frame, text="✕", width=30, command=self.hide_find_bar)
        self.close_find_button.grid(row=0, column=4, padx=(2, 5), pady=5)

        # Anomaly Report Toggle
        self.report_button = customtkinter.CTkButton(
            self.content_frame,
            text="🔍 Show Anomaly Report",
            command=self.toggle_anomaly_report,
            height=32,
        )
        self.report_button.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        self.report_panel = customtkinter.CTkFrame(self.content_frame)
        self.report_panel.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")
        self.report_panel.grid_remove()
        self.report_panel.grid_columnconfigure(0, weight=1)

        self.report_text = customtkinter.CTkTextbox(self.report_panel, height=150, wrap="none")
        self.report_text.grid(row=0, column=0, padx=5, pady=(5, 0), sticky="nsew")

        self.report_context_menu = tkinter.Menu(self, tearoff=0)
        self.report_context_menu.add_command(label="Copy", command=self.copy_selected_text_report)
        self.report_text.bind("<Button-3>", self.show_report_context_menu)

        self.resize_frame = customtkinter.CTkFrame(self.report_panel, height=8, fg_color="gray30")
        self.resize_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=(0, 5))
        self.resize_frame.bind("<Enter>", lambda e: self.resize_frame.configure(cursor="sb_v_double_arrow"))
        self.resize_frame.bind("<Leave>", lambda e: self.resize_frame.configure(cursor=""))
        self.resize_frame.bind("<Button-1>", self.start_resize)
        self.resize_frame.bind("<B1-Motion>", self.do_resize)
        self.initial_height = 150

        # Main Log Window
        self.log_scroll_frame = customtkinter.CTkFrame(self.content_frame)
        self.log_scroll_frame.grid(row=3, column=0, sticky="nsew")
        self.log_scroll_frame.grid_rowconfigure(0, weight=1)
        self.log_scroll_frame.grid_columnconfigure(0, weight=1)

        self.textbox = tkinter.Text(
            self.log_scroll_frame,
            wrap="none",
            bg="#2b2b2b",
            fg="white",
            insertbackground="white",
        )
        self.textbox.grid(row=0, column=0, sticky="nsew")

        self.log_scrollbar_y = customtkinter.CTkScrollbar(self.log_scroll_frame, command=self.textbox.yview)
        self.log_scrollbar_y.grid(row=0, column=1, sticky="ns")

        self.log_scrollbar_x = customtkinter.CTkScrollbar(self.log_scroll_frame, command=self.textbox.xview, orientation="horizontal")
        self.log_scrollbar_x.grid(row=1, column=0, sticky="ew")

        self.textbox.configure(yscrollcommand=self.log_scrollbar_y.set, xscrollcommand=self.log_scrollbar_x.set)

        self.textbox.tag_configure("ERROR", foreground="red")
        self.textbox.tag_configure("WARNING", foreground="yellow")
        self.textbox.tag_configure("EXCEP", foreground="orange")
        self.textbox.tag_configure("INFO", foreground="lightgreen")
        self.textbox.tag_configure("DEBUG", foreground="aqua")
        self.textbox.tag_configure("keyword_highlight", background="yellow", foreground="black")
        self.textbox.tag_configure("ANOMALY", foreground="cyan", font=("Arial", 10, "bold"))
        self.textbox.tag_configure("find_highlight", background="orange", foreground="black")

        self.context_menu = tkinter.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self.copy_selected_text)
        self.textbox.bind("<Button-3>", self.show_context_menu)

        self.bind_all("<Control-f>", self.show_find_bar)
        self.bind_all("<Escape>", self.hide_find_bar)
        self.find_entry.bind("<Return>", self.find_next)

        self.current_log_file_path = None
        self.diagnostics_run = False
        self.all_logs = []
        self.find_search_index = 0
        self.find_query = ""
        self.find_after_id = None
        self.filtered_logs = []
        self.filter_debounce_id = None
        self.current_page = 0
        self.page_size = 500

        self.log_cache = {}
        self.cache_size_limit = 3
        self.last_accessed = []

        # Pagination Frame
        self.pagination_frame = customtkinter.CTkFrame(self.textbox_frame, height=30)
        self.pagination_frame.grid(row=1, column=0, columnspan=2, padx=(10, 10), pady=(10, 0), sticky="ew")
        self.pagination_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.prev_button = customtkinter.CTkButton(self.pagination_frame, text="Previous Page", command=self.previous_page, state="disabled")
        self.prev_button.grid(row=0, column=0, padx=(10, 5), pady=5, sticky="ew")

        self.page_label = customtkinter.CTkLabel(self.pagination_frame, text="Page 0 of 0")
        self.page_label.grid(row=0, column=1, padx=5, pady=5)

        self.next_button = customtkinter.CTkButton(self.pagination_frame, text="Next Page", command=self.next_page, state="disabled")
        self.next_button.grid(row=0, column=2, padx=(5, 10), pady=5, sticky="ew")

        self.total_logs_label = customtkinter.CTkLabel(self.pagination_frame, text="Total Logs: 0")
        self.total_logs_label.grid(row=0, column=3, padx=10, pady=5, sticky="ew")

    def browse_file(self):
        file_path = customtkinter.filedialog.askopenfilename(
            parent=self,
            title="Select Log File",
            filetypes=[("Log Files", "*.log"), ("All Files", "*.*")],
        )
        if file_path:
            self.current_log_file_path = file_path
            self.log_label.configure(text=f"Log: {os.path.basename(file_path)}")
            self.textbox.delete("1.0", "end")
            self.keyword_filter_entry.delete(0, "end")
            self.level_filter_menu.set("ALL")
            self.all_logs = []
            self.filtered_logs = []
            self.diagnostics_run = False
            self.update_pagination_ui()
            self.reset_find_state()
            self.hide_find_bar()

    def on_click(self):
        self.diagnostics_run = True
        self.current_filter_id += 1
        self.textbox.delete("1.0", "end")
        self.filtered_logs = []
        self.current_page = 0
        self.update_pagination_ui()
        self.hide_find_bar()
        self.reset_find_state()

        if not self.current_log_file_path:
            self.textbox.insert("end", "⚠️ Please select a log file first by clicking 'Browse Log File'.")
            return

        filename = os.path.basename(self.current_log_file_path)
        self.textbox.insert("end", f"🔍 Running diagnostics on: {filename}\n\n")
        level_filter = self.level_filter_menu.get().upper()

        thread = threading.Thread(
            target=self._run_diagnostics_async,
            args=(self.current_filter_id, self.current_log_file_path, level_filter),
        )
        thread.daemon = True
        thread.start()
        self.after(50, self._check_filter_results)

    def load_all_logs(self):
        self.textbox.delete("1.0", "end")
        self.diagnostics_run = False
        self.reset_find_state()
        self.hide_find_bar()

        if self.current_log_file_path:
            self.current_filter_id += 1
            current_id = self.current_filter_id
            self.textbox.insert("end", f"Reading entries from: {os.path.basename(self.current_log_file_path)}...\n\n")
            self.update()

            thread = threading.Thread(
                target=self._load_all_logs_async,
                args=(current_id, self.current_log_file_path),
            )
            thread.daemon = True
            thread.start()
            self.after(50, self._check_filter_results)

    def _load_all_logs_async(self, filter_id, file_path):
        start_time = time.time()
        try:
            cached_logs = self.get_from_cache(file_path)
            if cached_logs:
                if filter_id == self.current_filter_id:
                    self.filter_queue.put({
                        "filter_id": filter_id,
                        "status": "load_complete",
                        "logs": cached_logs,
                        "message": "✓ Loaded from cache",
                    })
                return

            def parsing_progress_callback(progress, message):
                if filter_id == self.current_filter_id:
                    self.filter_queue.put({"filter_id": filter_id, "status": "progress", "message": message})

            all_logs = parse_log_file(file_path, progress_callback=parsing_progress_callback)
            all_logs.sort(key=lambda x: x.get("timestamp", datetime.min), reverse=True)
            self.update_cache(file_path, all_logs)

            duration = time.time() - start_time
            if filter_id == self.current_filter_id:
                self.filter_queue.put({
                    "filter_id": filter_id,
                    "status": "load_complete",
                    "logs": all_logs,
                    "duration": duration,
                    "message": f"All logs loaded in {duration:.2f} seconds. Total entries: {len(all_logs):,}",
                })
        except Exception as e:
            if filter_id == self.current_filter_id:
                self.filter_queue.put({"filter_id": filter_id, "status": "error", "message": str(e)})

    def _run_diagnostics_async(self, filter_id, file_path, level_filter):
        start_time = time.time()
        try:
            filter_levels = [level_filter] if level_filter != "ALL" else ["ERROR", "EXCEP", "CRITICAL"]

            def parsing_progress_callback(progress, message):
                if filter_id == self.current_filter_id:
                    self.filter_queue.put({"filter_id": filter_id, "status": "progress", "message": message})

            all_parsed_entries = parse_log_file(file_path, progress_callback=parsing_progress_callback)
            if filter_id != self.current_filter_id:
                return

            matching_entries = []
            for entry in all_parsed_entries:
                entry_level = str(entry.get("level", "")).strip().upper()
                if "ERR" in entry_level:
                    entry_level = "ERROR"
                elif "EXCEPT" in entry_level or "EXCEP" in entry_level:
                    entry_level = "EXCEP"
                elif "CRIT" in entry_level:
                    entry_level = "CRITICAL"

                if entry_level in filter_levels:
                    matching_entries.append(entry)

            duration = time.time() - start_time
            matching_entries.sort(key=lambda x: x.get("timestamp", datetime.min), reverse=True)

            if filter_id == self.current_filter_id:
                self.filter_queue.put({
                    "filter_id": filter_id,
                    "status": "diagnostic_complete",
                    "matching_entries": matching_entries,
                    "all_entries": all_parsed_entries,
                    "duration": duration,
                    "level_filter": level_filter,
                })
        except Exception as e:
            if filter_id == self.current_filter_id:
                self.filter_queue.put({"filter_id": filter_id, "status": "error", "message": str(e)})

    def update_anomaly_report(self, entries):
        try:
            analysis = analyze_log_anomalies(entries)
            self.report_text.delete("1.0", "end")
            self.report_text.insert("end", "=== ANOMALY ANALYSIS ===\n\n")

            for cat, title, emoji in [
                ("hardware_issues", "Hardware Issues", "🔧"),
                ("game_state_issues", "Game State Issues", "🎮"),
                ("io_event_issues", "IO/Peripheral Issues", "🔌"),
                ("system_issues", "System Issues", "🖥️"),
                ("memory_issues", "Memory Issues", "🧠"),
                ("network_issues", "Network Issues", "🌐"),
            ]:
                if analysis.get(cat):
                    self.report_text.insert("end", f"{emoji} {title}:\n")
                    for issue in analysis[cat]:
                        self.report_text.insert("end", f"   • {issue['message']}\n")
                    self.report_text.insert("end", "\n")

            if analysis.get("time_gaps"):
                self.report_text.insert("end", "🕐 Time Gap Analysis:\n")
                for gap in analysis["time_gaps"]:
                    self.report_text.insert("end", f"   Gap: {gap['start']} to {gap['end']} ({gap['duration']})\n")
                self.report_text.insert("end", "\n")

            if analysis.get("error_patterns"):
                self.report_text.insert("end", "🔥 Consecutive Error Patterns:\n")
                for pattern in analysis["error_patterns"]:
                    self.report_text.insert("end", f"   • {pattern['message']}\n")
                self.report_text.insert("end", "\n")

            total_issues = sum(len(analysis.get(k, [])) for k in ["hardware_issues", "game_state_issues", "io_event_issues", "system_issues", "network_issues", "memory_issues", "time_gaps"])
            if total_issues == 0:
                self.report_button.configure(text="🔍 Show Anomaly Report (All Clear)")
            else:
                self.report_button.configure(text=f"⚠️ Show Anomaly Report ({total_issues} Issues)")
                self.report_panel.grid()
        except Exception as e:
            self.report_text.delete("1.0", "end")
            self.report_text.insert("end", f"Error generating anomaly report: {e}\n")

    def show_raw_diagnostic_entries(self, entries):
        self.textbox.insert("end", "=== DIAGNOSTIC LOG ENTRIES ===\n\n")
        by_level = {}
        for entry in entries:
            level = str(entry.get("level", "")).strip().upper()
            if "ERR" in level:
                level = "ERROR"
            elif "EXCEPT" in level or "EXCEP" in level:
                level = "EXCEP"
            elif "CRIT" in level:
                level = "CRITICAL"
            by_level.setdefault(level, []).append(entry)

        for level in ["CRITICAL", "ERROR", "EXCEP"]:
            if level in by_level:
                sub_entries = by_level[level]
                emoji = "🔴" if level == "CRITICAL" else "⛔" if level == "ERROR" else "⚠️"
                self.textbox.insert("end", f"{emoji} {level}: {len(sub_entries)} entries\n", level)
                for entry in sub_entries:
                    timestamp = entry.get("timestamp", "")
                    if hasattr(timestamp, "strftime"):
                        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    msg = str(entry.get("message", "")).strip()
                    component = entry.get("component", "").strip()
                    self.textbox.insert("end", f"   [{timestamp}] {component}: {msg}\n", level)
                self.textbox.insert("end", "\n")

    def start_filter_debounce(self, event=None):
        if self.filter_debounce_id:
            self.after_cancel(self.filter_debounce_id)
        self.filter_debounce_id = self.after(300, self.filter_logs)

    def filter_logs(self, event=None):
        self.current_filter_id += 1
        current_id = self.current_filter_id
        self.reset_find_state()
        level_filter = self.level_filter_menu.get().upper()
        keyword_filter = self.keyword_filter_entry.get().lower()

        if self.diagnostics_run:
            self.on_click()
            return

        if not self.all_logs:
            self.filtered_logs = []
            self.current_page = 0
            self.display_page()
            return

        thread = threading.Thread(
            target=self._filter_logs_async,
            args=(current_id, level_filter, keyword_filter),
        )
        thread.daemon = True
        thread.start()
        self.after(50, self._check_filter_results)

    def _filter_logs_async(self, filter_id, level_filter, keyword_filter):
        filtered = []
        for entry in self.all_logs:
            if filter_id != self.current_filter_id:
                return
            if level_filter != "ALL":
                lvl = str(entry.get("level", "")).strip().upper()
                if level_filter not in lvl:
                    continue
            if keyword_filter:
                text = (str(entry.get("message", "")) + " " + str(entry.get("component", ""))).lower()
                if keyword_filter not in text:
                    continue
            filtered.append(entry)

        filtered.sort(key=lambda x: x.get("timestamp", datetime.min), reverse=True)
        if filter_id == self.current_filter_id:
            self.filter_queue.put({"filter_id": filter_id, "status": "complete", "logs": filtered})

    def _check_filter_results(self):
        while not self.filter_queue.empty():
            res = self.filter_queue.get_nowait()
            if res.get("filter_id") == self.current_filter_id:
                status = res.get("status")
                if status == "complete":
                    self.filtered_logs = res["logs"]
                    self.current_page = 0
                    self.display_page()
                    return
                elif status == "diagnostic_complete":
                    self.textbox.delete("1.0", "end")
                    self.show_raw_diagnostic_entries(res["matching_entries"])
                    self.update_anomaly_report(res["all_entries"])
                    self.update_pagination_ui()
                    return
                elif status == "load_complete":
                    self.all_logs = res["logs"]
                    self.filtered_logs = self.all_logs.copy()
                    self.current_page = 0
                    self.display_page()
                    self.update_anomaly_report(self.all_logs)
                    return
        if self.current_filter_id > 0:
            self.after(50, self._check_filter_results)

    def display_page(self):
        self.textbox.delete("1.0", "end")
        if not self.filtered_logs:
            self.textbox.insert("end", "No logs match the current filter.\n")
            self.update_pagination_ui()
            return

        start = self.current_page * self.page_size
        end = start + self.page_size
        page_logs = self.filtered_logs[start:end]

        for entry in page_logs:
            ts = entry.get("timestamp", "")
            if hasattr(ts, "strftime"):
                ts = ts.strftime("%Y-%m-%d %H:%M:%S")
            lvl = str(entry.get("level", "INFO"))
            comp = entry.get("component", "")
            msg = entry.get("message", "")
            line = f"[{ts}] [{lvl:7}] {comp}: {msg}\n"
            self.textbox.insert("end", line)

        self.update_pagination_ui()

    def previous_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.display_page()

    def next_page(self):
        if (self.current_page + 1) * self.page_size < len(self.filtered_logs):
            self.current_page += 1
            self.display_page()

    def update_pagination_ui(self):
        total = (len(self.filtered_logs) + self.page_size - 1) // self.page_size
        if total == 0 and len(self.filtered_logs) > 0:
            total = 1
        self.page_label.configure(text=f"Page {self.current_page + 1} of {total}")
        self.total_logs_label.configure(text=f"Total: {len(self.filtered_logs)}")
        self.prev_button.configure(state="normal" if self.current_page > 0 else "disabled")
        self.next_button.configure(state="normal" if (self.current_page + 1) * self.page_size < len(self.filtered_logs) else "disabled")

    def toggle_anomaly_report(self):
        if self.report_panel.winfo_viewable():
            self.report_panel.grid_remove()
            self.report_button.configure(text="🔍 Show Anomaly Report")
        else:
            self.report_panel.grid()
            self.report_button.configure(text="🔍 Hide Anomaly Report")

    def update_cache(self, file_path, logs):
        if file_path in self.last_accessed:
            self.last_accessed.remove(file_path)
        self.last_accessed.insert(0, file_path)
        self.log_cache[file_path] = logs
        if len(self.log_cache) > self.cache_size_limit:
            oldest = self.last_accessed.pop()
            self.log_cache.pop(oldest, None)

    def get_from_cache(self, file_path):
        return self.log_cache.get(file_path)

    def start_resize(self, event):
        self.resize_frame.initial_y = event.y_root
        self.resize_frame.initial_height = self.report_text.winfo_height()

    def do_resize(self, event):
        delta = event.y_root - self.resize_frame.initial_y
        new_h = max(50, min(self.winfo_height() - 200, self.resize_frame.initial_height + delta))
        self.report_text.configure(height=new_h)

    def reset_find_state(self):
        self.find_search_index = 0
        self.find_query = ""

    def show_find_bar(self, event=None):
        self.find_frame.grid(row=0, column=0, padx=5, pady=(5, 0), sticky="ew")
        self.find_entry.focus_set()
        return "break"

    def hide_find_bar(self, event=None):
        self.find_frame.grid_remove()
        self.textbox.tag_remove("find_highlight", "1.0", "end")
        self.reset_find_state()
        self.textbox.focus_set()

    def find_next(self, event=None):
        pass

    def find_previous(self, event=None):
        pass

    def show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def copy_selected_text(self):
        try:
            text = self.textbox.get(tkinter.SEL_FIRST, tkinter.SEL_LAST)
            self.clipboard_clear()
            self.clipboard_append(text)
        except Exception:
            pass

    def show_report_context_menu(self, event):
        try:
            self.report_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.report_context_menu.grab_release()

    def copy_selected_text_report(self):
        try:
            text = self.report_text.get(tkinter.SEL_FIRST, tkinter.SEL_LAST)
            self.clipboard_clear()
            self.clipboard_append(text)
        except Exception:
            pass


if __name__ == "__main__":
    app = App()
    app.mainloop()
