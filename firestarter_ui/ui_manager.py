# firestarter_ui/ui_manager.py
"""
Manages the Tkinter UI for the Firestarter application.

This module houses the main Tkinter application class (FirestarterApp),
manages UI construction, widget layout, event handling, delegates tasks
to firestarter_operations.py, and updates UI via callbacks/queue.
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import logging
import os  # Added for path operations
from pathlib import Path  # Added for path operations
from queue import Queue

from firestarter import __version__ as firestarter_version
from firestarter_ui import __version__ as ui_version

from firestarter_ui.firestarter_operations import FirestarterOperations
from firestarter_ui.operation_panels import OPERATION_PANELS

# Import Firestarter components for direct use in UI
from firestarter.database import EpromDatabase
from firestarter_ui.firestarter_operations import (
    FIRESTARTER_AVAILABLE,
)  # To check if real DB can be used
from firestarter.config import ConfigManager as RealFirestarterConfigManager

# If these modules are imported, we assume the Firestarter library is available.
FIRESTARTER_AVAILABLE = True
FIRESTARTER_CONFIG_AVAILABLE = True


class QueueHandler(logging.Handler):
    """A custom logging handler that sends records to a queue."""

    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def emit(self, record):
        """
        Puts the formatted log message into the queue with a specific type.
        """
        self.queue.put(("rurp_log", self.format(record)))


class PreferencesDialog(tk.Toplevel):
    def __init__(self, parent, config_manager):
        super().__init__(parent)
        self.transient(parent)
        self.title("Preferences")
        self.config_manager = config_manager

        # Logging Settings
        logging_frame = ttk.Frame(self, padding="10")
        logging_frame.pack(fill=tk.X)
        self.verbose_logging = tk.BooleanVar(
            value=self.config_manager.get_value("verbose_logging", default=False)
        )
        verbose_check = ttk.Checkbutton(
            logging_frame,
            text="Enable Verbose Logging",
            variable=self.verbose_logging,
        )
        verbose_check.pack(anchor=tk.W, pady=(0, 2))

        # Debug Logging Setting
        self.debug_logging = tk.BooleanVar(
            value=self.config_manager.get_value("debug_logging", default=False)
        )
        debug_check = ttk.Checkbutton(
            logging_frame,
            text="Enable Debug Logging",
            variable=self.debug_logging,
        )
        debug_check.pack(anchor=tk.W, pady=2)

        # Add other settings as needed, e.g.,
        # - Default directory for file operations
        # - Serial port settings (if not auto-detected)
        # - UI theme options

        # Example: Default Directory
        # dir_frame = ttk.Frame(self, padding="10")
        # dir_frame.pack(fill=tk.X)
        # ttk.Label(dir_frame, text="Default Directory:").pack(side=tk.LEFT)
        # self.default_dir = tk.StringVar(value=self.config_manager.get_value("default_dir", default="."))
        # ttk.Entry(dir_frame, textvariable=self.default_dir).pack(side=tk.LEFT, expand=True, fill=tk.X)

        # Buttons
        button_frame = ttk.Frame(self, padding="10")
        button_frame.pack(fill=tk.X)
        ttk.Button(button_frame, text="Save", command=self.save_preferences).pack(
            side=tk.RIGHT
        )
        ttk.Button(button_frame, text="Cancel", command=self.destroy).pack(
            side=tk.RIGHT, padx=5
        )

    def save_preferences(self):
        self.config_manager.set_value("verbose_logging", self.verbose_logging.get())
        self.config_manager.set_value("debug_logging", self.debug_logging.get())
        self.destroy()


class EpromSearchDialog(tk.Toplevel):
    def __init__(self, parent, all_eproms, title="Search EPROM"):
        super().__init__(parent)


class EpromSearchDialog(tk.Toplevel):
    def __init__(self, parent, all_eproms, title="Search EPROM"):
        super().__init__(parent)
        self.transient(parent)  # Show above parent
        self.title(title)
        self.parent = parent
        self.all_eproms = sorted(list(set(all_eproms)))  # Ensure unique and sorted
        self.result = None

        self.geometry("400x350")  # Adjust as needed

        # Search Entry
        search_frame = ttk.Frame(self, padding="5")
        search_frame.pack(fill=tk.X)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(fill=tk.X, expand=True)
        self.search_entry.bind("<KeyRelease>", self._on_search_keypress)

        # Listbox with Scrollbar
        list_frame = ttk.Frame(self, padding="5")
        list_frame.pack(fill=tk.BOTH, expand=True)
        self.listbox = tk.Listbox(
            list_frame, exportselection=False
        )  # exportselection=False allows programmatic selection
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(
            list_frame, orient=tk.VERTICAL, command=self.listbox.yview
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.config(yscrollcommand=scrollbar.set)
        self.listbox.bind("<<ListboxSelect>>", self._on_listbox_select)
        self.listbox.bind("<Double-1>", self._on_select_button)  # Double click

        # Buttons
        button_frame = ttk.Frame(self, padding="5")
        button_frame.pack(fill=tk.X)
        self.select_button = ttk.Button(
            button_frame,
            text="Select",
            command=self._on_select_button,
            state=tk.DISABLED,
        )
        self.select_button.pack(side=tk.RIGHT, padx=5)
        cancel_button = ttk.Button(
            button_frame, text="Cancel", command=self._on_cancel_button
        )
        cancel_button.pack(side=tk.RIGHT)

        self._populate_listbox(self.all_eproms)  # Initial population
        self.search_entry.focus_set()

        self.protocol(
            "WM_DELETE_WINDOW", self._on_cancel_button
        )  # Handle window close button
        self.grab_set()  # Make modal
        self.wait_window(self)  # Wait until this window is destroyed

    def _populate_listbox(self, items):
        self.listbox.delete(0, tk.END)
        for item in items:
            self.listbox.insert(tk.END, item)
        self._on_listbox_select()  # Update button state

    def _on_search_keypress(self, event=None):
        query = self.search_var.get().lower()
        if not query:
            filtered_eproms = self.all_eproms
        else:
            filtered_eproms = [
                eprom for eprom in self.all_eproms if query in eprom.lower()
            ]
        self._populate_listbox(filtered_eproms)

    def _on_listbox_select(self, event=None):
        if self.listbox.curselection():
            self.select_button.config(state=tk.NORMAL)
        else:
            self.select_button.config(state=tk.DISABLED)

    def _on_select_button(self, event=None):
        selected_indices = self.listbox.curselection()
        if selected_indices:
            self.result = self.listbox.get(selected_indices[0])
        self.destroy()

    def _on_cancel_button(self):
        self.result = None
        self.destroy()


class FirestarterApp(tk.Tk):
    """
    Main application class for the Firestarter UI.
    """

    def __init__(self):
        super().__init__()
        self.title("Firestarter UI")
        self.LAST_EPROM_CONFIG_KEY = "eprom"  # More specific key
        self.LAST_DEVICE_CONFIG_KEY = "device_port"  # More specific key
        self.WINDOW_GEOMETRY_CONFIG_KEY = "window_geometry"
        self.VERBOSE_LOGGING_CONFIG_KEY = "verbose_logging"
        self.DEBUG_LOGGING_CONFIG_KEY = "debug_logging"
        self.LAST_OPERATION_CONFIG_KEY = "last_operation"
        # Initialize FirestarterOperations and ConfigManager early to use for geometry
        self.db = EpromDatabase()  # Initialize EpromDatabase instance (db)

        self.ui_queue = Queue()

        self.selected_device = tk.StringVar()

        # Initialize EpromDatabase instance to be passed to FirestarterOperations
        # This instance (db_for_operations) will be the one used by FirestarterOperations

        # Initialize ConfigManager for the UI, using "config_ui.json"
        self.config_manager = None
        self.config_manager = RealFirestarterConfigManager(
            config_filename="config_ui.json"
        )
        logging.info("ConfigManager for UI (config_ui.json) initialized.")

        self.firestarter_ops = FirestarterOperations(
            self.ui_queue, self.db, self.config_manager
        )

        # Load and set window geometry
        saved_geometry = self.config_manager.get_value(self.WINDOW_GEOMETRY_CONFIG_KEY)
        if saved_geometry:
            logging.debug(f"Restoring window geometry: {saved_geometry}")
            self.geometry(saved_geometry)

        last_device = self.config_manager.get_value(self.LAST_DEVICE_CONFIG_KEY)
        if last_device and last_device != "None":
            self.selected_device.set(last_device)
        else:
            self.selected_device.set(
                "None"
            )  # Ensure consistent default if not found or "None"

        self.current_operation = None
        # Load last selected EPROM
        last_eprom = "None"
        saved_eprom = self.config_manager.get_value(self.LAST_EPROM_CONFIG_KEY)
        if saved_eprom and saved_eprom != "None":
            last_eprom = saved_eprom

        self.selected_eprom_type = tk.StringVar(value=last_eprom)

        self.all_eprom_names = (
            []
        )  # To store the full list of EPROMs for the search dialog
        self.current_operation_panel = (
            None  # To store the instance of the current operation panel
        )
        saved_verbose_setting = self.config_manager.get_value(
            self.VERBOSE_LOGGING_CONFIG_KEY, default=False
        )
        self.verbose_logging = tk.BooleanVar(value=saved_verbose_setting)

        saved_debug_setting = self.config_manager.get_value(
            self.DEBUG_LOGGING_CONFIG_KEY, default=False
        )
        self.debug_logging = tk.BooleanVar(value=saved_debug_setting)

        self._setup_logging()  # Configure basicConfig once.
        self._create_menu()
        self._create_toolbar()  # Placeholder
        self._create_device_eprom_selection_area()
        self._create_main_layout()  # For options panel and output console
        self._create_status_bar()

        self.after(100, self._process_ui_queue)  # Start polling the queue
        self._update_logging_level()  # Init logging level from config
        # Initial population of EPROM list
        self.firestarter_ops.get_eprom_list()

        # Handle window close event
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Load last selected operation panel, default to "read"
        last_operation = self.config_manager.get_value(
            self.LAST_OPERATION_CONFIG_KEY, default="read"
        )
        self._select_operation(last_operation, set_default=False)

    def _setup_logging(self):
        """Configures the logging system once at startup."""
        # This ensures basicConfig is only called once.
        logging.basicConfig(
            level=logging.INFO,  # Default level, will be updated by _update_logging_level
            format="%(asctime)s - %(name)-15s - %(levelname)-7s - %(message)s",
        )

        # Intercept RURP logs from the firestarter library and direct to UI console
        rurp_logger = logging.getLogger("RURP")
        queue_handler = QueueHandler(self.ui_queue)
        # Use a simple formatter that just passes the message through,
        # as the RURP logger already formats it nicely (e.g., "INFO: Programmer reset").
        formatter = logging.Formatter("%(message)s")
        queue_handler.setFormatter(formatter)
        rurp_logger.addHandler(queue_handler)

    def _update_logging_level(self):
        """Updates the application's logging level based on the verbose flag."""
        log_level = logging.DEBUG if  not self.debug_logging == None and self.debug_logging.get() else logging.INFO
        logging.getLogger().setLevel(log_level)  # For UI logs

        # Also update the level in firestarter_operations
        if self.firestarter_ops:
            self.firestarter_ops.set_logging_level(log_level)

        # Add a handler to also log to our UI console if desired, or rely on queue

    def _create_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(
            label="Open Configuration...", state=tk.DISABLED
        )  # FR-001.A
        file_menu.add_command(
            label="Save Configuration...", state=tk.DISABLED
        )  # FR-001.A
        file_menu.add_separator()
        file_menu.add_command(label="Preferences...", command=self._open_preferences)
        file_menu.add_separator()
        file_menu.add_command(
            label="Exit", command=self._on_closing
        )  # Changed to call _on_closing
        menubar.add_cascade(label="File", menu=file_menu)

        # Eproms Menu
        eprom_menu = tk.Menu(menubar, tearoff=0)
        # Add Search command to Eproms menu
        eprom_menu.add_command(
            label="Search...", command=self._open_eprom_search_dialog
        )
        eprom_menu.add_command(label="Info...", state=tk.DISABLED)  # FR-001.A
        menubar.add_cascade(label="Eproms", menu=eprom_menu)

        # Operations Menu
        operations_menu = tk.Menu(menubar, tearoff=0)
        operations_menu.add_command(
            label="Read EPROM", command=lambda: self._select_operation("read")
        )
        operations_menu.add_command(
            label="Write EPROM", command=lambda: self._select_operation("write")
        )
        operations_menu.add_command(
            label="Verify EPROM", command=lambda: self._select_operation("verify")
        )
        operations_menu.add_command(
            label="Erase EPROM", command=lambda: self._select_operation("erase")
        )
        operations_menu.add_command(
            label="Check Chip ID", command=lambda: self._select_operation("check_id")
        )
        operations_menu.add_command(
            label="Blank Check", command=lambda: self._select_operation("blank_check")
        )
        operations_menu.add_separator()
        operations_menu.add_command(
            label="[Placeholder: Advanced Op 1]", state=tk.DISABLED
        )
        menubar.add_cascade(label="Operations", menu=operations_menu)

        # Programmer Menu
        self.programmer_menu = tk.Menu(
            menubar, tearoff=0
        )  # Store as instance var to update
        # Refresh device list when the programmer menu is about to be displayed
        self.programmer_menu.config(postcommand=self._on_detect_devices)

        self.select_device_submenu = tk.Menu(self.programmer_menu, tearoff=0)
        self.programmer_menu.add_cascade(
            label="Select Device", menu=self.select_device_submenu
        )
        self.select_device_submenu.add_command(
            label=" (Detecting...) ", state=tk.DISABLED
        )  # Placeholder
        self.programmer_menu.add_separator()
        self.programmer_menu.add_command(
            label="Update Programmer Firmware...", state=tk.DISABLED
        )
        self.programmer_menu.add_command(label="About Programmer...", state=tk.DISABLED)
        menubar.add_cascade(label="Programmer", menu=self.programmer_menu)

        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About Firestarter UI...", command=self._on_about)
        help_menu.add_command(label="View Documentation...", state=tk.DISABLED)
        menubar.add_cascade(label="Help", menu=help_menu)

    def _create_toolbar(self):
        # FR-002: Toolbar (Optional quick access)
        self.toolbar = ttk.Frame(self, padding="2")
        self.toolbar.pack(side=tk.TOP, fill=tk.X)
        # Example: ttk.Button(self.toolbar, text="Read", command=lambda: self._select_operation("read")).pack(side=tk.LEFT)
        # For now, keeping it minimal as per "can be hidden"
        ttk.Label(
            self.toolbar, text="Toolbar (placeholder for icons/quick actions)"
        ).pack(side=tk.LEFT)

    def _create_device_eprom_selection_area(self):
        # FR-004, FR-005
        frame = ttk.Frame(self, padding="5")
        frame.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(frame, text="Selected Device:").grid(
            row=0, column=0, sticky=tk.W, padx=2
        )
        ttk.Label(frame, textvariable=self.selected_device).grid(
            row=0, column=1, sticky=tk.EW, padx=2
        )

        ttk.Label(frame, text="EPROM Type:").grid(row=1, column=0, sticky=tk.W, padx=2)
        # Changed from Combobox to a Label to display selected EPROM
        self.selected_eprom_label = ttk.Label(
            frame, textvariable=self.selected_eprom_type, relief=tk.SUNKEN, padding=2
        )
        self.selected_eprom_label.grid(row=1, column=1, sticky=tk.EW, padx=2)

        self.search_eprom_button = ttk.Button(
            frame, text="Search", command=self._open_eprom_search_dialog
        )
        self.search_eprom_button.grid(row=1, column=2, padx=(5, 2), sticky=tk.W)
        frame.columnconfigure(1, weight=1)

    def _create_main_layout(self):
        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Operation Options Panel (FR-003)
        self.options_panel_frame = ttk.Labelframe(
            main_pane, text="Operation Options", padding="5"
        )
        main_pane.add(self.options_panel_frame, weight=1)
        ttk.Label(
            self.options_panel_frame, text="(Select an operation from the menu)"
        ).pack(padx=5, pady=5)

        # Output Console (FR-006)
        console_frame = ttk.Labelframe(main_pane, text="Output Console", padding="5")
        main_pane.add(console_frame, weight=2)

        self.output_console = tk.Text(
            console_frame, wrap=tk.WORD, height=15, state=tk.DISABLED
        )
        console_scrollbar = ttk.Scrollbar(
            console_frame, orient=tk.VERTICAL, command=self.output_console.yview
        )
        self.output_console.config(yscrollcommand=console_scrollbar.set)

        self.output_console.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        console_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _create_status_bar(self):
        status_frame = ttk.Frame(self, relief=tk.SUNKEN, padding=0)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_bar = ttk.Label(status_frame, text="Status: Ready", anchor=tk.W)
        self.status_bar.pack(side=tk.LEFT, padx=2)  # Removed fill=tk.X, expand=True

        self.progress_bar = ttk.Progressbar(
            status_frame, orient=tk.HORIZONTAL, mode="determinate"
        )
        # The progress bar will be packed/unpacked as needed, so don't pack it here initially.

    def _log_to_console(self, message: str, level: str = "INFO"):
        self.output_console.config(state=tk.NORMAL)
        self.output_console.insert(tk.END, f"[{level}] {message}\n")
        self.output_console.see(tk.END)
        self.output_console.config(state=tk.DISABLED)
        if level.upper() == "ERROR":
            logging.error(message)
        elif level.upper() == "WARNING":
            logging.warning(message)
        else:
            logging.info(message)

    def _update_status_bar(self, message: str):
        self.status_bar.config(
            text=f"Status: {message} | Device: {self.selected_device.get()} | EPROM: {self.selected_eprom_type.get()}"
        )

    def _process_ui_queue(self):
        """Processes messages from the firestarter_operations queue."""
        try:
            while not self.ui_queue.empty():
                msg_type, data = self.ui_queue.get_nowait()

                if msg_type == "status":
                    # Reset progress bar at the start of an operation
                    if "started" in data and self.progress_bar.winfo_ismapped():
                        self.progress_bar.pack_forget()
                    self._log_to_console(data, "INFO")
                    self._update_status_bar(data)
                elif msg_type == "error":
                    self._log_to_console(data, "ERROR")
                    messagebox.showerror("Operation Error", data)
                    self._update_status_bar(f"Error: {data[:50]}...")
                    if self.progress_bar.winfo_ismapped():
                        self.progress_bar.pack_forget()
                elif msg_type == "progress":
                    current, total = data
                    if not self.progress_bar.winfo_ismapped():
                        self.progress_bar.pack(
                            side=tk.RIGHT, padx=5, pady=1, fill=tk.X, expand=True
                        )

                    if total > 0:
                        self.progress_bar["maximum"] = total
                        self.progress_bar["value"] = current
                elif msg_type == "result":
                    op_name, op_result = data
                    self._log_to_console(f"{op_name} result: {op_result}", "INFO")
                    # Handle specific results, e.g., device list
                    if op_name == "Detect Devices":
                        self._populate_device_menu(op_result)
                elif msg_type == "eprom_list" or msg_type == "eprom_search_results":
                    if isinstance(data, list) and (
                        not data or data[0] != "Error: DB not loaded"
                    ):
                        self.all_eprom_names = data
                        # If no EPROM is selected and we got a list, we don't auto-select anymore.
                        # User must use the search dialog.
                        # However, if a previously selected EPROM (from config) is not in the new list,
                        # we might want to reset it, or just let it be (it won't be valid for ops).
                        # For now, we just store the list. The selected_eprom_type is handled by config or search.
                    elif (
                        isinstance(data, list)
                        and data
                        and data[0] == "Error: DB not loaded"
                    ):
                        self.all_eprom_names = []  # Clear if error
                    elif (
                        msg_type == "eprom_search_results"
                    ):  # This message type might be unused now
                        logging.warning(
                            "Received 'eprom_search_results', but this path might be deprecated."
                        )
                elif msg_type == "rurp_log":
                    type, msg = data.split(":")
                    if not type == "DATA":
                        self._log_to_console(msg, type)
                elif msg_type == "operation_finished":
                    # Re-enable UI elements if they were disabled
                    self._update_status_bar(f"{data} finished. Ready.")
                    if hasattr(self, "execute_button") and self.execute_button:
                        self.execute_button.config(state=tk.NORMAL)
                    if self.progress_bar.winfo_ismapped():
                        # Ensure it shows 100% before hiding
                        self.progress_bar["value"] = self.progress_bar["maximum"]
                        self.progress_bar.after(500, self.progress_bar.pack_forget)

        except Exception as e:
            logging.error(f"Error processing UI queue: {e}")
        finally:
            self.after(100, self._process_ui_queue)  # Poll again

    def _on_eprom_selected(self, event=None):
        # This method is now called after a successful selection from the search dialog
        selected = self.selected_eprom_type.get()
        self._log_to_console(f"EPROM Type selected: {selected}")
        self._update_status_bar(f"EPROM selected: {selected}")
        self.config_manager.set_value(self.LAST_EPROM_CONFIG_KEY, selected)
        if self.current_operation:
            self._update_operation_options_panel(self.current_operation)

    def _open_eprom_search_dialog(self):
        if not self.all_eprom_names:
            messagebox.showinfo(
                "EPROM Search",
                "EPROM list not loaded or empty. Please wait or check logs.",
            )
            self.firestarter_ops.get_eprom_list()  # Try to refresh
            return

        dialog = EpromSearchDialog(self, self.all_eprom_names, title="Search EPROM")
        if dialog.result:
            self.selected_eprom_type.set(dialog.result)
            self._on_eprom_selected()  # Trigger updates based on new selection

    def _on_detect_devices(self):
        self._log_to_console("Detecting programmer devices...")
        self.firestarter_ops.detect_devices()

    def _populate_device_menu(self, devices):
        self.select_device_submenu.delete(0, tk.END)  # Clear old entries

        valid_devices = []
        if (
            devices
            and isinstance(devices, list)
            and devices[0] != "No programmers found"
            and not (
                devices[0]
                and isinstance(devices[0], str)
                and devices[0].startswith("Error")
            )
        ):
            valid_devices = [
                d for d in devices if isinstance(d, str) and d
            ]  # Filter out non-string or empty

        if valid_devices:
            for device_info in valid_devices:
                self.select_device_submenu.add_radiobutton(
                    label=device_info,
                    variable=self.selected_device,  # Ties to the StringVar
                    value=device_info,  # Value this radiobutton represents
                    command=lambda dev=device_info: self._set_selected_device(dev),
                )
        else:
            display_text = " (No devices found) "
            if (
                devices
                and isinstance(devices, list)
                and devices[0]
                and isinstance(devices[0], str)
            ):  # If devices list exists and has content (e.g. error message)
                display_text = f" ({devices[0]}) "
            self.select_device_submenu.add_command(
                label=display_text, state=tk.DISABLED
            )

            # If a device was selected but now none are found/valid
            if self.selected_device.get() != "None":
                self._set_selected_device(
                    "None"
                )  # This will update UI and save "None" to config

    def _set_selected_device(self, device_port):
        self.selected_device.set(device_port)
        self._log_to_console(f"Programmer device selected: {device_port}")
        self._update_status_bar(f"Device selected: {device_port}")
        self.config_manager.set_value(self.LAST_DEVICE_CONFIG_KEY, device_port)
        if (
            self.current_operation
        ):  # Refresh options panel if a device is selected/changed
            self._update_operation_options_panel(self.current_operation)

    def _on_about(self):
        messagebox.showinfo(
            "About Firestarter UI",
            f"Firestarter UI\nVersion {ui_version}\n\n"
            f"Firestarter programmer library (v{firestarter_version}).",
        )

    def _open_preferences(self):
        dialog = PreferencesDialog(self, self.config_manager)
        dialog.grab_set()  # Make modal
        dialog.wait_window(dialog)  # Wait for it to close

        # After preferences are closed, reload the settings into the app's BooleanVars
        # This ensures the running app reflects the saved preferences immediately.
        self.verbose_logging.set(
            self.config_manager.get_value(self.VERBOSE_LOGGING_CONFIG_KEY, default=False)
        )
        self.debug_logging.set(
            self.config_manager.get_value(self.DEBUG_LOGGING_CONFIG_KEY, default=False)
        )

        # After preferences are closed, re-apply any changes, e.g., verbose logging
        self._update_logging_level()
        self._log_to_console("Preferences updated.", "INFO")

    def _on_closing(self):
        """Handles window close events to save geometry."""
        current_geometry = self.geometry()
        logging.debug(f"Saving window geometry: {current_geometry}")
        self.config_manager.set_value(self.WINDOW_GEOMETRY_CONFIG_KEY, current_geometry)
        self.destroy()  # Properly close the Tkinter window

    def _select_operation(self, operation_name: str, set_default: bool = True):
        self.current_operation = operation_name
        if set_default:
            self.config_manager.set_value(self.LAST_OPERATION_CONFIG_KEY, operation_name)
        # self._log_to_console(
        #     f"Operation selected: {operation_name.replace('_', ' ').title()}"
        # )
        self._update_operation_options_panel(operation_name)
        self._update_status_bar(
            f"Selected operation: {operation_name.replace('_', ' ').title()}"
        )

    def _update_operation_options_panel(self, operation_name: str):
        # Clear previous options
        for widget in self.options_panel_frame.winfo_children():
            widget.destroy()

        if self.selected_device.get() == "None":
            ttk.Label(
                self.options_panel_frame,
                text="Please select a programmer device first.",
            ).pack(padx=5, pady=5)
            return

        # EPROM type is required for most operations
        eprom_required_ops = [
            "read",
            "write",
            "verify",
            "erase",
            "check_id",
            "blank_check",
        ]
        if (
            operation_name in eprom_required_ops
            and self.selected_eprom_type.get() == "None"
        ):
            ttk.Label(
                self.options_panel_frame, text="Please select an EPROM type first."
            ).pack(padx=5, pady=5)
            return

        PanelClass = OPERATION_PANELS.get(operation_name)

        if PanelClass:
            self.current_operation_panel = PanelClass(
                self.options_panel_frame, app_instance=self
            )
            self.current_operation_panel.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        else:
            ttk.Label(
                self.options_panel_frame,
                text=f"Options for '{operation_name}' not yet implemented.",
            ).pack()
            self.current_operation_panel = None
            return  # No execute button for unimplemented

        # FR-007: Execute Button
        self.execute_button = ttk.Button(
            self.options_panel_frame,
            text=f"{operation_name.replace('_', ' ').title()}",
            command=self._on_execute_operation,
        )
        self.execute_button.pack(pady=10)

    def _on_execute_operation(self):
        if not self.current_operation:
            messagebox.showerror("Error", "No operation selected.")
            return

        eprom_name = self.selected_eprom_type.get()

        if not self.current_operation_panel:
            messagebox.showerror("Error", "Operation panel not initialized.")
            return

        device_port = self.selected_device.get()
        if device_port == "None":
            messagebox.showerror("Error", "No programmer device selected.")
            if hasattr(self, "execute_button") and self.execute_button:
                self.execute_button.config(state=tk.NORMAL)
            return

        # Check if EPROM is required for the current operation
        eprom_required_ops = [
            "read",
            "write",
            "verify",
            "erase",
            "check_id",
            "blank_check",
        ]
        if self.current_operation in eprom_required_ops and eprom_name == "None":
            messagebox.showerror(
                "Error",
                f"No EPROM selected. Please select an EPROM for the '{self.current_operation}' operation.",
            )
            if hasattr(self, "execute_button") and self.execute_button:
                self.execute_button.config(state=tk.NORMAL)
            return

        if (
            device_port == "None"
        ):  # This check is now redundant due to the one above, but harmless if kept.
            messagebox.showerror("Error", "No programmer device selected.")
            if hasattr(self, "execute_button") and self.execute_button:
                self.execute_button.config(state=tk.NORMAL)
            return

        eprom_data = None

        if eprom_name != "None":
            full_eprom_data = self.db.get_eprom(eprom_name)
            if not full_eprom_data:  # If not found in DB
                messagebox.showerror(
                    "Error", f"EPROM '{eprom_name}' not found in database."
                )
                return
            try:
                eprom_data = self.db.convert_to_programmer(
                    full_eprom_data
                )  # Use firestarter_ops.db
            except Exception as e_conv:
                messagebox.showerror(
                    "Error", f"Error preparing EPROM data for '{eprom_name}': {e_conv}"
                )
                logging.error(
                    f"Error in self.db.convert_to_programmer for {eprom_name}: {e_conv}"
                )
                if hasattr(self, "execute_button") and self.execute_button:
                    self.execute_button.config(state=tk.NORMAL)
                return
            if not eprom_data:
                messagebox.showerror(
                    "Error", f"Failed to prepare EPROM data for '{eprom_name}'."
                )
                if hasattr(self, "execute_button") and self.execute_button:
                    self.execute_button.config(state=tk.NORMAL)
                return

        # Button should have been disabled earlier if it exists.
        # If an error occurred above, it should have been re-enabled and returned.

        try:
            # Disable button before calling panel's execute method
            if hasattr(self, "execute_button") and self.execute_button:
                self.execute_button.config(state=tk.DISABLED)
            else:
                logging.warning(
                    "_on_execute_operation: self.execute_button not found or is None at pre-check."
                )

            # Delegate to the current operation panel
            operation_initiated = self.current_operation_panel.execute_operation(
                eprom_name, eprom_data
            )

            if not operation_initiated:
                # If the panel's execute_operation returned False (e.g., validation error before async call),
                # re-enable the button. Otherwise, it will be re-enabled by the queue processor.
                if hasattr(self, "execute_button") and self.execute_button:
                    self.execute_button.config(state=tk.NORMAL)

        except KeyError as e:
            messagebox.showerror("Internal Error", f"Missing operation parameter: {e}")
            logging.error(f"Missing param for {self.current_operation}: {e}")
            if hasattr(self, "execute_button") and self.execute_button:
                self.execute_button.config(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror(
                "Execution Error", f"An unexpected error occurred: {e}"
            )
            logging.error(f"Unexpected error executing {self.current_operation}: {e}")
            if hasattr(self, "execute_button") and self.execute_button:
                self.execute_button.config(state=tk.NORMAL)

