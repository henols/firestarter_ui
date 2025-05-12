# ui_manager.py
"""
Manages the Tkinter UI for the Firestarter application.

This module houses the main Tkinter application class (FirestarterApp),
manages UI construction (window, menus, panels per PRD), widget layout,
event handling, delegates tasks to firestarter_operations.py, and
updates UI via callbacks.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import logging  # For capturing logs from the (mock) library

from firestarter_operations import FirestarterController


class FirestarterApp:
    """Main application class for the Firestarter GUI."""

    def __init__(self, root):
        self.root = root
        self.root.title("Firestarter UI")
        self.root.geometry("800x600")

        self.current_operation = None
        self.operation_params_widgets = {}  # To store dynamically created widgets

        # Create essential UI components first, especially the console for logging
        self._create_main_layout()
        self._create_output_console() # self.console_text is created here

        # Configure logging to capture messages from the operations module (and mock library)
        # This needs self.console_text to be available via log_to_console
        self.log_capture_handler = self._configure_logging()

        # Initialize Firestarter Operations Controller after console and logging are set up
        self.operations_controller = FirestarterController(self.handle_operation_update)

        self._create_menu()
        self._create_toolbar()
        self._create_config_panel()  # For EPROM and Programmer selection
        self._create_operation_options_panel()
        self._create_execute_button()
        self._create_status_bar()

        self.update_programmer_list()
        self.update_eprom_list()

        # Start polling the queue for results from operations controller
        self.root.after(100, self.process_operation_queue)

    def _configure_logging(self):
        """Configures logging to capture messages into the UI console."""
        log_text_handler = UITextViewHandler(self)
        log_text_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )

        # Configure root logger or specific logger used by firestarter_operations
        # For simplicity, let's assume firestarter_operations (and its mock lib) use a logger
        # named "MockFirestarterLib" or similar. If it uses root logger, configure that.
        logger = logging.getLogger()  # Get root logger
        logger.addHandler(log_text_handler)
        logger.setLevel(logging.INFO)  # Set desired level
        return log_text_handler

    def _create_main_layout(self):
        """Creates the main frames for UI sections."""
        self.top_frame = ttk.Frame(self.root, padding="5")
        self.top_frame.pack(side=tk.TOP, fill=tk.X)

        self.middle_frame = ttk.Frame(self.root, padding="5")
        self.middle_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.bottom_frame = ttk.Frame(self.root, padding="5")
        self.bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)

    def _create_menu(self):
        """Creates the main application menu bar (FR-001.A)."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        # Operations Menu (FR-002)
        operations_menu = tk.Menu(menubar, tearoff=0)
        operations = [
            ("Read EPROM", "read"),
            ("Write EPROM", "write"),
            ("Verify EPROM", "verify"),
            ("Erase EPROM", "erase"),
            ("Check Chip ID", "check_id"),
            ("Blank Check", "blank_check"),
        ]
        for label, op_key in operations:
            operations_menu.add_command(
                label=label, command=lambda op=op_key: self.select_operation(op)
            )
        menubar.add_cascade(label="Operations", menu=operations_menu)

        # Programmer Menu (FR-005)
        self.programmer_menu = tk.Menu(menubar, tearoff=0)
        self.programmer_menu.add_command(
            label="Detect Programmers", command=self.update_programmer_list
        )
        self.programmer_menu.add_separator()
        # Programmer devices will be added dynamically here
        menubar.add_cascade(label="Programmer", menu=self.programmer_menu)
        self.selected_programmer_var = tk.StringVar()

        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about_dialog)
        menubar.add_cascade(label="Help", menu=help_menu)

    def _create_toolbar(self):
        """Creates a toolbar with buttons for common operations."""
        toolbar = ttk.Frame(self.top_frame, relief=tk.RAISED, borderwidth=1)
        toolbar.pack(side=tk.TOP, fill=tk.X, pady=(0, 5))

        # Example toolbar buttons - map to operations
        buttons = [
            ("Read", "read"),
            ("Write", "write"),
            ("Verify", "verify"),
            ("Erase", "erase"),
        ]
        for text, op_key in buttons:
            btn = ttk.Button(
                toolbar, text=text, command=lambda op=op_key: self.select_operation(op)
            )
            btn.pack(side=tk.LEFT, padx=2, pady=2)

    def _create_config_panel(self):
        """Creates panel for EPROM and Programmer selection (FR-004, FR-005)."""
        config_frame = ttk.LabelFrame(self.top_frame, text="Configuration", padding="5")
        config_frame.pack(side=tk.TOP, fill=tk.X, expand=True)

        # EPROM Selection (FR-004)
        ttk.Label(config_frame, text="EPROM Type:").grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W
        )
        self.eprom_var = tk.StringVar()
        self.eprom_combobox = ttk.Combobox(
            config_frame, textvariable=self.eprom_var, state="readonly", width=20
        )
        self.eprom_combobox.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.eprom_combobox.bind("<<ComboboxSelected>>", self.on_eprom_selected)

        # Selected Programmer Display (updated via menu)
        ttk.Label(config_frame, text="Programmer:").grid(
            row=0, column=2, padx=5, pady=5, sticky=tk.W
        )
        self.programmer_display_var = tk.StringVar(value="None Selected")
        ttk.Label(
            config_frame, textvariable=self.programmer_display_var, width=25
        ).grid(row=0, column=3, padx=5, pady=5, sticky=tk.EW)

        config_frame.columnconfigure(1, weight=1)
        config_frame.columnconfigure(3, weight=1)

    def _create_operation_options_panel(self):
        """Creates the panel for operation-specific options (FR-003)."""
        self.options_panel_frame = ttk.LabelFrame(
            self.middle_frame, text="Operation Options", padding="10"
        )
        self.options_panel_frame.pack(side=tk.TOP, fill=tk.X, pady=5)
        # Content will be populated dynamically by select_operation()

    def _create_output_console(self):
        """Creates the text area for status messages and logs (FR-006)."""
        console_frame = ttk.LabelFrame(
            self.middle_frame, text="Output Console", padding="5"
        )
        console_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=5)

        self.console_text = scrolledtext.ScrolledText(
            console_frame, wrap=tk.WORD, height=10, state=tk.DISABLED
        )
        self.console_text.pack(fill=tk.BOTH, expand=True)

    def _create_execute_button(self):
        """Creates the execute button (FR-007)."""
        self.execute_button = ttk.Button(
            self.bottom_frame,
            text="Execute Operation",
            command=self.execute_current_operation,
            state=tk.DISABLED,
        )
        self.execute_button.pack(side=tk.RIGHT, padx=5, pady=5)

    def _create_status_bar(self):
        """Creates a simple status bar."""
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(
            self.bottom_frame,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
        )
        status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

    def log_to_console(self, message, level="INFO"):
        """Appends a message to the output console."""
        self.console_text.config(state=tk.NORMAL)
        self.console_text.insert(tk.END, f"[{level.upper()}] {message}\n")
        self.console_text.see(tk.END)  # Scroll to the end
        self.console_text.config(state=tk.DISABLED)

    def update_programmer_list(self):
        """Fetches and updates the list of available programmers in the menu."""
        self.log_to_console("Detecting programmers...")
        programmers = self.operations_controller.get_available_programmers()

        # Clear existing programmer entries (skip first 2: Detect, Separator)
        last_entry_index = self.programmer_menu.index(tk.END)
        if (
            last_entry_index is not None and last_entry_index >= 1
        ):  # Ensure there are items beyond separator
            for i in range(
                last_entry_index, 1, -1
            ):  # Iterate backwards from last to index 2
                self.programmer_menu.delete(i)

        if programmers:
            for programmer in programmers:
                self.programmer_menu.add_radiobutton(
                    label=programmer,
                    variable=self.selected_programmer_var,
                    value=programmer,
                    command=lambda p=programmer: self.on_programmer_selected(p),
                )
            self.log_to_console(f"Found programmers: {', '.join(programmers)}")
            if (
                not self.selected_programmer_var.get() and programmers
            ):  # Auto-select first if none selected
                self.selected_programmer_var.set(programmers[0])
                self.on_programmer_selected(programmers[0])
        else:
            self.programmer_menu.add_command(
                label="No programmers found", state=tk.DISABLED
            )
            self.log_to_console("No programmers found.", "WARNING")

        # If a programmer was previously selected but is no longer in the list, clear selection
        current_selection = self.selected_programmer_var.get()
        if current_selection and current_selection not in programmers:
            self.selected_programmer_var.set("")
            self.programmer_display_var.set("None Selected")
            self.operations_controller.set_active_programmer(None)
            self.log_to_console(
                f"Previously selected programmer '{current_selection}' not found.",
                "WARNING",
            )

    def on_programmer_selected(self, programmer_path):
        self.operations_controller.set_active_programmer(programmer_path)
        self.programmer_display_var.set(programmer_path)
        self.log_to_console(f"Programmer selected: {programmer_path}")
        self.status_var.set(f"Programmer: {programmer_path}")
        self.validate_and_enable_execute()

    def update_eprom_list(self):
        """Fetches and updates the list of supported EPROMs."""
        eproms = self.operations_controller.get_supported_eproms()
        if eproms:
            self.eprom_combobox["values"] = eproms
            if (
                not self.eprom_var.get() and eproms
            ):  # Auto-select first if none selected
                self.eprom_var.set(eproms[0])
                self.on_eprom_selected(None)  # Trigger selection logic
            self.log_to_console(f"Supported EPROMs loaded: {', '.join(eproms)}")
        else:
            self.eprom_combobox["values"] = []
            self.eprom_var.set("")
            self.log_to_console("No EPROMs loaded from library.", "WARNING")

    def on_eprom_selected(self, event):
        """Handles EPROM selection from the combobox."""
        selected_eprom = self.eprom_var.get()
        if selected_eprom:
            self.operations_controller.set_active_eprom(selected_eprom)
            self.log_to_console(f"EPROM type selected: {selected_eprom}")
            self.status_var.set(
                f"EPROM: {selected_eprom}, Programmer: {self.selected_programmer_var.get() or 'None'}"
            )
        self.validate_and_enable_execute()

    def select_operation(self, operation_key):
        """Sets the current operation and updates the options panel (FR-003)."""
        self.current_operation = operation_key
        self.status_var.set(f"Operation: {operation_key.replace('_', ' ').title()}")
        self.log_to_console(f"Selected operation: {operation_key}")

        # Clear previous options
        for widget in self.options_panel_frame.winfo_children():
            widget.destroy()
        self.operation_params_widgets = {}

        # Populate new options based on operation_key
        # This is where FR-003 (Operation Options Panel) is dynamically built
        row_idx = 0
        if operation_key == "read":
            self._add_file_option("Output File:", "output_file", "save", row_idx)
            row_idx += 1
            self._add_text_option("Start Address (hex):", "start_address", row_idx)
            row_idx += 1
            self._add_text_option("End Address (hex):", "end_address", row_idx)
            row_idx += 1
            self._add_text_option("Size (bytes, hex/dec):", "size", row_idx)
            row_idx += 1
        elif operation_key == "write":
            self._add_file_option("Input File:", "input_file", "open", row_idx)
            row_idx += 1
            self._add_text_option("Start Address (hex):", "start_address", row_idx)
            row_idx += 1
            self._add_checkbox_option("Verify Write", "verify_write", True, row_idx)
            row_idx += 1
        elif operation_key == "verify":
            self._add_file_option("Input File:", "input_file", "open", row_idx)
            row_idx += 1
            self._add_text_option("Start Address (hex):", "start_address", row_idx)
            row_idx += 1
        elif operation_key in ["erase", "check_id", "blank_check"]:
            ttk.Label(
                self.options_panel_frame, text="No specific options for this operation."
            ).grid(row=row_idx, column=0, columnspan=2, pady=5)
        else:
            ttk.Label(
                self.options_panel_frame, text="Operation not yet configured."
            ).grid(row=row_idx, column=0, columnspan=2, pady=5)

        self.validate_and_enable_execute()

    def _add_text_option(self, label_text, param_key, row_idx, default_value=""):
        ttk.Label(self.options_panel_frame, text=label_text).grid(
            row=row_idx, column=0, sticky=tk.W, padx=5, pady=2
        )
        entry = ttk.Entry(self.options_panel_frame, width=40)
        entry.insert(0, default_value)
        entry.grid(row=row_idx, column=1, sticky=tk.EW, padx=5, pady=2)
        self.operation_params_widgets[param_key] = entry
        self.options_panel_frame.columnconfigure(1, weight=1)  # Make entry expandable

    def _add_file_option(self, label_text, param_key, dialog_type, row_idx):
        ttk.Label(self.options_panel_frame, text=label_text).grid(
            row=row_idx, column=0, sticky=tk.W, padx=5, pady=2
        )
        entry_var = tk.StringVar()
        entry = ttk.Entry(self.options_panel_frame, textvariable=entry_var, width=30)
        entry.grid(row=row_idx, column=1, sticky=tk.EW, padx=5, pady=2)

        browse_cmd = lambda: self.browse_file(entry_var, dialog_type)
        ttk.Button(self.options_panel_frame, text="Browse...", command=browse_cmd).grid(
            row=row_idx, column=2, padx=5, pady=2
        )

        self.operation_params_widgets[param_key] = entry_var
        self.options_panel_frame.columnconfigure(1, weight=1)  # Make entry expandable

    def _add_checkbox_option(self, label_text, param_key, default_checked, row_idx):
        var = tk.BooleanVar(value=default_checked)
        chk = ttk.Checkbutton(self.options_panel_frame, text=label_text, variable=var)
        chk.grid(row=row_idx, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)
        self.operation_params_widgets[param_key] = var

    def browse_file(self, entry_var, dialog_type):
        """Handles file browsing (FR-008)."""
        if dialog_type == "open":
            filepath = filedialog.askopenfilename(title="Select Input File")
        elif dialog_type == "save":
            filepath = filedialog.asksaveasfilename(title="Select Output File")
        else:
            return

        if filepath:
            entry_var.set(filepath)
            self.log_to_console(f"File selected: {filepath}")

    def validate_and_enable_execute(self):
        """Checks if conditions are met to enable the Execute button."""
        # Basic validation: operation selected, programmer selected.
        # EPROM type might be optional for some lib functions but generally required for EPROM ops.
        op_selected = bool(self.current_operation)
        programmer_selected = bool(self.selected_programmer_var.get())
        eprom_selected = bool(self.eprom_var.get())

        # More specific validation can be added here based on self.current_operation
        # For now, enable if an operation is chosen and programmer/EPROM are set.
        can_execute = False
        if op_selected and programmer_selected:
            # Operations that don't strictly need an EPROM type (e.g., check_id might work on programmer)
            if self.current_operation in ["check_id"]:  # Add other such ops if any
                can_execute = True
            elif eprom_selected:  # Most operations need an EPROM type
                can_execute = True

        if can_execute:
            self.execute_button.config(state=tk.NORMAL)
        else:
            self.execute_button.config(state=tk.DISABLED)

    def execute_current_operation(self):
        """Gathers parameters and calls the appropriate method in firestarter_operations."""
        if not self.current_operation:
            messagebox.showerror("Error", "No operation selected.")
            return

        params = {}
        valid_input = True
        for key, widget_or_var in self.operation_params_widgets.items():
            if isinstance(widget_or_var, tk.StringVar) or isinstance(
                widget_or_var, tk.BooleanVar
            ):
                params[key] = widget_or_var.get()
            elif isinstance(widget_or_var, ttk.Entry):  # Direct entry widget
                params[key] = widget_or_var.get()

            # Basic Input Validation (FR - mentioned in summary)
            if key in ["input_file", "output_file"] and not params[key]:
                messagebox.showerror(
                    "Input Error", f"{key.replace('_', ' ').title()} is required."
                )
                valid_input = False
                break
            # Add more specific validation (e.g., for hex addresses) as needed

        if not valid_input:
            return

        self.log_to_console(
            f"Executing {self.current_operation} with params: {params}", "DEBUG"
        )
        self.execute_button.config(state=tk.DISABLED)  # Disable during operation
        self.status_var.set(f"Executing {self.current_operation}...")

        # Delegate to FirestarterController
        op_func_map = {
            "read": self.operations_controller.read_from_eprom,
            "write": self.operations_controller.write_to_eprom,
            "verify": self.operations_controller.verify_eprom_data,
            "erase": self.operations_controller.erase_selected_eprom,
            "check_id": self.operations_controller.check_eprom_chip_id,
            "blank_check": self.operations_controller.perform_blank_check,
        }

        if self.current_operation in op_func_map:
            target_method = op_func_map[self.current_operation]
            if self.current_operation in [
                "erase",
                "check_id",
                "blank_check",
            ]:  # Ops without params dict
                target_method()
            else:
                target_method(params)
        else:
            messagebox.showerror(
                "Error", f"Operation '{self.current_operation}' not implemented."
            )
            self.execute_button.config(state=tk.NORMAL)  # Re-enable if not implemented
            self.status_var.set("Ready")

    def handle_operation_update(self, update_type, data):
        """
        Callback for FirestarterController to send updates to the UI.
        This method is designed to be called from the main Tkinter thread.
        The operations controller uses root.after or a queue to ensure this.
        """
        if update_type == "log":
            self.log_to_console(data["message"], data["level"])
        elif update_type == "check_queue":
            # This is a signal to process the queue, actual data is in the queue
            # This is useful if the controller puts multiple items before signaling
            pass  # The process_operation_queue will handle it
        elif update_type.endswith("_result"):
            # This path can be used if controller directly calls back for simple/sync results
            # However, for threaded ops, queue is preferred.
            # For now, results are expected via the queue.
            self.log_to_console(
                f"Direct update (should be via queue for async): {update_type} - {data}",
                "DEBUG",
            )
            self._process_operation_result(update_type, data)

    def process_operation_queue(self):
        """Processes messages from the FirestarterController's queue."""
        try:
            while not self.operations_controller.operation_queue.empty():
                message = self.operations_controller.operation_queue.get_nowait()
                update_type = message.get("type")
                data = message.get("data")

                if update_type and data:
                    self._process_operation_result(update_type, data)
                else:
                    self.log_to_console(
                        f"Malformed message from queue: {message}", "ERROR"
                    )
        except Exception as e:
            self.log_to_console(f"Error processing operation queue: {e}", "ERROR")
        finally:
            # Reschedule to keep polling
            self.root.after(100, self.process_operation_queue)

    def _process_operation_result(self, op_type_result, data):
        """Handles the result of an operation."""
        self.log_to_console(f"Result for {op_type_result}: {data}", "INFO")
        status = data.get("status", "error")
        message = data.get("message", "Unknown outcome.")

        if status == "success":
            self.log_to_console(
                f"Operation {op_type_result.replace('_result','')} Succeeded: {message}",
                "SUCCESS",
            )
            if "chip_id" in data:  # Specific for check_id
                self.log_to_console(
                    f"Chip ID: {data['chip_id']}, Manufacturer: {data.get('manufacturer', 'N/A')}",
                    "RESULT",
                )
            if "is_blank" in data:  # Specific for blank_check
                self.log_to_console(
                    f"Blank Check: {'Chip is Blank.' if data['is_blank'] else message}",
                    "RESULT",
                )
            if op_type_result == "read_result" and "bytes_read" in data:
                self.log_to_console(f"Bytes Read: {data['bytes_read']}", "RESULT")

            messagebox.showinfo(
                "Success",
                f"Operation {op_type_result.replace('_result','')} successful.\n{message}",
            )
        else:  # error or failure
            self.log_to_console(
                f"Operation {op_type_result.replace('_result','')} Failed: {message}",
                "ERROR",
            )
            messagebox.showerror(
                "Operation Failed", f"An error occurred: {message}"
            )  # FR-013

        self.status_var.set("Ready")
        self.validate_and_enable_execute()  # Re-evaluate execute button state

    def show_about_dialog(self):
        """Displays the About dialog."""
        messagebox.showinfo(
            "About Firestarter UI",
            "Firestarter UI\nVersion 0.1.0\n\n"
            "A graphical interface for the Firestarter EPROM programmer library.",
        )


class UITextViewHandler(logging.Handler):
    """A logging handler that directs messages to the Tkinter Text widget."""

    def __init__(self, app_instance):
        super().__init__()
        self.app_instance = app_instance

    def emit(self, record):
        msg = self.format(record)
        # Ensure UI update is done in the main thread
        # The logger might be called from a worker thread
        self.app_instance.root.after(
            0, self.app_instance.log_to_console, msg, record.levelname
        )


if __name__ == "__main__":
    # This is for testing ui_manager.py independently if needed,
    # but the main entry is firestarter_gui_app.py
    root = tk.Tk()
    app = FirestarterApp(root)
    root.mainloop()
