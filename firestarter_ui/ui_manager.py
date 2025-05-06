# ui_manager.py
"""
Manages the Tkinter UI construction, event handling, and delegation
of Firestarter operations.
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from .firestarter_operations import FirestarterOperations


class FirestarterApp:
    """Main application class for the Firestarter Tkinter GUI."""

    def __init__(self, root):
        self.root = root
        self.root.title("Firestarter UI")
        self.root.geometry("900x700")

        # Style
        self.style = ttk.Style()
        self.style.theme_use("clam")  # Or 'alt', 'default', 'classic'

        # Operations handler
        self.firestarter_ops = FirestarterOperations(self)

        # UI State Variables
        self.current_operation_name = tk.StringVar(value="<No Operation Selected>")
        self.selected_eprom_type = tk.StringVar()
        self.selected_hardware_device = tk.StringVar()
        self.available_devices = []
        self.supported_eproms_map = {}  # Maps EPROM name to its details

        # Operation-specific input fields (StringVar, IntVar, etc.)
        self.operation_params = {}

        # Initialize UI elements
        self._create_menu()
        self._create_main_layout() # This will also create toolbar elements

        # Initial data load
        self._load_supported_eproms()


    def schedule_gui_update(self, task):
        """Schedules a task to be run in the Tkinter main thread."""
        self.root.after(0, task)

    def _create_menu(self):
        """Creates the main menu bar (FR-001)."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        # Eproms Menu (FR-001, related to FR-004)
        # FR-004 is primarily handled by the selection panel.
        # This menu could be for future EPROM-specific global actions.
        eprom_menu = tk.Menu(menubar, tearoff=0)
        eprom_menu.add_command(
            label="Refresh EPROM List", command=self._load_supported_eproms
        )
        menubar.add_cascade(label="EPROMs", menu=eprom_menu)

        # Operations Menu (FR-001, FR-002)
        self.operations_menu = tk.Menu(menubar, tearoff=0)
        self.defined_operations = {
            "Read EPROM": {
                "implemented": True,
                "params": {"start_address": "int", "length": "int_optional"},
            },
            "Write EPROM": {
                "implemented": True,
                "params": {"file_path": "file_open", "start_address": "int"},
            },
            "Verify EPROM": {
                "implemented": False,
                "params": {"file_path": "file_open", "start_address": "int"},
            },
            "Erase EPROM": {"implemented": False, "params": {}},
            # Add more operations as per Firestarter library
        }
        for op_name, op_details in self.defined_operations.items():
            state = tk.NORMAL if op_details["implemented"] else tk.DISABLED
            self.operations_menu.add_command(
                label=op_name,
                command=lambda o=op_name: self._select_operation(o),
                state=state,
            )
        menubar.add_cascade(label="Operations", menu=self.operations_menu)

        # Programmer Menu (FR-001, FR-004.A, FR-005)
        self.programmer_menu = tk.Menu(menubar, tearoff=0)
        self.programmer_menu.add_command(
            label="Detect Devices", command=self._on_detect_devices
        )  # FR-004.A
        self.select_device_submenu = tk.Menu(self.programmer_menu, tearoff=0)
        self.programmer_menu.add_cascade(
            label="Select Device", menu=self.select_device_submenu, state=tk.DISABLED
        )  # FR-005
        menubar.add_cascade(label="Programmer", menu=self.programmer_menu)

        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

    def _create_toolbar_frame(self, parent):
        """Creates the application toolbar below the menu."""
        toolbar = ttk.Frame(parent, padding=(5, 2, 5, 2), relief=tk.GROOVE, borderwidth=1)
        toolbar.pack(side=tk.TOP, fill=tk.X, pady=(0, 5)) # 5px space below toolbar

        # Detect Devices Button
        detect_devices_btn = ttk.Button(toolbar, text="Detect Devices", command=self._on_detect_devices)
        detect_devices_btn.pack(side=tk.LEFT, padx=(0, 2), pady=2)

        # Refresh EPROMs Button
        refresh_eproms_btn = ttk.Button(toolbar, text="Refresh EPROMs", command=self._load_supported_eproms)
        refresh_eproms_btn.pack(side=tk.LEFT, padx=2, pady=2)

        # Selected device status on toolbar
        self.toolbar_selected_device_label = ttk.Label(toolbar, text="Device: None")
        self.toolbar_selected_device_label.pack(side=tk.RIGHT, padx=5, pady=2)
        # Add trace to update this label when selected_hardware_device changes
        self.selected_hardware_device.trace_add("write", self._update_toolbar_device_status)

    def _update_toolbar_device_status(self, *args):
        """Updates the device status label on the toolbar."""
        if hasattr(self, 'toolbar_selected_device_label'): # Ensure label exists
            device_name = self.selected_hardware_device.get()
            if device_name:
                self.toolbar_selected_device_label.config(text=f"Device: {device_name}")
            else:
                self.toolbar_selected_device_label.config(text="Device: None")

    def _create_main_layout(self):
        """Creates the toolbar, main panels for controls/output, and action bar."""
        # 1. Toolbar (created and packed to TOP)
        self._create_toolbar_frame(self.root)

        # 2. Bottom Action Bar (created, will be packed to BOTTOM later)
        self.action_bar = ttk.Frame(self.root, padding=5)
        self._create_execute_button(self.action_bar)  # FR-007

        # Main paned window for resizable sections
        self.main_paned_window = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)

        # Left Frame for controls
        controls_frame = ttk.Frame(self.main_paned_window, padding=5)
        self.main_paned_window.add(controls_frame, weight=1)
        self._create_eprom_selection_panel(controls_frame)  # FR-004
        self._create_operation_options_panel(controls_frame)  # FR-003

        # Right Frame for Output Console
        output_frame = ttk.Frame(self.main_paned_window, padding=5)
        self.main_paned_window.add(output_frame, weight=2)
        self._create_output_console(output_frame)  # FR-006

        # Pack order: Action Bar (BOTTOM), then Main Paned Window (fills remaining space)
        self.action_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(5, 0)) # 5px space above action bar
        self.main_paned_window.pack(fill=tk.BOTH, expand=True, padx=5) # padx for side margins

    def _create_eprom_selection_panel(self, parent):
        """Creates EPROM type search and selection panel (FR-004)."""
        panel = ttk.LabelFrame(parent, text="EPROM Selection", padding=10)
        panel.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(panel, text="EPROM Type:").grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W
        )
        self.eprom_type_combo = ttk.Combobox(
            panel, textvariable=self.selected_eprom_type, state="readonly", width=30
        )
        self.eprom_type_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        # TODO: Add search/filter functionality if needed beyond combobox's default.
        # For now, combobox provides a dropdown list.

    def _create_operation_options_panel(self, parent):
        """Creates the panel for operation-specific options (FR-003)."""
        self.op_options_panel = ttk.LabelFrame(
            parent, text="Operation Options", padding=10
        )
        self.op_options_panel.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Placeholder label
        self.op_options_placeholder = ttk.Label(
            self.op_options_panel,
            text="Select an operation from the 'Operations' menu.",
        )
        self.op_options_placeholder.pack(padx=5, pady=5)

        # Frame to hold dynamic widgets
        self.op_options_content_frame = ttk.Frame(self.op_options_panel)
        # This frame will be packed when an operation is selected

    def _create_output_console(self, parent):
        """Creates the output console text area (FR-006)."""
        panel = ttk.LabelFrame(parent, text="Output Console", padding=10)
        panel.pack(fill=tk.BOTH, expand=True)

        self.console_text = tk.Text(
            panel,
            wrap=tk.WORD,
            height=10,
            state=tk.DISABLED,
            relief=tk.SUNKEN,
            borderwidth=1,
        )
        self.console_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(panel, command=self.console_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.console_text.config(yscrollcommand=scrollbar.set)

    def _create_execute_button(self, parent):
        """Creates the Execute button (FR-007)."""
        self.execute_button = ttk.Button(
            parent,
            text="Execute Operation",
            command=self._on_execute_operation,
            state=tk.DISABLED,
        )
        self.execute_button.pack(pady=5, padx=5, side=tk.RIGHT)

    def log_to_console(self, message, tag=None):
        """Appends a message to the output console (FR-006)."""
        self.console_text.config(state=tk.NORMAL)
        if tag:
            self.console_text.insert(tk.END, message + "\n", tag)
        else:
            self.console_text.insert(tk.END, message + "\n")
        self.console_text.see(tk.END)
        self.console_text.config(state=tk.DISABLED)
        # Define tags for coloring if desired
        self.console_text.tag_configure("error", foreground="red")
        self.console_text.tag_configure("success", foreground="green")
        self.console_text.tag_configure("info", foreground="blue")

    def _load_supported_eproms(self):
        """Fetches and populates the list of supported EPROMs."""
        self.log_to_console("Fetching supported EPROM types...", "info")
        self.firestarter_ops.get_supported_eproms(
            on_success=self._handle_supported_eproms_result,
            on_error=lambda e: self._handle_error("fetching EPROMs", e),
        )

    def _handle_supported_eproms_result(self, eproms_data):
        self.supported_eproms_map = eproms_data if eproms_data else {}
        eprom_names = sorted(list(self.supported_eproms_map.keys()))
        self.eprom_type_combo["values"] = eprom_names
        if eprom_names:
            self.selected_eprom_type.set(eprom_names[0])
            self.log_to_console(f"Loaded {len(eprom_names)} EPROM types.", "success")
        else:
            self.log_to_console(
                "No EPROM types found or returned from library.", "error"
            )
            self.eprom_type_combo["values"] = []
            self.selected_eprom_type.set("")

    def _select_operation(self, operation_name):
        """Handles selection of an operation from the menu (FR-002)."""
        self.current_operation_name.set(operation_name)
        self.log_to_console(f"Selected Operation: {operation_name}", "info")
        self._update_operation_options_panel(operation_name)
        self.execute_button.config(
            state=(
                tk.NORMAL
                if self.defined_operations[operation_name]["implemented"]
                else tk.DISABLED
            )
        )

    def _update_operation_options_panel(self, operation_name):
        """Dynamically updates the options panel based on the selected operation (FR-003)."""
        # Clear previous options
        for widget in self.op_options_content_frame.winfo_children():
            widget.destroy()
        self.operation_params.clear()

        self.op_options_placeholder.pack_forget()  # Hide placeholder
        self.op_options_content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        op_details = self.defined_operations.get(operation_name)
        if not op_details or not op_details["implemented"]:
            ttk.Label(
                self.op_options_content_frame,
                text=f"'{operation_name}' is not yet implemented or has no options.",
            ).pack()
            return

        params_config = op_details.get("params", {})
        row_idx = 0
        for param_name, param_type in params_config.items():
            ttk.Label(
                self.op_options_content_frame,
                text=f"{param_name.replace('_', ' ').title()}:",
            ).grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=2)

            if param_type == "int" or param_type == "int_optional":
                var = tk.StringVar()
                entry = ttk.Entry(
                    self.op_options_content_frame, textvariable=var, width=15
                )
                entry.grid(row=row_idx, column=1, sticky=tk.EW, padx=5, pady=2)
                self.operation_params[param_name] = {"var": var, "type": param_type}
            elif param_type == "file_open" or param_type == "file_save":  # FR-008
                var = tk.StringVar()
                entry = ttk.Entry(
                    self.op_options_content_frame, textvariable=var, width=25
                )
                entry.grid(row=row_idx, column=1, sticky=tk.EW, padx=5, pady=2)

                browse_cmd = lambda v=var, pt=param_type: self._browse_file(v, pt)
                browse_button = ttk.Button(
                    self.op_options_content_frame, text="Browse...", command=browse_cmd
                )
                browse_button.grid(row=row_idx, column=2, sticky=tk.W, padx=5, pady=2)
                self.operation_params[param_name] = {"var": var, "type": param_type}

            self.op_options_content_frame.grid_columnconfigure(1, weight=1)
            row_idx += 1

    def _browse_file(self, string_var, dialog_type):
        """Handles file browsing (FR-008)."""
        file_path = ""
        if dialog_type == "file_open":
            file_path = filedialog.askopenfilename(title="Select File")
        elif dialog_type == "file_save":
            file_path = filedialog.asksaveasfilename(title="Save File As")

        if file_path:
            string_var.set(file_path)
            self.log_to_console(f"Selected file: {file_path}")

    def _on_detect_devices(self):  # FR-004.A
        """Initiates hardware device detection."""
        self.log_to_console("Detecting hardware devices...", "info")
        self.programmer_menu.entryconfig("Detect Devices", state=tk.DISABLED)
        self.firestarter_ops.detect_devices(
            on_success=self._handle_detect_devices_result,
            on_error=lambda e: self._handle_error(
                "detecting devices",
                e,
                finalize_action=lambda: self.programmer_menu.entryconfig(
                    "Detect Devices", state=tk.NORMAL
                ),
            ),
        )

    def _handle_detect_devices_result(self, devices):
        self.programmer_menu.entryconfig("Detect Devices", state=tk.NORMAL)
        self.available_devices = devices if devices else []
        self.log_to_console(
            f"Detected devices: {self.available_devices if self.available_devices else 'None'}",
            "success" if self.available_devices else "info",
        )

        self.select_device_submenu.delete(0, tk.END)  # Clear previous entries
        if self.available_devices:
            for device_name in self.available_devices:
                self.select_device_submenu.add_command(
                    label=device_name,
                    command=lambda dn=device_name: self._on_select_device(dn),
                )
            self.programmer_menu.entryconfig("Select Device", state=tk.NORMAL)
            if not self.selected_hardware_device.get() and self.available_devices:
                # Auto-select the first device if none is selected
                self._on_select_device(self.available_devices[0])
        else:
            self.select_device_submenu.add_command(
                label="<No devices found>", state=tk.DISABLED
            )
            self.programmer_menu.entryconfig("Select Device", state=tk.DISABLED)
            self.selected_hardware_device.set("")

    def _on_select_device(self, device_name):  # FR-005
        """Handles selection of a hardware device."""
        self.log_to_console(f"Attempting to select device: {device_name}", "info")
        # Visually update selection immediately
        self.selected_hardware_device.set(device_name)
        # Update radio button checkmarks in menu (if using radiobutton items)
        # For command items, this visual cue is implicit by selection.

        # Confirm selection with the library
        self.firestarter_ops.select_device(
            device_name,
            on_success=lambda result: self._handle_select_device_result(
                device_name, result
            ),
            on_error=lambda e: self._handle_error(f"selecting device {device_name}", e),
        )

    def _handle_select_device_result(self, device_name, success):
        if success:
            self.selected_hardware_device.set(device_name)  # Confirmed
            self.log_to_console(
                f"Successfully selected device: {device_name}", "success"
            )
        else:
            # This case might be covered by on_error if select_device raises an exception on failure
            self.log_to_console(
                f"Failed to select device: {device_name}. Check library behavior.",
                "error",
            )
            if (
                self.selected_hardware_device.get() == device_name
            ):  # Revert if it was optimistically set
                self.selected_hardware_device.set("")

    def _on_execute_operation(self):  # FR-007
        """Executes the currently selected Firestarter operation."""
        op_name = self.current_operation_name.get()
        eprom = self.selected_eprom_type.get()
        device = self.selected_hardware_device.get()

        if not op_name or op_name == "<No Operation Selected>":
            messagebox.showerror("Error", "No operation selected.")
            return
        if not eprom:
            messagebox.showerror("Error", "No EPROM type selected.")
            return
        if not device and op_name not in [
            "Get Supported EPROMs"
        ]:  # Some ops might not need a device
            messagebox.showerror("Error", "No hardware programmer device selected.")
            return

        self.log_to_console(
            f"Executing '{op_name}' for EPROM '{eprom}' on device '{device}'...", "info"
        )
        self.execute_button.config(state=tk.DISABLED)

        # Collect parameters
        kwargs = {}
        try:
            for param_name, param_info in self.operation_params.items():
                val_str = param_info["var"].get()
                if param_info["type"] == "int":
                    if not val_str:
                        raise ValueError(f"Parameter '{param_name}' cannot be empty.")
                    kwargs[param_name] = int(val_str)
                elif param_info["type"] == "int_optional":
                    kwargs[param_name] = int(val_str) if val_str else None
                elif param_info["type"] in ["file_open", "file_save"]:
                    if not val_str:
                        raise ValueError(
                            f"File path for '{param_name}' cannot be empty."
                        )
                    kwargs[param_name] = val_str  # The path itself
                else:  # string or other
                    kwargs[param_name] = val_str
        except ValueError as ve:
            messagebox.showerror("Input Error", str(ve))
            self.log_to_console(f"Input error: {ve}", "error")
            self.execute_button.config(state=tk.NORMAL)
            return

        # Call the appropriate operation method
        common_callbacks = {
            "on_success": lambda res: self._handle_operation_success(op_name, res),
            "on_error": lambda err: self._handle_error(
                op_name,
                err,
                finalize_action=lambda: self.execute_button.config(state=tk.NORMAL),
            ),
        }

        if op_name == "Read EPROM":
            self.firestarter_ops.read_eprom(
                eprom,
                kwargs.get("start_address", 0),
                kwargs.get("length"),
                **common_callbacks,
            )
        elif op_name == "Write EPROM":
            self.firestarter_ops.write_eprom(
                eprom,
                kwargs["file_path"],
                kwargs.get("start_address", 0),
                **common_callbacks,
            )
        # Add elif for other operations (Verify, Erase)
        else:
            self.log_to_console(
                f"Operation '{op_name}' execution logic not implemented in UI.", "error"
            )
            self.execute_button.config(state=tk.NORMAL)

    def _handle_operation_success(self, op_name, result):
        self.log_to_console(f"Operation '{op_name}' completed successfully.", "success")
        if isinstance(result, bytes):
            self.log_to_console(
                f"  Result: {len(result)} bytes of data. (First 16: {result[:16].hex()}...)"
            )
            # Optionally offer to save byte data to a file
            if messagebox.askyesno(
                "Save Data?", f"{op_name} returned {len(result)} bytes. Save to file?"
            ):
                file_path = filedialog.asksaveasfilename(
                    defaultextension=".bin",
                    filetypes=[("Binary files", "*.bin"), ("All files", "*.*")],
                )
                if file_path:
                    try:
                        with open(file_path, "wb") as f:
                            f.write(result)
                        self.log_to_console(f"Data saved to {file_path}", "success")
                    except Exception as e:
                        self.log_to_console(f"Error saving data to file: {e}", "error")
                        messagebox.showerror(
                            "File Save Error", f"Could not save data: {e}"
                        )
        elif (
            result is not None
        ):  # For operations returning status messages or other data
            self.log_to_console(f"  Result: {result}")
        self.execute_button.config(state=tk.NORMAL)

    def _handle_error(self, operation_description, error, finalize_action=None):
        error_msg = f"Error during {operation_description}: {error}"
        self.log_to_console(error_msg, "error")
        messagebox.showerror(f"Operation Error ({operation_description})", str(error))
        if finalize_action:
            finalize_action()
        # Ensure execute button is re-enabled if it was an operation error
        if (
            self.execute_button["state"] == tk.DISABLED
            and operation_description in self.defined_operations
        ):
            self.execute_button.config(state=tk.NORMAL)

    def handle_operation_status(self, message):
        """Callback for firestarter_ops to send general status updates."""
        self.log_to_console(message, "info")

    def _show_about(self):
        """Displays the About dialog."""
        messagebox.showinfo(
            "About Firestarter UI",
            "Firestarter UI\nVersion 0.1.0 (Development)\n\n"
            "A Tkinter GUI for the Firestarter EPROM Programmer Library.",
        )

    def on_closing(self):
        """Handle window close event."""
        # Perform any cleanup here if necessary
        self.root.destroy()
