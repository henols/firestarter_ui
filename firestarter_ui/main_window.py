import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import logging

# Attempt to import firestarter components
try:
    from firestarter import __version__ as fs_version
    from firestarter.hardware import (
        get_programmer_info,
        update_firmware,
    )
    from firestarter.database import get_all_chip_names, get_chip_data
    from firestarter.eprom_operations import (
        read_eprom,
        write_eprom,
        verify_eprom,
        erase_eprom,
        check_chip_id,
        blank_check,
    )

    FIRESTARTER_AVAILABLE = True
except ImportError as e:
    print(
        f"Warning: Could not import the 'firestarter' library. Some features will be disabled. Error: {e}"
    )
    FIRESTARTER_AVAILABLE = False
    fs_version = "N/A"


class MainWindow:
    """Main application window for the Firestarter UI."""

    def __init__(self, master):
        self.master = master
        self.master.title(f"Firestarter UI (Library v{fs_version})")
        # Potentially set a minimum size
        # self.master.minsize(600, 400)

        self.selected_device = tk.StringVar()
        self.selected_chip_name = tk.StringVar()
        self.available_devices = []
        self.chip_data = None
        self.verbose_logging = tk.BooleanVar(value=False)

        # Queue for thread communication
        self.log_queue = queue.Queue()

        self._setup_logging()
        self._create_menu()
        self._create_widgets()
        self._layout_widgets()

        # Start pollinlist all functionsg the log queue
        self.master.after(100, self._process_log_queue)

        self.log_message("Firestarter UI Initialized.")
        if not FIRESTARTER_AVAILABLE:
            self.log_message(
                "WARNING: Firestarter library not found. Operations are disabled.",
                level=logging.ERROR,
            )
            messagebox.showerror(
                "Import Error",
                "Could not find the 'firestarter' library.\nPlease ensure it is installed correctly.",
            )

    def _setup_logging(self):
        """Sets up basic logging configuration."""
        self.logger = logging.getLogger("FirestarterUI")
        self.logger.setLevel(logging.INFO)  # Default level

        # Handler for the UI console
        self.log_handler = QueueHandler(self.log_queue)
        self.logger.addHandler(self.log_handler)

        # Optional: Add a file handler or stream handler for debugging if needed
        # file_handler = logging.FileHandler('firestarter_ui.log')
        # formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        # file_handler.setFormatter(formatter)
        # self.logger.addHandler(file_handler)

    def _create_menu(self):
        """Creates the main application menu bar."""
        self.menu_bar = tk.Menu(self.master)
        self.master.config(menu=self.menu_bar)

        # --- File Menu ---
        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(
            label="Open Configuration", command=self._not_implemented, state=tk.DISABLED
        )
        file_menu.add_command(
            label="Save Configuration", command=self._not_implemented, state=tk.DISABLED
        )
        file_menu.add_separator()
        file_menu.add_checkbutton(
            label="Verbose Logging",
            variable=self.verbose_logging,
            command=self._toggle_verbose_logging,
        )
        file_menu.add_command(
            label="Preferences", command=self._not_implemented, state=tk.DISABLED
        )
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)

        # --- Operations Menu ---
        operations_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Operations", menu=operations_menu)
        operations_menu.add_command(
            label="Read EPROM", command=self._op_read_eprom, state=self._get_op_state()
        )
        operations_menu.add_command(
            label="Write EPROM",
            command=self._op_write_eprom,
            state=self._get_op_state(),
        )
        operations_menu.add_command(
            label="Verify EPROM",
            command=self._op_verify_eprom,
            state=self._get_op_state(),
        )
        operations_menu.add_command(
            label="Erase EPROM",
            command=self._op_erase_eprom,
            state=self._get_op_state(),
        )
        operations_menu.add_command(
            label="Check Chip ID",
            command=self._op_check_chip_id,
            state=self._get_op_state(),
        )
        operations_menu.add_command(
            label="Blank Check",
            command=self._op_blank_check,
            state=self._get_op_state(),
        )
        # Add placeholders for other operations if needed

        # --- Hardware Menu ---
        hardware_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Hardware", menu=hardware_menu)
        hardware_menu.add_command(
            label="Detect Devices",
            command=self._hw_detect_devices,
            state=self._get_hw_state(),
        )
        self.device_menu = tk.Menu(
            hardware_menu, tearoff=0
        )  # Submenu for device selection
        hardware_menu.add_cascade(
            label="Select Device", menu=self.device_menu, state=tk.DISABLED
        )  # Disabled until devices detected
        hardware_menu.add_command(
            label="Update Programmer Firmware",
            command=self._hw_update_firmware,
            state=self._get_hw_state(),
        )
        hardware_menu.add_command(
            label="About Programmer",
            command=self._hw_about_programmer,
            state=self._get_hw_state(),
        )

        # --- Help Menu ---
        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About Firestarter UI", command=self._help_about)
        help_menu.add_command(
            label="View Documentation", command=self._not_implemented, state=tk.DISABLED
        )

    def _create_widgets(self):
        """Creates the main widgets of the application."""
        # Frame for Hardware and Chip Selection
        self.selection_frame = ttk.LabelFrame(self.master, text="Configuration")
        # TODO: Add Device Selection Dropdown (populated by _hw_detect_devices)
        # TODO: Add EPROM Type Search/Selection (populated from database)

        # Frame for Operation Specific Options
        self.options_frame = ttk.LabelFrame(self.master, text="Operation Options")
        self.options_label = ttk.Label(
            self.options_frame, text="Select an operation from the menu."
        )
        self.options_label.pack(padx=10, pady=10)
        # TODO: Add dynamic controls here based on selected operation

        # Frame for Execution and Status
        self.action_frame = ttk.Frame(self.master)
        self.execute_button = ttk.Button(
            self.action_frame,
            text="Execute",
            command=self._execute_operation,
            state=tk.DISABLED,
        )
        # TODO: Add Progress Bar

        # Output Console
        self.console_frame = ttk.LabelFrame(self.master, text="Output Console")
        self.console = scrolledtext.ScrolledText(
            self.console_frame, wrap=tk.WORD, height=10, state=tk.DISABLED
        )

    def _layout_widgets(self):
        """Arranges widgets in the main window."""
        self.selection_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        self.options_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.action_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        self.execute_button.pack(side=tk.RIGHT, padx=5, pady=5)
        self.console_frame.pack(
            side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=5, pady=5
        )
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _process_log_queue(self):
        """Processes messages from the logging queue to update the console."""
        while not self.log_queue.empty():
            try:
                record = self.log_queue.get_nowait()
                msg = self.log_handler.format(record)
                self.console.config(state=tk.NORMAL)
                self.console.insert(tk.END, msg + "\n")
                self.console.config(state=tk.DISABLED)
                self.console.see(tk.END)  # Auto-scroll
            except queue.Empty:
                break
            except Exception as e:
                print(f"Error processing log queue: {e}")  # Fallback logging
        # Reschedule polling
        self.master.after(100, self._process_log_queue)

    def log_message(self, message, level=logging.INFO):
        """Logs a message using the configured logger."""
        self.logger.log(level, message)

    def _toggle_verbose_logging(self):
        """Toggles the logging level based on the menu checkbox."""
        if self.verbose_logging.get():
            self.logger.setLevel(logging.DEBUG)
            self.log_message("Verbose logging enabled.", level=logging.DEBUG)
        else:
            self.log_message(
                "Verbose logging disabled.", level=logging.DEBUG
            )  # Log before changing level
            self.logger.setLevel(logging.INFO)

    # --- Placeholder & Helper Methods ---

    def _not_implemented(self):
        """Placeholder for features not yet implemented."""
        messagebox.showinfo("Not Implemented", "This feature is not yet available.")
        self.log_message(
            "Attempted to use an unimplemented feature.", level=logging.WARNING
        )

    def _get_op_state(self):
        """Returns the state for operation menu items."""
        return tk.NORMAL if FIRESTARTER_AVAILABLE else tk.DISABLED

    def _get_hw_state(self):
        """Returns the state for hardware menu items."""
        return tk.NORMAL if FIRESTARTER_AVAILABLE else tk.DISABLED

    # --- Menu Command Implementations (Placeholders/Basic) ---

    def _op_read_eprom(self):
        self.log_message("Selected: Read EPROM")
        self._show_options("Read")

    def _op_write_eprom(self):
        self.log_message("Selected: Write EPROM")
        self._show_options("Write")

    def _op_verify_eprom(self):
        self.log_message("Selected: Verify EPROM")
        self._show_options("Verify")

    def _op_erase_eprom(self):
        self.log_message("Selected: Erase EPROM")
        self._show_options("Erase")

    def _op_check_chip_id(self):
        self.log_message("Selected: Check Chip ID")
        self._show_options("Check ID")

    def _op_blank_check(self):
        self.log_message("Selected: Blank Check")
        self._show_options("Blank Check")

    def _hw_detect_devices(self):
        self.log_message("Selected: Detect Devices")
        self._not_implemented()  # TODO

    def _hw_update_firmware(self):
        self.log_message("Selected: Update Firmware")
        self._not_implemented()  # TODO

    def _hw_about_programmer(self):
        self.log_message("Selected: About Programmer")
        self._not_implemented()  # TODO

    def _help_about(self):
        messagebox.showinfo(
            "About Firestarter UI",
            f"Firestarter UI\nA graphical interface for the Firestarter EPROM Programmer.\n"
            f"Using Firestarter Library Version: {fs_version}",
        )

    def _show_options(self, operation_name):
        """Updates the options panel for the selected operation."""
        # Clear existing options
        for widget in self.options_frame.winfo_children():
            widget.destroy()

        # Display basic label
        ttk.Label(self.options_frame, text=f"Options for: {operation_name}").pack(
            pady=5
        )

        # TODO: Add specific controls based on operation_name
        # Example: File selection for Read/Write/Verify
        if operation_name in ["Read", "Write", "Verify"]:
            file_button = ttk.Button(
                self.options_frame, text="Select File...", command=self._select_file
            )
            file_button.pack(pady=5)
            # Add labels/entries for start/end address if needed

        self.execute_button.config(
            state=self._get_op_state()
        )  # Enable execute button if library is available

    def _select_file(self):
        """Opens a file dialog."""
        # TODO: Implement file selection logic and store the path
        filepath = filedialog.askopenfilename()  # Or asksaveasfilename for write output
        if filepath:
            self.log_message(f"Selected file: {filepath}")
            # Store filepath in a variable accessible by _execute_operation
        else:
            self.log_message("File selection cancelled.")

    def _execute_operation(self):
        """Placeholder for executing the selected operation."""
        self.log_message("Execute button clicked.")
        # TODO:
        # 1. Get selected operation type.
        # 2. Get selected device, chip data, file path, other options.
        # 3. Validate inputs.
        # 4. Call the appropriate firestarter function in a thread.
        # 5. Disable execute button during operation.
        # 6. Update UI (console, progress bar) via the queue.
        # 7. Re-enable execute button when done.
        self._not_implemented()


# --- Logging Handler for Tkinter Text Widget ---


class QueueHandler(logging.Handler):
    """A logging handler that puts records into a queue."""

    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(record)
