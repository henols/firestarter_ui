# firestarter_ui/operation_panels.py
"""
Contains the UI panels for different EPROM operations.
"""
import logging # Added for logging within panels
import tkinter as tk
from tkinter import ttk, filedialog, messagebox # Keep messagebox for potential direct use, though parent should handle most
from pathlib import Path

class BaseOperationPanel(ttk.Frame):
    """
    Base class for operation panels.
    Provides common functionality and structure.
    """
    def __init__(self, parent, app_instance, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.app = app_instance  # To access app methods like _browse_file, _log_to_console
        self.operation_params = {} # To store Entry widgets, BooleanVars, etc.

        # Common EPROM display (can be overridden if not needed)
        ttk.Label(self, text=f"EPROM: {self.app.selected_eprom_type.get()}").pack(anchor=tk.W, pady=2)

    def _browse_file(self, param_key, save=False):
        """Helper to call the app's browse file dialog."""
        if save:
            filepath = filedialog.asksaveasfilename(
                defaultextension=".bin",
                filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
            )
        else:
            filepath = filedialog.askopenfilename(
                filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
            )
        if filepath and param_key in self.operation_params and isinstance(self.operation_params[param_key], ttk.Entry):
            self.operation_params[param_key].delete(0, tk.END)
            self.operation_params[param_key].insert(0, filepath)

    def get_parameters(self):
        """
        Retrieves the current values from the panel's input widgets.
        This method should be implemented by subclasses.
        """
        params = {}
        for key, widget_or_var in self.operation_params.items():
            if isinstance(widget_or_var, tk.BooleanVar):
                params[key] = widget_or_var.get()
            elif isinstance(widget_or_var, ttk.Entry):
                params[key] = widget_or_var.get() or None # Return None if empty
            # Add other widget types if necessary
        return params

    def execute_operation(self, eprom_name: str, eprom_data_for_op: dict) -> bool:
        """
        Executes the specific operation for this panel.
        Subclasses should implement this method.

        Args:
            eprom_name (str): The name of the selected EPROM.
            eprom_data_for_op (dict): The EPROM data dictionary for the programmer.

        Returns:
            bool: True if the operation was successfully initiated (e.g., an async call was made),
                  False if there was a pre-flight error (e.g., validation failed).
        """
        self.app._log_to_console(f"Operation '{self.__class__.__name__}' not fully implemented in panel.", "WARNING")
        messagebox.showinfo("Not Implemented", f"Operation execution for {self.__class__.__name__} is not yet fully panel-specific.")
        return False # Indicates pre-flight error or not implemented

class ReadOperationPanel(BaseOperationPanel):
    def __init__(self, parent, app_instance, *args, **kwargs):
        super().__init__(parent, app_instance, *args, **kwargs)

        file_frame = ttk.Frame(self)
        file_frame.pack(fill=tk.X, pady=2)
        ttk.Label(file_frame, text="Output File:").pack(side=tk.LEFT, anchor=tk.W)
        self.operation_params["output_file"] = ttk.Entry(file_frame)
        self.operation_params["output_file"].pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        ttk.Button(file_frame, text="Browse...", command=lambda: self._browse_file("output_file", save=True)).pack(side=tk.LEFT)

        ttk.Label(self, text="Address (Hex, Optional):").pack(anchor=tk.W)
        self.operation_params["address"] = ttk.Entry(self)
        self.operation_params["address"].pack(fill=tk.X, padx=5, pady=2)

        ttk.Label(self, text="Length (Bytes, Hex/Dec, Optional):").pack(anchor=tk.W)
        self.operation_params["length"] = ttk.Entry(self)
        self.operation_params["length"].pack(fill=tk.X, padx=5, pady=2)

        self.operation_params["force_read"] = tk.BooleanVar()
        ttk.Checkbutton(self, text="Force Read (ignore ID mismatch)", variable=self.operation_params["force_read"]).pack(anchor=tk.W, pady=2)

    def execute_operation(self, eprom_name: str, eprom_data_for_op: dict) -> bool:
        params = self.get_parameters()
        output_file = params.get("output_file")
        force = params.get("force_read", False)
        address = params.get("address")
        length = params.get("length")

        if not output_file:
            if eprom_name and eprom_name != "None":
                default_dir = Path.home() / "firestarter"
                default_dir.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
                output_file = default_dir / f"{eprom_name.upper()}.bin"
                self.operation_params["output_file"].insert(0, str(output_file)) # Update UI
                self.app._log_to_console(f"Output file not set, defaulting to: {output_file}", "INFO")
            else:
                messagebox.showerror("Input Error", "EPROM type not selected, cannot set default output file.")
                return False # Pre-flight error

        if Path(output_file).exists():
            if not messagebox.askyesno("Overwrite Confirmation",
                                       f"The file '{output_file}' already exists.\nDo you want to overwrite it?"):
                self.app._log_to_console("Read operation cancelled by user (overwrite).", "INFO")
                return False # Pre-flight error / user cancellation
        self.app.firestarter_ops.read_eprom(eprom_name, eprom_data_for_op, str(output_file), address, length, force)
        return True # Operation initiated

class WriteOperationPanel(BaseOperationPanel):
    def __init__(self, parent, app_instance, *args, **kwargs):
        super().__init__(parent, app_instance, *args, **kwargs)

        file_frame = ttk.Frame(self)
        file_frame.pack(fill=tk.X, pady=2)
        ttk.Label(file_frame, text="Input File:").pack(side=tk.LEFT, anchor=tk.W)
        self.operation_params["input_file"] = ttk.Entry(file_frame)
        self.operation_params["input_file"].pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        ttk.Button(file_frame, text="Browse...", command=lambda: self._browse_file("input_file")).pack(side=tk.LEFT)

        ttk.Label(self, text="Address/Offset (Hex, Optional):").pack(anchor=tk.W)
        self.operation_params["address"] = ttk.Entry(self)
        self.operation_params["address"].pack(fill=tk.X, padx=5, pady=2)

        self.operation_params["verify_after_write"] = tk.BooleanVar(value=True)
        ttk.Checkbutton(self, text="Verify After Write", variable=self.operation_params["verify_after_write"]).pack(anchor=tk.W, pady=2)

        self.operation_params["force_write"] = tk.BooleanVar()
        ttk.Checkbutton(self, text="Force Write (ignore VPP/ID)", variable=self.operation_params["force_write"]).pack(anchor=tk.W, pady=2)

        self.operation_params["ignore_blank_check"] = tk.BooleanVar()
        ttk.Checkbutton(self, text="Ignore Blank Check (Skip Erase)", variable=self.operation_params["ignore_blank_check"]).pack(anchor=tk.W, pady=2)

    def execute_operation(self, eprom_name: str, eprom_data_for_op: dict) -> bool:
        params = self.get_parameters()
        input_file = params.get("input_file")
        address = params.get("address")
        verify_after = params.get("verify_after_write", True)
        force = params.get("force_write", False)
        ignore_blank = params.get("ignore_blank_check", False)

        if not input_file:
            messagebox.showerror("Input Error", "Input file is required for write operation.")
            return False # Pre-flight error
        self.app.firestarter_ops.write_eprom(eprom_name, eprom_data_for_op, input_file, verify_after, address, force, ignore_blank)
        return True # Operation initiated

class VerifyOperationPanel(BaseOperationPanel):
    def __init__(self, parent, app_instance, *args, **kwargs):
        super().__init__(parent, app_instance, *args, **kwargs)

        file_frame = ttk.Frame(self)
        file_frame.pack(fill=tk.X, pady=2)
        ttk.Label(file_frame, text="Input File:").pack(side=tk.LEFT, anchor=tk.W)
        self.operation_params["input_file"] = ttk.Entry(file_frame)
        self.operation_params["input_file"].pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        ttk.Button(file_frame, text="Browse...", command=lambda: self._browse_file("input_file")).pack(side=tk.LEFT)

        ttk.Label(self, text="Address/Offset (Hex, Optional):").pack(anchor=tk.W)
        self.operation_params["address"] = ttk.Entry(self)
        self.operation_params["address"].pack(fill=tk.X, padx=5, pady=2)

        self.operation_params["force_verify"] = tk.BooleanVar()
        ttk.Checkbutton(self, text="Force Verify", variable=self.operation_params["force_verify"]).pack(anchor=tk.W, pady=2)

    def execute_operation(self, eprom_name: str, eprom_data_for_op: dict) -> bool:
        params = self.get_parameters()
        input_file = params.get("input_file")
        address = params.get("address")
        force = params.get("force_verify", False)
        if not input_file:
            messagebox.showerror("Input Error", "Input file is required for verify operation.")
            return False # Pre-flight error
        # TODO: Implement self.app.firestarter_ops.verify_eprom(...)
        self.app._log_to_console(f"Verify EPROM for {eprom_name} with file {input_file} (address: {address}, force: {force}). Operation to be fully implemented in firestarter_ops.", "WARNING")
        return False # Not fully implemented yet

class EraseOperationPanel(BaseOperationPanel):
    def __init__(self, parent, app_instance, *args, **kwargs):
        super().__init__(parent, app_instance, *args, **kwargs)

        self.operation_params["perform_blank_check_after_erase"] = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text="Perform Blank Check After Erase", variable=self.operation_params["perform_blank_check_after_erase"]).pack(anchor=tk.W, pady=2)

        self.operation_params["force_erase"] = tk.BooleanVar()
        ttk.Checkbutton(self, text="Force Erase", variable=self.operation_params["force_erase"]).pack(anchor=tk.W, pady=2)
        ttk.Label(self, text="Erases the selected EPROM.").pack(pady=10)

    def execute_operation(self, eprom_name: str, eprom_data_for_op: dict) -> bool:
        params = self.get_parameters()
        force = params.get("force_erase", False)
        # TODO: Implement self.app.firestarter_ops.erase_eprom(...)
        self.app._log_to_console(f"Erase EPROM for {eprom_name} (force: {force}). Operation to be fully implemented in firestarter_ops.", "WARNING")
        return False # Not fully implemented yet

class CheckIdOperationPanel(BaseOperationPanel):
    def __init__(self, parent, app_instance, *args, **kwargs):
        super().__init__(parent, app_instance, *args, **kwargs)

        self.operation_params["force_check_id"] = tk.BooleanVar()
        ttk.Checkbutton(self, text="Force ID Check (ignore VPP)", variable=self.operation_params["force_check_id"]).pack(anchor=tk.W, pady=2)
        ttk.Label(self, text="Checks Chip ID of the selected EPROM.").pack(pady=10)

    def execute_operation(self, eprom_name: str, eprom_data_for_op: dict) -> bool:
        params = self.get_parameters()
        force = params.get("force_check_id", False)
        # TODO: Implement self.app.firestarter_ops.check_chip_id(...)
        self.app._log_to_console(f"Check Chip ID for {eprom_name} (force: {force}). Operation to be fully implemented in firestarter_ops.", "WARNING")
        return False # Not fully implemented yet

class BlankCheckOperationPanel(BaseOperationPanel):
    def __init__(self, parent, app_instance, *args, **kwargs):
        super().__init__(parent, app_instance, *args, **kwargs)

        self.operation_params["force_blank_check"] = tk.BooleanVar()
        ttk.Checkbutton(self, text="Force Blank Check", variable=self.operation_params["force_blank_check"]).pack(anchor=tk.W, pady=2)
        ttk.Label(self, text="Checks if the selected EPROM is blank.").pack(pady=10)

    def execute_operation(self, eprom_name: str, eprom_data_for_op: dict) -> bool:
        params = self.get_parameters()
        force = params.get("force_blank_check", False)
        self.app.firestarter_ops.blank_check_eprom(eprom_name, eprom_data_for_op, force)
        return True # Operation initiated

# Mapping of operation names to panel classes
OPERATION_PANELS = {
    "read": ReadOperationPanel,
    "write": WriteOperationPanel,
    "verify": VerifyOperationPanel,
    "erase": EraseOperationPanel,
    "check_id": CheckIdOperationPanel,
    "blank_check": BlankCheckOperationPanel,
}
