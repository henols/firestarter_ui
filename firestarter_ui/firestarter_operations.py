# firestarter_operations.py
"""
Handles interactions with the Firestarter library.

This module abstracts the Firestarter library calls, executes them in
non-blocking threads, and uses callbacks to send results/errors
to the ui_manager.py for UI updates.
"""

import time
import threading
import logging
from queue import Queue

# --- Mock Firestarter Library (Remove or replace with actual import) ---
# Assume 'firestarter' is an installed package:
# from firestarter import Firestarter as ActualFirestarter


class MockFirestarterLib:
    """
    A mock class simulating the Firestarter 1.4.x library.
    Replace this with the actual Firestarter library import and usage.
    """

    def __init__(self, programmer_device=None, eprom_type=None):
        self.programmer_device = programmer_device
        self.eprom_type = eprom_type
        self.logger = logging.getLogger("MockFirestarterLib")
        self.logger.info(
            f"MockFirestarterLib initialized. Programmer: {programmer_device}, EPROM: {eprom_type}"
        )

    def list_programmers(self):
        self.logger.info("Listing programmers...")
        time.sleep(0.5)  # Simulate hardware scan
        return ["/dev/ttyUSB0 (Mock)", "/dev/ttyUSB1 (Mock)", "COM3 (Mock)"]

    def list_eproms(self):
        self.logger.info("Listing EPROMs...")
        return ["27C256", "27C512", "AT28C256"]

    def set_programmer(self, device_path):
        self.programmer_device = device_path
        self.logger.info(f"Programmer set to: {device_path}")
        return True

    def set_eprom(self, eprom_name):
        self.eprom_type = eprom_name
        self.logger.info(f"EPROM type set to: {eprom_name}")
        return True

    def read_eprom(self, output_file, start_address=None, end_address=None, size=None):
        self.logger.info(
            f"Reading EPROM to {output_file} from {self.programmer_device} (EPROM: {self.eprom_type})"
        )
        self.logger.info(
            f"Params: start={start_address}, end={end_address}, size={size}"
        )
        time.sleep(2)  # Simulate operation
        # In a real scenario, this would return actual data or status
        return {
            "status": "success",
            "message": f"EPROM read successfully to {output_file}",
            "bytes_read": size or 256,
        }

    def write_eprom(self, input_file, start_address=None, verify_write=True):
        self.logger.info(
            f"Writing {input_file} to EPROM on {self.programmer_device} (EPROM: {self.eprom_type})"
        )
        self.logger.info(f"Params: start={start_address}, verify={verify_write}")
        time.sleep(3)  # Simulate operation
        return {
            "status": "success",
            "message": f"{input_file} written and verified successfully.",
        }

    def verify_eprom(self, input_file, start_address=None):
        self.logger.info(
            f"Verifying EPROM with {input_file} on {self.programmer_device} (EPROM: {self.eprom_type})"
        )
        self.logger.info(f"Params: start={start_address}")
        time.sleep(1.5)
        return {"status": "success", "message": "Verification successful."}

    def erase_eprom(self):
        self.logger.info(
            f"Erasing EPROM on {self.programmer_device} (EPROM: {self.eprom_type})"
        )
        time.sleep(5)  # Simulate long operation
        return {"status": "success", "message": "EPROM erased successfully."}

    def check_chip_id(self):
        self.logger.info(f"Checking chip ID on {self.programmer_device}")
        time.sleep(0.5)
        return {
            "status": "success",
            "chip_id": "0x1234 (Mock ID)",
            "manufacturer": "Mock Inc.",
        }

    def blank_check(self):
        self.logger.info(
            f"Performing blank check on {self.programmer_device} (EPROM: {self.eprom_type})"
        )
        time.sleep(1)
        # Simulate a non-blank chip for testing
        # return {"status": "success", "is_blank": True, "message": "Chip is blank."}
        return {
            "status": "failure",
            "is_blank": False,
            "message": "Chip is not blank at address 0x0010.",
        }


# --- End Mock Firestarter Library ---


class FirestarterController:
    """
    Controller to manage Firestarter library operations.
    """

    def __init__(self, ui_update_callback):
        self.ui_update_callback = ui_update_callback
        self.firestarter_lib = None
        self.selected_programmer = None
        self.selected_eprom = None
        self.operation_queue = Queue()  # For results from threads
        self._init_firestarter_library()

    def _init_firestarter_library(self):
        try:
            # Replace MockFirestarterLib with the actual Firestarter library class
            # self.firestarter_lib = ActualFirestarter()
            self.firestarter_lib = MockFirestarterLib()  # Using mock for now
            self.log_message("Firestarter library initialized (Mock).", "info")
        except ImportError:
            self.firestarter_lib = None
            self.log_message(
                "Firestarter library not found. Please install it.", "error"
            )
        except Exception as e:
            self.firestarter_lib = None
            self.log_message(f"Error initializing Firestarter library: {e}", "error")

    def log_message(self, message, level="info"):
        """Sends a log message to the UI via the callback."""
        # This ensures UI updates happen on the main thread if called from worker
        self.ui_update_callback("log", {"level": level, "message": message})

    def _execute_operation(self, target_func, op_name, *args, **kwargs):
        """Executes a Firestarter library function in a separate thread."""
        if not self.firestarter_lib:
            self.log_message("Firestarter library not available.", "error")
            self.ui_update_callback(
                f"{op_name}_result",
                {"status": "error", "message": "Library not available."},
            )
            return

        if not self.selected_programmer:
            self.log_message("No programmer selected.", "error")
            self.ui_update_callback(
                f"{op_name}_result",
                {"status": "error", "message": "Programmer not selected."},
            )
            return

        # Some operations might not need an EPROM type (e.g., list_programmers)
        # but core EPROM ops do.
        if (
            op_name not in ["get_programmers", "get_eproms"]
            and not self.selected_eprom
            and hasattr(self.firestarter_lib, "set_eprom")
        ):
            self.log_message("No EPROM type selected.", "error")
            self.ui_update_callback(
                f"{op_name}_result",
                {"status": "error", "message": "EPROM type not selected."},
            )
            return

        # Ensure library instance has current programmer/EPROM
        if self.selected_programmer and hasattr(self.firestarter_lib, "set_programmer"):
            self.firestarter_lib.set_programmer(self.selected_programmer)
        if self.selected_eprom and hasattr(self.firestarter_lib, "set_eprom"):
            self.firestarter_lib.set_eprom(self.selected_eprom)

        def threaded_task():
            try:
                self.log_message(f"Starting operation: {op_name}", "info")
                result = target_func(*args, **kwargs)
                self.operation_queue.put({"type": f"{op_name}_result", "data": result})
            except Exception as e:
                self.log_message(f"Error during {op_name}: {e}", "error")
                self.operation_queue.put(
                    {
                        "type": f"{op_name}_result",
                        "data": {"status": "error", "message": str(e)},
                    }
                )
            finally:
                # Signal UI to check queue
                self.ui_update_callback("check_queue", None)

        thread = threading.Thread(target=threaded_task, daemon=True)
        thread.start()

    # --- Public methods to be called by ui_manager ---

    def get_available_programmers(self):
        if not self.firestarter_lib:
            return []
        # This might not need threading if it's quick, or can be wrapped if slow
        try:
            return self.firestarter_lib.list_programmers()
        except Exception as e:
            self.log_message(f"Error listing programmers: {e}", "error")
            return []

    def get_supported_eproms(self):
        if not self.firestarter_lib:
            return []
        try:
            return self.firestarter_lib.list_eproms()
        except Exception as e:
            self.log_message(f"Error listing EPROMs: {e}", "error")
            return []

    def set_active_programmer(self, device_path):
        self.selected_programmer = device_path
        if self.firestarter_lib and hasattr(self.firestarter_lib, "set_programmer"):
            try:
                self.firestarter_lib.set_programmer(device_path)
                self.log_message(f"Active programmer set to: {device_path}", "info")
            except Exception as e:
                self.log_message(
                    f"Error setting programmer {device_path}: {e}", "error"
                )
        elif not self.firestarter_lib:
            self.log_message("Cannot set programmer, library not initialized.", "error")

    def set_active_eprom(self, eprom_name):
        self.selected_eprom = eprom_name
        if self.firestarter_lib and hasattr(self.firestarter_lib, "set_eprom"):
            try:
                self.firestarter_lib.set_eprom(eprom_name)
                self.log_message(f"Active EPROM set to: {eprom_name}", "info")
            except Exception as e:
                self.log_message(f"Error setting EPROM {eprom_name}: {e}", "error")
        elif not self.firestarter_lib:
            self.log_message("Cannot set EPROM, library not initialized.", "error")

    def read_from_eprom(self, params):
        self._execute_operation(self.firestarter_lib.read_eprom, "read", **params)

    def write_to_eprom(self, params):
        self._execute_operation(self.firestarter_lib.write_eprom, "write", **params)

    def verify_eprom_data(self, params):
        self._execute_operation(self.firestarter_lib.verify_eprom, "verify", **params)

    def erase_selected_eprom(self):
        self._execute_operation(self.firestarter_lib.erase_eprom, "erase")

    def check_eprom_chip_id(self):
        self._execute_operation(self.firestarter_lib.check_chip_id, "check_id")

    def perform_blank_check(self):
        self._execute_operation(self.firestarter_lib.blank_check, "blank_check")
