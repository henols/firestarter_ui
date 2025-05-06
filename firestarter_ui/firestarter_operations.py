# firestarter_operations.py
"""
Handles interactions with the Firestarter library,
executing operations in non-blocking threads and using callbacks.
"""
import threading
import time  # For simulating library work

# Assume 'firestarter' library version 1.4.x is installed.
# For development, we'll use a mock.
# import firestarter


class MockFirestarterLib:
    """
    A mock implementation of the Firestarter library for development purposes.
    This simulates the expected behavior of Firestarter 1.4.x API.
    """

    def __init__(self):
        self._detected_devices = []
        self._selected_device = None
        self._supported_eproms = {
            "27C256": {"size": 32 * 1024, "voltage": "5V"},
            "27C512": {"size": 64 * 1024, "voltage": "5V"},
            "AT28C256": {"size": 32 * 1024, "voltage": "5V", "page_write": True},
            "AM29F040B": {"size": 512 * 1024, "voltage": "5V", "sector_erase": True},
        }

    def detect_hardware_programmers(self):
        """Simulates detecting hardware programmers."""
        time.sleep(1.5)  # Simulate delay
        # Simulate finding some devices or none
        # self._detected_devices = [f"MockProgrammer-{i}" for i in range(1, 4)]
        self._detected_devices = ["TL866II+", "MiniPro TL866CS", "CH341A Programmer"]
        # if random.choice([True, False]): # Simulate occasional error
        #     raise ConnectionError("Mock Error: Failed to scan for programmers.")
        return self._detected_devices

    def select_hardware_programmer(self, device_name):
        """Simulates selecting a hardware programmer."""
        time.sleep(0.5)
        if device_name in self._detected_devices:
            self._selected_device = device_name
            return True
        raise ValueError(
            f"Mock Error: Device '{device_name}' not found or couldn't be selected."
        )

    def get_supported_eproms(self):
        """Simulates getting a list of supported EPROM types."""
        time.sleep(0.5)
        return self._supported_eproms

    def read_eprom(self, eprom_type, start_address=0, length=None):
        """Simulates reading data from an EPROM."""
        if not self._selected_device:
            raise ConnectionError("Mock Error: No programmer selected.")
        if eprom_type not in self._supported_eproms:
            raise ValueError(f"Mock Error: EPROM type '{eprom_type}' not supported.")

        actual_length = (
            length if length is not None else self._supported_eproms[eprom_type]["size"]
        )
        actual_length = min(
            actual_length, self._supported_eproms[eprom_type]["size"] - start_address
        )

        time.sleep(2)  # Simulate read time
        # Simulate some data
        return bytes([i % 256 for i in range(actual_length)])

    def write_eprom(self, eprom_type, file_path, start_address=0):
        """Simulates writing data to an EPROM from a file."""
        if not self._selected_device:
            raise ConnectionError("Mock Error: No programmer selected.")
        if eprom_type not in self._supported_eproms:
            raise ValueError(f"Mock Error: EPROM type '{eprom_type}' not supported.")

        # In a real scenario, you'd read data from file_path
        # For mock, we just simulate success based on file_path existing (not checked here)
        time.sleep(3)  # Simulate write time
        return f"Successfully wrote data from '{file_path}' to {eprom_type}."


# Use the mock library for now
firestarter_lib_instance = MockFirestarterLib()


class FirestarterOperations:
    """
    Provides methods to interact with the Firestarter library,
    handling threading and callbacks for UI updates.
    """

    def __init__(self, ui_callback_handler):
        """
        Initializes the operations handler.
        :param ui_callback_handler: An object (typically FirestarterApp instance)
                                    with methods to handle results and update the UI.
                                    It must have a 'schedule_gui_update(callable)' method.
        """
        self.ui_cb = ui_callback_handler

    def _execute_threaded(self, target_func, on_success, on_error, *args, **kwargs):
        """Executes a function in a new thread and handles callbacks."""

        def task_wrapper():
            try:
                self.ui_cb.schedule_gui_update(
                    lambda: self.ui_cb.handle_operation_status(
                        f"Executing: {target_func.__name__}..."
                    )
                )
                result = target_func(*args, **kwargs)
                self.ui_cb.schedule_gui_update(lambda: on_success(result))
            except Exception as e:
                self.ui_cb.schedule_gui_update(lambda: on_error(e))

        thread = threading.Thread(target=task_wrapper, daemon=True)
        thread.start()

    def detect_devices(self, on_success, on_error):
        self._execute_threaded(
            firestarter_lib_instance.detect_hardware_programmers, on_success, on_error
        )

    def select_device(self, device_name, on_success, on_error):
        # Selection is usually quick, but good practice to keep pattern if it could block
        self._execute_threaded(
            firestarter_lib_instance.select_hardware_programmer,
            on_success,
            on_error,
            device_name,
        )

    def get_supported_eproms(self, on_success, on_error):
        self._execute_threaded(
            firestarter_lib_instance.get_supported_eproms, on_success, on_error
        )

    def read_eprom(self, eprom_type, start_address, length, on_success, on_error):
        self._execute_threaded(
            firestarter_lib_instance.read_eprom,
            on_success,
            on_error,
            eprom_type,
            start_address,
            length,
        )

    def write_eprom(self, eprom_type, file_path, start_address, on_success, on_error):
        self._execute_threaded(
            firestarter_lib_instance.write_eprom,
            on_success,
            on_error,
            eprom_type,
            file_path,
            start_address,
        )

    # Add other Firestarter operations (erase, verify, etc.) here following the same pattern.
