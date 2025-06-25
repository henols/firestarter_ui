# firestarter_ui/firestarter_operations.py
"""
Handles interactions with the Firestarter library.

This module abstracts the Firestarter library calls, executes them in
non-blocking threads, and uses callbacks to send results or errors
back to the ui_manager.
"""
import threading
import logging
from queue import Queue

# Import the firestarter library components
from firestarter.eprom_operations import EpromOperator, EpromOperationError, build_flags as fs_build_flags
from firestarter.hardware import HardwareManager, HardwareOperationError
from firestarter.firmware import FirmwareManager, FirmwareOperationError
from firestarter.config import ConfigManager
from firestarter.main import allowed_eproms as fs_allowed_eproms # For EPROM list
from firestarter.constants import (
    FLAG_FORCE, FLAG_SKIP_BLANK_CHECK, FLAG_SKIP_ERASE, FLAG_VPE_AS_VPP
)
from firestarter.database import EpromDatabase

# If this module is imported, we assume the Firestarter library is available.
FIRESTARTER_AVAILABLE = True


class FirestarterOperations:
    """
    A class to manage operations using the Firestarter library.
    """
    def __init__(self, ui_queue: Queue, eprom_db: EpromDatabase, config_manager: ConfigManager):
        logging.debug("FirestarterOperations.__init__ called.")
        self.ui_queue = ui_queue
        self.db = eprom_db # Store the passed EpromDatabase instance
        self.config_manager = config_manager # Use the ConfigManager instance passed from UIManager

        logging.debug(f"Initializing Firestarter components with config type: {type(self.config_manager)}")
        try:
            self.eprom_operator = EpromOperator(self.config_manager, progress_callback=self._progress_callback)
            self.hardware_manager = HardwareManager(self.config_manager)
            self.firmware_manager = FirmwareManager(self.config_manager) # Pass real config_manager
            logging.info("Firestarter library components initialized.")
        except Exception as e:
            logging.error(f"Error initializing Firestarter components: {e}")
            self.ui_queue.put(("error", f"Init Error: {e}"))
            self.hardware_manager = None
            self.firmware_manager = None
        logging.debug("FirestarterOperations.__init__ finished.")

    def _progress_callback(self, current_bytes, total_bytes):
        """
        Callback for EPROM operations to report progress.
        Puts a ('progress', (current, total)) message on the UI queue.
        """
        self.ui_queue.put(("progress", (current_bytes, total_bytes)))

    def _execute_in_thread(self, target_func, *args, operation_name="Operation"):
        """
        Executes a target function in a new thread.
        Puts ('status', message) for start/end, ('result', data) for success,
        or ('error', message) for failure onto the ui_queue.
        """
        logging.debug(f"_execute_in_thread: operation_name='{operation_name}', target_func='{target_func.__name__}', args='{args}'")
        def threaded_operation():
            logging.debug(f"Thread for '{operation_name}' started.")
            self.ui_queue.put(("status", f"{operation_name} started..."))
            print(args)
            print(type(args ))
            try:
                result = target_func(*args)
                logging.debug(f"Thread for '{operation_name}' target_func completed. Result: {result}")
                self.ui_queue.put(("result", (operation_name, result)))
                self.ui_queue.put(("status", f"{operation_name} completed successfully."))
            except (EpromOperationError, HardwareOperationError, FirmwareOperationError, Exception) as e:
                logging.error(f"Error during {operation_name}: {e}")
                self.ui_queue.put(("error", f"{operation_name} failed: {e}"))
            finally:
                # Signal completion, perhaps for re-enabling UI elements
                logging.debug(f"Thread for '{operation_name}' finished.")
                self.ui_queue.put(("operation_finished", operation_name))

        thread = threading.Thread(target=threaded_operation)
        thread.daemon = True  # Allow main program to exit even if threads are running
        thread.start()
        logging.debug(f"Thread '{thread.name}' for operation '{operation_name}' launched.")

    def get_eprom_list(self):
        """Retrieves the list of EPROMs."""
        logging.debug("get_eprom_list called.")
        try:
            logging.debug("Calling fs_allowed_eproms()")
            eproms = fs_allowed_eproms()
            logging.debug(f"fs_allowed_eproms() returned: {eproms}")
            self.ui_queue.put(("eprom_list", eproms))
        except Exception as e:
            self.ui_queue.put(("error", f"Failed to get EPROM list: {e}"))

    def detect_devices(self):
        """Detects connected programmer hardware."""
        logging.debug("detect_devices called.")
        if not self.hardware_manager:
            logging.warning("detect_devices: HardwareManager not available.")
            self.ui_queue.put(("error", "HardwareManager not available."))
            return

        def _detect():
            # The Firestarter library's HardwareManager doesn't have a direct scan_for_programmers.
            # It typically tries to connect to a preferred/auto-detected port.
            # For the UI, we might need to list serial ports and let the user select.
            # This is a placeholder for how device detection might be initiated.
            # For now, we'll simulate finding some ports.
            # A real implementation would use serial.tools.list_ports.comports()
            # and then try to handshake with each.
            logging.debug("_detect (for detect_devices) started.")
            try:
                # Placeholder: In a real scenario, you'd use serial.tools.list_ports
                import serial.tools.list_ports
                logging.debug("Attempting to list serial ports using serial.tools.list_ports.comports()")
                ports = []
                system_ports = serial.tools.list_ports.comports()
                for p in system_ports:
                    if p.device not in ports:  # Avoid duplicates
                        # Common keywords for Arduino, FTDI, CH340, etc.
                        # if p.manufacturer and ( # This is the completed line
                        #         "Arduino" in p.manufacturer
                        #         or "FTDI" in p.manufacturer
                        #         or "CH340" in p.manufacturer
                        #     ) or (p.description and "USB Serial" in p.description):
                        ports.append(p.device)        
                            
                logging.debug(f"Detected ports: {ports}")
                if not ports:
                    ports = ["No programmers found"]
            except Exception as e:
                ports = [f"Error detecting: {e}"]
            return ports

        self._execute_in_thread(_detect, operation_name="Detect Devices")

    def _build_operation_flags(self, force=False, ignore_blank_check=False, vpe_as_vpp=False):
        """Helper to build flags for EPROM operations."""
        # This mirrors the logic from firestarter.eprom_operations.build_flags
        logging.debug(f"_build_operation_flags: force={force}, ignore_blank_check={ignore_blank_check}, vpe_as_vpp={vpe_as_vpp}")
        # or firestarter.main.build_arg_flags
        flag_value = fs_build_flags(force=force, ignore_blank_check=ignore_blank_check, vpe_as_vpp=vpe_as_vpp)
        logging.debug(f"_build_operation_flags: returning flag_value={flag_value:02x}")
        return flag_value

    def read_eprom(self, eprom_name: str, eprom_data: dict, output_file: str, address: str, length: str, force: bool):
        logging.debug(f"read_eprom: eprom_name='{eprom_name}', output_file='{output_file}', address='{address}', length='{length}', force={force}, eprom_data_for_op provided.")
        
        if not eprom_data:
            logging.error(f"read_eprom: EPROM data for '{eprom_name}' was not provided.")
            self.ui_queue.put(("error", f"EPROM data for '{eprom_name}' was not provided."))
            return
        flags = self._build_operation_flags(force=force)
        logging.debug(f"read_eprom: flags={flags:02x}")
        self._execute_in_thread(
            self.eprom_operator.read_eprom,
            eprom_name, eprom_data, output_file, flags, address, length,
            operation_name="Read EPROM"
        )

    def write_eprom(self, eprom_name: str, eprom_data_for_op: dict, input_file: str, verify_after: bool, address: str, force: bool, ignore_blank: bool):
        logging.debug(f"write_eprom: eprom_name='{eprom_name}', input_file='{input_file}', verify_after={verify_after}, address='{address}', force={force}, ignore_blank={ignore_blank}, eprom_data_for_op provided.")
        if not eprom_data_for_op:
            logging.error(f"write_eprom: EPROM data for '{eprom_name}' was not provided.")
            self.ui_queue.put(("error", f"EPROM data for '{eprom_name}' was not provided."))
            return

        def threaded_operation():
            operation_name = "Write EPROM"
            logging.debug(f"Thread for '{operation_name}' started.")
            self.ui_queue.put(("status", f"{operation_name} started..."))
            try:
                # Phase 1: Blank Check (if not ignored)
                if not ignore_blank:
                    self.ui_queue.put(("status", "Performing pre-write blank check..."))
                    blank_flags = self._build_operation_flags(force=force)
                    
                    # This call is blocking but will use the progress_callback
                    is_blank = self.eprom_operator.check_eprom_blank(
                        eprom_name, eprom_data_for_op, blank_flags
                    )
                    if not is_blank:
                        # The error is already logged by check_eprom_blank
                        raise EpromOperationError("EPROM is not blank. Write operation aborted.")
                
                # Phase 2: Write
                self.ui_queue.put(("status", "Blank check complete. Starting write..."))
                # The blank check is done, so we tell the write op to skip it.
                write_flags = self._build_operation_flags(force=force, ignore_blank_check=True)
                
                # This call is also blocking and uses the progress_callback
                write_success = self.eprom_operator.write_eprom(
                    eprom_name, eprom_data_for_op, input_file, write_flags, address
                )
                
                if not write_success:
                    raise EpromOperationError("EPROM write failed.")
                
                self.ui_queue.put(("result", (operation_name, write_success)))
                self.ui_queue.put(("status", f"{operation_name} completed successfully."))
            except (EpromOperationError, Exception) as e:
                logging.error(f"Error during {operation_name}: {e}")
                self.ui_queue.put(("error", f"{operation_name} failed: {e}"))
            finally:
                logging.debug(f"Thread for '{operation_name}' finished.")
                self.ui_queue.put(("operation_finished", operation_name))

        thread = threading.Thread(target=threaded_operation)
        thread.daemon = True
        thread.start()
        logging.debug(f"Thread '{thread.name}' for operation 'Write EPROM' launched.")

    # ... Implement other operations: verify, erase, check_chip_id, blank_check
    # For example:
    def blank_check_eprom(self, eprom_name: str, eprom_data_for_op: dict, force: bool):
        logging.debug(f"blank_check_eprom: eprom_name='{eprom_name}', force={force}, eprom_data_for_op provided.")
        if not eprom_data_for_op:
            logging.error(f"blank_check_eprom: EPROM data for '{eprom_name}' was not provided.")
            self.ui_queue.put(("error", f"EPROM data for '{eprom_name}' was not provided."))
            return
        flags = self._build_operation_flags(force=force)
        logging.debug(f"blank_check_eprom: flags={flags:02x}")
        self._execute_in_thread(
            self.eprom_operator.check_eprom_blank,
            eprom_name, eprom_data_for_op, flags,
            operation_name="Blank Check"
        )

    # Add stubs for other operations as per PRD
    # verify_eprom, erase_eprom, check_chip_id
    # update_firmware, read_vpp, read_vcc (vpe)