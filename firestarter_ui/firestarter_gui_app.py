# firestarter_gui_app.py
"""
Main entry point for the Firestarter Tkinter GUI application.
Instantiates the UI class from ui_manager.py and starts the Tkinter mainloop.
"""
import tkinter as tk
import sys
import os

# Attempt standard relative import for package execution
try:
    from .ui_manager import FirestarterApp  # Use relative import for package structure
except ImportError:
    # Fallback for direct script execution.
    # This allows running the script directly, e.g., when its directory is not
    # automatically on the Python path or when __package__ is not set.

    # Get the directory of the current script (e.g., .../project_root/package_name/)
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    # Get the parent directory (e.g., .../project_root/)
    project_root_dir = os.path.dirname(current_script_dir)

    # Add the project root directory to sys.path if it's not already there
    if project_root_dir not in sys.path:
        sys.path.insert(0, project_root_dir)

    # Now, attempt to import using the absolute package path
    # Assumes the package directory (current_script_dir) is named 'firestarter_ui'
    from firestarter_ui.ui_manager import FirestarterApp


def main():
    """Initializes and runs the Firestarter GUI application."""
    root = tk.Tk()
    app = FirestarterApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)  # Handle window close gracefully
    root.mainloop()


if __name__ == "__main__":
    main()
