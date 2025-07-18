# firestarter_gui_app.py
"""
Main entry point for the Firestarter GUI application.

This module initializes and runs the Tkinter-based GUI.
It instantiates the main application class from ui_manager.py and
starts the Tkinter event loop.
"""

import tkinter as tk
from .ui_manager import FirestarterApp


def main() -> None:
    """Initializes and runs the Firestarter GUI application."""
    root: tk.Tk = tk.Tk()
    app: FirestarterApp = FirestarterApp(root) # Assuming FirestarterApp is defined in ui_manager
    root.mainloop()


if __name__ == "__main__":
    main()
