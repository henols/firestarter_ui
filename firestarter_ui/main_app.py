# firestarter_ui/main_app.py
"""
Main entry point for the Firestarter UI application.

This script initializes and runs the Tkinter-based GUI.
"""

from firestarter_ui.ui_manager import FirestarterApp


def main():
    """
    Initializes and starts the Firestarter UI application.
    """
    app = FirestarterApp()
    app.mainloop()


if __name__ == "__main__":
    main()
