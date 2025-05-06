#!/usr/bin/env python3

import tkinter as tk
from firestarter_ui.main_window import MainWindow


def run_ui():
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()


if __name__ == "__main__":
    run_ui()
