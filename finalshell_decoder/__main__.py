import tkinter as tk
try:
    import ttkbootstrap as tb
except Exception:
    tb = None

from .gui import FinalShellGUI


def main():
    if tb is not None:
        try:
            root = tb.Window(themename='minty')
        except Exception:
            root = tk.Tk()
    else:
        root = tk.Tk()
    app = FinalShellGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()