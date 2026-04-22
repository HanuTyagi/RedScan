#!/usr/bin/env python3
"""
RedScan GUI entry point.

Usage:
    python gui_main.py

A display (DISPLAY env variable) is required.  For headless CI the app will
skip loading and print a message instead.
"""
from __future__ import annotations

import os
import sys


def launch() -> None:
    # Guard: detect missing display before importing Tk
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        print(
            "[RedScan] No display found ($DISPLAY / $WAYLAND_DISPLAY is not set).\n"
            "Set up a virtual framebuffer (e.g. Xvfb) or run in a desktop environment.",
            file=sys.stderr,
        )
        sys.exit(1)

    from gui.app import RedScanApp  # deferred so import guard fires first

    app = RedScanApp()
    app.mainloop()


if __name__ == "__main__":
    launch()
