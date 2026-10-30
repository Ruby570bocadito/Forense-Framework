"""Entry point of the standalone executable (PyInstaller)."""

import multiprocessing
import sys

from sabueso.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
