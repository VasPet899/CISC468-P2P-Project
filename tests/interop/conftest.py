"""Pytest configuration for interop tests.

Adds the python-client package and the interop directory itself to sys.path
so that test modules can import p2pshare and helpers.
"""

import os
import sys

_HERE = os.path.dirname(__file__)

# Allow test files to import helpers.py as a plain module
sys.path.insert(0, _HERE)

# Allow test files to import p2pshare
sys.path.insert(0, os.path.join(_HERE, "..", "..", "python-client"))
