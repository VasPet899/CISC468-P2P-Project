"""Shared helpers for interop tests."""

import json
import os

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name: str) -> dict:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path) as f:
        return json.load(f)
