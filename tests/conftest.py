"""Puts the repo root on sys.path so the tests import the flat modules (executor, agent, ...).

Run from the repo root: .venv/bin/python -m pytest -q tests
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
