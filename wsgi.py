"""WSGI entry point for PythonAnywhere.

PythonAnywhere's web tab points to this file.
"""
import sys
import os

_project = os.path.dirname(os.path.abspath(__file__))
if _project not in sys.path:
    sys.path.insert(0, _project)

from app import create_app
application = create_app()
