#!/bin/bash
# Firesharing - PythonAnywhere Auto Setup
# Run this in your PythonAnywhere Bash console after uploading files.
# Usage: bash setup_pythonanywhere.sh

set -e

PROJECT_DIR="$HOME/secure-file-sharing"
echo "========================================"
echo "  Firesharing - PythonAnywhere Setup"
echo "========================================"
echo ""

# 1. Navigate to project
cd "$PROJECT_DIR"
echo "[1/5] Creating runtime directories..."
mkdir -p keys uploads downloads instance
rm -rf __pycache__

# 2. Create virtualenv
echo "[2/5] Setting up virtual environment..."
python3.11 -m venv venv
source venv/bin/activate

# 3. Install dependencies
echo "[3/5] Installing dependencies..."
pip install --quiet --upgrade pip setuptools wheel
pip install --quiet -r requirements.txt

# 4. Print WSGI config instructions
echo "[4/5] Configuring Web app..."
echo ""
echo "  Go to PythonAnywhere Dashboard -> Web tab"
echo "  Add a new web app -> Manual config -> Python 3.11"
echo ""
echo "  Set these values:"
echo "    Code directory:    $PROJECT_DIR"
echo "    Working directory: $PROJECT_DIR"
echo "    Virtualenv:        $PROJECT_DIR/venv"
echo ""
echo "  Edit WSGI file at /var/www/YOURUSERNAME_pythonanywhere_com_wsgi.py"
echo "  Replace its contents with:"
echo ""
echo "    import sys"
echo "    sys.path.insert(0, '$PROJECT_DIR')"
echo "    from wsgi import application"
echo ""

echo "[5/5] Setting environment variable..."
echo "  In Web tab -> Environment variables, add:"
echo "    SFS_ENV = production"
echo ""
echo "========================================"
echo "  Done! Click the green Reload button"
echo "  in the Web tab to start the app."
echo "========================================"
