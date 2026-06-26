import re
import os
import puremagic
from flask import request, g, current_app
from config import Config


# ====================================================================
# Security Headers Middleware
# ====================================================================

SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '0',  # Deprecated but still scanned for
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': (
        'camera=(), microphone=(), geolocation=(), interest-cohort=()'
    ),
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'Pragma': 'no-cache',
}


def set_security_headers(response):
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value

    # CSP — relaxed enough for the UI to work
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    response.headers['Content-Security-Policy'] = csp
    return response


# ====================================================================
# File Validation
# ====================================================================

def validate_file_type(file_storage) -> tuple:
    filename = file_storage.filename or ''
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    if ext not in Config.ALLOWED_EXTENSIONS:
        return False, f'File type ".{ext}" is not allowed.'

    file_storage.seek(0)
    head = file_storage.read(2048)
    file_storage.seek(0)

    if not head:
        return False, 'Empty file.'

    try:
        mime = puremagic.from_string(head, mime=True) or 'application/octet-stream'
    except Exception:
        mime = 'application/octet-stream'

    allowed = any(mime.startswith(p) for p in Config.ALLOWED_MIME_PREFIXES)
    if not allowed:
        return False, f'MIME type "{mime}" is not allowed.'

    return True, ''


# ====================================================================
# Path Traversal Protection
# ====================================================================

TRAVERSAL_RE = re.compile(r'\.\.[/\\]|[/\\]\.\.')


def safe_filename(filename: str) -> str:
    name = os.path.basename(filename)
    if TRAVERSAL_RE.search(name):
        raise ValueError('Path traversal detected in filename.')
    return name


# ====================================================================
# Sanitisation Helpers
# ====================================================================

def sanitise_string(value: str, max_len: int = 256) -> str:
    cleaned = value.strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len]
    return cleaned


# ====================================================================
# IP Address helpers
# ====================================================================

def get_client_ip() -> str:
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'
