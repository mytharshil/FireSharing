import os
import secrets


class Config:
    # --- Core ---
    SECRET_KEY = os.environ.get('SFS_SECRET_KEY', secrets.token_hex(32))
    SQLALCHEMY_DATABASE_URI = os.environ.get('SFS_DATABASE_URL', 'sqlite:///firesharing.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Paths ---
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    KEY_FOLDER = os.path.join(BASE_DIR, 'keys')
    DOWNLOAD_FOLDER = os.path.join(BASE_DIR, 'downloads')

    # --- File Limits ---
    MAX_CONTENT_LENGTH = 64 * 1024 * 1024  # 64 MB
    ALLOWED_EXTENSIONS = {
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'txt', 'csv', 'json', 'xml', 'yaml', 'yml',
        'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp',
        'mp4', 'mp3', 'wav', 'avi', 'mkv',
        'zip', 'tar', 'gz', '7z', 'rar',
        'py', 'js', 'ts', 'html', 'css', 'sh',
    }
    ALLOWED_MIME_PREFIXES = [
        'text/', 'image/', 'application/pdf', 'application/json',
        'application/xml', 'application/zip', 'application/x-tar',
        'application/gzip', 'application/x-7z-compressed',
        'application/vnd.', 'audio/', 'video/',
        'application/octet-stream',
    ]

    # --- Session ---
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('SFS_ENV') == 'production'
    PERMANENT_SESSION_LIFETIME = 1800  # 30 min inactivity
    SESSION_REFRESH_EACH_REQUEST = True

    # --- Auth ---
    BCRYPT_ROUNDS = 12
    PASSWORD_MIN_LENGTH = 10
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 15
    REMEMBER_ME_DURATION = 2592000  # 30 days

    # --- Server ---
    SERVER_HOST = os.environ.get('SFS_HOST', '0.0.0.0')
    SERVER_PORT = int(os.environ.get('SFS_PORT', '5000'))
    SERVER_NAME = os.environ.get('SFS_SERVER_NAME', None)

    # --- Rate Limiting ---
    RATELIMIT_DEFAULT = '100/hour'
    RATELIMIT_STORAGE_URL = 'memory://'

    # --- Audit ---
    AUDIT_LOG_MAX_RECORDS = 10000

    # --- Encryption ---
    SCRYPT_N = 2 ** 17
    SCRYPT_R = 8
    SCRYPT_P = 1

    # --- Email (optional) ---
    SMTP_HOST = os.environ.get('SFS_SMTP_HOST', '')
    SMTP_PORT = int(os.environ.get('SFS_SMTP_PORT', '587'))
    SMTP_USER = os.environ.get('SFS_SMTP_USER', '')
    SMTP_PASS = os.environ.get('SFS_SMTP_PASS', '')
    SMTP_FROM = os.environ.get('SFS_SMTP_FROM', 'noreply@firesharing.local')
