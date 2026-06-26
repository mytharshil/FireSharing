import uuid
from datetime import datetime, timedelta


def _utcnow():
    return datetime.utcnow()
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db


# ====================================================================
# User Model
# ====================================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    public_key = db.Column(db.Text, nullable=True)

    # Encrypted private key (AES-256-GCM + Argon2 KDF)
    encrypted_private_key = db.Column(db.Text, nullable=True)

    # Account security
    email_verified = db.Column(db.Boolean, default=False)
    email_verify_token = db.Column(db.String(64), nullable=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32), nullable=True)

    # Lockout tracking
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)

    # Password rotation
    password_changed_at = db.Column(db.DateTime, default=lambda: _utcnow())

    # Profile
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: _utcnow())

    # Relationships
    files = db.relationship('File', backref='owner', lazy='dynamic',
                            foreign_keys='File.owner_id')
    shares_given = db.relationship(
        'Share', backref='owner', lazy='dynamic',
        foreign_keys='Share.owner_id'
    )
    shares_received = db.relationship(
        'Share', backref='shared_with', lazy='dynamic',
        foreign_keys='Share.shared_with_id'
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256:600000')
        self.password_changed_at = _utcnow()

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_locked(self) -> bool:
        if self.locked_until and self.locked_until > _utcnow():
            return True
        return False

    def record_failed_attempt(self):
        self.failed_attempts = (self.failed_attempts or 0) + 1
        from config import Config
        if self.failed_attempts >= Config.MAX_LOGIN_ATTEMPTS:
            self.locked_until = _utcnow() + timedelta(
                minutes=Config.LOGIN_LOCKOUT_MINUTES
            )
        db.session.commit()

    def reset_failed_attempts(self):
        self.failed_attempts = 0
        self.locked_until = None
        db.session.commit()


# ====================================================================
# File Model
# ====================================================================

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False,
                     default=lambda: str(uuid.uuid4()))
    original_name = db.Column(db.String(256), nullable=False)
    stored_path = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.BigInteger, default=0)
    mime_type = db.Column(db.String(128), nullable=True)
    file_hash = db.Column(db.String(64), nullable=False)  # SHA-256

    # Encrypted AES key (wrapped with owner's RSA public key)
    aes_key_encrypted = db.Column(db.Text, nullable=False)

    # Digital signature (RSA-SHA256)
    signature = db.Column(db.Text, nullable=False)

    download_count = db.Column(db.Integer, default=0)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: _utcnow())
    updated_at = db.Column(db.DateTime, default=lambda: _utcnow(),
                           onupdate=lambda: _utcnow())
    is_deleted = db.Column(db.Boolean, default=False)

    shares = db.relationship('Share', backref='file', lazy='dynamic',
                             foreign_keys='Share.file_id')


# ====================================================================
# Share Model
# ====================================================================

class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False, index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_with_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)

    # Encrypted AES key (wrapped with recipient's RSA public key)
    aes_key_encrypted = db.Column(db.Text, nullable=False)

    # Permissions
    can_download = db.Column(db.Boolean, default=True)
    can_reshare = db.Column(db.Boolean, default=False)

    # Expiry
    expires_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: _utcnow())
    revoked = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, default=lambda: _utcnow(),
                           onupdate=lambda: _utcnow())

    def is_expired(self) -> bool:
        """Check if share has expired."""
        if self.revoked:
            return True
        if self.expires_at and self.expires_at < _utcnow():
            return True
        return False




# ====================================================================
# Audit Log Model
# ====================================================================

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    username = db.Column(db.String(32), nullable=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    resource_type = db.Column(db.String(32), nullable=True)
    resource_id = db.Column(db.String(64), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(256), nullable=True)
    geo_city = db.Column(db.String(64), nullable=True)
    geo_country = db.Column(db.String(64), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: _utcnow(), index=True)
    success = db.Column(db.Boolean, default=True)

    db.Index('idx_audit_action_time', 'action', 'timestamp')
