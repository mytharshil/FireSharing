import os
import base64
import uuid as uuid_lib
import secrets
from datetime import datetime, timedelta


def _utcnow():
    return datetime.utcnow()

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, send_file, abort, jsonify, session, g
)
from flask_login import (
    login_user, logout_user, login_required, current_user
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import puremagic
from config import Config
from extensions import db, login_manager, csrf
from models import User, File, Share, AuditLog
from forms import (
    RegisterForm, LoginForm, ChangePasswordForm,
    UploadForm, ShareForm, DeleteAccountForm
)
from crypto_utils import (
    generate_aes_key, aes_encrypt, aes_decrypt,
    generate_rsa_keypair, rsa_encrypt, rsa_decrypt,
    sign_data, verify_signature,
    key_to_pem, pem_to_key,
    hash_file, encrypted_pem_to_private_key,
    private_key_to_encrypted_pem,
)
from security import (
    set_security_headers, validate_file_type,
    safe_filename, sanitise_string, get_client_ip
)


# ====================================================================
# App Factory
# ====================================================================

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # --- Ensure directories exist ---
    for d in [Config.UPLOAD_FOLDER, Config.KEY_FOLDER, Config.DOWNLOAD_FOLDER]:
        os.makedirs(d, exist_ok=True)

    # --- Extensions ---
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # In-memory private key cache (user_id -> RsaKey)
    _key_cache: dict = {}

    def _cache_private_key(user_id: int, priv_key) -> None:
        _key_cache[user_id] = priv_key

    def _get_cached_key(user_id: int):
        return _key_cache.get(user_id)

    def _clear_cached_key(user_id: int) -> None:
        _key_cache.pop(user_id, None)

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[Config.RATELIMIT_DEFAULT],
        storage_uri=Config.RATELIMIT_STORAGE_URL,
    )

    # ==================================================================
    # Login Manager
    # ==================================================================

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # ==================================================================
    # Security: Headers on every response
    # ==================================================================

    app.after_request(set_security_headers)

    # ==================================================================
    # Context Processors
    # ==================================================================

    @app.context_processor
    def inject_now():
        if current_user.is_authenticated:
            key_unlocked = current_user.id in _key_cache
        else:
            key_unlocked = False
        return {
            'now': _utcnow(),
            'has_private_key': key_unlocked,
        }

    from flask_wtf.csrf import generate_csrf
    app.jinja_env.globals['csrf_token'] = generate_csrf

    # ==================================================================
    # Audit Helper
    # ==================================================================

    def log_action(action, details=None, resource_type=None, resource_id=None,
                   success=True):
        log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            username=current_user.username if current_user.is_authenticated else None,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            details=details,
            ip_address=get_client_ip(),
            user_agent=request.headers.get('User-Agent', '')[:256],
            success=success,
        )
        db.session.add(log)
        db.session.commit()

        # Auto-prune old logs
        count = AuditLog.query.count()
        if count > Config.AUDIT_LOG_MAX_RECORDS:
            to_delete = (
                AuditLog.query
                .order_by(AuditLog.timestamp.asc())
                .limit(count - Config.AUDIT_LOG_MAX_RECORDS)
                .all()
            )
            for rec in to_delete:
                db.session.delete(rec)
            db.session.commit()

    # ==================================================================
    # Private Key Session Helpers
    # ==================================================================

    def unlock_private_key(password: str) -> bool:
        if not current_user.encrypted_private_key:
            return False
        try:
            priv = encrypted_pem_to_private_key(
                current_user.encrypted_private_key, password
            )
            _cache_private_key(current_user.id, priv)
            session.permanent = True
            return True
        except Exception:
            return False

    def get_private_key():
        return _get_cached_key(current_user.id)

    def lock_private_key():
        _clear_cached_key(current_user.id)

    # ==================================================================
    # Routes: Index
    # ==================================================================

    @app.route('/')
    def index():
        return render_template('index.html')

    # ==================================================================
    # Routes: Auth
    # ==================================================================

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegisterForm()
        if form.validate_on_submit():
            username = sanitise_string(form.username.data, 32)
            email = sanitise_string(form.email.data, 120)

            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'danger')
                return render_template('register.html', form=form)
            if User.query.filter_by(email=email).first():
                flash('Email already registered.', 'danger')
                return render_template('register.html', form=form)

            user = User(username=username, email=email)
            user.set_password(form.password.data)

            priv, pub = generate_rsa_keypair()
            user.public_key = key_to_pem(pub).decode()
            user.encrypted_private_key = private_key_to_encrypted_pem(
                priv, form.password.data
            )

            user.email_verify_token = secrets.token_urlsafe(32)

            db.session.add(user)
            db.session.commit()

            log_action('REGISTER', f'User {username} registered',
                       resource_type='user', resource_id=user.id)
            flash(
                'Registration successful! Please login to unlock your key.',
                'success'
            )
            return redirect(url_for('login'))

        return render_template('register.html', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit('10/minute')
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            username = sanitise_string(form.username.data, 32)
            user = User.query.filter_by(username=username).first()

            if not user:
                flash('Invalid credentials.', 'danger')
                log_action('LOGIN_FAIL', f'Unknown user: {username}',
                           success=False)
                return render_template('login.html', form=form)

            if not user.is_active:
                flash('Account is deactivated.', 'danger')
                return render_template('login.html', form=form)

            if user.is_locked():
                remaining = (user.locked_until - _utcnow()).seconds // 60
                flash(f'Account locked. Try again in {remaining} minutes.', 'danger')
                log_action('LOGIN_LOCKED', f'User {username} blocked (locked)',
                           resource_type='user', resource_id=user.id, success=False)
                return render_template('login.html', form=form)

            if user.check_password(form.password.data):
                login_user(user, remember=form.remember.data)
                user.reset_failed_attempts()
                user.last_login_at = _utcnow()
                user.last_login_ip = get_client_ip()
                db.session.commit()

                # Key is NOT auto-unlocked on login for security
                # User must explicitly unlock via /unlock

                log_action('LOGIN', f'User {username} logged in',
                           resource_type='user', resource_id=user.id)
                flash(f'Welcome back, {username}!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                user.record_failed_attempt()
                remaining = Config.MAX_LOGIN_ATTEMPTS - (user.failed_attempts or 0)
                if remaining > 0:
                    flash(f'Invalid credentials. {remaining} attempts remaining.', 'danger')
                else:
                    flash('Too many failed attempts. Account locked for 15 minutes.', 'danger')
                log_action('LOGIN_FAIL',
                           f'User {username} invalid password (attempt {user.failed_attempts})',
                           resource_type='user', resource_id=user.id, success=False)

        return render_template('login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        log_action('LOGOUT', f'User {current_user.username} logged out',
                   resource_type='user', resource_id=current_user.id)
        lock_private_key()
        logout_user()
        session.clear()
        flash('You have been logged out.', 'info')
        return redirect(url_for('index'))

    @app.route('/unlock', methods=['GET', 'POST'])
    @login_required
    def unlock():
        if get_private_key():
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            password = request.form.get('password', '')
            if unlock_private_key(password):
                log_action('KEY_UNLOCK', f'User {current_user.username} unlocked key',
                           resource_type='user', resource_id=current_user.id)
                flash('Private key unlocked for this session.', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect password.', 'danger')
        return render_template('unlock.html')

    @app.route('/lock')
    @login_required
    def lock():
        lock_private_key()
        flash('Private key locked.', 'info')
        return redirect(url_for('dashboard'))

    @app.route('/change-password', methods=['GET', 'POST'])
    @login_required
    def change_password():
        form = ChangePasswordForm()
        if form.validate_on_submit():
            if not current_user.check_password(form.current_password.data):
                flash('Current password is incorrect.', 'danger')
                return render_template('change_password.html', form=form)

            unlock_private_key(form.current_password.data)
            priv = get_private_key()
            if priv:
                current_user.encrypted_private_key = private_key_to_encrypted_pem(
                    priv, form.new_password.data
                )
            current_user.set_password(form.new_password.data)
            db.session.commit()
            lock_private_key()

            log_action('PASSWORD_CHANGE',
                       f'User {current_user.username} changed password',
                       resource_type='user', resource_id=current_user.id)
            flash('Password changed successfully. Please unlock your key again.', 'success')
            return redirect(url_for('dashboard'))

        return render_template('change_password.html', form=form)

    # ==================================================================
    # Routes: Dashboard
    # ==================================================================

    @app.route('/dashboard')
    @login_required
    def dashboard():
        page = request.args.get('page', 1, type=int)
        search_query = request.args.get('q', '').strip()
        sort_by = request.args.get('sort', 'date')

        file_query = File.query.filter_by(
            owner_id=current_user.id, is_deleted=False
        )
        if search_query:
            file_query = file_query.filter(
                File.original_name.ilike(f'%{search_query}%')
            )

        if sort_by == 'name':
            file_query = file_query.order_by(File.original_name.asc())
        elif sort_by == 'size':
            file_query = file_query.order_by(File.file_size.desc())
        else:
            file_query = file_query.order_by(File.created_at.desc())

        pagination = file_query.paginate(
            page=page, per_page=12, error_out=False
        )
        my_files = pagination.items

        shares_with_me = (
            Share.query
            .filter_by(shared_with_id=current_user.id, revoked=False)
            .order_by(Share.created_at.desc())
            .all()
        )

        total_files = File.query.filter_by(
            owner_id=current_user.id, is_deleted=False
        ).count()
        total_storage = db.session.query(
            db.func.coalesce(db.func.sum(File.file_size), 0)
        ).filter_by(owner_id=current_user.id, is_deleted=False).scalar()
        total_shares_given = Share.query.join(
            File, Share.file_id == File.id
        ).filter(
            File.owner_id == current_user.id,
            File.is_deleted == False,
            Share.revoked == False
        ).count()

        return render_template(
            'dashboard.html', files=my_files, shares=shares_with_me,
            total_files=total_files, total_storage=total_storage,
            total_shares_given=total_shares_given,
            search_query=search_query, sort_by=sort_by,
            pagination=pagination
        )

    # ==================================================================
    # Routes: File Upload
    # ==================================================================

    @app.route('/upload', methods=['GET', 'POST'])
    @login_required
    @limiter.limit('30/hour')
    def upload():
        form = UploadForm()
        if form.validate_on_submit():
            file = form.file.data
            if not file or file.filename == '':
                flash('No file selected.', 'danger')
                return render_template('upload.html', form=form)

            original_name = safe_filename(file.filename)

            is_valid, msg = validate_file_type(file)
            if not is_valid:
                flash(f'File rejected: {msg}', 'danger')
                log_action('UPLOAD_REJECTED',
                           f'Rejected {original_name}: {msg}',
                           resource_type='file', success=False)
                return render_template('upload.html', form=form)

            data = file.read()

            if len(data) > Config.MAX_CONTENT_LENGTH:
                flash('File exceeds maximum size (64 MB).', 'danger')
                return render_template('upload.html', form=form)

            # Encrypt file
            aes_key = generate_aes_key()
            aad = original_name.encode()
            enc_data = aes_encrypt(data, aes_key, aad=aad)

            # Wrap AES key with owner's RSA public key
            pub_key = pem_to_key(current_user.public_key.encode())
            aes_key_encrypted = rsa_encrypt(aes_key, pub_key)

            # Sign file
            priv_key = get_private_key()
            if not priv_key:
                flash('Please unlock your private key first.', 'warning')
                return redirect(url_for('unlock'))

            signature = sign_data(data, priv_key)
            file_hash = hash_file(data)

            # Detect MIME
            try:
                mime = puremagic.from_string(data, mime=True) or 'application/octet-stream'
            except Exception:
                mime = 'application/octet-stream'

            file_uuid = str(uuid_lib.uuid4())
            stored_name = f'{file_uuid}.enc'
            stored_path = os.path.join(Config.UPLOAD_FOLDER, stored_name)
            with open(stored_path, 'wb') as f:
                f.write(enc_data)

            db_file = File(
                uuid=file_uuid,
                original_name=original_name,
                stored_path=stored_path,
                file_size=len(data),
                mime_type=mime,
                file_hash=file_hash,
                aes_key_encrypted=base64.b64encode(aes_key_encrypted).decode(),
                signature=base64.b64encode(signature).decode(),
                owner_id=current_user.id,
            )
            db.session.add(db_file)
            db.session.commit()

            log_action('UPLOAD', f'File {original_name} ({len(data)} bytes) uploaded',
                       resource_type='file', resource_id=db_file.uuid)
            flash('File uploaded, encrypted, and signed successfully.', 'success')
            return redirect(url_for('dashboard'))

        return render_template('upload.html', form=form)

    # ==================================================================
    # Routes: File Download
    # ==================================================================

    @app.route('/download/<uuid:file_uuid>')
    @login_required
    @limiter.limit('60/hour')
    def download(file_uuid):
        db_file = File.query.filter_by(uuid=str(file_uuid), is_deleted=False).first()
        if not db_file:
            abort(404)

        is_owner = db_file.owner_id == current_user.id
        share = Share.query.filter_by(
            file_id=db_file.id,
            shared_with_id=current_user.id,
        ).first()

        if not is_owner and (not share or not share.can_download or share.is_expired()):
            log_action('DOWNLOAD_DENIED',
                       f'User {current_user.username} denied download of {db_file.original_name}',
                       resource_type='file', resource_id=db_file.uuid, success=False)
            abort(403)

        priv_key = get_private_key()
        if not priv_key:
            flash('Please unlock your private key first.', 'warning')
            return redirect(url_for('unlock'))

        # Decrypt AES key
        if is_owner:
            enc_aes_key = base64.b64decode(db_file.aes_key_encrypted)
        else:
            enc_aes_key = base64.b64decode(share.aes_key_encrypted)
        aes_key = rsa_decrypt(enc_aes_key, priv_key)

        # Read and decrypt file
        with open(db_file.stored_path, 'rb') as f:
            enc_data = f.read()

        aad = db_file.original_name.encode()
        data = aes_decrypt(enc_data, aes_key, aad=aad)

        # Verify integrity
        actual_hash = hash_file(data)
        if actual_hash != db_file.file_hash:
            log_action('DOWNLOAD_HASH_FAIL',
                       f'Hash mismatch for {db_file.original_name}',
                       resource_type='file', resource_id=db_file.uuid, success=False)
            flash('ERROR: File integrity check failed! File may be corrupted.', 'danger')
            return redirect(url_for('dashboard'))

        # Verify digital signature
        sig = base64.b64decode(db_file.signature)
        owner_pub = pem_to_key(db_file.owner.public_key.encode())
        if not verify_signature(data, sig, owner_pub):
            log_action('DOWNLOAD_SIG_FAIL',
                       f'Signature invalid for {db_file.original_name}',
                       resource_type='file', resource_id=db_file.uuid, success=False)
            flash('WARNING: Digital signature verification failed! File may be tampered.', 'warning')

        # Write temp decrypted file for download
        dl_path = os.path.join(Config.DOWNLOAD_FOLDER, f'{db_file.uuid}_{db_file.original_name}')
        with open(dl_path, 'wb') as f:
            f.write(data)

        db_file.download_count = (db_file.download_count or 0) + 1
        db.session.commit()

        log_action('DOWNLOAD',
                   f'User {current_user.username} downloaded {db_file.original_name}',
                   resource_type='file', resource_id=db_file.uuid)

        response = send_file(dl_path, as_attachment=True,
                             download_name=db_file.original_name)

        # Cleanup temp file after serving
        @response.call_on_close
        def cleanup():
            try:
                os.remove(dl_path)
            except OSError:
                pass

        return response

    # ==================================================================
    # Routes: Share
    # ==================================================================

    @app.route('/share/<uuid:file_uuid>', methods=['GET', 'POST'])
    @login_required
    def share(file_uuid):
        db_file = File.query.filter_by(uuid=str(file_uuid), is_deleted=False).first()
        if not db_file or db_file.owner_id != current_user.id:
            abort(404)

        form = ShareForm()
        if form.validate_on_submit():
            username = sanitise_string(form.username.data, 32)
            target = User.query.filter_by(username=username).first()
            if not target:
                flash('User not found.', 'danger')
                return render_template('share.html', form=form, file=db_file)

            if target.id == current_user.id:
                flash('You cannot share with yourself.', 'danger')
                return render_template('share.html', form=form, file=db_file)

            existing = Share.query.filter_by(
                file_id=db_file.id, shared_with_id=target.id
            ).first()
            if existing:
                flash('Already shared with this user.', 'info')
                return redirect(url_for('dashboard'))

            # Decrypt AES key with owner's private key
            priv_key = get_private_key()
            if not priv_key:
                flash('Please unlock your private key first.', 'warning')
                return redirect(url_for('unlock'))

            aes_key = rsa_decrypt(
                base64.b64decode(db_file.aes_key_encrypted), priv_key
            )

            # Re-encrypt with recipient's RSA public key
            target_pub = pem_to_key(target.public_key.encode())
            enc_key = rsa_encrypt(aes_key, target_pub)

            # Expiry
            expires_at = None
            if form.expiry_hours.data and form.expiry_hours.data > 0:
                expires_at = _utcnow() + timedelta(
                    hours=form.expiry_hours.data
                )

            share_record = Share(
                file_id=db_file.id,
                owner_id=current_user.id,
                shared_with_id=target.id,
                aes_key_encrypted=base64.b64encode(enc_key).decode(),
                can_download=(form.permission.data == 'download'),
                can_reshare=False,
                expires_at=expires_at,
            )
            db.session.add(share_record)
            db.session.commit()

            log_action('SHARE',
                       f'File {db_file.original_name} shared with {username}',
                       resource_type='share', resource_id=share_record.id)
            flash(f'File shared with {username}.', 'success')
            return redirect(url_for('dashboard'))

        return render_template('share.html', form=form, file=db_file)

    @app.route('/shares')
    @login_required
    def my_shares():
        show = request.args.get('show', 'active')
        my_files = File.query.filter_by(owner_id=current_user.id, is_deleted=False).all()
        file_ids = [f.id for f in my_files]
        share_query = Share.query.filter(Share.file_id.in_(file_ids))
        if show == 'active':
            share_query = share_query.filter(Share.revoked == False)
        elif show == 'revoked':
            share_query = share_query.filter(Share.revoked == True)
        shares_given = share_query.order_by(
            Share.created_at.desc()
        ).all() if file_ids else []
        return render_template('my_shares.html', shares=shares_given, show=show)

    @app.route('/revoke/<int:share_id>', methods=['POST'])
    @login_required
    def revoke(share_id):
        share_record = db.session.get(Share, share_id)
        if not share_record:
            abort(404)
        if share_record.file.owner_id != current_user.id:
            abort(403)

        share_record.revoked = True
        share_record.deleted_at = _utcnow()
        db.session.commit()

        log_action('REVOKE',
                   f'Access revoked for {share_record.shared_with.username} on {share_record.file.original_name}',
                   resource_type='share', resource_id=share_id)
        flash('Access revoked.', 'success')
        return redirect(url_for('my_shares'))

    # ==================================================================
    # Routes: File Management
    # ==================================================================

    @app.route('/file/<uuid:file_uuid>/delete', methods=['POST'])
    @login_required
    def delete_file(file_uuid):
        db_file = File.query.filter_by(uuid=str(file_uuid), is_deleted=False).first()
        if not db_file or db_file.owner_id != current_user.id:
            abort(404)

        db_file.is_deleted = True

        # Soft-delete associated shares
        now = _utcnow()
        for s in Share.query.filter_by(file_id=db_file.id).all():
            s.revoked = True
            s.deleted_at = now

        db.session.commit()

        log_action('DELETE', f'File {db_file.original_name} deleted',
                   resource_type='file', resource_id=db_file.uuid)
        flash('File deleted.', 'success')
        return redirect(url_for('dashboard'))

    @app.route('/file/<uuid:file_uuid>/info')
    @login_required
    def file_info(file_uuid):
        db_file = File.query.filter_by(uuid=str(file_uuid), is_deleted=False).first()
        if not db_file:
            abort(404)
        is_owner = db_file.owner_id == current_user.id
        share = Share.query.filter_by(
            file_id=db_file.id, shared_with_id=current_user.id
        ).first()
        if not is_owner and (not share or share.revoked):
            abort(403)

        return render_template('file_info.html', file=db_file, is_owner=is_owner)

    # ==================================================================
    # Routes: Audit Log
    # ==================================================================

    @app.route('/audit')
    @login_required
    def audit():
        logs = (
            AuditLog.query
            .order_by(AuditLog.timestamp.desc())
            .limit(200)
            .all()
        )
        return render_template('audit.html', logs=logs)

    # ==================================================================
    # Routes: Profile & Account
    # ==================================================================

    @app.route('/profile')
    @login_required
    def profile():
        return render_template('profile.html')

    @app.route('/profile/regenerate-keys', methods=['POST'])
    @login_required
    def regenerate_keys():
        password = request.form.get('password', '')
        if not current_user.check_password(password):
            flash('Password is incorrect.', 'danger')
            return redirect(url_for('profile'))

        priv, pub = generate_rsa_keypair()
        current_user.public_key = key_to_pem(pub).decode()
        current_user.encrypted_private_key = private_key_to_encrypted_pem(priv, password)
        db.session.commit()
        lock_private_key()

        log_action('KEY_ROTATION',
                   f'User {current_user.username} rotated RSA keys',
                   resource_type='user', resource_id=current_user.id)
        flash('RSA key pair regenerated. Please unlock your key again.', 'success')
        return redirect(url_for('dashboard'))

    @app.route('/profile/delete', methods=['GET', 'POST'])
    @login_required
    def delete_account():
        form = DeleteAccountForm()
        if form.validate_on_submit():
            if not current_user.check_password(form.password.data):
                flash('Password is incorrect.', 'danger')
                return render_template('delete_account.html', form=form)

            uid = current_user.id
            uname = current_user.username

            # Delete all files and shares
            for f in File.query.filter_by(owner_id=uid).all():
                try:
                    os.remove(f.stored_path)
                except OSError:
                    pass
                Share.query.filter_by(file_id=f.id).delete()
                db.session.delete(f)

            Share.query.filter_by(shared_with_id=uid).delete()

            db.session.delete(current_user)
            db.session.commit()

            log_action('ACCOUNT_DELETED', f'User {uname} deleted account',
                       resource_type='user', resource_id=uid)
            logout_user()
            session.clear()
            flash('Account permanently deleted.', 'info')
            return redirect(url_for('index'))

        return render_template('delete_account.html', form=form)

    # ==================================================================
    # Routes: API
    # ==================================================================

    @app.route('/api/public-key/<username>')
    def api_public_key(username):
        user = User.query.filter_by(username=sanitise_string(username, 32)).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({
            'username': user.username,
            'public_key': user.public_key,
        })

    # ==================================================================
    # Error Handlers
    # ==================================================================

    @app.errorhandler(400)
    def bad_request(e):
        return render_template('error.html', code=400,
                               message='Bad request.'), 400

    @app.errorhandler(403)
    def forbidden(e):
        log_action('ACCESS_DENIED',
                   f'403 on {request.path} by {current_user.username if current_user.is_authenticated else "anon"}',
                   success=False)
        return render_template('error.html', code=403,
                               message='Access denied.'), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('error.html', code=404,
                               message='Resource not found.'), 404

    @app.errorhandler(413)
    def too_large(e):
        return render_template('error.html', code=413,
                               message='File too large (max 64 MB).'), 413

    @app.errorhandler(429)
    def ratelimit_error(e):
        return render_template('error.html', code=429,
                               message='Too many requests. Please slow down.'), 429

    @app.errorhandler(500)
    def server_error(e):
        log_action('SERVER_ERROR',
                   f'500 on {request.path}',
                   success=False)
        return render_template('error.html', code=500,
                               message='Internal server error.'), 500

    # ==================================================================
    # Init DB
    # ==================================================================

    with app.app_context():
        db.create_all()
        # Migration: add missing columns
        try:
            from sqlalchemy import inspect as sa_inspect
            inspector = sa_inspect(db.engine)
            for tbl, cols in [
                ('share', [('revoked', 'BOOLEAN DEFAULT 0'),
                           ('deleted_at', 'DATETIME')]),
                ('file', [('download_count', 'INTEGER DEFAULT 0')]),
            ]:
                existing = [c['name'] for c in inspector.get_columns(tbl)]
                for col_name, col_def in cols:
                    if col_name not in existing:
                        db.session.execute(
                            db.text(f'ALTER TABLE {tbl} ADD COLUMN {col_name} {col_def}')
                        )
            db.session.commit()
        except Exception:
            pass

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=False)  # debug=False in production!
