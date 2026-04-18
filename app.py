import sqlite3
import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

# FIX 1 — Powerful, randomly-generated secret key.
# This creates a 32-byte cryptographically random key on startup.
# Load this in production as an environment variable or secrets manager.
# so it does survive restarts:
#   app.secret_key = os.environ['SECRET_KEY']

app.secret_key = secrets.token_hex(32)


# FIX 2 - Secure session cookies.
# HttpOnly: JavaScript is not able to read the cookie → XSS is not able to steal it.# Secure # Cookie is never transmitted in plain-HTTP → no plain-HTTP leakage..
# Secure    : Cookie is only sent over HTTPS → no plain-HTTP leakage.
# SameSite : Browser will not add the cookie to cross-site requests. → eliminates the main CSRF vector even without a token.

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# Fix 3 CSRF protection with Flask-WTF.
# All state changing forms (POST/PUT/DELETE) should have a valid token.
# that Flask-WF is embedded into templates with {{ csrf_token() }} in them.
# The requests that do not have a corresponding token are responded to with a 400 status.

csrf = CSRFProtect(app)

DATABASE = 'securenotes.db'


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if not os.path.exists(DATABASE):
        with app.app_context():
            db = get_db()
            with app.open_resource('schema.sql', mode='r') as f:
                db.cursor().executescript(f.read())
            db.commit()


init_db()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated

# FIX 4 Security response headers.
# Content-Security-Policy: prohibits inline scripts and limits resource.This is due to the fact that the majority of XSS payloads are defeated by the presence of the origins tag even in case they do reach the user.
#   origins, which defeats most XSS payloads even if one slips through.
# X-Content-Type-Options: eliminates attacks of MIME-sniffing.
# X-Frame-Options: prevents clickjacking through iframes.
# Referrer-Policy: restricts information leakage on the Referer header.
# Permissions-Policy: turns off browser features that the app does not require.

@app.after_request
def apply_secure_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options']         = 'DENY'
    response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']      = 'geolocation=(), microphone=(), camera=()'
    return response


# FIX 5 - Use parameterised queries everywhere (no SQL Injection)
# The sqlite3 driver supports the placeholders with a question mark. 
# User input is not concatenated in to the SQL string and therefore the database engine will always never takes it as SQL syntax.


# FIX 6 - Password hashing (Werkzeug pbkdf2-sha256) 
# The passwords are hashed using a user-specific salt and then stored.
# The attackers receive only salted hashes even in case the database is dumped.


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db  = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        db.close()

        if user and check_password_hash(user['password'], password):
            session.clear()                        # prevent session fixation
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['role']     = user['role']
            return redirect(url_for('dashboard'))

        # Same error message to incorrect username or incorrect password -
        # prevents username enumeration.

        error = 'Invalid credentials'
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            error = 'Username and password are required.'
            return render_template('register.html', error=error)

        if len(password) < 8:
            error = 'Password must be at least 8 characters.'
            return render_template('register.html', error=error)

        # FIX 6 — hash before storing
        hashed = generate_password_hash(password)
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed, 'user'),
            )
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = 'Username already exists.'
        finally:
            db.close()
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    db  = get_db()
    cur = db.execute(
        "SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC",
        (session['user_id'],),
    )
    notes = cur.fetchall()
    db.close()
    # FIX 7 XSS: note content is auto-escaped using the template.
    # (default Jinja2 behaviour - do NOT use |safe|).

    return render_template('dashboard.html', notes=notes)


@app.route('/note/create', methods=['POST'])
@login_required
def create_note():
    content = request.form.get('content', '').strip()
    if not content:
        return redirect(url_for('dashboard'))
    db = get_db()
    db.execute(
        "INSERT INTO notes (user_id, content) VALUES (?, ?)",
        (session['user_id'], content),
    )
    db.commit()
    db.close()
    return redirect(url_for('dashboard'))

# FIX 8 — IDOR fix: check ownership prior to read or write.
# We verify the ownership of the note (or administration) with the caller after the note is fetched.
# Non-owners are shown 403 Forbidden - they are unable to read or write the note.


@app.route('/note/edit/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    db   = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()

    if not note:
        db.close()
        abort(404)

    # Ownership check - admins can edit any note.
    if note['user_id'] != session['user_id'] and session.get('role') != 'admin':
        db.close()
        abort(403)

    if request.method == 'POST':
        new_content = request.form.get('content', '').strip()
        if new_content:
            db.execute(
                "UPDATE notes SET content = ? WHERE id = ?",
                (new_content, note_id),
            )
            db.commit()
        db.close()
        return redirect(url_for('dashboard'))

    db.close()
    return render_template('edit_note.html', note=note)


# FIX 8 - IDOR fix on delete: ownership check prior to deletion.
# Fix 9 - Deletion relocated to POST to avoid deletion of a plain <img> or a plain a link.Trigger it with a GET request; 
# CSRF token provides an extra security measure.

@app.route('/note/delete/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    db   = get_db()
    note = db.execute("SELECT user_id FROM notes WHERE id = ?", (note_id,)).fetchone()

    if not note:
        db.close()
        abort(404)

    if note['user_id'] != session['user_id'] and session.get('role') != 'admin':
        db.close()
        abort(403)

    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    db.close()
    return redirect(url_for('dashboard'))


@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    db    = get_db()
    users = db.execute("""
        SELECT u.id, u.username, u.role, COUNT(n.id) as note_count
        FROM users u LEFT JOIN notes n ON u.id = n.user_id
        GROUP BY u.id ORDER BY u.username
    """).fetchall()
    notes = db.execute("""
        SELECT notes.id, notes.content, notes.created_at, users.username
        FROM notes JOIN users ON notes.user_id = users.id
        ORDER BY notes.created_at DESC
    """).fetchall()
    db.close()
    return render_template('admin.html', users=users, notes=notes)


@app.context_processor
def inject_vars():
    # VULNERable_XSS is eliminated - templates automatically escape.
    return {}


@app.route('/')
def index():
    return redirect(url_for('login'))
