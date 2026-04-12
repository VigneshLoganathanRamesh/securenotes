import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, abort, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = 'development-key-change-in-production'


VULNERABLE_SQL = True
VULNERABLE_XSS = True
VULNERABLE_IDOR = True
ENABLE_CSRF = False
SECURE_HEADERS = False


DATABASE = 'securenotes.db'

def get_db():
    """Connect to the database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database from schema.sql."""
    if not os.path.exists(DATABASE):
        with app.app_context():
            db = get_db()
            with app.open_resource('schema.sql', mode='r') as f:
                db.cursor().executescript(f.read())
            db.commit()

init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def apply_secure_headers(response):
    if SECURE_HEADERS:
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        if VULNERABLE_SQL:
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            cur = db.execute(query)
        else:
            query = "SELECT * FROM users WHERE username = ?"
            cur = db.execute(query, (username,))
            user = cur.fetchone()
            if user and check_password_hash(user['password'], password):
                pass  # success
            else:
                user = None
            if VULNERABLE_SQL:
                user = cur.fetchone()
        
        if not VULNERABLE_SQL:
            cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cur.fetchone()
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid credentials'
        else:
            cur = db.execute(query)
            user = cur.fetchone()
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid credentials'
                
        db.close()
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = 'user'
        
        db = get_db()
        try:
            if VULNERABLE_SQL:
                db.execute(
                    f"INSERT INTO users (username, password, role) VALUES ('{username}', '{password}', '{role}')"
                )
            else:
                hashed = generate_password_hash(password)
                db.execute(
                    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    (username, hashed, role)
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
    db = get_db()
    if VULNERABLE_SQL:
        cur = db.execute(f"SELECT * FROM notes WHERE user_id = {session['user_id']} ORDER BY created_at DESC")
    else:
        cur = db.execute("SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC", (session['user_id'],))
    notes = cur.fetchall()
    db.close()
    return render_template('dashboard.html', notes=notes)





@app.route('/note/create', methods=['POST'])
@login_required
def create_note():
    content = request.form['content']
    db = get_db()
    if VULNERABLE_SQL:
        db.execute(f"INSERT INTO notes (user_id, content) VALUES ({session['user_id']}, '{content}')")
    else:
        db.execute("INSERT INTO notes (user_id, content) VALUES (?, ?)", (session['user_id'], content))
    db.commit()
    db.close()
    return redirect(url_for('dashboard'))



@app.route('/note/edit/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    db = get_db()
    if VULNERABLE_SQL:
        cur = db.execute(f"SELECT * FROM notes WHERE id = {note_id}")
    else:
        cur = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
    note = cur.fetchone()
    
    if not note:
        abort(404)
    
    if not VULNERABLE_IDOR:
        if note['user_id'] != session['user_id'] and session['role'] != 'admin':
            db.close()
            abort(403)  
    
    if request.method == 'POST':
        new_content = request.form['content']
        if VULNERABLE_SQL:
            db.execute(f"UPDATE notes SET content = '{new_content}' WHERE id = {note_id}")
        else:
            db.execute("UPDATE notes SET content = ? WHERE id = ?", (new_content, note_id))
        db.commit()
        db.close()
        return redirect(url_for('dashboard'))
    
    db.close()
    return render_template('edit_note.html', note=note)





@app.route('/note/delete/<int:note_id>')
@login_required
def delete_note(note_id):
    db = get_db()
    if not VULNERABLE_IDOR:
        cur = db.execute("SELECT user_id FROM notes WHERE id = ?", (note_id,))
        note = cur.fetchone()
        if not note or (note['user_id'] != session['user_id'] and session['role'] != 'admin'):
            db.close()
            abort(403)
    
    if VULNERABLE_SQL:
        db.execute(f"DELETE FROM notes WHERE id = {note_id}")
    else:
        db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    db.close()
    return redirect(url_for('dashboard'))





@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    db = get_db()
    
    users_cur = db.execute("""
        SELECT u.id, u.username, u.role, COUNT(n.id) as note_count
        FROM users u
        LEFT JOIN notes n ON u.id = n.user_id
        GROUP BY u.id
        ORDER BY u.username
    """)
    users = users_cur.fetchall()
    
    notes_cur = db.execute("""
        SELECT notes.id, notes.content, notes.created_at, users.username 
        FROM notes 
        JOIN users ON notes.user_id = users.id 
        ORDER BY notes.created_at DESC
    """)
    notes = notes_cur.fetchall()
    
    db.close()
    return render_template('admin.html', users=users, notes=notes)



@app.context_processor
def inject_vars():
    return dict(VULNERABLE_XSS=VULNERABLE_XSS)




csrf = CSRFProtect(app) if ENABLE_CSRF else None


if SECURE_HEADERS:
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,   
        SESSION_COOKIE_SAMESITE='Lax'
    )


@app.route('/')
def index():
    return redirect(url_for('login'))