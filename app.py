import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, abort

app = Flask(__name__)


# Vulnerability 1- Hardcoded secret key.
# The secret key is hard coded and extremely weak.
# When a person cracks it, he/she can create session cookies and log in as any user (including the admin) without a password.

app.secret_key = 'supersecret'

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
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated



# Vulnerability 2 - Lack of security headers.
# There are no security headers.
# This means:
# 	- No CSP → injected scripts won’t be blocked
# 	- No X-Frame-Options → app can be embedded (clickjacking risk)
# 	- No X-Content-Type-Options means that browser can guess the file types (MIME sniffing).


# Vulnerability 3 - SQL Injection (login)
# The query is directly typed into the SQL query.
# This makes the login vulnerable to SQL injection.
# Example:
# 	' OR '1'='1 → bypass login
# 	'; DROP TABLE users; -- → deletes the users table



@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()

        # Here an f-string implies straight user input to SQL.
        # No parameterization or validation.

        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = db.execute(query).fetchone()
        db.close()

        if user:
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['role']     = user['role']
            return redirect(url_for('dashboard'))
        error = 'Invalid credentials'
    return render_template('login.html', error=error)


# Vulnerability 3 & 4 - SQL Injection (register) and plain-text passwords.
# The passwords are stored in their original form (there are not hashed).
# In the event of a leak of the database, all user passwords are revealed immediately.


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']   # stored as plain text
        db = get_db()
        try:
            #Once more f-string is used → prone to SQL injection when registering.
            db.execute(
                f"INSERT INTO users (username, password, role) "
                f"VALUES ('{username}', '{password}', 'user')"
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


# Vulnerability 3 - SQL Injection (dashboard).
# The query directly involves the use of session [userid].
# In case of tampering with the session (which might occur because of a weak secret key), an attacker would be able to interfere with it and access the notes of other users.


@app.route('/dashboard')
@login_required
def dashboard():
    db  = get_db()
    cur = db.execute(
        f"SELECT * FROM notes WHERE user_id = {session['user_id']} ORDER BY created_at DESC"
    )
    notes = cur.fetchall()
    db.close()
    # Vulnerability 5 — Stored XSS
    # In the template, notes are translated into safe.
    # It implies that any HTML/JS (e.g. <script> will run in the browser.
    # Stored XSS applies to all users that see the note.


    return render_template('dashboard.html', notes=notes)



#Vulnerability 3, 5, 6
# It is susceptible to SQL injection as the query is used with the input of the user.
# The stored XSS can be caused by storing malicious content and rendering it later.
# It has no CSRF protection and thus another web site may trick a logged-in user into making a request without their awareness (e.g. creating a note).


@app.route('/note/create', methods=['POST'])
@login_required
def create_note():
    content = request.form['content']
    db = get_db()
    db.execute(
        f"INSERT INTO notes (user_id, content) VALUES ({session['user_id']}, '{content}')"
    )
    db.commit()
    db.close()
    return redirect(url_for('dashboard'))


#Vulnerability 2, 3, 6 — Edit note
# No ownership verification: any user that is logged in can edit any note changing the ID (IDOR).
# Query is susceptible to SQL injection.
# No CSRF protection on POST request


@app.route('/note/edit/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    db   = get_db()
    note = db.execute(f"SELECT * FROM notes WHERE id = {note_id}").fetchone()

    if not note:
        abort(404)

    # No verification is made to confirm that the note is of the current user.

    if request.method == 'POST':
        new_content = request.form['content']
        db.execute(f"UPDATE notes SET content = '{new_content}' WHERE id = {note_id}")
        db.commit()
        db.close()
        return redirect(url_for('dashboard'))

    db.close()
    return render_template('edit_note.html', note=note)


# Vulnerability 2, 3, 6 — Delete note
# Anyone who logs in can just change the ID (IDOR) to delete any note.
# SQL injection in delete statement.
# Uses GET for deletion → unsafe and vulnerable to CSRF
# Even accessing an ill-intentioned link might cause deletion.


@app.route('/note/delete/<int:note_id>')
@login_required
def delete_note(note_id):
    db = get_db()
    db.execute(f"DELETE FROM notes WHERE id = {note_id}")
    db.commit()
    db.close()
    return redirect(url_for('dashboard'))


@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    db = get_db()
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



# Vulnerability 7 - Weak session cookies.
# The flags that are missing in the session cookies are:
# 	- HttpOnly → JS can access them (bad with XSS)
# 	- Secure → sent over HTTP (can be intercepted)
# 	- SameSite → permits cross-site requests (aids CSRF attacks)




@app.context_processor
def inject_vars():
    # All notes are always sent as raw HTML (|Safe|), and stored XSS is feasible throughout the app.
    return dict(VULNERABLE_XSS=True)


@app.route('/')
def index():
    return redirect(url_for('login'))
