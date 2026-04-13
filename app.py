import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, abort

app = Flask(__name__)

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




@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()

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




@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']   
        db = get_db()
        try:
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




@app.route('/dashboard')
@login_required
def dashboard():
    db  = get_db()
    cur = db.execute(
        f"SELECT * FROM notes WHERE user_id = {session['user_id']} ORDER BY created_at DESC"
    )
    notes = cur.fetchall()
    db.close()

    return render_template('dashboard.html', notes=notes)




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



@app.route('/note/edit/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    db   = get_db()
    note = db.execute(f"SELECT * FROM notes WHERE id = {note_id}").fetchone()

    if not note:
        abort(404)


    if request.method == 'POST':
        new_content = request.form['content']
        db.execute(f"UPDATE notes SET content = '{new_content}' WHERE id = {note_id}")
        db.commit()
        db.close()
        return redirect(url_for('dashboard'))

    db.close()
    return render_template('edit_note.html', note=note)





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





@app.context_processor
def inject_vars():
    
    return dict(VULNERABLE_XSS=True)




@app.route('/')
def index():
    return redirect(url_for('login'))
