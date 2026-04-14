# SecureNotes — Flask Web Security Demo

A purposefully vulnerable Flask note-taking web application built to demonstrate common web security vulnerabilities and their fixes. The project ships in **two versions** side-by-side so you can see exactly what insecure code(securenote_vuln - app.py) looks like and how each vulnerability is resolved(securenote - app.py).



<img width="1252" height="556" alt="image" src="https://github.com/user-attachments/assets/fcf1aed0-9d5c-4efe-9479-0054b146856e" />


 ---
 
 
## About the Project

SecureNotes is a simple note-taking web app where users can register, log in, create, edit, and delete personal notes. An admin panel allows privileged users to view all users and notes.

The app was intentionally built with  real-world security vulnerabilities that are commonly found in web applications — then fixed one by one to produce a hardened secure version.



---


## Project Structure
```bash
securenotes/
│
├── app.py                  # Fully vulnerable version — all protections off  &&  Fully secure version — all vulnerabilities fixed
│
├── schema.sql              # Database schema with hashed sample passwords
│
├── templates/
│   ├── base.html           # Shared layout (Bootstrap 5 navbar, flash messages)
│   ├── login.html          # Login form
│   ├── register.html       # Registration form
│   ├── dashboard.html      # Notes list + create note form
│   ├── edit_note.html      # Edit a single note
│   └── admin.html          # Admin panel (users + all notes)
│
└── README.md
```

---


## Tools & Technologies

| Technology         | Purpose |
|---                 |---|
| Python 3           | Backend language |
| Flask              | Web framework |
| SQLite             | Database |
| Werkzeug           | Password hashing (`generate_password_hash`) |
| Flask-WTF          | CSRF protection |
| Bootstrap 5        | Frontend UI |
| Jinja2             | HTML templating with auto-escaping |


---


## Quick Start

1. Clone the repository

```bash
git clone https://github.com/your-username/securenotes.git
cd securenotes/securenotes-main
```

2. Run the application and check

```bash
python app_secure.py
```

Visit `http://127.0.0.1:5000` in your browser.


---




## Default Credentials

| Username | Password | Role  |
|----------|----------|-------|
| `admin`  | `admin123` | Admin |
| `alice`  | `alice123` | User  |
| `bob`    | `bob123`   | User  |




---

## Vulnerabilities Found


### 1. SQL Injection
Location: Login, Register, Dashboard, Edit Note, Delete Note routes
The app used Python f-strings to build SQL queries directly from user input:

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

An attacker can type `' OR '1'='1` in the username field and bypass the password check entirely, logging in as the first user in the database (usually admin). A payload like `'; DROP TABLE users; --` would destroy the entire users table.


### 2. Plain-Text Password Storage
Location: Register route, `schema.sql`
Passwords were stored as plain text in the database:

```sql
INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')
```

Any database breach instantly exposes every user's real password with zero effort.


### 3. XSS — Cross-Site Scripting (Stored)
Location: Dashboard, Admin panel templates
Note content was rendered with Jinja2's `| safe` filter, which disables HTML escaping:

```html
{{ note.content | safe }}
```

A note containing `<script>alert(document.cookie)</script>` executes in every visitor's browser, allowing cookie theft, session hijacking, or page defacement.


### 4. IDOR — Insecure Direct Object Reference
Location: Edit Note, Delete Note routes
No ownership check was performed before allowing access to a note:

```python
# Any logged-in user could edit /note/edit/1, /note/edit/2, etc.
note = db.execute(f"SELECT * FROM notes WHERE id = {note_id}").fetchone()
# Missing: check that note['user_id'] == session['user_id']
```

Any authenticated user could read, edit, or delete any other user's notes just by changing the ID in the URL.


### 5. CSRF — Cross-Site Request Forgery
Location:All state-changing forms (create, edit, delete)

No CSRF tokens were validated. A malicious page on another domain could silently submit forms on behalf of a logged-in user. The delete route was a plain `GET` link, meaning a hidden `<img src="/note/delete/1">` tag on any page would delete the note without the user clicking anything.


### 6. Hardcoded Weak Secret Key
Location: `app.py`

```python
app.secret_key = 'supersecret'
```

Flask uses the secret key to sign session cookies. Anyone who knows this value can forge a valid session cookie and log in as any user, including admin, without a password.


### 7. Insecure Session Cookies
Location: Flask app config

Flask's default cookie settings leave three important flags unset:
- No `HttpOnly` → JavaScript can read the cookie (XSS can steal it)
- No `Secure` → cookie is sent over plain HTTP (network sniffing)
- No `SameSite` → cookie is attached to cross-origin requests (aids CSRF)


### 8. Missing Security Headers
Location: HTTP responses

No security headers were set, leaving the browser with no defence policy:
- No `Content-Security-Policy` → injected scripts execute freely
- No `X-Frame-Options` → the app can be embedded in iframes (clickjacking)
- No `X-Content-Type-Options` → MIME-sniffing attacks possible



---



## Security Fixes Applied

### Fix 1 — Parameterised Queries (eliminates SQL Injection)

Every raw f-string query was replaced with `?` placeholders:

```python
# Before (vulnerable)
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

# After (secure)
cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
```

The database driver treats user input strictly as data — never as SQL syntax.


### Fix 2 — Password Hashing (Werkzeug pbkdf2-sha256)

Passwords are hashed with a per-user salt before storage:

```python
# On register
hashed = generate_password_hash(password)
db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed, role))

# On login
if user and check_password_hash(user['password'], password):
    ...
```

Even if the database is dumped, attackers get only salted hashes.


### Fix 3 — XSS Prevention (Jinja2 auto-escaping)

The `| safe` filter was removed from all templates. Jinja2's default auto-escaping converts `<script>` tags into harmless visible text:

```html
<!-- Before (vulnerable) -->
{{ note.content | safe }}

<!-- After (secure) -->
{{ note.content }}
```

### Fix 4 — IDOR Fix (ownership checks)

Every note route now verifies the caller owns the note before allowing access:

```python
if note['user_id'] != session['user_id'] and session.get('role') != 'admin':
    abort(403)
```


### Fix 5 — CSRF Protection (Flask-WTF)

`CSRFProtect(app)` is enabled globally. Every form includes a hidden token:

```html
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
```

The delete action was also changed from a `GET` link to a `POST` form, so it cannot be triggered by a URL alone.


### Fix 6 — Strong Random Secret Key

The hardcoded key is replaced with a cryptographically random value:

```python
app.secret_key = secrets.token_hex(32)
```

For production, load from an environment variable:

```python
app.secret_key = os.environ['SECRET_KEY']
```


### Fix 7 — Secure Session Cookies

All three cookie security flags are now set:

```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JS cannot read the cookie
    SESSION_COOKIE_SECURE=True,     # HTTPS only
    SESSION_COOKIE_SAMESITE='Lax',  # Blocks cross-origin requests
)
```


### Fix 8 — Security Response Headers

An `after_request` hook adds protective headers to every response:

```python
response.headers['Content-Security-Policy'] = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' https://cdn.jsdelivr.net; "
    ...
)
response.headers['X-Frame-Options']         = 'DENY'
response.headers['X-Content-Type-Options']  = 'nosniff'
response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
response.headers['Permissions-Policy']      = 'geolocation=(), microphone=(), camera=()'
```

---


## Vulnerability vs Secure — Side by Side

| Vulnerability         | app.py(Vulnerable version)      | app.py(Secure version) |
|---                    |---                               |---|
| SQL Injection         | ❌ Raw f-string queries         | ✅ Parameterised `?` placeholders |
| Password storage      | ❌ Plain text                   | ✅ Hashed (pbkdf2-sha256) |
| XSS                   | ❌ `\| safe` disables escaping  | ✅ Jinja2 auto-escaping |
| IDOR                  | ❌ No ownership check           | ✅ `user_id` verified before access |
| CSRF                  | ❌ No token, DELETE via GET     | ✅ Flask-WTF tokens, POST only |
| Secret key            | ❌ `'supersecret'` hardcoded    | ✅ `secrets.token_hex(32)` |
| Session cookies       | ❌ No flags set                 | ✅ HttpOnly + Secure + SameSite |
| Security headers      | ❌ None                         | ✅ CSP, X-Frame-Options, etc. |

---
 

